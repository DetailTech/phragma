package engines

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// procManager runs one external engine binary as a supervised child
// process: restart on config change, log unexpected exits. Engines that
// embed it stay license-isolated — we exec, never link.
type procManager struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	gen  int // bumped on every (re)start so the waiter can tell planned stops from crashes
	name string
}

// restart stops any running instance and starts the binary with args.
func (p *procManager) restart(name string, args ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	p.cmd = cmd
	p.gen++
	gen := p.gen
	p.name = name

	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		unexpected := p.gen == gen && p.cmd == cmd
		if unexpected {
			p.cmd = nil
		}
		p.mu.Unlock()
		if unexpected {
			slog.Error("engine process exited unexpectedly", "engine", name, "error", err)
		}
	}()

	// Give the process a moment to fail fast on bad config. The lock is
	// released during the sleep so the waiter goroutine can record an
	// early exit (deferred unlock still pairs with this re-lock).
	p.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
	p.mu.Lock()
	if p.gen != gen || p.cmd == nil {
		return fmt.Errorf("%s exited immediately after start (see logs)", name)
	}
	return nil
}

// stop terminates the child if running.
func (p *procManager) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
}

func (p *procManager) stopLocked() {
	if p.cmd == nil {
		return
	}
	p.gen++ // planned stop: the waiter must not log it as a crash
	cmd := p.cmd
	p.cmd = nil
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}
}

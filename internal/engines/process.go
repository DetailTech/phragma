package engines

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// procManager runs one external engine binary as a supervised child process:
// restart on config change, bounded auto-restart on stable unexpected exits,
// and log failures loudly. Engines that embed it stay license-isolated: we
// exec, never link.
type procManager struct {
	mu sync.Mutex

	cmd  *exec.Cmd
	done chan struct{}
	gen  int // bumped on every (re)start so the waiter can tell planned stops from crashes
	name string
	args []string

	restarts    int
	maxRestarts int
	restartWait time.Duration
	startGrace  time.Duration

	state       string
	lastStarted time.Time
	lastExit    time.Time
	lastError   string
	lastUptime  time.Duration
}

const (
	// ProcessStateStopped means the supervised engine process is not running.
	ProcessStateStopped = "stopped"
	// ProcessStateRunning means the supervised engine process is currently live.
	ProcessStateRunning = "running"
	// ProcessStateRestarting means the supervisor is waiting to restart the engine.
	ProcessStateRestarting = "restarting"
	// ProcessStateFailed means the supervised engine exited without a restart path.
	ProcessStateFailed = "failed"
)

// ProcessStatus is a point-in-time snapshot of a supervised child engine.
type ProcessStatus struct {
	State        string
	PID          int
	Restarts     int
	MaxRestarts  int
	StartedAt    time.Time
	LastExitAt   time.Time
	LastExitErr  string
	LastUptime   time.Duration
	RestartDelay time.Duration
	StartupGrace time.Duration
}

// restart stops any running instance and starts the binary with args.
func (p *procManager) restart(name string, args ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
	p.restarts = 0
	p.lastExit = time.Time{}
	p.lastError = ""
	p.lastUptime = 0

	gen, err := p.startLocked(name, args)
	if err != nil {
		return err
	}

	// Give the process a moment to fail fast on bad config. The lock is
	// released during the sleep so the waiter goroutine can record an
	// early exit (deferred unlock still pairs with this re-lock).
	grace := p.startupGrace()
	p.mu.Unlock()
	time.Sleep(grace)
	p.mu.Lock()
	if p.gen != gen || p.cmd == nil {
		return fmt.Errorf("%s exited immediately after start (see logs)", name)
	}
	return nil
}

func (p *procManager) startLocked(name string, args []string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start %s: %w", name, err)
	}
	done := make(chan struct{})
	p.cmd = cmd
	p.done = done
	p.gen++
	p.name = name
	p.args = append([]string(nil), args...)
	p.state = ProcessStateRunning
	gen := p.gen
	started := time.Now()
	p.lastStarted = started
	go p.wait(cmd, gen, started, done)
	return gen, nil
}

func (p *procManager) wait(cmd *exec.Cmd, gen int, started time.Time, done chan struct{}) {
	err := cmd.Wait()
	close(done)
	uptime := time.Since(started)
	p.mu.Lock()
	unexpected := p.gen == gen && p.cmd == cmd
	if unexpected {
		p.cmd = nil
		p.done = nil
		p.lastExit = time.Now()
		p.lastUptime = uptime
		if err != nil {
			p.lastError = err.Error()
		} else {
			p.lastError = "process exited"
		}
	}
	stable := uptime >= p.startupGrace()
	canRestart := unexpected && stable && p.restarts < p.restartLimit()
	if canRestart {
		p.restarts++
		p.state = ProcessStateRestarting
	} else if unexpected {
		p.state = ProcessStateFailed
	}
	name := p.name
	args := append([]string(nil), p.args...)
	attempt := p.restarts
	delay := p.restartDelay()
	p.mu.Unlock()

	if !unexpected {
		return
	}
	slog.Error("engine process exited unexpectedly", "engine", name, "error", err, "uptime", uptime.String())
	if !canRestart {
		if stable {
			slog.Error("engine auto-restart budget exhausted", "engine", name, "max_restarts", p.restartLimit())
		}
		return
	}
	time.Sleep(delay)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gen != gen || p.cmd != nil {
		return
	}
	if _, err := p.startLocked(name, args); err != nil {
		p.state = ProcessStateFailed
		p.lastError = err.Error()
		slog.Error("engine auto-restart failed", "engine", name, "attempt", attempt, "error", err)
		return
	}
	slog.Warn("engine auto-restarted", "engine", name, "attempt", attempt)
}

// stop terminates the child if running.
func (p *procManager) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
}

func (p *procManager) stopLocked() {
	p.gen++ // cancels waiter-owned delayed restarts even when no child is live
	p.state = ProcessStateStopped
	if p.cmd == nil {
		return
	}
	cmd := p.cmd
	done := p.done
	p.cmd = nil
	p.done = nil
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

// Status returns a concurrency-safe snapshot for operator readiness views.
func (p *procManager) Status() ProcessStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.state
	if state == "" {
		state = ProcessStateStopped
	}
	pid := 0
	if p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	return ProcessStatus{
		State:        state,
		PID:          pid,
		Restarts:     p.restarts,
		MaxRestarts:  p.restartLimit(),
		StartedAt:    p.lastStarted,
		LastExitAt:   p.lastExit,
		LastExitErr:  p.lastError,
		LastUptime:   p.lastUptime,
		RestartDelay: p.restartDelay(),
		StartupGrace: p.startupGrace(),
	}
}

func (p *procManager) restartLimit() int {
	if p.maxRestarts > 0 {
		return p.maxRestarts
	}
	return 3
}

func (p *procManager) restartDelay() time.Duration {
	if p.restartWait > 0 {
		return p.restartWait
	}
	return 2 * time.Second
}

func (p *procManager) startupGrace() time.Duration {
	if p.startGrace > 0 {
		return p.startGrace
	}
	return 500 * time.Millisecond
}

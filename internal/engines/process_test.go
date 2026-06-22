package engines

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const procManagerHelperArg = "--proc-manager-helper"

func TestProcManagerAutoRestartsStableCrash(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	p := &procManager{
		maxRestarts: 1,
		restartWait: 10 * time.Millisecond,
		startGrace:  30 * time.Millisecond,
	}
	t.Cleanup(p.stop)

	if err := p.restart(os.Args[0], helperArgs("stable-crash", marker)...); err != nil {
		t.Fatal(err)
	}

	waitForRunCount(t, marker, 2, 2*time.Second)
	status := p.Status()
	if status.State != ProcessStateRunning {
		t.Fatalf("state = %q, want %q", status.State, ProcessStateRunning)
	}
	if status.Restarts != 1 {
		t.Fatalf("restarts = %d, want 1", status.Restarts)
	}
	if status.PID == 0 {
		t.Fatal("expected running child pid")
	}
	if status.LastExitAt.IsZero() || status.LastExitErr == "" {
		t.Fatalf("expected last exit evidence after restart: %#v", status)
	}
}

func TestProcManagerDoesNotRestartFailFastExit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	p := &procManager{
		maxRestarts: 2,
		restartWait: 10 * time.Millisecond,
		startGrace:  500 * time.Millisecond,
	}
	t.Cleanup(p.stop)

	err := p.restart(os.Args[0], helperArgs("fast-crash", marker)...)
	if err == nil || !strings.Contains(err.Error(), "exited immediately") {
		t.Fatalf("expected immediate-exit error, got: %v", err)
	}
	waitForRunCount(t, marker, 1, time.Second)
	assertRunCountStays(t, marker, 1, 100*time.Millisecond)
	status := p.Status()
	if status.State != ProcessStateFailed {
		t.Fatalf("state = %q, want %q", status.State, ProcessStateFailed)
	}
	if status.Restarts != 0 {
		t.Fatalf("restarts = %d, want 0", status.Restarts)
	}
}

func TestProcManagerStopDoesNotAutoRestart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	p := &procManager{
		maxRestarts: 2,
		restartWait: 10 * time.Millisecond,
		startGrace:  30 * time.Millisecond,
	}
	t.Cleanup(p.stop)

	if err := p.restart(os.Args[0], helperArgs("long-running", marker)...); err != nil {
		t.Fatal(err)
	}
	waitForRunCount(t, marker, 1, time.Second)

	p.stop()

	assertRunCountStays(t, marker, 1, 150*time.Millisecond)
	if got := p.Status().State; got != ProcessStateStopped {
		t.Fatalf("state = %q, want %q", got, ProcessStateStopped)
	}
}

func TestProcManagerStopCancelsDelayedAutoRestart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	p := &procManager{
		maxRestarts: 1,
		restartWait: 200 * time.Millisecond,
		startGrace:  30 * time.Millisecond,
	}
	t.Cleanup(p.stop)

	if err := p.restart(os.Args[0], helperArgs("stable-crash", marker)...); err != nil {
		t.Fatal(err)
	}
	waitForRunCount(t, marker, 1, time.Second)
	time.Sleep(140 * time.Millisecond)

	p.stop()

	assertRunCountStays(t, marker, 1, 250*time.Millisecond)
	status := p.Status()
	if status.State != ProcessStateStopped {
		t.Fatalf("state = %q, want %q", status.State, ProcessStateStopped)
	}
	if status.Restarts != 1 {
		t.Fatalf("restarts = %d, want 1", status.Restarts)
	}
}

func TestProcManagerHelperProcess(_ *testing.T) {
	mode, marker, ok := procManagerHelperInvocation()
	if !ok {
		return
	}
	appendRun(marker, mode)
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	go func() {
		<-interrupts
		os.Exit(0)
	}()

	switch mode {
	case "stable-crash":
		time.Sleep(120 * time.Millisecond)
		os.Exit(42)
	case "fast-crash":
		os.Exit(42)
	case "long-running":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown proc manager helper mode: %s\n", mode)
		os.Exit(2)
	}
}

func helperArgs(mode, marker string) []string {
	return []string{"-test.run=TestProcManagerHelperProcess", "--", procManagerHelperArg, mode, marker}
}

func procManagerHelperInvocation() (string, string, bool) {
	for i, arg := range os.Args {
		if arg == procManagerHelperArg && i+2 < len(os.Args) {
			return os.Args[i+1], os.Args[i+2], true
		}
	}
	return "", "", false
}

func appendRun(marker, mode string) {
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "record helper run: %v\n", err)
		os.Exit(2)
	}
	if _, err := fmt.Fprintln(f, mode); err != nil {
		fmt.Fprintf(os.Stderr, "write helper run: %v\n", err)
		os.Exit(2)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close helper run marker: %v\n", err)
		os.Exit(2)
	}
}

func waitForRunCount(t *testing.T, marker string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := runCount(t, marker); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run count for %s did not reach %d before %s; got %d", marker, want, timeout, runCount(t, marker))
}

func assertRunCountStays(t *testing.T, marker string, want int, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if got := runCount(t, marker); got != want {
			t.Fatalf("run count for %s changed: got %d, want %d", marker, got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runCount(t *testing.T, marker string) int {
	t.Helper()
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read helper run marker: %v", err)
	}
	return strings.Count(string(data), "\n")
}

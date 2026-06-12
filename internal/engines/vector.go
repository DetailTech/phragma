package engines

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// VectorName keys the vector.yaml artifact.
const VectorName = "vector"

// Vector supervises the Vector telemetry shipper.
type Vector struct {
	// Binary is the vector executable; defaults to "vector".
	Binary string
	// StateDir holds vector.yaml and the disk buffer.
	StateDir string

	proc procManager
}

// Name implements Engine.
func (v *Vector) Name() string { return VectorName }

func (v *Vector) bin() string {
	if v.Binary != "" {
		return v.Binary
	}
	return "vector"
}

// Validate runs `vector validate` when telemetry is enabled.
func (v *Vector) Validate(ctx context.Context, config []byte) error {
	if parseMode(config).mode == "disabled" {
		return nil
	}
	if _, err := exec.LookPath(v.bin()); err != nil {
		return fmt.Errorf("policy enables telemetry but %s is not installed: %w", v.bin(), err)
	}
	tmp, err := writeTemp(config, "openngfw-vector-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	// --no-environment skips connectivity checks: ClickHouse may be
	// down during validation; that must not block a commit.
	return runCmd(ctx, v.bin(), "validate", "--no-environment", tmp)
}

// Apply writes the config and (re)starts or stops Vector.
func (v *Vector) Apply(_ context.Context, config []byte) error {
	if parseMode(config).mode == "disabled" {
		v.proc.stop()
		return nil
	}
	if err := os.MkdirAll(v.StateDir, 0o755); err != nil {
		return err
	}
	cfgPath := filepath.Join(v.StateDir, "vector.yaml")
	if err := os.WriteFile(cfgPath, config, 0o644); err != nil {
		return err
	}
	return v.proc.restart(v.bin(), "--config", cfgPath)
}

// Stop terminates a running Vector (daemon shutdown).
func (v *Vector) Stop() { v.proc.stop() }

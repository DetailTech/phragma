package engines

import (
	"context"
	"log/slog"
)

// DryRun stands in for a real engine when controld runs with
// --dry-run (demo/dev hosts without nftables, CI without privileges).
// Renders and policy validation still run; nothing touches the system.
type DryRun struct {
	EngineName string
}

// Name implements Engine.
func (d *DryRun) Name() string { return d.EngineName }

// Validate implements Engine; dry-run accepts everything.
func (d *DryRun) Validate(context.Context, []byte) error { return nil }

// Apply implements Engine; it only logs.
func (d *DryRun) Apply(_ context.Context, config []byte) error {
	slog.Info("dry-run: skipped engine apply", "engine", d.EngineName, "bytes", len(config))
	return nil
}

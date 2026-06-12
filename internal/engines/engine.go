// Package engines supervises the external engines OpenNGFW orchestrates.
// Engines are always separate processes (or the kernel); this package
// only writes rendered native configs and drives reload/validate hooks —
// it never links engine code (license isolation, build plan §3).
package engines

import (
	"context"
	"fmt"
)

// Engine is one supervised backend (nftables, routes, suricata, …).
type Engine interface {
	// Name keys this engine's artifact in the rendered artifact set.
	Name() string
	// Validate checks a rendered config without applying it.
	Validate(ctx context.Context, config []byte) error
	// Apply makes the rendered config live.
	Apply(ctx context.Context, config []byte) error
}

// Supervisor coordinates validate/apply across all engines so a commit
// is atomic from the operator's point of view: if any engine fails to
// apply, every previously applied engine is restored to the prior
// config.
type Supervisor struct {
	engines []Engine
}

// NewSupervisor builds a supervisor over the given engines. Apply order
// is the given order; restore happens in reverse.
func NewSupervisor(engines ...Engine) *Supervisor {
	return &Supervisor{engines: engines}
}

// Validate runs every engine's validator against its artifact. Engines
// with no artifact present are skipped.
func (s *Supervisor) Validate(ctx context.Context, artifacts map[string][]byte) error {
	for _, e := range s.engines {
		cfg, ok := artifacts[e.Name()]
		if !ok {
			continue
		}
		if err := e.Validate(ctx, cfg); err != nil {
			return fmt.Errorf("engine %s: validation failed: %w", e.Name(), err)
		}
	}
	return nil
}

// Apply applies the new artifacts in order. On failure it re-applies
// prev to every engine that had already been switched, then returns the
// original error (annotated with any restore failure — a restore failure
// is an operator emergency and is never swallowed).
func (s *Supervisor) Apply(ctx context.Context, next, prev map[string][]byte) error {
	var applied []Engine
	for _, e := range s.engines {
		cfg, ok := next[e.Name()]
		if !ok {
			continue
		}
		if err := e.Apply(ctx, cfg); err != nil {
			err = fmt.Errorf("engine %s: apply failed: %w", e.Name(), err)
			for i := len(applied) - 1; i >= 0; i-- {
				prevCfg, ok := prev[applied[i].Name()]
				if !ok {
					continue
				}
				if rerr := applied[i].Apply(ctx, prevCfg); rerr != nil {
					err = fmt.Errorf("%w; RESTORE FAILED for engine %s: %v", err, applied[i].Name(), rerr)
				}
			}
			return err
		}
		applied = append(applied, e)
	}
	return nil
}

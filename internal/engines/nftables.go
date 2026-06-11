package engines

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// NftablesName keys the nftables artifact.
const NftablesName = "nftables"

// Nftables drives the kernel ruleset via the nft CLI. `nft -f` executes
// a file as one transaction, which gives us atomic replace for free.
type Nftables struct {
	// Binary is the nft executable path; defaults to "nft".
	Binary string
	// StateDir is where the live ruleset file is kept (for inspection
	// and re-apply on boot).
	StateDir string
}

// Name implements Engine.
func (n *Nftables) Name() string { return NftablesName }

func (n *Nftables) bin() string {
	if n.Binary != "" {
		return n.Binary
	}
	return "nft"
}

// Validate runs `nft -c -f` (check mode) against the rendered ruleset.
func (n *Nftables) Validate(ctx context.Context, config []byte) error {
	tmp, err := writeTemp(config, "openngfw-nft-*.conf")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return runCmd(ctx, n.bin(), "-c", "-f", tmp)
}

// Apply persists the ruleset under StateDir and executes it.
func (n *Nftables) Apply(ctx context.Context, config []byte) error {
	if err := os.MkdirAll(n.StateDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(n.StateDir, "nftables.conf")
	if err := os.WriteFile(path, config, 0o644); err != nil {
		return err
	}
	return runCmd(ctx, n.bin(), "-f", path)
}

func writeTemp(data []byte, pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

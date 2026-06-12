package engines

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StrongswanName keys the swanctl.conf artifact.
const StrongswanName = "strongswan"

// Strongswan manages IPsec via swanctl: it owns one drop-in under
// swanctl's conf.d and reloads connections on change. The charon daemon
// runs under the system service manager.
type Strongswan struct {
	// ConfDir is swanctl's conf.d directory (default /etc/swanctl/conf.d).
	ConfDir string
	// Binary is the swanctl executable; defaults to "swanctl".
	Binary string
}

// Name implements Engine.
func (s *Strongswan) Name() string { return StrongswanName }

func (s *Strongswan) confDir() string {
	if s.ConfDir != "" {
		return s.ConfDir
	}
	// Debian/Ubuntu install swanctl under /etc/swanctl; EL9 (Oracle
	// Linux, RHEL, Rocky — EPEL strongswan) uses /etc/strongswan/swanctl.
	// Prefer whichever tree the package created.
	for _, dir := range []string{"/etc/swanctl", "/etc/strongswan/swanctl"} {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return filepath.Join(dir, "conf.d")
		}
	}
	return "/etc/swanctl/conf.d"
}

func (s *Strongswan) bin() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "swanctl"
}

// Validate checks tool availability and that referenced PSK snippets
// exist. swanctl has no offline syntax checker; load errors surface at
// apply, before the commit is recorded.
func (s *Strongswan) Validate(_ context.Context, config []byte) error {
	if parseMode(config).mode == "disabled" {
		return nil
	}
	if _, err := exec.LookPath(s.bin()); err != nil {
		return fmt.Errorf("policy defines IPsec tunnels but %s is not installed: %w", s.bin(), err)
	}
	for _, inc := range includedFiles(config) {
		if _, err := os.Stat(inc); err != nil {
			return fmt.Errorf("ipsec secrets snippet %s is missing: %w", inc, err)
		}
	}
	return nil
}

// Apply writes the drop-in and reloads swanctl connections.
func (s *Strongswan) Apply(ctx context.Context, config []byte) error {
	if parseMode(config).mode == "disabled" {
		path := filepath.Join(s.confDir(), "openngfw.conf")
		if _, err := os.Stat(path); err != nil {
			return nil // nothing managed, nothing to clean up
		}
		if err := os.WriteFile(path, config, 0o600); err != nil {
			return err
		}
		return runCmd(ctx, s.bin(), "--load-conns", "--clear")
	}
	if err := os.MkdirAll(s.confDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.confDir(), "openngfw.conf"), config, 0o600); err != nil {
		return err
	}
	if err := runCmd(ctx, s.bin(), "--load-all", "--noprompt"); err != nil {
		return fmt.Errorf("swanctl load (is charon running?): %w", err)
	}
	return nil
}

// includedFiles lists `include <path>` directives in the artifact.
func includedFiles(config []byte) []string {
	var out []string
	for _, line := range lines(config) {
		if v, ok := strings.CutPrefix(line, "include "); ok {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

package engines

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FRRName keys the frr.conf artifact.
const FRRName = "frr"

// FRR manages the FRRouting suite: it owns frr.conf and the daemons
// file, and reloads the FRR service on change. FRR daemons themselves
// run under the system service manager — separate processes, as always.
type FRR struct {
	// ConfigPath is the live frr.conf (default /etc/frr/frr.conf).
	ConfigPath string
	// DaemonsPath is FRR's daemon-enable file (default /etc/frr/daemons).
	DaemonsPath string
	// ReloadCmd reloads FRR after a config write
	// (default: systemctl reload-or-restart frr).
	ReloadCmd []string
	// StateDir holds the managed marker: FRR is only ever reconfigured
	// or cleaned up if OpenNGFW enabled routing in the first place.
	StateDir string
}

// Name implements Engine.
func (f *FRR) Name() string { return FRRName }

func (f *FRR) configPath() string {
	if f.ConfigPath != "" {
		return f.ConfigPath
	}
	return "/etc/frr/frr.conf"
}

func (f *FRR) daemonsPath() string {
	if f.DaemonsPath != "" {
		return f.DaemonsPath
	}
	return "/etc/frr/daemons"
}

func (f *FRR) reloadCmd() []string {
	if len(f.ReloadCmd) != 0 {
		return f.ReloadCmd
	}
	return []string{"systemctl", "reload-or-restart", "frr"}
}

// parseDaemons extracts the daemon list from the marker line.
func parseDaemons(config []byte) []string {
	sc := bufio.NewScanner(bytes.NewReader(config))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "! openngfw-daemons: "); ok {
			v = strings.TrimSpace(v)
			if v == "none" || v == "" {
				return nil
			}
			return strings.Split(v, ",")
		}
	}
	return nil
}

// Validate dry-checks the config with vtysh -C.
func (f *FRR) Validate(ctx context.Context, config []byte) error {
	if len(parseDaemons(config)) == 0 {
		return nil
	}
	if _, err := exec.LookPath("vtysh"); err != nil {
		return fmt.Errorf("policy enables dynamic routing but FRR (vtysh) is not installed: %w", err)
	}
	tmp, err := writeTemp(config, "openngfw-frr-*.conf")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return runCmd(ctx, "vtysh", "-C", "-f", tmp)
}

func (f *FRR) markerPath() string { return filepath.Join(f.StateDir, "frr.managed") }

// Apply writes frr.conf, enables the needed daemons, and reloads FRR.
// A node whose policy never enabled routing is left completely alone —
// FRR may be operated by something else.
func (f *FRR) Apply(ctx context.Context, config []byte) error {
	daemons := parseDaemons(config)
	if len(daemons) == 0 {
		if _, err := os.Stat(f.markerPath()); err != nil {
			return nil // we never managed FRR here
		}
		if err := f.enableDaemons(nil); err != nil {
			return err
		}
		if err := os.WriteFile(f.configPath(), config, 0o640); err != nil {
			return err
		}
		if err := f.reload(ctx); err != nil {
			return err
		}
		return os.Remove(f.markerPath())
	}

	if err := f.enableDaemons(daemons); err != nil {
		return err
	}
	if err := os.WriteFile(f.configPath(), config, 0o640); err != nil {
		return err
	}
	if err := f.reload(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(f.StateDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(f.markerPath(), []byte("managed\n"), 0o644)
}

func (f *FRR) reload(ctx context.Context) error {
	cmd := f.reloadCmd()
	return runCmd(ctx, cmd[0], cmd[1:]...)
}

// enableDaemons flips wanted daemons to yes (and managed-but-unwanted
// ones to no) in the FRR daemons file, preserving everything else.
func (f *FRR) enableDaemons(wanted []string) error {
	raw, err := os.ReadFile(f.daemonsPath())
	if err != nil {
		return fmt.Errorf("FRR daemons file: %w (is FRR installed?)", err)
	}
	want := map[string]bool{}
	for _, d := range wanted {
		want[d] = true
	}
	managed := map[string]bool{"bgpd": true, "ospfd": true}

	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		name, _, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if found && managed[name] {
			if want[name] {
				out = append(out, name+"=yes")
			} else {
				out = append(out, name+"=no")
			}
			continue
		}
		out = append(out, line)
	}
	return os.WriteFile(f.daemonsPath(), []byte(strings.Join(out, "\n")), 0o640)
}

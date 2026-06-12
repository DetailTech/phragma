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

// SuricataName keys the suricata.yaml artifact.
const SuricataName = "suricata"

// Suricata supervises the Suricata IDS/IPS process. The rendered
// artifact carries an "openngfw-mode:" marker (disabled/detect/prevent)
// that selects run mode; config changes restart the process.
type Suricata struct {
	// Binary is the suricata executable; defaults to "suricata".
	Binary string
	// StateDir holds suricata.yaml and the rules/ directory.
	StateDir string
	// LogDir receives eve.json (must match the renderer Options).
	LogDir string

	proc procManager
}

// Name implements Engine.
func (s *Suricata) Name() string { return SuricataName }

func (s *Suricata) bin() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "suricata"
}

type suricataMode struct {
	mode     string
	queueNum string
}

func parseMode(config []byte) suricataMode {
	m := suricataMode{mode: "disabled", queueNum: "0"}
	sc := bufio.NewScanner(bytes.NewReader(config))
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "# openngfw-mode: "); ok {
			m.mode = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "# openngfw-queue: "); ok {
			m.queueNum = strings.TrimSpace(v)
		}
	}
	return m
}

// ensureRuleFiles creates the rules dir and any missing referenced rule
// files (empty) so `suricata -T` can resolve them; operators populate
// them via suricata-update or drop-ins.
func (s *Suricata) ensureRuleFiles(config []byte) error {
	rulesDir := filepath.Join(s.StateDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(config))
	inRuleFiles := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "rule-files:") {
			inRuleFiles = true
			continue
		}
		if inRuleFiles {
			name, ok := strings.CutPrefix(line, "  - ")
			if !ok {
				inRuleFiles = false
				continue
			}
			path := filepath.Join(rulesDir, strings.TrimSpace(name))
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					return err
				}
			}
		}
	}
	return sc.Err()
}

// Validate runs `suricata -T` against the rendered config.
func (s *Suricata) Validate(ctx context.Context, config []byte) error {
	if parseMode(config).mode == "disabled" {
		return nil
	}
	if _, err := exec.LookPath(s.bin()); err != nil {
		return fmt.Errorf("policy enables IDS but %s is not installed: %w", s.bin(), err)
	}
	if err := s.ensureRuleFiles(config); err != nil {
		return err
	}
	if err := os.MkdirAll(s.LogDir, 0o755); err != nil {
		return err
	}
	tmp, err := writeTemp(config, "openngfw-suricata-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return runCmd(ctx, s.bin(), "-T", "-c", tmp)
}

// Apply writes the config and (re)starts or stops Suricata accordingly.
func (s *Suricata) Apply(_ context.Context, config []byte) error {
	mode := parseMode(config)
	if mode.mode == "disabled" {
		s.proc.stop()
		return nil
	}
	if err := s.ensureRuleFiles(config); err != nil {
		return err
	}
	if err := os.MkdirAll(s.LogDir, 0o755); err != nil {
		return err
	}
	cfgPath := filepath.Join(s.StateDir, "suricata.yaml")
	if err := os.WriteFile(cfgPath, config, 0o644); err != nil {
		return err
	}
	switch mode.mode {
	case "detect":
		return s.proc.restart(s.bin(), "-c", cfgPath, "--af-packet")
	case "prevent":
		return s.proc.restart(s.bin(), "-c", cfgPath, "-q", mode.queueNum)
	default:
		return fmt.Errorf("unknown suricata mode %q", mode.mode)
	}
}

// Stop terminates a running Suricata (daemon shutdown).
func (s *Suricata) Stop() { s.proc.stop() }

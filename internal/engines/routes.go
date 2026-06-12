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

// RoutesName keys the static-route artifact (an ip -batch script of
// `route replace` lines).
const RoutesName = "routes"

// Routes applies static routes via `ip -batch`. It records the managed
// route set in a state file so routes removed from policy are deleted on
// the next apply — without ever touching routes we didn't create.
type Routes struct {
	// Binary is the ip executable path; defaults to "ip".
	Binary string
	// StateDir holds the managed-routes state file.
	StateDir string
}

// Name implements Engine.
func (r *Routes) Name() string { return RoutesName }

func (r *Routes) bin() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "ip"
}

// Validate checks the script is well-formed (route replace lines only).
// Kernel acceptance can only be proven on apply.
func (r *Routes) Validate(_ context.Context, config []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(config))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "route replace ") {
			return fmt.Errorf("unexpected route statement %q", line)
		}
	}
	return sc.Err()
}

func (r *Routes) statePath() string { return filepath.Join(r.StateDir, "routes.state") }

// Apply replaces managed routes and deletes ones no longer in policy.
func (r *Routes) Apply(ctx context.Context, config []byte) error {
	if err := os.MkdirAll(r.StateDir, 0o755); err != nil {
		return err
	}
	prev, _ := os.ReadFile(r.statePath()) // absent on first run

	var batch strings.Builder
	batch.Write(config)
	for _, line := range lines(prev) {
		dest := routeDest(line)
		if dest == "" {
			continue
		}
		still := false
		for _, nl := range lines(config) {
			if routeDest(nl) == dest {
				still = true
				break
			}
		}
		if !still {
			batch.WriteString("route del " + dest + "\n")
		}
	}

	if strings.TrimSpace(batch.String()) != "" {
		cmd := exec.CommandContext(ctx, r.bin(), "-batch", "-")
		cmd.Stdin = strings.NewReader(batch.String())
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip -batch: %w: %s", err, out)
		}
	}
	return os.WriteFile(r.statePath(), config, 0o644)
}

func lines(data []byte) []string {
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// routeDest extracts the destination prefix from a "route replace <dest> ..." line.
func routeDest(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 3 && fields[0] == "route" && fields[1] == "replace" {
		return fields[2]
	}
	return ""
}

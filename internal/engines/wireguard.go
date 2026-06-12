package engines

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WireguardName keys the wireguard artifact.
const WireguardName = "wireguard"

// Wireguard manages kernel WireGuard interfaces via ip/wg. Managed
// interface names are tracked in a state file so interfaces removed
// from policy are deleted — interfaces we didn't create are never
// touched.
type Wireguard struct {
	// StateDir holds the managed-interfaces state file.
	StateDir string
}

// Name implements Engine.
func (w *Wireguard) Name() string { return WireguardName }

// wgIface is the parsed form of one interface block in the artifact.
type wgIface struct {
	name           string
	address        string
	listenPort     string
	privateKeyFile string
	peers          []wgPeer
}

type wgPeer struct {
	publicKey  string
	endpoint   string
	allowedIPs string
	keepalive  string
}

func parseWireguard(config []byte) ([]wgIface, error) {
	var (
		out []wgIface
		cur *wgIface
	)
	for _, line := range lines(config) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, val, _ := strings.Cut(line, " ")
		val = strings.TrimSpace(val)
		switch key {
		case "interface":
			out = append(out, wgIface{name: val})
			cur = &out[len(out)-1]
		case "address", "listen-port", "private-key-file", "peer", "endpoint", "allowed-ips", "keepalive":
			if cur == nil {
				return nil, fmt.Errorf("wireguard artifact: %q before any interface", line)
			}
			switch key {
			case "address":
				cur.address = val
			case "listen-port":
				cur.listenPort = val
			case "private-key-file":
				cur.privateKeyFile = val
			case "peer":
				cur.peers = append(cur.peers, wgPeer{publicKey: val})
			default:
				if len(cur.peers) == 0 {
					return nil, fmt.Errorf("wireguard artifact: %q before any peer", line)
				}
				p := &cur.peers[len(cur.peers)-1]
				switch key {
				case "endpoint":
					p.endpoint = val
				case "allowed-ips":
					p.allowedIPs = val
				case "keepalive":
					p.keepalive = val
				}
			}
		default:
			return nil, fmt.Errorf("wireguard artifact: unknown directive %q", line)
		}
	}
	return out, nil
}

// Validate parses the artifact and checks tools and key files exist.
func (w *Wireguard) Validate(_ context.Context, config []byte) error {
	ifaces, err := parseWireguard(config)
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return nil
	}
	for _, bin := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("policy defines WireGuard interfaces but %s is not installed: %w", bin, err)
		}
	}
	for _, ifc := range ifaces {
		if _, err := os.Stat(ifc.privateKeyFile); err != nil {
			return fmt.Errorf("wireguard %s: private key file: %w", ifc.name, err)
		}
	}
	return nil
}

func (w *Wireguard) statePath() string { return filepath.Join(w.StateDir, "wireguard.state") }

// Apply reconciles kernel interfaces with the artifact.
func (w *Wireguard) Apply(ctx context.Context, config []byte) error {
	ifaces, err := parseWireguard(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(w.StateDir, 0o755); err != nil {
		return err
	}

	current := map[string]bool{}
	for _, ifc := range ifaces {
		current[ifc.name] = true
		if err := w.applyInterface(ctx, ifc); err != nil {
			return err
		}
	}

	// Remove managed interfaces that left the policy.
	prev, _ := os.ReadFile(w.statePath())
	for _, name := range lines(prev) {
		if !current[name] {
			_ = runCmd(ctx, "ip", "link", "del", name)
		}
	}
	names := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		names = append(names, ifc.name)
	}
	return os.WriteFile(w.statePath(), []byte(strings.Join(names, "\n")+"\n"), 0o644)
}

func (w *Wireguard) applyInterface(ctx context.Context, ifc wgIface) error {
	// Idempotent create: adding an existing link fails, which is fine.
	_ = exec.CommandContext(ctx, "ip", "link", "add", ifc.name, "type", "wireguard").Run()
	if err := runCmd(ctx, "ip", "addr", "replace", ifc.address, "dev", ifc.name); err != nil {
		return err
	}

	args := []string{"set", ifc.name, "private-key", ifc.privateKeyFile}
	if ifc.listenPort != "" {
		args = append(args, "listen-port", ifc.listenPort)
	}
	for _, p := range ifc.peers {
		args = append(args, "peer", p.publicKey, "allowed-ips", p.allowedIPs)
		if p.endpoint != "" {
			args = append(args, "endpoint", p.endpoint)
		}
		if p.keepalive != "" {
			args = append(args, "persistent-keepalive", p.keepalive)
		}
	}
	if err := runCmd(ctx, "wg", args...); err != nil {
		return err
	}
	return runCmd(ctx, "ip", "link", "set", ifc.name, "up")
}

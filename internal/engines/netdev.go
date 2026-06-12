package engines

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NetdevName keys the link-settings artifact.
const NetdevName = "netdev"

// Netdev applies global link settings: managed MTUs (ip link) and NIC
// offload state on IDS-monitored interfaces (ethtool). Settings are
// declarative-apply only: interfaces dropped from policy keep their
// last values (restoring pre-management state would require tracking
// it; documented v1 behavior).
type Netdev struct{}

// Name implements Engine.
func (n *Netdev) Name() string { return NetdevName }

type netdevDirective struct {
	kind  string // "link" or "offload"
	iface string
	mtu   string // link only
}

func parseNetdev(config []byte) ([]netdevDirective, error) {
	var out []netdevDirective
	for _, line := range lines(config) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 4 && fields[0] == "link" && fields[2] == "mtu":
			out = append(out, netdevDirective{kind: "link", iface: fields[1], mtu: fields[3]})
		case len(fields) == 3 && fields[0] == "offload" && fields[2] == "off":
			out = append(out, netdevDirective{kind: "offload", iface: fields[1]})
		default:
			return nil, fmt.Errorf("netdev artifact: unknown directive %q", line)
		}
	}
	return out, nil
}

// Validate parses the artifact and checks required tools exist.
func (n *Netdev) Validate(_ context.Context, config []byte) error {
	directives, err := parseNetdev(config)
	if err != nil {
		return err
	}
	needEthtool := false
	for _, d := range directives {
		if d.kind == "offload" {
			needEthtool = true
		}
	}
	if len(directives) > 0 {
		if _, err := exec.LookPath("ip"); err != nil {
			return fmt.Errorf("network settings need ip(8): %w", err)
		}
	}
	if needEthtool {
		if _, err := exec.LookPath("ethtool"); err != nil {
			return fmt.Errorf("policy manages NIC offloads but ethtool is not installed: %w", err)
		}
	}
	return nil
}

// Apply executes the directives.
func (n *Netdev) Apply(ctx context.Context, config []byte) error {
	directives, err := parseNetdev(config)
	if err != nil {
		return err
	}
	for _, d := range directives {
		switch d.kind {
		case "link":
			if err := runCmd(ctx, "ip", "link", "set", "dev", d.iface, "mtu", d.mtu); err != nil {
				return err
			}
		case "offload":
			if err := runCmd(ctx, "ethtool", "-K", d.iface, "gro", "off", "tso", "off", "gso", "off"); err != nil {
				return err
			}
		}
	}
	return nil
}

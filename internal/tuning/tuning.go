// Package tuning owns the Linux host sysctl baseline required for routed,
// high-connection-churn OpenNGFW appliances.
package tuning

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// DefaultConfigPath is the default persistent sysctl profile path.
	DefaultConfigPath = "/etc/sysctl.d/99-openngfw.conf"
	// DefaultSysctlRoot is the default procfs sysctl root used for live checks.
	DefaultSysctlRoot = "/proc/sys"
	// DefaultProfile is the conservative routed-appliance tuning profile.
	DefaultProfile = "appliance"
	// ThroughputProfile is the higher-headroom tuning profile for benchmark runs.
	ThroughputProfile = "throughput"
)

// Requirement describes one appliance tuning requirement and how to validate
// it. Value is the concrete value written by the generated sysctl profile.
type Requirement struct {
	Name        string
	Key         string
	Value       string
	Recommended string
	Exact       string
	Min         uint64
	Detail      string
}

// Requirements is the canonical appliance baseline used by the installer, CLI,
// API status, and WebUI readiness surfaces.
var Requirements = []Requirement{
	{
		Name:        "IPv4 forwarding",
		Key:         "net.ipv4.ip_forward",
		Value:       "1",
		Recommended: "1",
		Exact:       "1",
		Detail:      "required for routed firewall forwarding",
	},
	{
		Name:        "Reverse-path filtering (all)",
		Key:         "net.ipv4.conf.all.rp_filter",
		Value:       "0",
		Recommended: "0",
		Exact:       "0",
		Detail:      "avoids asymmetric route drops on transit firewall interfaces",
	},
	{
		Name:        "Reverse-path filtering (default)",
		Key:         "net.ipv4.conf.default.rp_filter",
		Value:       "0",
		Recommended: "0",
		Exact:       "0",
		Detail:      "prevents new interfaces from inheriting reverse-path filtering",
	},
	{
		Name:        "Conntrack table size",
		Key:         "net.netfilter.nf_conntrack_max",
		Value:       "1048576",
		Recommended: ">=1048576",
		Min:         1048576,
		Detail:      "provides state-table headroom for high connection concurrency",
	},
	{
		Name:        "Listen backlog",
		Key:         "net.core.somaxconn",
		Value:       "4096",
		Recommended: ">=4096",
		Min:         4096,
		Detail:      "provides local service backlog headroom during bursts",
	},
}

// RequirementsForProfile returns the sysctl requirements for a named appliance
// profile. The default appliance profile is conservative enough for normal
// routed operation; the throughput profile raises state-table and queue
// headroom for high-bandwidth or high-connection-churn tests.
func RequirementsForProfile(profile string) ([]Requirement, error) {
	switch normalizeProfile(profile) {
	case DefaultProfile:
		return cloneRequirements(Requirements), nil
	case ThroughputProfile:
		reqs := cloneRequirements(Requirements)
		for i := range reqs {
			switch reqs[i].Key {
			case "net.netfilter.nf_conntrack_max":
				reqs[i].Value = "4194304"
				reqs[i].Recommended = ">=4194304"
				reqs[i].Min = 4194304
				reqs[i].Detail = "provides state-table headroom for high-bandwidth and high connection concurrency profiles"
			case "net.core.somaxconn":
				reqs[i].Value = "8192"
				reqs[i].Recommended = ">=8192"
				reqs[i].Min = 8192
				reqs[i].Detail = "provides local service backlog headroom during high-throughput bursts"
			}
		}
		reqs = append(reqs, Requirement{
			Name:        "Network device backlog",
			Key:         "net.core.netdev_max_backlog",
			Value:       "250000",
			Recommended: ">=250000",
			Min:         250000,
			Detail:      "provides packet queue headroom during high-throughput bursts",
		})
		return reqs, nil
	default:
		return nil, fmt.Errorf("unknown tuning profile %q; valid profiles: %s", profile, strings.Join(Profiles(), ", "))
	}
}

// Profiles returns valid appliance tuning profile names.
func Profiles() []string {
	return []string{DefaultProfile, ThroughputProfile}
}

// ConfigText returns the persistent sysctl profile written by the installer and
// ngfwctl system tune.
func ConfigText() string {
	text, _ := ConfigTextForProfile(DefaultProfile)
	return text
}

// ConfigTextForProfile returns the persistent sysctl profile for a named
// appliance tuning profile.
func ConfigTextForProfile(profile string) (string, error) {
	name := normalizeProfile(profile)
	reqs, err := RequirementsForProfile(name)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	b.WriteString("# OpenNGFW appliance baseline.\n")
	if name == ThroughputProfile {
		b.WriteString("# Values target high-bandwidth or high-connection-churn virtual firewall runs.\n")
	} else {
		b.WriteString("# Values are intentionally conservative and target a single-node routed virtual firewall.\n")
	}
	fmt.Fprintf(&b, "# profile: %s\n", name)
	for _, req := range reqs {
		fmt.Fprintf(&b, "%s = %s\n", req.Key, req.Value)
	}
	return b.String(), nil
}

// WriteConfig writes the persistent sysctl profile.
func WriteConfig(path string) error {
	return WriteConfigForProfile(path, DefaultProfile)
}

// WriteConfigForProfile writes the persistent sysctl profile for a named
// appliance tuning profile.
func WriteConfigForProfile(path string, profile string) error {
	if path == "" {
		path = DefaultConfigPath
	}
	text, err := ConfigTextForProfile(profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create sysctl config directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return fmt.Errorf("write sysctl config %s: %w", path, err)
	}
	return nil
}

// ApplyResult records one live sysctl attempt.
type ApplyResult struct {
	Key     string
	Value   string
	Applied bool
	Skipped bool
	Detail  string
}

// Runner executes one sysctl command.
type Runner func(context.Context, string, ...string) ([]byte, error)

// ApplyLive applies exposed baseline keys to the live kernel.
func ApplyLive(ctx context.Context, sysctlRoot string, run Runner) ([]ApplyResult, error) {
	return ApplyLiveProfile(ctx, sysctlRoot, DefaultProfile, run)
}

// ApplyLiveProfile applies exposed baseline keys for the named profile to the
// live kernel.
func ApplyLiveProfile(ctx context.Context, sysctlRoot string, profile string, run Runner) ([]ApplyResult, error) {
	if sysctlRoot == "" {
		sysctlRoot = DefaultSysctlRoot
	}
	if run == nil {
		run = execSysctl
	}
	reqs, err := RequirementsForProfile(profile)
	if err != nil {
		return nil, err
	}
	results := make([]ApplyResult, 0, len(reqs))
	for _, req := range reqs {
		result := ApplyResult{Key: req.Key, Value: req.Value}
		procPath := filepath.Join(sysctlRoot, strings.ReplaceAll(req.Key, ".", string(os.PathSeparator)))
		if _, err := os.Stat(procPath); err != nil {
			if os.IsNotExist(err) {
				result.Skipped = true
				result.Detail = "not exposed by this kernel"
				results = append(results, result)
				continue
			}
			return results, fmt.Errorf("inspect %s: %w", req.Key, err)
		}
		out, err := run(ctx, "sysctl", "-w", req.Key+"="+req.Value)
		if err != nil {
			return results, fmt.Errorf("apply %s: %w%s", req.Key, err, commandOutput(out))
		}
		result.Applied = true
		result.Detail = strings.TrimSpace(string(out))
		results = append(results, result)
	}
	return results, nil
}

func cloneRequirements(reqs []Requirement) []Requirement {
	out := make([]Requirement, len(reqs))
	copy(out, reqs)
	return out
}

func normalizeProfile(profile string) string {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return DefaultProfile
	}
	return profile
}

func execSysctl(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func commandOutput(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return ""
	}
	return ": " + text
}

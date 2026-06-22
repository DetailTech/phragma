package engines

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const haPromotionStateFile = "ha-promotion.state"

// HAPromotionRoute is one Linux route promoted with a local HA VIP.
type HAPromotionRoute struct {
	Destination netip.Prefix
	Via         netip.Addr
	Interface   string
	Metric      uint32
}

// HAPromotionResult summarizes the bounded Linux-local cutover action.
type HAPromotionResult struct {
	VIP             string
	Interface       string
	Routes          []string
	VIPsRemoved     int
	RoutesRemoved   int
	Announcements   int
	GARPState       string
	GARPDetail      string
	NeighborState   string
	NeighborDetail  string
	ObservedAt      string
	Warnings        []string
	TransportClaim  string
	ManagedStateKey string
}

// HAPromotion applies Linux-local HA VIP and route ownership. It owns only
// entries recorded in its state file; peer fencing and conntrack sync are
// intentionally outside this primitive.
type HAPromotion struct {
	Binary     string
	ArpBinary  string
	StateDir   string
	Interface  string
	VIP        netip.Prefix
	Routes     []HAPromotionRoute
	AnnounceIP bool
	run        func(context.Context, string, ...string) error
	runOutput  func(context.Context, string, ...string) ([]byte, error)
}

type haPromotionState struct {
	Interface string   `json:"interface"`
	VIP       string   `json:"vip"`
	Routes    []string `json:"routes,omitempty"`
}

func (p *HAPromotion) bin() string {
	if strings.TrimSpace(p.Binary) != "" {
		return strings.TrimSpace(p.Binary)
	}
	return "ip"
}

func (p *HAPromotion) arping() string {
	if strings.TrimSpace(p.ArpBinary) != "" {
		return strings.TrimSpace(p.ArpBinary)
	}
	return "arping"
}

func (p *HAPromotion) runner() func(context.Context, string, ...string) error {
	if p.run != nil {
		return p.run
	}
	return runHAPromotionCommand
}

func (p *HAPromotion) outputRunner() func(context.Context, string, ...string) ([]byte, error) {
	if p.runOutput != nil {
		return p.runOutput
	}
	return runHAPromotionOutput
}

// Validate checks that the promotion target is bounded and command-safe.
func (p *HAPromotion) Validate(_ context.Context) error {
	if p == nil {
		return fmt.Errorf("HA promotion is not configured")
	}
	if strings.TrimSpace(p.StateDir) == "" {
		return fmt.Errorf("HA promotion state directory is required")
	}
	if err := validateHAInterface(p.Interface); err != nil {
		return err
	}
	if !p.VIP.IsValid() || !p.VIP.Addr().IsValid() {
		return fmt.Errorf("HA promotion VIP is required")
	}
	seenRoutes := map[string]struct{}{}
	for _, route := range p.Routes {
		if !route.Destination.IsValid() {
			return fmt.Errorf("HA promotion route destination is required")
		}
		if !route.Via.IsValid() && strings.TrimSpace(route.Interface) == "" {
			return fmt.Errorf("HA promotion route %s requires via or interface", route.Destination)
		}
		if route.Interface != "" {
			if err := validateHAInterface(route.Interface); err != nil {
				return fmt.Errorf("HA promotion route %s: %w", route.Destination, err)
			}
		}
		key := routeLine(route)
		if _, ok := seenRoutes[key]; ok {
			return fmt.Errorf("duplicate HA promotion route %s", key)
		}
		seenRoutes[key] = struct{}{}
	}
	return nil
}

// Promote applies the configured VIP and routes, and removes stale entries
// recorded by the previous OpenNGFW promotion state.
func (p *HAPromotion) Promote(ctx context.Context) (HAPromotionResult, error) {
	if err := p.Validate(ctx); err != nil {
		return HAPromotionResult{}, err
	}
	prev, _ := readHAPromotionState(p.statePath())
	next := p.state()
	run := p.runner()
	result := HAPromotionResult{
		VIP:             p.VIP.String(),
		Interface:       p.Interface,
		Routes:          next.Routes,
		GARPState:       "not_requested",
		GARPDetail:      "gratuitous ARP announcement was not requested",
		NeighborState:   "not_sampled",
		NeighborDetail:  "neighbor table was not sampled",
		ObservedAt:      "",
		TransportClaim:  "linux_local_vip_route_promoted",
		ManagedStateKey: haPromotionStateFile,
	}

	if prev.VIP != "" && (prev.VIP != next.VIP || prev.Interface != next.Interface) {
		if err := run(ctx, p.bin(), "addr", "del", prev.VIP, "dev", prev.Interface); err != nil {
			return result, fmt.Errorf("remove stale HA VIP %s dev %s: %w", prev.VIP, prev.Interface, err)
		}
		result.VIPsRemoved++
	}
	nextRoutes := map[string]struct{}{}
	for _, route := range next.Routes {
		nextRoutes[route] = struct{}{}
	}
	for _, route := range prev.Routes {
		if _, ok := nextRoutes[route]; ok {
			continue
		}
		dest := strings.Fields(route)
		if len(dest) == 0 {
			continue
		}
		if err := run(ctx, p.bin(), "route", "del", dest[0]); err != nil {
			return result, fmt.Errorf("remove stale HA route %s: %w", dest[0], err)
		}
		result.RoutesRemoved++
	}
	if err := run(ctx, p.bin(), "addr", "replace", p.VIP.String(), "dev", p.Interface); err != nil {
		return result, fmt.Errorf("promote HA VIP %s dev %s: %w", p.VIP, p.Interface, err)
	}
	if p.AnnounceIP && p.VIP.Addr().Is4() {
		if err := run(ctx, p.arping(), "-A", "-c", "3", "-I", p.Interface, p.VIP.Addr().String()); err != nil {
			result.GARPState = "failed"
			result.GARPDetail = fmt.Sprintf("gratuitous ARP failed for %s on %s: %v", p.VIP.Addr(), p.Interface, err)
			result.Warnings = append(result.Warnings, result.GARPDetail)
		} else {
			result.Announcements++
			result.GARPState = "sent"
			result.GARPDetail = fmt.Sprintf("sent %d gratuitous ARP announcement(s) for %s on %s", result.Announcements, p.VIP.Addr(), p.Interface)
		}
	}
	result.NeighborState, result.NeighborDetail = p.neighborProof(ctx)
	for _, route := range p.Routes {
		args := append([]string{"route", "replace"}, routeArgs(route)...)
		if p.VIP.Addr().IsValid() {
			args = append(args, "src", p.VIP.Addr().String())
		}
		if err := run(ctx, p.bin(), args...); err != nil {
			return result, fmt.Errorf("promote HA route %s: %w", route.Destination, err)
		}
	}
	if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
		return result, err
	}
	if err := writeHAPromotionState(p.statePath(), next); err != nil {
		return result, err
	}
	result.ObservedAt = timeNowUTC()
	return result, nil
}

func (p *HAPromotion) neighborProof(ctx context.Context) (string, string) {
	out, err := p.outputRunner()(ctx, p.bin(), "-j", "neigh", "show", "dev", p.Interface)
	if err != nil {
		return "unavailable", fmt.Sprintf("neighbor table sample failed for %s: %v", p.Interface, err)
	}
	sample := strings.TrimSpace(string(out))
	if sample == "" || sample == "[]" {
		return "sampled_empty", fmt.Sprintf("neighbor table sample for %s returned no entries after VIP promotion", p.Interface)
	}
	return "sampled", "neighbor table sample after VIP promotion: " + capHAPromotionEvidence(sample, 600)
}

func capHAPromotionEvidence(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "...(truncated)"
}

var timeNowUTC = func() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (p *HAPromotion) statePath() string {
	return filepath.Join(p.StateDir, haPromotionStateFile)
}

func (p *HAPromotion) state() haPromotionState {
	state := haPromotionState{Interface: p.Interface, VIP: p.VIP.String()}
	for _, route := range p.Routes {
		state.Routes = append(state.Routes, routeLine(route))
	}
	return state
}

func validateHAInterface(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("HA promotion interface is required")
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == ':' {
			continue
		}
		return fmt.Errorf("HA promotion interface %q contains unsupported character %q", value, r)
	}
	return nil
}

func routeLine(route HAPromotionRoute) string {
	return strings.Join(routeArgs(route), " ")
}

func routeArgs(route HAPromotionRoute) []string {
	args := []string{route.Destination.String()}
	if route.Via.IsValid() {
		args = append(args, "via", route.Via.String())
	}
	if strings.TrimSpace(route.Interface) != "" {
		args = append(args, "dev", route.Interface)
	}
	if route.Metric != 0 {
		args = append(args, "metric", strconv.FormatUint(uint64(route.Metric), 10))
	}
	return args
}

func readHAPromotionState(path string) (haPromotionState, error) {
	var state haPromotionState
	raw, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	return state, json.Unmarshal(raw, &state)
}

func writeHAPromotionState(path string, state haPromotionState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func runHAPromotionCommand(ctx context.Context, name string, args ...string) error {
	out, err := runHAPromotionOutput(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runHAPromotionOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

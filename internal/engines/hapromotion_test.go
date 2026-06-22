package engines

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHAPromotionValidateRejectsUnsafeConfig(t *testing.T) {
	vip := netip.MustParsePrefix("192.0.2.10/32")
	for name, promotion := range map[string]*HAPromotion{
		"nil":           nil,
		"missing state": {Interface: "eth0", VIP: vip},
		"missing iface": {StateDir: t.TempDir(), VIP: vip},
		"bad iface":     {StateDir: t.TempDir(), Interface: "eth0;reboot", VIP: vip},
		"missing vip":   {StateDir: t.TempDir(), Interface: "eth0"},
		"bad route": {
			StateDir:  t.TempDir(),
			Interface: "eth0",
			VIP:       vip,
			Routes:    []HAPromotionRoute{{Destination: netip.MustParsePrefix("198.51.100.0/24")}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := promotion.Validate(context.Background()); err == nil {
				t.Fatalf("Validate(%s) succeeded unexpectedly", name)
			}
		})
	}
}

func TestHAPromotionPromoteAppliesDesiredStateAndRemovesManagedStaleEntries(t *testing.T) {
	dir := t.TempDir()
	prev := haPromotionState{
		Interface: "eth1",
		VIP:       "192.0.2.11/32",
		Routes:    []string{"198.51.100.0/24 dev eth1"},
	}
	if err := writeHAPromotionState(filepath.Join(dir, haPromotionStateFile), prev); err != nil {
		t.Fatal(err)
	}
	var calls []string
	promotion := &HAPromotion{
		StateDir:   dir,
		Interface:  "eth0",
		VIP:        netip.MustParsePrefix("192.0.2.10/32"),
		AnnounceIP: true,
		Routes: []HAPromotionRoute{{
			Destination: netip.MustParsePrefix("203.0.113.0/24"),
			Via:         netip.MustParseAddr("192.0.2.1"),
			Interface:   "eth0",
			Metric:      50,
		}},
		run: func(_ context.Context, name string, args ...string) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil
		},
		runOutput: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte(`[{"dst":"192.0.2.1","dev":"eth0","state":["REACHABLE"]}]`), nil
		},
	}
	result, err := promotion.Promote(context.Background())
	if err != nil {
		t.Fatalf("Promote returned error: %v", err)
	}
	for _, want := range []string{
		"ip addr del 192.0.2.11/32 dev eth1",
		"ip route del 198.51.100.0/24",
		"ip addr replace 192.0.2.10/32 dev eth0",
		"arping -A -c 3 -I eth0 192.0.2.10",
		"ip -j neigh show dev eth0",
		"ip route replace 203.0.113.0/24 via 192.0.2.1 dev eth0 metric 50 src 192.0.2.10",
	} {
		if !haPromotionHasCall(calls, want) {
			t.Fatalf("missing call %q in %#v", want, calls)
		}
	}
	if result.TransportClaim != "linux_local_vip_route_promoted" || result.VIPsRemoved != 1 || result.RoutesRemoved != 1 || result.Announcements != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.GARPState != "sent" || result.NeighborState != "sampled" || !strings.Contains(result.NeighborDetail, "REACHABLE") || result.ObservedAt == "" {
		t.Fatalf("promotion evidence missing GARP/neighbor proof: %+v", result)
	}
	raw, err := os.ReadFile(filepath.Join(dir, haPromotionStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "192.0.2.11") || !strings.Contains(string(raw), "192.0.2.10/32") || !strings.Contains(string(raw), "203.0.113.0/24") {
		t.Fatalf("state file did not record desired managed entries:\n%s", raw)
	}
}

func TestHAPromotionAnnouncementWarningDoesNotFailPromotion(t *testing.T) {
	var calls []string
	promotion := &HAPromotion{
		StateDir:   t.TempDir(),
		Interface:  "eth0",
		VIP:        netip.MustParsePrefix("192.0.2.10/32"),
		AnnounceIP: true,
		run: func(_ context.Context, name string, args ...string) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "arping" {
				return errHAPromotion("arp unavailable")
			}
			return nil
		},
		runOutput: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte(`[]`), nil
		},
	}
	result, err := promotion.Promote(context.Background())
	if err != nil {
		t.Fatalf("Promote returned error: %v", err)
	}
	if result.Announcements != 0 || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "gratuitous ARP failed") {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.GARPState != "failed" || result.NeighborState != "sampled_empty" {
		t.Fatalf("unexpected warning evidence states: %+v", result)
	}
	if !haPromotionHasCall(calls, "ip addr replace 192.0.2.10/32 dev eth0") {
		t.Fatalf("VIP promotion call missing: %#v", calls)
	}
}

type errHAPromotion string

func (e errHAPromotion) Error() string { return string(e) }

func haPromotionHasCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

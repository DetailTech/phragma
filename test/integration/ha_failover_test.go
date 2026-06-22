//go:build integration

package integration

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/store"
)

const (
	haLiveVIP   = "198.18.0.10/32"
	haLiveRoute = "198.19.0.0/24"
)

func TestHALiveActivationPromotesVIPAndRoute(t *testing.T) {
	requireHALiveRoot(t)
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command not installed")
	}
	iface := setupHALiveInterface(t)

	dir := t.TempDir()
	haStateDir := filepath.Join(dir, "ha")
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	runningVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "replicated"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "replicated baseline")
	if err != nil {
		t.Fatalf("commit running policy: %v", err)
	}
	lkg, err := st.GetVersionInfo(runningVersion)
	if err != nil {
		t.Fatalf("read lkg: %v", err)
	}

	svc := &apiserver.SystemService{Store: st, Status: apiserver.SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPromoter: &engines.HAPromotion{
			StateDir:  haStateDir,
			Interface: iface,
			VIP:       netip.MustParsePrefix(haLiveVIP),
			Routes: []engines.HAPromotionRoute{{
				Destination: netip.MustParsePrefix(haLiveRoute),
				Interface:   iface,
				Metric:      50,
			}},
		},
		HighAvailabilityPeerEvidence: func(context.Context) (*apiserver.HighAvailabilityPeerEvidence, error) {
			return &apiserver.HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: runningVersion,
				ArtifactSetSHA256:    lkg.ArtifactSetSHA256,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "active peer heartbeat",
			}, nil
		},
	}}

	resp, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "live local vip promotion",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if err != nil {
		t.Fatalf("ActivateHighAvailabilityFailover: %v", err)
	}
	if !strings.Contains(resp.GetAfter().GetDetail(), "Linux-local VIP/route promotion completed") {
		t.Fatalf("activation response missing VIP/route promotion detail: %+v", resp.GetAfter())
	}

	state, ok, err := st.GetHighAvailabilityState()
	if err != nil || !ok {
		t.Fatalf("read HA state ok=%v err=%v", ok, err)
	}
	if state.Role != "active" || state.TransportClaim != "linux_local_vip_route_promoted" {
		t.Fatalf("unexpected HA state after activation: %+v", state)
	}
	if !hasHALiveAuditAction(t, st, "ha-failover-activate-intent") || !hasHALiveAuditAction(t, st, "ha-failover-activate") {
		t.Fatalf("activation audit records missing")
	}

	addr := run(t, "ip", "addr", "show", "dev", iface)
	if !strings.Contains(addr, haLiveVIP) {
		t.Fatalf("VIP not present on %s:\n%s", iface, addr)
	}
	route := run(t, "ip", "route", "show", haLiveRoute)
	if !strings.Contains(route, "dev "+iface) ||
		!strings.Contains(route, "src "+strings.TrimSuffix(haLiveVIP, "/32")) ||
		!strings.Contains(route, "metric 50") {
		t.Fatalf("promoted route missing expected dev/src/metric:\n%s", route)
	}
	rawState, err := os.ReadFile(filepath.Join(haStateDir, "ha-promotion.state"))
	if err != nil {
		t.Fatalf("read HA promotion state: %v", err)
	}
	stateText := string(rawState)
	if !strings.Contains(stateText, iface) || !strings.Contains(stateText, haLiveVIP) || !strings.Contains(stateText, haLiveRoute) {
		t.Fatalf("HA promotion state missing managed VIP/route:\n%s", stateText)
	}
}

func requireHALiveRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("HA live activation test requires root")
	}
}

func setupHALiveInterface(t *testing.T) string {
	t.Helper()
	iface := "ngfwha" + strconv.Itoa(os.Getpid()%100000)
	runQuiet("ip", "route", "del", haLiveRoute)
	runQuiet("ip", "addr", "del", haLiveVIP, "dev", iface)
	runQuiet("ip", "link", "del", iface)
	run(t, "ip", "link", "add", iface, "type", "dummy")
	run(t, "ip", "link", "set", iface, "up")
	t.Cleanup(func() {
		runQuiet("ip", "route", "del", haLiveRoute)
		runQuiet("ip", "addr", "del", haLiveVIP, "dev", iface)
		runQuiet("ip", "link", "del", iface)
	})
	return iface
}

func hasHALiveAuditAction(t *testing.T, st *store.Store, action string) bool {
	t.Helper()
	entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditFiltered(%s): %v", action, err)
	}
	return len(entries) > 0
}

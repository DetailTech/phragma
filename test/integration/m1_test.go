//go:build integration

// M1 end-to-end test against real engines: nftables in the kernel, real
// network namespaces, real TCP traffic. Requires root, nft, ip, and nc.
//
//	make integration-test
//
// Topology (all veth):
//
//	client ns (10.100.1.2) ── cveth0 (10.100.1.1) [FW = root ns] sveth0 (10.100.2.1) ── server ns (10.100.2.2)
//
// The root namespace acts as the firewall: it forwards between the two
// veths under the policy committed through the real PolicyServer stack.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/store"
)

const (
	clientNS = "ngfw-it-client"
	serverNS = "ngfw-it-server"
	fwClient = "10.100.1.1" // firewall-side addresses
	fwServer = "10.100.2.1"
	clientIP = "10.100.1.2"
	serverIP = "10.100.2.2"
)

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}

func runQuiet(name string, args ...string) { _ = exec.Command(name, args...).Run() }

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}
	for _, bin := range []string{"nft", "ip", "nc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("integration test requires %s", bin)
		}
	}
	if err := exec.Command("nft", "list", "tables").Run(); err != nil {
		t.Skip("kernel does not expose nftables here")
	}
}

func teardown() {
	runQuiet("ip", "netns", "del", clientNS)
	runQuiet("ip", "netns", "del", serverNS)
	runQuiet("ip", "link", "del", "cveth0")
	runQuiet("ip", "link", "del", "sveth0")
	runQuiet("nft", "delete", "table", "inet", "openngfw")
	runQuiet("iptables", "-D", "FORWARD", "-s", "10.100.0.0/16", "-j", "ACCEPT")
	runQuiet("iptables", "-D", "FORWARD", "-d", "10.100.0.0/16", "-j", "ACCEPT")
}

func setupTopology(t *testing.T) {
	t.Helper()
	teardown() // clean any leftovers from a previous failed run
	t.Cleanup(teardown)

	run(t, "ip", "netns", "add", clientNS)
	run(t, "ip", "netns", "add", serverNS)

	run(t, "ip", "link", "add", "cveth0", "type", "veth", "peer", "name", "cpeer0")
	run(t, "ip", "link", "set", "cpeer0", "netns", clientNS)
	run(t, "ip", "addr", "add", fwClient+"/24", "dev", "cveth0")
	run(t, "ip", "link", "set", "cveth0", "up")
	run(t, "ip", "netns", "exec", clientNS, "ip", "addr", "add", clientIP+"/24", "dev", "cpeer0")
	run(t, "ip", "netns", "exec", clientNS, "ip", "link", "set", "cpeer0", "up")
	run(t, "ip", "netns", "exec", clientNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", clientNS, "ip", "route", "add", "default", "via", fwClient)

	run(t, "ip", "link", "add", "sveth0", "type", "veth", "peer", "name", "speer0")
	run(t, "ip", "link", "set", "speer0", "netns", serverNS)
	run(t, "ip", "addr", "add", fwServer+"/24", "dev", "sveth0")
	run(t, "ip", "link", "set", "sveth0", "up")
	run(t, "ip", "netns", "exec", serverNS, "ip", "addr", "add", serverIP+"/24", "dev", "speer0")
	run(t, "ip", "netns", "exec", serverNS, "ip", "link", "set", "speer0", "up")
	run(t, "ip", "netns", "exec", serverNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", serverNS, "ip", "route", "add", "default", "via", fwServer)

	run(t, "sysctl", "-w", "net.ipv4.ip_forward=1")

	// Docker hosts (GitHub runners included) set the legacy iptables
	// FORWARD policy to DROP. Every netfilter hook must accept a
	// forwarded packet, so allow the test subnets in that hook too —
	// scoped tightly and removed in teardown.
	runQuiet("iptables", "-I", "FORWARD", "1", "-s", "10.100.0.0/16", "-j", "ACCEPT")
	runQuiet("iptables", "-I", "FORWARD", "1", "-d", "10.100.0.0/16", "-j", "ACCEPT")
}

// startEchoServer runs a TCP listener on serverIP:8080 inside the server
// namespace for the duration of the test.
func startEchoServer(t *testing.T) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", serverNS,
		"sh", "-c", "while true; do echo pong | nc -l -p 8080 -q 0; done")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		runQuiet("pkill", "-f", "nc -l -p 8080")
	})
	time.Sleep(300 * time.Millisecond)
}

// tcpReachable attempts a TCP connection from the client namespace.
func tcpReachable(addr string, port int) bool {
	cmd := exec.Command("ip", "netns", "exec", clientNS,
		"nc", "-z", "-w", "2", addr, fmt.Sprintf("%d", port))
	return cmd.Run() == nil
}

// newStack builds the real M1 stack (store + engines + policy server) in
// a temp dir.
func newStack(t *testing.T) *apiserver.PolicyServer {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/store.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sup := engines.NewSupervisor(
		&engines.Nftables{StateDir: dir},
		&engines.Routes{StateDir: dir},
	)
	opts := renderers.DefaultOptions(dir, dir+"/log")
	return apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
}

func allowPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "outside", Interfaces: []string{"cveth0"}},
			{Name: "inside", Interfaces: []string{"sveth0"}},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "server", Cidr: serverIP + "/32"},
			{Name: "fw-outside", Cidr: fwClient + "/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "echo", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 8080}}},
		},
		Rules: []*openngfwv1.Rule{{
			Name: "client-to-server", FromZones: []string{"outside"}, ToZones: []string{"inside"},
			DestinationAddresses: []string{"server"}, Services: []string{"echo"},
			Action: openngfwv1.Action_ACTION_ALLOW, Log: true,
		}},
	}
}

func mustCommit(t *testing.T, srv *apiserver.PolicyServer, p *openngfwv1.Policy, comment string) uint64 {
	t.Helper()
	ctx := context.Background()
	if _, err := srv.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Commit(ctx, &openngfwv1.CommitRequest{Comment: comment})
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetVersion()
}

func TestM1EndToEnd(t *testing.T) {
	requireRoot(t)
	setupTopology(t)
	startEchoServer(t)
	srv := newStack(t)
	ctx := context.Background()

	// Baseline sanity: with no firewall table, forwarding works.
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("topology broken: server unreachable before any policy")
	}

	// 1. Commit an empty policy: default-drop must block the flow.
	emptyVersion := mustCommit(t, srv, &openngfwv1.Policy{}, "baseline empty policy")
	if tcpReachable(serverIP, 8080) {
		t.Fatal("default-drop policy did not block traffic")
	}

	// 2. Commit the allow policy: flow must pass.
	allowVersion := mustCommit(t, srv, allowPolicy(), "allow client to server")
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("allow rule did not pass traffic")
	}

	// 3. A *failing* commit must leave the running config untouched.
	bad := allowPolicy()
	bad.Rules[0].FromZones = []string{"no-such-zone"}
	if _, err := srv.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: bad}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Commit(ctx, &openngfwv1.CommitRequest{Comment: "should fail"}); err == nil {
		t.Fatal("commit of invalid policy must fail")
	}
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("failed commit disturbed the running ruleset")
	}

	// 4. DNAT: client hits the firewall's outside IP, lands on the server.
	dnat := allowPolicy()
	dnat.Rules = append(dnat.Rules, &openngfwv1.Rule{
		Name: "dnat-pass", FromZones: []string{"outside"}, ToZones: []string{"inside"},
		Services: []string{"echo"}, Action: openngfwv1.Action_ACTION_ALLOW,
	})
	dnat.Nat = &openngfwv1.Nat{
		Destination: []*openngfwv1.DestinationNat{{
			Name: "to-server", FromZone: "outside", Service: "echo",
			DestinationAddress: "fw-outside", TranslatedAddress: "server",
		}},
		Source: []*openngfwv1.SourceNat{{
			Name: "masq", ToZone: "inside", Masquerade: true,
		}},
	}
	mustCommit(t, srv, dnat, "dnat to server")
	if !tcpReachable(fwClient, 8080) {
		t.Fatal("DNAT did not redirect firewall IP to server")
	}

	// 5. Static routes are programmed and withdrawn.
	routed := allowPolicy()
	routed.StaticRoutes = []*openngfwv1.StaticRoute{{Destination: "192.168.77.0/24", Via: serverIP}}
	mustCommit(t, srv, routed, "add static route")
	if !strings.Contains(run(t, "ip", "route", "show", "192.168.77.0/24"), "192.168.77.0/24") {
		t.Fatal("static route not programmed")
	}
	mustCommit(t, srv, allowPolicy(), "remove static route")
	if strings.Contains(run(t, "ip", "route", "show", "192.168.77.0/24"), "192.168.77.0/24") {
		t.Fatal("stale static route not removed")
	}

	// 6. Rollback to the empty policy blocks traffic again…
	if _, err := srv.Rollback(ctx, &openngfwv1.RollbackRequest{Version: emptyVersion}); err != nil {
		t.Fatal(err)
	}
	if tcpReachable(serverIP, 8080) {
		t.Fatal("rollback to empty policy did not block traffic")
	}
	// …and rollback forward to the allow version restores it.
	if _, err := srv.Rollback(ctx, &openngfwv1.RollbackRequest{Version: allowVersion}); err != nil {
		t.Fatal(err)
	}
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("rollback to allow version did not restore traffic")
	}

	// 7. Every action above is in the audit log.
	audit, err := srv.ListAuditEntries(ctx, &openngfwv1.ListAuditEntriesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, e := range audit.GetEntries() {
		actions[e.GetAction()]++
	}
	if actions["commit"] < 4 || actions["rollback"] < 2 || actions["commit-failed"] < 1 || actions["set-candidate"] < 5 {
		t.Fatalf("audit log incomplete: %v", actions)
	}

	// 8. The kernel ruleset is exactly ours.
	ruleset := run(t, "nft", "list", "table", "inet", "openngfw")
	if !strings.Contains(ruleset, `comment "rule:client-to-server"`) {
		t.Fatalf("expected rule comment in live ruleset:\n%s", ruleset)
	}
}

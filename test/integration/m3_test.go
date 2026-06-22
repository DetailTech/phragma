//go:build integration

// M3 live-networking tests: policy-managed static routes change real packet
// flow across network namespaces, policy-managed FRR BGP learns a route
// from a netns peer and programs the kernel route table, and policy-managed
// WireGuard interfaces establish a netns peer handshake and pass overlay TCP.
// Requires Linux root plus the tools each test checks before running.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	m3RouteNS       = "ngfw-it-m3-route"
	m3RouteCIDR     = "198.18.3.0/24"
	m3RouteGateway  = "198.18.3.1"
	m3RouteTargetIP = "198.18.3.2"
	m3RoutePort     = 8081

	m3WireguardNS             = "ngfw-it-m3-wg"
	m3WireguardIf             = "ngfwm3wg0"
	m3WireguardPeerIf         = "ngfwm3peer"
	m3WireguardUnderlayRootIf = "ngfwm3u0"
	m3WireguardUnderlayPeerIf = "ngfwm3p0"
	m3WireguardUnderlayRootIP = "198.18.33.1"
	m3WireguardUnderlayPeerIP = "198.18.33.2"
	m3WireguardTunnelCIDR     = "198.18.103.0/24"
	m3WireguardRootTunnelIP   = "198.18.103.1"
	m3WireguardPeerTunnelIP   = "198.18.103.2"
	m3WireguardRootListenPort = 51891
	m3WireguardPeerListenPort = 51892
	m3WireguardEchoPort       = 8082

	m3BGPNS            = "ngfw-it-m3-bgp"
	m3BGPRootIf        = "ngfwm3bgr0"
	m3BGPPeerIf        = "ngfwm3bgp0"
	m3BGPRootIP        = "198.18.53.1"
	m3BGPPeerIP        = "198.18.53.2"
	m3BGPRootASN       = 65001
	m3BGPPeerASN       = 65002
	m3BGPLearnedCIDR   = "198.18.153.0/24"
	m3BGPLearnedHostIP = "198.18.153.1"
)

func TestM3StaticRouteProgramsLiveForwarding(t *testing.T) {
	requireRoot(t)
	if out := strings.TrimSpace(run(t, "ip", "route", "show", m3RouteCIDR)); out != "" {
		t.Skipf("M3 test route %s already exists on host: %s", m3RouteCIDR, out)
	}
	t.Cleanup(func() { runQuiet("ip", "route", "del", m3RouteCIDR) })

	setupTopology(t)
	setupM3RouteBranch(t)
	startM3EchoServer(t)
	srv := newStack(t)

	// The branch subnet exists behind serverNS, but the firewall/root
	// namespace should not know how to reach it until policy programs
	// the managed static route.
	if tcpReachable(m3RouteTargetIP, m3RoutePort) {
		t.Fatal("branch namespace reachable before M3 static route was committed")
	}

	pol := m3RoutePolicy()
	mustCommit(t, srv, pol, "m3 route branch")

	route := run(t, "ip", "route", "show", m3RouteCIDR)
	for _, want := range []string{m3RouteCIDR, "via " + serverIP, "dev sveth0"} {
		if !strings.Contains(route, want) {
			t.Fatalf("managed route missing %q:\n%s", want, route)
		}
	}
	if !tcpReachable(m3RouteTargetIP, m3RoutePort) {
		t.Fatal("branch namespace unreachable after M3 static route was committed")
	}

	noRoute := m3RoutePolicy()
	noRoute.StaticRoutes = nil
	mustCommit(t, srv, noRoute, "remove m3 route branch")
	if out := run(t, "ip", "route", "show", m3RouteCIDR); strings.TrimSpace(out) != "" {
		t.Fatalf("managed route was not removed:\n%s", out)
	}
	if tcpReachable(m3RouteTargetIP, m3RoutePort) {
		t.Fatal("branch namespace still reachable after managed static route was removed")
	}
}

func setupM3RouteBranch(t *testing.T) {
	t.Helper()
	teardownM3RouteBranch()
	t.Cleanup(teardownM3RouteBranch)

	run(t, "ip", "netns", "add", m3RouteNS)
	run(t, "ip", "link", "add", "m3srv0", "type", "veth", "peer", "name", "m3peer0")
	run(t, "ip", "link", "set", "m3srv0", "netns", serverNS)
	run(t, "ip", "link", "set", "m3peer0", "netns", m3RouteNS)

	run(t, "ip", "netns", "exec", serverNS, "ip", "addr", "add", m3RouteGateway+"/24", "dev", "m3srv0")
	run(t, "ip", "netns", "exec", serverNS, "ip", "link", "set", "m3srv0", "up")
	run(t, "ip", "netns", "exec", serverNS, "sysctl", "-w", "net.ipv4.ip_forward=1")

	run(t, "ip", "netns", "exec", m3RouteNS, "ip", "addr", "add", m3RouteTargetIP+"/24", "dev", "m3peer0")
	run(t, "ip", "netns", "exec", m3RouteNS, "ip", "link", "set", "m3peer0", "up")
	run(t, "ip", "netns", "exec", m3RouteNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", m3RouteNS, "ip", "route", "add", "default", "via", m3RouteGateway)
}

func teardownM3RouteBranch() {
	runQuiet("ip", "netns", "exec", serverNS, "ip", "link", "del", "m3srv0")
	runQuiet("ip", "netns", "del", m3RouteNS)
}

func startM3EchoServer(t *testing.T) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", m3RouteNS,
		"sh", "-c", netcatListenLoop(m3RoutePort, "m3-pong"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		runQuiet("pkill", "-f", fmt.Sprintf("nc -l -p %d", m3RoutePort))
	})
	time.Sleep(300 * time.Millisecond)
}

func m3RoutePolicy() *openngfwv1.Policy {
	p := allowPolicy()
	p.Addresses = append(p.Addresses, &openngfwv1.Address{Name: "m3-branch", Cidr: m3RouteTargetIP + "/32"})
	p.Services = append(p.Services, &openngfwv1.Service{
		Name:     "m3-echo",
		Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
		Ports:    []*openngfwv1.PortRange{{Start: m3RoutePort}},
	})
	p.Rules = append(p.Rules, &openngfwv1.Rule{
		Name:                 "client-to-m3-branch",
		FromZones:            []string{"outside"},
		ToZones:              []string{"inside"},
		DestinationAddresses: []string{"m3-branch"},
		Services:             []string{"m3-echo"},
		Action:               openngfwv1.Action_ACTION_ALLOW,
		Log:                  true,
	})
	p.StaticRoutes = []*openngfwv1.StaticRoute{{
		Destination: m3RouteCIDR,
		Via:         serverIP,
		Interface:   "sveth0",
		Metric:      30,
	}}
	return p
}

func TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic(t *testing.T) {
	requireWireguard(t)
	if out := strings.TrimSpace(run(t, "ip", "route", "show", m3WireguardTunnelCIDR)); out != "" {
		t.Skipf("M3 WireGuard test overlay route %s already exists on host: %s", m3WireguardTunnelCIDR, out)
	}

	teardownM3Wireguard()
	t.Cleanup(teardownM3Wireguard)

	rootKeyDir := "/etc/openngfw/keys"
	rootKeyDirExisted := pathExists(rootKeyDir)
	rootKeyParentExisted := pathExists(filepath.Dir(rootKeyDir))
	rootKeyPath := filepath.Join(rootKeyDir, fmt.Sprintf("ngfw-it-m3-wireguard-%d.key", os.Getpid()))
	rootPublicKey := writeM3WireguardKeypair(t, rootKeyPath)
	t.Cleanup(func() {
		_ = os.Remove(rootKeyPath)
		if !rootKeyDirExisted {
			_ = os.Remove(rootKeyDir)
		}
		if !rootKeyParentExisted {
			_ = os.Remove(filepath.Dir(rootKeyDir))
		}
	})

	peerKeyPath := filepath.Join(t.TempDir(), "peer.key")
	peerPublicKey := writeM3WireguardKeypair(t, peerKeyPath)

	setupM3WireguardUnderlay(t)
	configureM3WireguardPeer(t, peerKeyPath, rootPublicKey)
	startM3WireguardEchoServer(t)

	if tcpReachableFromRoot(m3WireguardPeerTunnelIP, m3WireguardEchoPort) {
		t.Fatal("WireGuard peer overlay reachable before M3 WireGuard policy was committed")
	}

	srv := newWireguardStack(t)
	mustCommit(t, srv, m3WireguardPolicy(rootKeyPath, peerPublicKey), "m3 wireguard peer")

	addr := run(t, "ip", "addr", "show", "dev", m3WireguardIf)
	if !strings.Contains(addr, m3WireguardRootTunnelIP+"/24") {
		t.Fatalf("managed WireGuard address missing from %s:\n%s", m3WireguardIf, addr)
	}
	wg := run(t, "wg", "show", m3WireguardIf)
	for _, want := range []string{
		fmt.Sprintf("listening port: %d", m3WireguardRootListenPort),
		"peer: " + peerPublicKey,
	} {
		if !strings.Contains(wg, want) {
			t.Fatalf("managed WireGuard interface missing %q:\n%s", want, wg)
		}
	}

	waitForM3(t, 8*time.Second, "WireGuard peer overlay TCP reachability", func() bool {
		return tcpReachableFromRoot(m3WireguardPeerTunnelIP, m3WireguardEchoPort)
	})
	if latest := m3WireguardLatestHandshake(t, m3WireguardIf, peerPublicKey); latest == 0 {
		t.Fatalf("WireGuard peer %s has no recorded handshake", peerPublicKey)
	}

	mustCommit(t, srv, &openngfwv1.Policy{}, "remove m3 wireguard peer")
	if linkExists(m3WireguardIf) {
		t.Fatalf("managed WireGuard interface %s still exists after policy removal", m3WireguardIf)
	}
	if tcpReachableFromRoot(m3WireguardPeerTunnelIP, m3WireguardEchoPort) {
		t.Fatal("WireGuard peer overlay still reachable after managed interface removal")
	}
}

func TestM3BGPProgramsKernelRouteFromFRRPeer(t *testing.T) {
	requireM3BGP(t)
	if out := strings.TrimSpace(run(t, "ip", "route", "show", m3BGPLearnedCIDR)); out != "" {
		t.Skipf("M3 BGP learned-route prefix %s already exists on host: %s", m3BGPLearnedCIDR, out)
	}

	teardownM3BGP()
	t.Cleanup(teardownM3BGP)

	setupM3BGPTopology(t)
	startM3FRRRuntime(t, m3BGPNS, makeM3FRRRuntimeDir(t, "openngfw-m3-peer-frr-"), m3BGPPeerConfig())

	srv := newBGPStack(t)
	mustCommit(t, srv, m3BGPPolicy(), "m3 bgp peer")

	waitForM3(t, 30*time.Second, "BGP learned kernel route from FRR peer", func() bool {
		return m3BGPRouteInstalled()
	})
	route := run(t, "ip", "route", "show", m3BGPLearnedCIDR)
	for _, want := range []string{m3BGPLearnedCIDR, "via " + m3BGPPeerIP, "dev " + m3BGPRootIf} {
		if !strings.Contains(route, want) {
			t.Fatalf("BGP learned route missing %q:\n%s", want, route)
		}
	}

	mustCommit(t, srv, &openngfwv1.Policy{}, "remove m3 bgp peer")
	waitForM3(t, 15*time.Second, "BGP learned kernel route withdrawal", func() bool {
		return strings.TrimSpace(run(t, "ip", "route", "show", m3BGPLearnedCIDR)) == ""
	})
}

func requireM3BGP(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("BGP integration test requires Linux; current OS is %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("BGP integration test requires root")
	}
	for _, bin := range []string{"ip", "vtysh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("BGP integration test requires %s", bin)
		}
	}
	for _, daemon := range []string{"zebra", "bgpd"} {
		path, ok := frrDaemonPath(daemon)
		if !ok {
			t.Skipf("BGP integration test requires %s", daemon)
		}
		if !frrDaemonSupports(path, "--vty_socket") {
			t.Skipf("BGP integration test requires --vty_socket support in %s --help", daemon)
		}
	}
	probe := fmt.Sprintf("ngfw-it-m3-bgp-probe-%d", os.Getpid())
	out, err := exec.Command("ip", "netns", "add", probe).CombinedOutput()
	if err != nil {
		t.Skipf("BGP integration test requires network namespace support: %v: %s", err, out)
	}
	runQuiet("ip", "netns", "del", probe)
}

func setupM3BGPTopology(t *testing.T) {
	t.Helper()

	run(t, "ip", "netns", "add", m3BGPNS)
	run(t, "ip", "link", "add", m3BGPRootIf, "type", "veth", "peer", "name", m3BGPPeerIf)
	run(t, "ip", "link", "set", m3BGPPeerIf, "netns", m3BGPNS)

	run(t, "ip", "addr", "add", m3BGPRootIP+"/30", "dev", m3BGPRootIf)
	run(t, "ip", "link", "set", m3BGPRootIf, "up")

	run(t, "ip", "netns", "exec", m3BGPNS, "ip", "addr", "add", m3BGPPeerIP+"/30", "dev", m3BGPPeerIf)
	run(t, "ip", "netns", "exec", m3BGPNS, "ip", "link", "set", m3BGPPeerIf, "up")
	run(t, "ip", "netns", "exec", m3BGPNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", m3BGPNS, "ip", "addr", "add", m3BGPLearnedHostIP+"/24", "dev", "lo")
}

func teardownM3BGP() {
	runQuiet("ip", "route", "del", m3BGPLearnedCIDR)
	runQuiet("ip", "link", "del", m3BGPRootIf)
	runQuiet("ip", "netns", "del", m3BGPNS)
}

func newBGPStack(t *testing.T) *apiserver.PolicyServer {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/store.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	frrDir := makeM3FRRRuntimeDir(t, "openngfw-m3-root-frr-")
	configPath := filepath.Join(frrDir, "frr.conf")
	daemonsPath := filepath.Join(frrDir, "daemons")
	if err := os.WriteFile(daemonsPath, []byte("zebra=yes\nbgpd=no\nospfd=no\nvtysh_enable=yes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reloadScript := writeM3BGPReloadScript(t, frrDir)
	t.Cleanup(func() { stopM3FRRRuntime(frrDir) })

	sup := engines.NewSupervisor(&engines.FRR{
		ConfigPath:  configPath,
		DaemonsPath: daemonsPath,
		ReloadCmd:   []string{reloadScript, configPath, frrDir},
		StateDir:    filepath.Join(dir, "state"),
	})
	opts := renderers.DefaultOptions(dir, dir+"/log")
	return apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
}

func writeM3BGPReloadScript(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "reload-frr.sh")
	zebra, ok := frrDaemonPath("zebra")
	if !ok {
		t.Skip("BGP integration test requires zebra")
	}
	bgpd, ok := frrDaemonPath("bgpd")
	if !ok {
		t.Skip("BGP integration test requires bgpd")
	}
	script := fmt.Sprintf(`#!/usr/bin/env sh
set -eu
config="$1"
root="$2"
zebra_bin=%s
bgpd_bin=%s
zebra_skip=%s
bgpd_skip=%s

stop_frr() {
  for pidfile in "$root/bgpd.pid" "$root/zebra.pid"; do
    if [ -s "$pidfile" ]; then
      pid="$(cat "$pidfile")"
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pidfile in "$root/bgpd.pid" "$root/zebra.pid"; do
    if [ -s "$pidfile" ]; then
      pid="$(cat "$pidfile")"
      kill -KILL "$pid" 2>/dev/null || true
      rm -f "$pidfile"
    fi
  done
  rm -f "$root/zebra.sock"
}

stop_frr
marker="$(sed -n 's/^! openngfw-daemons: //p' "$config" | head -n 1)"
if [ "$marker" = "none" ] || [ -z "$marker" ]; then
  exit 0
fi

mkdir -p "$root/vty"
"$zebra_bin" $zebra_skip -d -f "$config" -i "$root/zebra.pid" -z "$root/zebra.sock" --vty_socket "$root/vty" -P 0 >"$root/zebra.log" 2>&1 &
i=0
while [ "$i" -lt 30 ]; do
  [ -S "$root/zebra.sock" ] && break
  i=$((i + 1))
  sleep 0.1
done
"$bgpd_bin" $bgpd_skip -d -f "$config" -i "$root/bgpd.pid" -z "$root/zebra.sock" --vty_socket "$root/vty" -P 0 >"$root/bgpd.log" 2>&1 &
`, shellQuote(zebra), shellQuote(bgpd), shellQuote(frrDaemonSkipRunasArg(zebra)), shellQuote(frrDaemonSkipRunasArg(bgpd)))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func startM3FRRRuntime(t *testing.T, netns, dir, config string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "vty"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "vty"), 0o777); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	stopM3FRRRuntime(dir)
	t.Cleanup(func() { stopM3FRRRuntime(dir) })
	startM3FRRDaemon(t, netns, "zebra", configPath, dir)
	waitForM3Path(t, filepath.Join(dir, "zebra.sock"), 3*time.Second, "FRR zebra socket")
	startM3FRRDaemon(t, netns, "bgpd", configPath, dir)
}

func makeM3FRRRuntimeDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopM3FRRRuntime(dir)
		_ = os.RemoveAll(dir)
	})
	return dir
}

func startM3FRRDaemon(t *testing.T, netns, daemon, configPath, dir string) {
	t.Helper()
	daemonPath, ok := frrDaemonPath(daemon)
	if !ok {
		t.Skipf("BGP integration test requires %s", daemon)
	}
	args := []string{}
	if skipRunas := frrDaemonSkipRunasArg(daemonPath); skipRunas != "" {
		args = append(args, skipRunas)
	}
	args = append(args,
		"-d",
		"-f", configPath,
		"-i", filepath.Join(dir, daemon+".pid"),
		"-z", filepath.Join(dir, "zebra.sock"),
		"--vty_socket", filepath.Join(dir, "vty"),
		"-P", "0",
	)

	name := daemonPath
	cmdArgs := args
	if netns != "" {
		name = "ip"
		cmdArgs = append([]string{"netns", "exec", netns, daemonPath}, args...)
	}
	cmd := exec.Command(name, cmdArgs...)
	if err := cmd.Start(); err != nil {
		t.Skipf("FRR daemon %s could not start in isolated temp runtime: %v", daemon, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	pidFile := filepath.Join(dir, daemon+".pid")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pid := readM3PID(pidFile); pid != "" && m3PIDAlive(pid) {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Skipf("FRR daemon %s exited before publishing pid file: %v", daemon, err)
			}
			t.Skipf("FRR daemon %s exited before publishing pid file", daemon)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	t.Skipf("FRR daemon %s did not publish a live pid file at %s", daemon, pidFile)
}

func frrDaemonPath(name string) (string, bool) {
	if path, err := exec.LookPath(name); err == nil {
		return path, true
	}
	for _, dir := range []string{"/usr/libexec/frr", "/usr/lib/frr"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, true
		}
	}
	return "", false
}

func frrDaemonSupports(path, option string) bool {
	out, _ := exec.Command(path, "--help").CombinedOutput()
	return strings.Contains(string(out), option)
}

func frrDaemonSkipRunasArg(path string) string {
	if frrDaemonSupports(path, "--skip_runas") {
		return "-S"
	}
	return ""
}

func stopM3FRRRuntime(dir string) {
	for _, daemon := range []string{"bgpd", "zebra"} {
		if pid := readM3PID(filepath.Join(dir, daemon+".pid")); pid != "" {
			runQuiet("kill", "-TERM", pid)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, daemon := range []string{"bgpd", "zebra"} {
		pidFile := filepath.Join(dir, daemon+".pid")
		if pid := readM3PID(pidFile); pid != "" {
			runQuiet("kill", "-KILL", pid)
		}
		_ = os.Remove(pidFile)
	}
	_ = os.Remove(filepath.Join(dir, "zebra.sock"))
}

func readM3PID(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func m3PIDAlive(pid string) bool {
	return exec.Command("kill", "-0", pid).Run() == nil
}

func waitForM3Path(t *testing.T, path string, timeout time.Duration, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Skipf("timed out waiting for %s at %s", desc, path)
}

func m3BGPPeerConfig() string {
	return fmt.Sprintf(`frr defaults traditional
hostname openngfw-m3-peer
log file /tmp/openngfw-m3-bgp-peer.log
!
router bgp %d
 bgp router-id %s
 no bgp ebgp-requires-policy
 neighbor %s remote-as %d
 neighbor %s timers 1 3
 address-family ipv4 unicast
  network %s
 exit-address-family
!
`, m3BGPPeerASN, m3BGPPeerIP, m3BGPRootIP, m3BGPRootASN, m3BGPRootIP, m3BGPLearnedCIDR)
}

func m3BGPPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Routing: &openngfwv1.Routing{Bgp: &openngfwv1.Bgp{
			Enabled:  true,
			Asn:      m3BGPRootASN,
			RouterId: m3BGPRootIP,
			Neighbors: []*openngfwv1.BgpNeighbor{{
				Address:     m3BGPPeerIP,
				RemoteAsn:   m3BGPPeerASN,
				Description: "m3-netns-peer",
			}},
		}},
	}
}

func m3BGPRouteInstalled() bool {
	route := runM3Output("ip", "route", "show", m3BGPLearnedCIDR)
	return strings.Contains(route, m3BGPLearnedCIDR) &&
		strings.Contains(route, "via "+m3BGPPeerIP) &&
		strings.Contains(route, "dev "+m3BGPRootIf)
}

func runM3Output(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

func requireWireguard(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}
	for _, bin := range []string{"ip", "wg", "nc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("WireGuard integration test requires %s", bin)
		}
	}
	probe := fmt.Sprintf("ngfwg%d", os.Getpid())
	if len(probe) > 15 {
		probe = "ngfwgprobe"
	}
	out, err := exec.Command("ip", "link", "add", probe, "type", "wireguard").CombinedOutput()
	if err != nil {
		t.Skipf("WireGuard integration test requires kernel WireGuard link support: %v: %s", err, out)
	}
	runQuiet("ip", "link", "del", probe)
}

func newWireguardStack(t *testing.T) *apiserver.PolicyServer {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/store.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sup := engines.NewSupervisor(&engines.Wireguard{StateDir: dir})
	opts := renderers.DefaultOptions(dir, dir+"/log")
	return apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
}

func writeM3WireguardKeypair(t *testing.T, privateKeyPath string) string {
	t.Helper()
	privateKey := strings.TrimSpace(run(t, "wg", "genkey"))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wg pubkey: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, []byte(privateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func setupM3WireguardUnderlay(t *testing.T) {
	t.Helper()

	run(t, "ip", "netns", "add", m3WireguardNS)
	run(t, "ip", "link", "add", m3WireguardUnderlayRootIf, "type", "veth", "peer", "name", m3WireguardUnderlayPeerIf)
	run(t, "ip", "link", "set", m3WireguardUnderlayPeerIf, "netns", m3WireguardNS)

	run(t, "ip", "addr", "add", m3WireguardUnderlayRootIP+"/24", "dev", m3WireguardUnderlayRootIf)
	run(t, "ip", "link", "set", m3WireguardUnderlayRootIf, "up")
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "addr", "add", m3WireguardUnderlayPeerIP+"/24", "dev", m3WireguardUnderlayPeerIf)
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "link", "set", m3WireguardUnderlayPeerIf, "up")
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "link", "set", "lo", "up")
}

func configureM3WireguardPeer(t *testing.T, privateKeyPath, rootPublicKey string) {
	t.Helper()
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "link", "add", m3WireguardPeerIf, "type", "wireguard")
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "addr", "add", m3WireguardPeerTunnelIP+"/24", "dev", m3WireguardPeerIf)
	run(t, "ip", "netns", "exec", m3WireguardNS, "wg", "set", m3WireguardPeerIf,
		"private-key", privateKeyPath,
		"listen-port", fmt.Sprintf("%d", m3WireguardPeerListenPort),
		"peer", rootPublicKey,
		"allowed-ips", m3WireguardRootTunnelIP+"/32",
		"endpoint", fmt.Sprintf("%s:%d", m3WireguardUnderlayRootIP, m3WireguardRootListenPort),
		"persistent-keepalive", "1",
	)
	run(t, "ip", "netns", "exec", m3WireguardNS, "ip", "link", "set", m3WireguardPeerIf, "up")
}

func teardownM3Wireguard() {
	runQuiet("ip", "link", "del", m3WireguardIf)
	runQuiet("ip", "link", "del", m3WireguardUnderlayRootIf)
	runQuiet("ip", "netns", "del", m3WireguardNS)
}

func startM3WireguardEchoServer(t *testing.T) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", m3WireguardNS,
		"sh", "-c", netcatListenLoop(m3WireguardEchoPort, "m3-wg-pong"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		runQuiet("pkill", "-f", fmt.Sprintf("nc -l -p %d", m3WireguardEchoPort))
	})
	time.Sleep(300 * time.Millisecond)
}

func m3WireguardPolicy(privateKeyPath, peerPublicKey string) *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Vpn: &openngfwv1.Vpn{
			WireguardInterfaces: []*openngfwv1.WireguardInterface{{
				Name:           m3WireguardIf,
				Address:        m3WireguardRootTunnelIP + "/24",
				ListenPort:     m3WireguardRootListenPort,
				PrivateKeyFile: privateKeyPath,
				Peers: []*openngfwv1.WireguardPeer{{
					Name:                "netns-peer",
					PublicKey:           peerPublicKey,
					Endpoint:            fmt.Sprintf("%s:%d", m3WireguardUnderlayPeerIP, m3WireguardPeerListenPort),
					AllowedIps:          []string{m3WireguardPeerTunnelIP + "/32"},
					PersistentKeepalive: 1,
				}},
			}},
		},
	}
}

func tcpReachableFromRoot(addr string, port int) bool {
	cmd := exec.Command("nc", "-z", "-w", "2", addr, fmt.Sprintf("%d", port))
	return cmd.Run() == nil
}

func waitForM3(t *testing.T, timeout time.Duration, desc string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func m3WireguardLatestHandshake(t *testing.T, iface, peerPublicKey string) int64 {
	t.Helper()
	out := run(t, "wg", "show", iface, "latest-handshakes")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != peerPublicKey {
			continue
		}
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("parse WireGuard latest-handshakes line %q: %v", line, err)
		}
		return ts
	}
	return 0
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

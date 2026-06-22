//go:build integration

// M2 end-to-end test: Suricata in detect (af-packet) mode supervised by
// the real commit path, detecting a custom signature in live forwarded
// traffic, surfaced through the AlertService.
//
// Inline prevent (NFQUEUE) mode is covered by renderer tests; running it
// needs kernel nfnetlink_queue support, which containers often lack —
// the OCI test plan exercises it on a real VM.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/store"
)

const evilRule = `alert tcp any any -> any 8080 (msg:"NGFW-TEST evil payload"; content:"EVILSTRING"; sid:9000001; rev:1;)` + "\n"

func TestM2SuricataDetectEndToEnd(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("suricata"); err != nil {
		t.Skip("suricata not installed")
	}
	setupTopology(t)
	startEchoServer(t)

	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	opts := renderers.DefaultOptions(dir, logDir)

	// Drop the test signature in before the engine starts; the engine
	// only creates missing rule files, it never overwrites.
	if err := os.MkdirAll(opts.SuricataRulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.SuricataRulesDir, "local.rules"), []byte(evilRule), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	suri := &engines.Suricata{StateDir: filepath.Join(dir, "suricata"), LogDir: logDir}
	t.Cleanup(suri.Stop)
	sup := engines.NewSupervisor(
		&engines.Nftables{StateDir: dir},
		&engines.Routes{StateDir: dir},
		suri,
	)
	srv := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
	alerts := &apiserver.AlertServer{EvePath: opts.EvePath()}

	pol := allowPolicy()
	pol.Ids = &openngfwv1.Ids{
		Enabled:           true,
		Mode:              openngfwv1.IdsMode_IDS_MODE_DETECT,
		MonitorInterfaces: []string{"sveth0"},
		HomeNetworks:      []string{"10.100.0.0/16"},
	}
	mustCommit(t, srv, pol, "enable ids detect")

	// Suricata needs a moment to come up before it sees packets.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(opts.EvePath()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("suricata did not start logging within 30s")
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	// Send the malicious payload through the firewall.
	sendEvil := func() {
		cmd := exec.Command("ip", "netns", "exec", clientNS, "sh", "-c",
			fmt.Sprintf("echo EVILSTRING | nc -w 2 %s 8080", serverIP))
		_ = cmd.Run()
	}

	var found bool
	for time.Now().Before(deadline) && !found {
		sendEvil()
		time.Sleep(2 * time.Second)
		resp, err := alerts.ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range resp.GetAlerts() {
			if a.GetSignatureId() == 9000001 {
				found = true
				if a.GetSignature() != "NGFW-TEST evil payload" {
					t.Errorf("signature = %q", a.GetSignature())
				}
				if a.GetDestPort() != 8080 || a.GetProtocol() != "TCP" {
					t.Errorf("alert tuple = %s:%d -> %s:%d %s",
						a.GetSrcIp(), a.GetSrcPort(), a.GetDestIp(), a.GetDestPort(), a.GetProtocol())
				}
				break
			}
		}
	}
	if !found {
		t.Fatal("custom signature was not detected in forwarded traffic")
	}

	// Disabling IDS through policy stops the engine cleanly.
	mustCommit(t, srv, allowPolicy(), "disable ids")
}

func TestM2AppIDSignalOnlyDenyDropsHTTPInPreventMode(t *testing.T) {
	requireRoot(t)
	requireSuricataNFQueue(t)
	setupTopology(t)
	startHTTPServer(t)

	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	opts := renderers.DefaultOptions(dir, logDir)

	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	suri := &engines.Suricata{StateDir: filepath.Join(dir, "suricata"), LogDir: logDir}
	t.Cleanup(suri.Stop)
	sup := engines.NewSupervisor(
		&engines.Nftables{StateDir: dir},
		&engines.Routes{StateDir: dir},
		suri,
	)
	srv := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))

	baseline := allowPolicy()
	baseline.Ids = preventFailClosedIDS()
	mustCommit(t, srv, baseline, "enable ips prevent baseline")
	waitForSuricataEve(t, opts.EvePath())
	if body, ok := httpGetFromClient(serverIP, 8080); !ok || !strings.Contains(body, "pong") {
		t.Fatalf("baseline HTTP flow did not pass before App-ID deny, ok=%t body=%q", ok, body)
	}

	blockHTTP := allowPolicy()
	blockHTTP.Ids = preventFailClosedIDS()
	blockHTTP.Applications = []*openngfwv1.Application{{
		Name:          "web-browsing",
		DisplayName:   "Web Browsing",
		Category:      "business-app",
		EngineSignals: []string{"http"},
	}}
	blockHTTP.Rules = append([]*openngfwv1.Rule{{
		Name:         "block-web-browsing",
		Applications: []string{"web-browsing"},
		Action:       openngfwv1.Action_ACTION_DENY,
		Log:          true,
	}}, blockHTTP.Rules...)
	mustCommit(t, srv, blockHTTP, "block http app-id")
	waitForSuricataEve(t, opts.EvePath())
	assertPreventQueueFailClosed(t)

	if body, ok := httpGetFromClient(serverIP, 8080); ok {
		t.Fatalf("HTTP flow passed despite signal-only App-ID deny; body=%q", body)
	}
	assertSuricataAppIDDrop(t, opts.EvePath(), "block-web-browsing", "web-browsing")
	rules, err := os.ReadFile(filepath.Join(opts.SuricataRulesDir, "openngfw-appid.rules"))
	if err != nil {
		t.Fatalf("read managed App-ID rules: %v", err)
	}
	ruleText := string(rules)
	if !strings.Contains(ruleText, "sid:4200001") ||
		!strings.Contains(ruleText, "app-layer-protocol:http") ||
		!strings.Contains(ruleText, "openngfw_rule block-web-browsing") {
		t.Fatalf("managed App-ID rules missing HTTP drop metadata:\n%s", rules)
	}
}

func TestM2SecurityProfileRequiredAllowIsInspectedFailClosed(t *testing.T) {
	requireRoot(t)
	requireSuricataNFQueue(t)
	setupTopology(t)
	startEchoServer(t)

	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	opts := renderers.DefaultOptions(dir, logDir)

	if err := os.MkdirAll(opts.SuricataRulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.SuricataRulesDir, "local.rules"), []byte(evilRule), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	suri := &engines.Suricata{StateDir: filepath.Join(dir, "suricata"), LogDir: logDir}
	t.Cleanup(suri.Stop)
	sup := engines.NewSupervisor(
		&engines.Nftables{StateDir: dir},
		&engines.Routes{StateDir: dir},
		suri,
	)
	srv := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
	alerts := &apiserver.AlertServer{EvePath: opts.EvePath()}

	profiled := allowPolicy()
	profiled.Ids = preventFailClosedIDS()
	profiled.SecurityProfiles = []*openngfwv1.SecurityProfile{{
		Name:        "block-malicious-dns",
		Description: "Requires inline fail-closed inspection for profiled allow rules.",
		DnsSecurity: openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
	}}
	profiled.Rules[0].SecurityProfiles = []string{"block-malicious-dns"}
	mustCommit(t, srv, profiled, "enable profile-required fail-closed inspection")
	waitForSuricataEve(t, opts.EvePath())
	assertPreventQueueFailClosed(t)
	assertProfileInspectionRules(t, "client-to-server")
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("profile-required allow rule did not pass baseline TCP reachability")
	}

	sendEvilFromClient()
	assertSuricataSignatureAlert(t, alerts, 9000001)
}

func preventFailClosedIDS() *openngfwv1.Ids {
	return &openngfwv1.Ids{
		Enabled:           true,
		Mode:              openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior:   openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
		QueueNum:          0,
		MonitorInterfaces: []string{"sveth0"},
		HomeNetworks:      []string{"10.100.0.0/16"},
	}
}

func requireSuricataNFQueue(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("suricata"); err != nil {
		t.Skip("suricata not installed")
	}
	out, err := exec.Command("suricata", "--build-info").CombinedOutput()
	if err != nil {
		t.Skipf("suricata --build-info failed: %v", err)
	}
	if !strings.Contains(string(out), "NFQueue support:                         yes") &&
		!strings.Contains(string(out), "NFQ") {
		t.Skip("suricata was built without NFQUEUE support")
	}
	if err := exec.Command("modprobe", "nfnetlink_queue").Run(); err != nil {
		t.Skipf("nfnetlink_queue is not available: %v", err)
	}
}

func startHTTPServer(t *testing.T) {
	t.Helper()
	response := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"
	body := fmt.Sprintf("printf %s | nc -l -p 8080", shellQuote(response))
	if !netcatIsNcat() {
		body += " -q 0"
	}
	cmd := exec.Command("ip", "netns", "exec", serverNS, "sh", "-c", "while true; do "+body+"; done")
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

func httpGetFromClient(addr string, port int) (string, bool) {
	cmd := exec.Command("ip", "netns", "exec", clientNS,
		"curl", "-sS", "--max-time", "3", fmt.Sprintf("http://%s:%d/", addr, port))
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func assertPreventQueueFailClosed(t *testing.T) {
	t.Helper()
	ruleset := run(t, "nft", "list", "table", "inet", "openngfw")
	if !strings.Contains(ruleset, "queue to 0") {
		t.Fatalf("fail-closed IPS queue missing from live nftables table:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "bypass") {
		t.Fatalf("fail-closed IPS queue must not include bypass in live nftables table:\n%s", ruleset)
	}
}

func assertProfileInspectionRules(t *testing.T, ruleName string) {
	t.Helper()
	ruleset := run(t, "nft", "list", "table", "inet", "openngfw")
	for _, want := range []string{
		"profile-inspection:" + ruleName,
		"rule:" + ruleName + " inspection=ips-fail-closed",
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("profile-required inspection marker %q missing from live nftables table:\n%s", want, ruleset)
		}
	}
}

func sendEvilFromClient() {
	cmd := exec.Command("ip", "netns", "exec", clientNS, "sh", "-c",
		fmt.Sprintf("echo EVILSTRING | nc -w 2 %s 8080", serverIP))
	_ = cmd.Run()
}

func waitForSuricataEve(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("suricata did not create %s within 30s", path)
}

func assertSuricataAppIDDrop(t *testing.T, evePath, ruleName, appID string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(evePath)
		text := string(raw)
		if strings.Contains(text, `"event_type":"alert"`) &&
			strings.Contains(text, `"action":"blocked"`) &&
			strings.Contains(text, ruleName) &&
			strings.Contains(text, appID) {
			return
		}
		time.Sleep(1 * time.Second)
	}
	raw, _ := os.ReadFile(evePath)
	t.Fatalf("did not observe blocked App-ID alert for rule %s app %s in EVE:\n%s", ruleName, appID, raw)
}

func assertSuricataSignatureAlert(t *testing.T, alerts *apiserver.AlertServer, signatureID int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		sendEvilFromClient()
		time.Sleep(1 * time.Second)
		resp, err := alerts.ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, alert := range resp.GetAlerts() {
			if alert.GetSignatureId() == signatureID {
				return
			}
		}
	}
	resp, _ := alerts.ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{})
	t.Fatalf("did not observe Suricata signature %d alert in profile-required inspected flow: %+v", signatureID, resp.GetAlerts())
}

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

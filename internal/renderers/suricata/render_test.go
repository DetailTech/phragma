package suricata

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func detectIR() *compiler.IR {
	return &compiler.IR{IDs: &compiler.IDsIR{
		Interfaces: []string{"eth1", "eth2"},
		HomeNets:   []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		RuleFiles:  []string{"local.rules"},
	}}
}

func TestRenderDisabled(t *testing.T) {
	got, err := Render(&compiler.IR{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ModeMarker+ModeDisabled+"\n" {
		t.Fatalf("disabled artifact = %q", got)
	}
}

func TestRenderDetect(t *testing.T) {
	got, err := Render(detectIR(), Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		ModeMarker + ModeDetect,
		`HOME_NET: "[10.10.0.0/24]"`,
		"- interface: eth1",
		"- interface: eth2",
		"default-rule-path: /var/lib/openngfw/suricata/rules",
		"- local.rules",
		"filename: eve.json",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "nfq:") {
		t.Error("detect mode must not configure nfq")
	}
}

func TestRenderPrevent(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.QueueNum = 7
	got, err := Render(ir, Options{RulesDir: "/r", LogDir: "/l"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{ModeMarker + ModePrevent, "# openngfw-queue: 7", "nfq:\n  mode: accept"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "af-packet:") {
		t.Error("prevent mode must not configure af-packet")
	}
}

// TestRenderedConfigPassesSuricataT validates the rendered config with
// the real engine when available — the renderer contract is "suricata
// accepts this", not just "it looks like YAML".
func TestRenderedConfigPassesSuricataT(t *testing.T) {
	bin, err := exec.LookPath("suricata")
	if err != nil {
		t.Skip("suricata not installed")
	}
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	logDir := filepath.Join(dir, "log")
	for _, d := range []string{rulesDir, logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "local.rules"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	ir := detectIR()
	ir.IDs.Interfaces = []string{"lo"}
	got, err := Render(ir, Options{RulesDir: rulesDir, LogDir: logDir})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(cfgPath, got, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-T", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("suricata -T rejected rendered config: %v\n%s\n--- config ---\n%s", err, out, got)
	}
}

func TestRenderDerivesPacketSizeFromMTU(t *testing.T) {
	ir := detectIR()
	ir.Network = &compiler.NetworkIR{MaxMTU: 9000}
	got, err := Render(ir, Options{RulesDir: "/r", LogDir: "/l"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "default-packet-size: 9018") {
		t.Errorf("capture size not derived from MTU:\n%s", got)
	}
	// Without managed MTU the engine default stands.
	plain, err := Render(detectIR(), Options{RulesDir: "/r", LogDir: "/l"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "default-packet-size") {
		t.Error("default-packet-size must be absent when no MTU is managed")
	}
}

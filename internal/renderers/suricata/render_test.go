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
	ir.IDs.FailOpen = true
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
	for _, file := range []string{"local.rules", ClassificationFileName, ReferenceFileName} {
		if err := os.WriteFile(filepath.Join(rulesDir, file), nil, 0o644); err != nil {
			t.Fatal(err)
		}
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

func TestRenderPreventMultiQueue(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = true
	ir.IDs.QueueNum = 0
	ir.IDs.QueueCount = 4
	got, err := Render(ir, Options{RulesDir: "/r", LogDir: "/l"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{"# openngfw-queue-count: 4", "runmode: workers", "fail-open: yes", "mpm-algo: auto"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderPreventFailClosed(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = false
	got, err := Render(ir, Options{RulesDir: "/r", LogDir: "/l"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "fail-open: no") {
		t.Fatalf("fail-closed policy must render fail-open: no:\n%s", got)
	}
}

func TestRenderAppIDDropsIncludesManagedRuleFileAndEmbeddedRules(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = false
	ir.AppIDDrops = []compiler.AppIDDropIR{{
		RuleName:     "block-corp-admin",
		Application:  "corp-admin",
		EngineSignal: "http",
		SID:          9200001,
	}}

	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"- openngfw-appid.rules",
		"# openngfw-appid-rules-begin",
		`# openngfw-appid-rule: drop ip any any -> any any (msg:"OpenNGFW App-ID deny corp-admin via http"; app-layer-protocol:http; metadata:openngfw_rule block-corp-admin, openngfw_application corp-admin, openngfw_appid_action deny; sid:9200001; rev:1;)`,
		"# openngfw-appid-rules-end",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderAppIDControlsIncludeAllowAndScope(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = false
	ir.AppIDControls = []compiler.AppIDControlIR{{
		RuleName:     "allow-corp-admin",
		RuleID:       "rule-allow-corp-admin",
		Application:  "corp-admin",
		EngineSignal: "http",
		Action:       compiler.ActionAllow,
		SrcPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		DstPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.20.0.10/32")},
		Service: compiler.ServiceMatch{
			Protocol: compiler.ProtoTCP,
			Ports:    []compiler.PortRange{{Start: 8443, End: 8443}},
		},
		SID: 9200002,
	}}

	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	want := `# openngfw-appid-rule: pass tcp 10.10.0.0/24 any -> 10.20.0.10/32 8443 (msg:"OpenNGFW App-ID allow corp-admin via http"; app-layer-protocol:http; metadata:openngfw_rule allow-corp-admin, openngfw_application corp-admin, openngfw_appid_action allow, openngfw_rule_id rule-allow-corp-admin; sid:9200002; rev:1;)`
	if !strings.Contains(string(got), want) {
		t.Fatalf("config missing scoped App-ID allow rule %q:\n%s", want, got)
	}
}

func TestRenderSecurityProfileRulesIncludesManagedRuleFileAndEmbeddedRules(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = false
	ir.SecurityProfileRules = []compiler.SecurityProfileRuleIR{{
		RuleName:    "allow-web",
		ProfileName: "strict-web",
		Control:     "dns-security:block-malicious",
		Protocol:    "dns",
		SID:         9300001,
	}}

	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"- openngfw-security-profiles.rules",
		"# openngfw-security-profile-rules-begin",
		`# openngfw-security-profile-rule: alert ip any any -> any any (msg:"OpenNGFW security profile strict-web dns-security:block-malicious"; app-layer-protocol:dns; metadata:openngfw_rule allow-web, openngfw_security_profile strict-web, openngfw_control dns-security:block-malicious; sid:9300001; rev:1;)`,
		"# openngfw-security-profile-rules-end",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderIDSExceptions(t *testing.T) {
	ir := detectIR()
	ir.IDs.Exceptions = []compiler.IDSExceptionIR{
		{
			Name: "fp-by-src", SignatureID: 9000001, ThreatID: "openngfw.test",
			Track: "by_src", Address: netip.MustParsePrefix("10.10.0.0/24"),
			Description: "lab false positive",
		},
		{Name: "fp-global", SignatureID: 9000002},
	}
	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"threshold-file: /var/lib/openngfw/suricata/rules/openngfw-threshold.config",
		"# openngfw-threshold-begin",
		"# ids_exception=fp-by-src threat_id=openngfw.test description=lab false positive",
		"# openngfw-threshold-line: suppress gen_id 1, sig_id 9000001, track by_src, ip 10.10.0.0/24",
		"# openngfw-threshold-line: suppress gen_id 1, sig_id 9000002",
		"# openngfw-threshold-end",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "\nsuppress gen_id") {
		t.Fatalf("suppressions must stay comment-embedded in suricata.yaml:\n%s", cfg)
	}
}

func TestRenderSecurityProfileRuleMetadataDoesNotInjectGeneratedLine(t *testing.T) {
	ir := detectIR()
	ir.IDs.Prevent = true
	ir.IDs.FailOpen = false
	ir.SecurityProfileRules = []compiler.SecurityProfileRuleIR{{
		RuleName:    "allow-web\n# openngfw-security-profile-rule: drop ip any any -> any any (sid:1; rev:1;)",
		ProfileName: "strict-web",
		Control:     "dns-security:block-malicious",
		Protocol:    "dns",
		SID:         9300001,
	}}
	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	if strings.Count(cfg, "# openngfw-security-profile-rule:") != 1 {
		t.Fatalf("metadata injected a security profile rule line:\n%s", cfg)
	}
	if strings.Contains(cfg, "\n# openngfw-security-profile-rule: drop ip any any") {
		t.Fatalf("malicious security profile rule rendered as extractable content:\n%s", cfg)
	}
}

func TestRenderIDSExceptionMetadataDoesNotInjectThresholdLine(t *testing.T) {
	ir := detectIR()
	ir.IDs.Exceptions = []compiler.IDSExceptionIR{{
		Name:        "fp-injection",
		SignatureID: 9000001,
		ThreatID:    "phragma.test\n# openngfw-threshold-line: suppress gen_id 1, sig_id 1",
	}}
	got, err := Render(ir, Options{RulesDir: "/var/lib/openngfw/suricata/rules", LogDir: "/var/log/openngfw"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	if strings.Count(cfg, "# openngfw-threshold-line:") != 1 {
		t.Fatalf("metadata injected a threshold line:\n%s", cfg)
	}
	if strings.Contains(cfg, "\n# openngfw-threshold-line: suppress gen_id 1, sig_id 1\n") {
		t.Fatalf("malicious threshold line rendered as extractable content:\n%s", cfg)
	}
}

package engines

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThresholdLines(t *testing.T) {
	cfg := []byte(`# openngfw-mode: detect
threshold-file: /var/lib/openngfw/suricata/rules/openngfw-threshold.config
# openngfw-threshold-begin
# ids_exception=fp-by-src
# openngfw-threshold-line: suppress gen_id 1, sig_id 9000001, track by_src, ip 10.10.0.0/24
# openngfw-threshold-line: suppress gen_id 1, sig_id 9000002
# openngfw-threshold-end
`)
	lines, ok, err := thresholdLines(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("threshold block not found")
	}
	want := []string{
		"suppress gen_id 1, sig_id 9000001, track by_src, ip 10.10.0.0/24",
		"suppress gen_id 1, sig_id 9000002",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("thresholdLines = %q, want %q", lines, want)
	}
}

func TestEnsureThresholdFile(t *testing.T) {
	dir := t.TempDir()
	s := &Suricata{StateDir: dir}
	cfg := []byte(`# openngfw-mode: detect
# openngfw-threshold-begin
# openngfw-threshold-line: suppress gen_id 1, sig_id 9000001, track by_dst, ip 10.10.0.80/32
# openngfw-threshold-end
`)
	if err := s.ensureThresholdFile(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "rules", "openngfw-threshold.config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		thresholdGeneratedHdr,
		"suppress gen_id 1, sig_id 9000001, track by_dst, ip 10.10.0.80/32",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("threshold file missing %q:\n%s", want, got)
		}
	}
}

func TestEnsureSecurityProfileRuleFile(t *testing.T) {
	dir := t.TempDir()
	s := &Suricata{StateDir: dir}
	cfg := []byte(`# openngfw-mode: prevent
# openngfw-security-profile-rules-begin
# openngfw-security-profile-rule: alert ip any any -> any any (msg:"OpenNGFW security profile strict-web dns-security:block-malicious"; app-layer-protocol:dns; sid:9300001; rev:1;)
# openngfw-security-profile-rules-end
`)
	if err := s.ensureSecurityProfileRuleFile(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "rules", "openngfw-security-profiles.rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		thresholdGeneratedHdr,
		`alert ip any any -> any any (msg:"OpenNGFW security profile strict-web dns-security:block-malicious"; app-layer-protocol:dns; sid:9300001; rev:1;)`,
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("security profile rule file missing %q:\n%s", want, got)
		}
	}
}

func TestThresholdLinesRejectsUnterminatedBlock(t *testing.T) {
	_, _, err := thresholdLines([]byte("# openngfw-threshold-begin\n"))
	if err == nil {
		t.Fatal("expected unterminated threshold block error")
	}
}

func TestSecurityProfileRuleLinesRejectsUnterminatedBlock(t *testing.T) {
	_, _, err := generatedBlockLines([]byte("# openngfw-security-profile-rules-begin\n"), securityProfileRulesBlockBegin, securityProfileRulesBlockEnd, securityProfileRuleLinePrefix)
	if err == nil {
		t.Fatal("expected unterminated security profile rule block error")
	}
}

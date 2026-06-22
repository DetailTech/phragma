package nftables

import (
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/compiler"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestRenderGolden renders YAML policy fixtures and compares against
// committed golden rulesets. Run `go test ./internal/renderers/... -update`
// after an intentional renderer change and review the diff.
func TestRenderGolden(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no golden fixtures found: %v", err)
	}
	for _, yamlPath := range cases {
		name := filepath.Base(yamlPath[:len(yamlPath)-len(".yaml")])
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(yamlPath)
			if err != nil {
				t.Fatal(err)
			}
			jsonBytes, err := yaml.YAMLToJSON(raw)
			if err != nil {
				t.Fatalf("fixture %s: %v", yamlPath, err)
			}
			pol := &openngfwv1.Policy{}
			if err := protojson.Unmarshal(jsonBytes, pol); err != nil {
				t.Fatalf("fixture %s: %v", yamlPath, err)
			}
			ir, err := compiler.Compile(pol)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := Render(ir)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			goldenPath := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("rendered ruleset differs from golden file %s\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
			}
		})
	}
}

func TestRenderRejectsDisjointFamilies(t *testing.T) {
	ir := &compiler.IR{Rules: []compiler.RuleIR{{
		Name:        "broken",
		SrcPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		DstPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
		Action:      compiler.ActionAllow,
	}}}
	if _, err := Render(ir); err == nil {
		t.Fatal("expected error for v4-source/v6-destination rule")
	}
}

// TestGoldensPassNftCheck validates every golden ruleset with the real
// nft binary when present. Queue statements need kernel NFQUEUE support;
// kernels without it get a logged skip for those files only.
func TestGoldensPassNftCheck(t *testing.T) {
	bin, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs netlink (root); kernel validation runs in the integration job")
	}
	goldens, _ := filepath.Glob(filepath.Join("testdata", "*.nft"))
	if len(goldens) == 0 {
		t.Fatal("no golden files")
	}
	for _, g := range goldens {
		t.Run(filepath.Base(g), func(t *testing.T) {
			out, err := exec.Command(bin, "-c", "-f", g).CombinedOutput()
			if err != nil {
				if strings.Contains(string(out), "queue") && strings.Contains(string(out), "No such file or directory") {
					t.Skipf("kernel lacks NFQUEUE support; cannot kernel-validate %s here", g)
				}
				if strings.Contains(string(out), "flowtable") && strings.Contains(string(out), "No such file or directory") {
					t.Skipf("host lacks fixture flowtable devices; cannot kernel-validate %s here", g)
				}
				t.Fatalf("nft -c rejected %s: %v\n%s", g, err, out)
			}
		})
	}
}

func TestForwardQueueFanout(t *testing.T) {
	base := &compiler.IR{
		Zones: []compiler.ZoneIR{{Name: "lan", Interfaces: []string{"eth0"}}},
		IDs:   &compiler.IDsIR{Prevent: true, FailOpen: true, QueueNum: 2},
	}
	// Single queue keeps the simple form.
	base.IDs.QueueCount = 1
	got, err := Render(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "queue flags bypass to 2 ") {
		t.Errorf("single-queue form missing:\n%s", got)
	}
	// Multiple queues fan out across the range.
	base.IDs.QueueCount = 4
	got, err = Render(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "queue flags bypass,fanout to 2-5 ") {
		t.Errorf("fanout range missing:\n%s", got)
	}
}

func TestForwardQueueFailClosed(t *testing.T) {
	base := &compiler.IR{
		Zones: []compiler.ZoneIR{{Name: "lan", Interfaces: []string{"eth0"}}},
		IDs:   &compiler.IDsIR{Prevent: true, FailOpen: false, QueueNum: 2},
	}
	base.IDs.QueueCount = 1
	got, err := Render(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "bypass") {
		t.Fatalf("fail-closed queue must not include bypass:\n%s", got)
	}
	if !strings.Contains(string(got), "queue to 2 ") {
		t.Errorf("fail-closed single queue form missing:\n%s", got)
	}

	base.IDs.QueueCount = 4
	got, err = Render(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "bypass") {
		t.Fatalf("fail-closed fanout must not include bypass:\n%s", got)
	}
	if !strings.Contains(string(got), "queue flags fanout to 2-5 ") {
		t.Errorf("fail-closed fanout range missing:\n%s", got)
	}
}

func TestApplicationDenyRuleRendersPortHintMatches(t *testing.T) {
	ir := &compiler.IR{Rules: []compiler.RuleIR{{
		ID:           "rule-appid-001",
		Name:         "block-corp-admin",
		Applications: []string{"corp-admin"},
		Services: []compiler.ServiceMatch{
			{Protocol: compiler.ProtoTCP, Ports: []compiler.PortRange{{Start: 8443, End: 8443}}},
			{Protocol: compiler.ProtoUDP, Ports: []compiler.PortRange{{Start: 5353, End: 5353}}},
		},
		Action: compiler.ActionDeny,
		Log:    true,
	}}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(got)
	for _, want := range []string{
		`tcp dport 8443 log prefix "ngfw:block-corp-admin: " counter drop comment "rule:block-corp-admin id=rule-appid-001 app-id=corp-admin appid-path=port-hints"`,
		`udp dport 5353 log prefix "ngfw:block-corp-admin: " counter drop comment "rule:block-corp-admin id=rule-appid-001 app-id=corp-admin appid-path=port-hints"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q in ruleset:\n%s", want, ruleset)
		}
	}
}

func TestSignalOnlyAppIDDenyRuleDoesNotRenderNftablesDrop(t *testing.T) {
	ir := &compiler.IR{
		IDs: &compiler.IDsIR{Prevent: true, FailOpen: false, QueueNum: 0},
		Rules: []compiler.RuleIR{{
			Name:         "block-corp-admin",
			Applications: []string{"corp-admin"},
			AppIDSignals: []compiler.AppIDSignalIR{{
				Application: "corp-admin",
				Signals:     []string{"http"},
			}},
			AppIDOnly: true,
			Action:    compiler.ActionDeny,
			Log:       true,
		}},
		AppIDDrops: []compiler.AppIDDropIR{{
			RuleName:     "block-corp-admin",
			Application:  "corp-admin",
			EngineSignal: "http",
			SID:          9200001,
		}},
	}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(got)
	for _, notWant := range []string{
		`tcp dport`,
		`udp dport`,
		`comment "rule:block-corp-admin"`,
		`ngfw:block-corp-admin: `,
	} {
		if strings.Contains(ruleset, notWant) {
			t.Fatalf("signal-only App-ID deny must be enforced by Suricata, not nftables %q:\n%s", notWant, ruleset)
		}
	}
	if !strings.Contains(ruleset, `counter queue to 0 comment "ips-inspect"`) {
		t.Fatalf("inline IPS queue missing from signal-only App-ID ruleset:\n%s", ruleset)
	}
}

func TestProfileRequiredAllowRuleRendersInspectionEvidence(t *testing.T) {
	ir := &compiler.IR{
		IDs: &compiler.IDsIR{Prevent: true, FailOpen: false, QueueNum: 0},
		Rules: []compiler.RuleIR{{
			Name:               "allow-inspected-web",
			ID:                 "rule-inspect-001",
			SecurityProfiles:   []string{"block-malicious-dns"},
			InspectionRequired: true,
			Services: []compiler.ServiceMatch{{
				Protocol: compiler.ProtoTCP,
				Ports:    []compiler.PortRange{{Start: 443, End: 443}},
			}},
			Action: compiler.ActionAllow,
		}},
	}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(got)
	for _, want := range []string{
		`counter queue to 0 comment "ips-inspect"`,
		`tcp dport 443 counter comment "profile-inspection:allow-inspected-web"`,
		`tcp dport 443 counter accept comment "rule:allow-inspected-web id=rule-inspect-001 inspection=ips-fail-closed"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q in ruleset:\n%s", want, ruleset)
		}
	}
}

func TestHostInputDefaultDeny(t *testing.T) {
	ir := &compiler.IR{
		HostInputDefault: compiler.ActionDeny,
		HostInputRules: []compiler.RuleIR{{
			Name:       "allow-ssh",
			ID:         "host-input-allow-ssh-001",
			FromIfaces: []string{"eth1"},
			Services: []compiler.ServiceMatch{{
				Protocol: compiler.ProtoTCP,
				Ports:    []compiler.PortRange{{Start: 22, End: 22}},
			}},
			Action: compiler.ActionAllow,
		}},
	}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(got)
	for _, want := range []string{
		"type filter hook input priority filter; policy drop;",
		"iifname \"lo\" accept",
		"ct state established,related accept",
		"iifname \"eth1\" tcp dport 22 counter accept comment \"host-input:allow-ssh id=host-input-allow-ssh-001\"",
		"counter comment \"default-input-drop\"",
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q in ruleset:\n%s", want, ruleset)
		}
	}
}

func TestNATCommentsIncludeDurableIDs(t *testing.T) {
	ir := &compiler.IR{
		SNAT: []compiler.SNATIR{{
			ID:         "snat-lan-masq-001",
			Name:       "lan-masq",
			OutIfaces:  []string{"eth0"},
			SrcPrefix:  ptrPrefix(netip.MustParsePrefix("10.10.0.0/24")),
			Masquerade: true,
		}},
		DNAT: []compiler.DNATIR{{
			ID:          "dnat-web-001",
			Name:        "web",
			InIfaces:    []string{"eth0"},
			Protocol:    compiler.ProtoTCP,
			Ports:       []compiler.PortRange{{Start: 443, End: 443}},
			MatchDst:    netip.MustParseAddr("203.0.113.10"),
			TranslateTo: netip.MustParseAddr("10.20.0.80"),
			ToPort:      8443,
		}},
	}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(got)
	for _, want := range []string{
		`comment "snat:lan-masq id=snat-lan-masq-001"`,
		`comment "dnat:web id=dnat-web-001"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q in ruleset:\n%s", want, ruleset)
		}
	}
}

func ptrPrefix(p netip.Prefix) *netip.Prefix {
	return &p
}

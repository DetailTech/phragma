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
				t.Fatalf("nft -c rejected %s: %v\n%s", g, err, out)
			}
		})
	}
}

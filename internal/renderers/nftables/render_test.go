package nftables

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
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

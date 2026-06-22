package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderProxyPlan(t *testing.T) {
	got, err := Render(&compiler.IR{Proxy: &compiler.ProxyIR{
		WAFPolicies: []compiler.WAFPolicyIR{{
			Name:               "corp-waf",
			Mode:               "block",
			RequestBodyLimitKB: 128,
			AuditLogging:       true,
			RedactRequestBody:  true,
			RuleSets: []compiler.WAFRuleSetIR{{
				Name:    "crs",
				Version: "4.0.0",
				Source:  "owasp-crs",
				SHA256:  strings.Repeat("a", 64),
			}},
		}},
		VirtualServices: []compiler.VirtualServiceIR{{
			Name:      "admin-api",
			Enabled:   true,
			Hostnames: []string{"admin.example.com"},
			Listener: compiler.ProxyListenerIR{
				BindAddress:  "0.0.0.0",
				Port:         443,
				TLS:          true,
				TLSSecretRef: "vault://openngfw/admin-api",
			},
			Routes: []compiler.ProxyRouteIR{{
				Name:                 "api",
				PathPrefix:           "/api",
				WAFPolicy:            "corp-waf",
				RequireMTLSToBackend: true,
				Backends: []compiler.ProxyBackendIR{{
					Name:   "api-1",
					URL:    "https://api.internal",
					Weight: 100,
				}},
			}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(got, &plan); err != nil {
		t.Fatalf("rendered plan is not JSON: %v\n%s", err, got)
	}
	if plan["schemaVersion"] != PlanSchema {
		t.Fatalf("schemaVersion = %v, want %s", plan["schemaVersion"], PlanSchema)
	}
	if plan["state"] != "planned" {
		t.Fatalf("state = %v, want planned", plan["state"])
	}
	if !strings.Contains(string(got), "active-proxy-rollout") {
		t.Fatalf("hardening blockers missing from plan:\n%s", got)
	}
	if !strings.Contains(string(got), "admin.example.com") || !strings.Contains(string(got), "coraza") {
		t.Fatalf("proxy plan missing virtual service or WAF engine context:\n%s", got)
	}
	runtime, ok := plan["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("proxy plan missing runtime block:\n%s", got)
	}
	proof, ok := runtime["proofArtifacts"].([]any)
	if !ok || len(proof) != 4 {
		t.Fatalf("runtime proofArtifacts = %#v, want four functional proof artifacts", runtime["proofArtifacts"])
	}
	kinds := map[string]bool{}
	for _, raw := range proof {
		item := raw.(map[string]any)
		if item["status"] != "planned-not-executed" {
			t.Fatalf("proof artifact status = %v, want planned-not-executed", item["status"])
		}
		kinds[item["kind"].(string)] = true
	}
	for _, kind := range []string{"daemon", "listener", "cutover", "rollback"} {
		if !kinds[kind] {
			t.Fatalf("runtime proofArtifacts missing %s: %#v", kind, proof)
		}
	}
}

func TestRuntimeArtifactsDeterministicAndManifestHashes(t *testing.T) {
	ir := sampleProxyIR()
	first, err := RuntimeArtifacts(ir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RuntimeArtifacts(ir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{EnvoyBootstrapArtifact, CorazaRulesArtifact, RuntimeManifestArtifact} {
		if string(first[name]) != string(second[name]) {
			t.Fatalf("%s is not deterministic", name)
		}
	}
	if !strings.Contains(string(first[EnvoyBootstrapArtifact]), "static_resources:") {
		t.Fatalf("envoy bootstrap missing static_resources:\n%s", first[EnvoyBootstrapArtifact])
	}
	if !strings.Contains(string(first[CorazaRulesArtifact]), "SecRuleEngine On") {
		t.Fatalf("coraza rules missing blocking mode:\n%s", first[CorazaRulesArtifact])
	}
	var manifest struct {
		SchemaVersion string `json:"schemaVersion"`
		Artifacts     []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
		Proof []struct {
			ID       string   `json:"id"`
			Kind     string   `json:"kind"`
			Status   string   `json:"status"`
			Evidence []string `json:"evidence"`
			Boundary string   `json:"boundary"`
		} `json:"proofArtifacts"`
	}
	if err := json.Unmarshal(first[RuntimeManifestArtifact], &manifest); err != nil {
		t.Fatalf("manifest is not JSON: %v\n%s", err, first[RuntimeManifestArtifact])
	}
	if manifest.SchemaVersion != RuntimeManifestSchema {
		t.Fatalf("manifest schema = %q, want %q", manifest.SchemaVersion, RuntimeManifestSchema)
	}
	hashes := map[string]string{}
	for _, artifact := range manifest.Artifacts {
		hashes[artifact.Name] = artifact.SHA256
	}
	for _, name := range []string{EnvoyBootstrapArtifact, CorazaRulesArtifact} {
		got := hashes[name]
		want := fmt.Sprintf("%x", sha256.Sum256(first[name]))
		if got != want {
			t.Fatalf("%s hash = %s, want %s", name, got, want)
		}
	}
	if len(manifest.Proof) != 4 {
		t.Fatalf("proof artifact count = %d, want 4", len(manifest.Proof))
	}
	for _, proof := range manifest.Proof {
		if proof.Status != "planned-not-executed" {
			t.Fatalf("%s status = %q, want planned-not-executed", proof.ID, proof.Status)
		}
		if len(proof.Evidence) == 0 || proof.Boundary == "" {
			t.Fatalf("%s missing evidence or boundary: %#v", proof.ID, proof)
		}
	}
}

func sampleProxyIR() *compiler.IR {
	return &compiler.IR{Proxy: &compiler.ProxyIR{
		WAFPolicies: []compiler.WAFPolicyIR{{
			Name:               "corp-waf",
			Mode:               "block",
			RequestBodyLimitKB: 128,
			AuditLogging:       true,
			RedactRequestBody:  true,
			RuleSets: []compiler.WAFRuleSetIR{{
				Name:    "crs",
				Version: "4.0.0",
				Source:  "owasp-crs",
				SHA256:  strings.Repeat("a", 64),
			}},
		}},
		VirtualServices: []compiler.VirtualServiceIR{{
			Name:      "admin-api",
			Enabled:   true,
			Hostnames: []string{"admin.example.com"},
			Listener: compiler.ProxyListenerIR{
				BindAddress:  "0.0.0.0",
				Port:         443,
				TLS:          true,
				TLSSecretRef: "vault://openngfw/admin-api",
			},
			Routes: []compiler.ProxyRouteIR{{
				Name:                 "api",
				PathPrefix:           "/api",
				WAFPolicy:            "corp-waf",
				RequireMTLSToBackend: true,
				Backends: []compiler.ProxyBackendIR{{
					Name:   "api-1",
					URL:    "https://api.internal",
					Weight: 100,
				}},
			}},
		}},
	}}
}

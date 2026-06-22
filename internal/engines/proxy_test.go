package engines

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
	proxyrenderer "github.com/detailtech/oss-ngfw/internal/renderers/proxy"
)

func TestProxyValidateArtifactSetAndWriteLaunchPlan(t *testing.T) {
	artifacts := proxyArtifacts(t)
	engine := &Proxy{StateDir: t.TempDir()}
	if err := engine.ValidateArtifactSet(context.Background(), ProxyArtifactSet(artifacts)); err != nil {
		t.Fatal(err)
	}
	plan, err := engine.WriteArtifacts(context.Background(), ProxyArtifactSet(artifacts))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Engine != "envoy" || plan.Binary != "envoy" {
		t.Fatalf("launch engine/binary = %s/%s, want envoy/envoy", plan.Engine, plan.Binary)
	}
	if plan.ConfigPath != filepath.Join(engine.StateDir, proxyrenderer.EnvoyBootstrapArtifact) {
		t.Fatalf("config path = %s", plan.ConfigPath)
	}
	if !strings.Contains(strings.Join(plan.Args, " "), proxyrenderer.EnvoyBootstrapArtifact) {
		t.Fatalf("launch args do not reference envoy bootstrap: %#v", plan.Args)
	}
	if len(plan.RuntimeProof) != 4 {
		t.Fatalf("runtime proof count = %d, want 4", len(plan.RuntimeProof))
	}
	for _, proof := range plan.RuntimeProof {
		if proof.Status != "planned-not-executed" {
			t.Fatalf("%s status = %q, want planned-not-executed", proof.ID, proof.Status)
		}
	}
	for _, artifact := range plan.ManagedArtifacts {
		info, err := os.Stat(artifact.Path)
		if err != nil {
			t.Fatalf("artifact %s was not written: %v", artifact.Name, err)
		}
		if got := info.Mode().Perm(); got != proxyArtifactMode {
			t.Fatalf("artifact %s mode = %o, want %o", artifact.Name, got, proxyArtifactMode)
		}
	}
}

func TestProxyValidateArtifactSetRejectsMissingAndCorruptInputs(t *testing.T) {
	artifacts := ProxyArtifactSet(proxyArtifacts(t))
	delete(artifacts, proxyrenderer.CorazaRulesArtifact)
	engine := &Proxy{}
	if err := engine.ValidateArtifactSet(context.Background(), artifacts); err == nil {
		t.Fatal("expected missing coraza artifact to fail")
	}

	artifacts = ProxyArtifactSet(proxyArtifacts(t))
	artifacts[proxyrenderer.EnvoyBootstrapArtifact] = []byte("not envoy")
	if err := engine.ValidateArtifactSet(context.Background(), artifacts); err == nil {
		t.Fatal("expected corrupt envoy bootstrap to fail")
	}

	artifacts = ProxyArtifactSet(proxyArtifacts(t))
	artifacts[proxyrenderer.CorazaRulesArtifact] = append([]byte(nil), artifacts[proxyrenderer.CorazaRulesArtifact]...)
	artifacts[proxyrenderer.CorazaRulesArtifact] = append(artifacts[proxyrenderer.CorazaRulesArtifact], []byte("# tampered\n")...)
	if err := engine.ValidateArtifactSet(context.Background(), artifacts); err == nil {
		t.Fatal("expected manifest hash mismatch to fail")
	}

	artifacts = ProxyArtifactSet(proxyArtifacts(t))
	artifacts[proxyrenderer.RuntimeManifestArtifact] = []byte(`{"schemaVersion":"openngfw.proxy.runtime.v1","artifacts":[{"name":"envoy-bootstrap.yaml","sha256":"` + strings.Repeat("0", 64) + `"}]}`)
	if err := engine.ValidateArtifactSet(context.Background(), artifacts); err == nil || !strings.Contains(err.Error(), "proof artifacts") {
		t.Fatalf("expected missing proof artifacts to fail, got %v", err)
	}
}

func TestProxyRequireBinariesChecksEnvoyPresence(t *testing.T) {
	artifacts := ProxyArtifactSet(proxyArtifacts(t))
	engine := &Proxy{EnvoyBinary: "openngfw-envoy-missing-for-test", RequireBinaries: true}
	if err := engine.ValidateArtifactSet(context.Background(), artifacts); err == nil {
		t.Fatal("expected missing required envoy binary to fail")
	}
}

func proxyArtifacts(t *testing.T) map[string][]byte {
	t.Helper()
	artifacts, err := proxyrenderer.RuntimeArtifacts(&compiler.IR{Proxy: &compiler.ProxyIR{
		WAFPolicies: []compiler.WAFPolicyIR{{
			Name:               "corp-waf",
			Mode:               "block",
			RequestBodyLimitKB: 64,
			AuditLogging:       true,
			RuleSets: []compiler.WAFRuleSetIR{{
				Name:    "crs",
				Version: "4.0.0",
				Source:  "owasp-crs",
				SHA256:  strings.Repeat("b", 64),
			}},
		}},
		VirtualServices: []compiler.VirtualServiceIR{{
			Name:      "portal",
			Enabled:   true,
			Hostnames: []string{"portal.example.com"},
			Listener: compiler.ProxyListenerIR{
				BindAddress: "0.0.0.0",
				Port:        8443,
				TLS:         true,
			},
			Routes: []compiler.ProxyRouteIR{{
				Name:       "root",
				PathPrefix: "/",
				WAFPolicy:  "corp-waf",
				Backends: []compiler.ProxyBackendIR{{
					Name:   "portal-1",
					URL:    "https://portal.internal:9443",
					Weight: 100,
				}},
			}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return artifacts
}

package engines

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	proxyrenderer "github.com/detailtech/oss-ngfw/internal/renderers/proxy"
)

// ProxyName keys the managed proxy artifact set.
const ProxyName = "proxy"

const proxyArtifactMode = 0o600

// Proxy validates and materializes managed Envoy/Coraza runtime artifacts. It
// deliberately does not start Envoy; controld integration can use LaunchPlan
// once the active traffic cutover and HA proof work is ready.
type Proxy struct {
	// EnvoyBinary is the Envoy executable; defaults to "envoy".
	EnvoyBinary string
	// StateDir receives the deterministic proxy runtime artifacts.
	StateDir string
	// RequireBinaries makes validation fail when the expected runtime binaries
	// are absent. Leave false for planning-only hosts.
	RequireBinaries bool
}

// ProxyArtifactSet is the renderer output needed to plan a managed runtime.
type ProxyArtifactSet map[string][]byte

// ProxyLaunchPlan is the deterministic command shape for a future managed
// Envoy process.
type ProxyLaunchPlan struct {
	Engine           string
	Binary           string
	Args             []string
	ConfigPath       string
	CorazaConfig     string
	ManifestPath     string
	ManagedArtifacts []ProxyManagedArtifact
	RuntimeProof     []ProxyRuntimeProof
}

// ProxyManagedArtifact describes one materialized runtime artifact.
type ProxyManagedArtifact struct {
	Name   string
	Path   string
	SHA256 string
}

type ProxyRuntimeProof struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence"`
	Boundary string   `json:"boundary"`
}

type proxyRuntimeManifest struct {
	SchemaVersion string `json:"schemaVersion"`
	Artifacts     []struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"artifacts"`
	Proof []ProxyRuntimeProof `json:"proofArtifacts"`
}

// Name implements Engine for future supervisor integration.
func (p *Proxy) Name() string { return ProxyName }

func (p *Proxy) envoyBin() string {
	if p.EnvoyBinary != "" {
		return p.EnvoyBinary
	}
	return "envoy"
}

// Validate implements Engine for future supervisor integration. The supervisor
// only passes one artifact, so this path accepts a runtime manifest and checks
// its shape. Full artifact validation is exposed by ValidateArtifactSet.
func (p *Proxy) Validate(_ context.Context, config []byte) error {
	var manifest proxyRuntimeManifest
	if err := json.Unmarshal(config, &manifest); err != nil {
		return fmt.Errorf("proxy runtime manifest: %w", err)
	}
	if manifest.SchemaVersion != proxyrenderer.RuntimeManifestSchema {
		return fmt.Errorf("proxy runtime manifest schema %q, want %q", manifest.SchemaVersion, proxyrenderer.RuntimeManifestSchema)
	}
	if len(manifest.Artifacts) == 0 {
		return fmt.Errorf("proxy runtime manifest has no artifacts")
	}
	if err := validateProxyRuntimeProof(manifest.Proof); err != nil {
		return err
	}
	return p.validateBinaries()
}

// Apply implements Engine without starting a process. It persists the manifest
// only; full artifact materialization uses WriteArtifacts because the proxy
// runtime is multi-file by construction.
func (p *Proxy) Apply(ctx context.Context, config []byte) error {
	if err := p.Validate(ctx, config); err != nil {
		return err
	}
	if p.StateDir == "" {
		return fmt.Errorf("proxy StateDir is required")
	}
	if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(p.StateDir, proxyrenderer.RuntimeManifestArtifact)
	return writeProxyArtifact(path, config)
}

// ValidateArtifactSet verifies that a renderer-produced artifact set is
// internally consistent and contains the runtime inputs needed by Envoy and
// Coraza.
func (p *Proxy) ValidateArtifactSet(ctx context.Context, artifacts ProxyArtifactSet) error {
	if len(artifacts) == 0 {
		return fmt.Errorf("proxy artifact set is empty")
	}
	envoy := artifacts[proxyrenderer.EnvoyBootstrapArtifact]
	coraza := artifacts[proxyrenderer.CorazaRulesArtifact]
	manifest := artifacts[proxyrenderer.RuntimeManifestArtifact]
	if len(envoy) == 0 {
		return fmt.Errorf("missing %s", proxyrenderer.EnvoyBootstrapArtifact)
	}
	if len(coraza) == 0 {
		return fmt.Errorf("missing %s", proxyrenderer.CorazaRulesArtifact)
	}
	if len(manifest) == 0 {
		return fmt.Errorf("missing %s", proxyrenderer.RuntimeManifestArtifact)
	}
	if !bytes.Contains(envoy, []byte("static_resources:")) {
		return fmt.Errorf("%s does not look like an Envoy bootstrap", proxyrenderer.EnvoyBootstrapArtifact)
	}
	if !bytes.Contains(envoy, []byte("openngfw-proxy-runtime: envoy")) {
		return fmt.Errorf("%s missing OpenNGFW runtime marker", proxyrenderer.EnvoyBootstrapArtifact)
	}
	if !bytes.Contains(coraza, []byte("openngfw-proxy-runtime: coraza")) {
		return fmt.Errorf("%s missing OpenNGFW runtime marker", proxyrenderer.CorazaRulesArtifact)
	}
	if !bytes.Contains(coraza, []byte("SecRuleEngine")) {
		return fmt.Errorf("%s does not declare a Coraza rule engine mode", proxyrenderer.CorazaRulesArtifact)
	}
	var parsed proxyRuntimeManifest
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		return fmt.Errorf("%s: %w", proxyrenderer.RuntimeManifestArtifact, err)
	}
	if parsed.SchemaVersion != proxyrenderer.RuntimeManifestSchema {
		return fmt.Errorf("proxy runtime manifest schema %q, want %q", parsed.SchemaVersion, proxyrenderer.RuntimeManifestSchema)
	}
	if err := validateProxyRuntimeProof(parsed.Proof); err != nil {
		return err
	}
	expected := map[string][]byte{
		proxyrenderer.EnvoyBootstrapArtifact: envoy,
		proxyrenderer.CorazaRulesArtifact:    coraza,
	}
	seen := map[string]bool{}
	for _, artifact := range parsed.Artifacts {
		body, ok := expected[artifact.Name]
		if !ok {
			continue
		}
		seen[artifact.Name] = true
		got := fmt.Sprintf("%x", sha256.Sum256(body))
		if !strings.EqualFold(got, artifact.SHA256) {
			return fmt.Errorf("%s hash mismatch: manifest=%s actual=%s", artifact.Name, artifact.SHA256, got)
		}
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("proxy runtime manifest missing hash for %s", name)
		}
	}
	return p.validateRuntimeInputs(ctx, envoy)
}

// WriteArtifacts validates and writes every managed runtime artifact with
// restrictive permissions, then returns the deterministic future launch plan.
func (p *Proxy) WriteArtifacts(ctx context.Context, artifacts ProxyArtifactSet) (ProxyLaunchPlan, error) {
	if err := p.ValidateArtifactSet(ctx, artifacts); err != nil {
		return ProxyLaunchPlan{}, err
	}
	if p.StateDir == "" {
		return ProxyLaunchPlan{}, fmt.Errorf("proxy StateDir is required")
	}
	if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
		return ProxyLaunchPlan{}, err
	}
	names := []string{
		proxyrenderer.EnvoyBootstrapArtifact,
		proxyrenderer.CorazaRulesArtifact,
		proxyrenderer.RuntimeManifestArtifact,
	}
	managed := make([]ProxyManagedArtifact, 0, len(names))
	for _, name := range names {
		path := filepath.Join(p.StateDir, name)
		if err := writeProxyArtifact(path, artifacts[name]); err != nil {
			return ProxyLaunchPlan{}, err
		}
		managed = append(managed, ProxyManagedArtifact{
			Name:   name,
			Path:   path,
			SHA256: fmt.Sprintf("%x", sha256.Sum256(artifacts[name])),
		})
	}
	cfgPath := filepath.Join(p.StateDir, proxyrenderer.EnvoyBootstrapArtifact)
	return ProxyLaunchPlan{
		Engine:       "envoy",
		Binary:       p.envoyBin(),
		ConfigPath:   cfgPath,
		CorazaConfig: filepath.Join(p.StateDir, proxyrenderer.CorazaRulesArtifact),
		ManifestPath: filepath.Join(p.StateDir, proxyrenderer.RuntimeManifestArtifact),
		Args: []string{
			"--config-path", cfgPath,
			"--base-id", "0",
			"--log-format", "[%Y-%m-%dT%T.%eZ] [%l] [openngfw-proxy] %v",
		},
		ManagedArtifacts: managed,
		RuntimeProof:     parsedRuntimeProof(artifacts[proxyrenderer.RuntimeManifestArtifact]),
	}, nil
}

func validateProxyRuntimeProof(proof []ProxyRuntimeProof) error {
	required := map[string]bool{
		"daemon":   false,
		"listener": false,
		"cutover":  false,
		"rollback": false,
	}
	if len(proof) == 0 {
		return fmt.Errorf("proxy runtime manifest has no proof artifacts")
	}
	for _, item := range proof {
		if item.ID == "" {
			return fmt.Errorf("proxy runtime proof artifact missing id")
		}
		if _, ok := required[item.Kind]; ok {
			required[item.Kind] = true
		}
		if item.Status != "planned-not-executed" {
			return fmt.Errorf("proxy runtime proof artifact %s status %q, want planned-not-executed", item.ID, item.Status)
		}
		if len(item.Evidence) == 0 {
			return fmt.Errorf("proxy runtime proof artifact %s has no evidence fields", item.ID)
		}
		if item.Boundary == "" {
			return fmt.Errorf("proxy runtime proof artifact %s has no boundary", item.ID)
		}
	}
	for kind, seen := range required {
		if !seen {
			return fmt.Errorf("proxy runtime manifest missing %s proof artifact", kind)
		}
	}
	return nil
}

func parsedRuntimeProof(manifest []byte) []ProxyRuntimeProof {
	var parsed proxyRuntimeManifest
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		return nil
	}
	return parsed.Proof
}

func (p *Proxy) validateBinaries() error {
	if !p.RequireBinaries {
		return nil
	}
	if _, err := exec.LookPath(p.envoyBin()); err != nil {
		return fmt.Errorf("proxy runtime requires %s but it is not installed: %w", p.envoyBin(), err)
	}
	return nil
}

func (p *Proxy) validateRuntimeInputs(ctx context.Context, envoy []byte) error {
	if err := p.validateBinaries(); err != nil {
		return err
	}
	if !p.RequireBinaries {
		return nil
	}
	tmp, err := writeTemp(envoy, "openngfw-envoy-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return runCmd(ctx, p.envoyBin(), "--mode", "validate", "-c", tmp)
}

func writeProxyArtifact(path string, content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("refusing to write empty proxy artifact %s", filepath.Base(path))
	}
	if err := os.WriteFile(path, content, proxyArtifactMode); err != nil {
		return err
	}
	return os.Chmod(path, proxyArtifactMode)
}

// Package proxy renders bounded L7 proxy/WAF/API gateway intent into a
// reviewable deployment plan and deterministic runtime artifacts. It does not
// apply host traffic redirection.
package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

// PlanSchema identifies the reviewable proxy deployment plan format.
const PlanSchema = "openngfw.proxy.plan.v1"

// RuntimeManifestSchema identifies the deterministic proxy runtime manifest format.
const RuntimeManifestSchema = "openngfw.proxy.runtime.v1"

const (
	// EnvoyBootstrapArtifact is the rendered Envoy bootstrap filename.
	EnvoyBootstrapArtifact = "envoy-bootstrap.yaml"
	// CorazaRulesArtifact is the rendered Coraza WAF configuration filename.
	CorazaRulesArtifact = "coraza-waf.conf"
	// RuntimeManifestArtifact is the rendered proxy runtime manifest filename.
	RuntimeManifestArtifact = "proxy-runtime-manifest.json"
)

type plan struct {
	SchemaVersion string            `json:"schemaVersion"`
	GeneratedBy   string            `json:"generatedBy"`
	GeneratedAt   string            `json:"generatedAt"`
	State         string            `json:"state"`
	Engines       []string          `json:"engines"`
	Hardening     []string          `json:"hardening"`
	Proxy         *compiler.ProxyIR `json:"proxy"`
	Readiness     proxyReadiness    `json:"readiness"`
	Runtime       runtimeReadiness  `json:"runtime"`
}

type proxyReadiness struct {
	VirtualServiceCount uint32   `json:"virtualServiceCount"`
	EnabledServiceCount uint32   `json:"enabledServiceCount"`
	WAFPolicyCount      uint32   `json:"wafPolicyCount"`
	Blockers            []string `json:"blockers"`
}

type runtimeReadiness struct {
	SchemaVersion string            `json:"schemaVersion"`
	Artifacts     []RuntimeArtifact `json:"artifacts"`
	Launch        []RuntimeLaunch   `json:"launch"`
	Proof         []RuntimeProof    `json:"proofArtifacts"`
	Validation    []string          `json:"validation"`
}

// RuntimeArtifact identifies one hash-addressed proxy runtime input.
type RuntimeArtifact struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	SHA256      string `json:"sha256"`
}

// RuntimeLaunch describes the deterministic command for a managed proxy engine.
type RuntimeLaunch struct {
	Engine string   `json:"engine"`
	Binary string   `json:"binary"`
	Args   []string `json:"args"`
}

// RuntimeProof describes the status, evidence, and boundary of one runtime proof.
type RuntimeProof struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence"`
	Boundary string   `json:"boundary"`
}

type runtimeManifest struct {
	SchemaVersion string            `json:"schemaVersion"`
	GeneratedBy   string            `json:"generatedBy"`
	GeneratedAt   string            `json:"generatedAt"`
	Artifacts     []RuntimeArtifact `json:"artifacts"`
	Launch        []RuntimeLaunch   `json:"launch"`
	Proof         []RuntimeProof    `json:"proofArtifacts"`
}

// Render produces deterministic JSON suitable for API render-plan status,
// support bundles, and operator inspection.
func Render(ir *compiler.IR) ([]byte, error) {
	if ir == nil || ir.Proxy == nil {
		return []byte("{}\n"), nil
	}
	runtime := runtimePlan(ir.Proxy)
	out := plan{
		SchemaVersion: PlanSchema,
		GeneratedBy:   "openngfw-controld",
		GeneratedAt:   time.Unix(0, 0).UTC().Format(time.RFC3339),
		State:         "planned",
		Engines:       []string{"envoy", "coraza"},
		Hardening: []string{
			"tls-key-custody",
			"backend-mtls-proof",
			"waf-ruleset-provenance",
			"request-body-privacy",
			"active-proxy-rollout",
			"ha-traffic-proof",
		},
		Proxy:     ir.Proxy,
		Readiness: summarize(ir.Proxy),
		Runtime:   runtime,
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	return raw, nil
}

func summarize(proxy *compiler.ProxyIR) proxyReadiness {
	readiness := proxyReadiness{
		VirtualServiceCount: uint32(len(proxy.VirtualServices)),
		WAFPolicyCount:      uint32(len(proxy.WAFPolicies)),
		Blockers: []string{
			"Active traffic redirection to Envoy is not implemented.",
			"TLS private-key custody and certificate lifecycle are external.",
			"Backend mTLS needs runtime certificate proof.",
			"HA failover traffic proof is not recorded for proxy listeners.",
		},
	}
	for _, vs := range proxy.VirtualServices {
		if vs.Enabled {
			readiness.EnabledServiceCount++
		}
	}
	return readiness
}

// RuntimeArtifacts renders the deterministic on-disk inputs a future managed
// proxy engine would need. They are intentionally inert until controld wires
// them into a live process lifecycle.
func RuntimeArtifacts(ir *compiler.IR) (map[string][]byte, error) {
	if ir == nil || ir.Proxy == nil {
		return nil, nil
	}
	envoy := renderEnvoyBootstrap(ir.Proxy)
	coraza := renderCorazaRules(ir.Proxy)
	manifest, err := renderRuntimeManifest(envoy, coraza)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		EnvoyBootstrapArtifact:  envoy,
		CorazaRulesArtifact:     coraza,
		RuntimeManifestArtifact: manifest,
	}, nil
}

func runtimePlan(proxy *compiler.ProxyIR) runtimeReadiness {
	envoy := renderEnvoyBootstrap(proxy)
	coraza := renderCorazaRules(proxy)
	manifest := runtimeManifestFor(envoy, coraza)
	return runtimeReadiness{
		SchemaVersion: RuntimeManifestSchema,
		Artifacts:     manifest.Artifacts,
		Launch:        manifest.Launch,
		Proof:         manifest.Proof,
		Validation: []string{
			"envoy bootstrap artifact is deterministic and hash-addressed",
			"coraza WAF artifact is deterministic and hash-addressed",
			"managed runtime launch arguments are deterministic but not registered",
			"daemon, listener, cutover, and rollback proof artifacts are planned-not-executed status fields",
		},
	}
}

func renderRuntimeManifest(envoy, coraza []byte) ([]byte, error) {
	manifest := runtimeManifestFor(envoy, coraza)
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	return raw, nil
}

func runtimeManifestFor(envoy, coraza []byte) runtimeManifest {
	artifacts := []RuntimeArtifact{
		{
			Name:        EnvoyBootstrapArtifact,
			Path:        "/var/lib/openngfw/proxy/" + EnvoyBootstrapArtifact,
			ContentType: "application/x-yaml",
			SHA256:      fmt.Sprintf("%x", sha256.Sum256(envoy)),
		},
		{
			Name:        CorazaRulesArtifact,
			Path:        "/var/lib/openngfw/proxy/" + CorazaRulesArtifact,
			ContentType: "text/plain",
			SHA256:      fmt.Sprintf("%x", sha256.Sum256(coraza)),
		},
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	launch := []RuntimeLaunch{{
		Engine: "envoy",
		Binary: "envoy",
		Args: []string{
			"--config-path", "/var/lib/openngfw/proxy/" + EnvoyBootstrapArtifact,
			"--base-id", "0",
			"--log-format", "[%Y-%m-%dT%T.%eZ] [%l] [openngfw-proxy] %v",
		},
	}}
	return runtimeManifest{
		SchemaVersion: RuntimeManifestSchema,
		GeneratedBy:   "openngfw-controld",
		GeneratedAt:   time.Unix(0, 0).UTC().Format(time.RFC3339),
		Artifacts:     artifacts,
		Launch:        launch,
		Proof:         runtimeProofArtifacts(proxyRuntimeInputs{artifacts: artifacts, launch: launch}),
	}
}

type proxyRuntimeInputs struct {
	artifacts []RuntimeArtifact
	launch    []RuntimeLaunch
}

func runtimeProofArtifacts(inputs proxyRuntimeInputs) []RuntimeProof {
	hashEvidence := make([]string, 0, len(inputs.artifacts))
	for _, artifact := range inputs.artifacts {
		hashEvidence = append(hashEvidence, artifact.Name+" sha256="+artifact.SHA256)
	}
	launchEvidence := "envoy launch command not rendered"
	if len(inputs.launch) > 0 {
		launchEvidence = inputs.launch[0].Binary + " " + strings.Join(inputs.launch[0].Args, " ")
	}
	return []RuntimeProof{
		{
			ID:     "proxy-daemon-plan",
			Kind:   "daemon",
			Status: "planned-not-executed",
			Evidence: append([]string{
				launchEvidence,
				"artifact directory: /var/lib/openngfw/proxy",
			}, hashEvidence...),
			Boundary: "Functional proof artifact only; controld has not started, supervised, reloaded, or stopped Envoy/Coraza.",
		},
		{
			ID:       "proxy-listener-plan",
			Kind:     "listener",
			Status:   "planned-not-executed",
			Evidence: []string{"listener bind intent is present in envoy-bootstrap.yaml", "operator must capture socket bind, health endpoint, and request-path proof externally"},
			Boundary: "Listener intent is rendered, but no active listener bind, request sample, or HA traffic proof is claimed.",
		},
		{
			ID:       "proxy-cutover-plan",
			Kind:     "cutover",
			Status:   "planned-not-executed",
			Evidence: []string{"candidate proxy artifact hashes are available for change review", "traffic cutover requires an approved route, load balancer, or NAT change outside this renderer"},
			Boundary: "No production route, load balancer, NAT, DNS, or client traffic cutover is performed.",
		},
		{
			ID:       "proxy-rollback-plan",
			Kind:     "rollback",
			Status:   "planned-not-executed",
			Evidence: []string{"previous policy version and restore owner must be attached by rollout workflow", "artifact hash set can be compared before restore"},
			Boundary: "Rollback evidence is a handoff requirement; no rollback drill, daemon stop, or listener withdrawal is executed.",
		},
	}
}

func renderEnvoyBootstrap(proxy *compiler.ProxyIR) []byte {
	var b strings.Builder
	b.WriteString("# Generated by OpenNGFW controld. Do not edit; overwritten on every commit.\n")
	b.WriteString("# openngfw-proxy-runtime: envoy\n")
	b.WriteString("static_resources:\n")
	b.WriteString("  listeners:\n")
	for _, vs := range sortedVirtualServices(proxy.VirtualServices) {
		if !vs.Enabled {
			continue
		}
		b.WriteString("    - name: ")
		b.WriteString(yamlQuote("openngfw_" + safeName(vs.Name)))
		b.WriteString("\n")
		b.WriteString("      address:\n")
		b.WriteString("        socket_address:\n")
		b.WriteString("          address: ")
		b.WriteString(yamlQuote(vs.Listener.BindAddress))
		b.WriteString("\n")
		b.WriteString("          port_value: ")
		b.WriteString(fmt.Sprintf("%d\n", vs.Listener.Port))
		b.WriteString("      filter_chains:\n")
		b.WriteString("        - filters:\n")
		b.WriteString("            - name: envoy.filters.network.http_connection_manager\n")
		b.WriteString("              typed_config:\n")
		b.WriteString("                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n")
		b.WriteString("                codec_type: AUTO\n")
		b.WriteString("                stat_prefix: ")
		b.WriteString(yamlQuote("openngfw_" + safeName(vs.Name)))
		b.WriteString("\n")
		b.WriteString("                route_config:\n")
		b.WriteString("                  name: ")
		b.WriteString(yamlQuote("route_" + safeName(vs.Name)))
		b.WriteString("\n")
		b.WriteString("                  virtual_hosts:\n")
		b.WriteString("                    - name: ")
		b.WriteString(yamlQuote("vhost_" + safeName(vs.Name)))
		b.WriteString("\n")
		b.WriteString("                      domains:\n")
		for _, host := range sortedStrings(vs.Hostnames) {
			b.WriteString("                        - ")
			b.WriteString(yamlQuote(host))
			b.WriteString("\n")
		}
		b.WriteString("                      routes:\n")
		for _, route := range sortedRoutes(vs.Routes) {
			b.WriteString("                        - match:\n")
			b.WriteString("                            prefix: ")
			b.WriteString(yamlQuote(route.PathPrefix))
			b.WriteString("\n")
			b.WriteString("                          route:\n")
			b.WriteString("                            cluster: ")
			b.WriteString(yamlQuote(clusterName(vs.Name, route.Name)))
			b.WriteString("\n")
			if route.StripPrefix {
				b.WriteString("                            prefix_rewrite: \"/\"\n")
			}
			if route.WAFPolicy != "" {
				b.WriteString("                          metadata:\n")
				b.WriteString("                            filter_metadata:\n")
				b.WriteString("                              openngfw.coraza:\n")
				b.WriteString("                                policy: ")
				b.WriteString(yamlQuote(route.WAFPolicy))
				b.WriteString("\n")
			}
		}
		b.WriteString("                http_filters:\n")
		b.WriteString("                  - name: envoy.filters.http.router\n")
		b.WriteString("                    typed_config:\n")
		b.WriteString("                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\n")
	}
	b.WriteString("  clusters:\n")
	for _, cluster := range sortedClusters(proxy.VirtualServices) {
		b.WriteString("    - name: ")
		b.WriteString(yamlQuote(cluster.name))
		b.WriteString("\n")
		b.WriteString("      connect_timeout: 5s\n")
		b.WriteString("      type: STRICT_DNS\n")
		b.WriteString("      lb_policy: ROUND_ROBIN\n")
		b.WriteString("      load_assignment:\n")
		b.WriteString("        cluster_name: ")
		b.WriteString(yamlQuote(cluster.name))
		b.WriteString("\n")
		b.WriteString("        endpoints:\n")
		b.WriteString("          - lb_endpoints:\n")
		for _, backend := range cluster.backends {
			b.WriteString("              - endpoint:\n")
			b.WriteString("                  address:\n")
			b.WriteString("                    socket_address:\n")
			b.WriteString("                      address: ")
			b.WriteString(yamlQuote(backend.host))
			b.WriteString("\n")
			b.WriteString("                      port_value: ")
			b.WriteString(fmt.Sprintf("%d\n", backend.port))
		}
	}
	return []byte(b.String())
}

func renderCorazaRules(proxy *compiler.ProxyIR) []byte {
	var b strings.Builder
	b.WriteString("# Generated by OpenNGFW controld. Do not edit; overwritten on every commit.\n")
	b.WriteString("# openngfw-proxy-runtime: coraza\n")
	for _, policy := range sortedWAFPolicies(proxy.WAFPolicies) {
		b.WriteString("\n")
		b.WriteString("# policy: ")
		b.WriteString(policy.Name)
		b.WriteString("\n")
		switch strings.ToLower(policy.Mode) {
		case "block", "prevent":
			b.WriteString("SecRuleEngine On\n")
		case "detect", "monitor":
			b.WriteString("SecRuleEngine DetectionOnly\n")
		default:
			b.WriteString("SecRuleEngine DetectionOnly\n")
		}
		if policy.RequestBodyLimitKB > 0 {
			b.WriteString("SecRequestBodyLimit ")
			b.WriteString(fmt.Sprintf("%d\n", policy.RequestBodyLimitKB*1024))
		}
		b.WriteString("SecAuditEngine ")
		if policy.AuditLogging {
			b.WriteString("RelevantOnly\n")
		} else {
			b.WriteString("Off\n")
		}
		for _, ruleset := range sortedRuleSets(policy.RuleSets) {
			b.WriteString("# ruleset: ")
			b.WriteString(ruleset.Name)
			b.WriteString(" version=")
			b.WriteString(ruleset.Version)
			b.WriteString(" source=")
			b.WriteString(ruleset.Source)
			b.WriteString(" sha256=")
			b.WriteString(ruleset.SHA256)
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

type clusterPlan struct {
	name     string
	backends []backendPlan
}

type backendPlan struct {
	host string
	port uint32
}

func sortedVirtualServices(in []compiler.VirtualServiceIR) []compiler.VirtualServiceIR {
	out := append([]compiler.VirtualServiceIR(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedRoutes(in []compiler.ProxyRouteIR) []compiler.ProxyRouteIR {
	out := append([]compiler.ProxyRouteIR(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedWAFPolicies(in []compiler.WAFPolicyIR) []compiler.WAFPolicyIR {
	out := append([]compiler.WAFPolicyIR(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedRuleSets(in []compiler.WAFRuleSetIR) []compiler.WAFRuleSetIR {
	out := append([]compiler.WAFRuleSetIR(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedClusters(vss []compiler.VirtualServiceIR) []clusterPlan {
	var clusters []clusterPlan
	for _, vs := range sortedVirtualServices(vss) {
		if !vs.Enabled {
			continue
		}
		for _, route := range sortedRoutes(vs.Routes) {
			cluster := clusterPlan{name: clusterName(vs.Name, route.Name)}
			for _, backend := range route.Backends {
				host, port := backendAddress(backend.URL)
				cluster.backends = append(cluster.backends, backendPlan{host: host, port: port})
			}
			sort.SliceStable(cluster.backends, func(i, j int) bool {
				if cluster.backends[i].host == cluster.backends[j].host {
					return cluster.backends[i].port < cluster.backends[j].port
				}
				return cluster.backends[i].host < cluster.backends[j].host
			})
			clusters = append(clusters, cluster)
		}
	}
	sort.SliceStable(clusters, func(i, j int) bool { return clusters[i].name < clusters[j].name })
	return clusters
}

func clusterName(service, route string) string {
	return "cluster_" + safeName(service) + "_" + safeName(route)
}

func backendAddress(raw string) (string, uint32) {
	host := raw
	if after, ok := strings.CutPrefix(host, "https://"); ok {
		host = after
	} else if after, ok := strings.CutPrefix(host, "http://"); ok {
		host = after
	}
	host, _, _ = strings.Cut(host, "/")
	if h, p, ok := strings.Cut(host, ":"); ok {
		if port, err := strconv.ParseUint(p, 10, 32); err == nil && port > 0 {
			return h, uint32(port)
		}
	}
	if strings.HasPrefix(raw, "https://") {
		return host, 443
	}
	return host, 80
}

func safeName(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	lastDash := false
	for _, r := range in {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('_')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unnamed"
	}
	return out
}

func yamlQuote(in string) string {
	raw, _ := json.Marshal(in)
	return string(raw)
}

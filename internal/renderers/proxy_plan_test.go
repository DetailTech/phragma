package renderers

import (
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestRenderAllIncludesProxyPlanArtifact(t *testing.T) {
	p := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
		Addresses: []*openngfwv1.Address{{Name: "lan-net", Cidr: "10.0.0.0/24"}},
		Services:  []*openngfwv1.Service{{Name: "https", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 443}}}},
		Rules:     []*openngfwv1.Rule{{Name: "lan-out", FromZones: []string{"lan"}, ToZones: []string{"wan"}, SourceAddresses: []string{"lan-net"}, Services: []string{"https"}, Action: openngfwv1.Action_ACTION_ALLOW}},
		Proxy: &openngfwv1.Proxy{
			WafPolicies: []*openngfwv1.WafPolicy{{
				Name:               "corp-waf",
				Mode:               openngfwv1.WafMode_WAF_MODE_DETECT,
				RequestBodyLimitKb: 64,
				AuditLogging:       true,
				RedactRequestBody:  true,
				RuleSets:           []*openngfwv1.WafRuleSet{{Name: "crs", Version: "4.0.0", Source: "owasp-crs", Sha256: strings.Repeat("b", 64)}},
			}},
			VirtualServices: []*openngfwv1.VirtualService{{
				Name:      "portal",
				Enabled:   true,
				Hostnames: []string{"portal.example.com"},
				Listener:  &openngfwv1.ProxyListener{BindAddress: "0.0.0.0", Port: 443, Tls: true, TlsSecretRef: "vault://openngfw/portal"},
				Routes: []*openngfwv1.ProxyRoute{{
					Name:                 "root",
					PathPrefix:           "/",
					WafPolicy:            "corp-waf",
					RequireMtlsToBackend: true,
					Backends:             []*openngfwv1.ProxyBackend{{Name: "portal-1", Url: "https://portal.internal", Weight: 100}},
				}},
			}},
		},
	}
	artifacts, err := RenderAll(p, DefaultOptions("/tmp/openngfw", "/tmp/openngfw-log"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(artifacts["proxy"])
	if !strings.Contains(got, `"schemaVersion": "openngfw.proxy.plan.v1"`) {
		t.Fatalf("proxy plan missing schema:\n%s", got)
	}
	if !strings.Contains(got, `"portal.example.com"`) {
		t.Fatalf("proxy plan missing virtual service hostname:\n%s", got)
	}
	if !strings.Contains(got, `"proofArtifacts"`) || !strings.Contains(got, `"planned-not-executed"`) {
		t.Fatalf("proxy plan missing bounded runtime proof artifacts:\n%s", got)
	}
}

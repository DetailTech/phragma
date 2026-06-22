package policy

import (
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestSemanticFindingsReportsRulebaseHygiene(t *testing.T) {
	p := &openngfwv1.Policy{
		Addresses: []*openngfwv1.Address{
			{Name: "client-net", Cidr: "10.0.1.0/24"},
			{Name: "web-server", Cidr: "10.0.2.10/32"},
			{Name: "unused-host", Cidr: "10.0.9.9/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "https", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 443}}},
			{Name: "unused-svc", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 9443}}},
		},
		Applications: []*openngfwv1.Application{{
			Name:     "unused-app",
			Category: "business-app",
			Ports: []*openngfwv1.ApplicationPort{{
				Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
				Ports:    []*openngfwv1.PortRange{{Start: 8443}},
			}},
		}},
		Rules: []*openngfwv1.Rule{
			{
				Name:                 "allow-client",
				FromZones:            []string{"lan"},
				ToZones:              []string{"wan"},
				SourceAddresses:      []string{"client-net"},
				DestinationAddresses: []string{"any"},
				Services:             []string{"https"},
				Action:               openngfwv1.Action_ACTION_ALLOW,
			},
			{
				Name:                 "deny-web",
				FromZones:            []string{"lan"},
				ToZones:              []string{"wan"},
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"web-server"},
				Services:             []string{"any"},
				Action:               openngfwv1.Action_ACTION_DENY,
				Log:                  true,
			},
		},
		HostInput: &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{{
			Name:            "mgmt-ssh",
			SourceAddresses: []string{"client-net"},
			Services:        []string{"https"},
			Action:          openngfwv1.Action_ACTION_ALLOW,
		}}},
	}

	findings := SemanticFindings(p)
	for _, want := range []string{
		"POLICY_HYGIENE_MISSING_RULE_LOG",
		"POLICY_HYGIENE_MISSING_HOST_INPUT_LOG",
		"POLICY_HYGIENE_RULE_OVERLAP",
		"POLICY_HYGIENE_UNUSED_ADDRESS",
		"POLICY_HYGIENE_UNUSED_SERVICE",
		"POLICY_HYGIENE_UNUSED_APPLICATION",
	} {
		if !hasFindingCode(findings, want) {
			t.Fatalf("missing %s in %#v", want, findings)
		}
	}
}

func TestSemanticFindingsDoNotReportDisabledRuleLogging(t *testing.T) {
	findings := SemanticFindings(&openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name:     "disabled",
		Action:   openngfwv1.Action_ACTION_ALLOW,
		Disabled: true,
	}}})
	for _, finding := range findings {
		if strings.Contains(finding.GetCode(), "MISSING_RULE_LOG") {
			t.Fatalf("disabled rule produced log warning: %#v", findings)
		}
	}
}

func hasFindingCode(findings []*openngfwv1.ValidationFinding, code string) bool {
	for _, finding := range findings {
		if finding.GetCode() == code {
			return true
		}
	}
	return false
}

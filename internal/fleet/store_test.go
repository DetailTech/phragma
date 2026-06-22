package fleet

import (
	"errors"
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestCreateTemplatePersistsSanitizedRecordAndSummary(t *testing.T) {
	store := NewStore(DefaultStorePath(t.TempDir()))
	policy := fleetTestPolicy()

	record, err := store.CreateTemplate(CreateTemplateInput{
		Name:          "  Branch   Edge  ",
		Description:   strings.Repeat("x", MaxDescriptionSize+32),
		Scope:         "",
		Labels:        []string{"Prod Edge", "prod-edge", " ", "PCI/DMZ"},
		Policy:        policy,
		CreatedBy:     "operator",
		CreatedByRole: "operator",
		AuthSource:    "local-users-file",
	})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if record.Name != "Branch Edge" {
		t.Fatalf("Name = %q, want sanitized name", record.Name)
	}
	if !strings.HasPrefix(record.ID, "tmpl-branch-edge-") {
		t.Fatalf("ID = %q, want slugged local template id", record.ID)
	}
	if record.Scope != "local-appliance" {
		t.Fatalf("Scope = %q, want local-appliance default", record.Scope)
	}
	if got := strings.Join(record.Labels, ","); got != "prod-edge,pci-dmz" {
		t.Fatalf("Labels = %q, want cleaned and deduplicated labels", got)
	}
	if len(record.Description) != MaxDescriptionSize {
		t.Fatalf("Description length = %d, want %d", len(record.Description), MaxDescriptionSize)
	}
	if record.Revision == "" || !strings.HasPrefix(record.Revision, "sha256:") {
		t.Fatalf("Revision = %q, want sha256 revision", record.Revision)
	}
	if record.Revision != TemplateRevision(record) {
		t.Fatalf("Revision = %q, want recomputed %q", record.Revision, TemplateRevision(record))
	}
	assertFleetPolicySummary(t, record.PolicySummary, PolicySummary{
		Zones:            2,
		Rules:            1,
		SourceNAT:        1,
		DestinationNAT:   1,
		StaticRoutes:     1,
		IPsecTunnels:     1,
		WireGuardPeers:   1,
		HostInputRules:   1,
		DynamicRouting:   true,
		SecurityProfiles: 1,
		Applications:     1,
	})

	reopened := NewStore(DefaultStorePath(strings.TrimSuffix(store.path, "/fleet/templates.json")))
	got, err := reopened.GetTemplate(strings.ToUpper(record.ID))
	if err != nil {
		t.Fatalf("GetTemplate with mixed case id: %v", err)
	}
	if got.ID != record.ID || got.Revision != record.Revision {
		t.Fatalf("reopened record = %#v, want %#v", got, record)
	}
	decoded, err := DecodePolicy(got.Policy)
	if err != nil {
		t.Fatalf("DecodePolicy: %v", err)
	}
	if decoded.GetRules()[0].GetName() != "allow-web" {
		t.Fatalf("decoded rule = %q, want allow-web", decoded.GetRules()[0].GetName())
	}
}

func TestCreateTemplateGeneratesUniqueIDsAndListsNewestFirst(t *testing.T) {
	store := NewStore(DefaultStorePath(t.TempDir()))

	first, err := store.CreateTemplate(CreateTemplateInput{Name: "Branch Edge", Policy: fleetTestPolicy()})
	if err != nil {
		t.Fatalf("CreateTemplate first: %v", err)
	}
	second, err := store.CreateTemplate(CreateTemplateInput{Name: "Branch Edge", Policy: fleetTestPolicy()})
	if err != nil {
		t.Fatalf("CreateTemplate second: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("duplicate template id %q", first.ID)
	}

	records, err := store.ListTemplates()
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ListTemplates returned %d records, want 2", len(records))
	}
	if records[0].UpdatedAt < records[1].UpdatedAt {
		t.Fatalf("records not newest-first: %#v", records)
	}
}

func TestRecordApplyResultPersistsFiltersAndCapsCustody(t *testing.T) {
	store := NewStore(DefaultStorePath(t.TempDir()))
	template, err := store.CreateTemplate(CreateTemplateInput{Name: "Branch Edge", Policy: fleetTestPolicy()})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	record, err := store.RecordApplyResult(ApplyRecord{
		TemplateID:       template.ID,
		TemplateName:     template.Name,
		TemplateRevision: template.Revision,
		RequestedBy:      "operator",
		RequestedByRole:  "operator",
		Status:           "applied",
		NodeResults: []ApplyNodeResult{
			{NodeID: "local", NodeName: "local appliance", Result: "applied", Mutation: "local candidate policy updated; running policy not applied"},
			{NodeID: "fw-peer", NodeName: "fw-peer", Result: "skipped", Mutation: "none"},
		},
	})
	if err != nil {
		t.Fatalf("RecordApplyResult: %v", err)
	}
	if record.ID == "" || record.StartedAt == "" || record.FinishedAt == "" {
		t.Fatalf("record missing generated custody fields: %#v", record)
	}
	got, err := store.ListApplyResults(template.ID)
	if err != nil {
		t.Fatalf("ListApplyResults: %v", err)
	}
	if len(got) != 1 || got[0].ID != record.ID || len(got[0].NodeResults) != 2 {
		t.Fatalf("ListApplyResults = %#v, want retained result", got)
	}
	if got[0].NodeResults[0].Result != "applied" || got[0].NodeResults[1].Result != "skipped" {
		t.Fatalf("node results = %#v, want applied/skipped", got[0].NodeResults)
	}
	for i := 0; i < MaxApplyResults+5; i++ {
		if _, err := store.RecordApplyResult(ApplyRecord{TemplateID: template.ID, TemplateRevision: template.Revision, Status: "blocked"}); err != nil {
			t.Fatalf("RecordApplyResult %d: %v", i, err)
		}
	}
	capped, err := store.ListApplyResults("")
	if err != nil {
		t.Fatalf("ListApplyResults all: %v", err)
	}
	if len(capped) != MaxApplyResults {
		t.Fatalf("retained result count = %d, want cap %d", len(capped), MaxApplyResults)
	}
}

func TestCreateTemplateRejectsInvalidInputsAndLimit(t *testing.T) {
	store := NewStore(DefaultStorePath(t.TempDir()))

	if _, err := store.CreateTemplate(CreateTemplateInput{Name: "missing policy"}); err == nil {
		t.Fatalf("CreateTemplate without policy succeeded")
	}
	if _, err := store.CreateTemplate(CreateTemplateInput{Name: "   ", Policy: fleetTestPolicy()}); err == nil {
		t.Fatalf("CreateTemplate without name succeeded")
	}

	for i := 0; i < MaxTemplates; i++ {
		if _, err := store.CreateTemplate(CreateTemplateInput{Name: "template", Policy: fleetTestPolicy()}); err != nil {
			t.Fatalf("CreateTemplate %d: %v", i, err)
		}
	}
	if _, err := store.CreateTemplate(CreateTemplateInput{Name: "one too many", Policy: fleetTestPolicy()}); !errors.Is(err, ErrTemplateLimit) {
		t.Fatalf("CreateTemplate over limit error = %v, want ErrTemplateLimit", err)
	}
}

func TestDecodePolicyAndNormalizeTemplateIDValidateBounds(t *testing.T) {
	if _, err := DecodePolicy(nil); err == nil {
		t.Fatalf("DecodePolicy with empty body succeeded")
	}
	if _, err := DecodePolicy([]byte(`{"unknownField":true,"zones":[{"name":"lan"}]}`)); err != nil {
		t.Fatalf("DecodePolicy should discard unknown fields: %v", err)
	}
	if _, err := DecodePolicy([]byte(`{"zones":`)); err == nil {
		t.Fatalf("DecodePolicy with malformed JSON succeeded")
	}
	if _, err := DecodePolicy(make([]byte, MaxPolicyJSONBytes+1)); err == nil {
		t.Fatalf("DecodePolicy over max bytes succeeded")
	}
	if got, err := NormalizeTemplateID(" TMPL-EDGE_1.2 "); err != nil || got != "tmpl-edge_1.2" {
		t.Fatalf("NormalizeTemplateID = %q, %v; want tmpl-edge_1.2", got, err)
	}
	for _, id := range []string{"", "edge", "tmpl-x", "tmpl-edge!"} {
		if _, err := NormalizeTemplateID(id); err == nil {
			t.Fatalf("NormalizeTemplateID(%q) succeeded", id)
		}
	}
}

func fleetTestPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}, {Name: "wan"}},
		Addresses: []*openngfwv1.Address{
			{Name: "client-net", Cidr: "10.0.1.0/24"},
			{Name: "web-server", Cidr: "10.0.2.10/32"},
		},
		Services: []*openngfwv1.Service{{
			Name:     "https",
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 443}},
		}},
		Applications: []*openngfwv1.Application{{Name: "app-web", Category: "business"}},
		SecurityProfiles: []*openngfwv1.SecurityProfile{{
			Name:          "inspect",
			TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
		}},
		Rules: []*openngfwv1.Rule{{
			Name:                 "allow-web",
			FromZones:            []string{"lan"},
			ToZones:              []string{"wan"},
			SourceAddresses:      []string{"client-net"},
			DestinationAddresses: []string{"web-server"},
			Services:             []string{"https"},
			Action:               openngfwv1.Action_ACTION_ALLOW,
			Log:                  true,
		}},
		Nat: &openngfwv1.Nat{
			Source:      []*openngfwv1.SourceNat{{Name: "snat-out", ToZone: "wan", Masquerade: true}},
			Destination: []*openngfwv1.DestinationNat{{Name: "dnat-web", FromZone: "wan", Service: "https", TranslatedAddress: "web-server"}},
		},
		StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "0.0.0.0/0", Via: "198.51.100.1"}},
		Vpn: &openngfwv1.Vpn{
			IpsecTunnels: []*openngfwv1.IpsecTunnel{{Name: "branch-vpn"}},
			WireguardInterfaces: []*openngfwv1.WireguardInterface{{
				Name:  "wg0",
				Peers: []*openngfwv1.WireguardPeer{{Name: "branch"}},
			}},
		},
		HostInput: &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{{Name: "mgmt-ssh"}}},
		Routing:   &openngfwv1.Routing{Bgp: &openngfwv1.Bgp{Enabled: true}},
	}
}

func assertFleetPolicySummary(t *testing.T, got, want PolicySummary) {
	t.Helper()
	if got != want {
		t.Fatalf("PolicySummary = %#v, want %#v", got, want)
	}
}

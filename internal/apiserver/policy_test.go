package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
	policyidentity "github.com/detailtech/oss-ngfw/internal/policy"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestPolicyValidateReturnsImpact(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name: "allow-any", Action: openngfwv1.Action_ACTION_ALLOW, Log: true,
	}}}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("candidate should be valid: %v", resp.GetErrors())
	}
	if resp.GetImpact().GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("impact risk = %s, want high", resp.GetImpact().GetRisk())
	}
	if got := len(resp.GetImpact().GetItems()); got == 0 {
		t.Fatalf("expected impact items, got %d", got)
	}
	if !hasValidationFinding(resp.GetFindings(), openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING, openngfwv1.ValidationStage_VALIDATION_STAGE_IMPACT, "POLICY_IMPACT_HIGH", "New active allow rule") {
		t.Fatalf("missing structured impact finding: %#v", resp.GetFindings())
	}
}

func TestPolicyValidateReturnsFlowtableImpact(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
		Network: &openngfwv1.Network{EnableFlowOffload: true},
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("candidate should be valid: %v", resp.GetErrors())
	}
	if !hasAPIImpact(resp.GetImpact().GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path enabled") {
		t.Fatalf("missing flowtable impact: %#v", resp.GetImpact().GetItems())
	}
}

func TestPolicyValidateReturnsStructuredErrors(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		t.Fatalf("render should not run when policy model validation fails")
		return nil, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
		Rules: []*openngfwv1.Rule{{
			Name:      "bad-ref",
			FromZones: []string{"missing"},
			Action:    openngfwv1.Action_ACTION_ALLOW,
		}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("candidate should be invalid")
	}
	if len(resp.GetErrors()) == 0 {
		t.Fatalf("expected compatibility errors")
	}
	if resp.GetRenderPlan() != nil {
		t.Fatalf("render plan should be empty before render: %#v", resp.GetRenderPlan())
	}
	if !hasValidationFinding(resp.GetFindings(), openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR, openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL, "POLICY_VALIDATION_ERROR", "references unknown zone") {
		t.Fatalf("missing structured validation error: %#v", resp.GetFindings())
	}
}

func TestPolicyValidateReturnsRenderPlan(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{
			"nftables": []byte("table inet phragma {}"),
			"vector":   []byte("sources: {}"),
		}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("candidate should be valid: %v", resp.GetErrors())
	}
	plan := resp.GetRenderPlan()
	if plan.GetArtifactCount() != 2 || len(plan.GetArtifacts()) != 2 {
		t.Fatalf("render plan = %#v, want two artifacts", plan)
	}
	if plan.GetTotalBytes() != uint64(len("table inet phragma {}")+len("sources: {}")) {
		t.Fatalf("total bytes = %d", plan.GetTotalBytes())
	}
	if plan.GetArtifacts()[0].GetName() != "nftables" || plan.GetArtifacts()[1].GetName() != "vector" {
		t.Fatalf("artifacts not sorted/stable: %#v", plan.GetArtifacts())
	}
}

func TestPolicyValidateReturnsSemanticHygieneFindings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := validReferencePolicy()
	candidate.Rules[0].DestinationAddresses = []string{"any"}
	candidate.Rules = append(candidate.Rules, &openngfwv1.Rule{
		Name:                 "deny-web",
		FromZones:            []string{"lan"},
		ToZones:              []string{"wan"},
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"web-server"},
		Services:             []string{"any"},
		Action:               openngfwv1.Action_ACTION_DENY,
		Log:                  true,
	})
	candidate.Addresses = append(candidate.Addresses, &openngfwv1.Address{Name: "unused-host", Cidr: "10.0.9.9/32"})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("candidate should be valid: %v", resp.GetErrors())
	}
	if !hasValidationFinding(resp.GetFindings(), openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING, openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL, "POLICY_HYGIENE_MISSING_RULE_LOG", "logging disabled") {
		t.Fatalf("missing missing-log finding: %#v", resp.GetFindings())
	}
	if !hasValidationFinding(resp.GetFindings(), openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING, openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL, "POLICY_HYGIENE_RULE_OVERLAP", "overlapping") {
		t.Fatalf("missing overlap finding: %#v", resp.GetFindings())
	}
	if !hasValidationFinding(resp.GetFindings(), openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING, openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL, "POLICY_HYGIENE_UNUSED_ADDRESS", "unused") {
		t.Fatalf("missing unused-object finding: %#v", resp.GetFindings())
	}
}

func TestPolicyValidateAnnotatesRuleOverlapMetadata(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := validReferencePolicy()
	candidate.Rules[0].Id = "rule-allow-web"
	candidate.Rules[0].Name = "allow-web"
	candidate.Rules[0].DestinationAddresses = []string{"any"}
	candidate.Rules = append(candidate.Rules, &openngfwv1.Rule{
		Id:                   "rule-deny-web",
		Name:                 "deny-web",
		FromZones:            []string{"lan"},
		ToZones:              []string{"wan"},
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"web-server"},
		Services:             []string{"any"},
		Action:               openngfwv1.Action_ACTION_DENY,
		Log:                  true,
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var overlap *openngfwv1.ValidationFinding
	for _, finding := range resp.GetFindings() {
		if finding.GetCode() == "POLICY_HYGIENE_RULE_OVERLAP" {
			overlap = finding
			break
		}
	}
	if overlap == nil {
		t.Fatalf("missing overlap finding: %#v", resp.GetFindings())
	}
	var envelope struct {
		Text string `json:"text"`
		Peer struct {
			Index int    `json:"index"`
			ID    string `json:"id"`
			Name  string `json:"name"`
		} `json:"peer"`
		Dimensions []struct {
			Key    string `json:"key"`
			Result string `json:"result"`
			Sample string `json:"sample"`
		} `json:"dimensions"`
		Result struct {
			ID          string   `json:"id"`
			RuleIndex   int      `json:"ruleIndex"`
			RuleID      string   `json:"ruleId"`
			RuleName    string   `json:"ruleName"`
			PeerIndex   int      `json:"peerIndex"`
			PeerID      string   `json:"peerId"`
			PeerName    string   `json:"peerName"`
			Outcome     string   `json:"outcome"`
			RiskLabels  []string `json:"riskLabels"`
			IdentityKey string   `json:"identityKey"`
		} `json:"result"`
		Page struct {
			Limit        int    `json:"limit"`
			ResultIndex  int    `json:"resultIndex"`
			TotalResults int    `json:"totalResults"`
			Truncated    bool   `json:"truncated"`
			PageKey      string `json:"pageKey"`
		} `json:"page"`
	}
	if err := json.Unmarshal([]byte(overlap.GetDetail()), &envelope); err != nil {
		t.Fatalf("overlap detail is not metadata JSON: %v: %s", err, overlap.GetDetail())
	}
	if envelope.Peer.Index != 0 || envelope.Peer.ID != "rule-allow-web" || envelope.Peer.Name != "allow-web" {
		t.Fatalf("peer metadata = %#v", envelope.Peer)
	}
	if envelope.Result.RuleIndex != 1 || envelope.Result.RuleID != "rule-deny-web" || envelope.Result.RuleName != "deny-web" {
		t.Fatalf("result rule metadata = %#v", envelope.Result)
	}
	if envelope.Result.PeerIndex != 0 || envelope.Result.PeerID != "rule-allow-web" || envelope.Result.Outcome != "first-match-order-review" {
		t.Fatalf("result peer/outcome metadata = %#v", envelope.Result)
	}
	if !containsPolicyString(envelope.Result.RiskLabels, "allow-before-deny") || !containsPolicyString(envelope.Result.RiskLabels, "log-gap") {
		t.Fatalf("risk labels = %#v", envelope.Result.RiskLabels)
	}
	if envelope.Page.Limit != 25 || envelope.Page.ResultIndex != 0 || envelope.Page.TotalResults != 1 || envelope.Page.Truncated {
		t.Fatalf("page metadata = %#v", envelope.Page)
	}
	if envelope.Page.PageKey != "policy-hygiene-rule-overlap:v1" || !strings.Contains(envelope.Result.IdentityKey, "rules[1]:peer[0]") {
		t.Fatalf("identity metadata result=%#v page=%#v", envelope.Result, envelope.Page)
	}
	if len(envelope.Dimensions) == 0 {
		t.Fatalf("missing dimension metadata")
	}
}

func TestPolicyValidateRequestPolicyDoesNotRequireCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	var rendered *openngfwv1.Policy
	srv := NewPolicyServer(st, engines.NewSupervisor(), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		rendered = p
		return map[string][]byte{}, nil
	})
	imported := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "lan"}}}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{Policy: imported})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("imported policy should be valid: %v", resp.GetErrors())
	}
	normalized, _ := policyidentity.NormalizeRuleIDs(imported)
	if !proto.Equal(rendered, normalized) {
		t.Fatalf("render pipeline received %#v, want normalized imported policy %#v", rendered, normalized)
	}
}

func TestPolicyValidateRequestPolicyDoesNotReplaceCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	original := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "existing"}}}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: original}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	imported := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name: "allow-any", Action: openngfwv1.Action_ACTION_ALLOW,
	}}}

	resp, err := srv.Validate(context.Background(), &openngfwv1.ValidateRequest{Policy: imported})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("imported policy should be valid: %v", resp.GetErrors())
	}
	if resp.GetImpact().GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("impact risk = %s, want high", resp.GetImpact().GetRisk())
	}
	cand, err := srv.GetPolicy(context.Background(), &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
	if err != nil {
		t.Fatalf("Get candidate: %v", err)
	}
	if got := cand.GetPolicy().GetZones()[0].GetName(); got != "existing" {
		t.Fatalf("candidate zone = %q, want existing", got)
	}
}

func TestPolicySetCandidateRejectsStaleCandidateRevision(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	initialRevision := statusResp.GetCandidateRevision()
	if initialRevision == "" {
		t.Fatal("initial candidate revision is empty")
	}

	firstResp, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{
		Policy:                    &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "first"}}},
		ExpectedCandidateRevision: initialRevision,
	})
	if err != nil {
		t.Fatalf("first SetCandidate: %v", err)
	}
	if firstResp.GetCandidateRevision() == "" || firstResp.GetCandidateRevision() == initialRevision {
		t.Fatalf("first response revision = %q, initial = %q", firstResp.GetCandidateRevision(), initialRevision)
	}

	_, err = srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{
		Policy:                    &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "stale"}}},
		ExpectedCandidateRevision: initialRevision,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale SetCandidate error = %v, want FailedPrecondition", err)
	}
	cand, err := srv.GetPolicy(context.Background(), &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
	if err != nil {
		t.Fatalf("Get candidate: %v", err)
	}
	if got := cand.GetPolicy().GetZones()[0].GetName(); got != "first" {
		t.Fatalf("candidate zone after stale write = %q, want first", got)
	}
}

func TestPolicyNatMutationStagesCandidateWithRevisionGuard(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	base := validNatPolicyFixture()
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: base}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}

	resp, err := srv.UpsertCandidateSourceNat(context.Background(), &openngfwv1.UpsertCandidateSourceNatRequest{
		Rule: &openngfwv1.SourceNat{
			Name:              "lan-static",
			ToZone:            "wan",
			SourceAddress:     "client-net",
			TranslatedAddress: "wan-ip",
		},
		ExpectedCandidateRevision: statusResp.GetCandidateRevision(),
		Comment:                   "stage source NAT",
	})
	if err != nil {
		t.Fatalf("UpsertCandidateSourceNat: %v", err)
	}
	if resp.GetAction() != "added" || resp.GetNatType() != "source" || resp.GetCandidateRevision() == "" {
		t.Fatalf("upsert response = %#v", resp)
	}
	if !resp.GetValidation().GetValid() {
		t.Fatalf("validation should be valid: %#v", resp.GetValidation())
	}
	if resp.GetCandidateStatus().GetCandidateRevision() != resp.GetCandidateRevision() {
		t.Fatalf("candidate status revision = %q, want %q", resp.GetCandidateStatus().GetCandidateRevision(), resp.GetCandidateRevision())
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate ok=%v err=%v", ok, err)
	}
	if len(got.GetNat().GetSource()) != 1 || got.GetNat().GetSource()[0].GetName() != "lan-static" {
		t.Fatalf("source NAT not staged: %#v", got.GetNat().GetSource())
	}

	_, err = srv.DeleteCandidateSourceNat(context.Background(), &openngfwv1.DeleteCandidateSourceNatRequest{
		Name:                      "lan-static",
		ExpectedCandidateRevision: statusResp.GetCandidateRevision(),
		Comment:                   "stale delete",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale delete error = %v, want FailedPrecondition", err)
	}
}

func TestPolicyNatListAndDestinationDelete(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := validNatPolicyFixture()
	candidate.Nat = &openngfwv1.Nat{Destination: []*openngfwv1.DestinationNat{{
		Name:               "web-dnat",
		FromZone:           "wan",
		Service:            "https",
		DestinationAddress: "wan-ip",
		TranslatedAddress:  "web-server",
		TranslatedPort:     8443,
	}}}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	listResp, err := srv.ListNatRules(context.Background(), &openngfwv1.ListNatRulesRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
	if err != nil {
		t.Fatalf("ListNatRules: %v", err)
	}
	if listResp.GetSource() != "candidate" || len(listResp.GetDestinationNat()) != 1 {
		t.Fatalf("list response = %#v", listResp)
	}
	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	delResp, err := srv.DeleteCandidateDestinationNat(context.Background(), &openngfwv1.DeleteCandidateDestinationNatRequest{
		Name:                      "web-dnat",
		ExpectedCandidateRevision: statusResp.GetCandidateRevision(),
		Reason:                    "remove retired VIP",
	})
	if err != nil {
		t.Fatalf("DeleteCandidateDestinationNat: %v", err)
	}
	if delResp.GetAction() != "deleted" || delResp.GetDestinationNat().GetName() != "web-dnat" {
		t.Fatalf("delete response = %#v", delResp)
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate ok=%v err=%v", ok, err)
	}
	if len(got.GetNat().GetDestination()) != 0 {
		t.Fatalf("destination NAT still present: %#v", got.GetNat().GetDestination())
	}
}

func TestPolicyNatMutationByIDRenamesAndDeletesDurableRule(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := validNatPolicyFixture()
	candidate.Nat = &openngfwv1.Nat{
		Source: []*openngfwv1.SourceNat{{
			Name:              "lan-egress",
			ToZone:            "wan",
			SourceAddress:     "client-net",
			TranslatedAddress: "wan-ip",
			Id:                "snat-lan-egress",
		}},
		Destination: []*openngfwv1.DestinationNat{{
			Name:               "web-dnat",
			FromZone:           "wan",
			Service:            "https",
			DestinationAddress: "public-web",
			TranslatedAddress:  "web-server",
			Id:                 "dnat-web",
		}},
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	upsertResp, err := srv.UpsertCandidateSourceNat(context.Background(), &openngfwv1.UpsertCandidateSourceNatRequest{
		Id: "snat-lan-egress",
		Rule: &openngfwv1.SourceNat{
			Name:              "lan-egress-renamed",
			ToZone:            "wan",
			SourceAddress:     "client-net",
			TranslatedAddress: "wan-ip",
		},
		ExpectedCandidateRevision: statusResp.GetCandidateRevision(),
		Comment:                   "rename by durable ID",
	})
	if err != nil {
		t.Fatalf("UpsertCandidateSourceNat by ID: %v", err)
	}
	if upsertResp.GetAction() != "updated" ||
		upsertResp.GetSourceNat().GetName() != "lan-egress-renamed" ||
		upsertResp.GetSourceNat().GetId() != "snat-lan-egress" {
		t.Fatalf("source NAT by-ID upsert response = %#v", upsertResp)
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate ok=%v err=%v", ok, err)
	}
	if len(got.GetNat().GetSource()) != 1 ||
		got.GetNat().GetSource()[0].GetName() != "lan-egress-renamed" ||
		got.GetNat().GetSource()[0].GetId() != "snat-lan-egress" {
		t.Fatalf("source NAT by-ID update not preserved: %#v", got.GetNat().GetSource())
	}

	statusResp, err = srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus after source update: %v", err)
	}
	deleteResp, err := srv.DeleteCandidateDestinationNat(context.Background(), &openngfwv1.DeleteCandidateDestinationNatRequest{
		Id:                        "dnat-web",
		ExpectedCandidateRevision: statusResp.GetCandidateRevision(),
		Reason:                    "remove by durable ID",
	})
	if err != nil {
		t.Fatalf("DeleteCandidateDestinationNat by ID: %v", err)
	}
	if deleteResp.GetAction() != "deleted" ||
		deleteResp.GetDestinationNat().GetName() != "web-dnat" ||
		deleteResp.GetDestinationNat().GetId() != "dnat-web" {
		t.Fatalf("destination NAT by-ID delete response = %#v", deleteResp)
	}
	got, ok, err = st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate after delete ok=%v err=%v", ok, err)
	}
	if len(got.GetNat().GetDestination()) != 0 {
		t.Fatalf("destination NAT by-ID delete left rules: %#v", got.GetNat().GetDestination())
	}
}

func TestPolicyNatMutationByIDRejectsMismatchAndMissingID(t *testing.T) {
	p := &openngfwv1.Policy{Nat: &openngfwv1.Nat{Source: []*openngfwv1.SourceNat{{
		Name:              "lan-egress",
		ToZone:            "wan",
		TranslatedAddress: "wan-ip",
		Id:                "snat-lan",
	}}}}
	_, err := upsertSourceNat(p, &openngfwv1.SourceNat{
		Name:              "renamed",
		ToZone:            "wan",
		TranslatedAddress: "wan-ip",
		Id:                "snat-other",
	}, "snat-lan")
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "does not match requested id") {
		t.Fatalf("mismatch error = %v, want InvalidArgument mismatch", err)
	}
	_, err = deleteSourceNat(p, "", "snat-missing")
	if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "select a current durable ID") {
		t.Fatalf("missing ID error = %v, want NotFound recovery guidance", err)
	}
	ambiguous := &openngfwv1.Policy{Nat: &openngfwv1.Nat{Destination: []*openngfwv1.DestinationNat{
		{Name: "one", Id: "dnat-dup"},
		{Name: "two", Id: "dnat-dup"},
	}}}
	_, err = deleteDestinationNat(ambiguous, "", "dnat-dup")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous ID error = %v, want FailedPrecondition", err)
	}
}

func TestPolicyGetCandidateStatusNoCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	resp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	if resp.GetHasCandidate() || resp.GetDirty() || resp.GetChangeCount() != 0 || len(resp.GetChanges()) != 0 {
		t.Fatalf("unexpected status for fresh store: %#v", resp)
	}
	if resp.GetRunningVersion() != 0 {
		t.Fatalf("running version = %d, want 0", resp.GetRunningVersion())
	}
	if resp.GetImpact().GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_LOW {
		t.Fatalf("impact risk = %s, want low", resp.GetImpact().GetRisk())
	}
	if resp.GetCandidateRevision() == "" {
		t.Fatal("candidate revision is empty")
	}
}

func TestPolicyGetCandidateStatusReportsSectionChanges(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	running := validReferencePolicy()
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: running}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	candidate := validReferencePolicy()
	candidate.Addresses[0].Cidr = "10.0.10.0/24"
	candidate.SecurityProfiles = append(candidate.SecurityProfiles, &openngfwv1.SecurityProfile{
		Name:          "inspect-strict",
		Description:   "Strict profile for changed candidate status coverage.",
		TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
		DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
	})
	candidate.Rules = append(candidate.Rules, &openngfwv1.Rule{
		Name:                 "deny-admin",
		FromZones:            []string{"wan"},
		ToZones:              []string{"lan"},
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"web-server"},
		Services:             []string{"ssh"},
		SecurityProfiles:     []string{"inspect-strict"},
		Action:               openngfwv1.Action_ACTION_DENY,
	})
	candidate.Network = &openngfwv1.Network{EnableFlowOffload: true}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate candidate: %v", err)
	}

	resp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	if !resp.GetHasCandidate() || !resp.GetDirty() {
		t.Fatalf("status should report dirty candidate: %#v", resp)
	}
	if resp.GetRunningVersion() != 1 {
		t.Fatalf("running version = %d, want 1", resp.GetRunningVersion())
	}
	if resp.GetChangeCount() != 4 {
		t.Fatalf("change count = %d, want 4 (%#v)", resp.GetChangeCount(), resp.GetChanges())
	}
	assertCandidateChange(t, resp.GetChanges(), "rules", 1, 0, 0)
	assertCandidateChange(t, resp.GetChanges(), "addresses", 0, 1, 0)
	assertCandidateChange(t, resp.GetChanges(), "securityProfiles", 1, 0, 0)
	assertCandidateChange(t, resp.GetChanges(), "network", 0, 1, 0)
	if resp.GetImpact().GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("impact risk = %s, want high", resp.GetImpact().GetRisk())
	}
}

func TestPolicyGetCandidateStatusCountsRuleOrderOnlyChange(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	running := validReferencePolicy()
	running.Rules = append(running.Rules, &openngfwv1.Rule{
		Name:                 "deny-admin",
		FromZones:            []string{"wan"},
		ToZones:              []string{"lan"},
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"web-server"},
		Services:             []string{"ssh"},
		Action:               openngfwv1.Action_ACTION_DENY,
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: running}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	candidate := validReferencePolicy()
	candidate.Rules = []*openngfwv1.Rule{running.Rules[1], running.Rules[0]}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate candidate: %v", err)
	}

	resp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	if !resp.GetDirty() || resp.GetChangeCount() != 1 {
		t.Fatalf("status should report one rule-order change: %#v", resp)
	}
	assertCandidateChange(t, resp.GetChanges(), "rules", 0, 1, 0)
}

func TestPolicyListObjectReferencesCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
		Name:   "web-server",
	})
	if err != nil {
		t.Fatalf("ListObjectReferences: %v", err)
	}
	if resp.GetVersion() != 0 {
		t.Fatalf("candidate version = %d, want 0", resp.GetVersion())
	}
	if got := apiReferenceKeys(resp.GetReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"web-server:security rule:allow-web:destination address",
		"web-server:security rule:drop-admin:destination address",
		"web-server:destination NAT:published-web:translated address",
	}, "\n") {
		t.Fatalf("references = %#v", got)
	}
	if got := resp.GetReferences()[2].GetDetail(); got != "Traffic is translated to this address." {
		t.Fatalf("translated detail = %q", got)
	}
}

func TestPolicyListObjectReferencesAllForKindSkipsAny(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE,
	})
	if err != nil {
		t.Fatalf("ListObjectReferences: %v", err)
	}
	got := apiReferenceKeys(resp.GetReferences())
	want := []string{
		"lan:security rule:allow-web:from zone",
		"wan:security rule:allow-web:to zone",
		"wan:security rule:drop-admin:from zone",
		"lan:security rule:drop-admin:to zone",
		"lan:host-input rule:mgmt-ssh:from zone",
		"wan:source NAT:lan-egress:to zone",
		"wan:destination NAT:published-web:from zone",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("references = %#v", got)
	}
	for _, key := range got {
		if strings.HasPrefix(key, "any:") {
			t.Fatalf("wildcard any should not be reported as an object reference: %#v", got)
		}
	}
}

func TestPolicyListObjectReferencesSecurityProfile(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE,
		Name:   "inspect-standard",
	})
	if err != nil {
		t.Fatalf("ListObjectReferences: %v", err)
	}
	if got := apiReferenceKeys(resp.GetReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"inspect-standard:security rule:allow-web:security profile",
		"inspect-standard:security rule:drop-admin:security profile",
	}, "\n") {
		t.Fatalf("references = %#v", got)
	}
	if got := resp.GetReferences()[0].GetDetail(); got != "Layered inspection profile attached to this rule." {
		t.Fatalf("security profile detail = %q", got)
	}
	if got := resp.GetReferences()[0].GetItemId(); got != "rule-allow-web" {
		t.Fatalf("security rule item_id = %q, want rule-allow-web", got)
	}
	if got := resp.GetReferences()[1].GetItemId(); got != "rule-drop-admin" {
		t.Fatalf("security rule item_id = %q, want rule-drop-admin", got)
	}
}

func TestPolicyListObjectReferencesNonForwardingItemIDs(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	tests := []struct {
		name       string
		kind       openngfwv1.PolicyObjectKind
		objectName string
		area       string
		field      string
		wantID     string
	}{
		{name: "source NAT", kind: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS, objectName: "client-net", area: "source NAT", field: "source address", wantID: "snat-lan-egress-custom"},
		{name: "destination NAT", kind: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS, objectName: "public-web", area: "destination NAT", field: "destination address", wantID: "dnat-published-web-custom"},
		{name: "host input", kind: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS, objectName: "admin-host", area: "host-input rule", field: "source address", wantID: "host-input-mgmt-ssh-custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
				Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
				Kind:   tt.kind,
				Name:   tt.objectName,
			})
			if err != nil {
				t.Fatalf("ListObjectReferences: %v", err)
			}
			ref := findAPIReference(resp.GetReferences(), tt.area, tt.field)
			if ref == nil {
				t.Fatalf("missing %s/%s reference in %#v", tt.area, tt.field, apiReferenceKeys(resp.GetReferences()))
			}
			if got := ref.GetItemId(); got != tt.wantID {
				t.Fatalf("%s item_id = %q, want %q", tt.name, got, tt.wantID)
			}
		})
	}
}

func TestPolicyListObjectReferencesTrafficControlProfiles(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	qosResp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE,
		Name:   "latency-critical",
	})
	if err != nil {
		t.Fatalf("ListObjectReferences QoS profile: %v", err)
	}
	if got := apiReferenceKeys(qosResp.GetReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"latency-critical:security rule:allow-web:QoS profile",
		"latency-critical:security rule:drop-admin:QoS profile",
	}, "\n") {
		t.Fatalf("QoS references = %#v", got)
	}
	if got := qosResp.GetReferences()[0].GetDetail(); got != "Traffic shaping intent attached to this rule." {
		t.Fatalf("QoS detail = %q", got)
	}

	zoneProtectionResp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE,
		Name:   "edge-dos-watch",
	})
	if err != nil {
		t.Fatalf("ListObjectReferences zone-protection profile: %v", err)
	}
	if got := apiReferenceKeys(zoneProtectionResp.GetReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"edge-dos-watch:zone:wan:zone-protection profile",
	}, "\n") {
		t.Fatalf("zone-protection references = %#v", got)
	}
	if got := zoneProtectionResp.GetReferences()[0].GetDetail(); got != "DoS protection intent attached to this zone." {
		t.Fatalf("zone-protection detail = %q", got)
	}
	if got := zoneProtectionResp.GetReferences()[0].GetItemId(); got != "" {
		t.Fatalf("non-rule item_id = %q, want empty", got)
	}
}

func TestPolicyListObjectReferencesRejectsMissingKind(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	_, err = srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestPolicyListObjectReferencesVersionRequiresVersion(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	_, err = srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
		Source: openngfwv1.PolicySource_POLICY_SOURCE_VERSION,
		Kind:   openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestPolicyListObjectReferencesRunningAndVersion(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	p := validReferencePolicy()
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial references", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	for _, source := range []openngfwv1.PolicySource{
		openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		openngfwv1.PolicySource_POLICY_SOURCE_VERSION,
	} {
		resp, err := srv.ListObjectReferences(context.Background(), &openngfwv1.ListObjectReferencesRequest{
			Source:  source,
			Version: 1,
			Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
			Name:    "web-server",
		})
		if err != nil {
			t.Fatalf("ListObjectReferences(%s): %v", source, err)
		}
		if resp.GetVersion() != 1 {
			t.Fatalf("version = %d, want 1", resp.GetVersion())
		}
		if got := apiReferenceKeys(resp.GetReferences()); strings.Join(got, "\n") != "web-server:security rule:allow-web:destination address" {
			t.Fatalf("references = %#v", got)
		}
	}
}

func TestPolicyRenameObjectRewritesCandidateReferences(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	running := referencePolicyFixture()
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: running}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial references", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	candidate := referencePolicyFixture()
	candidate.GetIds().Exceptions = []*openngfwv1.IdsException{{
		Name:               "fp-web-server",
		SignatureId:        9000001,
		DestinationAddress: "web-server",
		Description:        "candidate exception scoped to the web host",
	}}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate candidate: %v", err)
	}

	resp, err := srv.RenamePolicyObject(context.Background(), &openngfwv1.RenamePolicyObjectRequest{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
		OldName: "web-server",
		NewName: "dmz-web",
		Comment: "operator renamed shared object",
	})
	if err != nil {
		t.Fatalf("RenamePolicyObject: %v", err)
	}
	if !resp.GetObjectRenamed() || resp.GetOldName() != "web-server" || resp.GetNewName() != "dmz-web" {
		t.Fatalf("rename response = %#v", resp)
	}
	if got := apiReferenceKeys(resp.GetRewrittenReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"dmz-web:security rule:allow-web:destination address",
		"dmz-web:security rule:drop-admin:destination address",
		"dmz-web:destination NAT:published-web:translated address",
		"dmz-web:IDS exception:fp-web-server:destination address",
	}, "\n") {
		t.Fatalf("rewritten references = %#v", got)
	}
	if ref := findAPIReference(resp.GetRewrittenReferences(), "destination NAT", "translated address"); ref == nil || ref.GetItemId() != "dnat-published-web-custom" {
		t.Fatalf("rewritten destination NAT item_id = %#v, want dnat-published-web-custom", ref)
	}
	if !resp.GetCandidateStatus().GetHasCandidate() || !resp.GetCandidateStatus().GetDirty() {
		t.Fatalf("candidate status = %#v", resp.GetCandidateStatus())
	}

	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate after rename ok=%v err=%v", ok, err)
	}
	if got.GetAddresses()[1].GetName() != "dmz-web" {
		t.Fatalf("address was not renamed: %#v", got.GetAddresses())
	}
	if got.GetRules()[0].GetDestinationAddresses()[0] != "dmz-web" ||
		got.GetRules()[1].GetDestinationAddresses()[0] != "dmz-web" ||
		got.GetNat().GetDestination()[0].GetTranslatedAddress() != "dmz-web" ||
		got.GetIds().GetExceptions()[0].GetDestinationAddress() != "dmz-web" {
		t.Fatalf("candidate references not rewritten: %#v", got)
	}
	runningAfter, _, err := st.GetRunning()
	if err != nil {
		t.Fatalf("GetRunning: %v", err)
	}
	if runningAfter.GetAddresses()[1].GetName() != "web-server" {
		t.Fatalf("running policy should not be mutated: %#v", runningAfter.GetAddresses())
	}
}

func TestPolicyRenameTrafficControlObjectsRewritesCandidateReferences(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	qosResp, err := srv.RenamePolicyObject(context.Background(), &openngfwv1.RenamePolicyObjectRequest{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE,
		OldName: "latency-critical",
		NewName: "low-latency-critical",
	})
	if err != nil {
		t.Fatalf("RenamePolicyObject QoS profile: %v", err)
	}
	if got := apiReferenceKeys(qosResp.GetRewrittenReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"low-latency-critical:security rule:allow-web:QoS profile",
		"low-latency-critical:security rule:drop-admin:QoS profile",
	}, "\n") {
		t.Fatalf("QoS rewritten references = %#v", got)
	}

	zoneProtectionResp, err := srv.RenamePolicyObject(context.Background(), &openngfwv1.RenamePolicyObjectRequest{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE,
		OldName: "edge-dos-watch",
		NewName: "edge-dos-strict",
	})
	if err != nil {
		t.Fatalf("RenamePolicyObject zone-protection profile: %v", err)
	}
	if got := apiReferenceKeys(zoneProtectionResp.GetRewrittenReferences()); strings.Join(got, "\n") != strings.Join([]string{
		"edge-dos-strict:zone:wan:zone-protection profile",
	}, "\n") {
		t.Fatalf("zone-protection rewritten references = %#v", got)
	}

	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate after traffic-control renames ok=%v err=%v", ok, err)
	}
	if got.GetQosProfiles()[0].GetName() != "low-latency-critical" ||
		got.GetRules()[0].GetQosProfile() != "low-latency-critical" ||
		got.GetRules()[1].GetQosProfile() != "low-latency-critical" {
		t.Fatalf("QoS profile rename was not applied: %#v", got)
	}
	if got.GetZoneProtectionProfiles()[0].GetName() != "edge-dos-strict" ||
		got.GetZones()[1].GetZoneProtectionProfile() != "edge-dos-strict" {
		t.Fatalf("zone-protection profile rename was not applied: %#v", got)
	}
}

func TestPolicyRenameObjectRejectsMissingCandidateAndDuplicateName(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	_, err = srv.RenamePolicyObject(context.Background(), &openngfwv1.RenamePolicyObjectRequest{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
		OldName: "web-server",
		NewName: "dmz-web",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing candidate code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: referencePolicyFixture()}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	_, err = srv.RenamePolicyObject(context.Background(), &openngfwv1.RenamePolicyObjectRequest{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
		OldName: "web-server",
		NewName: "client-net",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate code = %v, want AlreadyExists (err=%v)", status.Code(err), err)
	}
}

func TestPolicyDiffDefaultRunningToCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: validReferencePolicy()}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	candidate := validReferencePolicy()
	candidate.Rules[0].Name = "allow-web-new"
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate candidate: %v", err)
	}

	resp, err := srv.DiffPolicy(context.Background(), &openngfwv1.DiffPolicyRequest{})
	if err != nil {
		t.Fatalf("DiffPolicy: %v", err)
	}
	if !resp.GetChanged() {
		t.Fatalf("changed = false, want true")
	}
	if resp.GetFromLabel() != "running policy v1" || resp.GetToLabel() != "candidate" {
		t.Fatalf("labels = %q -> %q", resp.GetFromLabel(), resp.GetToLabel())
	}
	if resp.GetFromVersion() != 1 || resp.GetToVersion() != 0 {
		t.Fatalf("versions = %d -> %d, want 1 -> 0", resp.GetFromVersion(), resp.GetToVersion())
	}
	if !hasDiffLine(resp.GetLines(), openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_DELETE, "  name: allow-web") ||
		!hasDiffLine(resp.GetLines(), openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_ADD, "  name: allow-web-new") {
		t.Fatalf("diff lines missing rule rename: %#v", resp.GetLines())
	}
}

func TestPolicyDiffReportsUnchangedCandidate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	p := validReferencePolicy()
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: validReferencePolicy()}); err != nil {
		t.Fatalf("SetCandidate candidate: %v", err)
	}

	resp, err := srv.DiffPolicy(context.Background(), &openngfwv1.DiffPolicyRequest{})
	if err != nil {
		t.Fatalf("DiffPolicy: %v", err)
	}
	if resp.GetChanged() || len(resp.GetLines()) != 0 {
		t.Fatalf("changed=%v lines=%#v, want no diff", resp.GetChanged(), resp.GetLines())
	}
}

func TestPolicyDiffVersionRequiresVersion(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	_, err = srv.DiffPolicy(context.Background(), &openngfwv1.DiffPolicyRequest{
		FromSource: openngfwv1.PolicySource_POLICY_SOURCE_VERSION,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestPolicyCommitRejectsMissingAuditComment(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "   "})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "commit comment is required") {
		t.Fatalf("error = %v, want missing commit comment", err)
	}
}

func TestPolicyCommitRequiresChangeApproval(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus: %v", err)
	}
	_, err = srv.Commit(context.Background(), &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true, ReviewedCandidateRevision: statusResp.GetCandidateRevision()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "change approval is required before commit") {
		t.Fatalf("error = %v, want change approval requirement", err)
	}
}

func TestPolicyCommitRequiresReviewedCandidateRevision(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	_, err = srv.Commit(context.Background(), &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true, ApprovalId: approveCurrentCandidate(t, srv)})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "reviewed_candidate_revision is required") {
		t.Fatalf("error = %v, want reviewed candidate revision requirement", err)
	}
}

func TestPolicyCommitRejectsStaleReviewedCandidateRevision(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate initial: %v", err)
	}
	reviewed, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus initial: %v", err)
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}, {Name: "dmz"}},
	}}); err != nil {
		t.Fatalf("SetCandidate changed: %v", err)
	}

	_, err = srv.Commit(context.Background(), &openngfwv1.CommitRequest{
		Comment:                   "commit stale review",
		AckRisk:                   true,
		ApprovalId:                approveCurrentCandidate(t, srv),
		ReviewedCandidateRevision: reviewed.GetCandidateRevision(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "candidate changed since commit review") {
		t.Fatalf("error = %v, want stale review message", err)
	}
}

func TestPolicyCommitRequiresAckRiskForHighRiskImpact(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Rules: []*openngfwv1.Rule{{
			Name:   "allow-any",
			Action: openngfwv1.Action_ACTION_ALLOW,
		}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "open forwarding for lab"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "high-risk policy impact requires ack_risk") {
		t.Fatalf("error = %v, want high-risk acknowledgement error", err)
	}
}

func TestPolicyCommitAcceptsAckRiskForHighRiskImpact(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Rules: []*openngfwv1.Rule{{
			Name:   "allow-any",
			Action: openngfwv1.Action_ACTION_ALLOW,
		}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "open forwarding for lab", AckRisk: true})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if resp.GetVersion() != 1 {
		t.Fatalf("version = %d, want 1", resp.GetVersion())
	}
}

func TestPolicyCommitDoesNotApplyEnginesWhenDurableIntentFails(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	engine := &recordingPolicyEngine{name: "nftables"}
	renderCalls := 0
	srv := NewPolicyServer(st, engines.NewSupervisor(engine), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		renderCalls++
		artifacts := map[string][]byte{"nftables": policyTestArtifact(p)}
		if renderCalls == 2 {
			if err := st.Close(); err != nil {
				t.Fatalf("close store before durable prepare: %v", err)
			}
		}
		return artifacts, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "record intent") {
		t.Fatalf("error = %v, want durable intent failure", err)
	}
	if len(engine.applied) != 0 {
		t.Fatalf("engine applied before durable intent was recorded: %v", engine.applied)
	}
}

func TestPolicyCommitRecordsIntentAuditAndAppliesEngines(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	engine := &recordingPolicyEngine{name: "nftables"}
	srv := NewPolicyServer(st, engines.NewSupervisor(engine), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": policyTestArtifact(p)}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	resp, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if resp.GetPreviousVersion() != 0 {
		t.Fatalf("previous version = %d, want 0", resp.GetPreviousVersion())
	}
	assertActivePolicyVersionInfo(t, resp.GetVersionInfo(), resp.GetVersion(), "commit", 0, policyTestArtifact(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}))
	if got := strings.Join(engine.applied, ","); got != "lan" {
		t.Fatalf("engine applied = %q, want lan", got)
	}
	running, ver, err := st.GetRunning()
	if err != nil || ver != resp.GetVersion() || running.GetZones()[0].GetName() != "lan" {
		t.Fatalf("running = v%d %v err=%v", ver, running, err)
	}
	if _, ok, err := st.GetCandidate(); err != nil || ok {
		t.Fatalf("candidate should be cleared after commit (ok=%v err=%v)", ok, err)
	}
	assertPolicyAuditAction(t, st, "commit-intent", resp.GetVersion(), "initial baseline")
	assertPolicyAuditAction(t, st, "commit", resp.GetVersion(), "initial baseline")
}

func TestPolicyCommitApplyFailureRecordsFailureAuditAndLeavesPreparedInactive(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	engine := &recordingPolicyEngine{name: "nftables"}
	srv := NewPolicyServer(st, engines.NewSupervisor(engine), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": policyTestArtifact(p)}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "known-good"}},
	}}); err != nil {
		t.Fatalf("SetCandidate baseline: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "known-good", AckRisk: true}); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}

	engine.failConfig = "newer"
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "newer"}},
	}}); err != nil {
		t.Fatalf("SetCandidate newer: %v", err)
	}
	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "newer", AckRisk: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	running, ver, err := st.GetRunning()
	if err != nil || ver != 1 || running.GetZones()[0].GetName() != "known-good" {
		t.Fatalf("running should remain previous version after apply failure: v%d %v err=%v", ver, running, err)
	}
	if prepared, err := st.GetVersion(2); err != nil || prepared.GetZones()[0].GetName() != "newer" {
		t.Fatalf("prepared version should remain for audit/reconciliation: %v err=%v", prepared, err)
	}
	failedInfo, err := st.GetVersionInfo(2)
	if err != nil {
		t.Fatal(err)
	}
	if failedInfo.State != "apply_failed" || failedInfo.LastKnownGood || !strings.Contains(failedInfo.StateDetail, "prepared version 2 left inactive") {
		t.Fatalf("failed prepared metadata wrong: %+v", failedInfo)
	}
	lkgInfo, err := st.GetVersionInfo(1)
	if err != nil {
		t.Fatal(err)
	}
	if !lkgInfo.LastKnownGood || lkgInfo.State != "active" {
		t.Fatalf("previous version should remain last-known-good: %+v", lkgInfo)
	}
	candidate, ok, err := st.GetCandidate()
	if err != nil || !ok || candidate.GetZones()[0].GetName() != "newer" {
		t.Fatalf("candidate should remain after apply failure: ok=%v candidate=%v err=%v", ok, candidate, err)
	}
	assertPolicyAuditAction(t, st, "commit-intent", 2, "newer")
	failures, err := st.ListAuditFiltered(store.AuditFilter{Action: "commit-failed", Version: 2, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || !strings.Contains(failures[0].Detail, "prepared version 2 left inactive") {
		t.Fatalf("failure audit wrong: %+v", failures)
	}
	successes, err := st.ListAuditFiltered(store.AuditFilter{Action: "commit", Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(successes) != 0 {
		t.Fatalf("commit success audit should not exist after apply failure: %+v", successes)
	}
}

func TestPolicyCommitRequiresAckRuntimeForRuntimeWarnings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	srv.RuntimeReadiness = func(context.Context, *openngfwv1.Policy, *openngfwv1.Policy) ([]string, error) {
		return []string{"Kernel forwarding tuning is degraded"}, nil
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}

	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "runtime readiness warnings require ack_runtime before commit") {
		t.Fatalf("error = %v, want runtime acknowledgement error", err)
	}

	resp, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial baseline", AckRisk: true, AckRuntime: true})
	if err != nil {
		t.Fatalf("Commit with ack_runtime: %v", err)
	}
	if resp.GetVersion() != 1 {
		t.Fatalf("version = %d, want 1", resp.GetVersion())
	}
}

func TestPolicyCommitRuntimeReadinessReceivesTargetAndRunningPolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	running := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: running}); err != nil {
		t.Fatalf("SetCandidate running: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit running: %v", err)
	}

	target := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
		Network: &openngfwv1.Network{EnableFlowOffload: true},
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: target}); err != nil {
		t.Fatalf("SetCandidate target: %v", err)
	}

	var sawTarget, sawRunning bool
	srv.RuntimeReadiness = func(_ context.Context, target, running *openngfwv1.Policy) ([]string, error) {
		sawTarget = target.GetNetwork().GetEnableFlowOffload()
		sawRunning = running.GetNetwork().GetEnableFlowOffload()
		return []string{"nftables flowtable fast path is degraded"}, nil
	}

	_, err = commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "enable flowtable", AckRisk: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !sawTarget {
		t.Fatalf("runtime readiness did not receive target flowtable policy")
	}
	if sawRunning {
		t.Fatalf("runtime readiness should receive previous running policy before flowtable was enabled")
	}

	resp, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "enable flowtable", AckRisk: true, AckRuntime: true})
	if err != nil {
		t.Fatalf("Commit with ack_runtime: %v", err)
	}
	if resp.GetVersion() != 2 {
		t.Fatalf("version = %d, want 2", resp.GetVersion())
	}
}

func TestPolicyRollbackRejectsMissingAuditComment(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{Version: 1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "rollback audit comment is required") {
		t.Fatalf("error = %v, want missing rollback audit comment", err)
	}
}

func TestPolicyRollbackRequiresAckRiskForHighRiskImpact(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	for _, p := range []*openngfwv1.Policy{
		{Rules: []*openngfwv1.Rule{{Name: "allow-any", Action: openngfwv1.Action_ACTION_ALLOW}}},
		{Rules: []*openngfwv1.Rule{{Name: "deny-all", Action: openngfwv1.Action_ACTION_DENY}}},
	} {
		if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
			t.Fatalf("SetCandidate: %v", err)
		}
		if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: p.GetRules()[0].GetName(), AckRisk: true}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	_, err = srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{Version: 1, Comment: "restore deny policy"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "high-risk rollback impact requires ack_risk") {
		t.Fatalf("error = %v, want high-risk rollback acknowledgement error", err)
	}
}

func TestPolicyRollbackRequiresAckRuntimeForRuntimeWarnings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	srv.RuntimeReadiness = func(context.Context, *openngfwv1.Policy, *openngfwv1.Policy) ([]string, error) {
		return []string{"Runtime status is degraded"}, nil
	}
	for _, p := range []*openngfwv1.Policy{
		{Zones: []*openngfwv1.Zone{{Name: "known-good"}}},
		{Zones: []*openngfwv1.Zone{{Name: "newer"}}},
	} {
		if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
			t.Fatalf("SetCandidate: %v", err)
		}
		if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: p.GetZones()[0].GetName(), AckRisk: true, AckRuntime: true}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	_, err = srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{Version: 1, Comment: "restore known-good", AckRisk: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "runtime readiness warnings require ack_runtime before rollback") {
		t.Fatalf("error = %v, want runtime acknowledgement error", err)
	}

	resp, err := srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{Version: 1, Comment: "restore known-good", AckRisk: true, AckRuntime: true})
	if err != nil {
		t.Fatalf("Rollback with ack_runtime: %v", err)
	}
	if resp.GetVersion() != 3 {
		t.Fatalf("rollback created version %d, want 3", resp.GetVersion())
	}
}

func TestPolicyRollbackUsesOperatorComment(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	for _, p := range []*openngfwv1.Policy{
		{Zones: []*openngfwv1.Zone{{Name: "known-good"}}},
		{Zones: []*openngfwv1.Zone{{Name: "newer"}}},
	} {
		if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
			t.Fatalf("SetCandidate: %v", err)
		}
		if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: p.GetZones()[0].GetName(), AckRisk: true}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	const comment = "restore known-good policy after failed change"
	resp, err := srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{Version: 1, Comment: comment, AckRisk: true})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if resp.GetVersion() != 3 {
		t.Fatalf("rollback created version %d, want 3", resp.GetVersion())
	}
	versions, err := srv.ListVersions(context.Background(), &openngfwv1.ListVersionsRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if got := versions.GetVersions()[0].GetComment(); got != comment {
		t.Fatalf("version comment = %q, want %q", got, comment)
	}
	audit, err := srv.ListAuditEntries(context.Background(), &openngfwv1.ListAuditEntriesRequest{Action: "rollback", Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if got := audit.GetEntries()[0].GetDetail(); got != comment {
		t.Fatalf("audit detail = %q, want %q", got, comment)
	}
}

func TestPolicyRollbackRecordsIntentAuditAndAppliesEngines(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	engine := &recordingPolicyEngine{name: "nftables"}
	srv := NewPolicyServer(st, engines.NewSupervisor(engine), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": policyTestArtifact(p)}, nil
	})
	for _, p := range []*openngfwv1.Policy{
		{Zones: []*openngfwv1.Zone{{Name: "known-good"}}},
		{Zones: []*openngfwv1.Zone{{Name: "newer"}}},
	} {
		if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: p}); err != nil {
			t.Fatalf("SetCandidate: %v", err)
		}
		if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: p.GetZones()[0].GetName(), AckRisk: true}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	resp, err := srv.Rollback(context.Background(), &openngfwv1.RollbackRequest{
		Version: 1, Comment: "restore known-good", AckRisk: true,
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if resp.GetVersion() != 3 {
		t.Fatalf("rollback version = %d, want 3", resp.GetVersion())
	}
	if resp.GetPreviousVersion() != 2 {
		t.Fatalf("rollback previous version = %d, want 2", resp.GetPreviousVersion())
	}
	assertActivePolicyVersionInfo(t, resp.GetVersionInfo(), resp.GetVersion(), "rollback", 1, policyTestArtifact(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "known-good"}},
	}))
	if got := strings.Join(engine.applied, ","); got != "known-good,newer,known-good" {
		t.Fatalf("engine applied = %q, want known-good,newer,known-good", got)
	}
	running, ver, err := st.GetRunning()
	if err != nil || ver != resp.GetVersion() || running.GetZones()[0].GetName() != "known-good" {
		t.Fatalf("running = v%d %v err=%v", ver, running, err)
	}
	assertPolicyAuditAction(t, st, "rollback-intent", resp.GetVersion(), "restore known-good")
	assertPolicyAuditAction(t, st, "rollback", resp.GetVersion(), "restore known-good")
}

func TestPolicyAuditAndVersionsIncludeIdentityMetadata(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	candidate := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}
	if _, err := srv.SetCandidate(context.Background(), &openngfwv1.SetCandidateRequest{Policy: candidate}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	if _, err := commitApproved(t, srv, &openngfwv1.CommitRequest{Comment: "initial", AckRisk: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	audit, err := srv.ListAuditEntries(context.Background(), &openngfwv1.ListAuditEntriesRequest{})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(audit.GetEntries()) < 2 {
		t.Fatalf("expected audit entries, got %#v", audit.GetEntries())
	}
	for _, entry := range audit.GetEntries() {
		if entry.GetActor() != "local" || entry.GetActorRole() != "admin" || entry.GetAuthSource() != "disabled-local" {
			t.Fatalf("audit identity metadata wrong: %#v", entry)
		}
	}

	versions, err := srv.ListVersions(context.Background(), &openngfwv1.ListVersionsRequest{})
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions.GetVersions()) != 1 {
		t.Fatalf("expected one version, got %#v", versions.GetVersions())
	}
	version := versions.GetVersions()[0]
	if version.GetActor() != "local" || version.GetActorRole() != "admin" || version.GetAuthSource() != "disabled-local" {
		t.Fatalf("version identity metadata wrong: %#v", version)
	}
}

func TestPolicyListAuditEntriesFilters(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for _, e := range []store.AuditEntry{
		{Time: base.Add(-2 * time.Hour), Actor: "alice", ActorRole: "admin", AuthSource: "local", Action: "set-candidate", Detail: "draft"},
		{Time: base.Add(-1 * time.Hour), Actor: "bob", ActorRole: "operator", AuthSource: "oidc", Action: "commit", Detail: "initial", Version: 4},
	} {
		if err := st.AppendAudit(e); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})

	resp, err := srv.ListAuditEntries(context.Background(), &openngfwv1.ListAuditEntriesRequest{
		Actor:   "bo",
		Action:  "commit",
		Version: 4,
		Since:   timestamppb.New(base.Add(-90 * time.Minute)),
		Query:   "oidc",
	})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(resp.GetEntries()) != 1 || resp.GetEntries()[0].GetActor() != "bob" {
		t.Fatalf("filtered audit entries = %#v", resp.GetEntries())
	}
	if resp.GetEntries()[0].GetEntryHash() == "" {
		t.Fatalf("filtered audit entry missing entry hash: %#v", resp.GetEntries()[0])
	}
}

func TestPolicyVerifyAuditIntegrity(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	for _, action := range []string{"set-candidate", "commit"} {
		if err := st.AppendAudit(store.AuditEntry{Actor: "tester", Action: action, Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})

	resp, err := srv.VerifyAuditIntegrity(context.Background(), &openngfwv1.VerifyAuditIntegrityRequest{})
	if err != nil {
		t.Fatalf("VerifyAuditIntegrity: %v", err)
	}
	if !resp.GetOk() || resp.GetEntryCount() != 2 || resp.GetLatestEntryHash() == "" || resp.GetCheckedAt() == nil {
		t.Fatalf("VerifyAuditIntegrity response = %#v", resp)
	}
}

func TestPolicyListAuditEntriesRejectsInvalidTimeRange(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	_, err = srv.ListAuditEntries(context.Background(), &openngfwv1.ListAuditEntriesRequest{
		Since: timestamppb.New(time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC)),
		Until: timestamppb.New(time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

type recordingPolicyEngine struct {
	name       string
	failConfig string
	applied    []string
}

func (e *recordingPolicyEngine) Name() string { return e.name }

func (e *recordingPolicyEngine) Validate(context.Context, []byte) error { return nil }

func (e *recordingPolicyEngine) Apply(_ context.Context, cfg []byte) error {
	value := string(cfg)
	if e.failConfig != "" && value == e.failConfig {
		return errors.New("configured apply failure")
	}
	e.applied = append(e.applied, value)
	return nil
}

func policyTestArtifact(p *openngfwv1.Policy) []byte {
	if len(p.GetZones()) > 0 {
		return []byte(p.GetZones()[0].GetName())
	}
	if len(p.GetRules()) > 0 {
		return []byte(p.GetRules()[0].GetName())
	}
	return []byte("empty")
}

func commitApproved(t *testing.T, srv *PolicyServer, req *openngfwv1.CommitRequest) (*openngfwv1.CommitResponse, error) {
	t.Helper()
	if strings.TrimSpace(req.GetReviewedCandidateRevision()) == "" {
		statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
		if err != nil {
			t.Fatalf("GetCandidateStatus before commit: %v", err)
		}
		req.ReviewedCandidateRevision = statusResp.GetCandidateRevision()
	}
	if strings.TrimSpace(req.GetApprovalId()) == "" {
		req.ApprovalId = approveCurrentCandidate(t, srv)
	}
	return srv.Commit(context.Background(), req)
}

func approveCurrentCandidate(t *testing.T, srv *PolicyServer) string {
	t.Helper()
	statusResp, err := srv.GetCandidateStatus(context.Background(), &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		t.Fatalf("GetCandidateStatus before approval: %v", err)
	}
	resp, err := srv.CreateChangeApproval(context.Background(), &openngfwv1.CreateChangeApprovalRequest{
		CandidateRevision: statusResp.GetCandidateRevision(),
		Comment:           "test approval",
		AckRisk:           true,
		AckRuntime:        true,
	})
	if err != nil {
		t.Fatalf("CreateChangeApproval: %v", err)
	}
	return resp.GetApproval().GetId()
}

func assertPolicyAuditAction(t *testing.T, st *store.Store, action string, version uint64, detail string) {
	t.Helper()
	entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Version: version, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d %s audit entries for version %d, want 1", len(entries), action, version)
	}
	if entries[0].Detail != detail {
		t.Fatalf("%s audit detail = %q, want %q", action, entries[0].Detail, detail)
	}
}

func assertActivePolicyVersionInfo(t *testing.T, info *openngfwv1.VersionInfo, version uint64, action string, sourceVersion uint64, artifact []byte) {
	t.Helper()
	if info == nil {
		t.Fatal("version info is nil")
	}
	if info.GetId() != version || info.GetAction() != action || info.GetSourceVersion() != sourceVersion {
		t.Fatalf("version info identity wrong: %+v", info)
	}
	if info.GetState() != "active" || !info.GetLastKnownGood() || info.GetActivatedAt() == nil {
		t.Fatalf("version recovery state wrong: %+v", info)
	}
	if info.GetArtifactSetSha256() == "" || len(info.GetArtifacts()) != 1 {
		t.Fatalf("artifact metadata missing: %+v", info)
	}
	sum := sha256.Sum256(artifact)
	if got, want := info.GetArtifacts()[0].GetSha256(), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("artifact sha256 = %q, want %q", got, want)
	}
}

func hasAPIImpact(items []*openngfwv1.ChangeImpactItem, risk openngfwv1.ChangeRisk, title string) bool {
	for _, item := range items {
		if item.GetRisk() == risk && item.GetTitle() == title {
			return true
		}
	}
	return false
}

func hasDiffLine(lines []*openngfwv1.PolicyDiffLine, lineType openngfwv1.PolicyDiffLineType, text string) bool {
	for _, line := range lines {
		if line.GetType() == lineType && line.GetText() == text {
			return true
		}
	}
	return false
}

func hasValidationFinding(findings []*openngfwv1.ValidationFinding, severity openngfwv1.ValidationSeverity, stage openngfwv1.ValidationStage, code, text string) bool {
	for _, finding := range findings {
		if finding.GetSeverity() == severity &&
			finding.GetStage() == stage &&
			finding.GetCode() == code &&
			(strings.Contains(finding.GetMessage(), text) || strings.Contains(finding.GetDetail(), text)) {
			return true
		}
	}
	return false
}

//nolint:unparam // The full delta tuple keeps assertions readable even when one column is zero today.
func assertCandidateChange(t *testing.T, changes []*openngfwv1.CandidateChangeSummary, section string, added, modified, removed uint32) {
	t.Helper()
	for _, change := range changes {
		if change.GetSection() != section {
			continue
		}
		if change.GetAdded() != added || change.GetModified() != modified || change.GetRemoved() != removed {
			t.Fatalf("%s change = +%d ~%d -%d, want +%d ~%d -%d", section,
				change.GetAdded(), change.GetModified(), change.GetRemoved(), added, modified, removed)
		}
		return
	}
	t.Fatalf("missing %s change in %#v", section, changes)
}

func apiReferenceKeys(refs []*openngfwv1.PolicyObjectReference) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.GetObjectName()+":"+ref.GetArea()+":"+ref.GetItem()+":"+ref.GetField())
	}
	return out
}

func findAPIReference(refs []*openngfwv1.PolicyObjectReference, area, field string) *openngfwv1.PolicyObjectReference {
	for _, ref := range refs {
		if ref.GetArea() == area && ref.GetField() == field {
			return ref
		}
	}
	return nil
}

func referencePolicyFixture() *openngfwv1.Policy {
	p := validReferencePolicy()
	p.Applications = []*openngfwv1.Application{{
		Name:          "corp-admin",
		Category:      "business-app",
		EngineSignals: []string{"corp-admin"},
		Ports: []*openngfwv1.ApplicationPort{{
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 8443}},
		}},
	}}
	p.Rules = append(p.Rules, &openngfwv1.Rule{
		Id:                   "rule-drop-admin",
		Name:                 "drop-admin",
		FromZones:            []string{"wan"},
		ToZones:              []string{"lan"},
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"web-server"},
		Applications:         []string{"corp-admin"},
		SecurityProfiles:     []string{"inspect-standard"},
		QosProfile:           "latency-critical",
		Action:               openngfwv1.Action_ACTION_DENY,
	})
	p.HostInput = &openngfwv1.HostInput{
		DefaultAction: openngfwv1.Action_ACTION_ALLOW,
		Rules: []*openngfwv1.HostInputRule{{
			Id:              "host-input-mgmt-ssh-custom",
			Name:            "mgmt-ssh",
			FromZones:       []string{"lan"},
			SourceAddresses: []string{"admin-host"},
			Services:        []string{"ssh"},
			Action:          openngfwv1.Action_ACTION_ALLOW,
		}},
	}
	p.Nat = &openngfwv1.Nat{
		Source: []*openngfwv1.SourceNat{{
			Id:                "snat-lan-egress-custom",
			Name:              "lan-egress",
			ToZone:            "wan",
			SourceAddress:     "client-net",
			TranslatedAddress: "wan-ip",
		}},
		Destination: []*openngfwv1.DestinationNat{{
			Id:                 "dnat-published-web-custom",
			Name:               "published-web",
			FromZone:           "wan",
			DestinationAddress: "public-web",
			TranslatedAddress:  "web-server",
			Service:            "https",
		}},
	}
	return p
}

func validNatPolicyFixture() *openngfwv1.Policy {
	return validReferencePolicy()
}

func containsPolicyString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func validReferencePolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "lan"},
			{Name: "wan", ZoneProtectionProfile: "edge-dos-watch"},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "client-net", Cidr: "10.0.1.0/24"},
			{Name: "web-server", Cidr: "10.0.2.10/32"},
			{Name: "admin-host", Cidr: "10.0.1.50/32"},
			{Name: "wan-ip", Cidr: "198.51.100.10/32"},
			{Name: "public-web", Cidr: "198.51.100.20/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "https", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 443}}},
			{Name: "ssh", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 22}}},
			{Name: "admin-ui", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 8443}}},
		},
		SecurityProfiles: []*openngfwv1.SecurityProfile{{
			Name:          "inspect-standard",
			Description:   "Metadata, DNS, URL, and file inspection intent for policy review.",
			TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
			UrlCategories: []string{"malware", "phishing"},
			DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
			FileSecurity:  openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_LOG_ONLY,
		}},
		QosProfiles: []*openngfwv1.QosProfile{{
			Name:                    "latency-critical",
			Description:             "Plan-only shaping intent for latency-sensitive traffic.",
			MaxBandwidthKbps:        100000,
			GuaranteedBandwidthKbps: 25000,
			Priority:                openngfwv1.QosPriority_QOS_PRIORITY_HIGH,
			DscpMark:                46,
			BurstKbytes:             256,
		}},
		ZoneProtectionProfiles: []*openngfwv1.ZoneProtectionProfile{{
			Name:                     "edge-dos-watch",
			Description:              "Plan-only edge zone flood monitoring intent.",
			Enabled:                  true,
			SynFloodPps:              10000,
			UdpFloodPps:              20000,
			IcmpFloodPps:             5000,
			MaxConcurrentConnections: 100000,
			Action:                   openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_ALERT,
			AuditLog:                 true,
		}},
		Ids: &openngfwv1.Ids{
			Enabled:         true,
			Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
			FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
		},
		Rules: []*openngfwv1.Rule{{
			Id:                   "rule-allow-web",
			Name:                 "allow-web",
			FromZones:            []string{"lan"},
			ToZones:              []string{"wan"},
			SourceAddresses:      []string{"client-net"},
			DestinationAddresses: []string{"web-server"},
			Services:             []string{"https"},
			SecurityProfiles:     []string{"inspect-standard"},
			QosProfile:           "latency-critical",
			Action:               openngfwv1.Action_ACTION_ALLOW,
		}},
	}
}

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPolicyDiffLinesShowsCandidateChanges(t *testing.T) {
	from := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
		Rules: []*openngfwv1.Rule{{Name: "allow-old", Action: openngfwv1.Action_ACTION_ALLOW}},
	}
	to := clonePolicy(from)
	to.Rules[0].Name = "allow-new"

	lines, changed, err := policyDiffLines("running policy v1", "candidate", from, to)
	if err != nil {
		t.Fatalf("policyDiffLines returned error: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"--- running policy v1",
		"+++ candidate",
		"-   name: allow-old",
		"+   name: allow-new",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in diff:\n%s", want, joined)
		}
	}
}

func TestPolicyDiffLinesDetectsNoChanges(t *testing.T) {
	pol := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "lan"}}}
	lines, changed, err := policyDiffLines("running", "candidate", pol, clonePolicy(pol))
	if err != nil {
		t.Fatalf("policyDiffLines returned error: %v", err)
	}
	if changed || len(lines) != 0 {
		t.Fatalf("changed=%v lines=%#v, want no change", changed, lines)
	}
}

func TestPolicyDiffBaseSelectsRunningAndVersion(t *testing.T) {
	client := &fakePolicyClient{
		runningVersion: 9,
		running:        &openngfwv1.Policy{Network: &openngfwv1.Network{Mtu: 1500}},
		versions: map[uint64]*openngfwv1.Policy{
			3: {Network: &openngfwv1.Network{Mtu: 9000}},
		},
	}

	running, label, err := policyDiffBase(context.Background(), client, "running", 0)
	if err != nil {
		t.Fatalf("running policyDiffBase returned error: %v", err)
	}
	if label != "running policy v9" || running.GetNetwork().GetMtu() != 1500 {
		t.Fatalf("running base = %s %#v", label, running)
	}
	versioned, label, err := policyDiffBase(context.Background(), client, "version", 3)
	if err != nil {
		t.Fatalf("version policyDiffBase returned error: %v", err)
	}
	if label != "version 3" || versioned.GetNetwork().GetMtu() != 9000 {
		t.Fatalf("version base = %s %#v", label, versioned)
	}
}

func TestPolicyDiffBaseStartsFromEmptyRunningPolicy(t *testing.T) {
	client := &fakePolicyClient{runningErr: status.Error(codes.NotFound, "no running policy")}
	pol, label, err := policyDiffBase(context.Background(), client, "running", 0)
	if err != nil {
		t.Fatalf("policyDiffBase returned error: %v", err)
	}
	if label != "running policy v0" || pol == nil {
		t.Fatalf("base = %s %#v, want empty running v0", label, pol)
	}
}

func TestPolicyDiffBaseRejectsBadSource(t *testing.T) {
	if _, _, err := policyDiffBase(context.Background(), &fakePolicyClient{}, "candidate", 0); err == nil || !strings.Contains(err.Error(), "--from") {
		t.Fatalf("expected --from error, got %v", err)
	}
	if _, _, err := policyDiffBase(context.Background(), &fakePolicyClient{}, "version", 0); err == nil || !strings.Contains(err.Error(), "--version") {
		t.Fatalf("expected --version error, got %v", err)
	}
}

func TestApprovalCreateRequestUsesCurrentCandidateRevision(t *testing.T) {
	client := &fakePolicyClient{
		statusResp: &openngfwv1.GetCandidateStatusResponse{
			HasCandidate:      true,
			CandidateRevision: "sha256:current",
		},
	}

	req, err := approvalCreateRequest(context.Background(), client, approvalCreateOptions{
		comment:    " reviewed planned maintenance ",
		ackRisk:    true,
		ackRuntime: true,
	})
	if err != nil {
		t.Fatalf("approvalCreateRequest returned error: %v", err)
	}
	if client.statusCalls != 1 {
		t.Fatalf("statusCalls = %d, want 1", client.statusCalls)
	}
	if req.GetCandidateRevision() != "sha256:current" ||
		req.GetComment() != "reviewed planned maintenance" ||
		!req.GetAckRisk() ||
		!req.GetAckRuntime() {
		t.Fatalf("approval request = %+v", req)
	}
}

func TestApprovalCreateRequestUsesExplicitRevision(t *testing.T) {
	client := &fakePolicyClient{}
	req, err := approvalCreateRequest(context.Background(), client, approvalCreateOptions{
		candidateRevision: " sha256:reviewed ",
		comment:           "approve reviewed revision",
	})
	if err != nil {
		t.Fatalf("approvalCreateRequest returned error: %v", err)
	}
	if client.statusCalls != 0 {
		t.Fatalf("statusCalls = %d, want 0", client.statusCalls)
	}
	if req.GetCandidateRevision() != "sha256:reviewed" {
		t.Fatalf("candidate revision = %q", req.GetCandidateRevision())
	}
}

func TestApprovalCreateRequestRequiresCandidateAndComment(t *testing.T) {
	if _, err := approvalCreateRequest(context.Background(), &fakePolicyClient{}, approvalCreateOptions{comment: "   "}); err == nil || !strings.Contains(err.Error(), "approval comment") {
		t.Fatalf("expected comment error, got %v", err)
	}
	client := &fakePolicyClient{statusResp: &openngfwv1.GetCandidateStatusResponse{}}
	if _, err := approvalCreateRequest(context.Background(), client, approvalCreateOptions{comment: "approve"}); err == nil || !strings.Contains(err.Error(), "no candidate") {
		t.Fatalf("expected no candidate error, got %v", err)
	}
}

func TestRunPolicyApprovalCreatePrintsApprovalID(t *testing.T) {
	client := &fakePolicyClient{
		statusResp: &openngfwv1.GetCandidateStatusResponse{HasCandidate: true, CandidateRevision: "sha256:current"},
		createApprovalResp: &openngfwv1.CreateChangeApprovalResponse{Approval: &openngfwv1.ChangeApproval{
			Id:                "approval-3",
			CandidateRevision: "sha256:current",
		}},
	}
	cmd, stdout := policyCommandForTest()

	if err := runPolicyApprovalCreate(context.Background(), cmd, client, approvalCreateOptions{comment: "approve"}); err != nil {
		t.Fatalf("runPolicyApprovalCreate returned error: %v", err)
	}
	if client.createApprovalReq.GetCandidateRevision() != "sha256:current" {
		t.Fatalf("create approval request = %+v", client.createApprovalReq)
	}
	out := stdout.String()
	for _, want := range []string{"change approval approval-3 created", "ngfwctl commit --approval-id approval-3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("approval create output missing %q: %s", want, out)
		}
	}
}

func TestSourceNatFromOptionsRequiresRevisionAndTranslation(t *testing.T) {
	_, err := sourceNatFromOptions(sourceNatOptions{
		name:   "lan-egress",
		toZone: "wan",
		audit:  natAuditOptions{expectedRevision: "sha256:1", comment: "stage nat"},
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected translation error, got %v", err)
	}
	rule, err := sourceNatFromOptions(sourceNatOptions{
		name:              " lan-egress ",
		toZone:            " wan ",
		sourceAddress:     " client-net ",
		translatedAddress: " wan-ip ",
		audit:             natAuditOptions{expectedRevision: "sha256:1", reason: "egress static NAT"},
	})
	if err != nil {
		t.Fatalf("sourceNatFromOptions returned error: %v", err)
	}
	if rule.GetName() != "lan-egress" || rule.GetToZone() != "wan" || rule.GetSourceAddress() != "client-net" || rule.GetTranslatedAddress() != "wan-ip" {
		t.Fatalf("source NAT rule = %#v", rule)
	}
	if _, err := sourceNatFromOptions(sourceNatOptions{name: "lan-egress", toZone: "wan", masquerade: true, audit: natAuditOptions{comment: "missing revision"}}); err == nil || !strings.Contains(err.Error(), "--expected-candidate-revision") {
		t.Fatalf("expected revision error, got %v", err)
	}
}

func TestDestinationNatFromOptionsBuildsRule(t *testing.T) {
	rule, err := destinationNatFromOptions(destinationNatOptions{
		name:               " web-dnat ",
		fromZone:           " wan ",
		service:            " https ",
		destinationAddress: " public-web ",
		translatedAddress:  " web-server ",
		translatedPort:     8443,
		audit:              natAuditOptions{expectedRevision: "sha256:2", comment: "publish web"},
	})
	if err != nil {
		t.Fatalf("destinationNatFromOptions returned error: %v", err)
	}
	if rule.GetName() != "web-dnat" || rule.GetFromZone() != "wan" || rule.GetService() != "https" ||
		rule.GetDestinationAddress() != "public-web" || rule.GetTranslatedAddress() != "web-server" || rule.GetTranslatedPort() != 8443 {
		t.Fatalf("destination NAT rule = %#v", rule)
	}
}

func TestNatUpsertRequestsCarryDurableID(t *testing.T) {
	sourceReq, err := sourceNatUpsertRequest(sourceNatOptions{
		id:                " snat-lan-egress ",
		name:              " lan-egress-renamed ",
		toZone:            " wan ",
		sourceAddress:     " client-net ",
		translatedAddress: " wan-ip ",
		audit:             natAuditOptions{expectedRevision: "sha256:1", comment: "rename source NAT"},
	})
	if err != nil {
		t.Fatalf("sourceNatUpsertRequest returned error: %v", err)
	}
	if sourceReq.GetId() != "snat-lan-egress" ||
		sourceReq.GetRule().GetId() != "snat-lan-egress" ||
		sourceReq.GetRule().GetName() != "lan-egress-renamed" ||
		sourceReq.GetExpectedCandidateRevision() != "sha256:1" {
		t.Fatalf("source NAT upsert request = %#v", sourceReq)
	}

	destinationReq, err := destinationNatUpsertRequest(destinationNatOptions{
		id:                 " dnat-web ",
		name:               " web-dnat-renamed ",
		fromZone:           " wan ",
		service:            " https ",
		destinationAddress: " public-web ",
		translatedAddress:  " web-server ",
		translatedPort:     8443,
		audit:              natAuditOptions{expectedRevision: "sha256:2", reason: "rename destination NAT"},
	})
	if err != nil {
		t.Fatalf("destinationNatUpsertRequest returned error: %v", err)
	}
	if destinationReq.GetId() != "dnat-web" ||
		destinationReq.GetRule().GetId() != "dnat-web" ||
		destinationReq.GetRule().GetName() != "web-dnat-renamed" ||
		destinationReq.GetExpectedCandidateRevision() != "sha256:2" {
		t.Fatalf("destination NAT upsert request = %#v", destinationReq)
	}
}

func TestNatDeleteRequestSelectors(t *testing.T) {
	sourceReq, err := sourceNatDeleteRequest(natDeleteOptions{
		id:    " snat-lan-egress ",
		audit: natAuditOptions{expectedRevision: "sha256:3", comment: "delete source NAT"},
	})
	if err != nil {
		t.Fatalf("sourceNatDeleteRequest by ID returned error: %v", err)
	}
	if sourceReq.GetId() != "snat-lan-egress" || sourceReq.GetName() != "" {
		t.Fatalf("source NAT delete by-ID request = %#v", sourceReq)
	}

	destinationReq, err := destinationNatDeleteRequest(natDeleteOptions{
		name:  " web-dnat ",
		audit: natAuditOptions{expectedRevision: "sha256:4", reason: "delete destination NAT"},
	})
	if err != nil {
		t.Fatalf("destinationNatDeleteRequest by name returned error: %v", err)
	}
	if destinationReq.GetName() != "web-dnat" || destinationReq.GetId() != "" {
		t.Fatalf("destination NAT delete by-name request = %#v", destinationReq)
	}

	for _, tt := range []struct {
		name string
		opts natDeleteOptions
		want string
	}{
		{name: "missing selector", opts: natDeleteOptions{audit: natAuditOptions{expectedRevision: "sha256:5", comment: "delete"}}, want: "--name or --id"},
		{name: "both selectors", opts: natDeleteOptions{name: "web-dnat", id: "dnat-web", audit: natAuditOptions{expectedRevision: "sha256:5", comment: "delete"}}, want: "exactly one"},
		{name: "missing audit", opts: natDeleteOptions{id: "dnat-web"}, want: "--expected-candidate-revision"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := destinationNatDeleteRequest(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("destinationNatDeleteRequest error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNatMutationCLIErrorAddsByIDRecovery(t *testing.T) {
	err := natMutationCLIError("delete", "source", " snat-lan ", status.Error(codes.NotFound, "source NAT id not found"))
	if err == nil {
		t.Fatal("natMutationCLIError returned nil")
	}
	for _, want := range []string{"delete source NAT by durable ID \"snat-lan\"", "reload candidate NAT", "select a current ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	nameErr := natMutationCLIError("delete", "source", "", status.Error(codes.NotFound, "source NAT not found"))
	if !strings.Contains(nameErr.Error(), "delete source NAT:") || strings.Contains(nameErr.Error(), "durable ID") {
		t.Fatalf("name workflow error = %v", nameErr)
	}
}

func TestNatListRequestAndPrint(t *testing.T) {
	req, err := natListRequest(natListOptions{source: "version", version: 7})
	if err != nil {
		t.Fatalf("natListRequest returned error: %v", err)
	}
	if req.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_VERSION || req.GetVersion() != 7 {
		t.Fatalf("request = %#v", req)
	}
	if _, err := natListRequest(natListOptions{source: "candidate", version: 7}); err == nil || !strings.Contains(err.Error(), "--version") {
		t.Fatalf("expected version misuse error, got %v", err)
	}

	cmd, stdout := policyCommandForTest()
	err = printNatRules(cmd, &openngfwv1.ListNatRulesResponse{
		Source: "candidate",
		SourceNat: []*openngfwv1.SourceNat{{
			Name:       "lan-masq",
			ToZone:     "wan",
			Masquerade: true,
		}},
		DestinationNat: []*openngfwv1.DestinationNat{{
			Name:               "web-dnat",
			FromZone:           "wan",
			Service:            "https",
			DestinationAddress: "public-web",
			TranslatedAddress:  "web-server",
			TranslatedPort:     8443,
		}},
	}, false)
	if err != nil {
		t.Fatalf("printNatRules returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"NAT rules from candidate", "Source NAT", "ID", "lan-masq", "Destination NAT", "web-dnat", "8443"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestNatIDOutputHelpersPreferFutureDurableID(t *testing.T) {
	fileDesc, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/nat_identity.proto"),
		Package: proto.String("test"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("NatRule"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   proto.String("id"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
	}, nil)
	if err != nil {
		t.Fatalf("build dynamic descriptor: %v", err)
	}
	msgDesc := fileDesc.Messages().ByName("NatRule")
	msg := dynamicpb.NewMessage(msgDesc)
	msg.Set(msgDesc.Fields().ByName("id"), protoreflect.ValueOfString(" snat-lan-masq "))

	if got := protoStringField(msg, "id"); got != "snat-lan-masq" {
		t.Fatalf("protoStringField dynamic id = %q", got)
	}
	if got := protoStringField(&openngfwv1.SourceNat{Name: "legacy-name-only"}, "id"); got != "" {
		t.Fatalf("protoStringField legacy NAT id = %q, want empty fallback", got)
	}
	if got := natIDLabel(" snat-lan-masq "); got != " id=snat-lan-masq" {
		t.Fatalf("natIDLabel = %q", got)
	}
	if got := natIDLabel(""); got != "" {
		t.Fatalf("empty natIDLabel = %q", got)
	}
}

func TestRunPolicyApprovalListFiltersAndPrintsApprovals(t *testing.T) {
	created := time.Date(2026, 6, 22, 15, 4, 5, 0, time.UTC)
	client := &fakePolicyClient{
		listApprovalsResp: &openngfwv1.ListChangeApprovalsResponse{Approvals: []*openngfwv1.ChangeApproval{{
			Id:                "approval-9",
			CandidateRevision: "sha256:current",
			Actor:             "alice",
			ActorRole:         "admin",
			Comment:           "maintenance window",
			AckRisk:           true,
			CreatedAt:         timestamppb.New(created),
		}}},
	}
	cmd, stdout := policyCommandForTest()

	err := runPolicyApprovalList(context.Background(), cmd, client, approvalListOptions{
		candidateRevision: " sha256:current ",
		includeConsumed:   true,
		limit:             25,
	})
	if err != nil {
		t.Fatalf("runPolicyApprovalList returned error: %v", err)
	}
	if client.listApprovalsReq.GetCandidateRevision() != "sha256:current" ||
		!client.listApprovalsReq.GetIncludeConsumed() ||
		client.listApprovalsReq.GetLimit() != 25 {
		t.Fatalf("list approvals request = %+v", client.listApprovalsReq)
	}
	out := stdout.String()
	for _, want := range []string{"approval-9", "alice/admin", "active", "maintenance window", "candidate: sha256:current"} {
		if !strings.Contains(out, want) {
			t.Fatalf("approval list output missing %q: %s", want, out)
		}
	}
}

func TestApplyBaselinePolicyStagesTwoZonePolicy(t *testing.T) {
	opts := baselineOptions{
		insideZone:        "LAN",
		outsideZone:       "WAN",
		insideInterfaces:  []string{"ens5"},
		outsideInterfaces: []string{"ens4"},
		insideCIDR:        "10.0.2.0/24",
		webuiPort:         8443,
		allowOutbound:     true,
		masquerade:        true,
		hardenHostInput:   true,
		flowOffload:       true,
		clampMSS:          true,
		mtu:               9000,
	}
	pol := &openngfwv1.Policy{}

	summary, err := applyBaselinePolicy(pol, opts)
	if err != nil {
		t.Fatalf("applyBaselinePolicy returned error: %v", err)
	}
	if !reflect.DeepEqual(summary.zones, []string{"lan", "wan"}) {
		t.Fatalf("zones summary = %#v", summary.zones)
	}
	if summary.profile != baselineProfileThroughput || !reflect.DeepEqual(summary.ids, []string{"IDS/IPS disabled"}) {
		t.Fatalf("baseline summary = %#v", summary)
	}
	if len(pol.GetZones()) != 2 ||
		pol.GetZones()[0].GetName() != "lan" || pol.GetZones()[0].GetInterfaces()[0] != "ens5" ||
		pol.GetZones()[1].GetName() != "wan" || pol.GetZones()[1].GetInterfaces()[0] != "ens4" {
		t.Fatalf("zones = %#v", pol.GetZones())
	}
	if len(pol.GetAddresses()) != 1 || pol.GetAddresses()[0].GetName() != "lan-net" || pol.GetAddresses()[0].GetCidr() != "10.0.2.0/24" {
		t.Fatalf("addresses = %#v", pol.GetAddresses())
	}
	if len(pol.GetServices()) != 2 ||
		pol.GetServices()[0].GetName() != "ssh" || pol.GetServices()[0].GetPorts()[0].GetStart() != 22 ||
		pol.GetServices()[1].GetName() != "webui" || pol.GetServices()[1].GetPorts()[0].GetStart() != 8443 {
		t.Fatalf("services = %#v", pol.GetServices())
	}
	if len(pol.GetRules()) != 1 || pol.GetRules()[0].GetName() != "allow-lan-to-wan" ||
		pol.GetRules()[0].GetAction() != openngfwv1.Action_ACTION_ALLOW ||
		!pol.GetRules()[0].GetLog() {
		t.Fatalf("rules = %#v", pol.GetRules())
	}
	if len(pol.GetNat().GetSource()) != 1 || pol.GetNat().GetSource()[0].GetName() != "lan-masq" ||
		!pol.GetNat().GetSource()[0].GetMasquerade() {
		t.Fatalf("source nat = %#v", pol.GetNat().GetSource())
	}
	if pol.GetHostInput().GetDefaultAction() != openngfwv1.Action_ACTION_DENY ||
		len(pol.GetHostInput().GetRules()) != 1 ||
		pol.GetHostInput().GetRules()[0].GetName() != "allow-lan-management" {
		t.Fatalf("host input = %#v", pol.GetHostInput())
	}
	if !pol.GetNetwork().GetEnableFlowOffload() || !pol.GetNetwork().GetClampMssToPmtu() ||
		pol.GetNetwork().GetManageNicOffloads() || pol.GetNetwork().GetMtu() != 9000 {
		t.Fatalf("network = %#v", pol.GetNetwork())
	}
	if pol.GetIds().GetEnabled() {
		t.Fatalf("IDS should be disabled for throughput profile: %#v", pol.GetIds())
	}
}

func TestApplyBaselinePolicyStagesIDSDetectProfile(t *testing.T) {
	opts := baselineOptions{
		profile:           baselineProfileIDSDetect,
		insideZone:        "lan",
		outsideZone:       "wan",
		insideInterfaces:  []string{"lan0"},
		outsideInterfaces: []string{"wan0"},
		insideCIDR:        "10.10.0.0/16",
		webuiPort:         8443,
		allowOutbound:     true,
		masquerade:        true,
		hardenHostInput:   true,
		flowOffload:       true,
		clampMSS:          true,
	}
	pol := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: true}}

	summary, err := applyBaselinePolicy(pol, opts)
	if err != nil {
		t.Fatalf("applyBaselinePolicy returned error: %v", err)
	}
	if summary.profile != baselineProfileIDSDetect ||
		!reflect.DeepEqual(summary.ids, []string{"IDS detect"}) ||
		!containsString(summary.network, "flowtable fast path disabled") ||
		!containsString(summary.network, "IDS NIC offload management") {
		t.Fatalf("summary = %#v", summary)
	}
	if pol.GetNetwork().GetEnableFlowOffload() || !pol.GetNetwork().GetManageNicOffloads() {
		t.Fatalf("network = %#v, want flow offload disabled and NIC offload management enabled", pol.GetNetwork())
	}
	ids := pol.GetIds()
	if !ids.GetEnabled() || ids.GetMode() != openngfwv1.IdsMode_IDS_MODE_DETECT ||
		ids.GetFailureBehavior() != openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED ||
		!reflect.DeepEqual(ids.GetMonitorInterfaces(), []string{"lan0", "wan0"}) ||
		!reflect.DeepEqual(ids.GetHomeNetworks(), []string{"10.10.0.0/16"}) ||
		!reflect.DeepEqual(ids.GetRuleFiles(), []string{baselineDefaultRule}) {
		t.Fatalf("ids = %#v", ids)
	}
}

func TestApplyBaselinePolicyStagesIPSPreventProfile(t *testing.T) {
	opts := baselineOptions{
		profile:           baselineProfileIPSPrevent,
		insideZone:        "lan",
		outsideZone:       "wan",
		insideInterfaces:  []string{"lan0"},
		outsideInterfaces: []string{"wan0"},
		insideCIDR:        "10.10.0.0/16",
		webuiPort:         8443,
		allowOutbound:     true,
		masquerade:        true,
		hardenHostInput:   true,
		flowOffload:       true,
		clampMSS:          true,
		manageNICOffload:  true,
		idsMonitorIfaces:  []string{"lan0"},
		idsHomeNetworks:   []string{"10.10.0.0/16", "10.11.0.0/16"},
		idsRuleFiles:      []string{"local.rules", "emerging.rules"},
		idsQueueNum:       7,
		idsFailure:        baselineFailureOpen,
	}
	pol := &openngfwv1.Policy{Network: &openngfwv1.Network{
		EnableFlowOffload: true,
		ManageNicOffloads: true,
	}}

	summary, err := applyBaselinePolicy(pol, opts)
	if err != nil {
		t.Fatalf("applyBaselinePolicy returned error: %v", err)
	}
	if summary.profile != baselineProfileIPSPrevent ||
		!reflect.DeepEqual(summary.ids, []string{"IPS prevent fail-open"}) ||
		!containsString(summary.network, "flowtable fast path disabled") {
		t.Fatalf("summary = %#v", summary)
	}
	if pol.GetNetwork().GetEnableFlowOffload() || pol.GetNetwork().GetManageNicOffloads() {
		t.Fatalf("network = %#v, want flow offload and NIC offload management disabled", pol.GetNetwork())
	}
	ids := pol.GetIds()
	if !ids.GetEnabled() || ids.GetMode() != openngfwv1.IdsMode_IDS_MODE_PREVENT ||
		ids.GetFailureBehavior() != openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN ||
		ids.GetQueueNum() != 7 ||
		!reflect.DeepEqual(ids.GetMonitorInterfaces(), []string{"lan0"}) ||
		!reflect.DeepEqual(ids.GetHomeNetworks(), []string{"10.10.0.0/16", "10.11.0.0/16"}) ||
		!reflect.DeepEqual(ids.GetRuleFiles(), []string{"local.rules", "emerging.rules"}) {
		t.Fatalf("ids = %#v", ids)
	}
}

func TestApplyBaselinePolicyMergesExistingObjects(t *testing.T) {
	opts := baselineOptions{
		insideZone:        "lan",
		outsideZone:       "wan",
		insideInterfaces:  []string{"eth2"},
		outsideInterfaces: []string{"eth0"},
		insideCIDR:        "10.0.0.0/24",
		webuiPort:         8080,
		allowOutbound:     true,
		masquerade:        true,
		hardenHostInput:   true,
	}
	pol := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan", Interfaces: []string{"eth1"}}},
		Addresses: []*openngfwv1.Address{
			{Name: "inside-existing", Cidr: "10.0.0.0/24"},
		},
		Services: []*openngfwv1.Service{
			{Name: "ssh-existing", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 22}}},
		},
	}

	if _, err := applyBaselinePolicy(pol, opts); err != nil {
		t.Fatalf("applyBaselinePolicy returned error: %v", err)
	}
	if got := pol.GetZones()[0].GetInterfaces(); !reflect.DeepEqual(got, []string{"eth1", "eth2"}) {
		t.Fatalf("lan interfaces = %#v", got)
	}
	if len(pol.GetAddresses()) != 1 || pol.GetRules()[0].GetSourceAddresses()[0] != "inside-existing" {
		t.Fatalf("address reuse failed: addresses=%#v rules=%#v", pol.GetAddresses(), pol.GetRules())
	}
	if pol.GetHostInput().GetRules()[0].GetServices()[0] != "ssh-existing" {
		t.Fatalf("service reuse failed: host input = %#v", pol.GetHostInput())
	}
}

func TestApplyBaselinePolicyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		opts baselineOptions
		want string
	}{
		{
			name: "same zones",
			opts: baselineOptions{insideZone: "lan", outsideZone: "LAN", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080},
			want: "--inside-zone",
		},
		{
			name: "missing inside interface",
			opts: baselineOptions{insideZone: "lan", outsideZone: "wan", outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080},
			want: "--inside-interface",
		},
		{
			name: "bad cidr",
			opts: baselineOptions{insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "bad", webuiPort: 8080},
			want: "--inside-cidr",
		},
		{
			name: "bad webui port",
			opts: baselineOptions{insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24"},
			want: "--webui-port",
		},
		{
			name: "bad mtu",
			opts: baselineOptions{insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080, mtu: 1279},
			want: "--mtu",
		},
		{
			name: "bad profile",
			opts: baselineOptions{profile: "tap-only", insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080},
			want: "--profile",
		},
		{
			name: "bad ids failure",
			opts: baselineOptions{profile: baselineProfileIPSPrevent, insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080, idsFailure: "maybe"},
			want: "--ids-failure-behavior",
		},
		{
			name: "bad ids home network",
			opts: baselineOptions{profile: baselineProfileIDSDetect, insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080, idsHomeNetworks: []string{"bad"}},
			want: "--ids-home-network",
		},
		{
			name: "bad ids rule file",
			opts: baselineOptions{profile: baselineProfileIDSDetect, insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080, idsRuleFiles: []string{"../bad.rules"}},
			want: "--ids-rule-file",
		},
		{
			name: "bad ids queue",
			opts: baselineOptions{profile: baselineProfileIPSPrevent, insideZone: "lan", outsideZone: "wan", insideInterfaces: []string{"eth1"}, outsideInterfaces: []string{"eth0"}, insideCIDR: "10.0.0.0/24", webuiPort: 8080, idsQueueNum: 65536},
			want: "--ids-queue",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyBaselinePolicy(&openngfwv1.Policy{}, tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestApplyNetworkSetFlags(t *testing.T) {
	opts := networkSetOptions{
		flowOffload:        "on",
		clampMSS:           "on",
		manageNICOffload:   "off",
		mtu:                9000,
		clearInterfaceMTUs: true,
	}
	cmd := networkSetCommandForTest(t, &opts, map[string]string{
		"flow-offload":         "on",
		"clamp-mss":            "on",
		"manage-nic-offloads":  "off",
		"mtu":                  "9000",
		"clear-interface-mtus": "true",
		"interface-mtu":        "wan0=1500",
	})
	opts.interfaceMTUs = []string{"wan0=1500", "mgmt0=1500"}
	pol := &openngfwv1.Policy{Network: &openngfwv1.Network{
		ManageNicOffloads: true,
		InterfaceMtus:     []*openngfwv1.InterfaceMtu{{Interface: "old0", Mtu: 9000}},
	}}

	summary, err := applyNetworkSetFlags(pol, opts, cmd)
	if err != nil {
		t.Fatalf("applyNetworkSetFlags returned error: %v", err)
	}
	if pol.GetNetwork().GetEnableFlowOffload() != true {
		t.Fatal("flow offload was not enabled")
	}
	if pol.GetNetwork().GetClampMssToPmtu() != true {
		t.Fatal("MSS clamping was not enabled")
	}
	if pol.GetNetwork().GetManageNicOffloads() != false {
		t.Fatal("NIC offload management should be disabled")
	}
	if pol.GetNetwork().GetMtu() != 9000 {
		t.Fatalf("MTU = %d, want 9000", pol.GetNetwork().GetMtu())
	}
	if got := pol.GetNetwork().GetInterfaceMtus(); len(got) != 2 ||
		got[0].GetInterface() != "mgmt0" || got[0].GetMtu() != 1500 ||
		got[1].GetInterface() != "wan0" || got[1].GetMtu() != 1500 {
		t.Fatalf("interface MTUs = %#v, want mgmt0/wan0 overrides", got)
	}
	joined := strings.Join(summary, "\n")
	for _, want := range []string{
		"flowtable fast path enabled",
		"TCP MSS clamping enabled",
		"IDS NIC offload management disabled",
		"global MTU 9000",
		"cleared per-interface MTU overrides",
		"interface MTU wan0=1500",
		"interface MTU mgmt0=1500",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing summary %q in %q", want, joined)
		}
	}
}

func TestApplyNetworkSetFlagsMergesInterfaceMTUs(t *testing.T) {
	opts := networkSetOptions{interfaceMTUs: []string{"wan0=1500"}}
	cmd := networkSetCommandForTest(t, &opts, map[string]string{"interface-mtu": "wan0=1500"})
	pol := &openngfwv1.Policy{Network: &openngfwv1.Network{
		InterfaceMtus: []*openngfwv1.InterfaceMtu{
			{Interface: "lan0", Mtu: 9000},
			{Interface: "wan0", Mtu: 9000},
		},
	}}

	summary, err := applyNetworkSetFlags(pol, opts, cmd)
	if err != nil {
		t.Fatalf("applyNetworkSetFlags returned error: %v", err)
	}
	got := pol.GetNetwork().GetInterfaceMtus()
	if len(got) != 2 ||
		got[0].GetInterface() != "lan0" || got[0].GetMtu() != 9000 ||
		got[1].GetInterface() != "wan0" || got[1].GetMtu() != 1500 {
		t.Fatalf("merged interface MTUs = %#v", got)
	}
	if !strings.Contains(strings.Join(summary, "\n"), "interface MTU wan0=1500") {
		t.Fatalf("missing interface MTU summary: %#v", summary)
	}
}

func TestApplyNetworkSetFlagsRejectsBadToggle(t *testing.T) {
	opts := networkSetOptions{flowOffload: "maybe"}
	cmd := networkSetCommandForTest(t, &opts, map[string]string{"flow-offload": "maybe"})
	_, err := applyNetworkSetFlags(&openngfwv1.Policy{}, opts, cmd)
	if err == nil || !strings.Contains(err.Error(), "--flow-offload") {
		t.Fatalf("expected flow-offload error, got %v", err)
	}
}

func TestApplyNetworkSetFlagsRejectsBadMtu(t *testing.T) {
	opts := networkSetOptions{mtu: 1279}
	cmd := networkSetCommandForTest(t, &opts, map[string]string{"mtu": "1279"})
	_, err := applyNetworkSetFlags(&openngfwv1.Policy{}, opts, cmd)
	if err == nil || !strings.Contains(err.Error(), "--mtu") {
		t.Fatalf("expected mtu error, got %v", err)
	}
}

func TestApplyNetworkProfile(t *testing.T) {
	tests := []struct {
		name      string
		wantMTU   uint32
		wantClamp bool
		wantNIC   bool
		wantFlow  bool
	}{
		{name: "throughput", wantMTU: 9000, wantClamp: true, wantNIC: false, wantFlow: true},
		{name: "inspection", wantMTU: 0, wantClamp: true, wantNIC: true, wantFlow: false},
		{name: "edge-vpn", wantMTU: 1500, wantClamp: true, wantNIC: false, wantFlow: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &openngfwv1.Policy{Network: &openngfwv1.Network{
				InterfaceMtus: []*openngfwv1.InterfaceMtu{{Interface: "lan0", Mtu: 9000}},
			}}

			summary, err := applyNetworkProfile(pol, tt.name)
			if err != nil {
				t.Fatalf("applyNetworkProfile returned error: %v", err)
			}
			net := pol.GetNetwork()
			if net.GetMtu() != tt.wantMTU ||
				net.GetClampMssToPmtu() != tt.wantClamp ||
				net.GetManageNicOffloads() != tt.wantNIC ||
				net.GetEnableFlowOffload() != tt.wantFlow {
				t.Fatalf("network = %#v", net)
			}
			if got := net.GetInterfaceMtus(); len(got) != 1 || got[0].GetInterface() != "lan0" || got[0].GetMtu() != 9000 {
				t.Fatalf("interface MTUs = %#v, want preserved lan0 override", got)
			}
			if !strings.Contains(strings.Join(summary, "\n"), "preserved 1 per-interface MTU override") {
				t.Fatalf("missing preserved override summary: %#v", summary)
			}
		})
	}
}

func TestApplyNetworkProfileRejectsThroughputWithIDS(t *testing.T) {
	pol := &openngfwv1.Policy{Ids: &openngfwv1.Ids{Enabled: true}}
	_, err := applyNetworkProfile(pol, "throughput")
	if err == nil || !strings.Contains(err.Error(), "requires IDS/IPS disabled") {
		t.Fatalf("expected IDS guard error, got %v", err)
	}
}

func TestApplyNetworkProfileRejectsUnknownProfile(t *testing.T) {
	_, err := applyNetworkProfile(&openngfwv1.Policy{}, "bad-profile")
	if err == nil || !strings.Contains(err.Error(), "valid profiles: edge-vpn, inspection, throughput") {
		t.Fatalf("expected valid profile list, got %v", err)
	}
}

func TestParseInterfaceMTUsRejectsInvalidValues(t *testing.T) {
	for _, raw := range []string{"wan0", "=1500", "wan0=abc", "wan0=1279", "wan0=9601"} {
		if _, err := parseInterfaceMTUs([]string{raw}); err == nil {
			t.Fatalf("parseInterfaceMTUs(%q) succeeded, want error", raw)
		}
	}
	if _, err := parseInterfaceMTUs([]string{"wan0=1500", "wan0=9000"}); err == nil {
		t.Fatal("duplicate interface override succeeded, want error")
	}
}

func TestPolicyCommandIncludesStaticRouteCommands(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newPolicyCommand(&server)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{args: []string{"route", "add"}, want: "add"},
		{args: []string{"routes", "delete"}, want: "delete"},
		{args: []string{"static-route", "show"}, want: "list"},
	} {
		got, remaining, err := cmd.Find(tt.args)
		if err != nil {
			t.Fatalf("Find(%v) returned error: %v", tt.args, err)
		}
		if len(remaining) != 0 {
			t.Fatalf("Find(%v) remaining args = %v", tt.args, remaining)
		}
		if got.Name() != tt.want {
			t.Fatalf("Find(%v) = %s, want %s", tt.args, got.Name(), tt.want)
		}
	}
}

func TestPolicyCommandIncludesObjectReferencesCommand(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newPolicyCommand(&server)
	for _, args := range [][]string{
		{"references", "--kind", "address"},
		{"refs", "--kind", "service"},
	} {
		got, _, err := cmd.Find(args)
		if err != nil {
			t.Fatalf("Find(%v) returned error: %v", args, err)
		}
		if got.Name() != "references" {
			t.Fatalf("Find(%v) = %s, want references", args, got.Name())
		}
	}
}

func TestPolicyCommandIncludesStatusCommand(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newPolicyCommand(&server)
	got, remaining, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("Find(status) returned error: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("Find(status) remaining args = %v", remaining)
	}
	if got.Name() != "status" {
		t.Fatalf("Find(status) = %s, want status", got.Name())
	}
}

func TestRunPolicyStatusPrintsCandidateSummary(t *testing.T) {
	client := &fakePolicyStatusClient{resp: &openngfwv1.GetCandidateStatusResponse{
		HasCandidate:   true,
		Dirty:          true,
		RunningVersion: 7,
		ChangeCount:    4,
		Changes:        []*openngfwv1.CandidateChangeSummary{{Section: "rules", Added: 1, Modified: 2, Removed: 1}},
		Impact:         &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, Items: []*openngfwv1.ChangeImpactItem{{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, Title: "Rule path changed", Detail: "candidate changes verdict"}}},
	}}
	cmd, out := policyStatusCommandForTest()
	if err := runPolicyStatus(context.Background(), cmd, client, policyStatusOptions{}); err != nil {
		t.Fatalf("runPolicyStatus returned error: %v", err)
	}
	if client.req == nil {
		t.Fatal("GetCandidateStatus was not called")
	}
	for _, want := range []string{
		"candidate status",
		"candidate:       staged",
		"dirty:           yes",
		"running version: v7",
		"changes:         4",
		"rules",
		"+1 ~2 -1",
		"impact: medium",
		"Rule path changed",
		"candidate changes verdict",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in output:\n%s", want, out.String())
		}
	}
}

func TestRunPolicyStatusPrintsJSON(t *testing.T) {
	client := &fakePolicyStatusClient{resp: &openngfwv1.GetCandidateStatusResponse{
		HasCandidate:   true,
		Dirty:          false,
		RunningVersion: 9,
		ChangeCount:    0,
	}}
	cmd, out := policyStatusCommandForTest()
	if err := runPolicyStatus(context.Background(), cmd, client, policyStatusOptions{outJSON: true}); err != nil {
		t.Fatalf("runPolicyStatus json returned error: %v", err)
	}
	for _, want := range []string{`"has_candidate"`, `"running_version"`, `"9"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("json output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "candidate status") {
		t.Fatalf("json output included human header:\n%s", out.String())
	}
}

func TestRunPolicyStatusPropagatesError(t *testing.T) {
	client := &fakePolicyStatusClient{err: fmt.Errorf("down")}
	cmd, _ := policyStatusCommandForTest()
	err := runPolicyStatus(context.Background(), cmd, client, policyStatusOptions{})
	if err == nil || !strings.Contains(err.Error(), "get candidate status: down") {
		t.Fatalf("expected wrapped candidate status error, got %v", err)
	}
}

func TestPolicyReferencesRequestNormalizesInputs(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want openngfwv1.PolicyObjectKind
	}{
		{name: "security profile", kind: "security-profiles", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE},
		{name: "QoS profile", kind: "qos-profile", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE},
		{name: "zone protection profile", kind: "zone-protection-profile", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, label, err := policyReferencesRequest(policyReferenceOptions{
				source:  "version",
				version: 42,
				kind:    tt.kind,
				name:    " inspect-standard ",
			})
			if err != nil {
				t.Fatalf("policyReferencesRequest returned error: %v", err)
			}
			if label != "version 42 policy" ||
				req.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_VERSION ||
				req.GetVersion() != 42 ||
				req.GetKind() != tt.want ||
				req.GetName() != "inspect-standard" {
				t.Fatalf("request=%#v label=%q", req, label)
			}
		})
	}
}

func TestPolicyReferencesRequestRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name string
		opts policyReferenceOptions
		want string
	}{
		{name: "missing kind", opts: policyReferenceOptions{source: "running"}, want: "--kind"},
		{name: "bad kind", opts: policyReferenceOptions{source: "running", kind: "tag"}, want: "--kind"},
		{name: "bad source", opts: policyReferenceOptions{source: "candidate-running", kind: "address"}, want: "--source"},
		{name: "version without source", opts: policyReferenceOptions{source: "candidate", version: 7, kind: "address"}, want: "--version"},
		{name: "version source missing version", opts: policyReferenceOptions{source: "version", kind: "address"}, want: "--version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := policyReferencesRequest(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestRunPolicyReferencesPrintsHumanTable(t *testing.T) {
	client := &fakePolicyReferencesClient{resp: &openngfwv1.ListObjectReferencesResponse{
		Version: 7,
		References: []*openngfwv1.PolicyObjectReference{{
			ObjectName: "web-server",
			Area:       "security rule",
			Item:       "allow-web",
			ItemId:     "rule-allow-web",
			Index:      0,
			Field:      "destination address",
			Detail:     "Traffic targets this address.",
		}},
	}}
	cmd, stdout := policyReferencesCommandForTest()
	err := runPolicyReferences(context.Background(), cmd, client, policyReferenceOptions{
		source: "running",
		kind:   "address",
		name:   "web-server",
	})
	if err != nil {
		t.Fatalf("runPolicyReferences returned error: %v", err)
	}
	if client.req == nil ||
		client.req.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_RUNNING ||
		client.req.GetKind() != openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS ||
		client.req.GetName() != "web-server" {
		t.Fatalf("request = %#v", client.req)
	}
	out := stdout.String()
	for _, want := range []string{"object references from running policy v7", "ITEM ID", "web-server", "security rule", "allow-web", "rule-allow-web", "destination address"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunPolicyReferencesPrintsJSON(t *testing.T) {
	client := &fakePolicyReferencesClient{resp: &openngfwv1.ListObjectReferencesResponse{
		References: []*openngfwv1.PolicyObjectReference{{ObjectName: "svc-web", Area: "source NAT", ItemId: "snat-lan-egress-custom"}},
	}}
	cmd, stdout := policyReferencesCommandForTest()
	err := runPolicyReferences(context.Background(), cmd, client, policyReferenceOptions{
		source:  "candidate",
		kind:    "services",
		outJSON: true,
	})
	if err != nil {
		t.Fatalf("runPolicyReferences returned error: %v", err)
	}
	if client.req.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE ||
		client.req.GetKind() != openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE {
		t.Fatalf("request = %#v", client.req)
	}
	var body struct {
		References []struct {
			ObjectName string `json:"object_name"`
			Area       string `json:"area"`
			ItemID     string `json:"item_id"`
		} `json:"references"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("json output was not parseable: %v\n%s", err, stdout.String())
	}
	if len(body.References) != 1 ||
		body.References[0].ObjectName != "svc-web" ||
		body.References[0].Area != "source NAT" ||
		body.References[0].ItemID != "snat-lan-egress-custom" {
		t.Fatalf("json output missing object reference: %#v\n%s", body.References, stdout.String())
	}
}

func TestPrintPolicyReferencesHandlesEmptyResult(t *testing.T) {
	cmd, stdout := policyReferencesCommandForTest()
	printPolicyReferences(cmd, "candidate policy", openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION, "corp-admin", &openngfwv1.ListObjectReferencesResponse{})
	if got := stdout.String(); !strings.Contains(got, "no references found for application corp-admin in candidate policy") {
		t.Fatalf("empty output = %q", got)
	}
}

func TestPolicyRenameObjectRequestNormalizesInputs(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want openngfwv1.PolicyObjectKind
	}{
		{name: "security profile", kind: "security-profile", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE},
		{name: "QoS profile", kind: "qos", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE},
		{name: "zone protection profile", kind: "zone_protection", want: openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := policyRenameObjectRequest(policyRenameObjectOptions{
				kind:    tt.kind,
				oldName: " inspect-standard ",
				newName: " inspect-strict ",
				comment: " cleanup shared object name ",
			})
			if err != nil {
				t.Fatalf("policyRenameObjectRequest returned error: %v", err)
			}
			if req.GetKind() != tt.want ||
				req.GetOldName() != "inspect-standard" ||
				req.GetNewName() != "inspect-strict" ||
				req.GetComment() != "cleanup shared object name" {
				t.Fatalf("request = %#v", req)
			}
		})
	}
}

func TestPolicyRenameObjectRequestRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name string
		opts policyRenameObjectOptions
		want string
	}{
		{name: "bad kind", opts: policyRenameObjectOptions{kind: "tag", oldName: "old", newName: "new"}, want: "--kind"},
		{name: "missing old", opts: policyRenameObjectOptions{kind: "address", newName: "new"}, want: "--old-name"},
		{name: "missing new", opts: policyRenameObjectOptions{kind: "address", oldName: "old"}, want: "--new-name"},
		{name: "same name", opts: policyRenameObjectOptions{kind: "address", oldName: "same", newName: "same"}, want: "must be different"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := policyRenameObjectRequest(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestRunPolicyRenameObjectPrintsHumanSummary(t *testing.T) {
	client := &fakePolicyRenameObjectClient{resp: &openngfwv1.RenamePolicyObjectResponse{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS,
		OldName: "web-server",
		NewName: "dmz-web",
		RewrittenReferences: []*openngfwv1.PolicyObjectReference{{
			ObjectName: "dmz-web",
			Area:       "security rule",
			Item:       "allow-web",
			ItemId:     "rule-allow-web",
			Field:      "destination address",
			Detail:     "Traffic targets this address.",
		}},
		CandidateStatus: &openngfwv1.GetCandidateStatusResponse{
			HasCandidate:   true,
			Dirty:          true,
			RunningVersion: 4,
			ChangeCount:    2,
		},
	}}
	cmd, stdout := policyReferencesCommandForTest()
	err := runPolicyRenameObject(context.Background(), cmd, client, policyRenameObjectOptions{
		kind:    "address",
		oldName: "web-server",
		newName: "dmz-web",
		comment: "normalize naming",
	})
	if err != nil {
		t.Fatalf("runPolicyRenameObject returned error: %v", err)
	}
	if client.req == nil ||
		client.req.GetKind() != openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS ||
		client.req.GetOldName() != "web-server" ||
		client.req.GetNewName() != "dmz-web" ||
		client.req.GetComment() != "normalize naming" {
		t.Fatalf("request = %#v", client.req)
	}
	out := stdout.String()
	for _, want := range []string{
		`address "web-server" renamed to "dmz-web" in candidate`,
		"rewritten references: 1",
		"security rule",
		"rule-allow-web",
		"candidate status",
		"run 'ngfwctl policy validate' then 'ngfwctl commit' to apply",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunPolicyRenameObjectPrintsJSON(t *testing.T) {
	client := &fakePolicyRenameObjectClient{resp: &openngfwv1.RenamePolicyObjectResponse{
		Kind:    openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE,
		OldName: "https",
		NewName: "web-https",
	}}
	cmd, stdout := policyReferencesCommandForTest()
	err := runPolicyRenameObject(context.Background(), cmd, client, policyRenameObjectOptions{
		kind:    "service",
		oldName: "https",
		newName: "web-https",
		outJSON: true,
	})
	if err != nil {
		t.Fatalf("runPolicyRenameObject returned error: %v", err)
	}
	var body struct {
		OldName string `json:"old_name"`
		NewName string `json:"new_name"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("json output was not parseable: %v\n%s", err, stdout.String())
	}
	if body.OldName != "https" || body.NewName != "web-https" {
		t.Fatalf("json body = %#v", body)
	}
}

func TestStaticRouteFromOptionsNormalizesRoute(t *testing.T) {
	route, err := staticRouteFromOptions(staticRouteOptions{
		destination: " 10.0.2.7/24 ",
		via:         " 2001:db8::1 ",
		iface:       " wan0 ",
		metric:      42,
	})
	if err != nil {
		t.Fatalf("staticRouteFromOptions returned error: %v", err)
	}
	if route.GetDestination() != "10.0.2.0/24" ||
		route.GetVia() != "2001:db8::1" ||
		route.GetInterface() != "wan0" ||
		route.GetMetric() != 42 {
		t.Fatalf("route = %#v", route)
	}
}

func TestStaticRouteFromOptionsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		opts staticRouteOptions
		want string
	}{
		{name: "missing destination", opts: staticRouteOptions{via: "10.0.0.1"}, want: "--destination is required"},
		{name: "bad destination", opts: staticRouteOptions{destination: "not-a-cidr", via: "10.0.0.1"}, want: "--destination"},
		{name: "missing next hop and interface", opts: staticRouteOptions{destination: "10.0.0.0/24"}, want: "one of --via or --interface"},
		{name: "bad next hop", opts: staticRouteOptions{destination: "10.0.0.0/24", via: "not-an-ip"}, want: "--via"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := staticRouteFromOptions(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestStageStaticRouteUpsertAddsFromRunningPolicy(t *testing.T) {
	running := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{
		Destination: "192.0.2.0/24",
		Via:         "10.0.0.1",
	}}}
	client := &fakePolicyClient{
		candidateErr: status.Error(codes.NotFound, "no candidate policy is set"),
		running:      running,
	}
	route := &openngfwv1.StaticRoute{
		Destination: "10.0.2.0/24",
		Via:         "10.0.1.1",
		Interface:   "wan0",
		Metric:      10,
	}

	result, err := stageStaticRouteUpsert(context.Background(), client, route)
	if err != nil {
		t.Fatalf("stageStaticRouteUpsert returned error: %v", err)
	}
	if result.source != "running" || result.action != "added" {
		t.Fatalf("result = %#v, want running/added", result)
	}
	got := client.setCandidate.GetStaticRoutes()
	if len(got) != 2 ||
		got[0].GetDestination() != "192.0.2.0/24" ||
		got[1].GetDestination() != "10.0.2.0/24" ||
		got[1].GetVia() != "10.0.1.1" ||
		got[1].GetInterface() != "wan0" ||
		got[1].GetMetric() != 10 {
		t.Fatalf("staged routes = %#v", got)
	}
	if len(running.GetStaticRoutes()) != 1 {
		t.Fatalf("running policy was mutated: %#v", running.GetStaticRoutes())
	}
}

func TestStageStaticRouteUpsertUpdatesExistingCandidateRoute(t *testing.T) {
	candidate := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{
		{Destination: "10.0.2.99/24", Via: "10.0.1.1", Interface: "old0", Metric: 5},
		{Destination: "203.0.113.0/24", Interface: "wg0", Metric: 100},
	}}
	client := &fakePolicyClient{candidate: candidate}
	route := &openngfwv1.StaticRoute{
		Destination: "10.0.2.0/24",
		Via:         "10.0.3.1",
		Interface:   "wan1",
		Metric:      20,
	}

	result, err := stageStaticRouteUpsert(context.Background(), client, route)
	if err != nil {
		t.Fatalf("stageStaticRouteUpsert returned error: %v", err)
	}
	if result.source != "candidate" || result.action != "updated" {
		t.Fatalf("result = %#v, want candidate/updated", result)
	}
	got := client.setCandidate.GetStaticRoutes()
	if len(got) != 2 ||
		got[0].GetDestination() != "10.0.2.0/24" ||
		got[0].GetVia() != "10.0.3.1" ||
		got[0].GetInterface() != "wan1" ||
		got[0].GetMetric() != 20 ||
		got[1].GetDestination() != "203.0.113.0/24" {
		t.Fatalf("staged routes = %#v", got)
	}
	if candidate.GetStaticRoutes()[0].GetMetric() != 5 {
		t.Fatalf("candidate policy was mutated: %#v", candidate.GetStaticRoutes()[0])
	}
}

func TestStageStaticRouteDeleteRemovesCandidateRoute(t *testing.T) {
	candidate := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{
		{Destination: "10.0.2.0/24", Via: "10.0.1.1", Metric: 10},
		{Destination: "203.0.113.0/24", Interface: "wg0", Metric: 100},
	}}
	client := &fakePolicyClient{candidate: candidate}

	result, err := stageStaticRouteDelete(context.Background(), client, "10.0.2.7/24")
	if err != nil {
		t.Fatalf("stageStaticRouteDelete returned error: %v", err)
	}
	if result.source != "candidate" || result.action != "deleted" ||
		result.route.GetDestination() != "10.0.2.0/24" {
		t.Fatalf("result = %#v, want deleted 10.0.2.0/24", result)
	}
	got := client.setCandidate.GetStaticRoutes()
	if len(got) != 1 || got[0].GetDestination() != "203.0.113.0/24" {
		t.Fatalf("staged routes = %#v", got)
	}
	if len(candidate.GetStaticRoutes()) != 2 {
		t.Fatalf("candidate policy was mutated: %#v", candidate.GetStaticRoutes())
	}
}

func TestStageStaticRouteDeleteRejectsMissingRoute(t *testing.T) {
	client := &fakePolicyClient{candidate: &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{
		Destination: "10.0.2.0/24",
		Via:         "10.0.1.1",
	}}}}

	_, err := stageStaticRouteDelete(context.Background(), client, "198.51.100.0/24")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
	if client.setCandidateCalls != 0 {
		t.Fatalf("SetCandidate calls = %d, want 0", client.setCandidateCalls)
	}
}

func TestReadStaticRoutesSelectsPolicySource(t *testing.T) {
	client := &fakePolicyClient{
		candidate: &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "10.0.0.0/24", Interface: "lan0"}}},
		running:   &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "0.0.0.0/0", Via: "192.0.2.1"}}},
		versions: map[uint64]*openngfwv1.Policy{
			7: {StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "203.0.113.0/24", Interface: "wg0"}}},
		},
	}
	tests := []struct {
		source  string
		version uint64
		wantSrc string
		wantDst string
	}{
		{source: "running", wantSrc: "running", wantDst: "0.0.0.0/0"},
		{source: "candidate", wantSrc: "candidate", wantDst: "10.0.0.0/24"},
		{source: "version", version: 7, wantSrc: "version 7", wantDst: "203.0.113.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.wantSrc, func(t *testing.T) {
			req, label, err := staticRoutePolicyRequest(tt.source, tt.version)
			if err != nil {
				t.Fatalf("staticRoutePolicyRequest returned error: %v", err)
			}
			result, err := readStaticRoutes(context.Background(), client, req, label)
			if err != nil {
				t.Fatalf("readStaticRoutes returned error: %v", err)
			}
			if result.source != tt.wantSrc ||
				len(result.routes) != 1 ||
				result.routes[0].GetDestination() != tt.wantDst {
				t.Fatalf("result = %#v, want %s %s", result, tt.wantSrc, tt.wantDst)
			}
		})
	}
}

func TestStaticRoutePolicyRequestRejectsInvalidSource(t *testing.T) {
	if _, _, err := staticRoutePolicyRequest("version", 0); err == nil || !strings.Contains(err.Error(), "--version") {
		t.Fatalf("expected --version error, got %v", err)
	}
	if _, _, err := staticRoutePolicyRequest("running", 7); err == nil || !strings.Contains(err.Error(), "--version is only valid") {
		t.Fatalf("expected unused running --version error, got %v", err)
	}
	if _, _, err := staticRoutePolicyRequest("candidate", 7); err == nil || !strings.Contains(err.Error(), "--version is only valid") {
		t.Fatalf("expected unused candidate --version error, got %v", err)
	}
	if _, _, err := staticRoutePolicyRequest("startup", 0); err == nil || !strings.Contains(err.Error(), "--source") {
		t.Fatalf("expected --source error, got %v", err)
	}
}

func TestPrintStaticRoutesFormatsTableAndJSON(t *testing.T) {
	routes := []*openngfwv1.StaticRoute{
		{Destination: "203.0.113.0/24", Interface: "wg0", Metric: 100},
		{Destination: "0.0.0.0/0", Via: "192.0.2.1", Interface: "wan0", Metric: 10},
	}
	cmd := &cobra.Command{}
	var table bytes.Buffer
	cmd.SetOut(&table)
	if err := printStaticRoutes(cmd, "candidate", routes, false); err != nil {
		t.Fatalf("printStaticRoutes table returned error: %v", err)
	}
	out := table.String()
	if !strings.Contains(out, "static routes from candidate policy") ||
		!strings.Contains(out, "DESTINATION") ||
		!strings.Contains(out, "0.0.0.0/0") ||
		!strings.Contains(out, "192.0.2.1") ||
		!strings.Contains(out, "wg0") {
		t.Fatalf("table output missing route detail:\n%s", out)
	}
	if strings.Index(out, "0.0.0.0/0") > strings.Index(out, "203.0.113.0/24") {
		t.Fatalf("table output is not sorted by destination:\n%s", out)
	}

	var js bytes.Buffer
	cmd.SetOut(&js)
	if err := printStaticRoutes(cmd, "candidate", routes, true); err != nil {
		t.Fatalf("printStaticRoutes json returned error: %v", err)
	}
	jsonOut := js.String()
	if !strings.Contains(jsonOut, `"destination": "0.0.0.0/0"`) ||
		!strings.Contains(jsonOut, `"interface": "wg0"`) {
		t.Fatalf("json output missing route detail:\n%s", jsonOut)
	}
	if strings.Contains(jsonOut, "static routes from") {
		t.Fatalf("json output included human source label:\n%s", jsonOut)
	}
}

func TestReadVPNConfigSelectsPolicySource(t *testing.T) {
	client := &fakePolicyClient{
		candidate: &openngfwv1.Policy{Vpn: &openngfwv1.Vpn{WireguardInterfaces: []*openngfwv1.WireguardInterface{{Name: "wg-candidate"}}}},
		running:   &openngfwv1.Policy{Vpn: &openngfwv1.Vpn{IpsecTunnels: []*openngfwv1.IpsecTunnel{{Name: "site-running"}}}},
		versions: map[uint64]*openngfwv1.Policy{
			3: {Vpn: &openngfwv1.Vpn{WireguardInterfaces: []*openngfwv1.WireguardInterface{{Name: "wg-version"}}}},
		},
	}
	tests := []struct {
		source  string
		version uint64
		wantSrc string
		wantVPN string
	}{
		{source: "running", wantSrc: "running", wantVPN: "site-running"},
		{source: "candidate", wantSrc: "candidate", wantVPN: "wg-candidate"},
		{source: "version", version: 3, wantSrc: "version 3", wantVPN: "wg-version"},
	}
	for _, tt := range tests {
		t.Run(tt.wantSrc, func(t *testing.T) {
			req, label, err := staticRoutePolicyRequest(tt.source, tt.version)
			if err != nil {
				t.Fatalf("staticRoutePolicyRequest returned error: %v", err)
			}
			result, err := readVPNConfig(context.Background(), client, req, label)
			if err != nil {
				t.Fatalf("readVPNConfig returned error: %v", err)
			}
			if result.source != tt.wantSrc {
				t.Fatalf("source = %q, want %q", result.source, tt.wantSrc)
			}
			names := []string{}
			for _, tunnel := range result.vpn.GetIpsecTunnels() {
				names = append(names, tunnel.GetName())
			}
			for _, iface := range result.vpn.GetWireguardInterfaces() {
				names = append(names, iface.GetName())
			}
			if !containsString(names, tt.wantVPN) {
				t.Fatalf("vpn names = %v, want %q", names, tt.wantVPN)
			}
			if len(result.vpn.GetWireguardInterfaces()) > 0 {
				result.vpn.GetWireguardInterfaces()[0].Name = "mutated"
			}
			if tt.source == "candidate" && client.candidate.GetVpn().GetWireguardInterfaces()[0].GetName() != "wg-candidate" {
				t.Fatal("readVPNConfig returned aliased candidate VPN policy")
			}
		})
	}
}

func TestVPNConfigRowsRedactsSecretPathsAndPeerKeys(t *testing.T) {
	rows := vpnConfigRows(&openngfwv1.Vpn{
		IpsecTunnels: []*openngfwv1.IpsecTunnel{{
			Name:          "site-b",
			LocalAddress:  "%any",
			RemoteAddress: "203.0.113.10",
			LocalSubnets:  []string{"10.10.0.0/24"},
			RemoteSubnets: []string{"10.20.0.0/24"},
			PskFile:       "/etc/openngfw/secrets/site-b.conf",
			Initiate:      true,
		}},
		WireguardInterfaces: []*openngfwv1.WireguardInterface{{
			Name:           "wg0",
			Address:        "10.99.0.1/24",
			ListenPort:     51820,
			PrivateKeyFile: "/etc/openngfw/keys/wg0.key",
			Peers: []*openngfwv1.WireguardPeer{{
				Name:                "laptop",
				PublicKey:           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoint:            "203.0.113.20:51820",
				AllowedIps:          []string{"10.99.0.2/32"},
				PersistentKeepalive: 25,
			}},
		}},
	})
	if rows.IPsec[0].PskFile != "<redacted>" ||
		rows.WireGuard[0].PrivateKeyFile != "<redacted>" {
		t.Fatalf("secret path fields were not redacted: %#v", rows)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, leaked := range []string{"/etc/openngfw", "site-b.conf", "wg0.key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if strings.Contains(text, leaked) {
			t.Fatalf("VPN rows leaked %q in %s", leaked, text)
		}
	}
	if !strings.Contains(text, "203.0.113.20:51820") ||
		!strings.Contains(text, "10.99.0.2/32") {
		t.Fatalf("VPN rows lost non-secret peer routing detail: %s", text)
	}
}

func TestPrintVPNConfigFormatsTableAndJSON(t *testing.T) {
	vpn := &openngfwv1.Vpn{
		IpsecTunnels:        []*openngfwv1.IpsecTunnel{{Name: "site-b", LocalAddress: "%any", RemoteAddress: "203.0.113.10", LocalSubnets: []string{"10.10.0.0/24"}, RemoteSubnets: []string{"10.20.0.0/24"}, PskFile: "/etc/openngfw/secrets/site-b.conf", Initiate: true}},
		WireguardInterfaces: []*openngfwv1.WireguardInterface{{Name: "wg0", Address: "10.99.0.1/24", ListenPort: 51820, PrivateKeyFile: "/etc/openngfw/keys/wg0.key", Peers: []*openngfwv1.WireguardPeer{{Name: "laptop"}}}},
	}
	cmd := &cobra.Command{}
	var table bytes.Buffer
	cmd.SetOut(&table)
	if err := printVPNConfig(cmd, "candidate", vpn, false); err != nil {
		t.Fatalf("printVPNConfig table returned error: %v", err)
	}
	out := table.String()
	for _, want := range []string{"VPN configuration from candidate policy", "IPsec tunnels", "site-b", "WireGuard interfaces", "wg0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q:\n%s", want, out)
		}
	}
	for _, want := range []string{"Peers for wg0", "laptop"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing peer detail %q:\n%s", want, out)
		}
	}
	for _, leaked := range []string{"/etc/openngfw", "site-b.conf", "wg0.key"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("table output leaked %q:\n%s", leaked, out)
		}
	}

	var js bytes.Buffer
	cmd.SetOut(&js)
	if err := printVPNConfig(cmd, "candidate", vpn, true); err != nil {
		t.Fatalf("printVPNConfig json returned error: %v", err)
	}
	jsonOut := js.String()
	for _, want := range []string{`"source": "candidate"`, `"ipsec_tunnels"`, `"wireguard_interfaces"`, `"psk_file": "<redacted>"`, `"private_key_file": "<redacted>"`} {
		if !strings.Contains(jsonOut, want) {
			t.Fatalf("json output missing %q:\n%s", want, jsonOut)
		}
	}
	if strings.Contains(jsonOut, "VPN configuration from") || strings.Contains(jsonOut, "/etc/openngfw") {
		t.Fatalf("json output included human label or secret path:\n%s", jsonOut)
	}
}

func TestPolicyCommandIncludesVPNList(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newPolicyCommand(&server)
	vpnCmd, _, err := cmd.Find([]string{"vpn", "list"})
	if err != nil {
		t.Fatalf("find policy vpn list returned error: %v", err)
	}
	if vpnCmd == nil || vpnCmd.Use != "list" {
		t.Fatalf("policy vpn list command not registered: %#v", vpnCmd)
	}
}

func TestEditablePolicyPrefersCandidate(t *testing.T) {
	client := &fakePolicyClient{
		candidate: &openngfwv1.Policy{Network: &openngfwv1.Network{Mtu: 9000}},
		running:   &openngfwv1.Policy{Network: &openngfwv1.Network{Mtu: 1500}},
	}

	pol, source, err := editablePolicy(context.Background(), client)
	if err != nil {
		t.Fatalf("editablePolicy returned error: %v", err)
	}
	if source != "candidate" {
		t.Fatalf("source = %q, want candidate", source)
	}
	if pol.GetNetwork().GetMtu() != 9000 {
		t.Fatalf("MTU = %d, want candidate MTU 9000", pol.GetNetwork().GetMtu())
	}
	pol.Network.Mtu = 1200
	if client.candidate.GetNetwork().GetMtu() != 9000 {
		t.Fatal("editablePolicy returned aliased candidate policy")
	}
}

func TestEditablePolicyFallsBackToRunning(t *testing.T) {
	client := &fakePolicyClient{
		candidateErr: status.Error(codes.NotFound, "no candidate policy is set"),
		running:      &openngfwv1.Policy{Network: &openngfwv1.Network{Mtu: 1500}},
	}

	pol, source, err := editablePolicy(context.Background(), client)
	if err != nil {
		t.Fatalf("editablePolicy returned error: %v", err)
	}
	if source != "running" {
		t.Fatalf("source = %q, want running", source)
	}
	if pol.GetNetwork().GetMtu() != 1500 {
		t.Fatalf("MTU = %d, want running MTU 1500", pol.GetNetwork().GetMtu())
	}
}

func TestEditablePolicyStartsEmptyWhenNoPolicyExists(t *testing.T) {
	client := &fakePolicyClient{
		candidateErr: status.Error(codes.NotFound, "no candidate policy is set"),
		runningErr:   status.Error(codes.NotFound, "no running policy exists"),
	}

	pol, source, err := editablePolicy(context.Background(), client)
	if err != nil {
		t.Fatalf("editablePolicy returned error: %v", err)
	}
	if source != "empty" {
		t.Fatalf("source = %q, want empty", source)
	}
	if pol == nil {
		t.Fatal("editablePolicy returned nil policy")
	}
}

func networkSetCommandForTest(t *testing.T, opts *networkSetOptions, values map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&opts.flowOffload, "flow-offload", "keep", "")
	cmd.Flags().StringVar(&opts.clampMSS, "clamp-mss", "keep", "")
	cmd.Flags().StringVar(&opts.manageNICOffload, "manage-nic-offloads", "keep", "")
	cmd.Flags().Uint32Var(&opts.mtu, "mtu", 0, "")
	cmd.Flags().StringArrayVar(&opts.interfaceMTUs, "interface-mtu", nil, "")
	cmd.Flags().BoolVar(&opts.clearInterfaceMTUs, "clear-interface-mtus", false, "")
	for name, value := range values {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set flag %s: %v", name, err)
		}
	}
	return cmd
}

func policyReferencesCommandForTest() (*cobra.Command, *bytes.Buffer) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	return cmd, &stdout
}

func policyStatusCommandForTest() (*cobra.Command, *bytes.Buffer) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	return cmd, &stdout
}

func policyCommandForTest() (*cobra.Command, *bytes.Buffer) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	return cmd, &stdout
}

type fakePolicyClient struct {
	candidate          *openngfwv1.Policy
	candidateErr       error
	running            *openngfwv1.Policy
	runningVersion     uint64
	runningErr         error
	versions           map[uint64]*openngfwv1.Policy
	versionErr         error
	setCandidate       *openngfwv1.Policy
	setCandidateCalls  int
	setCandidateErr    error
	statusCalls        int
	statusResp         *openngfwv1.GetCandidateStatusResponse
	statusErr          error
	createApprovalReq  *openngfwv1.CreateChangeApprovalRequest
	createApprovalResp *openngfwv1.CreateChangeApprovalResponse
	createApprovalErr  error
	listApprovalsReq   *openngfwv1.ListChangeApprovalsRequest
	listApprovalsResp  *openngfwv1.ListChangeApprovalsResponse
	listApprovalsErr   error
}

func (f *fakePolicyClient) GetPolicy(_ context.Context, req *openngfwv1.GetPolicyRequest, _ ...grpc.CallOption) (*openngfwv1.GetPolicyResponse, error) {
	switch req.GetSource() {
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		if f.candidateErr != nil {
			return nil, f.candidateErr
		}
		return &openngfwv1.GetPolicyResponse{Policy: f.candidate}, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		if f.versionErr != nil {
			return nil, f.versionErr
		}
		pol := f.versions[req.GetVersion()]
		if pol == nil {
			return nil, status.Error(codes.NotFound, fmt.Sprintf("version %d not found", req.GetVersion()))
		}
		return &openngfwv1.GetPolicyResponse{Policy: pol, Version: req.GetVersion()}, nil
	default:
		if f.runningErr != nil {
			return nil, f.runningErr
		}
		return &openngfwv1.GetPolicyResponse{Policy: f.running, Version: f.runningVersion}, nil
	}
}

func (f *fakePolicyClient) SetCandidate(_ context.Context, req *openngfwv1.SetCandidateRequest, _ ...grpc.CallOption) (*openngfwv1.SetCandidateResponse, error) {
	f.setCandidateCalls++
	if f.setCandidateErr != nil {
		return nil, f.setCandidateErr
	}
	f.setCandidate = clonePolicy(req.GetPolicy())
	return &openngfwv1.SetCandidateResponse{}, nil
}

func (f *fakePolicyClient) GetCandidateStatus(_ context.Context, req *openngfwv1.GetCandidateStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error) {
	f.statusCalls++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.statusResp != nil {
		return f.statusResp, nil
	}
	return &openngfwv1.GetCandidateStatusResponse{}, nil
}

func (f *fakePolicyClient) CreateChangeApproval(_ context.Context, req *openngfwv1.CreateChangeApprovalRequest, _ ...grpc.CallOption) (*openngfwv1.CreateChangeApprovalResponse, error) {
	f.createApprovalReq = req
	if f.createApprovalErr != nil {
		return nil, f.createApprovalErr
	}
	if f.createApprovalResp != nil {
		return f.createApprovalResp, nil
	}
	return &openngfwv1.CreateChangeApprovalResponse{Approval: &openngfwv1.ChangeApproval{
		Id:                "approval-1",
		CandidateRevision: req.GetCandidateRevision(),
		Comment:           req.GetComment(),
		AckRisk:           req.GetAckRisk(),
		AckRuntime:        req.GetAckRuntime(),
	}}, nil
}

func (f *fakePolicyClient) ListChangeApprovals(_ context.Context, req *openngfwv1.ListChangeApprovalsRequest, _ ...grpc.CallOption) (*openngfwv1.ListChangeApprovalsResponse, error) {
	f.listApprovalsReq = req
	if f.listApprovalsErr != nil {
		return nil, f.listApprovalsErr
	}
	if f.listApprovalsResp != nil {
		return f.listApprovalsResp, nil
	}
	return &openngfwv1.ListChangeApprovalsResponse{}, nil
}

type fakePolicyStatusClient struct {
	req  *openngfwv1.GetCandidateStatusRequest
	resp *openngfwv1.GetCandidateStatusResponse
	err  error
}

func (f *fakePolicyStatusClient) GetCandidateStatus(_ context.Context, req *openngfwv1.GetCandidateStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.GetCandidateStatusResponse{}, nil
}

type fakePolicyReferencesClient struct {
	req  *openngfwv1.ListObjectReferencesRequest
	resp *openngfwv1.ListObjectReferencesResponse
	err  error
}

func (f *fakePolicyReferencesClient) ListObjectReferences(_ context.Context, req *openngfwv1.ListObjectReferencesRequest, _ ...grpc.CallOption) (*openngfwv1.ListObjectReferencesResponse, error) {
	f.req = req
	return f.resp, f.err
}

type fakePolicyRenameObjectClient struct {
	req  *openngfwv1.RenamePolicyObjectRequest
	resp *openngfwv1.RenamePolicyObjectResponse
	err  error
}

func (f *fakePolicyRenameObjectClient) RenamePolicyObject(_ context.Context, req *openngfwv1.RenamePolicyObjectRequest, _ ...grpc.CallOption) (*openngfwv1.RenamePolicyObjectResponse, error) {
	f.req = req
	return f.resp, f.err
}

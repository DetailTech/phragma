package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"sigs.k8s.io/yaml"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/policydiff"
)

func newPolicyCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage the declarative policy (candidate workflow)",
	}
	cmd.AddCommand(
		newPolicySetCommand(server),
		newPolicyShowCommand(server),
		newPolicyStatusCommand(server),
		newPolicyValidateCommand(server),
		newPolicyDiffCommand(server),
		newPolicyApprovalsCommand(server),
		newPolicyReferencesCommand(server),
		newPolicyRenameObjectCommand(server),
		newPolicyBaselineCommand(server),
		newPolicyNatCommand(server),
		newPolicyNetworkCommand(server),
		newPolicyRouteCommand(server),
		newPolicyVPNCommand(server),
	)
	return cmd
}

type policyStatusClient interface {
	GetCandidateStatus(context.Context, *openngfwv1.GetCandidateStatusRequest, ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error)
}

type policyApprovalsClient interface {
	GetCandidateStatus(context.Context, *openngfwv1.GetCandidateStatusRequest, ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error)
	CreateChangeApproval(context.Context, *openngfwv1.CreateChangeApprovalRequest, ...grpc.CallOption) (*openngfwv1.CreateChangeApprovalResponse, error)
	ListChangeApprovals(context.Context, *openngfwv1.ListChangeApprovalsRequest, ...grpc.CallOption) (*openngfwv1.ListChangeApprovalsResponse, error)
}

type policyStatusOptions struct {
	outJSON bool
}

func newPolicyStatusCommand(server *string) *cobra.Command {
	opts := policyStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show staged candidate dirty state and section impact",
		Long: "Show the candidate workspace status reported by /v1/candidate/status: " +
			"whether a candidate exists, whether it differs from running policy, section-level change counts, and impact summary. " +
			"This command is read-only and does not validate, commit, or mutate policy.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runPolicyStatus(ctx, cmd, openngfwv1.NewPolicyServiceClient(conn), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newPolicySetCommand(server *string) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Load a YAML/JSON policy file as the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			jsonBytes, err := yaml.YAMLToJSON(raw)
			if err != nil {
				return fmt.Errorf("parse %s: %w", file, err)
			}
			pol := &openngfwv1.Policy{}
			if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(jsonBytes, pol); err != nil {
				return fmt.Errorf("policy schema error in %s: %w", file, err)
			}

			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			cmd.Println("candidate updated; run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "policy file (YAML or JSON)")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func newPolicyShowCommand(server *string) *cobra.Command {
	var (
		source  string
		ver     uint64
		outJSON bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the running, candidate, or a historical policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := &openngfwv1.GetPolicyRequest{}
			switch source {
			case "running":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
			case "candidate":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE
			case "version":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_VERSION
				req.Version = ver
			default:
				return fmt.Errorf("--source must be running, candidate, or version")
			}

			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).GetPolicy(ctx, req)
			if err != nil {
				return err
			}

			jsonBytes, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp.GetPolicy())
			if err != nil {
				return err
			}
			if outJSON {
				cmd.Println(string(jsonBytes))
				return nil
			}
			y, err := yaml.JSONToYAML(jsonBytes)
			if err != nil {
				return err
			}
			cmd.Print(string(y))
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "running", "running | candidate | version")
	cmd.Flags().Uint64Var(&ver, "version", 0, "version id (with --source version)")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON instead of YAML")
	return cmd
}

func runPolicyStatus(ctx context.Context, cmd *cobra.Command, client policyStatusClient, opts policyStatusOptions) error {
	resp, err := client.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return fmt.Errorf("get candidate status: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPolicyStatus(cmd, resp)
	return nil
}

func printPolicyStatus(cmd *cobra.Command, resp *openngfwv1.GetCandidateStatusResponse) {
	cmd.Println("candidate status")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	if resp.GetHasCandidate() {
		cmd.Println("  candidate:       staged")
	} else {
		cmd.Println("  candidate:       none")
	}
	cmd.Printf("  dirty:           %s\n", yesNo(resp.GetDirty()))
	cmd.Printf("  running version: v%d\n", resp.GetRunningVersion())
	cmd.Printf("  changes:         %d\n", resp.GetChangeCount())
	if changes := resp.GetChanges(); len(changes) > 0 {
		cmd.Println("  sections:")
		for _, change := range changes {
			cmd.Printf("    - %-18s +%d ~%d -%d\n",
				displayEmpty(change.GetSection()),
				change.GetAdded(),
				change.GetModified(),
				change.GetRemoved())
		}
	}
	printImpact(cmd, resp.GetImpact())
}

func newPolicyValidateCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the candidate policy without applying it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).Validate(ctx, &openngfwv1.ValidateRequest{})
			if err != nil {
				return err
			}
			if !resp.GetValid() {
				errs := validationErrors(resp)
				for _, e := range errs {
					cmd.PrintErrln("error: " + e)
				}
				printValidationFindings(cmd, resp)
				printImpact(cmd, resp.GetImpact())
				return fmt.Errorf("candidate is invalid (%d errors)", len(errs))
			}
			cmd.Println("candidate is valid")
			printRenderPlan(cmd, resp.GetRenderPlan())
			printValidationFindings(cmd, resp)
			printImpact(cmd, resp.GetImpact())
			return nil
		},
	}
}

func newPolicyDiffCommand(server *string) *cobra.Command {
	var from string
	var version uint64
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show the staged candidate diff before commit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			req, err := policyDiffRequest(from, version)
			if err != nil {
				return err
			}
			resp, err := client.DiffPolicy(ctx, req)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					return fmt.Errorf("no candidate policy is set; stage one with 'ngfwctl policy set', 'ngfwctl policy baseline', or another policy command")
				}
				return fmt.Errorf("diff policy: %w", err)
			}
			if !resp.GetChanged() {
				cmd.Printf("%s matches %s\n", resp.GetToLabel(), resp.GetFromLabel())
				return nil
			}
			for _, line := range policydiff.TextLines(resp.GetFromLabel(), resp.GetToLabel(), resp.GetLines()) {
				cmd.Println(line)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "running", "baseline source: running | version")
	cmd.Flags().Uint64Var(&version, "version", 0, "version id when --from version")
	return cmd
}

func policyDiffRequest(from string, version uint64) (*openngfwv1.DiffPolicyRequest, error) {
	req := &openngfwv1.DiffPolicyRequest{ToSource: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE}
	switch strings.ToLower(strings.TrimSpace(from)) {
	case "", "running":
		req.FromSource = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
	case "version":
		if version == 0 {
			return nil, fmt.Errorf("--version is required when --from version")
		}
		req.FromSource = openngfwv1.PolicySource_POLICY_SOURCE_VERSION
		req.FromVersion = version
	default:
		return nil, fmt.Errorf("--from must be running or version")
	}
	return req, nil
}

type approvalCreateOptions struct {
	candidateRevision string
	comment           string
	ackRisk           bool
	ackRuntime        bool
	outJSON           bool
}

type approvalListOptions struct {
	candidateRevision string
	includeConsumed   bool
	limit             uint32
	outJSON           bool
}

func newPolicyApprovalsCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "approvals",
		Aliases: []string{"approval", "change-approvals", "change-approval"},
		Short:   "Create and list server-side change approvals",
		Long: "Create and list server-side change approvals bound to the candidate revision. " +
			"A commit consumes one unconsumed approval via 'ngfwctl commit --approval-id <id>'.",
	}
	cmd.AddCommand(
		newPolicyApprovalCreateCommand(server),
		newPolicyApprovalListCommand(server),
	)
	return cmd
}

func newPolicyApprovalCreateCommand(server *string) *cobra.Command {
	opts := approvalCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a change approval for the current candidate revision",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runPolicyApprovalCreate(ctx, cmd, openngfwv1.NewPolicyServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVarP(&opts.comment, "message", "m", "", "required approval rationale")
	cmd.Flags().StringVar(&opts.candidateRevision, "candidate-revision", "", "candidate revision to approve (defaults to current candidate status)")
	cmd.Flags().BoolVar(&opts.ackRisk, "ack-risk", false, "record that the approver reviewed high-risk impact")
	cmd.Flags().BoolVar(&opts.ackRuntime, "ack-runtime", false, "record that the approver reviewed runtime readiness warnings")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newPolicyApprovalListCommand(server *string) *cobra.Command {
	opts := approvalListOptions{limit: 100}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List change approvals",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runPolicyApprovalList(ctx, cmd, openngfwv1.NewPolicyServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.candidateRevision, "candidate-revision", "", "filter approvals by candidate revision")
	cmd.Flags().BoolVar(&opts.includeConsumed, "include-consumed", false, "include approvals already consumed by commit")
	cmd.Flags().Uint32Var(&opts.limit, "limit", opts.limit, "maximum approvals to return")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func runPolicyApprovalCreate(ctx context.Context, cmd *cobra.Command, client policyApprovalsClient, opts approvalCreateOptions) error {
	req, err := approvalCreateRequest(ctx, client, opts)
	if err != nil {
		return err
	}
	resp, err := client.CreateChangeApproval(ctx, req)
	if err != nil {
		return fmt.Errorf("create change approval: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printChangeApprovalCreated(cmd, resp.GetApproval())
	return nil
}

func approvalCreateRequest(ctx context.Context, client policyApprovalsClient, opts approvalCreateOptions) (*openngfwv1.CreateChangeApprovalRequest, error) {
	comment := strings.TrimSpace(opts.comment)
	if comment == "" {
		return nil, fmt.Errorf("approval comment is required; pass --message/-m with the reason for this approval")
	}
	revision := strings.TrimSpace(opts.candidateRevision)
	if revision == "" {
		statusResp, err := client.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
		if err != nil {
			return nil, fmt.Errorf("get candidate status: %w", err)
		}
		if !statusResp.GetHasCandidate() {
			return nil, fmt.Errorf("no candidate policy is set; stage one before creating an approval")
		}
		revision = strings.TrimSpace(statusResp.GetCandidateRevision())
	}
	if revision == "" {
		return nil, fmt.Errorf("candidate revision is required; reload candidate status and retry")
	}
	return &openngfwv1.CreateChangeApprovalRequest{
		CandidateRevision: revision,
		Comment:           comment,
		AckRisk:           opts.ackRisk,
		AckRuntime:        opts.ackRuntime,
	}, nil
}

func runPolicyApprovalList(ctx context.Context, cmd *cobra.Command, client policyApprovalsClient, opts approvalListOptions) error {
	resp, err := client.ListChangeApprovals(ctx, &openngfwv1.ListChangeApprovalsRequest{
		CandidateRevision: strings.TrimSpace(opts.candidateRevision),
		IncludeConsumed:   opts.includeConsumed,
		Limit:             opts.limit,
	})
	if err != nil {
		return fmt.Errorf("list change approvals: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printChangeApprovals(cmd, resp.GetApprovals())
	return nil
}

func printChangeApprovalCreated(cmd *cobra.Command, approval *openngfwv1.ChangeApproval) {
	if approval == nil {
		cmd.Println("change approval created")
		return
	}
	cmd.Printf("change approval %s created for candidate %s\n", valueOrDash(approval.GetId()), valueOrDash(approval.GetCandidateRevision()))
	cmd.Printf("commit with: ngfwctl commit --approval-id %s --message <reason>\n", valueOrDash(approval.GetId()))
}

func printChangeApprovals(cmd *cobra.Command, approvals []*openngfwv1.ChangeApproval) {
	if len(approvals) == 0 {
		cmd.Println("no change approvals found")
		return
	}
	cmd.Printf("%-8s %-19s %-18s %-9s %-9s %-10s %s\n", "ID", "CREATED", "ACTOR", "RISK-ACK", "RUN-ACK", "STATE", "COMMENT")
	for _, approval := range approvals {
		cmd.Printf("%-8s %-19s %-18s %-9s %-9s %-10s %s\n",
			valueOrDash(approval.GetId()),
			approvalTimeLabel(approval.GetCreatedAt()),
			actorWithRole(approval.GetActor(), approval.GetActorRole()),
			yesNo(approval.GetAckRisk()),
			yesNo(approval.GetAckRuntime()),
			approvalStateLabel(approval),
			approval.GetComment())
		cmd.Printf("         candidate: %s\n", valueOrDash(approval.GetCandidateRevision()))
		if approval.GetConsumed() {
			cmd.Printf("         consumed:  version %d by %s at %s\n",
				approval.GetConsumedVersion(),
				actorWithRole(approval.GetConsumedBy(), approval.GetConsumedByRole()),
				approvalTimeLabel(approval.GetConsumedAt()))
		}
	}
}

func approvalStateLabel(approval *openngfwv1.ChangeApproval) string {
	if approval != nil && approval.GetConsumed() {
		return "consumed"
	}
	return "active"
}

func approvalTimeLabel(ts interface{ AsTime() time.Time }) string {
	if ts == nil {
		return "-"
	}
	t := ts.AsTime()
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

type policyReferencesClient interface {
	ListObjectReferences(context.Context, *openngfwv1.ListObjectReferencesRequest, ...grpc.CallOption) (*openngfwv1.ListObjectReferencesResponse, error)
}

type policyRenameObjectClient interface {
	RenamePolicyObject(context.Context, *openngfwv1.RenamePolicyObjectRequest, ...grpc.CallOption) (*openngfwv1.RenamePolicyObjectResponse, error)
}

type policyReferenceOptions struct {
	source  string
	version uint64
	kind    string
	name    string
	outJSON bool
}

func newPolicyReferencesCommand(server *string) *cobra.Command {
	opts := policyReferenceOptions{source: "running"}
	cmd := &cobra.Command{
		Use:     "references --kind KIND [--name OBJECT]",
		Aliases: []string{"refs"},
		Short:   "Show where reusable policy objects are referenced",
		Long: `Show reverse references for zones, addresses, services, applications,
security profiles, QoS profiles, or zone-protection profiles in a running,
candidate, or historical policy snapshot.

Use this before editing, deleting, or renaming shared objects so the blast
radius is visible from the CLI as well as the Objects workbench.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runPolicyReferences(ctx, cmd, openngfwv1.NewPolicyServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.source, "source", opts.source, "running | candidate | version")
	cmd.Flags().Uint64Var(&opts.version, "version", 0, "version id (with --source version)")
	cmd.Flags().StringVar(&opts.kind, "kind", "", "object kind: zone | address | service | application | security-profile | qos-profile | zone-protection-profile")
	cmd.Flags().StringVar(&opts.name, "name", "", "optional object name to inspect")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("kind")
	return cmd
}

type policyRenameObjectOptions struct {
	kind    string
	oldName string
	newName string
	comment string
	outJSON bool
}

func newPolicyRenameObjectCommand(server *string) *cobra.Command {
	opts := policyRenameObjectOptions{}
	cmd := &cobra.Command{
		Use:   "rename-object --kind KIND --old-name OLD --new-name NEW",
		Short: "Rename a reusable policy object in the candidate",
		Long: "Rename one reusable zone, address, service, application, security profile, QoS profile, or zone-protection profile in the candidate policy, " +
			"rewriting candidate references to the new name. Running policy is not changed until the candidate is validated and committed.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runPolicyRenameObject(ctx, cmd, openngfwv1.NewPolicyServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.kind, "kind", "", "object kind: zone | address | service | application | security-profile | qos-profile | zone-protection-profile")
	cmd.Flags().StringVar(&opts.oldName, "old-name", "", "existing candidate object name")
	cmd.Flags().StringVar(&opts.newName, "new-name", "", "replacement candidate object name")
	cmd.Flags().StringVar(&opts.comment, "comment", "", "optional audit reason for the candidate rename")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("old-name")
	_ = cmd.MarkFlagRequired("new-name")
	return cmd
}

func runPolicyReferences(ctx context.Context, cmd *cobra.Command, client policyReferencesClient, opts policyReferenceOptions) error {
	req, label, err := policyReferencesRequest(opts)
	if err != nil {
		return err
	}
	resp, err := client.ListObjectReferences(ctx, req)
	if err != nil {
		return fmt.Errorf("list object references: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPolicyReferences(cmd, label, req.GetKind(), req.GetName(), resp)
	return nil
}

func runPolicyRenameObject(ctx context.Context, cmd *cobra.Command, client policyRenameObjectClient, opts policyRenameObjectOptions) error {
	req, err := policyRenameObjectRequest(opts)
	if err != nil {
		return err
	}
	resp, err := client.RenamePolicyObject(ctx, req)
	if err != nil {
		return fmt.Errorf("rename policy object: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPolicyRenameObject(cmd, resp)
	return nil
}

func policyReferencesRequest(opts policyReferenceOptions) (*openngfwv1.ListObjectReferencesRequest, string, error) {
	kind, err := parsePolicyObjectKind(opts.kind)
	if err != nil {
		return nil, "", err
	}
	source, label, err := parseReferencePolicySource(opts.source, opts.version)
	if err != nil {
		return nil, "", err
	}
	return &openngfwv1.ListObjectReferencesRequest{
		Source:  source,
		Version: opts.version,
		Kind:    kind,
		Name:    strings.TrimSpace(opts.name),
	}, label, nil
}

func policyRenameObjectRequest(opts policyRenameObjectOptions) (*openngfwv1.RenamePolicyObjectRequest, error) {
	kind, err := parsePolicyObjectKind(opts.kind)
	if err != nil {
		return nil, err
	}
	oldName := strings.TrimSpace(opts.oldName)
	if oldName == "" {
		return nil, fmt.Errorf("--old-name is required")
	}
	newName := strings.TrimSpace(opts.newName)
	if newName == "" {
		return nil, fmt.Errorf("--new-name is required")
	}
	if oldName == newName {
		return nil, fmt.Errorf("--old-name and --new-name must be different")
	}
	return &openngfwv1.RenamePolicyObjectRequest{
		Kind:    kind,
		OldName: oldName,
		NewName: newName,
		Comment: strings.TrimSpace(opts.comment),
	}, nil
}

func parseReferencePolicySource(raw string, version uint64) (openngfwv1.PolicySource, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "running":
		if version != 0 {
			return 0, "", fmt.Errorf("--version is only valid with --source version")
		}
		return openngfwv1.PolicySource_POLICY_SOURCE_RUNNING, "running policy", nil
	case "candidate":
		if version != 0 {
			return 0, "", fmt.Errorf("--version is only valid with --source version")
		}
		return openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE, "candidate policy", nil
	case "version":
		if version == 0 {
			return 0, "", fmt.Errorf("--version is required when --source version")
		}
		return openngfwv1.PolicySource_POLICY_SOURCE_VERSION, fmt.Sprintf("version %d policy", version), nil
	default:
		return 0, "", fmt.Errorf("--source must be running, candidate, or version")
	}
}

func parsePolicyObjectKind(raw string) (openngfwv1.PolicyObjectKind, error) {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.ReplaceAll(key, "_", "-")
	switch key {
	case "zone", "zones":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE, nil
	case "address", "addresses":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS, nil
	case "service", "services":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE, nil
	case "application", "applications", "app", "apps":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION, nil
	case "security-profile", "security-profiles", "profile", "profiles", "securityprofile", "securityprofiles":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE, nil
	case "qos", "qos-profile", "qos-profiles", "qosprofile", "qosprofiles":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE, nil
	case "zone-protection", "zone-protections", "zone-protection-profile", "zone-protection-profiles", "zoneprotection", "zoneprotections", "zoneprotectionprofile", "zoneprotectionprofiles":
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE, nil
	default:
		return openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_UNSPECIFIED,
			fmt.Errorf("--kind must be one of zone, address, service, application, security-profile, qos-profile, or zone-protection-profile")
	}
}

func printPolicyReferences(cmd *cobra.Command, sourceLabel string, kind openngfwv1.PolicyObjectKind, name string, resp *openngfwv1.ListObjectReferencesResponse) {
	refs := resp.GetReferences()
	if len(refs) == 0 {
		target := policyObjectKindLabel(kind)
		if strings.TrimSpace(name) != "" {
			target += " " + strings.TrimSpace(name)
		}
		cmd.Printf("no references found for %s in %s\n", target, sourceLabel)
		return
	}
	versionLabel := sourceLabel
	if resp.GetVersion() != 0 && !strings.Contains(sourceLabel, fmt.Sprintf("%d", resp.GetVersion())) {
		versionLabel = fmt.Sprintf("%s v%d", sourceLabel, resp.GetVersion())
	}
	cmd.Printf("object references from %s\n", versionLabel)
	cmd.Printf("%-22s %-18s %-24s %-26s %-22s %s\n", "OBJECT", "AREA", "ITEM", "ITEM ID", "FIELD", "DETAIL")
	for _, ref := range refs {
		cmd.Printf("%-22s %-18s %-24s %-26s %-22s %s\n",
			displayEmpty(ref.GetObjectName()),
			displayEmpty(ref.GetArea()),
			displayEmpty(ref.GetItem()),
			displayEmpty(ref.GetItemId()),
			displayEmpty(ref.GetField()),
			displayEmpty(ref.GetDetail()))
	}
}

func printPolicyRenameObject(cmd *cobra.Command, resp *openngfwv1.RenamePolicyObjectResponse) {
	cmd.Printf("%s %q renamed to %q in candidate\n",
		policyObjectKindLabel(resp.GetKind()),
		resp.GetOldName(),
		resp.GetNewName())
	cmd.Printf("rewritten references: %d\n", len(resp.GetRewrittenReferences()))
	if refs := resp.GetRewrittenReferences(); len(refs) > 0 {
		cmd.Printf("%-18s %-24s %-26s %-22s %s\n", "AREA", "ITEM", "ITEM ID", "FIELD", "DETAIL")
		for _, ref := range refs {
			cmd.Printf("%-18s %-24s %-26s %-22s %s\n",
				displayEmpty(ref.GetArea()),
				displayEmpty(ref.GetItem()),
				displayEmpty(ref.GetItemId()),
				displayEmpty(ref.GetField()),
				displayEmpty(ref.GetDetail()))
		}
	}
	if status := resp.GetCandidateStatus(); status != nil {
		cmd.Println()
		printPolicyStatus(cmd, status)
	}
	cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' to apply")
}

func policyObjectKindLabel(kind openngfwv1.PolicyObjectKind) string {
	switch kind {
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
		return "zone"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
		return "address"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
		return "service"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION:
		return "application"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE:
		return "security profile"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE:
		return "QoS profile"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE:
		return "zone-protection profile"
	default:
		return "object"
	}
}

func policyDiffBase(ctx context.Context, client policyClient, source string, version uint64) (*openngfwv1.Policy, string, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "running":
		resp, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return &openngfwv1.Policy{}, "running policy v0", nil
			}
			return nil, "", fmt.Errorf("read running policy: %w", err)
		}
		return clonePolicy(resp.GetPolicy()), fmt.Sprintf("running policy v%d", resp.GetVersion()), nil
	case "version":
		if version == 0 {
			return nil, "", fmt.Errorf("--version is required when --from version")
		}
		resp, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_VERSION, Version: version})
		if err != nil {
			return nil, "", fmt.Errorf("read version %d: %w", version, err)
		}
		return clonePolicy(resp.GetPolicy()), fmt.Sprintf("version %d", version), nil
	default:
		return nil, "", fmt.Errorf("--from must be running or version")
	}
}

func policyDiffLines(fromLabel, toLabel string, from, to *openngfwv1.Policy) ([]string, bool, error) {
	lines, changed, err := policydiff.Lines(from, to)
	if err != nil {
		return nil, false, fmt.Errorf("marshal policy diff: %w", err)
	}
	if !changed {
		return nil, false, nil
	}
	return policydiff.TextLines(fromLabel, toLabel, lines), true, nil
}

type baselineOptions struct {
	insideZone        string
	outsideZone       string
	insideInterfaces  []string
	outsideInterfaces []string
	insideCIDR        string
	insideAddressName string
	profile           string
	inspectionMode    string
	webuiPort         uint32
	mtu               uint32
	allowOutbound     bool
	masquerade        bool
	hardenHostInput   bool
	flowOffload       bool
	clampMSS          bool
	manageNICOffload  bool
	idsMonitorIfaces  []string
	idsHomeNetworks   []string
	idsRuleFiles      []string
	idsQueueNum       uint32
	idsFailure        string
}

type baselineSummary struct {
	profile   string
	zones     []string
	addresses []string
	services  []string
	rules     []string
	nat       []string
	hostInput []string
	network   []string
	ids       []string
}

const (
	baselineProfileThroughput = "throughput"
	baselineProfileIDSDetect  = "ids-detect"
	baselineProfileIPSPrevent = "ips-prevent"

	baselineInspectionOff     = "off"
	baselineInspectionDetect  = "detect"
	baselineInspectionPrevent = "prevent"

	baselineFailureOpen   = "fail-open"
	baselineFailureClosed = "fail-closed"
	baselineDefaultRule   = "local.rules"
)

func newPolicyBaselineCommand(server *string) *cobra.Command {
	opts := baselineOptions{
		insideZone:        "lan",
		outsideZone:       "wan",
		insideInterfaces:  []string{"eth1"},
		outsideInterfaces: []string{"eth0"},
		insideCIDR:        "10.0.0.0/24",
		profile:           baselineProfileThroughput,
		webuiPort:         8080,
		allowOutbound:     true,
		masquerade:        true,
		hardenHostInput:   true,
		flowOffload:       true,
		clampMSS:          true,
		idsRuleFiles:      []string{baselineDefaultRule},
		idsFailure:        baselineFailureClosed,
	}
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Stage a two-zone first-run firewall baseline as the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			pol, source, err := editablePolicy(ctx, client)
			if err != nil {
				return err
			}
			summary, err := applyBaselinePolicy(pol, opts)
			if err != nil {
				return err
			}
			if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			cmd.Printf("baseline policy staged from %s policy\n", source)
			printBaselineSummary(cmd, summary)
			cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.insideZone, "inside-zone", opts.insideZone, "trusted/inside zone name")
	cmd.Flags().StringVar(&opts.outsideZone, "outside-zone", opts.outsideZone, "untrusted/outside zone name")
	cmd.Flags().StringSliceVar(&opts.insideInterfaces, "inside-interface", opts.insideInterfaces, "inside interface name; repeat or comma-separate")
	cmd.Flags().StringSliceVar(&opts.outsideInterfaces, "outside-interface", opts.outsideInterfaces, "outside interface name; repeat or comma-separate")
	cmd.Flags().StringVar(&opts.insideCIDR, "inside-cidr", opts.insideCIDR, "inside network CIDR used by baseline objects")
	cmd.Flags().StringVar(&opts.insideAddressName, "inside-address-name", "", "address object name for --inside-cidr (default: <inside-zone>-net)")
	cmd.Flags().StringVar(&opts.profile, "profile", opts.profile, "baseline posture: throughput | ids-detect | ips-prevent")
	cmd.Flags().Uint32Var(&opts.webuiPort, "webui-port", opts.webuiPort, "WebUI/API management port for host-input allow")
	cmd.Flags().Uint32Var(&opts.mtu, "mtu", 0, "optional global MTU; 0 leaves MTUs unmanaged")
	cmd.Flags().BoolVar(&opts.allowOutbound, "allow-outbound", opts.allowOutbound, "stage a logged inside-to-outside allow rule")
	cmd.Flags().BoolVar(&opts.masquerade, "masquerade", opts.masquerade, "stage source NAT masquerade for inside clients")
	cmd.Flags().BoolVar(&opts.hardenHostInput, "harden-host-input", opts.hardenHostInput, "stage host-input default deny with inside management allow")
	cmd.Flags().BoolVar(&opts.flowOffload, "flow-offload", opts.flowOffload, "enable nftables flowtable fast path for forwarding profiles")
	cmd.Flags().BoolVar(&opts.clampMSS, "clamp-mss", opts.clampMSS, "enable TCP MSS clamping to path MTU")
	cmd.Flags().BoolVar(&opts.manageNICOffload, "manage-nic-offloads", opts.manageNICOffload, "enable IDS NIC offload management")
	cmd.Flags().StringSliceVar(&opts.idsMonitorIfaces, "ids-monitor-interface", nil, "IDS/IPS monitor interface; repeat or comma-separate (default: inside and outside interfaces)")
	cmd.Flags().StringSliceVar(&opts.idsHomeNetworks, "ids-home-network", nil, "IDS/IPS HOME_NET CIDR; repeat or comma-separate (default: --inside-cidr)")
	cmd.Flags().StringSliceVar(&opts.idsRuleFiles, "ids-rule-file", opts.idsRuleFiles, "IDS/IPS rule file under the managed rules directory; repeat or comma-separate")
	cmd.Flags().Uint32Var(&opts.idsQueueNum, "ids-queue", 0, "NFQUEUE number for --profile ips-prevent")
	cmd.Flags().StringVar(&opts.idsFailure, "ids-failure-behavior", opts.idsFailure, "IPS failure behavior: fail-closed | fail-open")
	return cmd
}

func applyBaselinePolicy(policy *openngfwv1.Policy, raw baselineOptions) (baselineSummary, error) {
	opts, err := normalizeBaselineOptions(raw)
	if err != nil {
		return baselineSummary{}, err
	}
	summary := baselineSummary{profile: opts.profile}

	insideZone := upsertZone(policy, &openngfwv1.Zone{
		Name:        opts.insideZone,
		Interfaces:  opts.insideInterfaces,
		Description: "Inside/trusted forwarding zone created by baseline setup.",
	})
	outsideZone := upsertZone(policy, &openngfwv1.Zone{
		Name:        opts.outsideZone,
		Interfaces:  opts.outsideInterfaces,
		Description: "Outside/untrusted forwarding zone created by baseline setup.",
	})
	summary.zones = append(summary.zones, insideZone, outsideZone)

	insideNet := ensureAddress(policy, opts.insideAddressName, opts.insideCIDR, "Inside network created by baseline setup.")
	summary.addresses = append(summary.addresses, insideNet)

	ssh := ensureService(policy, "ssh", openngfwv1.Protocol_PROTOCOL_TCP, []*openngfwv1.PortRange{{Start: 22}}, "SSH management service created by baseline setup.")
	webui := ensureService(policy, "webui", openngfwv1.Protocol_PROTOCOL_TCP, []*openngfwv1.PortRange{{Start: opts.webuiPort}}, "OpenNGFW WebUI/API management service created by baseline setup.")
	summary.services = append(summary.services, ssh, webui)

	if opts.allowOutbound {
		name := "allow-" + insideZone + "-to-" + outsideZone
		upsertRule(policy, &openngfwv1.Rule{
			Name:                 name,
			FromZones:            []string{insideZone},
			ToZones:              []string{outsideZone},
			SourceAddresses:      []string{insideNet},
			DestinationAddresses: []string{"any"},
			Services:             []string{"any"},
			Action:               openngfwv1.Action_ACTION_ALLOW,
			Log:                  true,
			Description:          "Baseline outbound rule. Review scope before committing in production.",
		})
		summary.rules = append(summary.rules, name)
	}

	if opts.masquerade {
		name := insideZone + "-masq"
		upsertSourceNat(policy, &openngfwv1.SourceNat{
			Name:          name,
			ToZone:        outsideZone,
			SourceAddress: insideNet,
			Masquerade:    true,
		})
		summary.nat = append(summary.nat, name)
	}

	if opts.hardenHostInput {
		ruleName := "allow-" + insideZone + "-management"
		if policy.HostInput == nil {
			policy.HostInput = &openngfwv1.HostInput{}
		}
		policy.HostInput.DefaultAction = openngfwv1.Action_ACTION_DENY
		upsertHostInputRule(policy.HostInput, &openngfwv1.HostInputRule{
			Name:            ruleName,
			FromZones:       []string{insideZone},
			SourceAddresses: []string{insideNet},
			Services:        []string{ssh, webui},
			Action:          openngfwv1.Action_ACTION_ALLOW,
			Log:             true,
			Description:     "Baseline management access. Restrict the source object before exposing the appliance.",
		})
		summary.hostInput = append(summary.hostInput, "default deny", ruleName)
	}

	if opts.clampMSS || opts.manageNICOffload || opts.flowOffload || opts.mtu > 0 || opts.inspectionMode != baselineInspectionOff {
		if policy.Network == nil {
			policy.Network = &openngfwv1.Network{}
		}
		if opts.clampMSS {
			policy.Network.ClampMssToPmtu = true
			summary.network = append(summary.network, "MSS clamp")
		}
		if opts.manageNICOffload {
			policy.Network.ManageNicOffloads = true
			summary.network = append(summary.network, "IDS NIC offload management")
		} else if opts.inspectionMode != baselineInspectionDetect {
			policy.Network.ManageNicOffloads = false
		}
		if opts.flowOffload {
			policy.Network.EnableFlowOffload = true
			summary.network = append(summary.network, "flowtable fast path")
		} else {
			policy.Network.EnableFlowOffload = false
			if opts.inspectionMode != baselineInspectionOff {
				summary.network = append(summary.network, "flowtable fast path disabled")
			}
		}
		if opts.mtu > 0 {
			policy.Network.Mtu = opts.mtu
			summary.network = append(summary.network, "MTU "+strconv.FormatUint(uint64(opts.mtu), 10))
		}
	}
	applyBaselineInspection(policy, opts, &summary)

	return summary, nil
}

func normalizeBaselineOptions(raw baselineOptions) (baselineOptions, error) {
	out := raw
	out.profile = strings.ToLower(strings.TrimSpace(firstNonEmptyString(raw.profile, baselineProfileThroughput)))
	switch out.profile {
	case baselineProfileThroughput:
		out.inspectionMode = baselineInspectionOff
	case baselineProfileIDSDetect:
		out.inspectionMode = baselineInspectionDetect
		out.flowOffload = false
		out.manageNICOffload = true
	case baselineProfileIPSPrevent:
		out.inspectionMode = baselineInspectionPrevent
		out.flowOffload = false
		out.manageNICOffload = false
	default:
		return baselineOptions{}, fmt.Errorf("--profile %q is invalid: valid profiles are %s, %s, %s", raw.profile, baselineProfileThroughput, baselineProfileIDSDetect, baselineProfileIPSPrevent)
	}
	out.insideZone = sanitizePolicyName(firstNonEmptyString(raw.insideZone, "lan"))
	out.outsideZone = sanitizePolicyName(firstNonEmptyString(raw.outsideZone, "wan"))
	if out.insideZone == out.outsideZone {
		return baselineOptions{}, fmt.Errorf("--inside-zone and --outside-zone must be distinct")
	}
	out.insideInterfaces = cleanStringList(raw.insideInterfaces)
	if len(out.insideInterfaces) == 0 {
		return baselineOptions{}, fmt.Errorf("--inside-interface is required")
	}
	out.outsideInterfaces = cleanStringList(raw.outsideInterfaces)
	if len(out.outsideInterfaces) == 0 {
		return baselineOptions{}, fmt.Errorf("--outside-interface is required")
	}
	out.insideCIDR = strings.TrimSpace(firstNonEmptyString(raw.insideCIDR, "10.0.0.0/24"))
	if _, err := netip.ParsePrefix(out.insideCIDR); err != nil {
		return baselineOptions{}, fmt.Errorf("--inside-cidr %q is invalid: %w", raw.insideCIDR, err)
	}
	out.insideAddressName = sanitizePolicyName(raw.insideAddressName)
	if out.insideAddressName == "object" && strings.TrimSpace(raw.insideAddressName) == "" {
		out.insideAddressName = out.insideZone + "-net"
	}
	if raw.webuiPort == 0 || raw.webuiPort > 65535 {
		return baselineOptions{}, fmt.Errorf("--webui-port must be 1-65535")
	}
	if raw.mtu != 0 && (raw.mtu < networkMinMTU || raw.mtu > networkMaxMTU) {
		return baselineOptions{}, fmt.Errorf("--mtu must be 0 or %d-%d", networkMinMTU, networkMaxMTU)
	}
	out.idsQueueNum = raw.idsQueueNum
	if out.idsQueueNum > 65535 {
		return baselineOptions{}, fmt.Errorf("--ids-queue must be 0-65535")
	}
	out.idsMonitorIfaces = cleanStringList(raw.idsMonitorIfaces)
	if len(out.idsMonitorIfaces) == 0 && out.inspectionMode != baselineInspectionOff {
		out.idsMonitorIfaces = unionStrings(out.insideInterfaces, out.outsideInterfaces)
	}
	out.idsHomeNetworks = cleanStringList(raw.idsHomeNetworks)
	if len(out.idsHomeNetworks) == 0 && out.inspectionMode != baselineInspectionOff {
		out.idsHomeNetworks = []string{out.insideCIDR}
	}
	for _, cidr := range out.idsHomeNetworks {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return baselineOptions{}, fmt.Errorf("--ids-home-network %q is invalid: %w", cidr, err)
		}
	}
	out.idsRuleFiles = cleanStringList(raw.idsRuleFiles)
	if len(out.idsRuleFiles) == 0 && out.inspectionMode != baselineInspectionOff {
		out.idsRuleFiles = []string{baselineDefaultRule}
	}
	for _, ruleFile := range out.idsRuleFiles {
		if ruleFile == "" || strings.Contains(ruleFile, "..") || strings.HasPrefix(ruleFile, "/") {
			return baselineOptions{}, fmt.Errorf("--ids-rule-file %q must be a relative path inside the rules directory", ruleFile)
		}
	}
	out.idsFailure = strings.ToLower(strings.TrimSpace(firstNonEmptyString(raw.idsFailure, baselineFailureClosed)))
	if out.inspectionMode == baselineInspectionPrevent {
		switch out.idsFailure {
		case baselineFailureOpen, baselineFailureClosed:
		default:
			return baselineOptions{}, fmt.Errorf("--ids-failure-behavior must be %s or %s", baselineFailureClosed, baselineFailureOpen)
		}
	} else {
		out.idsFailure = ""
	}
	return out, nil
}

func applyBaselineInspection(policy *openngfwv1.Policy, opts baselineOptions, summary *baselineSummary) {
	if policy.Ids == nil {
		policy.Ids = &openngfwv1.Ids{}
	}
	switch opts.inspectionMode {
	case baselineInspectionDetect:
		policy.Ids.Enabled = true
		policy.Ids.Mode = openngfwv1.IdsMode_IDS_MODE_DETECT
		policy.Ids.MonitorInterfaces = append([]string{}, opts.idsMonitorIfaces...)
		policy.Ids.HomeNetworks = append([]string{}, opts.idsHomeNetworks...)
		policy.Ids.RuleFiles = append([]string{}, opts.idsRuleFiles...)
		policy.Ids.QueueNum = opts.idsQueueNum
		policy.Ids.FailureBehavior = openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED
		summary.ids = append(summary.ids, "IDS detect")
	case baselineInspectionPrevent:
		policy.Ids.Enabled = true
		policy.Ids.Mode = openngfwv1.IdsMode_IDS_MODE_PREVENT
		policy.Ids.MonitorInterfaces = append([]string{}, opts.idsMonitorIfaces...)
		policy.Ids.HomeNetworks = append([]string{}, opts.idsHomeNetworks...)
		policy.Ids.RuleFiles = append([]string{}, opts.idsRuleFiles...)
		policy.Ids.QueueNum = opts.idsQueueNum
		policy.Ids.FailureBehavior = baselineFailureBehavior(opts.idsFailure)
		if opts.idsFailure == baselineFailureOpen {
			summary.ids = append(summary.ids, "IPS prevent fail-open")
		} else {
			summary.ids = append(summary.ids, "IPS prevent fail-closed")
		}
	default:
		policy.Ids.Enabled = false
		policy.Ids.FailureBehavior = openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED
		summary.ids = append(summary.ids, "IDS/IPS disabled")
	}
}

func baselineFailureBehavior(value string) openngfwv1.IdsFailureBehavior {
	if value == baselineFailureOpen {
		return openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN
	}
	return openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED
}

func upsertZone(policy *openngfwv1.Policy, zone *openngfwv1.Zone) string {
	for _, existing := range policy.GetZones() {
		if existing.GetName() == zone.GetName() {
			existing.Interfaces = unionStrings(existing.GetInterfaces(), zone.GetInterfaces())
			if existing.GetDescription() == "" {
				existing.Description = zone.GetDescription()
			}
			return existing.GetName()
		}
	}
	policy.Zones = append(policy.Zones, zone)
	return zone.GetName()
}

func ensureAddress(policy *openngfwv1.Policy, desiredName, cidr, description string) string {
	for _, existing := range policy.GetAddresses() {
		if existing.GetCidr() == cidr {
			return existing.GetName()
		}
	}
	name := uniquePolicyName(policy.GetAddresses(), desiredName, func(a *openngfwv1.Address) string { return a.GetName() })
	policy.Addresses = append(policy.Addresses, &openngfwv1.Address{Name: name, Cidr: cidr, Description: description})
	return name
}

func ensureService(policy *openngfwv1.Policy, desiredName string, protocol openngfwv1.Protocol, ports []*openngfwv1.PortRange, description string) string {
	for _, existing := range policy.GetServices() {
		if existing.GetProtocol() == protocol && samePortRanges(existing.GetPorts(), ports) {
			return existing.GetName()
		}
	}
	name := uniquePolicyName(policy.GetServices(), desiredName, func(s *openngfwv1.Service) string { return s.GetName() })
	policy.Services = append(policy.Services, &openngfwv1.Service{Name: name, Protocol: protocol, Ports: ports, Description: description})
	return name
}

func upsertRule(policy *openngfwv1.Policy, rule *openngfwv1.Rule) {
	for i, existing := range policy.GetRules() {
		if existing.GetName() == rule.GetName() {
			policy.Rules[i] = rule
			return
		}
	}
	policy.Rules = append(policy.Rules, rule)
}

func upsertSourceNat(policy *openngfwv1.Policy, item *openngfwv1.SourceNat) {
	if policy.Nat == nil {
		policy.Nat = &openngfwv1.Nat{}
	}
	for i, existing := range policy.Nat.GetSource() {
		if existing.GetName() == item.GetName() {
			policy.Nat.Source[i] = item
			return
		}
	}
	policy.Nat.Source = append(policy.Nat.Source, item)
}

func upsertHostInputRule(host *openngfwv1.HostInput, rule *openngfwv1.HostInputRule) {
	for i, existing := range host.GetRules() {
		if existing.GetName() == rule.GetName() {
			host.Rules[i] = rule
			return
		}
	}
	host.Rules = append(host.Rules, rule)
}

func printBaselineSummary(cmd *cobra.Command, summary baselineSummary) {
	if summary.profile != "" {
		cmd.Printf("- profile: %s\n", summary.profile)
	}
	for _, item := range []struct {
		label string
		items []string
	}{
		{"zones", summary.zones},
		{"addresses", summary.addresses},
		{"services", summary.services},
		{"rules", summary.rules},
		{"nat", summary.nat},
		{"host input", summary.hostInput},
		{"network", summary.network},
		{"ids/ips", summary.ids},
	} {
		if len(item.items) == 0 {
			continue
		}
		cmd.Printf("- %s: %s\n", item.label, strings.Join(item.items, ", "))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func cleanStringList(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func sanitizePolicyName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = r == '-'
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		out = "object"
	}
	if !asciiAlphaNum(out[0]) {
		out = "o-" + out
	}
	if len(out) > 63 {
		out = out[:63]
		out = strings.TrimRight(out, "-_")
	}
	if out == "" {
		out = "object"
	}
	if !asciiAlphaNum(out[len(out)-1]) {
		out += "1"
	}
	return out
}

func asciiAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func unionStrings(existing, extra []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range append(append([]string{}, existing...), extra...) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniquePolicyName[T any](items []T, desired string, nameOf func(T) string) string {
	base := sanitizePolicyName(desired)
	names := map[string]bool{}
	for _, item := range items {
		names[nameOf(item)] = true
	}
	if !names[base] {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !names[candidate] {
			return candidate
		}
	}
}

func samePortRanges(a, b []*openngfwv1.PortRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetStart() != b[i].GetStart() || a[i].GetEnd() != b[i].GetEnd() {
			return false
		}
	}
	return true
}

type networkSetOptions struct {
	flowOffload        string
	clampMSS           string
	manageNICOffload   string
	mtu                uint32
	interfaceMTUs      []string
	clearInterfaceMTUs bool
}

const (
	networkMinMTU = 1280
	networkMaxMTU = 9600
)

func newPolicyNetworkCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Stage global dataplane/network settings",
	}
	cmd.AddCommand(
		newPolicyNetworkSetCommand(server),
		newPolicyNetworkProfileCommand(server),
	)
	return cmd
}

func newPolicyNetworkSetCommand(server *string) *cobra.Command {
	opts := networkSetOptions{
		flowOffload:      "keep",
		clampMSS:         "keep",
		manageNICOffload: "keep",
	}
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Stage global MTU, MSS, NIC offload, and flowtable settings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !networkSetChanged(cmd) {
				return fmt.Errorf("set at least one network setting flag")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			pol, source, err := editablePolicy(ctx, client)
			if err != nil {
				return err
			}
			summary, err := applyNetworkSetFlags(pol, opts, cmd)
			if err != nil {
				return err
			}
			if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			cmd.Printf("network settings staged from %s policy\n", source)
			for _, line := range summary {
				cmd.Println("- " + line)
			}
			cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.flowOffload, "flow-offload", "keep", "flowtable fast path: on | off | keep")
	cmd.Flags().StringVar(&opts.clampMSS, "clamp-mss", "keep", "TCP MSS clamping: on | off | keep")
	cmd.Flags().StringVar(&opts.manageNICOffload, "manage-nic-offloads", "keep", "manage IDS NIC offloads: on | off | keep")
	cmd.Flags().Uint32Var(&opts.mtu, "mtu", 0, "global interface MTU; 0 leaves MTUs unmanaged")
	cmd.Flags().StringArrayVar(&opts.interfaceMTUs, "interface-mtu", nil, "per-interface MTU override IFACE=MTU; repeatable")
	cmd.Flags().BoolVar(&opts.clearInterfaceMTUs, "clear-interface-mtus", false, "remove all existing per-interface MTU overrides before applying --interface-mtu")
	return cmd
}

type networkProfile struct {
	name                  string
	title                 string
	detail                string
	requiresInspectionOff bool
	mtu                   uint32
	clampMSS              bool
	manageNICOffload      bool
	flowOffload           bool
}

var networkProfiles = []networkProfile{
	{
		name:                  "throughput",
		title:                 "Forwarding throughput",
		detail:                "jumbo MTU, TCP MSS clamp, and nftables flowtable for L3/L4 forwarding-only policies",
		requiresInspectionOff: true,
		mtu:                   9000,
		clampMSS:              true,
		flowOffload:           true,
	},
	{
		name:             "inspection",
		title:            "IDS/IPS inspected",
		detail:           "flowtable disabled and NIC offload management enabled so Suricata sees real packet frames",
		clampMSS:         true,
		manageNICOffload: true,
	},
	{
		name:     "edge-vpn",
		title:    "Internet / VPN edge",
		detail:   "standard MTU and TCP MSS clamp for tunnels, mixed peers, and conservative WAN paths",
		mtu:      1500,
		clampMSS: true,
	},
}

func newPolicyNetworkProfileCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile <throughput|inspection|edge-vpn>",
		Short: "Stage a known dataplane operating profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			pol, source, err := editablePolicy(ctx, client)
			if err != nil {
				return err
			}
			summary, err := applyNetworkProfile(pol, args[0])
			if err != nil {
				return err
			}
			if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			cmd.Printf("network profile %q staged from %s policy\n", strings.ToLower(strings.TrimSpace(args[0])), source)
			for _, line := range summary {
				cmd.Println("- " + line)
			}
			cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	return cmd
}

func networkSetChanged(cmd *cobra.Command) bool {
	for _, name := range []string{"flow-offload", "clamp-mss", "manage-nic-offloads", "mtu", "interface-mtu", "clear-interface-mtus"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func applyNetworkProfile(policy *openngfwv1.Policy, name string) ([]string, error) {
	profile, ok := findNetworkProfile(name)
	if !ok {
		return nil, fmt.Errorf("unknown network profile %q; valid profiles: %s", strings.TrimSpace(name), strings.Join(validNetworkProfileNames(), ", "))
	}
	if profile.requiresInspectionOff && policy.GetIds().GetEnabled() {
		return nil, fmt.Errorf("network profile %q requires IDS/IPS disabled; use profile \"inspection\" or disable IDS/IPS before staging throughput fast path", profile.name)
	}
	if policy.Network == nil {
		policy.Network = &openngfwv1.Network{}
	}
	policy.Network.Mtu = profile.mtu
	policy.Network.ClampMssToPmtu = profile.clampMSS
	policy.Network.ManageNicOffloads = profile.manageNICOffload
	policy.Network.EnableFlowOffload = profile.flowOffload

	return []string{
		profile.title + ": " + profile.detail,
		"global MTU " + strconv.FormatUint(uint64(profile.mtu), 10),
		"TCP MSS clamping " + onOff(profile.clampMSS),
		"IDS NIC offload management " + onOff(profile.manageNICOffload),
		"flowtable fast path " + onOff(profile.flowOffload),
		fmt.Sprintf("preserved %d per-interface MTU override(s)", len(policy.Network.GetInterfaceMtus())),
	}, nil
}

func findNetworkProfile(name string) (networkProfile, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, profile := range networkProfiles {
		if profile.name == normalized {
			return profile, true
		}
	}
	return networkProfile{}, false
}

func validNetworkProfileNames() []string {
	out := make([]string, 0, len(networkProfiles))
	for _, profile := range networkProfiles {
		out = append(out, profile.name)
	}
	sort.Strings(out)
	return out
}

type policyClient interface {
	GetPolicy(context.Context, *openngfwv1.GetPolicyRequest, ...grpc.CallOption) (*openngfwv1.GetPolicyResponse, error)
	SetCandidate(context.Context, *openngfwv1.SetCandidateRequest, ...grpc.CallOption) (*openngfwv1.SetCandidateResponse, error)
}

func editablePolicy(ctx context.Context, client policyClient) (*openngfwv1.Policy, string, error) {
	cand, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
	if err == nil {
		return clonePolicy(cand.GetPolicy()), "candidate", nil
	}
	if status.Code(err) != codes.NotFound {
		return nil, "", fmt.Errorf("read candidate policy: %w", err)
	}
	running, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return &openngfwv1.Policy{}, "empty", nil
		}
		return nil, "", fmt.Errorf("read running policy: %w", err)
	}
	return clonePolicy(running.GetPolicy()), "running", nil
}

func clonePolicy(p *openngfwv1.Policy) *openngfwv1.Policy {
	if p == nil {
		return &openngfwv1.Policy{}
	}
	return proto.Clone(p).(*openngfwv1.Policy)
}

func applyNetworkSetFlags(policy *openngfwv1.Policy, opts networkSetOptions, cmd *cobra.Command) ([]string, error) {
	if policy.Network == nil {
		policy.Network = &openngfwv1.Network{}
	}
	var summary []string
	if cmd.Flags().Changed("flow-offload") {
		value, err := parseOnOffKeep(opts.flowOffload)
		if err != nil {
			return nil, fmt.Errorf("--flow-offload: %w", err)
		}
		if value != nil {
			policy.Network.EnableFlowOffload = *value
			summary = append(summary, "flowtable fast path "+onOff(*value))
		}
	}
	if cmd.Flags().Changed("clamp-mss") {
		value, err := parseOnOffKeep(opts.clampMSS)
		if err != nil {
			return nil, fmt.Errorf("--clamp-mss: %w", err)
		}
		if value != nil {
			policy.Network.ClampMssToPmtu = *value
			summary = append(summary, "TCP MSS clamping "+onOff(*value))
		}
	}
	if cmd.Flags().Changed("manage-nic-offloads") {
		value, err := parseOnOffKeep(opts.manageNICOffload)
		if err != nil {
			return nil, fmt.Errorf("--manage-nic-offloads: %w", err)
		}
		if value != nil {
			policy.Network.ManageNicOffloads = *value
			summary = append(summary, "IDS NIC offload management "+onOff(*value))
		}
	}
	if cmd.Flags().Changed("mtu") {
		if opts.mtu != 0 && (opts.mtu < networkMinMTU || opts.mtu > networkMaxMTU) {
			return nil, fmt.Errorf("--mtu: MTU must be 0 or %d-%d", networkMinMTU, networkMaxMTU)
		}
		policy.Network.Mtu = opts.mtu
		summary = append(summary, "global MTU "+strconv.FormatUint(uint64(opts.mtu), 10))
	}
	if cmd.Flags().Changed("clear-interface-mtus") && opts.clearInterfaceMTUs {
		policy.Network.InterfaceMtus = nil
		summary = append(summary, "cleared per-interface MTU overrides")
	}
	if cmd.Flags().Changed("interface-mtu") {
		overrides, err := parseInterfaceMTUs(opts.interfaceMTUs)
		if err != nil {
			return nil, err
		}
		policy.Network.InterfaceMtus = mergeInterfaceMTUs(policy.Network.GetInterfaceMtus(), overrides)
		for _, item := range overrides {
			summary = append(summary, fmt.Sprintf("interface MTU %s=%d", item.GetInterface(), item.GetMtu()))
		}
	}
	if len(summary) == 0 {
		summary = append(summary, "no network settings changed")
	}
	return summary, nil
}

func parseInterfaceMTUs(values []string) ([]*openngfwv1.InterfaceMtu, error) {
	seen := map[string]bool{}
	var out []*openngfwv1.InterfaceMtu
	for _, raw := range values {
		name, mtuText, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok {
			return nil, fmt.Errorf("--interface-mtu %q: expected IFACE=MTU", raw)
		}
		name = strings.TrimSpace(name)
		mtuText = strings.TrimSpace(mtuText)
		if name == "" {
			return nil, fmt.Errorf("--interface-mtu %q: interface name is required", raw)
		}
		if seen[name] {
			return nil, fmt.Errorf("--interface-mtu %q: duplicate interface %q", raw, name)
		}
		seen[name] = true
		mtu, err := strconv.ParseUint(mtuText, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("--interface-mtu %q: MTU must be an integer", raw)
		}
		if mtu < networkMinMTU || mtu > networkMaxMTU {
			return nil, fmt.Errorf("--interface-mtu %q: MTU must be %d-%d", raw, networkMinMTU, networkMaxMTU)
		}
		out = append(out, &openngfwv1.InterfaceMtu{Interface: name, Mtu: uint32(mtu)})
	}
	return out, nil
}

func mergeInterfaceMTUs(existing, overrides []*openngfwv1.InterfaceMtu) []*openngfwv1.InterfaceMtu {
	byName := map[string]*openngfwv1.InterfaceMtu{}
	for _, item := range existing {
		if item.GetInterface() == "" {
			continue
		}
		byName[item.GetInterface()] = &openngfwv1.InterfaceMtu{Interface: item.GetInterface(), Mtu: item.GetMtu()}
	}
	for _, item := range overrides {
		byName[item.GetInterface()] = &openngfwv1.InterfaceMtu{Interface: item.GetInterface(), Mtu: item.GetMtu()}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*openngfwv1.InterfaceMtu, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out
}

func parseOnOffKeep(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "yes", "enabled", "enable":
		v := true
		return &v, nil
	case "off", "false", "no", "disabled", "disable":
		v := false
		return &v, nil
	case "keep", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("must be on, off, or keep")
	}
}

func onOff(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

type staticRouteOptions struct {
	destination string
	via         string
	iface       string
	metric      uint32
}

type staticRouteStageResult struct {
	source string
	action string
	route  *openngfwv1.StaticRoute
}

type staticRouteListResult struct {
	source string
	routes []*openngfwv1.StaticRoute
}

type policyNatClient interface {
	ListNatRules(context.Context, *openngfwv1.ListNatRulesRequest, ...grpc.CallOption) (*openngfwv1.ListNatRulesResponse, error)
	UpsertCandidateSourceNat(context.Context, *openngfwv1.UpsertCandidateSourceNatRequest, ...grpc.CallOption) (*openngfwv1.UpsertCandidateSourceNatResponse, error)
	DeleteCandidateSourceNat(context.Context, *openngfwv1.DeleteCandidateSourceNatRequest, ...grpc.CallOption) (*openngfwv1.DeleteCandidateSourceNatResponse, error)
	UpsertCandidateDestinationNat(context.Context, *openngfwv1.UpsertCandidateDestinationNatRequest, ...grpc.CallOption) (*openngfwv1.UpsertCandidateDestinationNatResponse, error)
	DeleteCandidateDestinationNat(context.Context, *openngfwv1.DeleteCandidateDestinationNatRequest, ...grpc.CallOption) (*openngfwv1.DeleteCandidateDestinationNatResponse, error)
}

type candidateNatMutation interface {
	proto.Message
	GetAction() string
	GetNatType() string
	GetValidation() *openngfwv1.ValidateResponse
	GetCandidateRevision() string
}

type natListOptions struct {
	source  string
	version uint64
	outJSON bool
}

type natAuditOptions struct {
	expectedRevision string
	comment          string
	reason           string
}

type sourceNatOptions struct {
	id                string
	name              string
	toZone            string
	sourceAddress     string
	masquerade        bool
	translatedAddress string
	audit             natAuditOptions
	outJSON           bool
}

type destinationNatOptions struct {
	id                 string
	name               string
	fromZone           string
	service            string
	destinationAddress string
	translatedAddress  string
	translatedPort     uint32
	audit              natAuditOptions
	outJSON            bool
}

type natDeleteOptions struct {
	name    string
	id      string
	audit   natAuditOptions
	outJSON bool
}

type natListOutput struct {
	Source         string               `json:"source"`
	Version        uint64               `json:"version,omitempty"`
	SourceNat      []*sourceNatRow      `json:"source_nat"`
	DestinationNat []*destinationNatRow `json:"destination_nat"`
}

type sourceNatRow struct {
	ID                string `json:"id,omitempty"`
	Name              string `json:"name"`
	ToZone            string `json:"to_zone"`
	SourceAddress     string `json:"source_address,omitempty"`
	Masquerade        bool   `json:"masquerade,omitempty"`
	TranslatedAddress string `json:"translated_address,omitempty"`
}

type destinationNatRow struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name"`
	FromZone           string `json:"from_zone"`
	Service            string `json:"service"`
	DestinationAddress string `json:"destination_address"`
	TranslatedAddress  string `json:"translated_address"`
	TranslatedPort     uint32 `json:"translated_port,omitempty"`
}

type staticRouteRow struct {
	Destination string `json:"destination"`
	Via         string `json:"via,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      uint32 `json:"metric"`
}

type vpnListResult struct {
	source string
	vpn    *openngfwv1.Vpn
}

type vpnIPsecRow struct {
	Name          string   `json:"name"`
	LocalAddress  string   `json:"local_address,omitempty"`
	RemoteAddress string   `json:"remote_address,omitempty"`
	LocalSubnets  []string `json:"local_subnets,omitempty"`
	RemoteSubnets []string `json:"remote_subnets,omitempty"`
	PskFile       string   `json:"psk_file"`
	Initiate      bool     `json:"initiate"`
}

type vpnWireGuardRow struct {
	Name           string       `json:"name"`
	Address        string       `json:"address,omitempty"`
	ListenPort     uint32       `json:"listen_port,omitempty"`
	PrivateKeyFile string       `json:"private_key_file"`
	Peers          []vpnPeerRow `json:"peers,omitempty"`
}

type vpnPeerRow struct {
	Name                string   `json:"name"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive uint32   `json:"persistent_keepalive,omitempty"`
}

type vpnRows struct {
	IPsec     []vpnIPsecRow     `json:"ipsec_tunnels"`
	WireGuard []vpnWireGuardRow `json:"wireguard_interfaces"`
}

type vpnInventoryOutput struct {
	Source    string            `json:"source"`
	IPsec     []vpnIPsecRow     `json:"ipsec_tunnels"`
	WireGuard []vpnWireGuardRow `json:"wireguard_interfaces"`
}

func newPolicyNatCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nat",
		Short: "Stage and inspect NAT rules",
	}
	cmd.AddCommand(
		newPolicyNatListCommand(server),
		newPolicyNatSourceCommand(server),
		newPolicyNatDestinationCommand(server),
	)
	return cmd
}

func newPolicyNatListCommand(server *string) *cobra.Command {
	opts := natListOptions{source: "running"}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"show"},
		Short:   "List source and destination NAT rules from a policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := natListRequest(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).ListNatRules(ctx, req)
			if err != nil {
				return fmt.Errorf("list NAT rules: %w", err)
			}
			return printNatRules(cmd, resp, opts.outJSON)
		},
	}
	cmd.Flags().StringVar(&opts.source, "source", opts.source, "running | candidate | version")
	cmd.Flags().Uint64Var(&opts.version, "version", 0, "version id (with --source version)")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON instead of a table")
	return cmd
}

func newPolicyNatSourceCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "source",
		Aliases: []string{"src", "snat"},
		Short:   "Stage source NAT candidate rules",
	}
	cmd.AddCommand(newPolicyNatSourceUpsertCommand(server), newPolicyNatSourceDeleteCommand(server))
	return cmd
}

func newPolicyNatSourceUpsertCommand(server *string) *cobra.Command {
	opts := sourceNatOptions{}
	cmd := &cobra.Command{
		Use:     "upsert",
		Aliases: []string{"add", "set"},
		Short:   "Add or update a source NAT rule in the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := sourceNatUpsertRequest(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).UpsertCandidateSourceNat(ctx, req)
			if err != nil {
				return natMutationCLIError("upsert", "source", opts.id, err)
			}
			return printNatMutation(cmd, resp, opts.outJSON)
		},
	}
	addSourceNatFlags(cmd, &opts)
	return cmd
}

func newPolicyNatSourceDeleteCommand(server *string) *cobra.Command {
	opts := natDeleteOptions{}
	cmd := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"del", "remove", "rm"},
		Short:   "Delete a source NAT rule from the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := sourceNatDeleteRequest(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).DeleteCandidateSourceNat(ctx, req)
			if err != nil {
				return natMutationCLIError("delete", "source", opts.id, err)
			}
			return printNatMutation(cmd, resp, opts.outJSON)
		},
	}
	addNatDeleteFlags(cmd, &opts)
	return cmd
}

func newPolicyNatDestinationCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "destination",
		Aliases: []string{"dst", "dnat"},
		Short:   "Stage destination NAT candidate rules",
	}
	cmd.AddCommand(newPolicyNatDestinationUpsertCommand(server), newPolicyNatDestinationDeleteCommand(server))
	return cmd
}

func newPolicyNatDestinationUpsertCommand(server *string) *cobra.Command {
	opts := destinationNatOptions{}
	cmd := &cobra.Command{
		Use:     "upsert",
		Aliases: []string{"add", "set"},
		Short:   "Add or update a destination NAT rule in the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := destinationNatUpsertRequest(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).UpsertCandidateDestinationNat(ctx, req)
			if err != nil {
				return natMutationCLIError("upsert", "destination", opts.id, err)
			}
			return printNatMutation(cmd, resp, opts.outJSON)
		},
	}
	addDestinationNatFlags(cmd, &opts)
	return cmd
}

func newPolicyNatDestinationDeleteCommand(server *string) *cobra.Command {
	opts := natDeleteOptions{}
	cmd := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"del", "remove", "rm"},
		Short:   "Delete a destination NAT rule from the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := destinationNatDeleteRequest(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).DeleteCandidateDestinationNat(ctx, req)
			if err != nil {
				return natMutationCLIError("delete", "destination", opts.id, err)
			}
			return printNatMutation(cmd, resp, opts.outJSON)
		},
	}
	addNatDeleteFlags(cmd, &opts)
	return cmd
}

func newPolicyRouteCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "route",
		Aliases: []string{"routes", "static-route", "static-routes"},
		Short:   "Stage and inspect static routes",
	}
	cmd.AddCommand(
		newPolicyRouteAddCommand(server),
		newPolicyRouteDeleteCommand(server),
		newPolicyRouteListCommand(server),
	)
	return cmd
}

func newPolicyRouteAddCommand(server *string) *cobra.Command {
	var opts staticRouteOptions
	cmd := &cobra.Command{
		Use:     "add",
		Aliases: []string{"upsert"},
		Short:   "Add or update a static route in the candidate policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			route, err := staticRouteFromOptions(opts)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			result, err := stageStaticRouteUpsert(ctx, openngfwv1.NewPolicyServiceClient(conn), route)
			if err != nil {
				return err
			}
			cmd.Printf("static route %s in candidate from %s policy\n", result.action, result.source)
			cmd.Printf("- %s\n", staticRouteText(result.route))
			cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.destination, "destination", "", "destination prefix in CIDR form, for example 0.0.0.0/0")
	cmd.Flags().StringVar(&opts.via, "via", "", "next-hop IP address")
	cmd.Flags().StringVar(&opts.iface, "interface", "", "egress interface for directly attached or pinned routes")
	cmd.Flags().Uint32Var(&opts.metric, "metric", 0, "route metric")
	_ = cmd.MarkFlagRequired("destination")
	return cmd
}

func newPolicyRouteDeleteCommand(server *string) *cobra.Command {
	var destination string
	cmd := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"del", "remove", "rm"},
		Short:   "Delete a static route from the candidate policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := staticRouteDestinationKey(destination)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			result, err := stageStaticRouteDelete(ctx, openngfwv1.NewPolicyServiceClient(conn), key)
			if err != nil {
				return err
			}
			cmd.Printf("static route deleted from candidate staged from %s policy\n", result.source)
			cmd.Printf("- %s\n", staticRouteText(result.route))
			cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
			return nil
		},
	}
	cmd.Flags().StringVar(&destination, "destination", "", "destination prefix in CIDR form")
	_ = cmd.MarkFlagRequired("destination")
	return cmd
}

func newPolicyRouteListCommand(server *string) *cobra.Command {
	var (
		source  string
		version uint64
		outJSON bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"show"},
		Short:   "List static routes from running, candidate, or versioned policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, label, err := staticRoutePolicyRequest(source, version)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			result, err := readStaticRoutes(ctx, openngfwv1.NewPolicyServiceClient(conn), req, label)
			if err != nil {
				return err
			}
			return printStaticRoutes(cmd, result.source, result.routes, outJSON)
		},
	}
	cmd.Flags().StringVar(&source, "source", "running", "running | candidate | version")
	cmd.Flags().Uint64Var(&version, "version", 0, "version id (with --source version)")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON instead of a table")
	return cmd
}

func newPolicyVPNCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vpn",
		Aliases: []string{"vpns"},
		Short:   "Inspect VPN policy configuration",
	}
	cmd.AddCommand(newPolicyVPNListCommand(server))
	return cmd
}

func newPolicyVPNListCommand(server *string) *cobra.Command {
	var (
		source  string
		version uint64
		outJSON bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"show"},
		Short:   "List IPsec and WireGuard configuration from running, candidate, or versioned policy",
		Long: "List IPsec and WireGuard configuration without exposing managed secret file paths or peer public keys. " +
			"Use this before route, tunnel, and peer reviews to confirm the candidate-visible VPN topology.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, label, err := staticRoutePolicyRequest(source, version)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			result, err := readVPNConfig(ctx, openngfwv1.NewPolicyServiceClient(conn), req, label)
			if err != nil {
				return err
			}
			return printVPNConfig(cmd, result.source, result.vpn, outJSON)
		},
	}
	cmd.Flags().StringVar(&source, "source", "running", "running | candidate | version")
	cmd.Flags().Uint64Var(&version, "version", 0, "version id (with --source version)")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON instead of a table")
	return cmd
}

func addSourceNatFlags(cmd *cobra.Command, opts *sourceNatOptions) {
	cmd.Flags().StringVar(&opts.id, "id", "", "existing source NAT durable ID to update; preserves the ID when --name renames the rule")
	cmd.Flags().StringVar(&opts.name, "name", "", "source NAT rule name")
	cmd.Flags().StringVar(&opts.toZone, "to-zone", "", "egress zone")
	cmd.Flags().StringVar(&opts.sourceAddress, "source-address", "", "optional source address object")
	cmd.Flags().BoolVar(&opts.masquerade, "masquerade", false, "translate to the egress interface address")
	cmd.Flags().StringVar(&opts.translatedAddress, "translated-address", "", "translated source address object")
	addNatAuditFlags(cmd, &opts.audit)
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("to-zone")
}

func addDestinationNatFlags(cmd *cobra.Command, opts *destinationNatOptions) {
	cmd.Flags().StringVar(&opts.id, "id", "", "existing destination NAT durable ID to update; preserves the ID when --name renames the rule")
	cmd.Flags().StringVar(&opts.name, "name", "", "destination NAT rule name")
	cmd.Flags().StringVar(&opts.fromZone, "from-zone", "", "ingress zone")
	cmd.Flags().StringVar(&opts.service, "service", "", "service object")
	cmd.Flags().StringVar(&opts.destinationAddress, "destination-address", "", "original destination address object")
	cmd.Flags().StringVar(&opts.translatedAddress, "translated-address", "", "translated destination address object")
	cmd.Flags().Uint32Var(&opts.translatedPort, "translated-port", 0, "optional translated port; 0 keeps original")
	addNatAuditFlags(cmd, &opts.audit)
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("from-zone")
	_ = cmd.MarkFlagRequired("service")
	_ = cmd.MarkFlagRequired("destination-address")
	_ = cmd.MarkFlagRequired("translated-address")
}

func addNatDeleteFlags(cmd *cobra.Command, opts *natDeleteOptions) {
	cmd.Flags().StringVar(&opts.name, "name", "", "NAT rule name")
	cmd.Flags().StringVar(&opts.id, "id", "", "durable NAT rule ID")
	addNatAuditFlags(cmd, &opts.audit)
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
}

func addNatAuditFlags(cmd *cobra.Command, opts *natAuditOptions) {
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-candidate-revision", "", "required candidate revision from 'ngfwctl policy status --json'")
	cmd.Flags().StringVar(&opts.comment, "comment", "", "operator audit comment")
	cmd.Flags().StringVar(&opts.reason, "reason", "", "operator reason recorded in the audit log")
	_ = cmd.MarkFlagRequired("expected-candidate-revision")
}

func sourceNatFromOptions(opts sourceNatOptions) (*openngfwv1.SourceNat, error) {
	name := strings.TrimSpace(opts.name)
	if name == "" {
		return nil, fmt.Errorf("--name is required")
	}
	toZone := strings.TrimSpace(opts.toZone)
	if toZone == "" {
		return nil, fmt.Errorf("--to-zone is required")
	}
	translated := strings.TrimSpace(opts.translatedAddress)
	if opts.masquerade == (translated != "") {
		return nil, fmt.Errorf("exactly one of --masquerade or --translated-address is required")
	}
	if err := requireNatAudit(opts.audit); err != nil {
		return nil, err
	}
	return &openngfwv1.SourceNat{
		Id:                strings.TrimSpace(opts.id),
		Name:              name,
		ToZone:            toZone,
		SourceAddress:     strings.TrimSpace(opts.sourceAddress),
		Masquerade:        opts.masquerade,
		TranslatedAddress: translated,
	}, nil
}

func destinationNatFromOptions(opts destinationNatOptions) (*openngfwv1.DestinationNat, error) {
	if strings.TrimSpace(opts.name) == "" {
		return nil, fmt.Errorf("--name is required")
	}
	if strings.TrimSpace(opts.fromZone) == "" {
		return nil, fmt.Errorf("--from-zone is required")
	}
	if strings.TrimSpace(opts.service) == "" {
		return nil, fmt.Errorf("--service is required")
	}
	if strings.TrimSpace(opts.destinationAddress) == "" {
		return nil, fmt.Errorf("--destination-address is required")
	}
	if strings.TrimSpace(opts.translatedAddress) == "" {
		return nil, fmt.Errorf("--translated-address is required")
	}
	if err := requireNatAudit(opts.audit); err != nil {
		return nil, err
	}
	return &openngfwv1.DestinationNat{
		Id:                 strings.TrimSpace(opts.id),
		Name:               strings.TrimSpace(opts.name),
		FromZone:           strings.TrimSpace(opts.fromZone),
		Service:            strings.TrimSpace(opts.service),
		DestinationAddress: strings.TrimSpace(opts.destinationAddress),
		TranslatedAddress:  strings.TrimSpace(opts.translatedAddress),
		TranslatedPort:     opts.translatedPort,
	}, nil
}

func requireNatAudit(opts natAuditOptions) error {
	if strings.TrimSpace(opts.expectedRevision) == "" {
		return fmt.Errorf("--expected-candidate-revision is required")
	}
	if strings.TrimSpace(opts.comment) == "" && strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--comment or --reason is required")
	}
	return nil
}

func natMutationCLIError(action, natType, id string, err error) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%s %s NAT: %w", action, natType, err)
	}
	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%s %s NAT by durable ID %q: %w; reload candidate NAT with 'ngfwctl policy nat list --source candidate' and select a current ID", action, natType, id, err)
	case codes.FailedPrecondition:
		return fmt.Errorf("%s %s NAT by durable ID %q: %w; reload candidate status and NAT, then retry with the current revision and a unique durable ID", action, natType, id, err)
	case codes.InvalidArgument:
		return fmt.Errorf("%s %s NAT by durable ID %q: %w; ensure --id matches the selected rule and --name is only the desired label", action, natType, id, err)
	default:
		return fmt.Errorf("%s %s NAT by durable ID %q: %w", action, natType, id, err)
	}
}

func sourceNatUpsertRequest(opts sourceNatOptions) (*openngfwv1.UpsertCandidateSourceNatRequest, error) {
	rule, err := sourceNatFromOptions(opts)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.UpsertCandidateSourceNatRequest{
		Id:                        strings.TrimSpace(opts.id),
		Rule:                      rule,
		ExpectedCandidateRevision: strings.TrimSpace(opts.audit.expectedRevision),
		Comment:                   strings.TrimSpace(opts.audit.comment),
		Reason:                    strings.TrimSpace(opts.audit.reason),
	}, nil
}

func destinationNatUpsertRequest(opts destinationNatOptions) (*openngfwv1.UpsertCandidateDestinationNatRequest, error) {
	rule, err := destinationNatFromOptions(opts)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.UpsertCandidateDestinationNatRequest{
		Id:                        strings.TrimSpace(opts.id),
		Rule:                      rule,
		ExpectedCandidateRevision: strings.TrimSpace(opts.audit.expectedRevision),
		Comment:                   strings.TrimSpace(opts.audit.comment),
		Reason:                    strings.TrimSpace(opts.audit.reason),
	}, nil
}

func sourceNatDeleteRequest(opts natDeleteOptions) (*openngfwv1.DeleteCandidateSourceNatRequest, error) {
	if err := validateNatDeleteSelector(opts); err != nil {
		return nil, err
	}
	if err := requireNatAudit(opts.audit); err != nil {
		return nil, err
	}
	return &openngfwv1.DeleteCandidateSourceNatRequest{
		Name:                      strings.TrimSpace(opts.name),
		Id:                        strings.TrimSpace(opts.id),
		ExpectedCandidateRevision: strings.TrimSpace(opts.audit.expectedRevision),
		Comment:                   strings.TrimSpace(opts.audit.comment),
		Reason:                    strings.TrimSpace(opts.audit.reason),
	}, nil
}

func destinationNatDeleteRequest(opts natDeleteOptions) (*openngfwv1.DeleteCandidateDestinationNatRequest, error) {
	if err := validateNatDeleteSelector(opts); err != nil {
		return nil, err
	}
	if err := requireNatAudit(opts.audit); err != nil {
		return nil, err
	}
	return &openngfwv1.DeleteCandidateDestinationNatRequest{
		Name:                      strings.TrimSpace(opts.name),
		Id:                        strings.TrimSpace(opts.id),
		ExpectedCandidateRevision: strings.TrimSpace(opts.audit.expectedRevision),
		Comment:                   strings.TrimSpace(opts.audit.comment),
		Reason:                    strings.TrimSpace(opts.audit.reason),
	}, nil
}

func validateNatDeleteSelector(opts natDeleteOptions) error {
	hasName := strings.TrimSpace(opts.name) != ""
	hasID := strings.TrimSpace(opts.id) != ""
	switch {
	case hasName && hasID:
		return fmt.Errorf("use exactly one of --name or --id for NAT delete")
	case hasID:
		return nil
	case hasName:
		return nil
	default:
		return fmt.Errorf("--name or --id is required")
	}
}

func natListRequest(opts natListOptions) (*openngfwv1.ListNatRulesRequest, error) {
	req := &openngfwv1.ListNatRulesRequest{}
	switch strings.ToLower(strings.TrimSpace(opts.source)) {
	case "", "running":
		if opts.version != 0 {
			return nil, fmt.Errorf("--version is only valid when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
	case "candidate":
		if opts.version != 0 {
			return nil, fmt.Errorf("--version is only valid when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE
	case "version":
		if opts.version == 0 {
			return nil, fmt.Errorf("--version is required when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_VERSION
		req.Version = opts.version
	default:
		return nil, fmt.Errorf("--source must be running, candidate, or version")
	}
	return req, nil
}

func printNatRules(cmd *cobra.Command, resp *openngfwv1.ListNatRulesResponse, outJSON bool) error {
	output := natListRows(resp)
	if outJSON {
		raw, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(raw))
		return nil
	}
	cmd.Printf("NAT rules from %s\n", displayEmpty(resp.GetSource()))
	cmd.Println("Source NAT")
	if len(output.SourceNat) == 0 {
		cmd.Println("  none")
	} else {
		cmd.Printf("%-18s %-20s %-14s %-18s %-11s %s\n", "ID", "NAME", "TO-ZONE", "SOURCE", "MASQ", "TRANSLATED")
		for _, row := range output.SourceNat {
			cmd.Printf("%-18s %-20s %-14s %-18s %-11s %s\n", displayEmpty(row.ID), row.Name, row.ToZone, displayEmpty(row.SourceAddress), yesNo(row.Masquerade), displayEmpty(row.TranslatedAddress))
		}
	}
	cmd.Println("Destination NAT")
	if len(output.DestinationNat) == 0 {
		cmd.Println("  none")
		return nil
	}
	cmd.Printf("%-18s %-20s %-14s %-14s %-18s %-18s %s\n", "ID", "NAME", "FROM-ZONE", "SERVICE", "DESTINATION", "TRANSLATED", "PORT")
	for _, row := range output.DestinationNat {
		port := ""
		if row.TranslatedPort != 0 {
			port = strconv.FormatUint(uint64(row.TranslatedPort), 10)
		}
		cmd.Printf("%-18s %-20s %-14s %-14s %-18s %-18s %s\n", displayEmpty(row.ID), row.Name, row.FromZone, row.Service, row.DestinationAddress, row.TranslatedAddress, displayEmpty(port))
	}
	return nil
}

func natListRows(resp *openngfwv1.ListNatRulesResponse) natListOutput {
	out := natListOutput{Source: resp.GetSource(), Version: resp.GetVersion()}
	for _, rule := range resp.GetSourceNat() {
		out.SourceNat = append(out.SourceNat, sourceNatOutput(rule))
	}
	for _, rule := range resp.GetDestinationNat() {
		out.DestinationNat = append(out.DestinationNat, destinationNatOutput(rule))
	}
	return out
}

func printNatMutation(cmd *cobra.Command, resp proto.Message, outJSON bool) error {
	if outJSON {
		return printProtoJSON(cmd, resp)
	}
	mutation, ok := resp.(candidateNatMutation)
	if !ok {
		return fmt.Errorf("unexpected NAT mutation response %T", resp)
	}
	cmd.Printf("%s NAT %s in candidate\n", mutation.GetNatType(), mutation.GetAction())
	switch typed := resp.(type) {
	case interface{ GetSourceNat() *openngfwv1.SourceNat }:
		row := sourceNatOutput(typed.GetSourceNat())
		cmd.Printf("- %s%s to-zone=%s source=%s masquerade=%s translated=%s\n", row.Name, natIDLabel(row.ID), row.ToZone, displayEmpty(row.SourceAddress), yesNo(row.Masquerade), displayEmpty(row.TranslatedAddress))
	case interface {
		GetDestinationNat() *openngfwv1.DestinationNat
	}:
		row := destinationNatOutput(typed.GetDestinationNat())
		cmd.Printf("- %s%s from-zone=%s service=%s destination=%s translated=%s", row.Name, natIDLabel(row.ID), row.FromZone, row.Service, row.DestinationAddress, row.TranslatedAddress)
		if row.TranslatedPort != 0 {
			cmd.Printf(" translated-port=%d", row.TranslatedPort)
		}
		cmd.Println()
	}
	cmd.Printf("candidate revision: %s\n", mutation.GetCandidateRevision())
	printImpact(cmd, mutation.GetValidation().GetImpact())
	cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' (add '--ack-risk' if validation reports high impact)")
	return nil
}

func sourceNatOutput(rule *openngfwv1.SourceNat) *sourceNatRow {
	return &sourceNatRow{
		ID:                protoStringField(rule, "id"),
		Name:              rule.GetName(),
		ToZone:            rule.GetToZone(),
		SourceAddress:     rule.GetSourceAddress(),
		Masquerade:        rule.GetMasquerade(),
		TranslatedAddress: rule.GetTranslatedAddress(),
	}
}

func destinationNatOutput(rule *openngfwv1.DestinationNat) *destinationNatRow {
	return &destinationNatRow{
		ID:                 protoStringField(rule, "id"),
		Name:               rule.GetName(),
		FromZone:           rule.GetFromZone(),
		Service:            rule.GetService(),
		DestinationAddress: rule.GetDestinationAddress(),
		TranslatedAddress:  rule.GetTranslatedAddress(),
		TranslatedPort:     rule.GetTranslatedPort(),
	}
}

func protoStringField(msg proto.Message, name protoreflect.Name) string {
	if msg == nil {
		return ""
	}
	field := msg.ProtoReflect().Descriptor().Fields().ByName(name)
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return strings.TrimSpace(msg.ProtoReflect().Get(field).String())
}

func natIDLabel(id string) string {
	if strings.TrimSpace(id) == "" {
		return ""
	}
	return " id=" + strings.TrimSpace(id)
}

func staticRouteFromOptions(opts staticRouteOptions) (*openngfwv1.StaticRoute, error) {
	destination, err := staticRouteDestinationKey(opts.destination)
	if err != nil {
		return nil, err
	}
	via := strings.TrimSpace(opts.via)
	if via != "" {
		addr, err := netip.ParseAddr(via)
		if err != nil {
			return nil, fmt.Errorf("--via %q is invalid: %w", opts.via, err)
		}
		via = addr.String()
	}
	iface := strings.TrimSpace(opts.iface)
	if via == "" && iface == "" {
		return nil, fmt.Errorf("one of --via or --interface is required")
	}
	return &openngfwv1.StaticRoute{
		Destination: destination,
		Via:         via,
		Interface:   iface,
		Metric:      opts.metric,
	}, nil
}

func staticRouteDestinationKey(destination string) (string, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", fmt.Errorf("--destination is required")
	}
	prefix, err := netip.ParsePrefix(destination)
	if err != nil {
		return "", fmt.Errorf("--destination %q is invalid: %w", destination, err)
	}
	return prefix.Masked().String(), nil
}

func stageStaticRouteUpsert(ctx context.Context, client policyClient, route *openngfwv1.StaticRoute) (staticRouteStageResult, error) {
	if route == nil {
		return staticRouteStageResult{}, fmt.Errorf("static route is required")
	}
	route, err := staticRouteFromOptions(staticRouteOptions{
		destination: route.GetDestination(),
		via:         route.GetVia(),
		iface:       route.GetInterface(),
		metric:      route.GetMetric(),
	})
	if err != nil {
		return staticRouteStageResult{}, err
	}
	pol, source, err := editablePolicy(ctx, client)
	if err != nil {
		return staticRouteStageResult{}, err
	}
	action := upsertStaticRoute(pol, route)
	if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
		return staticRouteStageResult{}, fmt.Errorf("set candidate: %w", err)
	}
	return staticRouteStageResult{source: source, action: action, route: cloneStaticRoute(route)}, nil
}

func stageStaticRouteDelete(ctx context.Context, client policyClient, destination string) (staticRouteStageResult, error) {
	key, err := staticRouteDestinationKey(destination)
	if err != nil {
		return staticRouteStageResult{}, err
	}
	pol, source, err := editablePolicy(ctx, client)
	if err != nil {
		return staticRouteStageResult{}, err
	}
	removed, err := deleteStaticRoute(pol, key)
	if err != nil {
		return staticRouteStageResult{}, err
	}
	if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
		return staticRouteStageResult{}, fmt.Errorf("set candidate: %w", err)
	}
	return staticRouteStageResult{source: source, action: "deleted", route: removed}, nil
}

func upsertStaticRoute(policy *openngfwv1.Policy, route *openngfwv1.StaticRoute) string {
	key, err := staticRouteDestinationKey(route.GetDestination())
	if err != nil {
		key = strings.TrimSpace(route.GetDestination())
	}
	for i, existing := range policy.GetStaticRoutes() {
		if staticRouteDestinationMatches(existing.GetDestination(), key, route.GetDestination()) {
			policy.StaticRoutes[i] = cloneStaticRoute(route)
			return "updated"
		}
	}
	policy.StaticRoutes = append(policy.StaticRoutes, cloneStaticRoute(route))
	return "added"
}

func deleteStaticRoute(policy *openngfwv1.Policy, destination string) (*openngfwv1.StaticRoute, error) {
	key, err := staticRouteDestinationKey(destination)
	if err != nil {
		return nil, err
	}
	for i, existing := range policy.GetStaticRoutes() {
		if staticRouteDestinationMatches(existing.GetDestination(), key, destination) {
			removed := cloneStaticRoute(existing)
			policy.StaticRoutes = append(policy.StaticRoutes[:i], policy.StaticRoutes[i+1:]...)
			return removed, nil
		}
	}
	return nil, fmt.Errorf("static route %q not found in candidate policy", key)
}

func staticRouteDestinationMatches(existing, key, raw string) bool {
	existingKey, err := staticRouteDestinationKey(existing)
	if err == nil {
		return existingKey == key
	}
	return strings.TrimSpace(existing) == strings.TrimSpace(raw)
}

func staticRoutePolicyRequest(source string, version uint64) (*openngfwv1.GetPolicyRequest, string, error) {
	req := &openngfwv1.GetPolicyRequest{}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "running":
		if version != 0 {
			return nil, "", fmt.Errorf("--version is only valid when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
		return req, "running", nil
	case "candidate":
		if version != 0 {
			return nil, "", fmt.Errorf("--version is only valid when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE
		return req, "candidate", nil
	case "version":
		if version == 0 {
			return nil, "", fmt.Errorf("--version is required when --source version")
		}
		req.Source = openngfwv1.PolicySource_POLICY_SOURCE_VERSION
		req.Version = version
		return req, fmt.Sprintf("version %d", version), nil
	default:
		return nil, "", fmt.Errorf("--source must be running, candidate, or version")
	}
}

func readStaticRoutes(ctx context.Context, client policyClient, req *openngfwv1.GetPolicyRequest, label string) (staticRouteListResult, error) {
	resp, err := client.GetPolicy(ctx, req)
	if err != nil {
		return staticRouteListResult{}, fmt.Errorf("read %s policy: %w", label, err)
	}
	return staticRouteListResult{source: label, routes: cloneStaticRoutes(resp.GetPolicy().GetStaticRoutes())}, nil
}

func cloneStaticRoutes(routes []*openngfwv1.StaticRoute) []*openngfwv1.StaticRoute {
	out := make([]*openngfwv1.StaticRoute, 0, len(routes))
	for _, route := range routes {
		out = append(out, cloneStaticRoute(route))
	}
	return out
}

func cloneStaticRoute(route *openngfwv1.StaticRoute) *openngfwv1.StaticRoute {
	if route == nil {
		return &openngfwv1.StaticRoute{}
	}
	return proto.Clone(route).(*openngfwv1.StaticRoute)
}

func printStaticRoutes(cmd *cobra.Command, source string, routes []*openngfwv1.StaticRoute, outJSON bool) error {
	rows := staticRouteRows(routes)
	if outJSON {
		raw, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(raw))
		return nil
	}
	if len(rows) == 0 {
		cmd.Println("no static routes configured")
		return nil
	}
	cmd.Printf("static routes from %s policy\n", source)
	cmd.Printf("%-18s %-15s %-12s %s\n", "DESTINATION", "VIA", "INTERFACE", "METRIC")
	for _, row := range rows {
		cmd.Printf("%-18s %-15s %-12s %d\n", row.Destination, displayEmpty(row.Via), displayEmpty(row.Interface), row.Metric)
	}
	return nil
}

func staticRouteRows(routes []*openngfwv1.StaticRoute) []staticRouteRow {
	rows := make([]staticRouteRow, 0, len(routes))
	for _, route := range routes {
		if route == nil {
			continue
		}
		rows = append(rows, staticRouteRow{
			Destination: route.GetDestination(),
			Via:         route.GetVia(),
			Interface:   route.GetInterface(),
			Metric:      route.GetMetric(),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Destination != rows[j].Destination {
			return rows[i].Destination < rows[j].Destination
		}
		if rows[i].Via != rows[j].Via {
			return rows[i].Via < rows[j].Via
		}
		if rows[i].Interface != rows[j].Interface {
			return rows[i].Interface < rows[j].Interface
		}
		return rows[i].Metric < rows[j].Metric
	})
	return rows
}

func staticRouteText(route *openngfwv1.StaticRoute) string {
	return fmt.Sprintf("%s via %s dev %s metric %d", route.GetDestination(), displayEmpty(route.GetVia()), displayEmpty(route.GetInterface()), route.GetMetric())
}

func readVPNConfig(ctx context.Context, client policyClient, req *openngfwv1.GetPolicyRequest, label string) (vpnListResult, error) {
	resp, err := client.GetPolicy(ctx, req)
	if err != nil {
		return vpnListResult{}, fmt.Errorf("read %s policy: %w", label, err)
	}
	vpn := resp.GetPolicy().GetVpn()
	if vpn == nil {
		vpn = &openngfwv1.Vpn{}
	}
	return vpnListResult{source: label, vpn: cloneVPN(vpn)}, nil
}

func cloneVPN(vpn *openngfwv1.Vpn) *openngfwv1.Vpn {
	if vpn == nil {
		return &openngfwv1.Vpn{}
	}
	return proto.Clone(vpn).(*openngfwv1.Vpn)
}

func printVPNConfig(cmd *cobra.Command, source string, vpn *openngfwv1.Vpn, outJSON bool) error {
	rows := vpnConfigRows(vpn)
	if outJSON {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(vpnInventoryOutput{
			Source:    source,
			IPsec:     rows.IPsec,
			WireGuard: rows.WireGuard,
		}); err != nil {
			return err
		}
		cmd.Print(buf.String())
		return nil
	}
	if len(rows.IPsec) == 0 && len(rows.WireGuard) == 0 {
		cmd.Println("no VPN configuration")
		return nil
	}
	cmd.Printf("VPN configuration from %s policy\n", source)
	if len(rows.IPsec) > 0 {
		cmd.Println("IPsec tunnels")
		cmd.Printf("%-18s %-15s %-15s %-18s %-18s %s\n", "NAME", "LOCAL", "REMOTE", "LOCAL CIDRS", "REMOTE CIDRS", "MODE")
		for _, row := range rows.IPsec {
			mode := "responder"
			if row.Initiate {
				mode = "initiator"
			}
			cmd.Printf("%-18s %-15s %-15s %-18s %-18s %s\n",
				displayEmpty(row.Name),
				displayEmpty(row.LocalAddress),
				displayEmpty(row.RemoteAddress),
				displayEmpty(strings.Join(row.LocalSubnets, ",")),
				displayEmpty(strings.Join(row.RemoteSubnets, ",")),
				mode)
		}
	}
	if len(rows.WireGuard) > 0 {
		cmd.Println("WireGuard interfaces")
		cmd.Printf("%-14s %-18s %-10s %s\n", "NAME", "ADDRESS", "LISTEN", "PEERS")
		for _, row := range rows.WireGuard {
			cmd.Printf("%-14s %-18s %-10s %d\n",
				displayEmpty(row.Name),
				displayEmpty(row.Address),
				displayPort(row.ListenPort),
				len(row.Peers))
		}
		for _, row := range rows.WireGuard {
			if len(row.Peers) == 0 {
				continue
			}
			cmd.Printf("Peers for %s\n", displayEmpty(row.Name))
			cmd.Printf("%-18s %-24s %-24s %s\n", "NAME", "ENDPOINT", "ALLOWED IPS", "KEEPALIVE")
			for _, peer := range row.Peers {
				cmd.Printf("%-18s %-24s %-24s %s\n",
					displayEmpty(peer.Name),
					displayEmpty(peer.Endpoint),
					displayEmpty(strings.Join(peer.AllowedIPs, ",")),
					displayPort(peer.PersistentKeepalive))
			}
		}
	}
	return nil
}

func vpnConfigRows(vpn *openngfwv1.Vpn) vpnRows {
	rows := vpnRows{}
	for _, tunnel := range vpn.GetIpsecTunnels() {
		if tunnel == nil {
			continue
		}
		rows.IPsec = append(rows.IPsec, vpnIPsecRow{
			Name:          tunnel.GetName(),
			LocalAddress:  tunnel.GetLocalAddress(),
			RemoteAddress: tunnel.GetRemoteAddress(),
			LocalSubnets:  append([]string{}, tunnel.GetLocalSubnets()...),
			RemoteSubnets: append([]string{}, tunnel.GetRemoteSubnets()...),
			PskFile:       redactedSecretValue(tunnel.GetPskFile()),
			Initiate:      tunnel.GetInitiate(),
		})
	}
	sort.SliceStable(rows.IPsec, func(i, j int) bool {
		return rows.IPsec[i].Name < rows.IPsec[j].Name
	})
	for _, iface := range vpn.GetWireguardInterfaces() {
		if iface == nil {
			continue
		}
		row := vpnWireGuardRow{
			Name:           iface.GetName(),
			Address:        iface.GetAddress(),
			ListenPort:     iface.GetListenPort(),
			PrivateKeyFile: redactedSecretValue(iface.GetPrivateKeyFile()),
		}
		for _, peer := range iface.GetPeers() {
			if peer == nil {
				continue
			}
			row.Peers = append(row.Peers, vpnPeerRow{
				Name:                peer.GetName(),
				Endpoint:            peer.GetEndpoint(),
				AllowedIPs:          append([]string{}, peer.GetAllowedIps()...),
				PersistentKeepalive: peer.GetPersistentKeepalive(),
			})
		}
		sort.SliceStable(row.Peers, func(i, j int) bool {
			return row.Peers[i].Name < row.Peers[j].Name
		})
		rows.WireGuard = append(rows.WireGuard, row)
	}
	sort.SliceStable(rows.WireGuard, func(i, j int) bool {
		return rows.WireGuard[i].Name < rows.WireGuard[j].Name
	})
	return rows
}

func redactedSecretValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "<redacted>"
}

func displayEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func displayPort(value uint32) string {
	if value == 0 {
		return "-"
	}
	return fmt.Sprint(value)
}

func printImpact(cmd *cobra.Command, impact *openngfwv1.ChangeImpact) {
	if impact == nil {
		return
	}
	cmd.Printf("impact: %s\n", riskLabel(impact.GetRisk()))
	for _, item := range impact.GetItems() {
		cmd.Printf("- [%s] %s", riskLabel(item.GetRisk()), item.GetTitle())
		if item.GetDetail() != "" {
			cmd.Printf(": %s", item.GetDetail())
		}
		cmd.Println()
	}
}

func riskLabel(r openngfwv1.ChangeRisk) string {
	switch r {
	case openngfwv1.ChangeRisk_CHANGE_RISK_HIGH:
		return "high"
	case openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM:
		return "medium"
	case openngfwv1.ChangeRisk_CHANGE_RISK_LOW:
		return "low"
	default:
		return "unspecified"
	}
}

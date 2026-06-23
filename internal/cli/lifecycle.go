package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newCommitCommand(server *string) *cobra.Command {
	var comment string
	var ackRisk bool
	var ackRuntime bool
	var approvalID string
	var reviewedCandidateRevision string
	var stepUpToken string
	cmd := &cobra.Command{
		Use:   "commit",
		Short: "Validate and atomically apply the candidate policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			comment = strings.TrimSpace(comment)
			if comment == "" {
				return fmt.Errorf("commit comment is required; pass --message/-m with the reason for this change")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			system := openngfwv1.NewSystemServiceClient(conn)
			revision, err := commitReviewedCandidateRevision(ctx, client, reviewedCandidateRevision)
			if err != nil {
				return err
			}
			validation, err := client.Validate(ctx, &openngfwv1.ValidateRequest{})
			if err != nil {
				return fmt.Errorf("validate candidate before commit: %w", err)
			}
			target, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
			if err != nil {
				return fmt.Errorf("load candidate before commit: %w", err)
			}
			running, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
			if err != nil {
				return fmt.Errorf("load running policy before commit: %w", err)
			}
			runtime := cliRuntimePreflightFromServer(ctx, system, "commit", target.GetPolicy(), running.GetPolicy())
			if err := handleCommitPreflight(cmd, validation, runtime, ackRisk, ackRuntime); err != nil {
				return err
			}
			resp, err := client.Commit(ctx, newCommitRequest(comment, ackRisk, ackRuntime, approvalID, revision, stepUpToken))
			if err != nil {
				return commitError(err)
			}
			cmd.Printf("committed version %d\n", resp.GetVersion())
			return nil
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required commit audit comment")
	cmd.Flags().BoolVar(&ackRisk, "ack-risk", false, "acknowledge high-risk policy impact reported by validation")
	cmd.Flags().BoolVar(&ackRuntime, "ack-runtime", false, "acknowledge runtime readiness warnings before applying")
	cmd.Flags().StringVar(&approvalID, "approval-id", "", "required server-side change approval id to consume")
	cmd.Flags().StringVar(&reviewedCandidateRevision, "candidate-revision", "", "candidate revision reviewed before commit (defaults to current candidate status)")
	cmd.Flags().StringVar(&reviewedCandidateRevision, "expected-candidate-revision", "", "alias for --candidate-revision")
	cmd.Flags().StringVar(&stepUpToken, "step-up-token", "", "one-time privileged action token for commit")
	return cmd
}

type commitCandidateStatusClient interface {
	GetCandidateStatus(context.Context, *openngfwv1.GetCandidateStatusRequest, ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error)
}

func commitReviewedCandidateRevision(ctx context.Context, client commitCandidateStatusClient, explicitRevision string) (string, error) {
	revision := strings.TrimSpace(explicitRevision)
	if revision != "" {
		return revision, nil
	}
	statusResp, err := client.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return "", fmt.Errorf("get candidate status before commit: %w", err)
	}
	if !statusResp.GetHasCandidate() {
		return "", fmt.Errorf("no candidate policy is set; stage one before committing")
	}
	revision = strings.TrimSpace(statusResp.GetCandidateRevision())
	if revision == "" {
		return "", fmt.Errorf("candidate revision is empty; reload candidate status, review validation and diff, then retry commit")
	}
	return revision, nil
}

func newCommitRequest(comment string, ackRisk, ackRuntime bool, approvalID string, reviewedCandidateRevision string, stepUpToken string) *openngfwv1.CommitRequest {
	return &openngfwv1.CommitRequest{
		Comment:                   strings.TrimSpace(comment),
		AckRisk:                   ackRisk,
		AckRuntime:                ackRuntime,
		ApprovalId:                strings.TrimSpace(approvalID),
		ReviewedCandidateRevision: strings.TrimSpace(reviewedCandidateRevision),
		StepUpToken:               strings.TrimSpace(stepUpToken),
	}
}

func commitError(err error) error {
	if err == nil {
		return nil
	}
	if grpcstatus.Code(err) == codes.FailedPrecondition && strings.Contains(strings.ToLower(err.Error()), "candidate changed") {
		return fmt.Errorf("commit: %w; recovery: run 'ngfwctl policy status' and 'ngfwctl policy diff', review the current candidate, create or select an approval for the new candidate revision, then retry with 'ngfwctl commit --candidate-revision <revision> --approval-id <id> --message <reason>'", err)
	}
	if grpcstatus.Code(err) == codes.InvalidArgument && strings.Contains(strings.ToLower(err.Error()), "reviewed_candidate_revision") {
		return fmt.Errorf("commit: %w; recovery: run 'ngfwctl policy status' to reload the candidate revision, review validation and diff, then retry commit", err)
	}
	return fmt.Errorf("commit: %w", err)
}

func handleCommitPreflight(cmd *cobra.Command, resp *openngfwv1.ValidateResponse, runtime cliRuntimePreflightResult, ackRisk, ackRuntime bool) error {
	if resp == nil {
		return fmt.Errorf("candidate validation returned no response")
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
	printRuntimePreflight(cmd, runtime)
	if commitNeedsRiskAck(resp.GetImpact()) && !ackRisk {
		return fmt.Errorf("high-risk policy impact requires --ack-risk before commit")
	}
	if runtime.requiresAck && !ackRuntime {
		return fmt.Errorf("runtime readiness warnings require --ack-runtime before commit")
	}
	return nil
}

func commitNeedsRiskAck(impact *openngfwv1.ChangeImpact) bool {
	return impact != nil && impact.GetRisk() == openngfwv1.ChangeRisk_CHANGE_RISK_HIGH
}

func newRollbackCommand(server *string) *cobra.Command {
	var comment string
	var ackRisk bool
	var ackRuntime bool
	var stepUpToken string
	cmd := &cobra.Command{
		Use:   "rollback <version>",
		Short: "Re-apply a historical version as a new commit",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			comment = strings.TrimSpace(comment)
			if comment == "" {
				return fmt.Errorf("rollback audit comment is required; pass --message/-m with the reason for this rollback")
			}
			ver, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("version must be a number: %w", err)
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			system := openngfwv1.NewSystemServiceClient(conn)
			target, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_VERSION, Version: ver})
			if err != nil {
				return fmt.Errorf("load rollback target: %w", err)
			}
			validation, err := client.Validate(ctx, &openngfwv1.ValidateRequest{Policy: target.GetPolicy()})
			if err != nil {
				return fmt.Errorf("validate rollback target: %w", err)
			}
			running, err := client.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
			if err != nil {
				return fmt.Errorf("load running policy before rollback: %w", err)
			}
			runtime := cliRuntimePreflightFromServer(ctx, system, "rollback", target.GetPolicy(), running.GetPolicy())
			if err := handleRollbackPreflight(cmd, validation, runtime, ackRisk, ackRuntime); err != nil {
				return err
			}
			resp, err := client.Rollback(ctx, &openngfwv1.RollbackRequest{Version: ver, Comment: comment, AckRisk: ackRisk, AckRuntime: ackRuntime, StepUpToken: strings.TrimSpace(stepUpToken)})
			if err != nil {
				return fmt.Errorf("rollback: %w", err)
			}
			cmd.Printf("rolled back to version %d (new version %d)\n", ver, resp.GetVersion())
			return nil
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required rollback audit comment")
	cmd.Flags().BoolVar(&ackRisk, "ack-risk", false, "acknowledge high-risk policy impact reported by rollback validation")
	cmd.Flags().BoolVar(&ackRuntime, "ack-runtime", false, "acknowledge runtime readiness warnings before rollback")
	cmd.Flags().StringVar(&stepUpToken, "step-up-token", "", "one-time privileged action token for rollback")
	return cmd
}

func handleRollbackPreflight(cmd *cobra.Command, resp *openngfwv1.ValidateResponse, runtime cliRuntimePreflightResult, ackRisk, ackRuntime bool) error {
	if resp == nil {
		return fmt.Errorf("rollback validation returned no response")
	}
	if !resp.GetValid() {
		errs := validationErrors(resp)
		for _, e := range errs {
			cmd.PrintErrln("error: " + e)
		}
		printValidationFindings(cmd, resp)
		printImpact(cmd, resp.GetImpact())
		return fmt.Errorf("rollback target is invalid (%d errors)", len(errs))
	}
	cmd.Println("rollback target is valid")
	printRenderPlan(cmd, resp.GetRenderPlan())
	printValidationFindings(cmd, resp)
	printImpact(cmd, resp.GetImpact())
	printRuntimePreflight(cmd, runtime)
	if commitNeedsRiskAck(resp.GetImpact()) && !ackRisk {
		return fmt.Errorf("high-risk rollback impact requires --ack-risk before rollback")
	}
	if runtime.requiresAck && !ackRuntime {
		return fmt.Errorf("runtime readiness warnings require --ack-runtime before rollback")
	}
	return nil
}

func validationErrors(resp *openngfwv1.ValidateResponse) []string {
	if len(resp.GetErrors()) > 0 {
		return resp.GetErrors()
	}
	var out []string
	for _, finding := range resp.GetFindings() {
		if finding.GetSeverity() != openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
			continue
		}
		out = append(out, validationFindingText(finding))
	}
	return out
}

func validationFindingText(finding *openngfwv1.ValidationFinding) string {
	if finding == nil {
		return ""
	}
	text := finding.GetMessage()
	if text == "" {
		text = finding.GetCode()
	}
	if finding.GetFieldPath() != "" {
		text += " (" + finding.GetFieldPath() + ")"
	}
	if finding.GetDetail() != "" && finding.GetDetail() != text {
		text += ": " + finding.GetDetail()
	}
	return text
}

func printValidationFindings(cmd *cobra.Command, resp *openngfwv1.ValidateResponse) {
	if resp == nil {
		return
	}
	var findings []*openngfwv1.ValidationFinding
	for _, finding := range resp.GetFindings() {
		if finding.GetStage() == openngfwv1.ValidationStage_VALIDATION_STAGE_IMPACT ||
			finding.GetSeverity() == openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR {
			continue
		}
		findings = append(findings, finding)
	}
	if len(findings) == 0 {
		return
	}
	cmd.Println("validation findings:")
	for _, finding := range findings {
		cmd.Printf("- [%s/%s] %s\n", validationSeverityLabel(finding.GetSeverity()), validationStageLabel(finding.GetStage()), validationFindingText(finding))
	}
}

func validationSeverityLabel(severity openngfwv1.ValidationSeverity) string {
	switch severity {
	case openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING:
		return "warning"
	case openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_INFO:
		return "info"
	case openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR:
		return "error"
	default:
		return "unspecified"
	}
}

func validationStageLabel(stage openngfwv1.ValidationStage) string {
	switch stage {
	case openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL:
		return "policy"
	case openngfwv1.ValidationStage_VALIDATION_STAGE_RENDER:
		return "render"
	case openngfwv1.ValidationStage_VALIDATION_STAGE_ENGINE_VALIDATE:
		return "engine"
	case openngfwv1.ValidationStage_VALIDATION_STAGE_IMPACT:
		return "impact"
	default:
		return "validation"
	}
}

func printRenderPlan(cmd *cobra.Command, plan *openngfwv1.RenderPlan) {
	if plan == nil || plan.GetArtifactCount() == 0 {
		return
	}
	cmd.Printf("render plan: %d artifacts, %d bytes\n", plan.GetArtifactCount(), plan.GetTotalBytes())
	for _, artifact := range plan.GetArtifacts() {
		cmd.Printf("- %s: %d bytes\n", artifact.GetName(), artifact.GetSizeBytes())
	}
}

type cliRuntimePreflightItem struct {
	level  string
	title  string
	detail string
}

type cliRuntimePreflightResult struct {
	label       string
	requiresAck bool
	items       []cliRuntimePreflightItem
}

type cliRuntimeReadinessClient interface {
	CheckRuntimeReadiness(context.Context, *openngfwv1.CheckRuntimeReadinessRequest, ...grpc.CallOption) (*openngfwv1.CheckRuntimeReadinessResponse, error)
	GetStatus(context.Context, *openngfwv1.GetStatusRequest, ...grpc.CallOption) (*openngfwv1.GetStatusResponse, error)
}

func cliRuntimePreflightFromServer(ctx context.Context, client cliRuntimeReadinessClient, operation string, target, running *openngfwv1.Policy) cliRuntimePreflightResult {
	resp, err := client.CheckRuntimeReadiness(ctx, &openngfwv1.CheckRuntimeReadinessRequest{
		Operation:     operation,
		TargetPolicy:  target,
		RunningPolicy: running,
	})
	if err == nil {
		return cliRuntimePreflightFromResponse(resp)
	}
	if grpcstatus.Code(err) == codes.Unimplemented {
		statusResp, statusErr := client.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
		return cliRuntimePreflight(statusResp, statusErr, target, running)
	}
	return cliRuntimePreflightResult{
		label:       "unknown",
		requiresAck: true,
		items: []cliRuntimePreflightItem{{
			level:  "warning",
			title:  "Runtime readiness preflight unavailable",
			detail: err.Error(),
		}},
	}
}

func cliRuntimePreflightFromResponse(resp *openngfwv1.CheckRuntimeReadinessResponse) cliRuntimePreflightResult {
	if resp == nil {
		return cliRuntimePreflightResult{
			label:       "unknown",
			requiresAck: true,
			items: []cliRuntimePreflightItem{{
				level:  "warning",
				title:  "Runtime readiness preflight unavailable",
				detail: "server returned no response",
			}},
		}
	}
	out := cliRuntimePreflightResult{
		label:       value(firstNonEmptyRuntime(resp.GetLabel(), resp.GetCls())),
		requiresAck: resp.GetRequiresAck(),
	}
	for _, item := range resp.GetItems() {
		if item == nil {
			continue
		}
		out.items = append(out.items, cliRuntimePreflightItem{
			level:  firstNonEmptyRuntime(item.GetLevel(), item.GetBadge(), "warning"),
			title:  value(item.GetTitle()),
			detail: firstNonEmptyRuntime(item.GetCommand(), item.GetDetail()),
		})
	}
	if len(out.items) == 0 {
		for _, warning := range resp.GetWarnings() {
			warning = strings.TrimSpace(warning)
			if warning == "" {
				continue
			}
			out.items = append(out.items, cliRuntimePreflightItem{
				level:  "warning",
				title:  warning,
				detail: resp.GetDetail(),
			})
		}
	}
	return out
}

func cliRuntimePreflight(st *openngfwv1.GetStatusResponse, err error, target, running *openngfwv1.Policy) cliRuntimePreflightResult {
	if err != nil {
		return cliRuntimePreflightResult{
			label:       "unknown",
			requiresAck: true,
			items: []cliRuntimePreflightItem{{
				level:  "warning",
				title:  "Runtime status unavailable",
				detail: err.Error(),
			}},
		}
	}
	if st == nil {
		return cliRuntimePreflightResult{
			label:       "unknown",
			requiresAck: true,
			items: []cliRuntimePreflightItem{{
				level:  "warning",
				title:  "Runtime status unavailable",
				detail: "status endpoint returned no response",
			}},
		}
	}
	var items []cliRuntimePreflightItem
	addItem := func(level, title, detail string) {
		title = value(title)
		for _, item := range items {
			if item.title == title && item.detail == detail {
				return
			}
		}
		items = append(items, cliRuntimePreflightItem{level: level, title: title, detail: detail})
	}
	rt := st.GetRuntime()
	if rt.GetDryRun() {
		addItem("critical", "Daemon is running in dry-run mode", "Policy state can be recorded without changing host firewall enforcement.")
	}
	for _, w := range st.GetWarnings() {
		if w.GetSeverity() != "critical" && w.GetSeverity() != "warning" {
			continue
		}
		addItem(value(w.GetSeverity()), value(w.GetMessage()), w.GetAction())
	}
	for _, c := range st.GetCapabilities() {
		switch c.GetState() {
		case "degraded", "missing-prerequisites", "failed":
			addItem("warning", value(c.GetName())+" is "+value(c.GetState()), c.GetDetail())
		}
	}
	items = appendPolicyRuntimePreflightItems(items, st, target, running)
	if len(items) == 0 {
		label := value(rt.GetActiveDataplane())
		if label == "n/a" {
			label = "ready"
		}
		return cliRuntimePreflightResult{label: label}
	}
	label := "warnings"
	for _, item := range items {
		if item.level == "critical" {
			label = "not-ready"
			break
		}
	}
	return cliRuntimePreflightResult{label: label, requiresAck: true, items: items}
}

func appendPolicyRuntimePreflightItems(items []cliRuntimePreflightItem, st *openngfwv1.GetStatusResponse, target, running *openngfwv1.Policy) []cliRuntimePreflightItem {
	if st == nil || !policyRequestsFlowOffload(target) {
		return items
	}
	addItem := func(level, title, detail string) {
		title = value(title)
		for _, item := range items {
			if item.title == title && item.detail == detail {
				return
			}
		}
		items = append(items, cliRuntimePreflightItem{level: level, title: title, detail: detail})
	}
	flowtable := st.GetDataplane().GetFlowtable()
	hostState := firstNonEmptyRuntime(flowtable.GetHostState(), cliCapabilityState(st.GetCapabilities(), "nftables flowtable fast path"))
	hostDetail := firstNonEmptyRuntime(flowtable.GetHostDetail(), cliCapabilityDetail(st.GetCapabilities(), "nftables flowtable fast path"))
	if hostState != "" && hostState != "ready" && hostState != "active" {
		addItem("critical", "nftables flowtable fast path is "+hostState, hostDetail)
	}

	if !policyRequestsFlowOffload(running) {
		return items
	}
	runtimeState := firstNonEmptyRuntime(flowtable.GetRuntimeState(), cliCapabilityState(st.GetCapabilities(), "nftables flowtable runtime"))
	runtimeDetail := firstNonEmptyRuntime(flowtable.GetRuntimeDetail(), cliCapabilityDetail(st.GetCapabilities(), "nftables flowtable runtime"))
	if runtimeState != "" && runtimeState != "active" {
		addItem("critical", "nftables flowtable runtime is "+runtimeState, runtimeDetail)
	}
	return items
}

func policyRequestsFlowOffload(p *openngfwv1.Policy) bool {
	return p != nil && p.GetNetwork().GetEnableFlowOffload()
}

func cliCapabilityState(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetState()
		}
	}
	return ""
}

func cliCapabilityDetail(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetDetail()
		}
	}
	return ""
}

func firstNonEmptyRuntime(items ...string) string {
	for _, item := range items {
		if item != "" {
			return item
		}
	}
	return ""
}

func printRuntimePreflight(cmd *cobra.Command, runtime cliRuntimePreflightResult) {
	cmd.Printf("runtime: %s\n", value(runtime.label))
	for _, item := range runtime.items {
		cmd.Printf("  [%s] %s", strings.ToUpper(value(item.level)), value(item.title))
		if item.detail != "" {
			cmd.Printf(" Action: %s", item.detail)
		}
		cmd.Println()
	}
}

func newVersionsCommand(server *string) *cobra.Command {
	var limit uint32
	cmd := &cobra.Command{
		Use:   "versions",
		Short: "List committed policy versions, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).ListVersions(ctx, &openngfwv1.ListVersionsRequest{Limit: limit})
			if err != nil {
				return err
			}
			if len(resp.GetVersions()) == 0 {
				cmd.Println("no versions committed yet")
				return nil
			}
			for _, v := range resp.GetVersions() {
				cmd.Printf("%-6d %s  %-18s %-16s %s\n",
					v.GetId(), v.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
					actorWithRole(v.GetActor(), v.GetActorRole()), valueOrDash(v.GetAuthSource()), v.GetComment())
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max entries (0 = server default)")
	return cmd
}

func newAuditCommand(server *string) *cobra.Command {
	var limit uint32
	var actor string
	var action string
	var query string
	var since string
	var until string
	var version uint64
	var showHashes bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			req := &openngfwv1.ListAuditEntriesRequest{
				Limit:   limit,
				Actor:   actor,
				Action:  action,
				Query:   query,
				Version: version,
			}
			if since != "" {
				ts, err := parseAuditTimeBound(since, false)
				if err != nil {
					return fmt.Errorf("invalid --since: %w", err)
				}
				req.Since = timestamppb.New(ts)
			}
			if until != "" {
				ts, err := parseAuditTimeBound(until, true)
				if err != nil {
					return fmt.Errorf("invalid --until: %w", err)
				}
				req.Until = timestamppb.New(ts)
			}
			resp, err := openngfwv1.NewPolicyServiceClient(conn).ListAuditEntries(ctx, req)
			if err != nil {
				return err
			}
			if len(resp.GetEntries()) == 0 {
				cmd.Println("audit log is empty")
				return nil
			}
			for _, e := range resp.GetEntries() {
				cmd.Println(auditEntryLine(e, showHashes))
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max entries (0 = server default)")
	cmd.Flags().StringVar(&actor, "actor", "", "filter by actor substring")
	cmd.Flags().StringVar(&action, "action", "", "filter by exact action, e.g. commit or rollback-failed")
	cmd.Flags().StringVar(&query, "query", "", "search actor, role, auth source, action, detail, and version")
	cmd.Flags().Uint64Var(&version, "version", 0, "filter by created version")
	cmd.Flags().StringVar(&since, "since", "", "include entries at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&until, "until", "", "include entries at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().BoolVar(&showHashes, "hashes", false, "show tamper-evident audit hash chain fields")
	cmd.AddCommand(newAuditVerifyCommand(server))
	return cmd
}

func newAuditVerifyCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the tamper-evident audit hash chain",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).VerifyAuditIntegrity(ctx, &openngfwv1.VerifyAuditIntegrityRequest{})
			if err != nil {
				return err
			}
			cmd.Println(auditVerifyLine(resp))
			if !resp.GetOk() {
				return fmt.Errorf("audit integrity verification failed")
			}
			return nil
		},
	}
}

func auditVerifyLine(resp *openngfwv1.VerifyAuditIntegrityResponse) string {
	state := "FAILED"
	if resp.GetOk() {
		state = "OK"
	}
	return fmt.Sprintf("audit integrity: %s entries=%d latest=%s detail=%s",
		state, resp.GetEntryCount(), shortAuditHash(resp.GetLatestEntryHash()), valueOrDash(resp.GetDetail()))
}

func auditEntryLine(e *openngfwv1.AuditEntry, showHashes bool) string {
	line := fmt.Sprintf("%-6d %s  %-18s %-16s %-16s %s",
		e.GetId(), e.GetTime().AsTime().Format("2006-01-02 15:04:05"),
		actorWithRole(e.GetActor(), e.GetActorRole()), valueOrDash(e.GetAuthSource()), e.GetAction(), e.GetDetail())
	if e.GetVersion() != 0 {
		line += fmt.Sprintf(" (version %d)", e.GetVersion())
	}
	if showHashes {
		line += fmt.Sprintf(" hash=%s prev=%s", shortAuditHash(e.GetEntryHash()), previousAuditHashLabel(e.GetPreviousHash()))
	}
	return line
}

func shortAuditHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return "-"
	}
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

func previousAuditHashLabel(hash string) string {
	if strings.TrimSpace(hash) == "" {
		return "genesis"
	}
	return shortAuditHash(hash)
}

func parseAuditTimeBound(value string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", value, time.UTC); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Nanosecond), nil
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("must be RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS'")
}

func actorWithRole(actor, role string) string {
	if actor == "" {
		actor = "-"
	}
	if role == "" {
		return actor
	}
	return actor + "/" + role
}

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newIntelCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Threat-intelligence feeds and blocklists",
	}
	cmd.AddCommand(newIntelFeedsCommand(server), newIntelContentCommand(server), newIntelRefreshCommand(server))
	return cmd
}

func newIntelFeedsCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "feeds",
		Short: "List registry feeds with license constraints and state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewIntelServiceClient(conn).ListFeeds(ctx, &openngfwv1.ListFeedsRequest{})
			if err != nil {
				return err
			}
			for _, f := range resp.GetFeeds() {
				state := "disabled"
				if f.GetEnabled() {
					state = "ENABLED"
				}
				kind := "builtin"
				if f.GetCustom() {
					kind = "custom"
				}
				commercial := "commercial-use:no"
				if f.GetAllowsCommercialUse() {
					commercial = "commercial-use:yes"
				}
				cmd.Printf("%-16s %-8s %-8s %-18s %s\n", f.GetName(), state, kind, commercial, f.GetLicense())
				cmd.Printf("                 %s\n", f.GetDescription())
				if f.GetAttribution() != "" {
					cmd.Printf("                 attribution: %s\n", f.GetAttribution())
				}
			}
			return nil
		},
	}
}

type intelContentClient interface {
	ListContentPackages(context.Context, *openngfwv1.ListContentPackagesRequest, ...grpc.CallOption) (*openngfwv1.ListContentPackagesResponse, error)
}

type intelContentPreviewClient interface {
	PreviewContentPackage(context.Context, *openngfwv1.PreviewContentPackageRequest, ...grpc.CallOption) (*openngfwv1.PreviewContentPackageResponse, error)
}

type intelContentCorpusClient interface {
	GetContentCorpus(context.Context, *openngfwv1.GetContentCorpusRequest, ...grpc.CallOption) (*openngfwv1.GetContentCorpusResponse, error)
}

type intelContentCompareClient interface {
	CompareContentPackage(context.Context, *openngfwv1.CompareContentPackageRequest, ...grpc.CallOption) (*openngfwv1.CompareContentPackageResponse, error)
}

type intelContentInstallClient interface {
	InstallContentPackage(context.Context, *openngfwv1.InstallContentPackageRequest, ...grpc.CallOption) (*openngfwv1.InstallContentPackageResponse, error)
}

type intelContentRollbackClient interface {
	RollbackContentPackage(context.Context, *openngfwv1.RollbackContentPackageRequest, ...grpc.CallOption) (*openngfwv1.RollbackContentPackageResponse, error)
}

func newIntelContentCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "content",
		Short: "Show App-ID, Threat-ID, and feed content package posture",
		Long: `Show App-ID, Threat-ID, and feed content package posture.

Content package install and rollback are audited appliance lifecycle actions.
Feed enablement and custom feeds remain policy candidate changes that must be
committed separately.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContent(ctx, cmd, openngfwv1.NewIntelServiceClient(conn))
		},
	}
	cmd.AddCommand(
		newIntelContentPreviewCommand(server),
		newIntelContentCorpusCommand(server),
		newIntelContentCompareCommand(server),
		newIntelContentInstallCommand(server),
		newIntelContentRollbackCommand(server),
	)
	return cmd
}

func newIntelContentPreviewCommand(server *string) *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "preview KIND --source SERVER_DIR",
		Short: "Preview a package from the firewall content import directory",
		Long: `Preview verifies a package directory that already exists on the
firewall server under the configured content import directory, without
promoting files or writing lifecycle audit entries.

Use an absolute path under that root, or a relative directory name inside it.
This command does not upload files from a browser or operator workstation, and
it does not read arbitrary client-side paths.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if source == "" {
				return fmt.Errorf("--source is required: provide a server-local directory under the configured content import directory")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContentPreview(ctx, cmd, openngfwv1.NewIntelServiceClient(conn), args[0], source)
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "server-local package directory under the configured content import directory")
	return cmd
}

func newIntelContentCorpusCommand(server *string) *cobra.Command {
	var evidenceType string
	var query string
	var verdict string
	var limit uint32
	cmd := &cobra.Command{
		Use:   "corpus KIND",
		Short: "Browse typed regression corpus rows from installed content evidence",
		Long: `Browse normalized regression corpus rows from the installed package's
package-local evidence JSON. The server verifies the evidence artifact against
the signed manifest before returning rows.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContentCorpus(ctx, cmd, openngfwv1.NewIntelServiceClient(conn), args[0], evidenceType, query, verdict, limit)
		},
	}
	cmd.Flags().StringVar(&evidenceType, "evidence-type", "", "corpus evidence type (default is kind-specific)")
	cmd.Flags().StringVar(&query, "query", "", "filter samples by id, app, SID, verdict, PCAP hash, or detail")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter samples by verdict")
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max rows (0 = server default)")
	return cmd
}

func newIntelContentCompareCommand(server *string) *cobra.Command {
	var source string
	var evidenceType string
	cmd := &cobra.Command{
		Use:   "compare KIND --source SERVER_DIR",
		Short: "Compare installed content package with an import candidate",
		Long: `Compare verifies a package directory under the firewall content import
directory and returns installed-vs-candidate package posture plus regression
corpus changes. No files are promoted and no lifecycle audit entry is written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if source == "" {
				return fmt.Errorf("--source is required: provide a server-local directory under the configured content import directory")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContentCompare(ctx, cmd, openngfwv1.NewIntelServiceClient(conn), args[0], source, evidenceType)
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "server-local package directory under the configured content import directory")
	cmd.Flags().StringVar(&evidenceType, "evidence-type", "", "corpus evidence type (default is kind-specific)")
	return cmd
}

func newIntelContentInstallCommand(server *string) *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "install KIND --source SERVER_DIR",
		Short: "Install a verified package from the firewall content import directory",
		Long: `Install verifies and promotes a content package directory that already exists
on the firewall server under the configured content import directory. In
controld's default layout that root is <data-dir>/content-import.

Use an absolute path under that root, or a relative directory name inside it.
This command does not upload files from a browser or operator workstation, and
it does not read arbitrary client-side paths.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if source == "" {
				return fmt.Errorf("--source is required: provide a server-local directory under the configured content import directory")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContentInstall(ctx, cmd, openngfwv1.NewIntelServiceClient(conn), args[0], source)
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "server-local package directory under the configured content import directory")
	return cmd
}

func newIntelContentRollbackCommand(server *string) *cobra.Command {
	var ack bool
	cmd := &cobra.Command{
		Use:   "rollback KIND --ack-rollback",
		Short: "Restore the latest verified content package backup",
		Long: `Restore the latest verified local backup for a content package kind.

Rollback is an audited content lifecycle action. It replaces the installed
package from local package backups and is separate from policy candidate
rollback and commit.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !ack {
				return fmt.Errorf("--ack-rollback is required to restore a previous content package")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runIntelContentRollback(ctx, cmd, openngfwv1.NewIntelServiceClient(conn), args[0])
		},
	}
	cmd.Flags().BoolVar(&ack, "ack-rollback", false, "acknowledge that an audited content lifecycle rollback will replace the installed package")
	return cmd
}

func runIntelContent(ctx context.Context, cmd *cobra.Command, client intelContentClient) error {
	resp, err := client.ListContentPackages(ctx, &openngfwv1.ListContentPackagesRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetPackages()) == 0 {
		cmd.Println("no content package status returned")
		return nil
	}
	for _, p := range resp.GetPackages() {
		printContentPackage(cmd, p)
	}
	return nil
}

func runIntelContentPreview(ctx context.Context, cmd *cobra.Command, client intelContentPreviewClient, kind, source string) error {
	resp, err := client.PreviewContentPackage(ctx, &openngfwv1.PreviewContentPackageRequest{Kind: kind, SourcePath: source})
	if err != nil {
		return err
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	printContentPackage(cmd, resp.GetPackage())
	return nil
}

func runIntelContentCorpus(ctx context.Context, cmd *cobra.Command, client intelContentCorpusClient, kind, evidenceType, query, verdict string, limit uint32) error {
	resp, err := client.GetContentCorpus(ctx, &openngfwv1.GetContentCorpusRequest{
		Kind:         kind,
		EvidenceType: evidenceType,
		Query:        query,
		Verdict:      verdict,
		Limit:        limit,
	})
	if err != nil {
		return err
	}
	cmd.Printf("%s corpus %s package=%s samples=%d failed=%d status=%s\n",
		resp.GetKind(), valueOrDash(resp.GetEvidenceType()), valueOrDash(resp.GetPackageVersion()), resp.GetSampleCount(), resp.GetFailedSamples(), valueOrDash(resp.GetStatus()))
	if resp.GetSummary() != "" {
		cmd.Printf("summary: %s\n", resp.GetSummary())
	}
	if resp.GetManifestSha256() != "" {
		cmd.Printf("manifest-sha256: %s\n", resp.GetManifestSha256())
	}
	if len(resp.GetVerdicts()) > 0 {
		cmd.Printf("verdicts: %s\n", joinComma(resp.GetVerdicts()))
	}
	if len(resp.GetSamples()) == 0 {
		cmd.Println("no corpus samples returned")
		return nil
	}
	for _, sample := range resp.GetSamples() {
		cmd.Printf("%-24s verdict=%-8s expected=%-18s observed=%-18s pcap=%s\n",
			valueOrDash(sample.GetId()),
			valueOrDash(sample.GetVerdict()),
			valueOrDash(sample.GetExpected()),
			valueOrDash(sample.GetObserved()),
			shortCLIHash(sample.GetPcapSha256()))
		if sample.GetDetail() != "" {
			cmd.Printf("                         detail: %s\n", sample.GetDetail())
		}
	}
	return nil
}

func runIntelContentCompare(ctx context.Context, cmd *cobra.Command, client intelContentCompareClient, kind, source, evidenceType string) error {
	resp, err := client.CompareContentPackage(ctx, &openngfwv1.CompareContentPackageRequest{Kind: kind, SourcePath: source, EvidenceType: evidenceType})
	if err != nil {
		return err
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	cmd.Println("installed:")
	printContentPackage(cmd, resp.GetCurrentPackage())
	cmd.Println("preview:")
	printContentPackage(cmd, resp.GetPreviewPackage())
	diff := resp.GetCorpusDiff()
	if diff == nil {
		return nil
	}
	cmd.Printf("corpus-diff %s current=%s/%d samples preview=%s/%d samples added=%d removed=%d changed=%d failed-delta=%+d\n",
		valueOrDash(diff.GetEvidenceType()),
		valueOrDash(diff.GetCurrentPackageVersion()), diff.GetCurrentSampleCount(),
		valueOrDash(diff.GetPreviewPackageVersion()), diff.GetPreviewSampleCount(),
		diff.GetAdded(), diff.GetRemoved(), diff.GetChanged(), diff.GetFailedDelta())
	if diff.GetSummary() != "" {
		cmd.Printf("summary: %s\n", diff.GetSummary())
	}
	for _, sample := range diff.GetSampleDiffs() {
		cmd.Printf("%-8s %-24s current=%s/%s preview=%s/%s\n",
			valueOrDash(sample.GetChange()),
			valueOrDash(sample.GetId()),
			valueOrDash(sample.GetCurrent().GetExpected()),
			valueOrDash(sample.GetCurrent().GetObserved()),
			valueOrDash(sample.GetPreview().GetExpected()),
			valueOrDash(sample.GetPreview().GetObserved()))
	}
	return nil
}

func runIntelContentInstall(ctx context.Context, cmd *cobra.Command, client intelContentInstallClient, kind, source string) error {
	resp, err := client.InstallContentPackage(ctx, &openngfwv1.InstallContentPackageRequest{Kind: kind, SourcePath: source})
	if err != nil {
		return err
	}
	printContentPackageAction(cmd, resp.GetPackage(), resp.GetDetail(), resp.GetRollbackCreated(), resp.GetRollbackPath(), "")
	return nil
}

func runIntelContentRollback(ctx context.Context, cmd *cobra.Command, client intelContentRollbackClient, kind string) error {
	resp, err := client.RollbackContentPackage(ctx, &openngfwv1.RollbackContentPackageRequest{Kind: kind, AckRollback: true})
	if err != nil {
		return err
	}
	printContentPackageAction(cmd, resp.GetPackage(), resp.GetDetail(), resp.GetRollbackCreated(), resp.GetRollbackPath(), resp.GetRestoredRollbackPath())
	return nil
}

func newIntelRefreshCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Fetch enabled feeds now and reprogram the blocklists",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewIntelServiceClient(conn).RefreshFeeds(ctx, &openngfwv1.RefreshFeedsRequest{})
			if err != nil {
				return err
			}
			cmd.Printf("blocklists refreshed: %d entries at %s\n",
				resp.GetEntries(), resp.GetRefreshedAt().AsTime().Format("2006-01-02 15:04:05"))
			return nil
		},
	}
}

func newFlowsCommand(server *string) *cobra.Command {
	var limit uint32
	var srcIP string
	var destIP string
	var ip string
	var protocol string
	var app string
	var query string
	var flowID string
	var since string
	var until string
	var port uint32
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Show recent flows with app/protocol labels, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			req := &openngfwv1.ListFlowsRequest{
				Limit:    limit,
				SrcIp:    srcIP,
				DestIp:   destIP,
				Ip:       ip,
				Protocol: protocol,
				App:      app,
				Port:     port,
				Query:    query,
				FlowId:   flowID,
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
			resp, err := openngfwv1.NewFlowServiceClient(conn).ListFlows(ctx, req)
			if err != nil {
				return err
			}
			if len(resp.GetFlows()) == 0 {
				cmd.Println("no flows recorded (is IDS enabled?)")
				return nil
			}
			printTelemetryPolicyContext(cmd, resp.GetRunningPolicyVersion(), resp.GetPolicyContext())
			for _, f := range resp.GetFlows() {
				app := f.GetAppId()
				if app == "" {
					app = f.GetAppProtocol()
				}
				if app == "" {
					app = "unknown"
				}
				cmd.Printf("%s  %-14s %-6s %s:%d -> %s:%d  bytes=%d/%d pkts=%d confidence=%d%% signal=%s flow_id=%s event_policy=%s\n",
					f.GetTime().AsTime().Format("2006-01-02 15:04:05"),
					app, f.GetProtocol(),
					f.GetSrcIp(), f.GetSrcPort(), f.GetDestIp(), f.GetDestPort(),
					f.GetBytesToServer(), f.GetBytesToClient(), f.GetPackets(),
					f.GetAppConfidence(), valueOrDash(f.GetAppProtocol()), valueOrDash(f.GetFlowId()), eventPolicyVersionLabel(f.GetPolicyVersion(), f.GetPolicyVersionKnown()))
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max flows (0 = server default)")
	cmd.Flags().StringVar(&srcIP, "src-ip", "", "filter by exact source IP")
	cmd.Flags().StringVar(&destIP, "dest-ip", "", "filter by exact destination IP")
	cmd.Flags().StringVar(&ip, "ip", "", "filter by exact source or destination IP")
	cmd.Flags().StringVar(&protocol, "protocol", "", "filter by protocol, e.g. TCP, UDP, ICMP")
	cmd.Flags().StringVar(&app, "app", "", "filter by App-ID, app name, app category, or engine app signal")
	cmd.Flags().Uint32Var(&port, "port", 0, "filter by source or destination port")
	cmd.Flags().StringVar(&query, "query", "", "search endpoints, protocol, app fields, and App-ID evidence")
	cmd.Flags().StringVar(&flowID, "flow-id", "", "filter by exact engine/telemetry flow ID")
	cmd.Flags().StringVar(&since, "since", "", "include flows at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&until, "until", "", "include flows at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	return cmd
}

func printContentPackageAction(cmd *cobra.Command, p *openngfwv1.ContentPackageInfo, detail string, rollbackCreated bool, rollbackPath, restoredRollbackPath string) {
	if detail != "" {
		cmd.Println(detail)
	}
	if restoredRollbackPath != "" {
		cmd.Printf("rollback-restored: %s\n", restoredRollbackPath)
	}
	if rollbackCreated {
		cmd.Printf("rollback-backup: %s\n", rollbackPath)
	}
	if p != nil {
		printContentPackage(cmd, p)
	}
}

func printContentPackage(cmd *cobra.Command, p *openngfwv1.ContentPackageInfo) {
	version := valueOrDash(p.GetVersion())
	signature := valueOrDash(p.GetSignatureStatus())
	regression := valueOrDash(p.GetRegressionStatus())
	rollout := valueOrDash(p.GetRolloutState())
	rollback := "no"
	if p.GetRollbackAvailable() {
		rollback = "yes"
	}
	cmd.Printf("%-12s %-11s version=%-10s signature=%-9s regression=%-8s rollout=%-8s rollback-backup=%s\n",
		p.GetKind(), p.GetState(), version, signature, regression, rollout, rollback)
	if p.GetName() != "" {
		cmd.Printf("             name: %s\n", p.GetName())
	}
	if p.GetSource() != "" {
		cmd.Printf("             source: %s\n", p.GetSource())
	}
	if p.GetManifestSha256() != "" {
		cmd.Printf("             manifest-sha256: %s\n", p.GetManifestSha256())
	}
	if readiness := p.GetContentReadiness(); readiness != nil {
		label := readiness.GetReadinessLabel()
		if label == "" {
			label = readiness.GetEvidenceStatus()
		}
		cmd.Printf("             content-readiness: %s scope=%s production-content=%t production-ready=%t\n",
			valueOrDash(label),
			valueOrDash(readiness.GetScope()),
			readiness.GetProductionContent(),
			readiness.GetProductionReady())
		cmd.Printf("             production-evidence-inventory: %s required=%d attached=%d\n",
			contentProductionEvidenceInventoryStatus(readiness),
			len(readiness.GetRequiredProductionEvidence()),
			len(readiness.GetRequiredProductionEvidence())-len(missingContentEvidence(readiness.GetRequiredProductionEvidence(), readiness.GetEvidence())))
		if readiness.GetReadinessDetail() != "" {
			cmd.Printf("             readiness-detail: %s\n", readiness.GetReadinessDetail())
		}
		printContentReadinessEvidence(cmd, p, readiness)
	}
	if len(p.GetBlockers()) > 0 {
		cmd.Printf("             blockers: %s\n", joinComma(p.GetBlockers()))
	}
	if len(p.GetProvenance()) > 0 {
		cmd.Printf("             provenance: %s\n", provenanceSummary(p.GetProvenance()))
	}
}

func contentProductionEvidenceInventoryStatus(readiness *openngfwv1.ContentReadinessInfo) string {
	if readiness == nil {
		return "missing"
	}
	label := readiness.GetReadinessLabel()
	switch label {
	case "production-ready":
		if readiness.GetProductionReady() && readiness.GetEvidenceStatus() == "passed" && len(readiness.GetBlockers()) == 0 && len(missingContentEvidence(readiness.GetRequiredProductionEvidence(), readiness.GetEvidence())) == 0 {
			return "production-ready"
		}
		return "production-blocked"
	case "demo-only":
		return "demo"
	case "missing-readiness":
		return "missing"
	case "production-blocked":
		return "production-blocked"
	}
	switch readiness.GetEvidenceStatus() {
	case "passed":
		if readiness.GetProductionReady() && len(readiness.GetBlockers()) == 0 && len(missingContentEvidence(readiness.GetRequiredProductionEvidence(), readiness.GetEvidence())) == 0 {
			return "production-ready"
		}
		return "production-blocked"
	case "demo-only":
		return "demo"
	case "missing", "":
		return "missing"
	default:
		return "production-blocked"
	}
}

func printContentReadinessEvidence(cmd *cobra.Command, p *openngfwv1.ContentPackageInfo, readiness *openngfwv1.ContentReadinessInfo) {
	required := readiness.GetRequiredProductionEvidence()
	evidence := readiness.GetEvidence()
	if len(required) > 0 || len(evidence) > 0 {
		missing := missingContentEvidence(required, evidence)
		if len(required) > 0 {
			cmd.Printf("             required-evidence: %d/%d attached", len(required)-len(missing), len(required))
			if len(missing) > 0 {
				cmd.Printf(" missing=%s", joinComma(missing))
			}
		} else {
			cmd.Printf("             evidence-attached: %d", len(evidence))
		}
		cmd.Println()
	}
	for _, ref := range evidence {
		cmd.Printf("             evidence: %s artifact=%s sha256=%s\n",
			valueOrDash(ref.GetType()),
			valueOrDash(ref.GetArtifact()),
			shortCLIHash(ref.GetSha256()))
	}
	for _, action := range contentReadinessCLIPlan(p, readiness) {
		cmd.Printf("             next-action: %s\n", action)
	}
}

func missingContentEvidence(required []string, evidence []*openngfwv1.ContentEvidenceRef) []string {
	if len(required) == 0 {
		return nil
	}
	attached := map[string]bool{}
	for _, ref := range evidence {
		if ref.GetType() != "" && ref.GetArtifact() != "" && ref.GetSha256() != "" {
			attached[ref.GetType()] = true
		}
	}
	missing := make([]string, 0)
	for _, name := range required {
		if !attached[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

func contentReadinessCLIPlan(p *openngfwv1.ContentPackageInfo, readiness *openngfwv1.ContentReadinessInfo) []string {
	kind := p.GetKind()
	if kind == "" {
		kind = "package"
	}
	actions := []string{"ngfwctl intel content"}
	missing := missingContentEvidence(readiness.GetRequiredProductionEvidence(), readiness.GetEvidence())
	if !readiness.GetProductionReady() || readiness.GetEvidenceStatus() != "passed" || len(readiness.GetBlockers()) > 0 || len(missing) > 0 {
		source := "<data-dir>/content-import/" + kind
		actions = append(actions,
			"ngfwctl intel content preview "+kind+" --source "+source,
			"ngfwctl intel content install "+kind+" --source "+source)
	}
	for _, ref := range readiness.GetEvidence() {
		if contentEvidenceIsCorpus(ref.GetType()) {
			actions = append(actions, "ngfwctl intel content corpus "+kind+" --evidence-type "+ref.GetType())
			break
		}
	}
	if p.GetRollbackAvailable() {
		actions = append(actions, "ngfwctl intel content rollback "+kind+" --ack-rollback")
	}
	return actions
}

func contentEvidenceIsCorpus(evidenceType string) bool {
	return strings.Contains(evidenceType, "regression-corpus") ||
		strings.Contains(evidenceType, "parser-tests") ||
		strings.Contains(evidenceType, "false-positive-regression")
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinComma(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	out := values[0]
	for _, value := range values[1:] {
		out += ", " + value
	}
	return out
}

func provenanceSummary(values []*openngfwv1.ContentProvenance) string {
	if len(values) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(values))
	for _, p := range values {
		part := p.GetName()
		if p.GetLicense() != "" {
			part += " (" + p.GetLicense() + ")"
		}
		parts = append(parts, part)
	}
	return joinComma(parts)
}

func shortCLIHash(value string) string {
	if value == "" {
		return "-"
	}
	if len(value) <= 12 {
		return value
	}
	return "sha256:" + value[:12]
}

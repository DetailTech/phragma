package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

type appIDObservationsClient interface {
	ListAppIdObservations(context.Context, *openngfwv1.ListAppIdObservationsRequest, ...grpc.CallOption) (*openngfwv1.ListAppIdObservationsResponse, error)
}

type appIDStageClient interface {
	StageAppIdObservation(context.Context, *openngfwv1.StageAppIdObservationRequest, ...grpc.CallOption) (*openngfwv1.StageAppIdObservationResponse, error)
}

type appIDCorpusClient interface {
	StageAppIdRegressionSample(context.Context, *openngfwv1.StageAppIdRegressionSampleRequest, ...grpc.CallOption) (*openngfwv1.StageAppIdRegressionSampleResponse, error)
}

type appIDObservationOptions struct {
	limit               uint32
	flowLimit           uint32
	confidenceThreshold uint32
	query               string
	kind                string
	engineSignal        string
	protocol            string
	port                uint32
	since               string
	until               string
	outJSON             bool
}

type appIDPromoteOptions struct {
	flowLimit           uint32
	confidenceThreshold uint32
	reason              string
	drop                bool
	confirmDrop         bool
	since               string
	until               string
	appName             string
	displayName         string
	category            string
	engineSignals       []string
	tcpPorts            []string
	udpPorts            []string
	description         string
	outJSON             bool
}

type appIDCorpusAddOptions struct {
	flowLimit           uint32
	confidenceThreshold uint32
	reason              string
	pcapSHA256          string
	expectedApp         string
	observedApp         string
	since               string
	until               string
	outJSON             bool
}

func newAppIDCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app-id",
		Short: "Review Phragma App-ID observation queues",
		Long: "Review unknown, low-confidence, and conflicting App-ID observations derived from recent flow telemetry. " +
			"Suggested application objects are evidence for candidate policy staging; this command does not mutate policy.",
	}
	cmd.AddCommand(newAppIDObservationsCommand(server), newAppIDPromoteCommand(server), newAppIDCorpusCommand(server))
	return cmd
}

func newAppIDObservationsCommand(server *string) *cobra.Command {
	opts := appIDObservationOptions{
		flowLimit:           1000,
		confidenceThreshold: 70,
	}
	cmd := &cobra.Command{
		Use:   "observations",
		Short: "List unknown, low-confidence, and conflicting App-ID observations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAppIDObservations(ctx, cmd, openngfwv1.NewAppIdServiceClient(conn), opts)
		},
	}
	cmd.Flags().Uint32Var(&opts.limit, "limit", 0, "max observations (0 = server default)")
	cmd.Flags().Uint32Var(&opts.flowLimit, "flow-limit", opts.flowLimit, "max recent flows to scan before grouping")
	cmd.Flags().Uint32Var(&opts.confidenceThreshold, "confidence-threshold", opts.confidenceThreshold, "low-confidence threshold percent")
	cmd.Flags().StringVar(&opts.query, "query", "", "search observation, evidence, and suggestion fields")
	cmd.Flags().StringVar(&opts.kind, "kind", "", "filter by observation kind: unknown | low-confidence | conflicting-evidence")
	cmd.Flags().StringVar(&opts.engineSignal, "engine-signal", "", "filter by exact engine-native app signal")
	cmd.Flags().StringVar(&opts.protocol, "protocol", "", "filter by protocol, e.g. TCP, UDP, ICMP")
	cmd.Flags().Uint32Var(&opts.port, "port", 0, "filter by destination port")
	cmd.Flags().StringVar(&opts.since, "since", "", "include observations from flows at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.until, "until", "", "include observations from flows at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newAppIDPromoteCommand(server *string) *cobra.Command {
	opts := appIDPromoteOptions{
		flowLimit:           1000,
		confidenceThreshold: 70,
	}
	cmd := &cobra.Command{
		Use:   "promote QUEUE_ID",
		Short: "Stage an App-ID observation into the candidate policy",
		Long: "Stage the current App-ID observation queue item into the candidate policy. " +
			"By default this defines only the suggested Application object. With --drop and --confirm-drop it also stages a top deny rule using current TCP/UDP port-hint enforcement.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAppIDPromote(ctx, cmd, openngfwv1.NewAppIdServiceClient(conn), args[0], opts)
		},
	}
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required audit reason for candidate staging")
	cmd.Flags().BoolVar(&opts.drop, "drop", false, "also stage a top candidate deny rule using TCP/UDP App-ID port hints")
	cmd.Flags().BoolVar(&opts.confirmDrop, "confirm-drop", false, "acknowledge candidate drop-rule staging")
	cmd.Flags().Uint32Var(&opts.flowLimit, "flow-limit", opts.flowLimit, "max recent flows to scan before looking up QUEUE_ID")
	cmd.Flags().Uint32Var(&opts.confidenceThreshold, "confidence-threshold", opts.confidenceThreshold, "low-confidence threshold percent")
	cmd.Flags().StringVar(&opts.since, "since", "", "include observations from flows at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.until, "until", "", "include observations from flows at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.appName, "app-name", "", "override staged Application name")
	cmd.Flags().StringVar(&opts.displayName, "display-name", "", "override staged Application display name")
	cmd.Flags().StringVar(&opts.category, "category", "", "override staged Application category")
	cmd.Flags().StringSliceVar(&opts.engineSignals, "engine-signal", nil, "override engine signal alias; repeat or comma-separate")
	cmd.Flags().StringSliceVar(&opts.tcpPorts, "tcp-port", nil, "override TCP port hint or range; repeat or comma-separate")
	cmd.Flags().StringSliceVar(&opts.udpPorts, "udp-port", nil, "override UDP port hint or range; repeat or comma-separate")
	cmd.Flags().StringVar(&opts.description, "description", "", "override staged Application description")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newAppIDCorpusCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "corpus",
		Short: "Stage reviewed App-ID regression corpus samples",
	}
	cmd.AddCommand(newAppIDCorpusAddCommand(server))
	return cmd
}

func newAppIDCorpusAddCommand(server *string) *cobra.Command {
	opts := appIDCorpusAddOptions{
		flowLimit:           1000,
		confidenceThreshold: 70,
	}
	cmd := &cobra.Command{
		Use:   "add QUEUE_ID",
		Short: "Append a reviewed App-ID observation to the draft regression corpus",
		Long: "Append one current App-ID observation queue item to the draft App-ID regression corpus. " +
			"The resulting JSONL artifact is package-builder input and is not installed or signed production content.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAppIDCorpusAdd(ctx, cmd, openngfwv1.NewAppIdServiceClient(conn), args[0], opts)
		},
	}
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required review reason for audit and package-builder context")
	cmd.Flags().StringVar(&opts.pcapSHA256, "pcap-sha256", "", "required SHA-256 of the bounded packet capture")
	cmd.Flags().StringVar(&opts.expectedApp, "expected-app", "", "override expected canonical App-ID")
	cmd.Flags().StringVar(&opts.observedApp, "observed-app", "", "override observed App-ID")
	cmd.Flags().Uint32Var(&opts.flowLimit, "flow-limit", opts.flowLimit, "max recent flows to scan before looking up QUEUE_ID")
	cmd.Flags().Uint32Var(&opts.confidenceThreshold, "confidence-threshold", opts.confidenceThreshold, "low-confidence threshold percent")
	cmd.Flags().StringVar(&opts.since, "since", "", "include observations from flows at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.until, "until", "", "include observations from flows at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func runAppIDObservations(ctx context.Context, cmd *cobra.Command, client appIDObservationsClient, opts appIDObservationOptions) error {
	kind, err := parseAppIDObservationKind(opts.kind)
	if err != nil {
		return err
	}
	req := &openngfwv1.ListAppIdObservationsRequest{
		Limit:               opts.limit,
		FlowLimit:           opts.flowLimit,
		ConfidenceThreshold: opts.confidenceThreshold,
		Query:               opts.query,
		Kind:                kind,
		EngineSignal:        opts.engineSignal,
		Protocol:            opts.protocol,
		Port:                opts.port,
	}
	if opts.since != "" {
		ts, err := parseAuditTimeBound(opts.since, false)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		req.Since = timestamppb.New(ts)
	}
	if opts.until != "" {
		ts, err := parseAuditTimeBound(opts.until, true)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		req.Until = timestamppb.New(ts)
	}
	resp, err := client.ListAppIdObservations(ctx, req)
	if err != nil {
		return fmt.Errorf("list App-ID observations: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printAppIDObservations(cmd, resp)
	return nil
}

func runAppIDPromote(ctx context.Context, cmd *cobra.Command, client appIDStageClient, queueID string, opts appIDPromoteOptions) error {
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	override, err := appIDApplicationOverride(opts)
	if err != nil {
		return err
	}
	mode := openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY
	if opts.drop {
		mode = openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP
	}
	req := &openngfwv1.StageAppIdObservationRequest{
		QueueId:             strings.TrimSpace(queueID),
		Mode:                mode,
		Reason:              strings.TrimSpace(opts.reason),
		ConfirmDrop:         opts.confirmDrop,
		FlowLimit:           opts.flowLimit,
		ConfidenceThreshold: opts.confidenceThreshold,
		ApplicationOverride: override,
	}
	if opts.since != "" {
		ts, err := parseAuditTimeBound(opts.since, false)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		req.Since = timestamppb.New(ts)
	}
	if opts.until != "" {
		ts, err := parseAuditTimeBound(opts.until, true)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		req.Until = timestamppb.New(ts)
	}
	resp, err := client.StageAppIdObservation(ctx, req)
	if err != nil {
		return fmt.Errorf("stage App-ID observation: %w", err)
	}
	if opts.outJSON {
		if err := printProtoJSON(cmd, resp); err != nil {
			return err
		}
		if resp.GetValidation() != nil && !resp.GetValidation().GetValid() {
			return fmt.Errorf("App-ID promotion candidate is invalid (%d errors)", len(validationErrors(resp.GetValidation())))
		}
		return nil
	}
	printAppIDPromotion(cmd, resp)
	if resp.GetValidation() != nil && !resp.GetValidation().GetValid() {
		return fmt.Errorf("App-ID promotion candidate is invalid (%d errors)", len(validationErrors(resp.GetValidation())))
	}
	return nil
}

func runAppIDCorpusAdd(ctx context.Context, cmd *cobra.Command, client appIDCorpusClient, queueID string, opts appIDCorpusAddOptions) error {
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	if strings.TrimSpace(opts.pcapSHA256) == "" {
		return fmt.Errorf("--pcap-sha256 is required")
	}
	req := &openngfwv1.StageAppIdRegressionSampleRequest{
		QueueId:             strings.TrimSpace(queueID),
		Reason:              strings.TrimSpace(opts.reason),
		PcapSha256:          strings.TrimSpace(opts.pcapSHA256),
		ExpectedApp:         strings.TrimSpace(opts.expectedApp),
		ObservedApp:         strings.TrimSpace(opts.observedApp),
		FlowLimit:           opts.flowLimit,
		ConfidenceThreshold: opts.confidenceThreshold,
	}
	if opts.since != "" {
		ts, err := parseAuditTimeBound(opts.since, false)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		req.Since = timestamppb.New(ts)
	}
	if opts.until != "" {
		ts, err := parseAuditTimeBound(opts.until, true)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		req.Until = timestamppb.New(ts)
	}
	resp, err := client.StageAppIdRegressionSample(ctx, req)
	if err != nil {
		return fmt.Errorf("stage App-ID regression sample: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printAppIDCorpusAdd(cmd, resp)
	return nil
}

func parseAppIDObservationKind(value string) (openngfwv1.AppIdObservationKind, error) {
	v := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(value, "_", "-")))
	switch v {
	case "":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNSPECIFIED, nil
	case "unknown":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN, nil
	case "low-confidence":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE, nil
	case "conflicting-evidence", "conflict":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE, nil
	case "app-id-observation-kind-unknown":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN, nil
	case "app-id-observation-kind-low-confidence":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE, nil
	case "app-id-observation-kind-conflicting-evidence":
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE, nil
	default:
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNSPECIFIED,
			fmt.Errorf("invalid --kind %q: must be unknown, low-confidence, or conflicting-evidence", value)
	}
}

func printAppIDObservations(cmd *cobra.Command, resp *openngfwv1.ListAppIdObservationsResponse) {
	cmd.Println("App-ID observations")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	printTelemetryPolicyContext(cmd, resp.GetRunningPolicyVersion(), resp.GetPolicyContext())
	if resp.GetAppIdPackageVersion() != "" || resp.GetAppIdPackageManifestSha256() != "" {
		cmd.Printf("app-id-package: version=%s manifest=%s\n", valueOrDash(resp.GetAppIdPackageVersion()), shortAppIDHash(resp.GetAppIdPackageManifestSha256()))
	}
	cmd.Printf("scanned-flows: %d threshold=%d%%\n", resp.GetScannedFlows(), resp.GetConfidenceThreshold())
	if len(resp.GetObservations()) == 0 {
		cmd.Println("no App-ID observations")
		return
	}
	for _, obs := range resp.GetObservations() {
		printAppIDObservation(cmd, obs)
	}
}

func printAppIDObservation(cmd *cobra.Command, obs *openngfwv1.AppIdObservation) {
	kind := appIDObservationKindLabel(obs.GetKind())
	app := valueOrDash(obs.GetAppId())
	if obs.GetAppName() != "" && obs.GetAppName() != obs.GetAppId() {
		app = fmt.Sprintf("%s (%s)", app, obs.GetAppName())
	}
	cmd.Printf("%s  %-21s %-22s confidence=%d%% signal=%s proto=%s dport=%d count=%d bytes=%s pkts=%d\n",
		appIDTimestampLabel(obs.GetLastSeen()),
		kind,
		app,
		obs.GetAppConfidence(),
		valueOrDash(obs.GetEngineSignal()),
		valueOrDash(obs.GetProtocol()),
		obs.GetDestPort(),
		obs.GetCount(),
		humanBytes(obs.GetBytes()),
		obs.GetPackets())
	if obs.GetQueueId() != "" || obs.GetSampleFlowId() != "" || obs.GetSampleSrcIp() != "" || obs.GetSampleDestIp() != "" {
		cmd.Printf("  queue_id=%s flow_id=%s sample=%s -> %s source=%s\n",
			valueOrDash(obs.GetQueueId()),
			valueOrDash(obs.GetSampleFlowId()),
			captureEndpoint(obs.GetSampleSrcIp(), obs.GetSampleSrcPort()),
			valueOrDash(obs.GetSampleDestIp()),
			valueOrDash(obs.GetEngineSignalSource()))
	}
	if suggested := obs.GetSuggestedApplication(); suggested != nil && suggested.GetName() != "" {
		cmd.Printf("  suggested: %s display=%s category=%s signals=%s ports=%s\n",
			suggested.GetName(),
			valueOrDash(suggested.GetDisplayName()),
			valueOrDash(suggested.GetCategory()),
			joinComma(suggested.GetEngineSignals()),
			appIDApplicationPorts(suggested.GetPorts()))
	}
	if evidence := obs.GetAppEvidence(); len(evidence) > 0 {
		cmd.Printf("  evidence: %s\n", joinComma(evidence))
	}
}

func printAppIDPromotion(cmd *cobra.Command, resp *openngfwv1.StageAppIdObservationResponse) {
	cmd.Println("App-ID observation staged")
	if obs := resp.GetObservation(); obs != nil {
		cmd.Printf("queue: %s kind=%s signal=%s proto=%s dport=%d count=%d\n",
			valueOrDash(obs.GetQueueId()),
			appIDObservationKindLabel(obs.GetKind()),
			valueOrDash(obs.GetEngineSignal()),
			valueOrDash(obs.GetProtocol()),
			obs.GetDestPort(),
			obs.GetCount())
	}
	app := resp.GetApplication()
	if app != nil {
		reused := ""
		if resp.GetApplicationReused() {
			reused = " reused"
		}
		cmd.Printf("application%s: %s display=%s category=%s signals=%s ports=%s\n",
			reused,
			valueOrDash(app.GetName()),
			valueOrDash(app.GetDisplayName()),
			valueOrDash(app.GetCategory()),
			joinComma(app.GetEngineSignals()),
			appIDApplicationPorts(app.GetPorts()))
	}
	if rule := resp.GetRule(); rule != nil && rule.GetName() != "" {
		cmd.Printf("rule: %s action=%s applications=%s source=%s destination=%s\n",
			rule.GetName(),
			shortEnum(rule.GetAction().String(), "ACTION_"),
			joinComma(rule.GetApplications()),
			joinComma(rule.GetSourceAddresses()),
			joinComma(rule.GetDestinationAddresses()))
	}
	if validation := resp.GetValidation(); validation != nil {
		if validation.GetValid() {
			cmd.Println("validation: valid")
			printRenderPlan(cmd, validation.GetRenderPlan())
		} else {
			cmd.Println("validation: invalid; candidate was not stored")
			for _, e := range validationErrors(validation) {
				cmd.PrintErrln("error: " + e)
			}
			printValidationFindings(cmd, validation)
		}
		printImpact(cmd, validation.GetImpact())
	}
	if status := resp.GetCandidateStatus(); status != nil {
		cmd.Printf("candidate: dirty=%t changes=%d running=v%d\n", status.GetDirty(), status.GetChangeCount(), status.GetRunningVersion())
	}
	if diff := resp.GetDiff(); diff != nil && diff.GetChanged() {
		cmd.Printf("diff: %s -> %s (%d lines)\n", diff.GetFromLabel(), diff.GetToLabel(), len(diff.GetLines()))
	}
	if resp.GetValidation() == nil || resp.GetValidation().GetValid() {
		cmd.Println("run 'ngfwctl policy validate' then 'ngfwctl commit' after review")
	}
}

func printAppIDCorpusAdd(cmd *cobra.Command, resp *openngfwv1.StageAppIdRegressionSampleResponse) {
	cmd.Println("App-ID regression sample staged")
	if obs := resp.GetObservation(); obs != nil {
		cmd.Printf("queue: %s kind=%s signal=%s proto=%s dport=%d count=%d\n",
			valueOrDash(obs.GetQueueId()),
			appIDObservationKindLabel(obs.GetKind()),
			valueOrDash(obs.GetEngineSignal()),
			valueOrDash(obs.GetProtocol()),
			obs.GetDestPort(),
			obs.GetCount())
	}
	if sample := resp.GetSample(); sample != nil {
		cmd.Printf("sample: %s expected=%s observed=%s pcap=%s reason=%s\n",
			valueOrDash(sample.GetSampleId()),
			valueOrDash(sample.GetExpectedApp()),
			valueOrDash(sample.GetObservedApp()),
			shortAppIDHash(sample.GetPcapSha256()),
			valueOrDash(sample.GetReason()))
	}
	cmd.Printf("artifact: %s samples=%d\n", valueOrDash(resp.GetDraftArtifact()), resp.GetSampleCount())
	if resp.GetAppIdPackageVersion() != "" || resp.GetAppIdPackageManifestSha256() != "" {
		cmd.Printf("app-id-package: version=%s manifest=%s\n", valueOrDash(resp.GetAppIdPackageVersion()), shortAppIDHash(resp.GetAppIdPackageManifestSha256()))
	}
	cmd.Println("build, sign, and compare an App-ID content package before production install")
}

func appIDObservationKindLabel(kind openngfwv1.AppIdObservationKind) string {
	if kind == openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNSPECIFIED {
		return "unspecified"
	}
	return shortEnum(kind.String(), "APP_ID_OBSERVATION_KIND_")
}

func appIDTimestampLabel(ts *timestamppb.Timestamp) string {
	if ts == nil || !ts.IsValid() {
		return "-"
	}
	return ts.AsTime().Format("2006-01-02 15:04:05")
}

func appIDApplicationPorts(ports []*openngfwv1.ApplicationPort) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		proto := strings.ToLower(shortEnum(port.GetProtocol().String(), "PROTOCOL_"))
		if proto == "unspecified" || proto == "" {
			proto = "any"
		}
		ranges := make([]string, 0, len(port.GetPorts()))
		for _, pr := range port.GetPorts() {
			if pr.GetEnd() != 0 && pr.GetEnd() != pr.GetStart() {
				ranges = append(ranges, fmt.Sprintf("%d-%d", pr.GetStart(), pr.GetEnd()))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d", pr.GetStart()))
			}
		}
		parts = append(parts, fmt.Sprintf("%s/%s", proto, strings.Join(ranges, ",")))
	}
	return strings.Join(parts, ";")
}

func appIDApplicationOverride(opts appIDPromoteOptions) (*openngfwv1.Application, error) {
	hasOverride := strings.TrimSpace(opts.appName) != "" ||
		strings.TrimSpace(opts.displayName) != "" ||
		strings.TrimSpace(opts.category) != "" ||
		len(opts.engineSignals) > 0 ||
		len(opts.tcpPorts) > 0 ||
		len(opts.udpPorts) > 0 ||
		strings.TrimSpace(opts.description) != ""
	if !hasOverride {
		return nil, nil
	}
	if strings.TrimSpace(opts.appName) == "" {
		return nil, fmt.Errorf("--app-name is required when overriding the suggested Application")
	}
	app := &openngfwv1.Application{
		Name:          strings.TrimSpace(opts.appName),
		DisplayName:   strings.TrimSpace(opts.displayName),
		Category:      strings.TrimSpace(opts.category),
		EngineSignals: cleanStringSlice(opts.engineSignals),
		Description:   strings.TrimSpace(opts.description),
	}
	tcp, err := appIDPortRanges(opts.tcpPorts)
	if err != nil {
		return nil, fmt.Errorf("invalid --tcp-port: %w", err)
	}
	if len(tcp) > 0 {
		app.Ports = append(app.Ports, &openngfwv1.ApplicationPort{Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: tcp})
	}
	udp, err := appIDPortRanges(opts.udpPorts)
	if err != nil {
		return nil, fmt.Errorf("invalid --udp-port: %w", err)
	}
	if len(udp) > 0 {
		app.Ports = append(app.Ports, &openngfwv1.ApplicationPort{Protocol: openngfwv1.Protocol_PROTOCOL_UDP, Ports: udp})
	}
	return app, nil
}

func appIDPortRanges(values []string) ([]*openngfwv1.PortRange, error) {
	var out []*openngfwv1.PortRange
	for _, value := range cleanStringSlice(values) {
		startText, endText, hasRange := strings.Cut(value, "-")
		start, err := strconv.ParseUint(strings.TrimSpace(startText), 10, 32)
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("%q is not a valid port", value)
		}
		pr := &openngfwv1.PortRange{Start: uint32(start)}
		if hasRange {
			end, err := strconv.ParseUint(strings.TrimSpace(endText), 10, 32)
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("%q is not a valid port range", value)
			}
			if end != start {
				pr.End = uint32(end)
			}
		}
		out = append(out, pr)
	}
	return out, nil
}

func cleanStringSlice(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			text := strings.TrimSpace(part)
			if text == "" || seen[text] {
				continue
			}
			seen[text] = true
			out = append(out, text)
		}
	}
	return out
}

func shortAppIDHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16]
	}
	return valueOrDash(hash)
}

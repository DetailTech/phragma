package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	httpbody "google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/replayvalidation"
	"github.com/detailtech/oss-ngfw/internal/tuning"
)

var (
	releaseStatusLocalPathRE = regexp.MustCompile(`(?i)(^|[\s"'({=,;])/(?:var/lib|var/log(?:/openngfw)?|etc/(?:openngfw|phragma)|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+|opt/[^'"\s,;}]+|data/[^'"\s,;}]+)[^'"\s,;}]*`)
	releaseStatusSecretRE    = regexp.MustCompile(`(?i)(^|[?&\s"',;])(-{0,2}(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)[=:])[^&\s"',;]+`)
	releaseStatusBearerRE    = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}`)
)

type systemTuneOptions struct {
	configPath string
	profile    string
	sysctlRoot string
	write      bool
	apply      bool
	run        tuning.Runner
}

type systemCaptureOptions struct {
	iface           string
	protocol        string
	srcIP           string
	srcPort         uint32
	destIP          string
	destPort        uint32
	durationSeconds uint32
	packetCount     uint32
	snaplenBytes    uint32
	label           string
	flowID          string
	start           bool
	ackCapture      bool
	limit           uint32
	artifactID      string
	outputPath      string
	retainUntil     string
	retentionReason string
	caseID          string
	ackRetention    bool
	outJSON         bool
}

type systemHAOptions struct {
	comment            string
	ackPull            bool
	ackFailover        bool
	ackExternalCutover bool
	ackExternalFencing bool
	ackRisk            bool
	ackRuntime         bool
	outJSON            bool
}

type systemTelemetryOptions struct {
	outJSON bool
}

type systemLogsOptions struct {
	limit    uint32
	source   string
	engine   string
	severity string
	query    string
	since    string
	until    string
	outJSON  bool
}

type systemEbpfReadinessOptions struct {
	outJSON bool
}

type systemReleaseAcceptanceOptions struct {
	outJSON bool
}

type systemNetworkPathOptions struct {
	srcIP               string
	destIP              string
	protocol            string
	destPort            uint32
	sourceInterface     string
	tunnelKind          string
	tunnelName          string
	tunnelInterface     string
	tunnelPeer          string
	tunnelPeerPublicKey string
	outJSON             bool
}

type systemAutomationReplayOptions struct {
	recordingPath     string
	runbookPath       string
	candidateRevision string
	mode              string
	ackAuthority      bool
	ackNoLiveApply    bool
	ackCandidateOnly  bool
	ackRevision       bool
	ackReadOnly       bool
	outJSON           bool
}

type systemCaptureClient interface {
	PlanPacketCapture(context.Context, *openngfwv1.PlanPacketCaptureRequest, ...grpc.CallOption) (*openngfwv1.PlanPacketCaptureResponse, error)
	StartPacketCapture(context.Context, *openngfwv1.StartPacketCaptureRequest, ...grpc.CallOption) (*openngfwv1.StartPacketCaptureResponse, error)
	ListPacketCaptures(context.Context, *openngfwv1.ListPacketCapturesRequest, ...grpc.CallOption) (*openngfwv1.ListPacketCapturesResponse, error)
	DownloadPacketCapture(context.Context, *openngfwv1.DownloadPacketCaptureRequest, ...grpc.CallOption) (*httpbody.HttpBody, error)
	SetPacketCaptureRetention(context.Context, *openngfwv1.SetPacketCaptureRetentionRequest, ...grpc.CallOption) (*openngfwv1.SetPacketCaptureRetentionResponse, error)
}

type systemHAClient interface {
	GetHighAvailabilityStatus(context.Context, *openngfwv1.GetHighAvailabilityStatusRequest, ...grpc.CallOption) (*openngfwv1.GetHighAvailabilityStatusResponse, error)
	PullHighAvailabilityPolicy(context.Context, *openngfwv1.PullHighAvailabilityPolicyRequest, ...grpc.CallOption) (*openngfwv1.PullHighAvailabilityPolicyResponse, error)
	ActivateHighAvailabilityFailover(context.Context, *openngfwv1.ActivateHighAvailabilityFailoverRequest, ...grpc.CallOption) (*openngfwv1.ActivateHighAvailabilityFailoverResponse, error)
}

type systemTelemetryClient interface {
	GetTelemetryExportStatus(context.Context, *openngfwv1.GetTelemetryExportStatusRequest, ...grpc.CallOption) (*openngfwv1.GetTelemetryExportStatusResponse, error)
}

type systemLogsClient interface {
	ListSystemLogs(context.Context, *openngfwv1.ListSystemLogsRequest, ...grpc.CallOption) (*openngfwv1.ListSystemLogsResponse, error)
}

type systemStatusClient interface {
	GetStatus(context.Context, *openngfwv1.GetStatusRequest, ...grpc.CallOption) (*openngfwv1.GetStatusResponse, error)
}

type systemReleaseAcceptanceClient interface {
	GetReleaseAcceptanceStatus(context.Context, *openngfwv1.GetReleaseAcceptanceStatusRequest, ...grpc.CallOption) (*openngfwv1.GetReleaseAcceptanceStatusResponse, error)
}

type systemNetworkPathClient interface {
	ProveNetworkPath(context.Context, *openngfwv1.ProveNetworkPathRequest, ...grpc.CallOption) (*openngfwv1.ProveNetworkPathResponse, error)
}

func newSystemCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Operate on the local firewall host",
	}
	cmd.AddCommand(
		newSystemTuneCommand(),
		newSystemHACommand(server),
		newSystemEbpfReadinessCommand(server),
		newSystemReleaseAcceptanceStatusCommand(server),
		newSystemTelemetryExportStatusCommand(server),
		newSystemLogsCommand(server),
		newSystemNetworkPathCommand(server),
		newSystemCaptureCommand(server),
		newSystemAutomationCommand(),
	)
	return cmd
}

func newSystemAutomationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automation",
		Short: "Inspect automation replay runbooks and prepare bounded replay requests",
	}
	cmd.AddCommand(newSystemAutomationReplayCommand())
	return cmd
}

func newSystemAutomationReplayCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Validate bounded automation replay authority",
	}
	cmd.AddCommand(newSystemAutomationReplayPlanCommand())
	return cmd
}

func newSystemAutomationReplayPlanCommand() *cobra.Command {
	opts := systemAutomationReplayOptions{mode: "dry-run", outJSON: true}
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Create a bounded replay dry-run or apply-authority plan",
		Long: "Create a replay validation and execution-authority plan from a browser recording or shell runbook. " +
			"Mode execute emits the server request shape for the audited bounded executor, but this local command does not execute HTTP, gRPC, CLI, shell, candidate, running-policy, host-runtime, packet-capture, HA, commit, rollback, or live apply steps.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSystemAutomationReplayPlan(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.recordingPath, "recording", "", "browser automation recording JSON file")
	cmd.Flags().StringVar(&opts.runbookPath, "runbook", "", "shell runbook text file")
	cmd.Flags().StringVar(&opts.candidateRevision, "candidate-revision", "", "expected candidate revision for candidate-only replay authority")
	cmd.Flags().StringVar(&opts.mode, "mode", opts.mode, "replay mode: validate | dry-run | apply-authority | execute")
	cmd.Flags().BoolVar(&opts.ackAuthority, "ack-replay-authority", false, "acknowledge bounded replay authority review")
	cmd.Flags().BoolVar(&opts.ackNoLiveApply, "ack-no-live-apply", false, "acknowledge replay will not execute destructive/live apply steps")
	cmd.Flags().BoolVar(&opts.ackCandidateOnly, "ack-candidate-only-replay", false, "acknowledge candidate-only replay authority")
	cmd.Flags().BoolVar(&opts.ackRevision, "ack-candidate-revision", false, "acknowledge candidate revision binding")
	cmd.Flags().BoolVar(&opts.ackReadOnly, "ack-read-only-replay", false, "acknowledge read-only replay authority")
	cmd.Flags().BoolVar(&opts.outJSON, "json", opts.outJSON, "output JSON")
	return cmd
}

func newSystemNetworkPathCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network-path",
		Short: "Prove passive server-side network path evidence",
	}
	cmd.AddCommand(newSystemNetworkPathProveCommand(server))
	return cmd
}

func newSystemNetworkPathProveCommand(server *string) *cobra.Command {
	opts := systemNetworkPathOptions{protocol: "any"}
	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Sample passive route and VPN runtime evidence for one path",
		Long: "Sample passive server-side evidence for one representative path. " +
			"The API runs a fixed kernel route lookup and optional VPN runtime correlation; " +
			"it does not send active probes, start packet capture, attest the remote peer, or create signed custody.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemNetworkPathProve(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.srcIP, "src", "", "representative source IP address")
	cmd.Flags().StringVar(&opts.destIP, "dst", "", "representative destination IP address")
	cmd.Flags().StringVar(&opts.protocol, "protocol", opts.protocol, "protocol: tcp | udp | icmp | any")
	cmd.Flags().Uint32Var(&opts.destPort, "dport", 0, "destination port")
	cmd.Flags().StringVar(&opts.sourceInterface, "source-interface", "", "expected source interface")
	cmd.Flags().StringVar(&opts.tunnelKind, "tunnel-kind", "", "VPN tunnel kind: wireguard | ipsec")
	cmd.Flags().StringVar(&opts.tunnelName, "tunnel-name", "", "IPsec tunnel name or display label")
	cmd.Flags().StringVar(&opts.tunnelInterface, "tunnel-interface", "", "WireGuard interface name")
	cmd.Flags().StringVar(&opts.tunnelPeer, "tunnel-peer", "", "VPN peer display name")
	cmd.Flags().StringVar(&opts.tunnelPeerPublicKey, "tunnel-peer-public-key", "", "WireGuard peer public key")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemReleaseAcceptanceStatusCommand(server *string) *cobra.Command {
	opts := systemReleaseAcceptanceOptions{}
	cmd := &cobra.Command{
		Use:   "release-acceptance-status",
		Short: "Show release acceptance evidence status",
		Long: "Show the release acceptance manifest, evidence summary, per-check status, and " +
			"source-tree recordability advisory reported by the appliance API. This command is read-only " +
			"and does not record evidence or change release state.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemReleaseAcceptanceStatus(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemLogsCommand(server *string) *cobra.Command {
	opts := systemLogsOptions{limit: 200}
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show bounded redacted system and engine logs",
		Long: "Show bounded, redacted OpenNGFW appliance and engine logs from the server-configured log root. " +
			"Clients can filter source, engine, severity, query, and time range but cannot choose filesystem paths.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemLogs(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().Uint32Var(&opts.limit, "limit", opts.limit, "maximum rows to return")
	cmd.Flags().StringVar(&opts.source, "source", "", "source filter: system | engine | dataplane | audit")
	cmd.Flags().StringVar(&opts.engine, "engine", "", "engine filter, such as suricata, vector, frr, wireguard, or nftables")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "severity filter: critical | error | warn | notice | info | debug")
	cmd.Flags().StringVar(&opts.query, "query", "", "case-insensitive message search")
	cmd.Flags().StringVar(&opts.since, "since", "", "RFC3339 lower time bound")
	cmd.Flags().StringVar(&opts.until, "until", "", "RFC3339 upper time bound")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemEbpfReadinessCommand(server *string) *cobra.Command {
	opts := systemEbpfReadinessOptions{}
	cmd := &cobra.Command{
		Use:   "ebpf-readiness",
		Short: "Show eBPF host, attach, renderer, and field-evidence readiness",
		Long: "Show the existing eBPF readiness contract reported by controld: host probes, " +
			"XDP/tc attach prerequisites, renderer scope, runtime attachments, and indexed field-evidence artifacts. " +
			"This command is read-only and does not compile, attach, detach, pin maps, or make eBPF the active dataplane.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemEbpfReadiness(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemTelemetryExportStatusCommand(server *string) *cobra.Command {
	opts := systemTelemetryOptions{}
	cmd := &cobra.Command{
		Use:   "telemetry-export-status",
		Short: "Show passive telemetry export posture",
		Long: "Show passive telemetry export posture from the running policy, Vector runtime state, " +
			"and local JSON export file metadata. The command does not emit test events or dial remote SIEM receivers.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemTelemetryExportStatus(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemHACommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ha",
		Short: "Operate active/passive high availability workflows",
	}
	cmd.AddCommand(newSystemHAStatusCommand(server), newSystemHAPullPolicyCommand(server), newSystemHAActivatePassiveCommand(server))
	return cmd
}

func newSystemHAStatusCommand(server *string) *cobra.Command {
	opts := systemHAOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show active/passive HA readiness and cutover evidence",
		Long: "Show the active/passive HA status, policy sync posture, automatic replication state, " +
			"manual failover eligibility, and the operator cutover evidence needed before VIP, route, " +
			"traffic, or peer-fencing actions. This command is read-only and does not move traffic.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemHAStatus(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "print raw JSON response")
	return cmd
}

func newSystemHAPullPolicyCommand(server *string) *cobra.Command {
	opts := systemHAOptions{}
	cmd := &cobra.Command{
		Use:   "pull-policy",
		Short: "Pull the active peer policy onto this passive node",
		Long: "Pull the active peer's running policy onto this passive node through the audited " +
			"policy apply path. The server verifies active/passive role, fresh peer heartbeat, " +
			"newer peer version, and local candidate state before applying.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemHAPullPolicy(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVarP(&opts.comment, "message", "m", "", "audit comment for the HA policy pull")
	cmd.Flags().BoolVar(&opts.ackPull, "ack-pull", false, "acknowledge replacing local running policy from the active peer")
	cmd.Flags().BoolVar(&opts.ackRisk, "ack-risk", false, "acknowledge high-risk policy impact if reported")
	cmd.Flags().BoolVar(&opts.ackRuntime, "ack-runtime", false, "acknowledge runtime readiness warnings if reported")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "print raw JSON response")
	return cmd
}

func newSystemHAActivatePassiveCommand(server *string) *cobra.Command {
	opts := systemHAOptions{}
	cmd := &cobra.Command{
		Use:   "activate-passive",
		Short: "Mark this passive node active after manual HA failover",
		Long: "Mark this passive node active in durable node-local HA state after the server verifies " +
			"active/passive readiness, synchronized policy/LKG metadata, and clean candidate state. " +
			"This does not move VIPs or routes, fence the peer, or synchronize connection state.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemHAActivatePassive(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVarP(&opts.comment, "message", "m", "", "audit comment for the HA failover activation")
	cmd.Flags().BoolVar(&opts.ackFailover, "ack-failover", false, "acknowledge marking this passive node active")
	cmd.Flags().BoolVar(&opts.ackExternalCutover, "ack-external-cutover", false, "acknowledge VIP/route/traffic cutover is external")
	cmd.Flags().BoolVar(&opts.ackExternalFencing, "ack-external-fencing", false, "acknowledge peer fencing is external")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "print raw JSON response")
	return cmd
}

func newSystemTuneCommand() *cobra.Command {
	opts := systemTuneOptions{
		configPath: tuning.DefaultConfigPath,
		profile:    tuning.DefaultProfile,
		sysctlRoot: tuning.DefaultSysctlRoot,
	}
	cmd := &cobra.Command{
		Use:   "tune",
		Short: "Print, write, or apply the OpenNGFW appliance sysctl baseline",
		Long: "Print, write, or apply the Linux sysctl baseline required for routed forwarding, " +
			"conntrack headroom, and high-throughput virtual firewall operation.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSystemTune(cmd.Context(), cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.configPath, "config-path", opts.configPath, "persistent sysctl config path")
	cmd.Flags().StringVar(&opts.profile, "profile", opts.profile, "tuning profile: appliance | throughput")
	cmd.Flags().BoolVar(&opts.write, "write", false, "write the persistent sysctl config")
	cmd.Flags().BoolVar(&opts.apply, "apply", false, "apply exposed sysctl values to the live kernel")
	cmd.Flags().StringVar(&opts.sysctlRoot, "sysctl-root", opts.sysctlRoot, "proc sysctl root")
	_ = cmd.Flags().MarkHidden("sysctl-root")
	return cmd
}

func newSystemCaptureCommand(server *string) *cobra.Command {
	opts := systemCaptureOptions{
		iface:           "any",
		protocol:        "any",
		durationSeconds: 20,
		packetCount:     500,
		snaplenBytes:    256,
		label:           "flow",
	}
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Plan or start a bounded packet capture through the audited API",
		Long: "Plan or start a bounded tcpdump capture on the firewall host. " +
			"Planning is read-only. Starting a capture requires --start and --ack-capture, " +
			"and the server still enforces admin RBAC, dry-run refusal, scope, and audit logging.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemCapture(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.iface, "interface", opts.iface, "interface to capture on, or any")
	cmd.Flags().StringVar(&opts.protocol, "protocol", opts.protocol, "protocol: tcp | udp | icmp | any")
	cmd.Flags().StringVar(&opts.srcIP, "src", "", "source IP address")
	cmd.Flags().Uint32Var(&opts.srcPort, "sport", 0, "source port")
	cmd.Flags().StringVar(&opts.destIP, "dst", "", "destination IP address")
	cmd.Flags().Uint32Var(&opts.destPort, "dport", 0, "destination port")
	cmd.Flags().Uint32Var(&opts.durationSeconds, "duration", opts.durationSeconds, "capture duration seconds")
	cmd.Flags().Uint32Var(&opts.packetCount, "packets", opts.packetCount, "maximum packet count")
	cmd.Flags().Uint32Var(&opts.snaplenBytes, "snaplen", opts.snaplenBytes, "snap length bytes")
	cmd.Flags().StringVar(&opts.label, "label", opts.label, "human label used for the output filename")
	cmd.Flags().StringVar(&opts.flowID, "flow-id", "", "telemetry flow identifier to preserve with capture metadata")
	cmd.Flags().BoolVar(&opts.start, "start", false, "start the capture instead of only planning it")
	cmd.Flags().BoolVar(&opts.ackCapture, "ack-capture", false, "acknowledge starting host packet capture; required with --start")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	cmd.AddCommand(
		newSystemCaptureListCommand(server),
		newSystemCaptureDownloadCommand(server),
		newSystemCaptureRetainCommand(server),
		newSystemCaptureReleaseCommand(server),
	)
	return cmd
}

func newSystemCaptureListCommand(server *string) *cobra.Command {
	opts := systemCaptureOptions{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List packet capture artifacts available for download",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemCaptureList(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().Uint32Var(&opts.limit, "limit", 0, "maximum artifacts to return; 0 uses the server default")
	cmd.Flags().StringVar(&opts.flowID, "flow-id", "", "only list captures with this telemetry flow identifier")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemCaptureDownloadCommand(server *string) *cobra.Command {
	opts := systemCaptureOptions{}
	cmd := &cobra.Command{
		Use:   "download <artifact-id>",
		Short: "Download one packet capture artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.artifactID = args[0]
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemCaptureDownload(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "local path for the downloaded pcap")
	return cmd
}

func newSystemCaptureRetainCommand(server *string) *cobra.Command {
	opts := systemCaptureOptions{}
	cmd := &cobra.Command{
		Use:   "retain <artifact-id>",
		Short: "Retain a packet capture artifact until a UTC timestamp",
		Long: "Record non-destructive retention metadata for an existing packet capture artifact. " +
			"The server updates only the capture sidecar, writes an audit entry, and requires acknowledgement.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.artifactID = args[0]
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemCaptureRetention(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED)
		},
	}
	cmd.Flags().StringVar(&opts.retainUntil, "retain-until", "", "future UTC RFC3339 timestamp ending in Z")
	cmd.Flags().StringVar(&opts.retentionReason, "reason", "", "bounded audit reason for retaining capture metadata")
	cmd.Flags().StringVar(&opts.caseID, "case-id", "", "optional incident or case label")
	cmd.Flags().BoolVar(&opts.ackRetention, "ack-retention-change", false, "acknowledge changing packet capture evidence metadata")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newSystemCaptureReleaseCommand(server *string) *cobra.Command {
	opts := systemCaptureOptions{}
	cmd := &cobra.Command{
		Use:   "release <artifact-id>",
		Short: "Release packet capture retention metadata",
		Long: "Release non-destructive retention metadata for an existing packet capture artifact. " +
			"The server updates only the capture sidecar, writes an audit entry, and requires acknowledgement.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.artifactID = args[0]
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runSystemCaptureRetention(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED)
		},
	}
	cmd.Flags().StringVar(&opts.retentionReason, "reason", "", "bounded audit reason for releasing capture retention")
	cmd.Flags().StringVar(&opts.caseID, "case-id", "", "optional incident or case label")
	cmd.Flags().BoolVar(&opts.ackRetention, "ack-retention-change", false, "acknowledge changing packet capture evidence metadata")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func runSystemTune(ctx context.Context, cmd *cobra.Command, opts systemTuneOptions) error {
	text, err := tuning.ConfigTextForProfile(opts.profile)
	if err != nil {
		return err
	}
	cmd.Println("OpenNGFW appliance sysctl baseline:")
	cmd.Print(text)
	if !opts.write && !opts.apply {
		cmd.Println("No changes made. Re-run with --write to install the profile, --apply to update the live kernel, or both.")
		return nil
	}
	if opts.write {
		if err := tuning.WriteConfigForProfile(opts.configPath, opts.profile); err != nil {
			return err
		}
		cmd.Printf("wrote %s\n", opts.configPath)
	}
	if opts.apply {
		results, err := tuning.ApplyLiveProfile(ctx, opts.sysctlRoot, opts.profile, opts.run)
		if err != nil {
			return err
		}
		printTuneResults(cmd, results)
	}
	cmd.Println("Verify with: ngfwctl status")
	return nil
}

func runSystemAutomationReplayPlan(cmd *cobra.Command, opts systemAutomationReplayOptions) error {
	if strings.TrimSpace(opts.recordingPath) == "" && strings.TrimSpace(opts.runbookPath) == "" {
		return fmt.Errorf("--recording or --runbook is required")
	}
	if strings.TrimSpace(opts.recordingPath) != "" && strings.TrimSpace(opts.runbookPath) != "" {
		return fmt.Errorf("use only one of --recording or --runbook")
	}
	req := replayvalidation.Request{
		ExecutionMode:            opts.mode,
		CandidateRevision:        strings.TrimSpace(opts.candidateRevision),
		RequireAcknowledgements:  boolPtr(true),
		RequireCandidateRevision: boolPtr(true),
		Acknowledgements: map[string]bool{
			"ackReplayAuthority":     opts.ackAuthority,
			"ackReplayNoLiveApply":   opts.ackNoLiveApply,
			"ackCandidateOnlyReplay": opts.ackCandidateOnly,
			"ackCandidateRevision":   opts.ackRevision,
			"ackReadOnlyReplay":      opts.ackReadOnly,
		},
	}
	if path := strings.TrimSpace(opts.recordingPath); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read recording: %w", err)
		}
		req.Recording = json.RawMessage(raw)
	}
	if path := strings.TrimSpace(opts.runbookPath); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read runbook: %w", err)
		}
		req.Runbook = string(raw)
	}
	report := replayvalidation.Validate(req, replayvalidation.State{
		CandidateRevision:  strings.TrimSpace(opts.candidateRevision),
		ExpectedRevision:   strings.TrimSpace(opts.candidateRevision),
		Source:             "cli-local",
		CurrentStateLoaded: false,
	}, time.Now().UTC())
	if opts.outJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	plan := report.ExecutionPlan
	mode := "validate"
	if plan != nil {
		mode = plan.Mode
	}
	cmd.Printf("replay plan: mode=%s blocked=%t executable=%d\n", value(mode), report.Summary.Blocked, report.Summary.ExecutableStepCount)
	if plan != nil {
		cmd.Printf("authority: requested=%t granted=%t read-only=%d candidate-only=%d blocked=%d\n",
			plan.AuthorityRequested, plan.AuthorityGranted, plan.ReadOnlySteps, plan.CandidateOnlySteps, plan.BlockedSteps)
		if len(plan.MissingAcks) > 0 {
			cmd.Printf("missing acknowledgements: %s\n", strings.Join(plan.MissingAcks, ", "))
		}
	}
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}

func printTuneResults(cmd *cobra.Command, results []tuning.ApplyResult) {
	for _, result := range results {
		switch {
		case result.Applied:
			cmd.Printf("applied %s=%s\n", result.Key, result.Value)
		case result.Skipped:
			cmd.Printf("skipped %s: %s\n", result.Key, result.Detail)
		default:
			cmd.Printf("%s %s=%s\n", value(result.Detail), result.Key, result.Value)
		}
	}
}

func runSystemCapture(ctx context.Context, cmd *cobra.Command, client systemCaptureClient, opts systemCaptureOptions) error {
	protocol, err := parseProtocol(opts.protocol)
	if err != nil {
		return err
	}
	if opts.start && !opts.ackCapture {
		return fmt.Errorf("--ack-capture is required with --start")
	}
	if opts.start {
		req := &openngfwv1.StartPacketCaptureRequest{
			Interface:       opts.iface,
			Protocol:        protocol,
			SrcIp:           opts.srcIP,
			SrcPort:         opts.srcPort,
			DestIp:          opts.destIP,
			DestPort:        opts.destPort,
			DurationSeconds: opts.durationSeconds,
			PacketCount:     opts.packetCount,
			SnaplenBytes:    opts.snaplenBytes,
			Label:           opts.label,
			FlowId:          opts.flowID,
			AckCapture:      opts.ackCapture,
		}
		resp, err := client.StartPacketCapture(ctx, req)
		if err != nil {
			return fmt.Errorf("start packet capture: %w", err)
		}
		if opts.outJSON {
			return printProtoJSON(cmd, resp)
		}
		printPacketCaptureJob(cmd, resp.GetJob())
		return nil
	}
	req := &openngfwv1.PlanPacketCaptureRequest{
		Interface:       opts.iface,
		Protocol:        protocol,
		SrcIp:           opts.srcIP,
		SrcPort:         opts.srcPort,
		DestIp:          opts.destIP,
		DestPort:        opts.destPort,
		DurationSeconds: opts.durationSeconds,
		PacketCount:     opts.packetCount,
		SnaplenBytes:    opts.snaplenBytes,
		Label:           opts.label,
		FlowId:          opts.flowID,
	}
	resp, err := client.PlanPacketCapture(ctx, req)
	if err != nil {
		return fmt.Errorf("plan packet capture: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPacketCapturePlan(cmd, resp.GetPlan())
	return nil
}

func runSystemCaptureList(ctx context.Context, cmd *cobra.Command, client systemCaptureClient, opts systemCaptureOptions) error {
	req := &openngfwv1.ListPacketCapturesRequest{Limit: opts.limit, FlowId: opts.flowID}
	resp, err := client.ListPacketCaptures(ctx, req)
	if err != nil {
		return fmt.Errorf("list packet captures: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPacketCaptureArtifacts(cmd, resp)
	return nil
}

func runSystemCaptureDownload(ctx context.Context, cmd *cobra.Command, client systemCaptureClient, opts systemCaptureOptions) error {
	artifactID := strings.TrimSpace(opts.artifactID)
	if artifactID == "" {
		return fmt.Errorf("artifact id is required")
	}
	outputPath := strings.TrimSpace(opts.outputPath)
	if outputPath == "" {
		return fmt.Errorf("--output is required")
	}
	body, err := client.DownloadPacketCapture(ctx, &openngfwv1.DownloadPacketCaptureRequest{Id: artifactID})
	if err != nil {
		return fmt.Errorf("download packet capture: %w", err)
	}
	if body == nil {
		return fmt.Errorf("download packet capture: no response body returned")
	}
	if err := os.WriteFile(outputPath, body.GetData(), 0o600); err != nil {
		return fmt.Errorf("write packet capture %s: %w", outputPath, err)
	}
	cmd.Printf("downloaded packet capture %s to %s (%s", artifactID, outputPath, humanBytes(uint64(len(body.GetData()))))
	if body.GetContentType() != "" {
		cmd.Printf(", %s", body.GetContentType())
	}
	cmd.Println(")")
	return nil
}

func runSystemCaptureRetention(ctx context.Context, cmd *cobra.Command, client systemCaptureClient, opts systemCaptureOptions, state openngfwv1.PacketCaptureRetentionState) error {
	artifactID := strings.TrimSpace(opts.artifactID)
	if artifactID == "" {
		return fmt.Errorf("artifact id is required")
	}
	reason := strings.TrimSpace(opts.retentionReason)
	if reason == "" {
		return fmt.Errorf("--reason is required")
	}
	if !opts.ackRetention {
		return fmt.Errorf("--ack-retention-change is required")
	}
	retainUntil := strings.TrimSpace(opts.retainUntil)
	if state == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED && retainUntil == "" {
		return fmt.Errorf("--retain-until is required")
	}
	if state == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED {
		retainUntil = ""
	}
	resp, err := client.SetPacketCaptureRetention(ctx, &openngfwv1.SetPacketCaptureRetentionRequest{
		Id:                 artifactID,
		State:              state,
		RetainUntil:        retainUntil,
		RetentionReason:    reason,
		CaseId:             strings.TrimSpace(opts.caseID),
		AckRetentionChange: opts.ackRetention,
	})
	if err != nil {
		return fmt.Errorf("set packet capture retention: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printPacketCaptureJob(cmd, resp.GetJob())
	return nil
}

func runSystemHAStatus(ctx context.Context, cmd *cobra.Command, client systemHAClient, opts systemHAOptions) error {
	resp, err := client.GetHighAvailabilityStatus(ctx, &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		return fmt.Errorf("query HA status: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printHAStatus(cmd, resp)
	return nil
}

func runSystemHAPullPolicy(ctx context.Context, cmd *cobra.Command, client systemHAClient, opts systemHAOptions) error {
	comment := strings.TrimSpace(opts.comment)
	if comment == "" {
		return fmt.Errorf("--message is required")
	}
	if !opts.ackPull {
		return fmt.Errorf("--ack-pull is required")
	}
	resp, err := client.PullHighAvailabilityPolicy(ctx, &openngfwv1.PullHighAvailabilityPolicyRequest{
		Comment:    comment,
		AckPull:    opts.ackPull,
		AckRisk:    opts.ackRisk,
		AckRuntime: opts.ackRuntime,
	})
	if err != nil {
		return fmt.Errorf("pull HA policy: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printHAPolicyPull(cmd, resp)
	return nil
}

func runSystemHAActivatePassive(ctx context.Context, cmd *cobra.Command, client systemHAClient, opts systemHAOptions) error {
	comment := strings.TrimSpace(opts.comment)
	if comment == "" {
		return fmt.Errorf("--message is required")
	}
	if !opts.ackFailover {
		return fmt.Errorf("--ack-failover is required")
	}
	if !opts.ackExternalCutover {
		return fmt.Errorf("--ack-external-cutover is required")
	}
	if !opts.ackExternalFencing {
		return fmt.Errorf("--ack-external-fencing is required")
	}
	resp, err := client.ActivateHighAvailabilityFailover(ctx, &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            comment,
		AckFailover:        opts.ackFailover,
		AckExternalCutover: opts.ackExternalCutover,
		AckExternalFencing: opts.ackExternalFencing,
	})
	if err != nil {
		return fmt.Errorf("activate HA passive node: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printHAFailoverActivation(cmd, resp)
	return nil
}

func runSystemEbpfReadiness(ctx context.Context, cmd *cobra.Command, client systemStatusClient, opts systemEbpfReadinessOptions) error {
	resp, err := client.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
	if err != nil {
		return fmt.Errorf("query eBPF readiness: %w", err)
	}
	ebpf := resp.GetDataplane().GetEbpf()
	if opts.outJSON {
		if ebpf == nil {
			ebpf = &openngfwv1.EbpfDataplaneStatus{}
		}
		return printProtoJSON(cmd, ebpf)
	}
	printSystemEbpfReadiness(cmd, ebpf)
	return nil
}

func printSystemEbpfReadiness(cmd *cobra.Command, ebpf *openngfwv1.EbpfDataplaneStatus) {
	cmd.Println("eBPF readiness")
	if ebpf == nil {
		cmd.Println("  state:           unavailable")
		cmd.Println("  detail:          status response did not include eBPF readiness")
		return
	}
	cmd.Printf("  host:            %s\n", value(ebpf.GetState()))
	cmd.Printf("  attach:          %s\n", value(ebpf.GetAttachState()))
	cmd.Printf("  renderer:        %s\n", value(ebpf.GetRendererState()))
	if hooks := ebpf.GetSupportedHooks(); len(hooks) > 0 {
		cmd.Printf("  hooks:           %s\n", strings.Join(hooks, ", "))
	}
	if ebpf.GetEvidenceScope() != "" {
		cmd.Printf("  evidence scope:  %s\n", ebpf.GetEvidenceScope())
	}
	if ebpf.GetEvidenceCollectedAt() != "" {
		cmd.Printf("  evidence time:   %s\n", ebpf.GetEvidenceCollectedAt())
	}
	if ebpf.GetDetail() != "" {
		cmd.Printf("  host detail:     %s\n", ebpf.GetDetail())
	}
	if ebpf.GetAttachDetail() != "" {
		cmd.Printf("  attach detail:   %s\n", ebpf.GetAttachDetail())
	}
	if ebpf.GetRendererDetail() != "" {
		cmd.Printf("  renderer detail: %s\n", ebpf.GetRendererDetail())
	}
	if blockers := ebpf.GetBlockers(); len(blockers) > 0 {
		cmd.Println("  blockers:")
		for _, blocker := range blockers {
			cmd.Printf("    - %s\n", blocker)
		}
	}
	printSystemEbpfProbeList(cmd, "host probes", ebpf.GetProbes())
	printSystemEbpfProbeList(cmd, "attach probes", ebpf.GetAttachProbes())
	if attachments := ebpf.GetAttachments(); len(attachments) > 0 {
		cmd.Println("  attachments:")
		for _, attachment := range attachments {
			cmd.Printf("    - %-8s %-4s %-10s", value(attachment.GetInterface()), value(attachment.GetHook()), value(attachment.GetState()))
			if attachment.GetProgramId() != "" || attachment.GetProgramName() != "" {
				cmd.Printf(" program=%s/%s", value(attachment.GetProgramId()), value(attachment.GetProgramName()))
			}
			if attachment.GetPinnedPath() != "" {
				cmd.Printf(" pinned=%s", attachment.GetPinnedPath())
			}
			if attachment.GetDetail() != "" {
				cmd.Printf(" %s", attachment.GetDetail())
			}
			cmd.Println()
		}
	}
	if artifacts := ebpf.GetArtifacts(); len(artifacts) > 0 {
		cmd.Println("  artifacts:")
		for _, artifact := range artifacts {
			cmd.Printf("    - %-24s %-12s %-10s", value(artifact.GetName()), value(artifact.GetKind()), value(artifact.GetState()))
			if artifact.GetSha256() != "" {
				cmd.Printf(" sha256:%s", shortHAHash(artifact.GetSha256()))
			}
			if artifact.GetDetail() != "" {
				cmd.Printf(" %s", artifact.GetDetail())
			}
			cmd.Println()
		}
	}
	cmd.Println("  active dataplane: nftables/conntrack")
}

func printSystemEbpfProbeList(cmd *cobra.Command, title string, probes []*openngfwv1.EbpfProbe) {
	if len(probes) == 0 {
		return
	}
	cmd.Printf("  %s:\n", title)
	for _, probe := range probes {
		cmd.Printf("    - %-24s %-10s %s\n", value(probe.GetName()), value(probe.GetState()), value(probe.GetDetail()))
	}
}

func runSystemTelemetryExportStatus(ctx context.Context, cmd *cobra.Command, client systemTelemetryClient, opts systemTelemetryOptions) error {
	resp, err := client.GetTelemetryExportStatus(ctx, &openngfwv1.GetTelemetryExportStatusRequest{})
	if err != nil {
		return fmt.Errorf("query telemetry export status: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printTelemetryExportStatus(cmd, resp)
	return nil
}

func runSystemReleaseAcceptanceStatus(ctx context.Context, cmd *cobra.Command, client systemReleaseAcceptanceClient, opts systemReleaseAcceptanceOptions) error {
	resp, err := client.GetReleaseAcceptanceStatus(ctx, &openngfwv1.GetReleaseAcceptanceStatusRequest{})
	if err != nil {
		return fmt.Errorf("query release acceptance status: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printReleaseAcceptanceStatus(cmd, resp)
	return nil
}

func runSystemLogs(ctx context.Context, cmd *cobra.Command, client systemLogsClient, opts systemLogsOptions) error {
	resp, err := client.ListSystemLogs(ctx, &openngfwv1.ListSystemLogsRequest{
		Limit:    opts.limit,
		Source:   opts.source,
		Engine:   opts.engine,
		Severity: opts.severity,
		Query:    opts.query,
		Since:    opts.since,
		Until:    opts.until,
	})
	if err != nil {
		return fmt.Errorf("query system logs: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printSystemLogs(cmd, resp)
	return nil
}

func runSystemNetworkPathProve(ctx context.Context, cmd *cobra.Command, client systemNetworkPathClient, opts systemNetworkPathOptions) error {
	req, err := systemNetworkPathRequest(opts)
	if err != nil {
		return err
	}
	resp, err := client.ProveNetworkPath(ctx, req)
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printSystemNetworkPathProof(cmd, resp)
	return nil
}

func systemNetworkPathRequest(opts systemNetworkPathOptions) (*openngfwv1.ProveNetworkPathRequest, error) {
	protocol, err := parseProtocol(opts.protocol)
	if err != nil {
		return nil, err
	}
	req := &openngfwv1.ProveNetworkPathRequest{
		SrcIp:           strings.TrimSpace(opts.srcIP),
		DestIp:          strings.TrimSpace(opts.destIP),
		Protocol:        protocol,
		DestPort:        opts.destPort,
		SourceInterface: strings.TrimSpace(opts.sourceInterface),
	}
	tunnel := &openngfwv1.NetworkPathTunnelRef{
		Kind:          strings.TrimSpace(opts.tunnelKind),
		Name:          strings.TrimSpace(opts.tunnelName),
		Interface:     strings.TrimSpace(opts.tunnelInterface),
		Peer:          strings.TrimSpace(opts.tunnelPeer),
		PeerPublicKey: strings.TrimSpace(opts.tunnelPeerPublicKey),
	}
	if tunnel.GetKind() != "" || tunnel.GetName() != "" || tunnel.GetInterface() != "" || tunnel.GetPeer() != "" || tunnel.GetPeerPublicKey() != "" {
		req.Tunnel = tunnel
	}
	return req, nil
}

func printSystemNetworkPathProof(cmd *cobra.Command, resp *openngfwv1.ProveNetworkPathResponse) {
	cmd.Printf("network path proof: %s\n", value(resp.GetState()))
	if resp.GetDetail() != "" {
		cmd.Printf("  detail:           %s\n", resp.GetDetail())
	}
	cmd.Printf("  generated:        %s\n", value(resp.GetGeneratedAt()))
	cmd.Printf("  running policy:   v%d\n", resp.GetRunningPolicyVersion())
	if route := resp.GetRoute(); route != nil {
		cmd.Println("  route:")
		cmd.Printf("    state:          %s\n", value(route.GetState()))
		cmd.Printf("    destination:    %s\n", value(route.GetDestination()))
		cmd.Printf("    dev:            %s\n", value(route.GetDev()))
		cmd.Printf("    gateway:        %s\n", value(route.GetGateway()))
		cmd.Printf("    preferred src:  %s\n", value(route.GetPreferredSource()))
		cmd.Printf("    protocol/table: %s/%s\n", value(route.GetProtocol()), value(route.GetTable()))
		if route.GetDetail() != "" {
			cmd.Printf("    detail:         %s\n", route.GetDetail())
		}
	}
	if vpn := resp.GetVpn(); vpn != nil {
		cmd.Println("  vpn:")
		cmd.Printf("    kind/state:     %s/%s\n", value(vpn.GetKind()), value(vpn.GetState()))
		cmd.Printf("    matched:        %s\n", firstNonEmpty(vpn.GetMatchedTunnel(), vpn.GetInterface(), "-"))
		cmd.Printf("    peer:           %s\n", value(vpn.GetPeer()))
		if vpn.GetHandshakeAgeSeconds() > 0 {
			cmd.Printf("    handshake age:  %ds\n", vpn.GetHandshakeAgeSeconds())
		}
		if vpn.GetChildSaCount() > 0 || vpn.GetInstalledChildSaCount() > 0 {
			cmd.Printf("    child SAs:      %d/%d installed\n", vpn.GetInstalledChildSaCount(), vpn.GetChildSaCount())
		}
		if vpn.GetCorrelation() != "" {
			cmd.Printf("    correlation:    %s\n", vpn.GetCorrelation())
		}
		if vpn.GetDetail() != "" {
			cmd.Printf("    detail:         %s\n", vpn.GetDetail())
		}
	}
	if mismatches := resp.GetMismatches(); len(mismatches) > 0 {
		cmd.Println("  mismatches:")
		for _, mismatch := range mismatches {
			cmd.Printf("    - [%s] %s: %s\n", value(mismatch.GetSeverity()), value(mismatch.GetSubject()), value(mismatch.GetDetail()))
		}
	} else {
		cmd.Println("  mismatches:       none")
	}
	if evidence := resp.GetEvidence(); len(evidence) > 0 {
		cmd.Println("  evidence:")
		for _, item := range evidence {
			cmd.Printf("    - %s\n", item)
		}
	}
	if warnings := resp.GetWarnings(); len(warnings) > 0 {
		cmd.Printf("  warnings:         %s\n", strings.Join(warnings, "; "))
	}
	if limitations := resp.GetLimitations(); len(limitations) > 0 {
		cmd.Printf("  limitations:      %s\n", strings.Join(limitations, "; "))
	}
	if resp.GetCliHandoff() != "" {
		cmd.Printf("  cli handoff:      %s\n", resp.GetCliHandoff())
	}
	if resp.GetApiHandoff() != "" {
		cmd.Printf("  api handoff:      %s\n", strings.ReplaceAll(resp.GetApiHandoff(), "\n", " "))
	}
}

func printReleaseAcceptanceStatus(cmd *cobra.Command, resp *openngfwv1.GetReleaseAcceptanceStatusResponse) {
	cmd.Println("release acceptance status")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	cmd.Printf("  state:           %s\n", value(resp.GetState()))
	cmd.Printf("  ready:           %s\n", yesNo(resp.GetReady()))
	cmd.Printf("  manifest:        %s (%s)\n", presentMissing(resp.GetManifestPresent()), releaseStatusDisplayValue(resp.GetManifestPath()))
	cmd.Printf("  evidence dir:    %s\n", releaseStatusDisplayValue(resp.GetEvidenceDir()))
	if resp.GetGeneratedAt() != "" {
		cmd.Printf("  generated:       %s\n", resp.GetGeneratedAt())
	}
	if summary := resp.GetSummary(); summary != nil {
		cmd.Printf("  summary:         passed=%d recorded=%d missing=%d invalid=%d not_applicable=%d todo=%d\n",
			summary.GetPassed(),
			summary.GetRecorded(),
			summary.GetMissing(),
			summary.GetInvalid(),
			summary.GetNotApplicable(),
			summary.GetTodo())
	}
	if recordability := resp.GetRecordability(); recordability != nil {
		cmd.Printf("  recordability:   %s\n", readyBlocked(recordability.GetReady()))
		cmd.Println("    scope:         source-control acceptance only; does not prove functional generation or accept release evidence")
		if recordability.GetGitHead() != "" {
			cmd.Printf("    git head:      %s\n", recordability.GetGitHead())
		}
		if recordability.GetRecordCommit() != "" {
			cmd.Printf("    record commit: %s\n", recordability.GetRecordCommit())
		}
		if dirty := recordability.GetDirtySourcePaths(); len(dirty) > 0 {
			cmd.Printf("    dirty paths:   %s\n", releaseStatusDisplayValue(strings.Join(dirty, ", ")))
		}
		if allowed := recordability.GetAllowedDirtyPaths(); len(allowed) > 0 {
			cmd.Printf("    allowed dirty: %s\n", releaseStatusDisplayValue(strings.Join(allowed, ", ")))
		}
		if stale := recordability.GetStaleEvidencePaths(); len(stale) > 0 {
			cmd.Printf("    stale evidence: %s\n", releaseStatusDisplayValue(strings.Join(stale, ", ")))
		}
		printReleaseStatusIndentedList(cmd, "    problems", recordability.GetProblems())
	}
	printReleaseStatusIndentedList(cmd, "  problems", resp.GetProblems())
	checks := resp.GetChecks()
	if len(checks) == 0 {
		cmd.Println("  checks:          none")
		return
	}
	cmd.Println("  checks:")
	for _, check := range checks {
		cmd.Printf("    - %-24s %s\n", value(check.GetName()), value(check.GetState()))
		if check.GetName() == "proto-verify" {
			printProtoVerifyAcceptanceNote(cmd, resp.GetRecordability())
		}
		if check.GetArtifact() != "" {
			cmd.Printf("      artifact:    %s\n", releaseStatusDisplayValue(check.GetArtifact()))
		}
		if check.GetEvidencePath() != "" {
			cmd.Printf("      evidence:    %s\n", releaseStatusDisplayValue(check.GetEvidencePath()))
		}
		if check.GetRanAt() != "" {
			cmd.Printf("      ran at:      %s\n", check.GetRanAt())
		}
		if check.GetBenchmarkSummary() != "" {
			cmd.Printf("      benchmark:   %s\n", releaseStatusDisplayValue(check.GetBenchmarkSummary()))
		}
		if check.GetDetail() != "" {
			cmd.Printf("      detail:      %s\n", releaseStatusDisplayValue(check.GetDetail()))
		}
		if command := check.GetCommand(); len(command) > 0 {
			cmd.Printf("      command:     %s\n", releaseStatusDisplayValue(strings.Join(command, " ")))
		}
		if check.GetNextAction() != "" {
			cmd.Printf("      next:        %s\n", releaseStatusDisplayValue(check.GetNextAction()))
		}
		if nextCommand := check.GetNextCommand(); len(nextCommand) > 0 {
			cmd.Printf("      next cmd:    %s\n", releaseStatusDisplayValue(strings.Join(nextCommand, " ")))
		}
		printReleaseStatusIndentedList(cmd, "      problems", check.GetProblems())
	}
}

func printReleaseStatusIndentedList(cmd *cobra.Command, title string, items []string) {
	if len(items) == 0 {
		return
	}
	safe := make([]string, 0, len(items))
	for _, item := range items {
		safe = append(safe, releaseStatusDisplayValue(item))
	}
	printIndentedList(cmd, title, safe)
}

func releaseStatusDisplayValue(value string) string {
	value = releaseStatusBearerRE.ReplaceAllString(value, "Bearer [redacted]")
	value = releaseStatusSecretRE.ReplaceAllString(value, "${1}${2}[redacted]")
	value = releaseStatusLocalPathRE.ReplaceAllString(value, "$1[server-local path redacted]")
	return strings.TrimSpace(value)
}

func printProtoVerifyAcceptanceNote(cmd *cobra.Command, recordability *openngfwv1.ReleaseAcceptanceRecordabilityStatus) {
	cmd.Println("      functional:  make proto-status && make proto-verify validate generated proto/gateway/OpenAPI consistency")
	if recordability == nil {
		cmd.Println("      source:      acceptance unknown; proto-verify release evidence also requires the atomic API contract tree to be accepted in source control")
		return
	}
	dirtyCount := len(recordability.GetDirtySourcePaths())
	problemCount := len(recordability.GetProblems())
	blocked := !recordability.GetReady() || dirtyCount > 0 || problemCount > 0
	if blocked {
		cmd.Printf("      source:      blocked (%d dirty source path(s), %d problem(s)); release evidence is not acceptable until proto inputs, generator config, generated Go/gateway files, normalized OpenAPI, docs spec, and WebUI spec are accepted together\n", dirtyCount, problemCount)
		return
	}
	cmd.Println("      source:      clear for recordability; proto-verify release evidence still requires recording and manifest verification")
}

func printIndentedList(cmd *cobra.Command, title string, items []string) {
	if len(items) == 0 {
		return
	}
	cmd.Printf("%s:\n", title)
	itemIndent := strings.Repeat(" ", leadingSpaces(title)+2)
	for _, item := range items {
		cmd.Printf("%s- %s\n", itemIndent, item)
	}
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func presentMissing(v bool) string {
	if v {
		return "present"
	}
	return "missing"
}

func readyBlocked(v bool) string {
	if v {
		return "ready"
	}
	return "blocked"
}

func printTelemetryExportStatus(cmd *cobra.Command, resp *openngfwv1.GetTelemetryExportStatusResponse) {
	cmd.Println("telemetry export status")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	cmd.Printf("  state:           %s\n", value(resp.GetState()))
	cmd.Printf("  detail:          %s\n", value(resp.GetDetail()))
	cmd.Printf("  running policy:  v%d\n", resp.GetRunningPolicyVersion())
	cmd.Printf("  telemetry:       %t\n", resp.GetTelemetryEnabled())
	if resp.GetGeneratedAt() != "" {
		cmd.Printf("  sampled:         %s\n", resp.GetGeneratedAt())
	}
	if vector := resp.GetVector(); vector != nil {
		cmd.Printf("  vector:          %s - %s\n", value(vector.GetState()), value(vector.GetDetail()))
	}
	if clickhouse := resp.GetClickhouse(); clickhouse != nil {
		cmd.Printf("  clickhouse:      %s\n", telemetrySinkState(clickhouse.GetConfigured(), clickhouse.GetEvidenceState()))
		if clickhouse.GetEndpoint() != "" || clickhouse.GetDatabase() != "" {
			cmd.Printf("    target:        %s/%s\n", value(clickhouse.GetEndpoint()), value(clickhouse.GetDatabase()))
		}
		if clickhouse.GetEvidenceDetail() != "" {
			cmd.Printf("    evidence:      %s\n", clickhouse.GetEvidenceDetail())
		}
	}
	if exports := resp.GetExports(); len(exports) > 0 {
		cmd.Println("  exports:")
		for _, export := range exports {
			cmd.Printf("    - %-16s %-9s %-22s %s\n",
				value(export.GetName()),
				telemetryExportTypeLabel(export.GetType(), export.GetProtocol()),
				telemetrySinkState(export.GetConfigured(), export.GetEvidenceState()),
				value(export.GetTarget()))
			if file := export.GetFile(); file != nil {
				if file.GetPresent() {
					cmd.Printf("      file:         %s (%s, modified %s)\n", value(file.GetPath()), humanBytes(file.GetSizeBytes()), value(file.GetModifiedAt()))
				} else if file.GetError() != "" {
					cmd.Printf("      file:         %s\n", file.GetError())
				} else if file.GetPath() != "" {
					cmd.Printf("      file:         %s not present\n", file.GetPath())
				}
			}
			if export.GetEvidenceDetail() != "" {
				cmd.Printf("      evidence:     %s\n", export.GetEvidenceDetail())
			}
		}
	}
	if warnings := resp.GetWarnings(); len(warnings) > 0 {
		cmd.Println("  warnings:")
		for _, warning := range warnings {
			cmd.Printf("    [%s] %s", strings.ToUpper(value(warning.GetSeverity())), warning.GetMessage())
			if warning.GetAction() != "" {
				cmd.Printf(" Action: %s", warning.GetAction())
			}
			cmd.Println()
		}
	}
}

func printSystemLogs(cmd *cobra.Command, resp *openngfwv1.ListSystemLogsResponse) {
	cmd.Println("system logs")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	if summary := resp.GetSummary(); summary != nil {
		cmd.Printf("  scanned:         %d files, %d lines\n", summary.GetScannedFiles(), summary.GetScannedLines())
		cmd.Printf("  matched:         %d lines\n", summary.GetMatchedLines())
		if summary.GetTruncated() {
			cmd.Println("  truncated:       true")
		}
		if len(summary.GetSources()) > 0 {
			cmd.Printf("  sources:         %s\n", strings.Join(summary.GetSources(), ", "))
		}
		if len(summary.GetEngines()) > 0 {
			cmd.Printf("  engines:         %s\n", strings.Join(summary.GetEngines(), ", "))
		}
		if len(summary.GetSeverities()) > 0 {
			cmd.Printf("  severities:      %s\n", strings.Join(summary.GetSeverities(), ", "))
		}
		for _, warning := range summary.GetWarnings() {
			cmd.Printf("  warning:         %s\n", warning)
		}
	}
	entries := resp.GetEntries()
	if len(entries) == 0 {
		cmd.Println("  no matching log entries")
		return
	}
	cmd.Println("  entries:")
	for _, entry := range entries {
		cmd.Printf("    - %s %-8s %-10s %-10s %s\n",
			value(entry.GetTimestamp()),
			strings.ToUpper(value(entry.GetSeverity())),
			value(entry.GetSource()),
			value(entry.GetEngine()),
			value(entry.GetMessage()))
		location := strings.TrimSpace(entry.GetFile())
		if entry.GetLine() > 0 {
			location = fmt.Sprintf("%s:%d", value(location), entry.GetLine())
		}
		cmd.Printf("      file:         %s\n", value(location))
		if entry.GetFacility() != "" {
			cmd.Printf("      facility:     %s\n", entry.GetFacility())
		}
		if entry.GetId() != "" {
			cmd.Printf("      id:           %s\n", entry.GetId())
		}
	}
}

func telemetrySinkState(configured bool, evidenceState string) string {
	if !configured {
		return "disabled"
	}
	if strings.TrimSpace(evidenceState) == "" {
		return "configured"
	}
	return evidenceState
}

func printHAStatus(cmd *cobra.Command, resp *openngfwv1.GetHighAvailabilityStatusResponse) {
	cmd.Println("HA status")
	if resp == nil || resp.GetStatus() == nil {
		cmd.Println("  state:           unavailable")
		cmd.Println("  detail:          status response did not include HA posture")
		return
	}
	ha := resp.GetStatus()
	if resp.GetGeneratedAt() != "" {
		cmd.Printf("  generated at:    %s\n", resp.GetGeneratedAt())
	}
	cmd.Printf("  mode/role:       %s / %s\n", value(ha.GetMode()), value(ha.GetRole()))
	cmd.Printf("  state:           %s\n", value(ha.GetState()))
	cmd.Printf("  node:            %s\n", value(ha.GetNodeId()))
	if ha.GetPeerId() != "" || ha.GetPeerAddress() != "" {
		cmd.Printf("  peer:            %s", value(ha.GetPeerId()))
		if ha.GetPeerAddress() != "" {
			cmd.Printf(" (%s)", ha.GetPeerAddress())
		}
		cmd.Println()
	}
	cmd.Printf("  policy:          running v%d / lkg v%d %s\n", ha.GetRunningPolicyVersion(), ha.GetLastKnownGoodVersion(), value(ha.GetLastKnownGoodState()))
	if hash := ha.GetLastKnownGoodArtifactSetSha256(); hash != "" {
		cmd.Printf("  artifact set:    %s\n", shortHAHash(hash))
	}
	if sync := ha.GetSync(); sync != nil {
		cmd.Printf("  sync:            %s\n", value(sync.GetState()))
		if sync.GetLocalVersion() > 0 || sync.GetPeerVersion() > 0 {
			cmd.Printf("  sync versions:   local v%d / peer v%d\n", sync.GetLocalVersion(), sync.GetPeerVersion())
		}
		if sync.GetPeerArtifactSetSha256() != "" {
			cmd.Printf("  peer artifact:   %s\n", shortHAHash(sync.GetPeerArtifactSetSha256()))
		}
		if sync.GetSecondsSinceHeartbeat() > 0 {
			cmd.Printf("  heartbeat age:   %s\n", seconds(sync.GetSecondsSinceHeartbeat()))
		}
		if sync.GetDetail() != "" {
			cmd.Printf("  sync detail:     %s\n", sync.GetDetail())
		}
	}
	if replication := ha.GetReplication(); replication != nil {
		cmd.Printf("  replication:     %s enabled=%t\n", value(replication.GetState()), replication.GetEnabled())
		if replication.GetLastPeerVersion() > 0 || replication.GetLastLocalVersion() > 0 {
			cmd.Printf("  replicated:      peer v%d -> local v%d\n", replication.GetLastPeerVersion(), replication.GetLastLocalVersion())
		}
		if replication.GetLastSuccessAt() != "" {
			cmd.Printf("  repl success:    %s\n", replication.GetLastSuccessAt())
		}
		if replication.GetLastAttemptAt() != "" {
			cmd.Printf("  repl attempt:    %s\n", replication.GetLastAttemptAt())
		}
		if replication.GetLastError() != "" {
			cmd.Printf("  repl error:      %s\n", replication.GetLastError())
		} else if replication.GetDetail() != "" {
			cmd.Printf("  repl detail:     %s\n", replication.GetDetail())
		}
	}
	if fencing := ha.GetFencingEvidence(); fencing != nil {
		cmd.Printf("  fencing:         %s\n", value(fencing.GetState()))
		if fencing.GetProvider() != "" || fencing.GetClaim() != "" {
			cmd.Printf("  fencing proof:   provider=%s claim=%s\n", value(fencing.GetProvider()), value(fencing.GetClaim()))
		}
		if fencing.GetEvidenceId() != "" {
			cmd.Printf("  fencing id:      %s\n", fencing.GetEvidenceId())
		}
		if fencing.GetObservedAt() != "" {
			cmd.Printf("  fencing at:      %s\n", fencing.GetObservedAt())
		}
		if fencing.GetDetail() != "" {
			cmd.Printf("  fencing detail:  %s\n", fencing.GetDetail())
		}
	}
	if failover := ha.GetFailover(); failover != nil {
		cmd.Printf("  failover:        %s eligible=%t\n", value(failover.GetState()), failover.GetEligible())
		if failover.GetDetail() != "" {
			cmd.Printf("  failover detail: %s\n", failover.GetDetail())
		}
		if blockers := failover.GetBlockers(); len(blockers) > 0 {
			cmd.Printf("  failover blocks: %s\n", strings.Join(blockers, "; "))
		}
	}
	for _, blocker := range ha.GetBlockers() {
		cmd.Printf("  blocker:         %s\n", blocker)
	}
	if ha.GetDetail() != "" {
		cmd.Printf("  detail:          %s\n", ha.GetDetail())
	}
	printHACutoverPlan(cmd, ha)
}

func printHACutoverPlan(cmd *cobra.Command, ha *openngfwv1.HighAvailabilityStatus) {
	cmd.Println("  cutover plan:")
	failover := ha.GetFailover()
	if failover != nil && failover.GetEligible() {
		cmd.Println("    - preflight: ready from peer heartbeat, policy sync, and LKG evidence")
		cmd.Println("    - local role: run activate-passive with failover, external-cutover, and external-fencing acknowledgements")
		cmd.Println("    - traffic: move VIP/route ownership using the site runbook after activation")
		cmd.Println("    - fencing: verify provider-backed peer fencing evidence; this API records evidence but does not fence the peer")
		cmd.Println("    - verification: confirm VIP/route ownership, traffic path, peer role, and post-activation HA status")
		return
	}
	cmd.Println("    - preflight: blocked; do not move VIPs or routes")
	cmd.Println("    - required: resolve HA blockers, peer heartbeat, policy sync, and LKG metadata before activation")
	cmd.Println("    - traffic: VIP/route cutover remains external and must wait for eligible server evidence")
	cmd.Println("    - fencing: peer fencing remains external and must be verified during the hardening/field pass")
}

func telemetryExportTypeLabel(t openngfwv1.TelemetryExportType, protocol string) string {
	switch t {
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE:
		return "json-file"
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP:
		return "json-tcp"
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP:
		return "json-udp"
	default:
		if protocol != "" {
			return protocol
		}
		return "unknown"
	}
}

func printHAPolicyPull(cmd *cobra.Command, resp *openngfwv1.PullHighAvailabilityPolicyResponse) {
	cmd.Println("HA policy pull")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	cmd.Printf("  previous version: v%d\n", resp.GetPreviousVersion())
	cmd.Printf("  new version:      v%d\n", resp.GetVersion())
	cmd.Printf("  peer version:     v%d\n", resp.GetPeerVersion())
	if hash := resp.GetPeerArtifactSetSha256(); hash != "" {
		cmd.Printf("  peer artifact:    %s\n", shortHAHash(hash))
	}
	if info := resp.GetVersionInfo(); info != nil {
		cmd.Printf("  action:           %s\n", value(info.GetAction()))
		cmd.Printf("  state:            %s\n", value(info.GetState()))
	}
	if before := resp.GetBefore(); before != nil {
		cmd.Printf("  before:           %s/%s v%d\n", value(before.GetRole()), value(before.GetSync().GetState()), before.GetRunningPolicyVersion())
	}
	if after := resp.GetAfter(); after != nil {
		cmd.Printf("  after:            %s/%s v%d\n", value(after.GetRole()), value(after.GetSync().GetState()), after.GetRunningPolicyVersion())
	}
	if resp.GetDetail() != "" {
		cmd.Printf("  detail:           %s\n", resp.GetDetail())
	}
}

func printHAFailoverActivation(cmd *cobra.Command, resp *openngfwv1.ActivateHighAvailabilityFailoverResponse) {
	cmd.Println("HA failover activation")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	cmd.Printf("  activated at:     %s\n", value(resp.GetActivatedAt()))
	cmd.Printf("  running policy:   v%d\n", resp.GetRunningPolicyVersion())
	cmd.Printf("  last known good:  v%d\n", resp.GetLastKnownGoodVersion())
	if before := resp.GetBefore(); before != nil {
		cmd.Printf("  before:           %s/%s v%d\n", value(before.GetRole()), value(before.GetFailover().GetState()), before.GetRunningPolicyVersion())
		cmd.Printf("  preflight:        %s\n", value(before.GetFailover().GetDetail()))
	}
	if after := resp.GetAfter(); after != nil {
		cmd.Printf("  after:            %s/%s v%d\n", value(after.GetRole()), value(after.GetFailover().GetState()), after.GetRunningPolicyVersion())
		cmd.Printf("  post-check:       %s\n", value(after.GetFailover().GetDetail()))
		if blockers := after.GetFailover().GetBlockers(); len(blockers) > 0 {
			cmd.Printf("  post-blockers:    %s\n", strings.Join(blockers, "; "))
		}
	}
	if resp.GetDetail() != "" {
		cmd.Printf("  detail:           %s\n", resp.GetDetail())
	}
	cmd.Println("  traffic cutover:  external acknowledged; verify outside API")
	cmd.Println("  peer fencing:     external acknowledged; verify outside API")
}

func printProtoJSON(cmd *cobra.Command, msg proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(msg)
	if err != nil {
		return err
	}
	cmd.Println(string(b))
	return nil
}

func printPacketCapturePlan(cmd *cobra.Command, plan *openngfwv1.PacketCapturePlan) {
	cmd.Println("packet capture plan")
	if plan == nil {
		cmd.Println("  no plan returned")
		return
	}
	cmd.Printf("  interface:       %s\n", value(plan.GetInterface()))
	cmd.Printf("  protocol:        %s\n", captureProtocolLabel(plan.GetProtocol()))
	cmd.Printf("  scope:           %s <-> %s\n",
		captureEndpoint(plan.GetSrcIp(), plan.GetSrcPort()),
		captureEndpoint(plan.GetDestIp(), plan.GetDestPort()))
	if plan.GetFlowId() != "" {
		cmd.Printf("  flow id:         %s\n", plan.GetFlowId())
	}
	cmd.Printf("  limits:          %ds, %d packets, %d byte snaplen\n",
		plan.GetDurationSeconds(), plan.GetPacketCount(), plan.GetSnaplenBytes())
	cmd.Printf("  output:          %s\n", value(plan.GetOutputPath()))
	cmd.Printf("  bpf:             %s\n", value(plan.GetBpfFilter()))
	if len(plan.GetWarnings()) > 0 {
		cmd.Println("  warnings:")
		for _, warning := range plan.GetWarnings() {
			cmd.Printf("    - %s\n", warning)
		}
	}
	if plan.GetCommand() != "" {
		cmd.Println("  command:")
		cmd.Printf("    %s\n", plan.GetCommand())
	}
}

func printPacketCaptureJob(cmd *cobra.Command, job *openngfwv1.PacketCaptureJob) {
	cmd.Println("packet capture job")
	if job == nil {
		cmd.Println("  no job returned")
		return
	}
	cmd.Printf("  id:              %s\n", value(job.GetId()))
	if artifactID := job.GetArtifactId(); artifactID != "" && artifactID != job.GetId() {
		cmd.Printf("  artifact id:     %s\n", artifactID)
	}
	cmd.Printf("  state:           %s\n", value(job.GetState()))
	cmd.Printf("  detail:          %s\n", value(job.GetDetail()))
	if job.GetStartedAt() != "" {
		cmd.Printf("  started:         %s\n", job.GetStartedAt())
	}
	if job.GetCompletedAt() != "" {
		cmd.Printf("  completed:       %s\n", job.GetCompletedAt())
	}
	if job.GetExitCode() != 0 {
		cmd.Printf("  exit code:       %d\n", job.GetExitCode())
	}
	cmd.Printf("  bytes:           %s\n", humanBytes(job.GetBytesWritten()))
	if job.GetSha256() != "" {
		cmd.Printf("  sha256:          %s\n", job.GetSha256())
	}
	if plan := job.GetPlan(); plan != nil {
		if plan.GetFlowId() != "" {
			cmd.Printf("  flow id:         %s\n", plan.GetFlowId())
		}
		cmd.Printf("  output:          %s\n", value(plan.GetOutputPath()))
	}
	if job.GetFilename() != "" {
		cmd.Printf("  filename:        %s\n", job.GetFilename())
	}
	if job.GetDownloadPath() != "" {
		cmd.Printf("  download:        %s\n", job.GetDownloadPath())
	}
	if job.GetMediaType() != "" {
		cmd.Printf("  media type:      %s\n", job.GetMediaType())
	}
	printPacketCaptureRetention(cmd, "  ", job.GetRetention())
	if job.GetStderr() != "" {
		cmd.Printf("  stderr:          %s\n", job.GetStderr())
	}
}

func printPacketCaptureArtifacts(cmd *cobra.Command, resp *openngfwv1.ListPacketCapturesResponse) {
	cmd.Println("packet capture artifacts")
	if resp == nil {
		cmd.Println("  no response returned")
		return
	}
	if resp.GetCaptureDir() != "" {
		cmd.Printf("  capture dir:     %s\n", resp.GetCaptureDir())
	}
	captures := resp.GetCaptures()
	if len(captures) == 0 {
		cmd.Println("  none found")
		return
	}
	for _, capture := range captures {
		artifactID := packetCaptureArtifactID(capture)
		cmd.Printf("  - id:            %s\n", value(artifactID))
		cmd.Printf("    state:         %s\n", value(capture.GetState()))
		if capture.GetCompletedAt() != "" {
			cmd.Printf("    completed:     %s\n", capture.GetCompletedAt())
		}
		cmd.Printf("    bytes:         %s\n", humanBytes(capture.GetBytesWritten()))
		if capture.GetSha256() != "" {
			cmd.Printf("    sha256:        %s\n", capture.GetSha256())
		}
		if capture.GetFilename() != "" {
			cmd.Printf("    filename:      %s\n", capture.GetFilename())
		}
		if plan := capture.GetPlan(); plan != nil {
			if plan.GetFlowId() != "" {
				cmd.Printf("    flow id:       %s\n", plan.GetFlowId())
			}
			if plan.GetOutputPath() != "" {
				cmd.Printf("    output:        %s\n", plan.GetOutputPath())
			}
		}
		if capture.GetDownloadPath() != "" {
			cmd.Printf("    download:      %s\n", capture.GetDownloadPath())
		}
		if capture.GetMediaType() != "" {
			cmd.Printf("    media type:    %s\n", capture.GetMediaType())
		}
		printPacketCaptureRetention(cmd, "    ", capture.GetRetention())
		if capture.GetDetail() != "" {
			cmd.Printf("    detail:        %s\n", capture.GetDetail())
		}
	}
}

func printPacketCaptureRetention(cmd *cobra.Command, indent string, retention *openngfwv1.PacketCaptureRetention) {
	if retention == nil || retention.GetState() == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_UNSPECIFIED {
		return
	}
	cmd.Printf("%sretention:     %s\n", indent, retentionStateLabel(retention.GetState()))
	if retention.GetRetainUntil() != "" {
		cmd.Printf("%sretain until:  %s\n", indent, retention.GetRetainUntil())
	}
	if retention.GetCaseId() != "" {
		cmd.Printf("%scase id:       %s\n", indent, retention.GetCaseId())
	}
	if retention.GetRetentionReason() != "" {
		cmd.Printf("%sreason:        %s\n", indent, retention.GetRetentionReason())
	}
	if retention.GetUpdatedAt() != "" || retention.GetUpdatedBy() != "" {
		cmd.Printf("%supdated:       %s by %s\n", indent, value(retention.GetUpdatedAt()), value(retention.GetUpdatedBy()))
	}
}

func packetCaptureArtifactID(job *openngfwv1.PacketCaptureJob) string {
	if job == nil {
		return ""
	}
	if job.GetArtifactId() != "" {
		return job.GetArtifactId()
	}
	return job.GetId()
}

func captureProtocolLabel(p openngfwv1.Protocol) string {
	if p == openngfwv1.Protocol_PROTOCOL_UNSPECIFIED {
		return "unspecified"
	}
	return shortEnum(p.String(), "PROTOCOL_")
}

func retentionStateLabel(state openngfwv1.PacketCaptureRetentionState) string {
	if state == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_UNSPECIFIED {
		return "unspecified"
	}
	return shortEnum(state.String(), "PACKET_CAPTURE_RETENTION_STATE_")
}

func captureEndpoint(ip string, port uint32) string {
	if ip == "" {
		ip = "-"
	}
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

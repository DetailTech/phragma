// Package supportbundle owns the redacted diagnostic bundle contract used by
// ngfwctl, controld, WebUI downloads, and automation readiness evidence.
package supportbundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// Schema is the stable schema identifier for serialized support bundles.
const Schema = "phragma.support.bundle.v1"

// Redacted is the placeholder used when sensitive values are removed.
const Redacted = "[redacted]"

const (
	// DefaultVersionLimit is the fallback number of policy versions to collect.
	DefaultVersionLimit = uint32(100)
	// DefaultAuditLimit is the fallback number of audit entries to collect.
	DefaultAuditLimit = uint32(300)
	// DefaultEventLimit is the fallback number of recent events to collect.
	DefaultEventLimit = uint32(500)
	// MaxVersionLimit caps policy version collection requests.
	MaxVersionLimit = uint32(1000)
	// MaxAuditLimit caps audit entry collection requests.
	MaxAuditLimit = uint32(2000)
	// MaxEventLimit caps event collection requests.
	MaxEventLimit = uint32(2000)
)

var (
	bearerRE     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	authBearerRE = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s"',;]+`)
	assignRE     = regexp.MustCompile(`(?i)(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|key|cookie)=)[^&\s"',;]+`)
	yamlRE       = regexp.MustCompile(`(?i)(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|key|cookie)\s*:\s*)[^\s"',;]+`)
	urlRE        = regexp.MustCompile(`https?://[^\s"'<>]+`)
	pathRE       = regexp.MustCompile(`(?i)(^|[\s"',;{])(["']?(?:artifact[_-]?path|bundle[_-]?path|data[_-]?dir|evidence[_-]?(?:dir|path)?|log[_-]?dir|output[_-]?(?:dir|path)?|sysctl[_-]?config[_-]?path|manifest[_-]?path|rollback[_-]?path|restored[_-]?rollback[_-]?path|source[_-]?path|source)["']?\s*[:=]\s*["']?)(/(?:var/lib|var/log(?:/openngfw)?|etc/(?:openngfw|phragma)|opt/(?:openngfw|phragma)|data|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+)[^'"\s,;}]*)`)
	absPathRE    = regexp.MustCompile(`(?i)(^|[\s"'({=,;])(/(?:var/lib|var/log(?:/openngfw)?|etc/(?:openngfw|phragma)|opt/(?:openngfw|phragma)|data|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+)[^'"\s,;}]*)`)
)

// Limits controls how much historical support-bundle data is collected.
type Limits struct {
	VersionLimit uint32
	AuditLimit   uint32
	EventLimit   uint32
}

// Bundle is the redacted support-bundle document shared by CLIs, APIs, and UI downloads.
type Bundle struct {
	SchemaVersion string              `json:"schemaVersion"`
	CollectedAt   string              `json:"collectedAt"`
	Collector     Collector           `json:"collector"`
	Client        Client              `json:"client"`
	Endpoints     map[string]Endpoint `json:"endpoints"`
	Summary       Summary             `json:"summary"`
}

// Collector identifies the component that assembled a support bundle.
type Collector struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Client identifies the caller that requested or received a support bundle.
type Client struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Endpoint records the redacted result of one support-bundle collection call.
type Endpoint struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Summary contains the compact health and readiness fields derived from collected endpoints.
type Summary struct {
	RuntimeVersion                    string   `json:"runtimeVersion"`
	RunningPolicyVersion              string   `json:"runningPolicyVersion"`
	ActiveDataplane                   string   `json:"activeDataplane"`
	ConntrackState                    string   `json:"conntrackState"`
	ConntrackUsagePercent             float64  `json:"conntrackUsagePercent"`
	ConntrackEntries                  uint64   `json:"conntrackEntries"`
	ConntrackMaxEntries               uint64   `json:"conntrackMaxEntries"`
	CandidateValidation               string   `json:"candidateValidation"`
	CandidateImpact                   string   `json:"candidateImpact"`
	CandidateHasCandidate             bool     `json:"candidateHasCandidate"`
	CandidateDirty                    bool     `json:"candidateDirty"`
	CandidateRunningVersion           uint64   `json:"candidateRunningVersion"`
	CandidateChangeCount              uint32   `json:"candidateChangeCount"`
	SessionState                      string   `json:"sessionState"`
	SessionCount                      int      `json:"sessionCount"`
	AlertCount                        int      `json:"alertCount"`
	FlowCount                         int      `json:"flowCount"`
	FeedCount                         int      `json:"feedCount"`
	EnabledFeeds                      int      `json:"enabledFeeds"`
	TelemetryExportState              string   `json:"telemetryExportState"`
	TelemetryExportEnabled            bool     `json:"telemetryExportEnabled"`
	TelemetryExportVectorState        string   `json:"telemetryExportVectorState"`
	TelemetryExportSinkCount          int      `json:"telemetryExportSinkCount"`
	TelemetryExportObservedSinkCount  int      `json:"telemetryExportObservedSinkCount"`
	TelemetryExportClickHouseEvidence string   `json:"telemetryExportClickHouseEvidence"`
	TelemetryExportWarnings           int      `json:"telemetryExportWarnings"`
	ContentPackageCount               int      `json:"contentPackageCount"`
	VerifiedContentPackages           int      `json:"verifiedContentPackages"`
	ContentPackageBlockers            int      `json:"contentPackageBlockers"`
	ReleaseAcceptanceState            string   `json:"releaseAcceptanceState"`
	ReleaseAcceptanceReady            bool     `json:"releaseAcceptanceReady"`
	ReleaseManifestPresent            bool     `json:"releaseAcceptanceManifestPresent"`
	ReleaseMissing                    uint32   `json:"releaseAcceptanceMissing"`
	ReleaseInvalid                    uint32   `json:"releaseAcceptanceInvalid"`
	ReleaseNotApplicable              uint32   `json:"releaseAcceptanceNotApplicable"`
	ReleaseTodo                       uint32   `json:"releaseAcceptanceTodo"`
	ReleaseProblems                   int      `json:"releaseAcceptanceProblems"`
	ReleaseNextActions                int      `json:"releaseAcceptanceNextActions"`
	ReleaseNextCommands               int      `json:"releaseAcceptanceNextCommands"`
	ReleaseRecordabilityReady         bool     `json:"releaseAcceptanceRecordabilityReady"`
	ReleaseRecordabilityProblems      int      `json:"releaseAcceptanceRecordabilityProblems"`
	ReleaseDirtySourcePaths           int      `json:"releaseAcceptanceDirtySourcePaths"`
	ReleaseTruncatedDirtySourceCount  uint32   `json:"releaseAcceptanceTruncatedDirtySourceCount"`
	AuditIntegrity                    string   `json:"auditIntegrity"`
	AuditEntryCount                   uint32   `json:"auditEntryCount"`
	LatestAuditHash                   string   `json:"latestAuditHash"`
	CriticalWarnings                  int      `json:"criticalWarnings"`
	Warnings                          int      `json:"warnings"`
	BlockedEngines                    int      `json:"blockedEngines"`
	FailedEndpoints                   []string `json:"failedEndpoints"`
}

// Collected holds typed endpoint responses before they are converted into a bundle summary.
type Collected struct {
	Status          *openngfwv1.GetStatusResponse
	Running         *openngfwv1.GetPolicyResponse
	CandStat        *openngfwv1.GetCandidateStatusResponse
	Validate        *openngfwv1.ValidateResponse
	Alerts          *openngfwv1.ListAlertsResponse
	Flows           *openngfwv1.ListFlowsResponse
	Sessions        *openngfwv1.ListSessionsResponse
	Feeds           *openngfwv1.ListFeedsResponse
	Content         *openngfwv1.ListContentPackagesResponse
	AuditOK         *openngfwv1.VerifyAuditIntegrityResponse
	Release         *openngfwv1.GetReleaseAcceptanceStatusResponse
	TelemetryExport *openngfwv1.GetTelemetryExportStatusResponse
}

// DefaultLimits returns the bounded default collection limits for a support bundle.
func DefaultLimits() Limits {
	return Limits{
		VersionLimit: DefaultVersionLimit,
		AuditLimit:   DefaultAuditLimit,
		EventLimit:   DefaultEventLimit,
	}
}

// Normalize fills zero limits with defaults and clamps each limit to its maximum.
func (l Limits) Normalize() Limits {
	if l.VersionLimit == 0 {
		l.VersionLimit = DefaultVersionLimit
	}
	if l.AuditLimit == 0 {
		l.AuditLimit = DefaultAuditLimit
	}
	if l.EventLimit == 0 {
		l.EventLimit = DefaultEventLimit
	}
	if l.VersionLimit > MaxVersionLimit {
		l.VersionLimit = MaxVersionLimit
	}
	if l.AuditLimit > MaxAuditLimit {
		l.AuditLimit = MaxAuditLimit
	}
	if l.EventLimit > MaxEventLimit {
		l.EventLimit = MaxEventLimit
	}
	return l
}

// CollectClient collects support-bundle endpoints from the supplied OpenNGFW gRPC connection.
func CollectClient(ctx context.Context, conn grpc.ClientConnInterface, now time.Time, limits Limits, collector Collector, client Client) Bundle {
	limits = limits.Normalize()
	endpoints := map[string]Endpoint{}
	collected := Collected{}
	system := openngfwv1.NewSystemServiceClient(conn)
	policy := openngfwv1.NewPolicyServiceClient(conn)
	alerts := openngfwv1.NewAlertServiceClient(conn)
	flows := openngfwv1.NewFlowServiceClient(conn)
	intel := openngfwv1.NewIntelServiceClient(conn)

	statusResp, err := system.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
	collected.Status = statusResp
	endpoints["status"] = ProtoEndpoint(statusResp, err)

	haResp, err := system.GetHighAvailabilityStatus(ctx, &openngfwv1.GetHighAvailabilityStatusRequest{})
	endpoints["highAvailabilityStatus"] = ProtoEndpoint(haResp, err)

	telemetryExportResp, err := system.GetTelemetryExportStatus(ctx, &openngfwv1.GetTelemetryExportStatusRequest{})
	collected.TelemetryExport = telemetryExportResp
	endpoints["telemetryExportStatus"] = ProtoEndpoint(telemetryExportResp, err)

	identityResp, err := system.GetIdentity(ctx, &openngfwv1.GetIdentityRequest{})
	endpoints["identity"] = ProtoEndpoint(identityResp, err)

	runningResp, err := policy.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
	collected.Running = runningResp
	endpoints["runningPolicy"] = RunningPolicyEndpoint(runningResp, err)

	candidateResp, err := policy.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
	endpoints["candidatePolicy"] = CandidatePolicyEndpoint(candidateResp, err)

	candidateStatusResp, err := policy.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	collected.CandStat = candidateStatusResp
	endpoints["candidateStatus"] = ProtoEndpoint(candidateStatusResp, err)

	validateResp, err := policy.Validate(ctx, &openngfwv1.ValidateRequest{})
	collected.Validate = validateResp
	endpoints["candidateValidation"] = CandidateValidationEndpoint(validateResp, err)

	runningPolicy, targetPolicy := runtimeReadinessPolicies(runningResp, candidateResp)
	runtimeReadinessResp, err := system.CheckRuntimeReadiness(ctx, &openngfwv1.CheckRuntimeReadinessRequest{
		Operation:     "commit",
		TargetPolicy:  targetPolicy,
		RunningPolicy: runningPolicy,
	})
	endpoints["runtimeReadinessPreflight"] = ProtoEndpoint(runtimeReadinessResp, err)

	versionsResp, err := policy.ListVersions(ctx, &openngfwv1.ListVersionsRequest{Limit: limits.VersionLimit})
	endpoints["versions"] = ProtoEndpoint(versionsResp, err)

	auditResp, err := policy.ListAuditEntries(ctx, &openngfwv1.ListAuditEntriesRequest{Limit: limits.AuditLimit})
	endpoints["audit"] = ProtoEndpoint(auditResp, err)

	auditIntegrityResp, err := policy.VerifyAuditIntegrity(ctx, &openngfwv1.VerifyAuditIntegrityRequest{})
	collected.AuditOK = auditIntegrityResp
	endpoints["auditIntegrity"] = ProtoEndpoint(auditIntegrityResp, err)

	alertResp, err := alerts.ListAlerts(ctx, &openngfwv1.ListAlertsRequest{Limit: limits.EventLimit})
	collected.Alerts = alertResp
	endpoints["alerts"] = ProtoEndpoint(alertResp, err)

	flowResp, err := flows.ListFlows(ctx, &openngfwv1.ListFlowsRequest{Limit: limits.EventLimit})
	collected.Flows = flowResp
	endpoints["flows"] = ProtoEndpoint(flowResp, err)

	sessionResp, err := flows.ListSessions(ctx, &openngfwv1.ListSessionsRequest{Limit: limits.EventLimit})
	collected.Sessions = sessionResp
	endpoints["sessions"] = ProtoEndpoint(sessionResp, err)

	feedResp, err := intel.ListFeeds(ctx, &openngfwv1.ListFeedsRequest{})
	collected.Feeds = feedResp
	endpoints["feeds"] = ProtoEndpoint(feedResp, err)

	contentResp, err := intel.ListContentPackages(ctx, &openngfwv1.ListContentPackagesRequest{})
	collected.Content = contentResp
	endpoints["contentPackages"] = ProtoEndpoint(contentResp, err)

	releaseResp, err := system.GetReleaseAcceptanceStatus(ctx, &openngfwv1.GetReleaseAcceptanceStatusRequest{})
	collected.Release = releaseResp
	endpoints["releaseAcceptanceStatus"] = ProtoEndpoint(releaseResp, err)

	return Build(now, collector, client, endpoints, collected)
}

func runtimeReadinessPolicies(runningResp, candidateResp *openngfwv1.GetPolicyResponse) (*openngfwv1.Policy, *openngfwv1.Policy) {
	var runningPolicy *openngfwv1.Policy
	if runningResp != nil {
		runningPolicy = runningResp.GetPolicy()
	}
	targetPolicy := runningPolicy
	if candidateResp != nil && candidateResp.GetPolicy() != nil {
		targetPolicy = candidateResp.GetPolicy()
	}
	return runningPolicy, targetPolicy
}

// Build assembles a support bundle from already collected endpoints and typed responses.
func Build(now time.Time, collector Collector, client Client, endpoints map[string]Endpoint, collected Collected) Bundle {
	if endpoints == nil {
		endpoints = map[string]Endpoint{}
	}
	return Bundle{
		SchemaVersion: Schema,
		CollectedAt:   now.UTC().Format(time.RFC3339Nano),
		Collector:     collector,
		Client:        client,
		Endpoints:     endpoints,
		Summary:       Summarize(endpoints, collected),
	}
}

// ProtoEndpoint converts a protobuf response or gRPC error into a redacted endpoint result.
func ProtoEndpoint(msg proto.Message, err error) Endpoint {
	if err != nil {
		return Endpoint{OK: false, Error: EndpointError(err)}
	}
	if msg == nil {
		return Endpoint{OK: true, Data: json.RawMessage(`{}`)}
	}
	raw, err := protojson.MarshalOptions{}.Marshal(msg)
	if err != nil {
		return Endpoint{OK: false, Error: RedactString(err.Error())}
	}
	return Endpoint{OK: true, Data: RedactRawJSON(raw)}
}

// EndpointError returns a redacted endpoint error string safe for support-bundle output.
func EndpointError(err error) string {
	switch status.Code(err) {
	case codes.Internal, codes.Unknown, codes.DataLoss:
		return "internal server error"
	default:
		return RedactString(err.Error())
	}
}

// CandidatePolicyEndpoint treats a missing candidate policy as an empty successful endpoint.
func CandidatePolicyEndpoint(resp *openngfwv1.GetPolicyResponse, err error) Endpoint {
	if status.Code(err) == codes.NotFound {
		return Endpoint{OK: true, Data: json.RawMessage(`{}`)}
	}
	return ProtoEndpoint(resp, err)
}

// RunningPolicyEndpoint treats a missing running policy as an empty successful endpoint.
func RunningPolicyEndpoint(resp *openngfwv1.GetPolicyResponse, err error) Endpoint {
	if status.Code(err) == codes.NotFound {
		return Endpoint{OK: true, Data: json.RawMessage(`{}`)}
	}
	return ProtoEndpoint(resp, err)
}

// CandidateValidationEndpoint treats an unready candidate as an empty successful endpoint.
func CandidateValidationEndpoint(resp *openngfwv1.ValidateResponse, err error) Endpoint {
	if status.Code(err) == codes.FailedPrecondition {
		return Endpoint{OK: true, Data: json.RawMessage(`{}`)}
	}
	return ProtoEndpoint(resp, err)
}

// RedactRawJSON recursively redacts sensitive keys and string values from JSON bytes.
func RedactRawJSON(raw []byte) json.RawMessage {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		encoded, _ := json.Marshal(RedactString(string(raw)))
		return json.RawMessage(encoded)
	}
	encoded, err := json.Marshal(redactValue(value))
	if err != nil {
		encoded, _ := json.Marshal(RedactString(string(raw)))
		return json.RawMessage(encoded)
	}
	return json.RawMessage(encoded)
}

func redactValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			if SensitiveDetailListKey(key) {
				out[key] = redactDetailList(child)
				continue
			}
			if SensitiveCommandKey(key) {
				out[key] = redactCommandValue(child)
				continue
			}
			if SensitiveKey(key) {
				out[key] = Redacted
				continue
			}
			out[key] = redactValue(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = redactValue(child)
		}
		return out
	case string:
		return RedactString(v)
	default:
		return value
	}
}

func redactDetailList(value any) any {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			if _, ok := child.(string); ok {
				out[i] = Redacted
				continue
			}
			out[i] = redactValue(child)
		}
		return out
	case string:
		return Redacted
	default:
		return redactValue(value)
	}
}

func redactCommandValue(value any) any {
	switch v := value.(type) {
	case []any:
		return redactCommandList(v)
	default:
		return redactValue(value)
	}
}

func redactCommandList(items []any) []any {
	out := make([]any, 0, len(items))
	redactNext := false
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			out = append(out, redactValue(item))
			redactNext = false
			continue
		}
		value, next := redactCommandArg(text, redactNext)
		out = append(out, value)
		redactNext = next
	}
	return out
}

func redactCommandArg(arg string, forceRedact bool) (string, bool) {
	if forceRedact {
		return Redacted, false
	}
	prefix, name, assigned, ok := splitCLIFlag(arg)
	if !ok {
		return RedactString(arg), false
	}
	if SensitiveKey(name) || SensitivePathFlag(name) {
		if assigned != nil {
			return prefix + name + "=" + Redacted, false
		}
		return arg, true
	}
	return RedactString(arg), false
}

func splitCLIFlag(arg string) (prefix, name string, assigned *string, ok bool) {
	if strings.HasPrefix(arg, "--") {
		prefix = "--"
		name = strings.TrimPrefix(arg, "--")
	} else if strings.HasPrefix(arg, "-") {
		prefix = "-"
		name = strings.TrimPrefix(arg, "-")
	} else {
		return "", "", nil, false
	}
	before, after, hasAssign := strings.Cut(name, "=")
	if before == "" {
		return "", "", nil, false
	}
	for _, r := range before {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "", "", nil, false
		}
	}
	if hasAssign {
		assigned = &after
	}
	return prefix, before, assigned, true
}

// SensitiveCommandKey reports command arrays where flag-adjacent argument
// values may contain local paths or secrets that plain string redaction cannot
// infer safely.
func SensitiveCommandKey(key string) bool {
	switch normalizeRedactionKey(key) {
	case "command", "nextcommand", "nextcommands":
		return true
	default:
		return false
	}
}

// SensitiveDetailListKey reports detail arrays where values are operational
// disclosure, but length should remain available for bundle summaries.
func SensitiveDetailListKey(key string) bool {
	normalized := normalizeRedactionKey(key)
	switch normalized {
	case "alloweddirtypaths", "dirtysourcepaths":
		return true
	default:
		return false
	}
}

// SensitiveKey reports whether a field or query key should be redacted.
func SensitiveKey(key string) bool {
	normalized := normalizeRedactionKey(key)
	switch normalized {
	case "authorization", "proxyauthorization", "cookie", "setcookie",
		"token", "accesstoken", "refreshtoken", "idtoken", "sessiontoken",
		"key", "apikey", "apiaccesskey", "accesskey", "clientsecret",
		"password", "passwd", "credential",
		"psk", "pskfile", "privatekey", "privatekeyfile",
		"datadir", "evidencedir", "evidencepath", "artifactpath", "bundlepath",
		"logdir", "outputpath", "sysctlconfigpath",
		"manifestpath", "rollbackpath", "restoredrollbackpath", "sourcepath":
		return true
	}
	return strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "credential") ||
		strings.Contains(normalized, "privatekey") ||
		strings.Contains(normalized, "apikey") ||
		strings.Contains(normalized, "clientsecret") ||
		strings.Contains(normalized, "pskfile") ||
		strings.Contains(normalized, "secretfile")
}

// SensitivePathFlag reports CLI flags whose values disclose local collection
// paths even when the value appears as the next array element.
func SensitivePathFlag(key string) bool {
	switch normalizeRedactionKey(key) {
	case "artifact", "artifactpath", "bundle", "bundlepath", "evidence", "evidencedir", "evidencepath",
		"file", "manifest", "manifestpath", "output", "outputdir", "outputpath", "path", "source", "sourcepath":
		return true
	default:
		return false
	}
}

func normalizeRedactionKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return -1
	}, key)
}

// RedactString removes credentials, tokens, secrets, and sensitive paths from text.
func RedactString(value string) string {
	value = redactURLs(value)
	value = authBearerRE.ReplaceAllString(value, "${1}"+Redacted)
	value = bearerRE.ReplaceAllString(value, "${1}"+Redacted)
	value = assignRE.ReplaceAllString(value, "${1}${2}"+Redacted)
	value = yamlRE.ReplaceAllString(value, "${1}${2}"+Redacted)
	value = pathRE.ReplaceAllString(value, "${1}${2}"+Redacted)
	value = absPathRE.ReplaceAllString(value, "${1}"+Redacted)
	return value
}

func redactURLs(value string) string {
	return urlRE.ReplaceAllStringFunc(value, redactURL)
}

func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return raw
	}
	sanitized := *parsed
	hadUserInfo := sanitized.User != nil
	sanitized.User = nil
	sanitized.RawQuery = redactRawQuery(sanitized.RawQuery)
	out := sanitized.String()
	if hadUserInfo {
		prefix := sanitized.Scheme + "://"
		out = strings.Replace(out, prefix, prefix+Redacted+"@", 1)
	}
	return out
}

func redactRawQuery(raw string) string {
	if raw == "" {
		return raw
	}
	var out strings.Builder
	start := 0
	for i, r := range raw {
		if r != '&' && r != ';' {
			continue
		}
		out.WriteString(redactRawQueryPart(raw[start:i]))
		out.WriteRune(r)
		start = i + 1
	}
	out.WriteString(redactRawQueryPart(raw[start:]))
	return out.String()
}

func redactRawQueryPart(part string) string {
	name, _, _ := strings.Cut(part, "=")
	decodedName, err := url.QueryUnescape(name)
	if err != nil {
		decodedName = name
	}
	if SensitiveKey(decodedName) {
		return name + "=" + Redacted
	}
	return part
}

// Summarize derives the compact support-bundle summary from endpoint status and payloads.
func Summarize(endpoints map[string]Endpoint, collected Collected) Summary {
	summary := Summary{RunningPolicyVersion: "none", CandidateValidation: "not-set", AuditIntegrity: "unknown", FailedEndpoints: []string{}}
	if st := collected.Status; st != nil {
		summary.RuntimeVersion = st.GetRuntime().GetVersion()
		summary.ActiveDataplane = firstNonEmpty(st.GetDataplane().GetActiveDataplane(), st.GetRuntime().GetActiveDataplane())
		if ct := st.GetDataplane().GetConntrack(); ct != nil {
			summary.ConntrackState = ct.GetState()
			summary.ConntrackUsagePercent = ct.GetUsagePercent()
			summary.ConntrackEntries = ct.GetCurrentEntries()
			summary.ConntrackMaxEntries = ct.GetMaxEntries()
		}
		for _, w := range st.GetWarnings() {
			switch w.GetSeverity() {
			case "critical":
				summary.CriticalWarnings++
			case "warning":
				summary.Warnings++
			}
		}
		for _, e := range st.GetEngines() {
			if e.GetState() == "missing-prerequisites" || e.GetState() == "failed" {
				summary.BlockedEngines++
			}
		}
	}
	if running := collected.Running; running != nil && running.GetVersion() != 0 {
		summary.RunningPolicyVersion = fmt.Sprint(running.GetVersion())
	} else if ep, ok := endpoints["runningPolicy"]; ok && !ep.OK {
		summary.RunningPolicyVersion = "unavailable"
	}
	if validation := collected.Validate; validation != nil {
		if validation.GetValid() {
			summary.CandidateValidation = "valid"
		} else {
			summary.CandidateValidation = "invalid"
		}
		if impact := validation.GetImpact(); impact != nil {
			summary.CandidateImpact = RiskLabel(impact.GetRisk())
		}
	} else if ep, ok := endpoints["candidateValidation"]; ok && !ep.OK {
		summary.CandidateValidation = "unavailable"
	}
	if candidateStatus := collected.CandStat; candidateStatus != nil {
		summary.CandidateHasCandidate = candidateStatus.GetHasCandidate()
		summary.CandidateDirty = candidateStatus.GetDirty()
		summary.CandidateRunningVersion = candidateStatus.GetRunningVersion()
		summary.CandidateChangeCount = candidateStatus.GetChangeCount()
		if impact := candidateStatus.GetImpact(); impact != nil && summary.CandidateImpact == "" {
			summary.CandidateImpact = RiskLabel(impact.GetRisk())
		}
	}
	if alerts := collected.Alerts; alerts != nil {
		summary.AlertCount = len(alerts.GetAlerts())
	}
	if flows := collected.Flows; flows != nil {
		summary.FlowCount = len(flows.GetFlows())
	}
	if sessions := collected.Sessions; sessions != nil {
		summary.SessionState = sessions.GetState()
		summary.SessionCount = len(sessions.GetSessions())
	}
	if feeds := collected.Feeds; feeds != nil {
		summary.FeedCount = len(feeds.GetFeeds())
		for _, f := range feeds.GetFeeds() {
			if f.GetEnabled() {
				summary.EnabledFeeds++
			}
		}
	}
	if telemetryExport := collected.TelemetryExport; telemetryExport != nil {
		summary.TelemetryExportState = telemetryExport.GetState()
		summary.TelemetryExportEnabled = telemetryExport.GetTelemetryEnabled()
		summary.TelemetryExportVectorState = telemetryExport.GetVector().GetState()
		summary.TelemetryExportSinkCount = len(telemetryExport.GetExports())
		for _, sink := range telemetryExport.GetExports() {
			if sink.GetEvidenceState() == "receiving" {
				summary.TelemetryExportObservedSinkCount++
			}
		}
		if clickhouse := telemetryExport.GetClickhouse(); clickhouse != nil {
			summary.TelemetryExportClickHouseEvidence = clickhouse.GetEvidenceState()
			if summary.TelemetryExportClickHouseEvidence == "" && clickhouse.GetConfigured() {
				summary.TelemetryExportClickHouseEvidence = "configured"
			}
		}
		summary.TelemetryExportWarnings = len(telemetryExport.GetWarnings())
	} else if ep, ok := endpoints["telemetryExportStatus"]; ok && !ep.OK {
		summary.TelemetryExportState = "unavailable"
	}
	if content := collected.Content; content != nil {
		summary.ContentPackageCount = len(content.GetPackages())
		for _, pkg := range content.GetPackages() {
			if pkg.GetState() == "verified" {
				summary.VerifiedContentPackages++
			}
			summary.ContentPackageBlockers += len(pkg.GetBlockers())
		}
	}
	if release := collected.Release; release != nil {
		summary.ReleaseAcceptanceState = release.GetState()
		summary.ReleaseAcceptanceReady = release.GetReady()
		summary.ReleaseManifestPresent = release.GetManifestPresent()
		if release.GetSummary() != nil {
			summary.ReleaseMissing = release.GetSummary().GetMissing()
			summary.ReleaseInvalid = release.GetSummary().GetInvalid()
			summary.ReleaseNotApplicable = release.GetSummary().GetNotApplicable()
			summary.ReleaseTodo = release.GetSummary().GetTodo()
		}
		summary.ReleaseProblems = len(release.GetProblems())
		for _, check := range release.GetChecks() {
			if strings.TrimSpace(check.GetNextAction()) != "" {
				summary.ReleaseNextActions++
			}
			if len(check.GetNextCommand()) > 0 {
				summary.ReleaseNextCommands++
			}
		}
		if recordability := release.GetRecordability(); recordability != nil {
			summary.ReleaseRecordabilityReady = recordability.GetReady()
			summary.ReleaseRecordabilityProblems = len(recordability.GetProblems())
			summary.ReleaseDirtySourcePaths = len(recordability.GetDirtySourcePaths())
			//nolint:staticcheck // Preserve compatibility summary while the API field is still served.
			summary.ReleaseTruncatedDirtySourceCount = recordability.GetTruncatedDirtySourceCount()
		}
	}
	if audit := collected.AuditOK; audit != nil {
		if audit.GetOk() {
			summary.AuditIntegrity = "verified"
		} else {
			summary.AuditIntegrity = "failed"
		}
		summary.AuditEntryCount = audit.GetEntryCount()
		summary.LatestAuditHash = audit.GetLatestEntryHash()
	} else if ep, ok := endpoints["auditIntegrity"]; ok && !ep.OK {
		summary.AuditIntegrity = "unavailable"
	}
	for name, ep := range endpoints {
		if !ep.OK {
			summary.FailedEndpoints = append(summary.FailedEndpoints, name)
		}
	}
	sort.Strings(summary.FailedEndpoints)
	return summary
}

// ToProto converts a bundle into the API response shape used by the system service.
func ToProto(bundle Bundle) (*openngfwv1.GetSupportBundleResponse, error) {
	endpoints := make(map[string]*openngfwv1.SupportBundleEndpoint, len(bundle.Endpoints))
	for name, ep := range bundle.Endpoints {
		data, err := endpointDataStruct(ep.Data)
		if err != nil {
			return nil, fmt.Errorf("convert endpoint %s: %w", name, err)
		}
		endpoints[name] = &openngfwv1.SupportBundleEndpoint{
			Ok:    ep.OK,
			Data:  data,
			Error: ep.Error,
		}
	}
	return &openngfwv1.GetSupportBundleResponse{
		SchemaVersion: bundle.SchemaVersion,
		CollectedAt:   bundle.CollectedAt,
		Collector: &openngfwv1.SupportBundleCollector{
			Type:    bundle.Collector.Type,
			Name:    bundle.Collector.Name,
			Version: bundle.Collector.Version,
		},
		Endpoints: endpoints,
		Summary:   summaryProto(bundle.Summary),
	}, nil
}

// FromProto converts an API support-bundle response back into the local bundle shape.
func FromProto(resp *openngfwv1.GetSupportBundleResponse, client Client) (Bundle, error) {
	if resp == nil {
		return Bundle{}, fmt.Errorf("support bundle response is nil")
	}
	endpoints := make(map[string]Endpoint, len(resp.GetEndpoints()))
	for name, ep := range resp.GetEndpoints() {
		endpoint, err := endpointFromProto(ep)
		if err != nil {
			return Bundle{}, fmt.Errorf("convert endpoint %s: %w", name, err)
		}
		endpoints[name] = endpoint
	}
	return Bundle{
		SchemaVersion: resp.GetSchemaVersion(),
		CollectedAt:   resp.GetCollectedAt(),
		Collector: Collector{
			Type:    resp.GetCollector().GetType(),
			Name:    resp.GetCollector().GetName(),
			Version: resp.GetCollector().GetVersion(),
		},
		Client:    client,
		Endpoints: endpoints,
		Summary:   summaryFromProto(resp.GetSummary()),
	}, nil
}

func endpointDataStruct(raw json.RawMessage) (*structpb.Struct, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	if object, ok := value.(map[string]any); ok {
		return structpb.NewStruct(object)
	}
	return structpb.NewStruct(map[string]any{"value": value})
}

func endpointFromProto(ep *openngfwv1.SupportBundleEndpoint) (Endpoint, error) {
	if ep == nil {
		return Endpoint{OK: true, Data: json.RawMessage(`{}`)}, nil
	}
	out := Endpoint{OK: ep.GetOk(), Error: RedactString(ep.GetError())}
	if ep.GetData() != nil {
		raw, err := json.Marshal(ep.GetData().AsMap())
		if err != nil {
			return Endpoint{}, err
		}
		out.Data = RedactRawJSON(raw)
	}
	return out, nil
}

func summaryProto(summary Summary) *openngfwv1.SupportBundleSummary {
	return &openngfwv1.SupportBundleSummary{
		RuntimeVersion:                             summary.RuntimeVersion,
		RunningPolicyVersion:                       summary.RunningPolicyVersion,
		ActiveDataplane:                            summary.ActiveDataplane,
		ConntrackState:                             summary.ConntrackState,
		ConntrackUsagePercent:                      summary.ConntrackUsagePercent,
		ConntrackEntries:                           summary.ConntrackEntries,
		ConntrackMaxEntries:                        summary.ConntrackMaxEntries,
		CandidateValidation:                        summary.CandidateValidation,
		CandidateImpact:                            summary.CandidateImpact,
		CandidateHasCandidate:                      summary.CandidateHasCandidate,
		CandidateDirty:                             summary.CandidateDirty,
		CandidateRunningVersion:                    summary.CandidateRunningVersion,
		CandidateChangeCount:                       summary.CandidateChangeCount,
		SessionState:                               summary.SessionState,
		SessionCount:                               int32(summary.SessionCount),
		AlertCount:                                 int32(summary.AlertCount),
		FlowCount:                                  int32(summary.FlowCount),
		FeedCount:                                  int32(summary.FeedCount),
		EnabledFeeds:                               int32(summary.EnabledFeeds),
		ContentPackageCount:                        int32(summary.ContentPackageCount),
		VerifiedContentPackages:                    int32(summary.VerifiedContentPackages),
		ContentPackageBlockers:                     int32(summary.ContentPackageBlockers),
		ReleaseAcceptanceState:                     summary.ReleaseAcceptanceState,
		ReleaseAcceptanceReady:                     summary.ReleaseAcceptanceReady,
		ReleaseAcceptanceManifestPresent:           summary.ReleaseManifestPresent,
		ReleaseAcceptanceMissing:                   summary.ReleaseMissing,
		ReleaseAcceptanceInvalid:                   summary.ReleaseInvalid,
		ReleaseAcceptanceNotApplicable:             summary.ReleaseNotApplicable,
		ReleaseAcceptanceTodo:                      summary.ReleaseTodo,
		ReleaseAcceptanceProblems:                  int32(summary.ReleaseProblems),
		ReleaseAcceptanceNextActions:               int32(summary.ReleaseNextActions),
		ReleaseAcceptanceNextCommands:              int32(summary.ReleaseNextCommands),
		ReleaseAcceptanceRecordabilityReady:        summary.ReleaseRecordabilityReady,
		ReleaseAcceptanceRecordabilityProblems:     int32(summary.ReleaseRecordabilityProblems),
		ReleaseAcceptanceDirtySourcePaths:          int32(summary.ReleaseDirtySourcePaths),
		ReleaseAcceptanceTruncatedDirtySourceCount: summary.ReleaseTruncatedDirtySourceCount,
		TelemetryExportState:                       summary.TelemetryExportState,
		TelemetryExportEnabled:                     summary.TelemetryExportEnabled,
		TelemetryExportVectorState:                 summary.TelemetryExportVectorState,
		TelemetryExportSinkCount:                   int32(summary.TelemetryExportSinkCount),
		TelemetryExportObservedSinkCount:           int32(summary.TelemetryExportObservedSinkCount),
		TelemetryExportClickhouseEvidence:          summary.TelemetryExportClickHouseEvidence,
		TelemetryExportWarnings:                    int32(summary.TelemetryExportWarnings),
		AuditIntegrity:                             summary.AuditIntegrity,
		AuditEntryCount:                            summary.AuditEntryCount,
		LatestAuditHash:                            summary.LatestAuditHash,
		CriticalWarnings:                           int32(summary.CriticalWarnings),
		Warnings:                                   int32(summary.Warnings),
		BlockedEngines:                             int32(summary.BlockedEngines),
		FailedEndpoints:                            append([]string{}, summary.FailedEndpoints...),
	}
}

func summaryFromProto(summary *openngfwv1.SupportBundleSummary) Summary {
	if summary == nil {
		return Summary{RunningPolicyVersion: "none", CandidateValidation: "not-set", AuditIntegrity: "unknown", FailedEndpoints: []string{}}
	}
	return Summary{
		RuntimeVersion:                    summary.GetRuntimeVersion(),
		RunningPolicyVersion:              summary.GetRunningPolicyVersion(),
		ActiveDataplane:                   summary.GetActiveDataplane(),
		ConntrackState:                    summary.GetConntrackState(),
		ConntrackUsagePercent:             summary.GetConntrackUsagePercent(),
		ConntrackEntries:                  summary.GetConntrackEntries(),
		ConntrackMaxEntries:               summary.GetConntrackMaxEntries(),
		CandidateValidation:               summary.GetCandidateValidation(),
		CandidateImpact:                   summary.GetCandidateImpact(),
		CandidateHasCandidate:             summary.GetCandidateHasCandidate(),
		CandidateDirty:                    summary.GetCandidateDirty(),
		CandidateRunningVersion:           summary.GetCandidateRunningVersion(),
		CandidateChangeCount:              summary.GetCandidateChangeCount(),
		SessionState:                      summary.GetSessionState(),
		SessionCount:                      int(summary.GetSessionCount()),
		AlertCount:                        int(summary.GetAlertCount()),
		FlowCount:                         int(summary.GetFlowCount()),
		FeedCount:                         int(summary.GetFeedCount()),
		EnabledFeeds:                      int(summary.GetEnabledFeeds()),
		ContentPackageCount:               int(summary.GetContentPackageCount()),
		VerifiedContentPackages:           int(summary.GetVerifiedContentPackages()),
		ContentPackageBlockers:            int(summary.GetContentPackageBlockers()),
		ReleaseAcceptanceState:            summary.GetReleaseAcceptanceState(),
		ReleaseAcceptanceReady:            summary.GetReleaseAcceptanceReady(),
		ReleaseManifestPresent:            summary.GetReleaseAcceptanceManifestPresent(),
		ReleaseMissing:                    summary.GetReleaseAcceptanceMissing(),
		ReleaseInvalid:                    summary.GetReleaseAcceptanceInvalid(),
		ReleaseNotApplicable:              summary.GetReleaseAcceptanceNotApplicable(),
		ReleaseTodo:                       summary.GetReleaseAcceptanceTodo(),
		ReleaseProblems:                   int(summary.GetReleaseAcceptanceProblems()),
		ReleaseNextActions:                int(summary.GetReleaseAcceptanceNextActions()),
		ReleaseNextCommands:               int(summary.GetReleaseAcceptanceNextCommands()),
		ReleaseRecordabilityReady:         summary.GetReleaseAcceptanceRecordabilityReady(),
		ReleaseRecordabilityProblems:      int(summary.GetReleaseAcceptanceRecordabilityProblems()),
		ReleaseDirtySourcePaths:           int(summary.GetReleaseAcceptanceDirtySourcePaths()),
		ReleaseTruncatedDirtySourceCount:  summary.GetReleaseAcceptanceTruncatedDirtySourceCount(),
		TelemetryExportState:              summary.GetTelemetryExportState(),
		TelemetryExportEnabled:            summary.GetTelemetryExportEnabled(),
		TelemetryExportVectorState:        summary.GetTelemetryExportVectorState(),
		TelemetryExportSinkCount:          int(summary.GetTelemetryExportSinkCount()),
		TelemetryExportObservedSinkCount:  int(summary.GetTelemetryExportObservedSinkCount()),
		TelemetryExportClickHouseEvidence: summary.GetTelemetryExportClickhouseEvidence(),
		TelemetryExportWarnings:           int(summary.GetTelemetryExportWarnings()),
		AuditIntegrity:                    summary.GetAuditIntegrity(),
		AuditEntryCount:                   summary.GetAuditEntryCount(),
		LatestAuditHash:                   summary.GetLatestAuditHash(),
		CriticalWarnings:                  int(summary.GetCriticalWarnings()),
		Warnings:                          int(summary.GetWarnings()),
		BlockedEngines:                    int(summary.GetBlockedEngines()),
		FailedEndpoints:                   append([]string{}, summary.GetFailedEndpoints()...),
	}
}

// Filename returns a timestamped JSON filename for a collected support bundle.
func Filename(now time.Time) string {
	stamp := now.UTC().Format(time.RFC3339Nano)
	stamp = strings.NewReplacer(":", "-", ".", "-").Replace(stamp)
	return "phragma-support-" + stamp + ".json"
}

// RiskLabel converts an API change risk enum into its support-bundle summary label.
func RiskLabel(r openngfwv1.ChangeRisk) string {
	switch r {
	case openngfwv1.ChangeRisk_CHANGE_RISK_LOW:
		return "low"
	case openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM:
		return "medium"
	case openngfwv1.ChangeRisk_CHANGE_RISK_HIGH:
		return "high"
	default:
		return "unspecified"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

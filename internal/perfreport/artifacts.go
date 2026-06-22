package perfreport

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const rawThroughputTolerance = 0.001 // 0.1%

const (
	maxSummaryArtifactBytes = 2 * 1024 * 1024
	maxIperfArtifactBytes   = 10 * 1024 * 1024
	maxStatusArtifactBytes  = 2 * 1024 * 1024
	maxNftArtifactBytes     = 2 * 1024 * 1024
)

var (
	conntrackStatusRE            = regexp.MustCompile(`(?m)^\s*state table:\s+(\S+)(?:\s+([0-9]+)/([0-9]+) entries \(([0-9.]+)%\))?`)
	hostTuningStatusRE           = regexp.MustCompile(`(?m)^\s*kernel tuning:\s+(\S+)`)
	flowtableHostRE              = regexp.MustCompile(`(?m)^\s*flowtable host:\s+(\S+)`)
	flowtableRuntimeRE           = regexp.MustCompile(`(?m)^\s*flowtable live:\s+(\S+)`)
	inspectionPolicyRE           = regexp.MustCompile(`(?m)^\s*inspection:\s+(.+?)\s*$`)
	inspectionReadinessRE        = regexp.MustCompile(`(?m)^\s*inspection ready:\s*(\S+)`)
	inspectionEngineRE           = regexp.MustCompile(`(?m)^\s*inspection eng:\s+(\S+)\s+(\S+)/(\S+)`)
	inspectionFailureBehaviorRE  = regexp.MustCompile(`(?m)^\s*fail behavior:\s+(\S+)`)
	inspectionBypassReasonRE     = regexp.MustCompile(`(?m)^\s*bypass reason:\s+(.+?)\s*$`)
	inspectionDegradedBehaviorRE = regexp.MustCompile(`(?m)^\s*degraded mode:\s+(.+?)\s*$`)
)

// ValidateSummaryFile validates summary.json and, when present, the adjacent
// raw artifacts that prove the summary's high-bandwidth claims.
func ValidateSummaryFile(path string) (ValidationResult, error) {
	data, err := readFileBounded(path, maxSummaryArtifactBytes)
	if err != nil {
		return ValidationResult{}, err
	}
	result := ValidateSummary(data)
	if !result.Valid() {
		return result, nil
	}
	dir := filepath.Dir(path)
	validateIperfArtifact(filepath.Join(dir, "iperf3.json"), &result)
	validateStatusArtifacts(dir, &result)
	validateNftArtifacts(dir, &result)
	return result, nil
}

type iperfReport struct {
	Error string `json:"error"`
	Start struct {
		Connected    []struct{} `json:"connected"`
		ConnectingTo struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"connecting_to"`
		TestStart struct {
			NumStreams int     `json:"num_streams"`
			Duration   float64 `json:"duration"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		SumReceived iperfSummaryStream `json:"sum_received"`
		SumSent     iperfSummaryStream `json:"sum_sent"`
		Sum         iperfSummaryStream `json:"sum"`
		Streams     []struct {
			Sender iperfSummaryStream `json:"sender"`
		} `json:"streams"`
	} `json:"end"`
}

type iperfSummaryStream struct {
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   int64   `json:"retransmits"`
}

type statusArtifact struct {
	inspectionFound bool
	inspection      InspectionEvidence
	conntrackFound  bool
	conntrack       ConntrackEvidence
	hostTuningFound bool
	hostTuning      HostTuningEvidence
	flowHostFound   bool
	flowHostState   string
	flowLiveFound   bool
	flowLiveState   string
}

func validateIperfArtifact(path string, result *ValidationResult) {
	data, err := readFileBounded(path, maxIperfArtifactBytes)
	if err != nil {
		if os.IsNotExist(err) {
			if requiresConntrackEvidence(result.Summary, nil) {
				result.Warnings = append(result.Warnings, "raw iperf3.json is not present next to summary.json; throughput cannot be traced to raw iperf evidence")
			}
			return
		}
		result.Errors = append(result.Errors, "read iperf3.json: "+err.Error())
		return
	}

	var report iperfReport
	if err := json.Unmarshal(data, &report); err != nil {
		result.Errors = append(result.Errors, "iperf3.json invalid JSON: "+err.Error())
		return
	}
	if report.Error != "" {
		result.Errors = append(result.Errors, "iperf3.json reports benchmark error: "+report.Error)
		return
	}

	measured := chooseThroughput(report)
	if measured.BitsPerSecond <= 0 || !finiteNonNegative(measured.BitsPerSecond) {
		result.Errors = append(result.Errors, "iperf3.json does not contain a positive end.sum_received/sum/sum_sent bits_per_second value")
		return
	}
	if !closeRelative(result.Summary.TCPBitsPerSecond, measured.BitsPerSecond, rawThroughputTolerance) {
		result.Errors = append(result.Errors, fmt.Sprintf("summary tcp_bits_per_second %.3f does not match iperf3.json %.3f", result.Summary.TCPBitsPerSecond, measured.BitsPerSecond))
	}
	measuredGbps := measured.BitsPerSecond / 1_000_000_000
	if !closeRelative(result.Summary.TCPGbps, measuredGbps, rawThroughputTolerance) {
		result.Errors = append(result.Errors, fmt.Sprintf("summary tcp_gbps %.6f does not match iperf3.json %.6f", result.Summary.TCPGbps, measuredGbps))
	}

	retransmits := iperfRetransmits(report)
	if int64(result.Summary.TCPRetransmits) != retransmits {
		result.Errors = append(result.Errors, fmt.Sprintf("summary tcp_retransmits %d does not match iperf3.json %d", result.Summary.TCPRetransmits, retransmits))
	}
	if report.Start.ConnectingTo.Host != "" && report.Start.ConnectingTo.Host != result.Summary.Target.IP {
		result.Errors = append(result.Errors, fmt.Sprintf("summary target.ip %q does not match iperf3.json %q", result.Summary.Target.IP, report.Start.ConnectingTo.Host))
	}
	if report.Start.ConnectingTo.Port > 0 && report.Start.ConnectingTo.Port != result.Summary.Target.Port {
		result.Errors = append(result.Errors, fmt.Sprintf("summary target.port %d does not match iperf3.json %d", result.Summary.Target.Port, report.Start.ConnectingTo.Port))
	}
	if report.Start.TestStart.Duration > 0 && math.Abs(float64(result.Summary.DurationSeconds)-report.Start.TestStart.Duration) > 1 {
		result.Errors = append(result.Errors, fmt.Sprintf("summary duration_seconds %d does not match iperf3.json %.3f", result.Summary.DurationSeconds, report.Start.TestStart.Duration))
	}
	streams := report.Start.TestStart.NumStreams
	if streams == 0 {
		streams = len(report.Start.Connected)
	}
	if streams > 0 && streams != result.Summary.ParallelStreams {
		result.Errors = append(result.Errors, fmt.Sprintf("summary parallel_streams %d does not match iperf3.json %d", result.Summary.ParallelStreams, streams))
	}
}

func chooseThroughput(report iperfReport) iperfSummaryStream {
	if report.End.SumReceived.BitsPerSecond > 0 {
		return report.End.SumReceived
	}
	if report.End.Sum.BitsPerSecond > 0 {
		return report.End.Sum
	}
	return report.End.SumSent
}

func iperfRetransmits(report iperfReport) int64 {
	var total int64
	for _, stream := range report.End.Streams {
		total += stream.Sender.Retransmits
	}
	if total == 0 {
		total = report.End.SumSent.Retransmits
	}
	return total
}

func closeRelative(got, want, tolerance float64) bool {
	if got == want {
		return true
	}
	if !finiteNonNegative(got) || !finiteNonNegative(want) {
		return false
	}
	scale := math.Max(math.Abs(want), 1)
	return math.Abs(got-want)/scale <= tolerance
}

func validateStatusArtifacts(dir string, result *ValidationResult) {
	path, data, ok, duplicates, err := readFirstExisting(dir, []string{
		"ngfw-status-active.txt",
		"firewall-status-active.txt",
		"ngfw-status-final.txt",
		"firewall-status-final.txt",
		"ngfw-status.txt",
		"firewall-status.txt",
	}, maxStatusArtifactBytes)
	if err != nil {
		result.Errors = append(result.Errors, "read status artifact: "+err.Error())
		return
	}
	if len(duplicates) > 0 {
		result.Errors = append(result.Errors, "multiple status artifacts found; remove ambiguous files before verification (selected "+filepath.Base(path)+", also found "+strings.Join(duplicates, ", ")+")")
	}
	if !ok {
		if result.Summary.HostTuningEvidence != nil && result.Summary.HostTuningEvidence.StatusCaptured {
			result.Warnings = append(result.Warnings, "host_tuning_evidence.status_captured is true but no raw ngfwctl status artifact is present")
		}
		if result.Summary.ConntrackEvidence != nil && result.Summary.ConntrackEvidence.StatusCaptured {
			result.Warnings = append(result.Warnings, "conntrack_evidence.status_captured is true but no raw ngfwctl status artifact is present")
		}
		if result.Summary.FlowtableEvidence != nil && result.Summary.FlowtableEvidence.StatusCaptured {
			result.Warnings = append(result.Warnings, "flowtable_evidence.status_captured is true but no raw ngfwctl status artifact is present")
		}
		if result.Summary.InspectionEvidence != nil && result.Summary.InspectionEvidence.StatusCaptured {
			result.Warnings = append(result.Warnings, "inspection_evidence.status_captured is true but no raw ngfwctl status artifact is present")
		}
		return
	}
	parsed := parseStatusArtifact(string(data))
	if result.Summary.InspectionEvidence != nil {
		validateInspectionStatusArtifact(path, parsed, result.Summary.InspectionEvidence, result)
	}
	if result.Summary.HostTuningEvidence != nil {
		validateHostTuningArtifact(path, parsed, result.Summary.HostTuningEvidence, result)
	}
	if result.Summary.ConntrackEvidence != nil {
		validateConntrackArtifact(path, parsed, result.Summary.ConntrackEvidence, result)
	}
	if result.Summary.FlowtableEvidence != nil {
		validateFlowtableStatusArtifact(path, parsed, result.Summary.FlowtableEvidence, result)
	}
}

func validateNftArtifacts(dir string, result *ValidationResult) {
	path, data, ok, duplicates, err := readFirstExisting(dir, []string{
		"nft-openngfw-active.txt",
		"nft-openngfw-final.txt",
		"nft-openngfw.txt",
	}, maxNftArtifactBytes)
	if err != nil {
		result.Errors = append(result.Errors, "read nftables artifact: "+err.Error())
		return
	}
	e := result.Summary.FlowtableEvidence
	if e == nil {
		return
	}
	if len(duplicates) > 0 {
		result.Errors = append(result.Errors, "multiple nftables artifacts found; remove ambiguous files before verification (selected "+filepath.Base(path)+", also found "+strings.Join(duplicates, ", ")+")")
	}
	if !ok {
		if e.NftRulesetCaptured {
			result.Warnings = append(result.Warnings, "flowtable_evidence.nft_ruleset_captured is true but no raw nftables artifact is present")
		}
		return
	}
	text := string(data)
	declared := strings.Contains(text, "flowtable fastpath")
	offload := strings.Contains(text, "flow add @fastpath")
	if !e.NftRulesetCaptured {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence.nft_ruleset_captured=false but %s is present", filepath.Base(path)))
	}
	if e.FlowtableDeclared != declared {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence.flowtable_declared=%t does not match %s=%t", e.FlowtableDeclared, filepath.Base(path), declared))
	}
	if e.OffloadRulePresent != offload {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence.offload_rule_present=%t does not match %s=%t", e.OffloadRulePresent, filepath.Base(path), offload))
	}
}

func parseStatusArtifact(text string) statusArtifact {
	var out statusArtifact
	if match := inspectionPolicyRE.FindStringSubmatch(text); len(match) == 2 {
		out.inspectionFound = true
		out.inspection.StatusCaptured = true
		out.inspection.InspectionState = inspectionStateFromStatus(match[1], "")
	}
	if match := inspectionReadinessRE.FindStringSubmatch(text); len(match) == 2 {
		out.inspectionFound = true
		out.inspection.State = match[1]
		out.inspection.StatusCaptured = true
		out.inspection.InspectionState = inspectionStateFromStatus("", match[1])
		if policyMatch := inspectionPolicyRE.FindStringSubmatch(text); len(policyMatch) == 2 {
			out.inspection.InspectionState = inspectionStateFromStatus(policyMatch[1], match[1])
		}
	}
	if match := inspectionEngineRE.FindStringSubmatch(text); len(match) == 4 {
		out.inspectionFound = true
		out.inspection.EngineName = match[1]
		out.inspection.EngineMode = match[2]
		out.inspection.EngineState = match[3]
		out.inspection.StatusCaptured = true
	}
	if match := inspectionFailureBehaviorRE.FindStringSubmatch(text); len(match) == 2 {
		out.inspectionFound = true
		out.inspection.FailureBehavior = match[1]
		out.inspection.StatusCaptured = true
	}
	if match := inspectionBypassReasonRE.FindStringSubmatch(text); len(match) == 2 {
		out.inspectionFound = true
		out.inspection.BypassReason = strings.TrimSpace(match[1])
		out.inspection.StatusCaptured = true
	}
	if match := inspectionDegradedBehaviorRE.FindStringSubmatch(text); len(match) == 2 {
		out.inspectionFound = true
		out.inspection.DegradedBehavior = strings.TrimSpace(match[1])
		out.inspection.StatusCaptured = true
	}
	if match := conntrackStatusRE.FindStringSubmatch(text); len(match) == 5 {
		out.conntrackFound = true
		out.conntrack.State = match[1]
		out.conntrack.StatusCaptured = true
		if match[2] != "" {
			out.conntrack.CurrentEntries, _ = strconv.ParseInt(match[2], 10, 64)
			out.conntrack.MaxEntries, _ = strconv.ParseInt(match[3], 10, 64)
			out.conntrack.UsagePercent, _ = strconv.ParseFloat(match[4], 64)
		}
	}
	if match := hostTuningStatusRE.FindStringSubmatch(text); len(match) == 2 {
		out.hostTuningFound = true
		out.hostTuning.State = match[1]
		out.hostTuning.StatusCaptured = true
	}
	if match := flowtableHostRE.FindStringSubmatch(text); len(match) == 2 {
		out.flowHostFound = true
		out.flowHostState = match[1]
	}
	if match := flowtableRuntimeRE.FindStringSubmatch(text); len(match) == 2 {
		out.flowLiveFound = true
		out.flowLiveState = match[1]
	}
	return out
}

func inspectionStateFromStatus(policyState, readinessState string) string {
	switch strings.ToLower(strings.TrimSpace(readinessState)) {
	case "disabled":
		return "not-inspected"
	case "failed-open":
		return "failed-open"
	case "failed-closed":
		return "failed-closed"
	case "degraded", "unknown":
		return "bypassed-by-engine-health"
	}
	policy := strings.ToLower(strings.TrimSpace(policyState))
	switch {
	case strings.Contains(policy, "disabled"):
		return "not-inspected"
	case strings.Contains(policy, "ips"), strings.Contains(policy, "prevent"):
		return "fully-inspected"
	case strings.Contains(policy, "ids"), strings.Contains(policy, "detect"):
		return "partially-inspected"
	default:
		return ""
	}
}

func validateInspectionStatusArtifact(path string, parsed statusArtifact, expected *InspectionEvidence, result *ValidationResult) {
	if !expected.StatusCaptured {
		return
	}
	if !parsed.inspectionFound {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence is present but %s has no inspection lines", filepath.Base(path)))
		return
	}
	got := parsed.inspection
	if expected.State != "" && expected.State != got.State {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.state %q does not match %s %q", expected.State, filepath.Base(path), got.State))
	}
	if expected.InspectionState != "" && got.InspectionState != "" && expected.InspectionState != got.InspectionState {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.inspection_state %q does not match %s %q", expected.InspectionState, filepath.Base(path), got.InspectionState))
	}
	if expected.EngineName != "" && got.EngineName != "" && expected.EngineName != got.EngineName {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.engine_name %q does not match %s %q", expected.EngineName, filepath.Base(path), got.EngineName))
	}
	if expected.EngineMode != "" && got.EngineMode != "" && expected.EngineMode != got.EngineMode {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.engine_mode %q does not match %s %q", expected.EngineMode, filepath.Base(path), got.EngineMode))
	}
	if expected.EngineState != "" && got.EngineState != "" && expected.EngineState != got.EngineState {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.engine_state %q does not match %s %q", expected.EngineState, filepath.Base(path), got.EngineState))
	}
	if expected.FailureBehavior != "" && got.FailureBehavior != "" && expected.FailureBehavior != got.FailureBehavior {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.failure_behavior %q does not match %s %q", expected.FailureBehavior, filepath.Base(path), got.FailureBehavior))
	}
	if expected.BypassReason != "" && got.BypassReason != "" && expected.BypassReason != got.BypassReason {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.bypass_reason %q does not match %s %q", expected.BypassReason, filepath.Base(path), got.BypassReason))
	}
	if expected.DegradedBehavior != "" && got.DegradedBehavior != "" && expected.DegradedBehavior != got.DegradedBehavior {
		result.Errors = append(result.Errors, fmt.Sprintf("summary inspection_evidence.degraded_behavior %q does not match %s %q", expected.DegradedBehavior, filepath.Base(path), got.DegradedBehavior))
	}
}

func validateHostTuningArtifact(path string, parsed statusArtifact, expected *HostTuningEvidence, result *ValidationResult) {
	if !expected.StatusCaptured {
		return
	}
	if !parsed.hostTuningFound {
		result.Errors = append(result.Errors, fmt.Sprintf("summary host_tuning_evidence is present but %s has no kernel tuning line", filepath.Base(path)))
		return
	}
	got := parsed.hostTuning
	if expected.State != got.State {
		result.Errors = append(result.Errors, fmt.Sprintf("summary host_tuning_evidence.state %q does not match %s %q", expected.State, filepath.Base(path), got.State))
	}
}

func validateConntrackArtifact(path string, parsed statusArtifact, expected *ConntrackEvidence, result *ValidationResult) {
	if !parsed.conntrackFound {
		result.Errors = append(result.Errors, fmt.Sprintf("summary conntrack_evidence is present but %s has no state table line", filepath.Base(path)))
		return
	}
	got := parsed.conntrack
	if expected.State != got.State {
		result.Errors = append(result.Errors, fmt.Sprintf("summary conntrack_evidence.state %q does not match %s %q", expected.State, filepath.Base(path), got.State))
	}
	if expected.CurrentEntries != got.CurrentEntries {
		result.Errors = append(result.Errors, fmt.Sprintf("summary conntrack_evidence.current_entries %d does not match %s %d", expected.CurrentEntries, filepath.Base(path), got.CurrentEntries))
	}
	if expected.MaxEntries != got.MaxEntries {
		result.Errors = append(result.Errors, fmt.Sprintf("summary conntrack_evidence.max_entries %d does not match %s %d", expected.MaxEntries, filepath.Base(path), got.MaxEntries))
	}
	if math.Abs(expected.UsagePercent-got.UsagePercent) > 0.05 {
		result.Errors = append(result.Errors, fmt.Sprintf("summary conntrack_evidence.usage_percent %.3f does not match %s %.3f", expected.UsagePercent, filepath.Base(path), got.UsagePercent))
	}
}

func validateFlowtableStatusArtifact(path string, parsed statusArtifact, expected *FlowtableEvidence, result *ValidationResult) {
	if !expected.StatusCaptured {
		return
	}
	if !parsed.flowHostFound {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence is present but %s has no flowtable host line", filepath.Base(path)))
	} else if expected.HostState != parsed.flowHostState {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence.host_state %q does not match %s %q", expected.HostState, filepath.Base(path), parsed.flowHostState))
	}
	if !parsed.flowLiveFound {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence is present but %s has no flowtable live line", filepath.Base(path)))
	} else if expected.RuntimeState != parsed.flowLiveState {
		result.Errors = append(result.Errors, fmt.Sprintf("summary flowtable_evidence.runtime_state %q does not match %s %q", expected.RuntimeState, filepath.Base(path), parsed.flowLiveState))
	}
}

func readFirstExisting(dir string, names []string, maxBytes int64) (string, []byte, bool, []string, error) {
	var found []string
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			found = append(found, name)
		} else if !os.IsNotExist(err) {
			return path, nil, false, nil, err
		}
	}
	if len(found) == 0 {
		return "", nil, false, nil, nil
	}
	path := filepath.Join(dir, found[0])
	data, err := readFileBounded(path, maxBytes)
	if err != nil {
		return path, nil, false, nil, err
	}
	return path, data, true, found[1:], nil
}

func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit", filepath.Base(path), info.Size(), maxBytes)
	}
	return os.ReadFile(path)
}

// Package perfreport validates Phragma benchmark summary evidence.
package perfreport

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	// SchemaVersion is the current Phragma performance summary contract version.
	SchemaVersion = "phragma.perf.v1"
	// LegacySchemaVersion is the older OpenNGFW performance summary contract version.
	LegacySchemaVersion = "openngfw.perf.v1"
)

var canonicalInspectionStates = map[string]bool{
	"fully-inspected":           true,
	"partially-inspected":       true,
	"bypassed-by-policy":        true,
	"bypassed-by-engine-health": true,
	"failed-open":               true,
	"failed-closed":             true,
	"blocked-before-inspection": true,
	"not-inspected":             true,
}

// Summary is the machine-readable benchmark summary written by perf harnesses.
type Summary struct {
	SchemaVersion      string              `json:"schema_version"`
	GeneratedAt        string              `json:"generated_at"`
	Profile            string              `json:"profile"`
	SecurityServices   string              `json:"security_services"`
	InspectionState    string              `json:"inspection_state"`
	Target             Target              `json:"target"`
	DurationSeconds    int                 `json:"duration_seconds"`
	ParallelStreams    int                 `json:"parallel_streams"`
	TCPBitsPerSecond   float64             `json:"tcp_bits_per_second"`
	TCPGbps            float64             `json:"tcp_gbps"`
	TCPRetransmits     int                 `json:"tcp_retransmits"`
	PingAvgMS          *float64            `json:"ping_avg_ms"`
	ConnectionChurn    map[string]any      `json:"connection_churn"`
	InspectionEvidence *InspectionEvidence `json:"inspection_evidence,omitempty"`
	ConntrackEvidence  *ConntrackEvidence  `json:"conntrack_evidence,omitempty"`
	HostTuningEvidence *HostTuningEvidence `json:"host_tuning_evidence,omitempty"`
	FlowtableEvidence  *FlowtableEvidence  `json:"flowtable_evidence,omitempty"`
	ClaimScope         string              `json:"claim_scope"`
}

// InspectionEvidence records the policy-aware inspection readiness captured
// from ngfwctl status while benchmark traffic was being measured.
type InspectionEvidence struct {
	State            string `json:"state"`
	StatusCaptured   bool   `json:"status_captured"`
	InspectionState  string `json:"inspection_state"`
	EngineName       string `json:"engine_name,omitempty"`
	EngineMode       string `json:"engine_mode,omitempty"`
	EngineState      string `json:"engine_state,omitempty"`
	FailureBehavior  string `json:"failure_behavior,omitempty"`
	BypassReason     string `json:"bypass_reason,omitempty"`
	DegradedBehavior string `json:"degraded_behavior,omitempty"`
}

// ConntrackEvidence records whether a benchmark captured state-table pressure
// from the firewall while measuring throughput or connection churn.
type ConntrackEvidence struct {
	State           string  `json:"state"`
	StatusCaptured  bool    `json:"status_captured"`
	CurrentEntries  int64   `json:"current_entries"`
	MaxEntries      int64   `json:"max_entries"`
	UsagePercent    float64 `json:"usage_percent"`
	WarningPercent  float64 `json:"warning_percent,omitempty"`
	DegradedPercent float64 `json:"degraded_percent,omitempty"`
}

// HostTuningEvidence records whether benchmark traffic ran on a firewall host
// with the OpenNGFW appliance/high-throughput kernel sysctl baseline ready.
type HostTuningEvidence struct {
	State          string `json:"state"`
	StatusCaptured bool   `json:"status_captured"`
	Profile        string `json:"profile,omitempty"`
	ConfigPath     string `json:"config_path,omitempty"`
}

// FlowtableEvidence records whether a flowtable benchmark actually ran with
// the live nftables fast path installed.
type FlowtableEvidence struct {
	HostState          string `json:"host_state"`
	RuntimeState       string `json:"runtime_state"`
	StatusCaptured     bool   `json:"status_captured"`
	NftRulesetCaptured bool   `json:"nft_ruleset_captured"`
	FlowtableDeclared  bool   `json:"flowtable_declared"`
	OffloadRulePresent bool   `json:"offload_rule_present"`
}

// Target describes the traffic endpoint used by the benchmark.
type Target struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ValidationResult captures hard schema errors and softer evidence warnings.
type ValidationResult struct {
	Summary  Summary
	Errors   []string
	Warnings []string
}

// Valid reports whether the summary satisfies the hard evidence contract.
func (r ValidationResult) Valid() bool {
	return len(r.Errors) == 0
}

// ValidateSummary checks the benchmark report contract enforced by Phragma.
func ValidateSummary(data []byte) ValidationResult {
	var s Summary
	var raw map[string]json.RawMessage
	result := ValidationResult{Summary: s}
	if err := json.Unmarshal(data, &raw); err != nil {
		result.Errors = append(result.Errors, "invalid JSON: "+err.Error())
		return result
	}
	if err := json.Unmarshal(data, &s); err != nil {
		result.Errors = append(result.Errors, "invalid summary shape: "+err.Error())
		return result
	}
	result.Summary = s

	required := []string{
		"schema_version", "generated_at", "profile", "security_services",
		"inspection_state", "target", "duration_seconds", "parallel_streams",
		"tcp_bits_per_second", "tcp_gbps", "tcp_retransmits", "claim_scope",
	}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			result.Errors = append(result.Errors, "missing required field "+key)
		}
	}
	if s.SchemaVersion == LegacySchemaVersion {
		result.Warnings = append(result.Warnings, fmt.Sprintf("schema_version %q is legacy; prefer %q", LegacySchemaVersion, SchemaVersion))
	} else if s.SchemaVersion != SchemaVersion {
		result.Errors = append(result.Errors, fmt.Sprintf("schema_version = %q, want %q", s.SchemaVersion, SchemaVersion))
	}
	if s.GeneratedAt == "" {
		result.Errors = append(result.Errors, "generated_at is required")
	} else if _, err := time.Parse(time.RFC3339Nano, s.GeneratedAt); err != nil {
		result.Errors = append(result.Errors, "generated_at must be RFC3339/RFC3339Nano: "+err.Error())
	}
	if s.Profile == "" {
		result.Errors = append(result.Errors, "profile is required")
	}
	if s.SecurityServices == "" {
		result.Errors = append(result.Errors, "security_services is required")
	}
	if s.InspectionState == "" {
		result.Errors = append(result.Errors, "inspection_state is required")
	} else if !canonicalInspectionStates[s.InspectionState] {
		result.Warnings = append(result.Warnings, fmt.Sprintf("inspection_state %q is not canonical; prefer one of: fully-inspected, partially-inspected, bypassed-by-policy, bypassed-by-engine-health, failed-open, failed-closed, blocked-before-inspection, not-inspected", s.InspectionState))
	}
	validateSecurityServiceConsistency(s, &result)
	if s.Target.IP == "" {
		result.Errors = append(result.Errors, "target.ip is required")
	}
	if s.Target.Port < 1 || s.Target.Port > 65535 {
		result.Errors = append(result.Errors, "target.port must be 1..65535")
	}
	if s.DurationSeconds < 1 {
		result.Errors = append(result.Errors, "duration_seconds must be >= 1")
	}
	if s.ParallelStreams < 1 {
		result.Errors = append(result.Errors, "parallel_streams must be >= 1")
	}
	if !finiteNonNegative(s.TCPBitsPerSecond) {
		result.Errors = append(result.Errors, "tcp_bits_per_second must be a finite non-negative number")
	}
	if !finiteNonNegative(s.TCPGbps) {
		result.Errors = append(result.Errors, "tcp_gbps must be a finite non-negative number")
	}
	if s.TCPRetransmits < 0 {
		result.Errors = append(result.Errors, "tcp_retransmits must be >= 0")
	}
	if s.PingAvgMS != nil && !finiteNonNegative(*s.PingAvgMS) {
		result.Errors = append(result.Errors, "ping_avg_ms must be null or a finite non-negative number")
	}
	if s.ClaimScope == "" {
		result.Errors = append(result.Errors, "claim_scope is required")
	}
	if _, ok := raw["connection_churn"]; ok && s.ConnectionChurn == nil {
		result.Errors = append(result.Errors, "connection_churn must be an object when present")
	}
	validateInspectionEvidence(raw, s, &result)
	validateHostTuningEvidence(raw, s, &result)
	validateConntrackEvidence(raw, s, &result)
	validateFlowtableEvidence(raw, s, &result)
	return result
}

func validateInspectionEvidence(raw map[string]json.RawMessage, s Summary, result *ValidationResult) {
	_, present := raw["inspection_evidence"]
	if !present {
		if requiresInspectionEvidence(s) {
			result.Warnings = append(result.Warnings, "inspection_evidence is recommended for inspected, bypassed, or failure-mode benchmark claims; policy-aware inspection posture cannot be evaluated")
		}
		return
	}
	if s.InspectionEvidence == nil {
		result.Errors = append(result.Errors, "inspection_evidence must be an object when present")
		return
	}
	e := s.InspectionEvidence
	if !e.StatusCaptured {
		result.Errors = append(result.Errors, "inspection_evidence.status_captured must be true")
	}
	if e.State == "" {
		result.Errors = append(result.Errors, "inspection_evidence.state is required")
	}
	if e.InspectionState == "" {
		result.Errors = append(result.Errors, "inspection_evidence.inspection_state is required")
	} else if !canonicalInspectionStates[e.InspectionState] {
		result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.inspection_state %q is not canonical", e.InspectionState))
	} else if canonicalInspectionStates[s.InspectionState] && s.InspectionState != e.InspectionState {
		result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.inspection_state %q does not match summary inspection_state %q", e.InspectionState, s.InspectionState))
	}

	switch s.InspectionState {
	case "fully-inspected", "partially-inspected":
		if e.State != "" && e.State != "ready" {
			result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.state %q does not support summary inspection_state %q", e.State, s.InspectionState))
		}
	case "failed-open":
		if e.State != "" && e.State != "failed-open" {
			result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.state %q does not support failed-open summary", e.State))
		}
		if e.FailureBehavior != "" && e.FailureBehavior != "fail-open" {
			result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.failure_behavior %q does not support failed-open summary", e.FailureBehavior))
		}
	case "failed-closed":
		if e.State != "" && e.State != "failed-closed" {
			result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.state %q does not support failed-closed summary", e.State))
		}
		if e.FailureBehavior != "" && e.FailureBehavior != "fail-closed" {
			result.Errors = append(result.Errors, fmt.Sprintf("inspection_evidence.failure_behavior %q does not support failed-closed summary", e.FailureBehavior))
		}
	case "bypassed-by-engine-health":
		if e.State == "ready" {
			result.Errors = append(result.Errors, "inspection_evidence.state ready does not support bypassed-by-engine-health summary")
		}
	case "not-inspected":
		if e.State != "" && e.State != "disabled" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("inspection_evidence.state is %s while summary inspection_state is not-inspected", e.State))
		}
	}
}

func validateSecurityServiceConsistency(s Summary, result *ValidationResult) {
	if s.InspectionState == "" || s.SecurityServices == "" || !canonicalInspectionStates[s.InspectionState] {
		return
	}
	if inspectionStateRequiresServices(s.InspectionState) && !securityServicesMentionInspection(s.SecurityServices) {
		result.Errors = append(result.Errors, fmt.Sprintf("security_services %q cannot support inspection_state %q", s.SecurityServices, s.InspectionState))
	}
	if s.InspectionState == "not-inspected" && securityServicesMentionInspection(s.SecurityServices) {
		result.Errors = append(result.Errors, fmt.Sprintf("security_services %q conflicts with inspection_state \"not-inspected\"", s.SecurityServices))
	}
}

func inspectionStateRequiresServices(state string) bool {
	switch state {
	case "fully-inspected", "partially-inspected", "failed-open", "failed-closed", "bypassed-by-engine-health":
		return true
	default:
		return false
	}
}

func securityServicesMentionInspection(value string) bool {
	text := strings.TrimSpace(strings.ToLower(value))
	switch text {
	case "", "none", "off", "disabled", "n/a", "na", "not-inspected", "forwarding-only", "l3/l4-only":
		return false
	}
	terms := []string{"ids", "ips", "suricata", "snort", "zeek", "threat", "app-id", "app_id", "appid", "dpi", "inspection", "malware", "url", "tls", "waf"}
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func requiresInspectionEvidence(s Summary) bool {
	return canonicalInspectionStates[s.InspectionState] && s.InspectionState != "not-inspected"
}

func validateHostTuningEvidence(raw map[string]json.RawMessage, s Summary, result *ValidationResult) {
	_, present := raw["host_tuning_evidence"]
	if !present {
		if requiresHostTuningEvidence(s) {
			result.Warnings = append(result.Warnings, "host_tuning_evidence is recommended for high-bandwidth or connection-rate benchmarks; kernel forwarding tuning cannot be evaluated")
		}
		return
	}
	if s.HostTuningEvidence == nil {
		result.Errors = append(result.Errors, "host_tuning_evidence must be an object when present")
		return
	}
	e := s.HostTuningEvidence
	if !e.StatusCaptured {
		result.Errors = append(result.Errors, "host_tuning_evidence.status_captured must be true")
	}
	if e.State == "" {
		result.Errors = append(result.Errors, "host_tuning_evidence.state is required")
	}
	if e.State != "" && e.State != "ready" {
		result.Warnings = append(result.Warnings, "host_tuning_evidence state is "+e.State+"; kernel forwarding tuning affected the benchmark")
	}
}

func validateConntrackEvidence(raw map[string]json.RawMessage, s Summary, result *ValidationResult) {
	_, present := raw["conntrack_evidence"]
	if !present {
		if requiresConntrackEvidence(s, raw) {
			result.Warnings = append(result.Warnings, "conntrack_evidence is recommended for throughput or connection-rate benchmarks; state-table capacity cannot be evaluated")
		}
		return
	}
	if s.ConntrackEvidence == nil {
		result.Errors = append(result.Errors, "conntrack_evidence must be an object when present")
		return
	}
	e := s.ConntrackEvidence
	if !e.StatusCaptured {
		result.Errors = append(result.Errors, "conntrack_evidence.status_captured must be true")
	}
	if e.State == "" {
		result.Errors = append(result.Errors, "conntrack_evidence.state is required")
	}
	if e.CurrentEntries < 0 {
		result.Errors = append(result.Errors, "conntrack_evidence.current_entries must be >= 0")
	}
	if e.MaxEntries < 0 {
		result.Errors = append(result.Errors, "conntrack_evidence.max_entries must be >= 0")
	}
	if !finiteNonNegative(e.UsagePercent) {
		result.Errors = append(result.Errors, "conntrack_evidence.usage_percent must be a finite non-negative number")
	}
	if e.MaxEntries > 0 && e.CurrentEntries > e.MaxEntries {
		result.Warnings = append(result.Warnings, "conntrack_evidence.current_entries exceeds max_entries")
	}
	if e.State == "warning" || e.State == "degraded" {
		result.Warnings = append(result.Warnings, "conntrack_evidence state is "+e.State+"; state-table pressure affected the benchmark")
	}
}

func requiresConntrackEvidence(s Summary, raw map[string]json.RawMessage) bool {
	if _, hasChurn := raw["connection_churn"]; hasChurn {
		return true
	}
	text := strings.ToLower(s.Profile + " " + s.ClaimScope)
	for _, term := range []string{"throughput", "connection", "churn", "conntrack", "gbps", "high-bandwidth", "high bandwidth"} {
		if strings.Contains(text, term) {
			return true
		}
	}
	return s.TCPBitsPerSecond > 0 || s.TCPGbps > 0
}

func requiresHostTuningEvidence(s Summary) bool {
	return requiresConntrackEvidence(s, nil)
}

func validateFlowtableEvidence(raw map[string]json.RawMessage, s Summary, result *ValidationResult) {
	_, present := raw["flowtable_evidence"]
	required := strings.Contains(strings.ToLower(s.Profile+" "+s.ClaimScope), "flowtable")
	if required && !present {
		result.Errors = append(result.Errors, "flowtable_evidence is required for flowtable benchmark profiles")
		return
	}
	if !present {
		return
	}
	if s.FlowtableEvidence == nil {
		result.Errors = append(result.Errors, "flowtable_evidence must be an object when present")
		return
	}
	e := s.FlowtableEvidence
	if e.HostState == "" {
		result.Errors = append(result.Errors, "flowtable_evidence.host_state is required")
	}
	if e.RuntimeState == "" {
		result.Errors = append(result.Errors, "flowtable_evidence.runtime_state is required")
	}
	if required && e.RuntimeState != "" && e.RuntimeState != "active" {
		result.Errors = append(result.Errors, "flowtable_evidence.runtime_state must be active for flowtable benchmark claims")
	}
	if required && !e.StatusCaptured {
		result.Errors = append(result.Errors, "flowtable_evidence.status_captured must be true")
	}
	if required && !e.NftRulesetCaptured {
		result.Errors = append(result.Errors, "flowtable_evidence.nft_ruleset_captured must be true")
	}
	if required && !e.FlowtableDeclared {
		result.Errors = append(result.Errors, "flowtable_evidence.flowtable_declared must be true")
	}
	if required && !e.OffloadRulePresent {
		result.Errors = append(result.Errors, "flowtable_evidence.offload_rule_present must be true")
	}
}

func finiteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

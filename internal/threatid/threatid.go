// Package threatid owns OpenNGFW's normalized threat event model.
// Suricata alerts are matching-engine output; this package converts them
// into first-party Threat-ID fields with evidence and confidence.
package threatid

import (
	"strconv"
	"strings"
)

// Result is the normalized OpenNGFW Threat-ID view of one engine alert.
type Result struct {
	ID         string
	Name       string
	Category   string
	Severity   string
	Confidence uint32
	Evidence   []string
}

// PackageMetadata is one signed content-package threat metadata row.
type PackageMetadata struct {
	ID           string
	Name         string
	Category     string
	Severity     string
	Confidence   uint32
	SignatureIDs []int64
	Evidence     []string
}

// ReplayExpected is the operator-supplied expectation for one bounded
// Threat-ID evidence replay sample.
type ReplayExpected struct {
	SignatureID int64
	ThreatID    string
	Verdict     string
}

// ReplaySample is one bounded, metadata-only Threat-ID replay input. It is not
// a packet or malware sample; it carries the same normalized fields the alert
// reader extracts from Suricata EVE evidence.
type ReplaySample struct {
	ID          string
	Source      string
	Signature   string
	SignatureID int64
	Category    string
	Severity    int
	Action      string
	Expected    ReplayExpected
}

// ReplayResult compares one replay sample's expected signature, Threat-ID, and
// verdict against the observed first-party Threat-ID classification.
type ReplayResult struct {
	SampleID         string
	Source           string
	Expected         ReplayExpected
	Observed         Result
	ObservedVerdict  string
	SignatureMatched bool
	ThreatIDMatched  bool
	VerdictMatched   bool
	Passed           bool
	Evidence         []string
	Warnings         []string
}

// Classify normalizes a Suricata alert into OpenNGFW Threat-ID fields.
func Classify(signature string, signatureID int64, category string, severity int, action string) Result {
	return ClassifyWithMetadata(signature, signatureID, category, severity, action, nil)
}

// ClassifyWithMetadata normalizes a Suricata alert and enriches the result
// with matching signed Threat-ID package metadata when supplied.
func ClassifyWithMetadata(signature string, signatureID int64, category string, severity int, action string, metadata []PackageMetadata) Result {
	name := strings.TrimSpace(signature)
	if name == "" {
		name = "Unknown Threat"
	}
	id := "unknown-threat"
	if signatureID > 0 {
		id = "suricata-sid-" + strconv.FormatInt(signatureID, 10)
	}

	taxonomy := classifyCategory(signature, category)
	confidence := confidence(signatureID, category, action)
	evidence := []string{
		"engine signal suricata.signature_id=" + strconv.FormatInt(signatureID, 10),
		"engine signal suricata.signature=" + valueOrUnknown(signature),
		"engine signal suricata.category=" + valueOrUnknown(category),
		"OpenNGFW taxonomy category=" + taxonomy,
		"OpenNGFW severity=" + severityLabel(severity),
	}
	if action != "" {
		evidence = append(evidence, "engine action="+strings.ToLower(strings.TrimSpace(action)))
	}

	result := Result{
		ID:         id,
		Name:       name,
		Category:   taxonomy,
		Severity:   severityLabel(severity),
		Confidence: confidence,
		Evidence:   evidence,
	}
	for _, candidate := range metadata {
		if metadataMatches(candidate, id, signatureID) {
			return applyMetadata(result, candidate)
		}
	}
	return result
}

// Replay runs bounded evidence samples through the same classifier used for
// API alert normalization, then compares expected and observed fields.
func Replay(samples []ReplaySample, metadata []PackageMetadata) []ReplayResult {
	out := make([]ReplayResult, 0, len(samples))
	for _, sample := range samples {
		observed := ClassifyWithMetadata(sample.Signature, sample.SignatureID, sample.Category, sample.Severity, sample.Action, metadata)
		expected := normalizeExpected(sample.Expected)
		result := ReplayResult{
			SampleID:        strings.TrimSpace(sample.ID),
			Source:          valueOrUnknown(sample.Source),
			Expected:        expected,
			Observed:        observed,
			ObservedVerdict: observedVerdict(sample.Action),
			Evidence: append([]string{
				"replay source=" + valueOrUnknown(sample.Source),
				"bounded metadata replay; no packet payload or malware artifact executed",
			}, observed.Evidence...),
		}
		result.SignatureMatched = expected.SignatureID == 0 || expected.SignatureID == sample.SignatureID
		result.ThreatIDMatched = expected.ThreatID == "" || strings.EqualFold(expected.ThreatID, observed.ID)
		result.VerdictMatched = expected.Verdict == "" || expected.Verdict == result.ObservedVerdict
		result.Passed = result.SignatureMatched && result.ThreatIDMatched && result.VerdictMatched
		if expected.SignatureID != 0 && !result.SignatureMatched {
			result.Warnings = append(result.Warnings, "expected signature_id did not match observed engine signature_id")
		}
		if expected.ThreatID != "" && !result.ThreatIDMatched {
			result.Warnings = append(result.Warnings, "expected Threat-ID did not match observed classifier output")
		}
		if expected.Verdict != "" && !result.VerdictMatched {
			result.Warnings = append(result.Warnings, "expected verdict did not match observed engine action mapping")
		}
		out = append(out, result)
	}
	return out
}

func classifyCategory(signature, category string) string {
	hay := strings.ToLower(category + " " + signature)
	switch {
	case containsAny(hay, "trojan", "malware", "botnet", "command and control", "c2"):
		return "malware"
	case containsAny(hay, "scan", "recon", "probe"):
		return "reconnaissance"
	case containsAny(hay, "brute", "credential", "login", "password"):
		return "credential-attack"
	case containsAny(hay, "exploit", "attack", "attempted", "shellcode", "injection"):
		return "exploit-attempt"
	case containsAny(hay, "dos", "denial of service"):
		return "denial-of-service"
	case containsAny(hay, "policy", "p2p", "torrent"):
		return "policy-violation"
	case containsAny(hay, "web", "http"):
		return "web-threat"
	default:
		return "suspicious"
	}
}

func confidence(signatureID int64, category, action string) uint32 {
	score := uint32(45)
	if signatureID > 0 {
		score = 70
	}
	if strings.TrimSpace(category) != "" {
		score += 10
	}
	if strings.EqualFold(strings.TrimSpace(action), "blocked") {
		score += 5
	}
	if score > 95 {
		return 95
	}
	return score
}

func severityLabel(severity int) string {
	switch severity {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "low"
	default:
		if severity <= 0 {
			return "info"
		}
		return "low"
	}
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func valueOrUnknown(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}

func metadataMatches(metadata PackageMetadata, id string, signatureID int64) bool {
	for _, sid := range metadata.SignatureIDs {
		if sid > 0 && sid == signatureID {
			return true
		}
	}
	return strings.TrimSpace(metadata.ID) != "" && strings.EqualFold(strings.TrimSpace(metadata.ID), id)
}

func applyMetadata(result Result, metadata PackageMetadata) Result {
	if id := strings.TrimSpace(metadata.ID); id != "" {
		result.ID = id
	}
	if name := strings.TrimSpace(metadata.Name); name != "" {
		result.Name = name
	}
	if category := strings.TrimSpace(metadata.Category); category != "" {
		result.Category = category
	}
	if severity := strings.TrimSpace(metadata.Severity); severity != "" {
		result.Severity = severity
	}
	if metadata.Confidence > 0 {
		result.Confidence = metadata.Confidence
	}
	result.Evidence = append(result.Evidence, cleanEvidence(metadata.Evidence)...)
	return result
}

func cleanEvidence(evidence []string) []string {
	out := make([]string, 0, len(evidence))
	for _, entry := range evidence {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

func normalizeExpected(expected ReplayExpected) ReplayExpected {
	expected.ThreatID = strings.TrimSpace(expected.ThreatID)
	expected.Verdict = normalizeVerdict(expected.Verdict)
	return expected
}

func observedVerdict(action string) string {
	return normalizeVerdict(action)
}

func normalizeVerdict(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "block", "blocked", "drop", "dropped", "deny", "denied", "prevented":
		return "blocked"
	case "alert", "allowed", "allow", "detect", "detected", "observed":
		return "detected"
	case "":
		return "unknown"
	default:
		return v
	}
}

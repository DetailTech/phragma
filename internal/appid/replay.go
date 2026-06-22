package appid

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// ReplayVerdict is the lab comparison outcome for a bounded App-ID sample.
type ReplayVerdict string

const (
	ReplayVerdictMatch            ReplayVerdict = "match"
	ReplayVerdictMismatch         ReplayVerdict = "mismatch"
	ReplayVerdictNeedsExpectedApp ReplayVerdict = "needs_expected_app"
	ReplayVerdictNeedsEvidence    ReplayVerdict = "needs_evidence"
)

// ReplayInput is a normalized observation or corpus row submitted for
// read-only lab replay comparison.
type ReplayInput struct {
	Source                     string
	QueueID                    string
	SampleID                   string
	CorpusArtifact             string
	PCAPSHA256                 string
	ObservedApp                string
	ExpectedApp                string
	AppConfidence              uint32
	ObservationKind            ObservationKind
	EngineSignal               string
	EngineSignalSource         string
	Protocol                   string
	DestPort                   uint32
	SampleFlowID               string
	AppEvidence                []string
	AppIDPackageVersion        string
	AppIDPackageManifestSHA256 string
}

// ReplayReport is the operator-facing comparison result. It is intentionally
// evidence-scoped and does not represent production App-ID enforcement breadth.
type ReplayReport struct {
	ReportID              string
	Source                string
	QueueID               string
	SampleID              string
	CorpusArtifact        string
	PCAPSHA256            string
	ObservedApp           string
	ExpectedApp           string
	Confidence            uint32
	Verdict               ReplayVerdict
	MismatchReasons       []string
	BoundedEvidence       []string
	RecommendedNextAction string
	SampleFlowID          string
	EngineSignal          string
	EngineSignalSource    string
	Protocol              string
	DestPort              uint32
	ComparisonScope       string
}

// ReplayInputFromObservation converts a grouped observation into a replay input.
func ReplayInputFromObservation(obs Observation, expectedOverride string) ReplayInput {
	expected := strings.TrimSpace(expectedOverride)
	if expected == "" {
		expected = firstNonEmpty(obs.SuggestedApplication.ID, obs.AppID, obs.EngineSignal)
	}
	observed := firstNonEmpty(obs.AppID, obs.AppName, obs.EngineSignal)
	return ReplayInput{
		Source:             "observation",
		QueueID:            strings.TrimSpace(obs.QueueID),
		ObservedApp:        observed,
		ExpectedApp:        expected,
		AppConfidence:      obs.AppConfidence,
		ObservationKind:    obs.Kind,
		EngineSignal:       strings.TrimSpace(obs.EngineSignal),
		EngineSignalSource: strings.TrimSpace(obs.EngineSignalSource),
		Protocol:           strings.ToUpper(strings.TrimSpace(obs.Protocol)),
		DestPort:           obs.DestPort,
		SampleFlowID:       strings.TrimSpace(obs.SampleFlowID),
		AppEvidence:        append([]string(nil), obs.AppEvidence...),
	}
}

// ReplayInputFromRegressionSample converts a reviewed corpus row into a replay
// input without mutating corpus storage.
func ReplayInputFromRegressionSample(sample RegressionSample, artifact, expectedOverride string) ReplayInput {
	expected := strings.TrimSpace(expectedOverride)
	if expected == "" {
		expected = strings.TrimSpace(sample.ExpectedApp)
	}
	return ReplayInput{
		Source:                     "corpus_sample",
		QueueID:                    strings.TrimSpace(sample.QueueID),
		SampleID:                   strings.TrimSpace(sample.SampleID),
		CorpusArtifact:             strings.TrimSpace(artifact),
		PCAPSHA256:                 strings.ToLower(strings.TrimSpace(sample.PCAPSHA256)),
		ObservedApp:                strings.TrimSpace(sample.ObservedApp),
		ExpectedApp:                expected,
		AppConfidence:              sample.AppConfidence,
		ObservationKind:            sample.ObservationKind,
		EngineSignal:               strings.TrimSpace(sample.EngineSignal),
		EngineSignalSource:         strings.TrimSpace(sample.EngineSignalSource),
		Protocol:                   strings.ToUpper(strings.TrimSpace(sample.Protocol)),
		DestPort:                   sample.DestPort,
		SampleFlowID:               strings.TrimSpace(sample.SampleFlowID),
		AppEvidence:                append([]string(nil), sample.AppEvidence...),
		AppIDPackageVersion:        strings.TrimSpace(sample.AppIDPackageVersion),
		AppIDPackageManifestSHA256: strings.TrimSpace(sample.AppIDPackageManifestSHA256),
	}
}

// CompareReplay produces a bounded lab replay comparison report.
func CompareReplay(input ReplayInput, threshold uint32) ReplayReport {
	if threshold == 0 {
		threshold = DefaultObservationConfidenceThreshold
	}
	input.Source = firstNonEmpty(input.Source, "submitted")
	input.ObservedApp = strings.TrimSpace(input.ObservedApp)
	input.ExpectedApp = strings.TrimSpace(input.ExpectedApp)
	report := ReplayReport{
		Source:             input.Source,
		QueueID:            strings.TrimSpace(input.QueueID),
		SampleID:           strings.TrimSpace(input.SampleID),
		CorpusArtifact:     strings.TrimSpace(input.CorpusArtifact),
		PCAPSHA256:         strings.ToLower(strings.TrimSpace(input.PCAPSHA256)),
		ObservedApp:        input.ObservedApp,
		ExpectedApp:        input.ExpectedApp,
		Confidence:         input.AppConfidence,
		SampleFlowID:       strings.TrimSpace(input.SampleFlowID),
		EngineSignal:       strings.TrimSpace(input.EngineSignal),
		EngineSignalSource: strings.TrimSpace(input.EngineSignalSource),
		Protocol:           strings.ToUpper(strings.TrimSpace(input.Protocol)),
		DestPort:           input.DestPort,
		ComparisonScope:    "lab replay comparison only; no candidate policy, corpus append, or dataplane enforcement change",
	}
	report.MismatchReasons = replayMismatchReasons(input, threshold)
	report.BoundedEvidence = replayBoundedEvidence(input, threshold)
	report.Verdict = replayVerdict(input, report.MismatchReasons)
	report.RecommendedNextAction = replayNextAction(report)
	report.ReportID = replayReportID(report)
	return report
}

func replayMismatchReasons(input ReplayInput, threshold uint32) []string {
	var reasons []string
	if strings.TrimSpace(input.ExpectedApp) == "" {
		reasons = append(reasons, "expected App-ID is missing; provide a reviewed expected_app before treating this as a regression result")
	}
	if strings.TrimSpace(input.ObservedApp) == "" {
		reasons = append(reasons, "observed App-ID is missing; replay evidence did not produce an application label")
	} else if strings.EqualFold(input.ObservedApp, "unknown") {
		reasons = append(reasons, "observed App-ID is unknown")
	}
	if input.ExpectedApp != "" && input.ObservedApp != "" && !sameApp(input.ExpectedApp, input.ObservedApp) {
		reasons = append(reasons, "observed App-ID does not match expected App-ID")
	}
	if input.AppConfidence > 0 && input.AppConfidence < threshold {
		reasons = append(reasons, "confidence is below review threshold")
	}
	if input.ObservationKind == ObservationKindConflictingEvidence {
		reasons = append(reasons, "source observation has conflicting App-ID evidence")
	}
	if input.Source == "corpus_sample" && strings.TrimSpace(input.PCAPSHA256) == "" {
		reasons = append(reasons, "corpus sample is missing packet-capture SHA-256 custody")
	}
	return reasons
}

func replayVerdict(input ReplayInput, reasons []string) ReplayVerdict {
	if strings.TrimSpace(input.ExpectedApp) == "" {
		return ReplayVerdictNeedsExpectedApp
	}
	if strings.TrimSpace(input.ObservedApp) == "" {
		return ReplayVerdictNeedsEvidence
	}
	if len(reasons) == 0 {
		return ReplayVerdictMatch
	}
	return ReplayVerdictMismatch
}

func replayBoundedEvidence(input ReplayInput, threshold uint32) []string {
	evidence := []string{
		"source=" + firstNonEmpty(input.Source, "submitted"),
	}
	if input.QueueID != "" {
		evidence = append(evidence, "queue_id="+input.QueueID)
	}
	if input.SampleID != "" {
		evidence = append(evidence, "sample_id="+input.SampleID)
	}
	if input.SampleFlowID != "" {
		evidence = append(evidence, "sample_flow_id="+input.SampleFlowID)
	}
	if input.EngineSignal != "" {
		evidence = append(evidence, "engine_signal="+firstNonEmpty(input.EngineSignalSource, "engine")+"="+input.EngineSignal)
	}
	if input.Protocol != "" && input.DestPort != 0 {
		evidence = append(evidence, "tuple_hint="+strings.ToLower(input.Protocol)+"/"+uintToString(input.DestPort))
	}
	if input.AppConfidence != 0 {
		evidence = append(evidence, "confidence="+uintToString(input.AppConfidence)+" threshold="+uintToString(threshold))
	}
	for _, item := range input.AppEvidence {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if len(item) > 180 {
			item = item[:180]
		}
		evidence = append(evidence, item)
		if len(evidence) >= 10 {
			break
		}
	}
	return evidence
}

func replayNextAction(report ReplayReport) string {
	switch report.Verdict {
	case ReplayVerdictMatch:
		return "Keep the sample in regression evidence and compare it against the next signed App-ID package before promotion."
	case ReplayVerdictNeedsExpectedApp:
		return "Add a reviewed expected App-ID or select a corpus row with expected_app before using this as pass/fail evidence."
	case ReplayVerdictNeedsEvidence:
		return "Replay or recapture the sample with App-ID signal collection enabled, then compare the resulting observation."
	default:
		if report.SampleID != "" || report.PCAPSHA256 != "" {
			return "Inspect taxonomy or confidence-model drift, keep the PCAP retained, and do not promote the package until the mismatch is resolved."
		}
		return "Cluster related observations, capture a bounded PCAP, and stage a reviewed regression sample before package promotion."
	}
}

func replayReportID(report ReplayReport) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		report.Source,
		report.QueueID,
		report.SampleID,
		report.PCAPSHA256,
		report.ExpectedApp,
		report.ObservedApp,
		report.EngineSignal,
	}, "|")))
	return hex.EncodeToString(sum[:])[:24]
}

func sameApp(a, b string) bool {
	return normalize(a) == normalize(b)
}

func uintToString(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

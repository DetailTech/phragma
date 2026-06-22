package appid

import (
	"strings"
	"testing"
)

func TestCompareReplayReportsMatchForCorpusSample(t *testing.T) {
	report := CompareReplay(ReplayInputFromRegressionSample(RegressionSample{
		SampleID:      "sample-1",
		QueueID:       "qid-1",
		ExpectedApp:   "corp-admin",
		ObservedApp:   "corp-admin",
		PCAPSHA256:    strings.Repeat("a", 64),
		AppConfidence: 92,
		AppEvidence:   []string{"taxonomy match corp-admin"},
	}, RegressionCorpusArtifact, ""), 70)
	if report.Verdict != ReplayVerdictMatch || len(report.MismatchReasons) != 0 {
		t.Fatalf("report = %#v, want clean match", report)
	}
	if report.ReportID == "" || report.Source != "corpus_sample" || report.PCAPSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("report identity = %#v", report)
	}
	if !strings.Contains(report.ComparisonScope, "lab replay comparison") {
		t.Fatalf("scope = %q", report.ComparisonScope)
	}
}

func TestCompareReplayReportsMismatchReasonsForObservation(t *testing.T) {
	report := CompareReplay(ReplayInputFromObservation(Observation{
		QueueID:       "qid-1",
		Kind:          ObservationKindConflictingEvidence,
		AppID:         "unknown",
		AppConfidence: 35,
		EngineSignal:  "weird-proto",
		Protocol:      "tcp",
		DestPort:      8443,
		AppEvidence:   []string{"no OpenNGFW taxonomy match for engine signal"},
	}, "corp-admin"), 70)
	if report.Verdict != ReplayVerdictMismatch {
		t.Fatalf("verdict = %v, want mismatch: %#v", report.Verdict, report)
	}
	for _, want := range []string{"does not match", "below review threshold", "conflicting"} {
		if !containsReason(report.MismatchReasons, want) {
			t.Fatalf("missing reason %q in %#v", want, report.MismatchReasons)
		}
	}
	if !strings.Contains(report.RecommendedNextAction, "Cluster related observations") {
		t.Fatalf("next action = %q", report.RecommendedNextAction)
	}
}

func TestCompareReplayNeedsExpectedApp(t *testing.T) {
	report := CompareReplay(ReplayInput{Source: "submitted", ObservedApp: "ssh", AppConfidence: 90}, 70)
	if report.Verdict != ReplayVerdictNeedsExpectedApp {
		t.Fatalf("verdict = %v, want needs expected app", report.Verdict)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, want) {
			return true
		}
	}
	return false
}

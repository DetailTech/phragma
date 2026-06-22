package appid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegressionSampleFromObservationAndAppend(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	sample, err := RegressionSampleFromObservation(Observation{
		QueueID:              "qid-1",
		Kind:                 ObservationKindUnknown,
		AppID:                "unknown",
		AppName:              "Unknown",
		EngineSignal:         "weird-proto",
		EngineSignalSource:   "suricata.app_proto",
		Protocol:             "tcp",
		DestPort:             8443,
		SampleFlowID:         "flow-1",
		SampleSrcIP:          "10.0.1.20",
		SampleSrcPort:        51515,
		SampleDestIP:         "10.0.2.20",
		AppConfidence:        0,
		AppEvidence:          []string{"unmapped signal"},
		SuggestedApplication: Definition{ID: "corp-admin"},
	}, RegressionSampleOptions{
		Reason:                     "reviewed capture",
		PCAPSHA256:                 strings.Repeat("A", 64),
		AppIDPackageVersion:        "2.4.6",
		AppIDPackageManifestSHA256: strings.Repeat("f", 64),
		CreatedAt:                  createdAt,
	})
	if err != nil {
		t.Fatalf("RegressionSampleFromObservation: %v", err)
	}
	if sample.ExpectedApp != "corp-admin" || sample.ObservedApp != "weird-proto" || sample.PCAPSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("sample = %#v", sample)
	}
	root := t.TempDir()
	result, err := AppendRegressionSample(root, sample)
	if err != nil {
		t.Fatalf("AppendRegressionSample: %v", err)
	}
	if result.Artifact != RegressionCorpusArtifact || result.SampleCount != 1 {
		t.Fatalf("result = %#v", result)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RegressionCorpusArtifact)))
	if err != nil {
		t.Fatal(err)
	}
	var row RegressionSample
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("draft row did not parse: %v\n%s", err, raw)
	}
	if row.SampleID == "" || !row.CreatedAt.Equal(createdAt) || row.AppIDPackageVersion != "2.4.6" {
		t.Fatalf("row = %#v", row)
	}
}

func TestRegressionSampleRejectsMissingReviewInputs(t *testing.T) {
	obs := Observation{QueueID: "qid-1", EngineSignal: "weird-proto"}
	_, err := RegressionSampleFromObservation(obs, RegressionSampleOptions{PCAPSHA256: strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("reason error = %v", err)
	}
	_, err = RegressionSampleFromObservation(obs, RegressionSampleOptions{Reason: "reviewed", PCAPSHA256: "bad"})
	if err == nil || !strings.Contains(err.Error(), "pcap_sha256") {
		t.Fatalf("pcap error = %v", err)
	}
}

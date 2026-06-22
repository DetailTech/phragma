package appid

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	RegressionCorpusArtifact = "app-id/.reviewed-corpus/app-regression-corpus.jsonl"
	regressionSampleSchema   = "openngfw.appid.regression_sample.v1"
)

var sha256HexPattern = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

// RegressionSampleOptions carries operator review inputs and package context.
type RegressionSampleOptions struct {
	Reason                     string
	PCAPSHA256                 string
	ExpectedApp                string
	ObservedApp                string
	AppIDPackageVersion        string
	AppIDPackageManifestSHA256 string
	CreatedAt                  time.Time
}

// RegressionSample is a draft App-ID regression-corpus row. It is intentionally
// JSON-native because the package builder consumes reviewed corpus artifacts.
type RegressionSample struct {
	SchemaVersion              string          `json:"schema_version"`
	SampleID                   string          `json:"sample_id"`
	QueueID                    string          `json:"queue_id"`
	ObservationKind            ObservationKind `json:"observation_kind"`
	ExpectedApp                string          `json:"expected_app"`
	ObservedApp                string          `json:"observed_app"`
	EngineSignal               string          `json:"engine_signal,omitempty"`
	EngineSignalSource         string          `json:"engine_signal_source,omitempty"`
	Protocol                   string          `json:"protocol,omitempty"`
	DestPort                   uint32          `json:"dest_port,omitempty"`
	SampleFlowID               string          `json:"sample_flow_id,omitempty"`
	SampleSrcIP                string          `json:"sample_src_ip,omitempty"`
	SampleSrcPort              uint32          `json:"sample_src_port,omitempty"`
	SampleDestIP               string          `json:"sample_dest_ip,omitempty"`
	AppConfidence              uint32          `json:"app_confidence,omitempty"`
	AppEvidence                []string        `json:"app_evidence,omitempty"`
	PCAPSHA256                 string          `json:"pcap_sha256"`
	Reason                     string          `json:"reason"`
	CreatedAt                  time.Time       `json:"created_at"`
	AppIDPackageVersion        string          `json:"app_id_package_version,omitempty"`
	AppIDPackageManifestSHA256 string          `json:"app_id_package_manifest_sha256,omitempty"`
}

// AppendResult describes the draft corpus append.
type AppendResult struct {
	Artifact    string
	SampleCount uint32
}

// RegressionSampleFromObservation converts a reviewed queue item into a draft
// corpus row.
func RegressionSampleFromObservation(obs Observation, opts RegressionSampleOptions) (RegressionSample, error) {
	reason := strings.TrimSpace(opts.Reason)
	if reason == "" {
		return RegressionSample{}, fmt.Errorf("reason is required")
	}
	pcapSHA := strings.ToLower(strings.TrimSpace(opts.PCAPSHA256))
	if !sha256HexPattern.MatchString(pcapSHA) {
		return RegressionSample{}, fmt.Errorf("pcap_sha256 must be a 64-character hex SHA-256")
	}
	expected := strings.TrimSpace(opts.ExpectedApp)
	if expected == "" {
		expected = firstNonEmpty(obs.SuggestedApplication.ID, obs.AppID, obs.EngineSignal)
	}
	observed := strings.TrimSpace(opts.ObservedApp)
	if observed == "" {
		observed = firstNonEmpty(obs.AppID, obs.AppName, obs.EngineSignal)
	}
	if expected == "" {
		return RegressionSample{}, fmt.Errorf("expected_app is required when the observation has no suggestion")
	}
	if observed == "" {
		return RegressionSample{}, fmt.Errorf("observed_app is required when the observation has no App-ID evidence")
	}
	createdAt := opts.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	sample := RegressionSample{
		SchemaVersion:              regressionSampleSchema,
		QueueID:                    strings.TrimSpace(obs.QueueID),
		ObservationKind:            obs.Kind,
		ExpectedApp:                expected,
		ObservedApp:                observed,
		EngineSignal:               strings.TrimSpace(obs.EngineSignal),
		EngineSignalSource:         strings.TrimSpace(obs.EngineSignalSource),
		Protocol:                   strings.ToUpper(strings.TrimSpace(obs.Protocol)),
		DestPort:                   obs.DestPort,
		SampleFlowID:               strings.TrimSpace(obs.SampleFlowID),
		SampleSrcIP:                strings.TrimSpace(obs.SampleSrcIP),
		SampleSrcPort:              obs.SampleSrcPort,
		SampleDestIP:               strings.TrimSpace(obs.SampleDestIP),
		AppConfidence:              obs.AppConfidence,
		AppEvidence:                append([]string(nil), obs.AppEvidence...),
		PCAPSHA256:                 pcapSHA,
		Reason:                     reason,
		CreatedAt:                  createdAt,
		AppIDPackageVersion:        strings.TrimSpace(opts.AppIDPackageVersion),
		AppIDPackageManifestSHA256: strings.TrimSpace(opts.AppIDPackageManifestSHA256),
	}
	sample.SampleID = regressionSampleID(sample)
	return sample, nil
}

// AppendRegressionSample appends a reviewed draft sample under contentRoot.
func AppendRegressionSample(contentRoot string, sample RegressionSample) (AppendResult, error) {
	root := strings.TrimSpace(contentRoot)
	if root == "" {
		return AppendResult{}, fmt.Errorf("content directory is required")
	}
	path := filepath.Join(root, filepath.FromSlash(RegressionCorpusArtifact))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return AppendResult{}, fmt.Errorf("create draft corpus directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return AppendResult{}, fmt.Errorf("open draft corpus: %w", err)
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(sample); err != nil {
		_ = f.Close()
		return AppendResult{}, fmt.Errorf("write draft sample: %w", err)
	}
	if err := f.Close(); err != nil {
		return AppendResult{}, fmt.Errorf("close draft corpus: %w", err)
	}
	count, err := countJSONLLines(path)
	if err != nil {
		return AppendResult{}, err
	}
	return AppendResult{Artifact: RegressionCorpusArtifact, SampleCount: count}, nil
}

func regressionSampleID(sample RegressionSample) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		sample.QueueID,
		sample.ExpectedApp,
		sample.ObservedApp,
		sample.PCAPSHA256,
		sample.CreatedAt.Format(time.RFC3339Nano),
	}, "|")))
	return hex.EncodeToString(sum[:])[:24]
}

func countJSONLLines(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("read draft corpus: %w", err)
	}
	defer func() { _ = f.Close() }()
	var count uint32
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan draft corpus: %w", err)
	}
	return count, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" && !strings.EqualFold(v, "unknown") {
			return v
		}
	}
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			return v
		}
	}
	return ""
}

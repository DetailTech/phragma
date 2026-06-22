// Package contentpkg reads and verifies local Phragma content package
// manifests. It is intentionally offline-first: package status is derived
// from files already installed on the appliance.
package contentpkg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/appid"
	"github.com/detailtech/oss-ngfw/internal/threatid"
)

// SchemaVersion identifies manifests supported by the content package loader.
const SchemaVersion = "phragma.content.package.v1"
const trustedKeyringDir = ".trust/ed25519"
const maxManifestBytes = 1 << 20

// MaxEvidenceArtifactBytes caps evidence artifact reads from package contents.
const MaxEvidenceArtifactBytes = 256 << 10

var semverRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
var sha256HexRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
var evidenceTypeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)
var renamePackageDir = os.Rename

var (
	// ErrInvalidKind indicates an unknown content package kind.
	ErrInvalidKind = errors.New("invalid content package kind")
	// ErrInvalidPackage indicates package data failed validation or promotion.
	ErrInvalidPackage = errors.New("invalid content package")
	// ErrNoRollback indicates no verified rollback package is available.
	ErrNoRollback = errors.New("no content package rollback is available")
	// ErrInvalidEvidenceRequest indicates an invalid evidence lookup request.
	ErrInvalidEvidenceRequest = errors.New("invalid content evidence request")
	// ErrEvidenceNotFound indicates the requested evidence type is absent.
	ErrEvidenceNotFound = errors.New("content evidence not found")
)

// ExpectedPackage describes a content package kind required by the appliance.
type ExpectedPackage struct {
	Kind        string
	DisplayName string
	Detail      string
}

// Status reports the installed or candidate state of one content package.
type Status struct {
	Kind              string
	Name              string
	State             string
	Version           string
	Source            string
	InstalledAt       time.Time
	ManifestPath      string
	ManifestSHA256    string
	SignatureStatus   string
	RegressionStatus  string
	RolloutState      string
	RollbackAvailable bool
	Provenance        []Provenance
	ContentReadiness  ContentReadinessStatus
	Blockers          []string
	Detail            string
}

// ActionResult describes the outcome of an install or rollback operation.
type ActionResult struct {
	Status               Status
	RollbackCreated      bool
	RollbackPath         string
	RestoredRollbackPath string
	Detail               string
}

// EvidenceArtifact contains a verified package evidence reference and payload.
type EvidenceArtifact struct {
	Kind           string
	PackageState   string
	PackageVersion string
	ManifestSHA256 string
	Evidence       EvidenceRef
	ContentJSON    []byte
}

// AppIDTaxonomy is the verified App-ID taxonomy view exposed to classifiers.
type AppIDTaxonomy struct {
	Kind           string
	PackageVersion string
	ManifestSHA256 string
	Evidence       EvidenceRef
	Definitions    []appid.Definition
}

// ThreatIDTaxonomy is the verified Threat-ID taxonomy view exposed to alert
// normalization.
type ThreatIDTaxonomy struct {
	Kind           string
	PackageVersion string
	ManifestSHA256 string
	Evidence       EvidenceRef
	Metadata       []threatid.PackageMetadata
}

// CorpusSample is one normalized regression-corpus row extracted from package
// evidence JSON.
type CorpusSample struct {
	ID          string
	PCAPSHA256  string
	Expected    string
	Observed    string
	ExpectedApp string
	ObservedApp string
	SignatureID string
	Verdict     string
	Detail      string
}

// RegressionCorpus is a typed view over package-local regression evidence.
type RegressionCorpus struct {
	Kind           string
	PackageState   string
	PackageVersion string
	ManifestSHA256 string
	Evidence       EvidenceRef
	EvidenceType   string
	Status         string
	Samples        []CorpusSample
	Verdicts       []string
	SampleCount    uint32
	FailedSamples  uint32
	Summary        string
}

// CorpusComparison compares current installed corpus evidence with a candidate
// package source under the configured import root.
type CorpusComparison struct {
	Kind         string
	EvidenceType string
	Current      RegressionCorpus
	Preview      RegressionCorpus
	Added        uint32
	Removed      uint32
	Changed      uint32
	FailedDelta  int32
	SampleDiffs  []CorpusSampleDiff
	Summary      string
}

// CorpusSampleDiff is one sample-level comparison row.
type CorpusSampleDiff struct {
	ID      string
	Change  string
	Current CorpusSample
	Preview CorpusSample
}

// ThreatMetadataCatalog is the verified metadata extracted from the installed
// Threat-ID content package.
type ThreatMetadataCatalog struct {
	Version        string
	ManifestSHA256 string
	Metadata       []threatid.PackageMetadata
}

type trustedKeyring map[string]ed25519.PublicKey

// Manifest is the signed JSON manifest stored with each content package.
type Manifest struct {
	SchemaVersion    string            `json:"schema_version"`
	Kind             string            `json:"kind"`
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Source           string            `json:"source"`
	CreatedAt        string            `json:"created_at,omitempty"`
	InstalledAt      string            `json:"installed_at,omitempty"`
	Files            []File            `json:"files,omitempty"`
	Signature        *Signature        `json:"signature,omitempty"`
	Regression       *Regression       `json:"regression,omitempty"`
	Rollout          *Rollout          `json:"rollout,omitempty"`
	Rollback         *Rollback         `json:"rollback,omitempty"`
	Provenance       []Provenance      `json:"provenance,omitempty"`
	ContentReadiness *ContentReadiness `json:"content_readiness,omitempty"`
}

// File declares one package file and its expected SHA-256 digest.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Signature carries the Ed25519 signature metadata for a manifest.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// Regression records package regression corpus results from build evidence.
type Regression struct {
	Status string `json:"status"`
	Corpus string `json:"corpus,omitempty"`
	Passed uint32 `json:"passed,omitempty"`
	Failed uint32 `json:"failed,omitempty"`
	RunAt  string `json:"run_at,omitempty"`
}

// Rollout records the rollout state and scope declared by a package.
type Rollout struct {
	State string `json:"state"`
	Scope string `json:"scope,omitempty"`
}

// Rollback records whether a package can roll back to a prior version.
type Rollback struct {
	Available       bool   `json:"available"`
	PreviousVersion string `json:"previous_version,omitempty"`
}

// Provenance records licensing and source metadata for package inputs.
type Provenance struct {
	Name                 string `json:"name"`
	URL                  string `json:"url,omitempty"`
	License              string `json:"license,omitempty"`
	AllowsCommercialUse  *bool  `json:"allows_commercial_use,omitempty"`
	AllowsRedistribution *bool  `json:"allows_redistribution,omitempty"`
}

// ContentReadiness declares production readiness evidence in a manifest.
type ContentReadiness struct {
	Scope                      string        `json:"scope,omitempty"`
	ProductionContent          bool          `json:"production_content"`
	Evidence                   []EvidenceRef `json:"evidence,omitempty"`
	RequiredProductionEvidence []string      `json:"required_production_evidence,omitempty"`
}

// EvidenceRef identifies a content readiness evidence artifact.
type EvidenceRef struct {
	Type        string `json:"type"`
	Artifact    string `json:"artifact"`
	SHA256      string `json:"sha256"`
	GeneratedAt string `json:"generated_at,omitempty"`
}

// ContentReadinessStatus reports evaluated readiness for package evidence.
type ContentReadinessStatus struct {
	Scope                      string
	ProductionContent          bool
	ProductionReady            bool
	EvidenceStatus             string
	ProductionEvidenceStatus   string
	ReadinessLabel             string
	ReadinessDetail            string
	Evidence                   []EvidenceRef
	RequiredProductionEvidence []string
	AttachedProductionEvidence int
	Blockers                   []string
}

// ExpectedPackages returns the content package kinds tracked by status checks.
func ExpectedPackages() []ExpectedPackage {
	return []ExpectedPackage{
		{Kind: "app-id", DisplayName: "App-ID catalog", Detail: "Phragma-owned application taxonomy, evidence, confidence, and custom application definitions."},
		{Kind: "threat-id", DisplayName: "Threat-ID catalog", Detail: "Phragma-owned threat metadata, severity, exception context, and Suricata signature normalization."},
		{Kind: "intel-feeds", DisplayName: "Threat-intel feed package", Detail: "Governed feed provenance, license metadata, and offline blocklist release state."},
	}
}

// Statuses loads status for all expected package kinds under root.
func Statuses(root string) ([]Status, error) {
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(ExpectedPackages()))
	for _, exp := range ExpectedPackages() {
		st, err := loadOne(root, exp, keys)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// StatusFromDir evaluates one package manifest from an explicit directory.
func StatusFromDir(kind, dir string) (Status, error) {
	keys, err := loadTrustedKeyring(filepath.Dir(dir))
	if err != nil {
		return Status{}, err
	}
	return statusFromDirWithKeyring(kind, dir, keys)
}

// Preview evaluates a candidate package directory without installing it.
func Preview(root, kind, sourceDir string) (Status, error) {
	if strings.TrimSpace(sourceDir) == "" {
		return Status{}, fmt.Errorf("%w: source path is required", ErrInvalidPackage)
	}
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return Status{}, err
	}
	return statusFromDirWithKeyring(kind, sourceDir, keys)
}

// ReadEvidence returns a verified content readiness evidence artifact.
func ReadEvidence(root, kind, evidenceType string) (EvidenceArtifact, error) {
	evidenceType = strings.ToLower(strings.TrimSpace(evidenceType))
	if !evidenceTypeRE.MatchString(evidenceType) {
		return EvidenceArtifact{}, fmt.Errorf("%w: evidence_type must be a package evidence token", ErrInvalidEvidenceRequest)
	}
	exp, ok := expectedForKind(kind)
	if !ok {
		return EvidenceArtifact{}, fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	dir := filepath.Join(root, exp.Kind)
	st, err := loadFromManifest(filepath.Join(dir, "manifest.json"), exp, keys)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	var ref EvidenceRef
	for _, candidate := range st.ContentReadiness.Evidence {
		if strings.ToLower(strings.TrimSpace(candidate.Type)) == evidenceType {
			ref = candidate
			break
		}
	}
	if strings.TrimSpace(ref.Type) == "" {
		return EvidenceArtifact{}, fmt.Errorf("%w: %s", ErrEvidenceNotFound, evidenceType)
	}
	raw, err := readEvidenceFile(dir, ref)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	return EvidenceArtifact{
		Kind:           st.Kind,
		PackageState:   st.State,
		PackageVersion: st.Version,
		ManifestSHA256: st.ManifestSHA256,
		Evidence:       ref,
		ContentJSON:    raw,
	}, nil
}

// DefaultCorpusEvidenceType returns the package evidence artifact that carries
// corpus rows for the package kind.
func DefaultCorpusEvidenceType(kind string) string {
	switch strings.TrimSpace(kind) {
	case "app-id":
		return "app-regression-corpus"
	case "threat-id":
		return "pcap-regression-corpus"
	case "intel-feeds":
		return "parser-tests"
	default:
		return ""
	}
}

// ReadRegressionCorpus returns normalized sample rows from a verified
// package-local corpus evidence artifact.
func ReadRegressionCorpus(root, kind, evidenceType string) (RegressionCorpus, error) {
	if strings.TrimSpace(evidenceType) == "" {
		evidenceType = DefaultCorpusEvidenceType(kind)
	}
	artifact, err := ReadEvidence(root, kind, evidenceType)
	if err != nil {
		return RegressionCorpus{}, err
	}
	return regressionCorpusFromEvidence(artifact)
}

// ReadAppIDTaxonomy returns classifier-ready definitions from the verified
// app-taxonomy evidence artifact in the installed App-ID content package.
func ReadAppIDTaxonomy(root string) (AppIDTaxonomy, error) {
	artifact, err := ReadEvidence(root, "app-id", "app-taxonomy")
	if err != nil {
		return AppIDTaxonomy{}, err
	}
	defs, err := appIDDefinitionsFromTaxonomyEvidence(artifact)
	if err != nil {
		return AppIDTaxonomy{}, err
	}
	return AppIDTaxonomy{
		Kind:           artifact.Kind,
		PackageVersion: artifact.PackageVersion,
		ManifestSHA256: artifact.ManifestSHA256,
		Evidence:       artifact.Evidence,
		Definitions:    defs,
	}, nil
}

// ReadThreatIDTaxonomy returns classifier-ready metadata from the verified
// threat-taxonomy evidence artifact in the installed Threat-ID content package.
func ReadThreatIDTaxonomy(root string) (ThreatIDTaxonomy, error) {
	artifact, err := ReadEvidence(root, "threat-id", "threat-taxonomy")
	if err != nil {
		return ThreatIDTaxonomy{}, err
	}
	metadata, err := threatIDMetadataFromTaxonomyEvidence(artifact)
	if err != nil {
		return ThreatIDTaxonomy{}, err
	}
	return ThreatIDTaxonomy{
		Kind:           artifact.Kind,
		PackageVersion: artifact.PackageVersion,
		ManifestSHA256: artifact.ManifestSHA256,
		Evidence:       artifact.Evidence,
		Metadata:       metadata,
	}, nil
}

// CompareRegressionCorpus compares installed package corpus evidence with a
// server-local candidate package directory.
func CompareRegressionCorpus(root, kind, sourceDir, evidenceType string) (CorpusComparison, error) {
	if strings.TrimSpace(sourceDir) == "" {
		return CorpusComparison{}, fmt.Errorf("%w: source path is required", ErrInvalidPackage)
	}
	if strings.TrimSpace(evidenceType) == "" {
		evidenceType = DefaultCorpusEvidenceType(kind)
	}
	current, currentErr := ReadRegressionCorpus(root, kind, evidenceType)
	if currentErr != nil && !errors.Is(currentErr, ErrEvidenceNotFound) && !errors.Is(currentErr, ErrInvalidPackage) {
		return CorpusComparison{}, currentErr
	}
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return CorpusComparison{}, err
	}
	st, err := statusFromDirWithKeyring(kind, sourceDir, keys)
	if err != nil {
		return CorpusComparison{}, err
	}
	if st.State == "invalid" {
		return CorpusComparison{}, fmt.Errorf("%w: %s package is invalid: %s", ErrInvalidPackage, kind, strings.Join(st.Blockers, ", "))
	}
	previewArtifact, err := readEvidenceFromStatus(sourceDir, st, evidenceType)
	if err != nil {
		return CorpusComparison{}, err
	}
	preview, err := regressionCorpusFromEvidence(previewArtifact)
	if err != nil {
		return CorpusComparison{}, err
	}
	if currentErr != nil {
		current = RegressionCorpus{Kind: st.Kind, EvidenceType: evidenceType, Summary: "No installed corpus evidence is available for comparison."}
	}
	return compareCorpora(kind, evidenceType, current, preview), nil
}

func readEvidenceFromStatus(dir string, st Status, evidenceType string) (EvidenceArtifact, error) {
	evidenceType = strings.ToLower(strings.TrimSpace(evidenceType))
	if !evidenceTypeRE.MatchString(evidenceType) {
		return EvidenceArtifact{}, fmt.Errorf("%w: evidence_type must be a package evidence token", ErrInvalidEvidenceRequest)
	}
	var ref EvidenceRef
	for _, candidate := range st.ContentReadiness.Evidence {
		if strings.ToLower(strings.TrimSpace(candidate.Type)) == evidenceType {
			ref = candidate
			break
		}
	}
	if strings.TrimSpace(ref.Type) == "" {
		return EvidenceArtifact{}, fmt.Errorf("%w: %s", ErrEvidenceNotFound, evidenceType)
	}
	raw, err := readEvidenceFile(dir, ref)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	return EvidenceArtifact{
		Kind:           st.Kind,
		PackageState:   st.State,
		PackageVersion: st.Version,
		ManifestSHA256: st.ManifestSHA256,
		Evidence:       ref,
		ContentJSON:    raw,
	}, nil
}

func appIDDefinitionsFromTaxonomyEvidence(artifact EvidenceArtifact) ([]appid.Definition, error) {
	var parsed map[string]any
	if err := json.Unmarshal(artifact.ContentJSON, &parsed); err != nil {
		return nil, fmt.Errorf("%w: parse App-ID taxonomy evidence: %v", ErrInvalidPackage, err)
	}
	rawApps, _ := parsed["applications"].([]any)
	if len(rawApps) == 0 {
		rawApps, _ = parsed["apps"].([]any)
	}
	if len(rawApps) == 0 {
		rawApps, _ = parsed["Applications"].([]any)
	}
	source := appIDTaxonomySource(artifact)
	defs := make([]appid.Definition, 0, len(rawApps))
	for _, raw := range rawApps {
		app, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := strings.TrimSpace(firstStringField(app, "id", "ID", "name", "Name"))
		if id == "" {
			continue
		}
		name := strings.TrimSpace(firstStringField(app, "display_name", "displayName", "DisplayName", "name", "Name", "id", "ID"))
		category := strings.TrimSpace(firstStringField(app, "category", "Category"))
		def := appid.Definition{
			ID:            id,
			Name:          name,
			Category:      category,
			EngineSignals: stringSliceField(app, "engine_signals", "engineSignals", "EngineSignals", "signals", "Signals"),
			Ports:         appIDPortMatchesField(app, "ports", "Ports"),
			Source:        source,
		}
		if def.Name == "" {
			def.Name = def.ID
		}
		if def.Category == "" {
			def.Category = "unknown"
		}
		defs = append(defs, def)
	}
	return defs, nil
}

func threatIDMetadataFromTaxonomyEvidence(artifact EvidenceArtifact) ([]threatid.PackageMetadata, error) {
	var parsed map[string]any
	if err := json.Unmarshal(artifact.ContentJSON, &parsed); err != nil {
		return nil, fmt.Errorf("%w: parse Threat-ID taxonomy evidence: %v", ErrInvalidPackage, err)
	}
	rawThreats, _ := parsed["threats"].([]any)
	if len(rawThreats) == 0 {
		rawThreats, _ = parsed["metadata"].([]any)
	}
	if len(rawThreats) == 0 {
		rawThreats, _ = parsed["Threats"].([]any)
	}
	source := threatIDTaxonomySource(artifact)
	metadata := make([]threatid.PackageMetadata, 0, len(rawThreats))
	for _, raw := range rawThreats {
		threat, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		entry := threatid.PackageMetadata{
			ID:           strings.TrimSpace(firstStringField(threat, "id", "ID", "threat_id", "threatId", "ThreatId")),
			Name:         strings.TrimSpace(firstStringField(threat, "name", "Name", "display_name", "displayName", "DisplayName")),
			Category:     strings.TrimSpace(firstStringField(threat, "category", "Category")),
			Severity:     strings.TrimSpace(firstStringField(threat, "severity", "Severity")),
			SignatureIDs: int64SliceField(threat, "signature_ids", "signatureIds", "SignatureIds", "sids", "SIDs"),
			Evidence:     stringSliceField(threat, "evidence", "Evidence"),
		}
		if sid, ok := int64Field(threat, "signature_id", "signatureId", "SignatureId", "sid", "SID"); ok {
			entry.SignatureIDs = append(entry.SignatureIDs, sid)
		}
		if confidence, ok := uint32Field(threat, "confidence", "Confidence"); ok {
			entry.Confidence = confidence
		}
		if entry.ID == "" && len(entry.SignatureIDs) > 0 {
			entry.ID = "suricata-sid-" + strconv.FormatInt(entry.SignatureIDs[0], 10)
		}
		if entry.ID == "" && len(entry.SignatureIDs) == 0 {
			continue
		}
		entry.Evidence = append(entry.Evidence, source)
		metadata = append(metadata, entry)
	}
	return metadata, nil
}

func appIDTaxonomySource(artifact EvidenceArtifact) string {
	version := strings.TrimSpace(artifact.PackageVersion)
	manifestSHA := strings.TrimSpace(artifact.ManifestSHA256)
	if manifestSHA != "" && len(manifestSHA) > 12 {
		manifestSHA = manifestSHA[:12]
	}
	switch {
	case version != "" && manifestSHA != "":
		return "signed App-ID package " + version + "@" + manifestSHA
	case version != "":
		return "signed App-ID package " + version
	default:
		return "signed App-ID package"
	}
}

func threatIDTaxonomySource(artifact EvidenceArtifact) string {
	version := strings.TrimSpace(artifact.PackageVersion)
	manifestSHA := strings.TrimSpace(artifact.ManifestSHA256)
	if manifestSHA != "" && len(manifestSHA) > 12 {
		manifestSHA = manifestSHA[:12]
	}
	switch {
	case version != "" && manifestSHA != "":
		return "signed Threat-ID package " + version + "@" + manifestSHA
	case version != "":
		return "signed Threat-ID package " + version
	default:
		return "signed Threat-ID package"
	}
}

func stringSliceField(values map[string]any, names ...string) []string {
	for _, name := range names {
		switch raw := values[name].(type) {
		case []any:
			out := make([]string, 0, len(raw))
			for _, item := range raw {
				if value, ok := item.(string); ok {
					value = strings.TrimSpace(value)
					if value != "" {
						out = append(out, value)
					}
				}
			}
			return out
		case []string:
			out := make([]string, 0, len(raw))
			for _, value := range raw {
				value = strings.TrimSpace(value)
				if value != "" {
					out = append(out, value)
				}
			}
			return out
		}
	}
	return nil
}

func int64SliceField(values map[string]any, names ...string) []int64 {
	for _, name := range names {
		switch raw := values[name].(type) {
		case []any:
			out := make([]int64, 0, len(raw))
			for _, item := range raw {
				if value, ok := int64Value(item); ok && value > 0 {
					out = append(out, value)
				}
			}
			return out
		}
	}
	return nil
}

func int64Field(values map[string]any, names ...string) (int64, bool) {
	for _, name := range names {
		if value, ok := int64Value(values[name]); ok && value > 0 {
			return value, true
		}
	}
	return 0, false
}

func int64Value(raw any) (int64, bool) {
	switch value := raw.(type) {
	case float64:
		parsed := int64(value)
		if value == float64(parsed) {
			return parsed, true
		}
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func uint32Field(values map[string]any, names ...string) (uint32, bool) {
	for _, name := range names {
		switch value := values[name].(type) {
		case float64:
			parsed := uint32(value)
			if value >= 0 && value <= 100 && value == float64(parsed) {
				return parsed, true
			}
		case string:
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err == nil && parsed <= 100 {
				return uint32(parsed), true
			}
		}
	}
	return 0, false
}

func appIDPortMatchesField(values map[string]any, names ...string) []appid.PortMatch {
	var rawPorts []any
	for _, name := range names {
		rawPorts, _ = values[name].([]any)
		if len(rawPorts) > 0 {
			break
		}
	}
	matches := make([]appid.PortMatch, 0, len(rawPorts))
	for _, raw := range rawPorts {
		port, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(firstStringField(port, "protocol", "Protocol")))
		if proto != "tcp" && proto != "udp" {
			continue
		}
		for _, pr := range appIDPortRanges(port) {
			if pr.Start == 0 || pr.End < pr.Start {
				continue
			}
			matches = append(matches, appid.PortMatch{Protocol: proto, Start: pr.Start, End: pr.End})
		}
	}
	return matches
}

func appIDPortRanges(port map[string]any) []appid.PortMatch {
	if rawRanges, ok := port["ranges"].([]any); ok {
		return appIDPortRangeObjects(rawRanges)
	}
	if rawRanges, ok := port["ports"].([]any); ok {
		return appIDPortRangeObjects(rawRanges)
	}
	start, ok := uint16Field(port, "start", "Start", "port", "Port")
	if !ok {
		return nil
	}
	end, ok := uint16Field(port, "end", "End")
	if !ok {
		end = start
	}
	return []appid.PortMatch{{Start: start, End: end}}
}

func appIDPortRangeObjects(rawRanges []any) []appid.PortMatch {
	out := make([]appid.PortMatch, 0, len(rawRanges))
	for _, raw := range rawRanges {
		switch value := raw.(type) {
		case float64:
			if value >= 1 && value <= 65535 && value == float64(uint16(value)) {
				port := uint16(value)
				out = append(out, appid.PortMatch{Start: port, End: port})
			}
		case map[string]any:
			start, ok := uint16Field(value, "start", "Start", "port", "Port")
			if !ok {
				continue
			}
			end, ok := uint16Field(value, "end", "End")
			if !ok {
				end = start
			}
			out = append(out, appid.PortMatch{Start: start, End: end})
		}
	}
	return out
}

func uint16Field(values map[string]any, names ...string) (uint16, bool) {
	for _, name := range names {
		switch value := values[name].(type) {
		case float64:
			if value >= 1 && value <= 65535 && value == float64(uint16(value)) {
				return uint16(value), true
			}
		case string:
			var parsed uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &parsed); err == nil && parsed >= 1 && parsed <= 65535 {
				return uint16(parsed), true
			}
		}
	}
	return 0, false
}

func regressionCorpusFromEvidence(artifact EvidenceArtifact) (RegressionCorpus, error) {
	var parsed map[string]any
	if err := json.Unmarshal(artifact.ContentJSON, &parsed); err != nil {
		return RegressionCorpus{}, fmt.Errorf("%w: parse regression corpus evidence: %v", ErrInvalidPackage, err)
	}
	samples := normalizeCorpusSamples(parsed)
	failed := uint32(0)
	verdictSet := map[string]bool{}
	for _, sample := range samples {
		if sample.Verdict != "" {
			verdictSet[sample.Verdict] = true
			if sample.Verdict != "passed" {
				failed++
			}
		}
	}
	verdicts := make([]string, 0, len(verdictSet))
	for verdict := range verdictSet {
		verdicts = append(verdicts, verdict)
	}
	sort.Strings(verdicts)
	status := strings.ToLower(strings.TrimSpace(firstStringField(parsed, "verdict", "status", "Verdict", "Status")))
	summary := "No sample rows were declared in this evidence artifact."
	if len(samples) > 0 {
		summary = fmt.Sprintf("%d samples loaded; %d failing samples reported.", len(samples), failed)
	}
	evidenceType := strings.ToLower(strings.TrimSpace(artifact.Evidence.Type))
	if evidenceType == "" {
		evidenceType = strings.ToLower(strings.TrimSpace(firstStringField(parsed, "evidence_type", "EvidenceType", "type", "Type")))
	}
	return RegressionCorpus{
		Kind:           artifact.Kind,
		PackageState:   artifact.PackageState,
		PackageVersion: artifact.PackageVersion,
		ManifestSHA256: artifact.ManifestSHA256,
		Evidence:       artifact.Evidence,
		EvidenceType:   evidenceType,
		Status:         status,
		Samples:        samples,
		Verdicts:       verdicts,
		SampleCount:    uint32(len(samples)),
		FailedSamples:  failed,
		Summary:        summary,
	}, nil
}

func normalizeCorpusSamples(parsed map[string]any) []CorpusSample {
	rawSamples, _ := parsed["samples"].([]any)
	if len(rawSamples) == 0 {
		rawSamples, _ = parsed["Samples"].([]any)
	}
	if len(rawSamples) == 0 {
		rawSamples, _ = parsed["corpus"].([]any)
	}
	if len(rawSamples) == 0 {
		rawSamples, _ = parsed["rows"].([]any)
	}
	out := make([]CorpusSample, 0, len(rawSamples))
	for idx, raw := range rawSamples {
		sample, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		signatureID := firstStringField(sample, "signature_id", "signatureId", "sid", "SID")
		if signatureID == "" {
			if v, ok := sample["signature_id"].(float64); ok {
				signatureID = fmt.Sprintf("%.0f", v)
			} else if v, ok := sample["sid"].(float64); ok {
				signatureID = fmt.Sprintf("%.0f", v)
			}
		}
		expectedApp := firstStringField(sample, "expected_app", "expectedApp", "ExpectedApp")
		observedApp := firstStringField(sample, "observed_app", "observedApp", "ObservedApp")
		expectedVerdict := firstStringField(sample, "expected_verdict", "expectedVerdict", "expected", "Expected")
		observedVerdict := firstStringField(sample, "observed_verdict", "observedVerdict", "observed", "Observed")
		expected := expectedApp
		if expected == "" && signatureID != "" {
			expected = "SID " + signatureID
		}
		if expected == "" {
			expected = expectedVerdict
		}
		observed := observedApp
		if observed == "" {
			observed = observedVerdict
		}
		if observed == "" {
			observed = firstStringField(sample, "result", "Result")
		}
		id := firstStringField(sample, "id", "name", "sample_id", "sampleId")
		if id == "" {
			id = fmt.Sprintf("sample-%d", idx+1)
		}
		out = append(out, CorpusSample{
			ID:          id,
			PCAPSHA256:  firstStringField(sample, "pcap_sha256", "pcapSha256", "PcapSha256"),
			Expected:    expected,
			Observed:    observed,
			ExpectedApp: expectedApp,
			ObservedApp: observedApp,
			SignatureID: signatureID,
			Verdict:     strings.ToLower(strings.TrimSpace(firstStringField(sample, "verdict", "status", "Verdict", "Status"))),
			Detail:      firstStringField(sample, "detail", "reason", "Detail", "Reason"),
		})
	}
	return out
}

func compareCorpora(kind, evidenceType string, current, preview RegressionCorpus) CorpusComparison {
	currentByID := corpusSamplesByID(current.Samples)
	previewByID := corpusSamplesByID(preview.Samples)
	var diffs []CorpusSampleDiff
	added := uint32(0)
	removed := uint32(0)
	changed := uint32(0)
	for id, sample := range previewByID {
		if currentSample, ok := currentByID[id]; !ok {
			added++
			diffs = append(diffs, CorpusSampleDiff{ID: id, Change: "added", Preview: sample})
		} else if !sameCorpusSample(currentSample, sample) {
			changed++
			diffs = append(diffs, CorpusSampleDiff{ID: id, Change: "changed", Current: currentSample, Preview: sample})
		}
	}
	for id, sample := range currentByID {
		if _, ok := previewByID[id]; !ok {
			removed++
			diffs = append(diffs, CorpusSampleDiff{ID: id, Change: "removed", Current: sample})
		}
	}
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Change == diffs[j].Change {
			return diffs[i].ID < diffs[j].ID
		}
		return diffs[i].Change < diffs[j].Change
	})
	failedDelta := int32(preview.FailedSamples) - int32(current.FailedSamples)
	summary := fmt.Sprintf("%d added, %d removed, %d changed; failed sample delta %+d.", added, removed, changed, failedDelta)
	return CorpusComparison{
		Kind:         kind,
		EvidenceType: evidenceType,
		Current:      current,
		Preview:      preview,
		Added:        added,
		Removed:      removed,
		Changed:      changed,
		FailedDelta:  failedDelta,
		SampleDiffs:  diffs,
		Summary:      summary,
	}
}

func corpusSamplesByID(samples []CorpusSample) map[string]CorpusSample {
	out := make(map[string]CorpusSample, len(samples))
	for idx, sample := range samples {
		id := strings.TrimSpace(sample.ID)
		if id == "" {
			id = fmt.Sprintf("sample-%d", idx+1)
		}
		out[id] = sample
	}
	return out
}

func sameCorpusSample(a, b CorpusSample) bool {
	return a.PCAPSHA256 == b.PCAPSHA256 &&
		a.Expected == b.Expected &&
		a.Observed == b.Observed &&
		a.ExpectedApp == b.ExpectedApp &&
		a.ObservedApp == b.ObservedApp &&
		a.SignatureID == b.SignatureID &&
		a.Verdict == b.Verdict &&
		a.Detail == b.Detail
}

func statusFromDirWithKeyring(kind, dir string, keys trustedKeyring) (Status, error) {
	exp, ok := expectedForKind(kind)
	if !ok {
		return Status{}, fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	return loadFromManifest(filepath.Join(dir, "manifest.json"), exp, keys)
}

// Install promotes a verified content package into the active package root.
func Install(root, kind, sourceDir string) (ActionResult, error) {
	if strings.TrimSpace(sourceDir) == "" {
		return ActionResult{}, fmt.Errorf("%w: source path is required", ErrInvalidPackage)
	}
	exp, ok := expectedForKind(kind)
	if !ok {
		return ActionResult{}, fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return ActionResult{}, err
	}
	st, err := loadFromManifest(filepath.Join(sourceDir, "manifest.json"), exp, keys)
	if err != nil {
		return ActionResult{}, err
	}
	if st.State != "verified" {
		return ActionResult{}, fmt.Errorf("%w: %s package is %s: %s", ErrInvalidPackage, kind, st.State, strings.Join(st.Blockers, ", "))
	}
	created, rollbackPath, err := promote(root, kind, sourceDir, true, keys)
	if err != nil {
		return ActionResult{}, err
	}
	current, err := statusFromDirWithKeyring(kind, filepath.Join(root, kind), keys)
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{
		Status:          current,
		RollbackCreated: created,
		RollbackPath:    rollbackPath,
		Detail:          fmt.Sprintf("installed %s content package %s", kind, current.Version),
	}, nil
}

// RollbackPackage restores the latest verified rollback for a package kind.
func RollbackPackage(root, kind string) (ActionResult, error) {
	if _, ok := expectedForKind(kind); !ok {
		return ActionResult{}, fmt.Errorf("%w: %s", ErrInvalidKind, kind)
	}
	keys, err := loadTrustedKeyring(root)
	if err != nil {
		return ActionResult{}, err
	}
	target := filepath.Join(root, kind)
	selected, err := latestVerifiedRollback(target, kind, keys)
	if err != nil {
		return ActionResult{}, err
	}
	st, err := statusFromDirWithKeyring(kind, selected, keys)
	if err != nil {
		return ActionResult{}, err
	}
	if st.State != "verified" {
		return ActionResult{}, fmt.Errorf("%w: rollback package is %s: %s", ErrInvalidPackage, st.State, strings.Join(st.Blockers, ", "))
	}
	created, rollbackPath, err := backupCurrent(root, kind, keys)
	if err != nil {
		return ActionResult{}, err
	}
	if _, _, err := promote(root, kind, selected, false, keys); err != nil {
		return ActionResult{}, err
	}
	current, err := statusFromDirWithKeyring(kind, target, keys)
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{
		Status:               current,
		RollbackCreated:      created,
		RollbackPath:         rollbackPath,
		RestoredRollbackPath: selected,
		Detail:               fmt.Sprintf("rolled back %s content package to %s", kind, current.Version),
	}, nil
}

func loadOne(root string, exp ExpectedPackage, keys trustedKeyring) (Status, error) {
	return loadFromManifest(filepath.Join(root, exp.Kind, "manifest.json"), exp, keys)
}

func loadFromManifest(manifestPath string, exp ExpectedPackage, keys trustedKeyring) (Status, error) {
	st := fallbackStatusAt(manifestPath, exp)
	raw, err := readManifestRaw(manifestPath)
	if os.IsNotExist(err) {
		return st, nil
	}
	if errors.Is(err, ErrInvalidPackage) {
		st.Blockers = []string{"manifest path"}
		st.State = "invalid"
		return st, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("read %s manifest: %w", exp.Kind, err)
	}

	st.ManifestSHA256 = shaHex(raw)
	st.Blockers = nil
	st.State = "incomplete"
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		st.Blockers = append(st.Blockers, "manifest parse error")
		st.State = "invalid"
		return st, nil
	}
	if m.Name != "" {
		st.Name = m.Name
	}
	st.Version = m.Version
	st.Source = m.Source
	st.Provenance = m.Provenance
	st.InstalledAt = parsePackageTime(m.InstalledAt, m.CreatedAt)

	if m.SchemaVersion != SchemaVersion {
		st.Blockers = append(st.Blockers, "schema version")
	}
	if m.Kind != exp.Kind {
		st.Blockers = append(st.Blockers, "package kind")
	}
	if m.Version == "" || !semverRE.MatchString(m.Version) {
		st.Blockers = append(st.Blockers, "semantic version")
	}
	st.Blockers = append(st.Blockers, provenanceBlockers(m.Source, m.Provenance)...)

	hashBlockers := verifyFileHashes(filepath.Dir(st.ManifestPath), m.Files)
	st.Blockers = append(st.Blockers, hashBlockers...)
	st.SignatureStatus = verifySignatureStatus(m, keys)
	if st.SignatureStatus != "verified" {
		st.Blockers = append(st.Blockers, "signed manifest")
		switch st.SignatureStatus {
		case "invalid":
			st.Blockers = append(st.Blockers, "signature invalid")
		case "untrusted":
			st.Blockers = append(st.Blockers, "trusted publisher")
		case "unsupported":
			st.Blockers = append(st.Blockers, "signature algorithm")
		}
	}
	st.RegressionStatus = regressionStatus(m.Regression)
	st.Blockers = append(st.Blockers, regressionBlockers(m.Regression, st.RegressionStatus)...)
	st.RolloutState = ""
	if m.Rollout != nil {
		st.RolloutState = strings.ToLower(strings.TrimSpace(m.Rollout.State))
	}
	if st.RolloutState == "" {
		st.Blockers = append(st.Blockers, "staged rollout")
	}
	manifestRollbackAvailable := m.Rollback != nil && m.Rollback.Available
	if !manifestRollbackAvailable {
		st.Blockers = append(st.Blockers, "package rollback")
	}
	st.RollbackAvailable = verifiedRollbackAvailable(filepath.Dir(st.ManifestPath), exp.Kind, keys)
	st.ContentReadiness = evaluateContentReadiness(filepath.Dir(st.ManifestPath), exp.Kind, m.Version, m.ContentReadiness, m.Files, st.Blockers)

	st.Blockers = uniqueStrings(st.Blockers)
	if len(st.Blockers) == 0 {
		st.State = "verified"
	} else if containsAny(st.Blockers, "manifest parse error", "manifest path", "package kind", "file hash", "file path", "signature invalid") {
		st.State = "invalid"
	}
	return st, nil
}

func fallbackStatusAt(manifestPath string, exp ExpectedPackage) Status {
	return Status{
		Kind:             exp.Kind,
		Name:             exp.DisplayName,
		State:            "local-only",
		ManifestPath:     manifestPath,
		SignatureStatus:  "missing",
		RegressionStatus: "missing",
		Detail:           exp.Detail,
		ContentReadiness: ContentReadinessStatus{
			Scope:                      "missing",
			EvidenceStatus:             "missing",
			ProductionEvidenceStatus:   "missing",
			ReadinessLabel:             "missing-readiness",
			ReadinessDetail:            "No signed content readiness declaration is installed for this package.",
			RequiredProductionEvidence: requiredProductionEvidence(exp.Kind),
			Blockers: []string{
				"content readiness declaration",
				"production content scope",
			},
		},
		Blockers: []string{
			"signed manifest",
			"source identity",
			"package version/hash",
			"provenance",
			"provenance license",
			"provenance rights",
			"regression result",
			"regression evidence",
			"staged rollout",
			"package rollback",
		},
	}
}

func provenanceBlockers(source string, provenance []Provenance) []string {
	var blockers []string
	if strings.TrimSpace(source) == "" {
		blockers = append(blockers, "source identity")
	}
	if len(provenance) == 0 {
		return append(blockers, "provenance", "provenance license", "provenance rights")
	}
	hasNamedSource := false
	licenseMissing := false
	rightsMissing := false
	for _, p := range provenance {
		if strings.TrimSpace(p.Name) != "" && strings.TrimSpace(p.URL) != "" {
			hasNamedSource = true
		}
		if strings.TrimSpace(p.License) == "" {
			licenseMissing = true
		}
		if p.AllowsCommercialUse == nil || p.AllowsRedistribution == nil {
			rightsMissing = true
		}
	}
	if !hasNamedSource {
		blockers = append(blockers, "provenance")
	}
	if licenseMissing {
		blockers = append(blockers, "provenance license")
	}
	if rightsMissing {
		blockers = append(blockers, "provenance rights")
	}
	return blockers
}

func regressionStatus(regression *Regression) string {
	if regression == nil || strings.TrimSpace(regression.Status) == "" {
		return "missing"
	}
	return strings.ToLower(strings.TrimSpace(regression.Status))
}

func regressionBlockers(regression *Regression, status string) []string {
	if status != "passed" {
		return []string{"regression result"}
	}
	if regression == nil {
		return []string{"regression result"}
	}
	var blockers []string
	if regression.Failed != 0 {
		blockers = append(blockers, "regression result")
	}
	if strings.TrimSpace(regression.Corpus) == "" ||
		strings.TrimSpace(regression.RunAt) == "" ||
		parsePackageTime(regression.RunAt).IsZero() ||
		regression.Passed == 0 {
		blockers = append(blockers, "regression evidence")
	}
	return blockers
}

func evaluateContentReadiness(base, kind, packageVersion string, declaration *ContentReadiness, files []File, packageBlockers []string) ContentReadinessStatus {
	required := requiredProductionEvidence(kind)
	st := ContentReadinessStatus{
		Scope:                      "missing",
		EvidenceStatus:             "missing",
		ProductionEvidenceStatus:   "missing",
		ReadinessLabel:             "missing-readiness",
		ReadinessDetail:            "No signed content readiness declaration is installed for this package.",
		RequiredProductionEvidence: required,
		Blockers: []string{
			"content readiness declaration",
			"production content scope",
		},
	}
	if declaration == nil {
		return st
	}

	st.Scope = strings.ToLower(strings.TrimSpace(declaration.Scope))
	st.ProductionContent = declaration.ProductionContent
	st.Evidence = declaration.Evidence
	st.Blockers = nil
	if st.Scope == "" {
		st.Scope = "unspecified"
	}
	if st.Scope != "production" || !declaration.ProductionContent {
		st.Blockers = append(st.Blockers, "production content scope")
	}
	if declaration.ProductionContent && !sameEvidenceSet(declaration.RequiredProductionEvidence, required) {
		st.Blockers = append(st.Blockers, "production evidence declaration")
	}
	if len(packageBlockers) != 0 {
		st.Blockers = append(st.Blockers, "verified package")
	}

	fileHashes := packageFileHashes(files)
	seenEvidence := map[string]bool{}
	for _, evidence := range declaration.Evidence {
		evidenceType := strings.ToLower(strings.TrimSpace(evidence.Type))
		if evidenceType == "" {
			st.Blockers = append(st.Blockers, "production evidence type")
			continue
		}
		if seenEvidence[evidenceType] {
			st.Blockers = append(st.Blockers, "production evidence duplicate:"+evidenceType)
		}
		seenEvidence[evidenceType] = true
		validateEvidenceRef(base, kind, packageVersion, evidence, fileHashes, &st)
	}

	for _, evidenceType := range required {
		if !seenEvidence[evidenceType] {
			st.Blockers = append(st.Blockers, "production evidence:"+evidenceType)
		}
	}
	for _, evidenceType := range required {
		if seenEvidence[evidenceType] && !hasBlockerPrefix(st.Blockers, "production evidence:"+evidenceType) {
			st.AttachedProductionEvidence++
		}
	}

	st.Blockers = uniqueStrings(st.Blockers)
	switch {
	case len(st.Blockers) == 0:
		st.ProductionReady = true
		st.EvidenceStatus = "passed"
		st.ProductionEvidenceStatus = "production-ready"
		st.ReadinessLabel = "production-ready"
		st.ReadinessDetail = "Signed production content evidence passed; this package is eligible for reviewed production rollout."
	case st.Scope == "demo-only" || !st.ProductionContent:
		st.EvidenceStatus = "demo-only"
		st.ProductionEvidenceStatus = "demo"
		st.ReadinessLabel = "demo-only"
		st.ReadinessDetail = "This package is verified for demo or lab use only and is not approved for verdict-changing production content."
	default:
		st.EvidenceStatus = "incomplete"
		st.ProductionEvidenceStatus = "production-blocked"
		st.ReadinessLabel = "production-blocked"
		st.ReadinessDetail = "This package is not production-ready until every signed production evidence gate is present and passing."
	}
	return st
}

func hasBlockerPrefix(blockers []string, prefix string) bool {
	for _, blocker := range blockers {
		if strings.HasPrefix(blocker, prefix) {
			return true
		}
	}
	return false
}

func validateEvidenceRef(base, kind, packageVersion string, evidence EvidenceRef, fileHashes map[string]string, st *ContentReadinessStatus) {
	artifact := filepath.Clean(strings.TrimSpace(evidence.Artifact))
	evidenceType := strings.ToLower(strings.TrimSpace(evidence.Type))
	if artifact == "." || artifact == "" {
		st.Blockers = append(st.Blockers, "production evidence artifact")
		return
	}
	artifactSlash := filepath.ToSlash(artifact)
	if !strings.HasPrefix(artifactSlash, "evidence/") || filepath.Ext(artifactSlash) != ".json" {
		st.Blockers = append(st.Blockers, "production evidence artifact")
		return
	}
	declaredHash := strings.ToLower(strings.TrimSpace(evidence.SHA256))
	if !sha256HexRE.MatchString(declaredHash) {
		st.Blockers = append(st.Blockers, "production evidence hash")
		return
	}
	path, ok := safeExistingPackageFilePath(base, artifact)
	if !ok {
		st.Blockers = append(st.Blockers, "production evidence artifact")
		return
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		st.Blockers = append(st.Blockers, "production evidence artifact")
		return
	}
	if info.Size() > MaxEvidenceArtifactBytes {
		st.Blockers = append(st.Blockers, "production evidence content")
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil || shaHex(raw) != declaredHash {
		st.Blockers = append(st.Blockers, "production evidence hash")
		return
	}
	if len(raw) > MaxEvidenceArtifactBytes {
		st.Blockers = append(st.Blockers, "production evidence content")
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		st.Blockers = append(st.Blockers, "production evidence content")
	}
	if !json.Valid(raw) {
		st.Blockers = append(st.Blockers, "production evidence format")
		return
	}
	var artifactJSON map[string]any
	if err := json.Unmarshal(raw, &artifactJSON); err != nil || artifactJSON == nil {
		st.Blockers = append(st.Blockers, "production evidence format")
		return
	}
	artifactType := strings.ToLower(strings.TrimSpace(firstStringField(artifactJSON, "evidence_type", "EvidenceType", "type", "Type")))
	if artifactType != evidenceType {
		st.Blockers = append(st.Blockers, "production evidence type:"+evidenceType)
	}
	artifactVerdict := strings.ToLower(strings.TrimSpace(firstStringField(artifactJSON, "verdict", "Verdict", "status", "Status")))
	if artifactVerdict != "passed" {
		st.Blockers = append(st.Blockers, "production evidence verdict:"+evidenceType)
	}
	if kind == "app-id" && evidenceType == "app-regression-corpus" {
		validateAppRegressionCorpusArtifact(artifactJSON, packageVersion, st)
	}
	if signedHash := fileHashes[artifactSlash]; signedHash != declaredHash {
		st.Blockers = append(st.Blockers, "production evidence package file")
	}
	if strings.TrimSpace(evidence.GeneratedAt) == "" || parsePackageTime(evidence.GeneratedAt).IsZero() {
		st.Blockers = append(st.Blockers, "production evidence timestamp")
	}
}

func validateAppRegressionCorpusArtifact(artifactJSON map[string]any, packageVersion string, st *ContentReadinessStatus) {
	artifactVersion := strings.TrimSpace(firstStringField(artifactJSON, "package_version", "packageVersion", "PackageVersion"))
	if artifactVersion == "" || !semverRE.MatchString(artifactVersion) {
		st.Blockers = append(st.Blockers, "production evidence package version:app-regression-corpus")
	} else if strings.TrimSpace(packageVersion) != "" && artifactVersion != strings.TrimSpace(packageVersion) {
		st.Blockers = append(st.Blockers, "production evidence package version mismatch:app-regression-corpus")
	}

	samples, ok := artifactJSON["samples"].([]any)
	if !ok {
		samples, ok = artifactJSON["Samples"].([]any)
	}
	if !ok || len(samples) == 0 {
		st.Blockers = append(st.Blockers, "production evidence corpus:app-regression-corpus")
		return
	}
	for _, rawSample := range samples {
		sample, ok := rawSample.(map[string]any)
		if !ok {
			st.Blockers = append(st.Blockers, "production evidence corpus:app-regression-corpus")
			continue
		}
		if !sha256HexRE.MatchString(strings.TrimSpace(firstStringField(sample, "pcap_sha256", "pcapSha256", "PcapSha256"))) {
			st.Blockers = append(st.Blockers, "production evidence sample hash:app-regression-corpus")
		}
		if strings.TrimSpace(firstStringField(sample, "expected_app", "expectedApp", "ExpectedApp")) == "" ||
			strings.TrimSpace(firstStringField(sample, "observed_app", "observedApp", "ObservedApp")) == "" {
			st.Blockers = append(st.Blockers, "production evidence sample app:app-regression-corpus")
		}
		sampleVerdict := strings.ToLower(strings.TrimSpace(firstStringField(sample, "verdict", "Verdict", "status", "Status")))
		if sampleVerdict != "passed" {
			st.Blockers = append(st.Blockers, "production evidence sample verdict:app-regression-corpus")
		}
	}
}

func firstStringField(values map[string]any, names ...string) string {
	for _, name := range names {
		switch value := values[name].(type) {
		case string:
			return value
		}
	}
	return ""
}

func readEvidenceFile(base string, evidence EvidenceRef) ([]byte, error) {
	artifact := filepath.Clean(strings.TrimSpace(evidence.Artifact))
	if artifact == "." || artifact == "" {
		return nil, fmt.Errorf("%w: production evidence artifact", ErrEvidenceNotFound)
	}
	artifactSlash := filepath.ToSlash(artifact)
	if !strings.HasPrefix(artifactSlash, "evidence/") || filepath.Ext(artifactSlash) != ".json" {
		return nil, fmt.Errorf("%w: production evidence artifact", ErrInvalidPackage)
	}
	declaredHash := strings.ToLower(strings.TrimSpace(evidence.SHA256))
	if !sha256HexRE.MatchString(declaredHash) {
		return nil, fmt.Errorf("%w: production evidence hash", ErrInvalidPackage)
	}
	path, ok := safeExistingPackageFilePath(base, artifact)
	if !ok {
		return nil, fmt.Errorf("%w: production evidence artifact", ErrInvalidPackage)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: production evidence artifact", ErrEvidenceNotFound)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: production evidence artifact", ErrInvalidPackage)
	}
	if info.Size() > MaxEvidenceArtifactBytes {
		return nil, fmt.Errorf("%w: production evidence exceeds %d bytes", ErrInvalidPackage, MaxEvidenceArtifactBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read production evidence: %v", ErrInvalidPackage, err)
	}
	if len(raw) > MaxEvidenceArtifactBytes {
		return nil, fmt.Errorf("%w: production evidence exceeds %d bytes", ErrInvalidPackage, MaxEvidenceArtifactBytes)
	}
	if shaHex(raw) != declaredHash {
		return nil, fmt.Errorf("%w: production evidence hash", ErrInvalidPackage)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%w: production evidence format", ErrInvalidPackage)
	}
	return raw, nil
}

func sameEvidenceSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotSet := map[string]bool{}
	for _, value := range got {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || gotSet[value] {
			return false
		}
		gotSet[value] = true
	}
	for _, value := range want {
		if !gotSet[value] {
			return false
		}
	}
	return true
}

func packageFileHashes(files []File) map[string]string {
	out := map[string]string{}
	for _, file := range files {
		path := filepath.ToSlash(filepath.Clean(strings.TrimSpace(file.Path)))
		if path == "." || path == "" {
			continue
		}
		out[path] = strings.ToLower(strings.TrimSpace(file.SHA256))
	}
	return out
}

func requiredProductionEvidence(kind string) []string {
	switch kind {
	case "app-id":
		return []string{"app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"}
	case "threat-id":
		return []string{"threat-taxonomy", "pcap-regression-corpus", "false-positive-regression", "license-review", "staged-rollout", "rollback-drill"}
	case "intel-feeds":
		return []string{"feed-registry", "parser-tests", "license-review", "false-positive-regression", "staged-rollout", "rollback-drill"}
	default:
		return nil
	}
}

func expectedForKind(kind string) (ExpectedPackage, bool) {
	kind = strings.TrimSpace(kind)
	for _, exp := range ExpectedPackages() {
		if exp.Kind == kind {
			return exp, true
		}
	}
	return ExpectedPackage{}, false
}

func promote(root, kind, sourceDir string, createBackup bool, keys trustedKeyring) (bool, string, error) {
	st, err := statusFromDirWithKeyring(kind, sourceDir, keys)
	if err != nil {
		return false, "", err
	}
	if st.State != "verified" {
		return false, "", fmt.Errorf("%w: %s package is %s: %s", ErrInvalidPackage, kind, st.State, strings.Join(st.Blockers, ", "))
	}
	target := filepath.Join(root, kind)
	sourceAbs, err := filepath.Abs(sourceDir)
	if err != nil {
		return false, "", fmt.Errorf("resolve source path: %w", err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false, "", fmt.Errorf("resolve target path: %w", err)
	}
	if sourceAbs == targetAbs {
		return false, "", fmt.Errorf("%w: source already matches installed package", ErrInvalidPackage)
	}

	m, raw, err := readManifest(filepath.Join(sourceDir, "manifest.json"))
	if err != nil {
		return false, "", err
	}
	staging := filepath.Join(root, ".staging", backupName(kind, st.Version))
	if err := os.RemoveAll(staging); err != nil {
		return false, "", fmt.Errorf("prepare staging: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := copyPackageFiles(sourceDir, staging, raw, m); err != nil {
		return false, "", err
	}
	staged, err := statusFromDirWithKeyring(kind, staging, keys)
	if err != nil {
		return false, "", err
	}
	if staged.State != "verified" {
		return false, "", fmt.Errorf("%w: staged package is %s: %s", ErrInvalidPackage, staged.State, strings.Join(staged.Blockers, ", "))
	}
	if createBackup {
		created, rollbackPath, err := backupCurrent(root, kind, keys)
		if err != nil {
			return false, "", err
		}
		if err := copyRollbackBackups(target, staging); err != nil {
			return false, "", err
		}
		if err := swapPackageDir(target, staging); err != nil {
			return false, "", err
		}
		return created, rollbackPath, nil
	}

	if err := copyRollbackBackups(target, staging); err != nil {
		return false, "", err
	}
	if err := swapPackageDir(target, staging); err != nil {
		return false, "", err
	}
	return false, "", nil
}

func backupCurrent(root, kind string, keys trustedKeyring) (bool, string, error) {
	target := filepath.Join(root, kind)
	manifestPath := filepath.Join(target, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return false, "", nil
	} else if err != nil {
		return false, "", fmt.Errorf("stat current manifest: %w", err)
	}
	st, err := statusFromDirWithKeyring(kind, target, keys)
	if err != nil {
		return false, "", err
	}
	if st.State != "verified" {
		return false, "", nil
	}
	m, raw, err := readManifest(manifestPath)
	if err != nil {
		return false, "", err
	}
	backupDir := filepath.Join(target, ".rollback", backupName(kind, st.Version))
	if err := copyPackageFiles(target, backupDir, raw, m); err != nil {
		return false, "", err
	}
	backupStatus, err := statusFromDirWithKeyring(kind, backupDir, keys)
	if err != nil {
		return false, "", err
	}
	if backupStatus.State != "verified" {
		return false, "", fmt.Errorf("%w: rollback backup is %s: %s", ErrInvalidPackage, backupStatus.State, strings.Join(backupStatus.Blockers, ", "))
	}
	return true, backupDir, nil
}

func verifiedRollbackAvailable(target, kind string, keys trustedKeyring) bool {
	_, err := latestVerifiedRollback(target, kind, keys)
	return err == nil
}

func latestVerifiedRollback(target, kind string, keys trustedKeyring) (string, error) {
	rollbackRoot := filepath.Join(target, ".rollback")
	entries, err := os.ReadDir(rollbackRoot)
	if os.IsNotExist(err) {
		return "", ErrNoRollback
	}
	if err != nil {
		return "", fmt.Errorf("read rollback directory: %w", err)
	}
	var candidates []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(rollbackRoot, entry.Name())
		if _, err := os.Stat(filepath.Join(candidate, "manifest.json")); err == nil {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return "", ErrNoRollback
	}
	sort.Strings(candidates)
	for i := len(candidates) - 1; i >= 0; i-- {
		st, err := statusFromDirWithKeyring(kind, candidates[i], keys)
		if err == nil && st.State == "verified" {
			return candidates[i], nil
		}
	}
	return "", ErrNoRollback
}

func readManifest(manifestPath string) (Manifest, []byte, error) {
	raw, err := readManifestRaw(manifestPath)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("%w: read manifest: %v", ErrInvalidPackage, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, nil, fmt.Errorf("%w: parse manifest: %v", ErrInvalidPackage, err)
	}
	return m, raw, nil
}

func readManifestRaw(manifestPath string) ([]byte, error) {
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: manifest is not a regular file", ErrInvalidPackage)
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidPackage, maxManifestBytes)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidPackage, maxManifestBytes)
	}
	return raw, nil
}

func swapPackageDir(target, staging string) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create content package root: %w", err)
	}
	previous := filepath.Join(parent, ".staging", "previous-"+filepath.Base(target)+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("prepare previous package path: %w", err)
	}
	targetExists := true
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		targetExists = false
	} else if err != nil {
		return fmt.Errorf("stat installed package directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("%w: installed package path is not a directory", ErrInvalidPackage)
	}
	if targetExists {
		if err := renamePackageDir(target, previous); err != nil {
			return fmt.Errorf("move previous package aside: %w", err)
		}
	}
	if err := renamePackageDir(staging, target); err != nil {
		if targetExists {
			restoreErr := renamePackageDir(previous, target)
			if restoreErr != nil {
				return fmt.Errorf("activate package: %w; restore previous package: %v", err, restoreErr)
			}
		}
		return fmt.Errorf("activate package: %w", err)
	}
	if targetExists {
		_ = os.RemoveAll(previous)
	}
	return nil
}

func copyRollbackBackups(sourcePackageDir, targetPackageDir string) error {
	source := filepath.Join(sourcePackageDir, ".rollback")
	if _, err := os.Lstat(source); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat rollback backups: %w", err)
	}
	return copyTreeNoSymlinks(source, filepath.Join(targetPackageDir, ".rollback"))
}

func copyTreeNoSymlinks(source, target string) error {
	rootInfo, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("stat package tree: %w", err)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("%w: package tree is not a directory", ErrInvalidPackage)
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("read package tree entry: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: package tree contains symlink %s", ErrInvalidPackage, path)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve package tree entry: %w", err)
		}
		dst := filepath.Join(target, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: package tree entry %s is not a regular file", ErrInvalidPackage, path)
		}
		return copyRegularFile(path, dst)
	})
}

func copyPackageFiles(sourceDir, targetDir string, manifestRaw []byte, m Manifest) error {
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create package directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "manifest.json"), manifestRaw, 0o644); err != nil {
		return fmt.Errorf("write package manifest: %w", err)
	}
	for _, f := range m.Files {
		src, ok := safeExistingPackageFilePath(sourceDir, f.Path)
		if !ok || f.Path == "" {
			return fmt.Errorf("%w: unsafe package path %q", ErrInvalidPackage, f.Path)
		}
		dst, ok := safeNewPackageFilePath(targetDir, f.Path)
		if !ok {
			return fmt.Errorf("%w: unsafe target path %q", ErrInvalidPackage, f.Path)
		}
		if err := copyRegularFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyRegularFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("%w: read package file %s: %v", ErrInvalidPackage, src, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: package file %s is not a regular file", ErrInvalidPackage, src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create package file directory: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("%w: open package file %s: %v", ErrInvalidPackage, src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("write package file %s: %w", dst, err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy package file %s: %w", dst, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close package file %s: %w", dst, closeErr)
	}
	return nil
}

func backupName(kind, version string) string {
	version = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(strings.TrimSpace(version))
	if version == "" {
		version = "unknown"
	}
	return fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102T150405.000000000Z"), kind, version)
}

func verifyFileHashes(base string, files []File) []string {
	if len(files) == 0 {
		return []string{"package version/hash"}
	}
	var blockers []string
	for _, f := range files {
		path, ok := safeExistingPackageFilePath(base, f.Path)
		if !ok || f.Path == "" {
			blockers = append(blockers, "file path")
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			blockers = append(blockers, "file hash")
			continue
		}
		if !info.Mode().IsRegular() {
			blockers = append(blockers, "file path")
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			blockers = append(blockers, "file hash")
			continue
		}
		if !strings.EqualFold(shaHex(raw), strings.TrimSpace(f.SHA256)) {
			blockers = append(blockers, "file hash")
		}
	}
	return uniqueStrings(blockers)
}

func safePackagePath(base, rel string) (string, bool) {
	if filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", false
	}
	if reservedPackageRelPath(clean) {
		return "", false
	}
	path := filepath.Join(base, clean)
	relToBase, err := filepath.Rel(base, path)
	if err != nil || strings.HasPrefix(relToBase, "..") {
		return "", false
	}
	return path, true
}

func safeExistingPackageFilePath(base, rel string) (string, bool) {
	path, ok := safePackagePath(base, rel)
	if !ok {
		return "", false
	}
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", false
	}
	pathReal, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	if !pathWithinDir(baseReal, pathReal) || pathHasSymlinkComponent(base, rel, true) {
		return "", false
	}
	return path, true
}

func safeNewPackageFilePath(base, rel string) (string, bool) {
	_, ok := safePackagePath(base, rel)
	if !ok {
		return "", false
	}
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", false
	}
	path := filepath.Join(baseReal, filepath.Clean(rel))
	if !pathWithinDir(baseReal, path) || pathHasSymlinkComponent(baseReal, rel, false) {
		return "", false
	}
	return path, true
}

func pathWithinDir(base, path string) bool {
	base = filepath.Clean(base)
	path = filepath.Clean(path)
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathHasSymlinkComponent(base, rel string, includeFinal bool) bool {
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." {
		return true
	}
	parts := strings.Split(clean, string(filepath.Separator))
	limit := len(parts)
	if !includeFinal && limit > 0 {
		limit--
	}
	current := base
	for i := 0; i < limit; i++ {
		current = filepath.Join(current, parts[i])
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && !includeFinal {
			return false
		}
		if err != nil {
			return true
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func reservedPackageRelPath(clean string) bool {
	first := clean
	if i := strings.Index(clean, string(filepath.Separator)); i >= 0 {
		first = clean[:i]
	}
	first = strings.TrimSpace(first)
	return first == "" || first == "manifest.json" || strings.HasPrefix(first, ".")
}

func loadTrustedKeyring(root string) (trustedKeyring, error) {
	out := trustedKeyring{}
	dir := filepath.Join(root, trustedKeyringDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read trusted content publisher keyring: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		keyID := trustedKeyIDFromFilename(entry.Name())
		if keyID == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read trusted content publisher key %s: %w", entry.Name(), err)
		}
		pub, err := decodeBase64(string(raw))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted content publisher key %s is not a base64 Ed25519 public key", entry.Name())
		}
		out[keyID] = ed25519.PublicKey(pub)
	}
	return out, nil
}

func trustedKeyIDFromFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	for _, suffix := range []string{".ed25519.pub", ".pub"} {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
			if name == "." || name == string(filepath.Separator) {
				return ""
			}
			return strings.TrimSpace(name)
		}
	}
	return ""
}

func verifySignatureStatus(m Manifest, keys trustedKeyring) string {
	if m.Signature == nil {
		return "missing"
	}
	if strings.ToLower(m.Signature.Algorithm) != "ed25519" {
		return "unsupported"
	}
	keyID := strings.TrimSpace(m.Signature.KeyID)
	if keyID == "" {
		return "untrusted"
	}
	pub := keys[keyID]
	if len(pub) != ed25519.PublicKeySize {
		return "untrusted"
	}
	if strings.TrimSpace(m.Signature.PublicKey) != "" {
		declaredPub, err := decodeBase64(m.Signature.PublicKey)
		if err != nil || !bytes.Equal(declaredPub, pub) {
			return "invalid"
		}
	}
	sig, err := decodeBase64(m.Signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "invalid"
	}
	payload, err := signaturePayload(m)
	if err != nil {
		return "invalid"
	}
	if !ed25519.Verify(pub, payload, sig) {
		return "invalid"
	}
	return "verified"
}

// SignaturePayloadForTest exposes manifest signature payload generation to tests.
func SignaturePayloadForTest(m Manifest) ([]byte, error) {
	return signaturePayload(m)
}

func signaturePayload(m Manifest) ([]byte, error) {
	m.Signature = nil
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(raw), nil
}

func parsePackageTime(values ...string) time.Time {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty")
	}
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func shaHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func containsAny(values []string, needles ...string) bool {
	for _, value := range values {
		for _, needle := range needles {
			if strings.Contains(value, needle) {
				return true
			}
		}
	}
	return false
}

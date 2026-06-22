package contentpkg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusesReportsMissingPackagesAsLocalOnly(t *testing.T) {
	statuses, err := Statuses(t.TempDir())
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if got, want := len(statuses), 3; got != want {
		t.Fatalf("status count = %d, want %d", got, want)
	}
	for _, st := range statuses {
		if st.State != "local-only" {
			t.Fatalf("%s state = %q, want local-only", st.Kind, st.State)
		}
		for _, want := range []string{"signed manifest", "package version/hash", "regression result", "staged rollout", "package rollback"} {
			if !hasString(st.Blockers, want) {
				t.Fatalf("%s missing blocker %q in %#v", st.Kind, want, st.Blockers)
			}
		}
	}
}

func TestStatusesVerifiesSignedPackageManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, "apps.json"), []byte(`{"apps":[{"name":"corp-admin"}]}`))
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	writeTrustedPublisherKey(t, root, "test-key", pub)
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Kind:          "app-id",
		Name:          "Phragma App-ID catalog",
		Version:       "1.2.3",
		Source:        "Phragma content release pipeline",
		CreatedAt:     "2026-06-17T12:00:00Z",
		InstalledAt:   "2026-06-17T12:05:00Z",
		Files: []File{{
			Path:   "apps.json",
			SHA256: "e247cff4aef1648e5eccda45a39f0695f4dfd703661f62baf9f18da6959caa6f",
		}},
		Regression: &Regression{Status: "passed", Corpus: "pcap-regression", Passed: 27, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &Rollout{State: "stable", Scope: "all"},
		Rollback:   &Rollback{Available: true, PreviousVersion: "1.2.2"},
		Provenance: []Provenance{{
			Name:                 "Phragma lab",
			URL:                  "https://example.test/content",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtr(true),
			AllowsRedistribution: boolPtr(true),
		}},
	}
	payload, err := SignaturePayloadForTest(manifest)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	manifest.Signature = &Signature{
		Algorithm: "ed25519",
		KeyID:     "test-key",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), raw)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.Kind != "app-id" {
		t.Fatalf("first kind = %q, want app-id", app.Kind)
	}
	if app.State != "verified" {
		t.Fatalf("state = %q, blockers=%#v", app.State, app.Blockers)
	}
	if app.SignatureStatus != "verified" {
		t.Fatalf("signature = %q", app.SignatureStatus)
	}
	if app.RegressionStatus != "passed" {
		t.Fatalf("regression = %q", app.RegressionStatus)
	}
	if app.RolloutState != "stable" {
		t.Fatalf("rollout = %q", app.RolloutState)
	}
	if app.RollbackAvailable {
		t.Fatal("rollback should not be operationally available without a verified local backup")
	}
	if app.Version != "1.2.3" {
		t.Fatalf("version = %q", app.Version)
	}
	if len(app.Provenance) != 1 || app.Provenance[0].License != "Apache-2.0" {
		t.Fatalf("provenance = %#v", app.Provenance)
	}
}

func TestStatusesRequiresProvenanceLicenseRightsAndSourceIdentity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "intel-feeds")
	publisher := writeSignedPackageWithMutator(t, dir, "intel-feeds", "1.0.0", "feeds.json", []byte(`{"feeds":["urlhaus"]}`), func(m *Manifest) {
		m.Source = " "
		m.Provenance = []Provenance{{
			Name:    " ",
			URL:     " ",
			License: " ",
		}}
	})
	publisher.trust(t, root)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	intel := statuses[2]
	if intel.State != "incomplete" {
		t.Fatalf("state = %q, want incomplete blockers=%#v", intel.State, intel.Blockers)
	}
	if intel.SignatureStatus != "verified" {
		t.Fatalf("signature status = %q, want verified", intel.SignatureStatus)
	}
	for _, want := range []string{"source identity", "provenance", "provenance license", "provenance rights"} {
		if !hasString(intel.Blockers, want) {
			t.Fatalf("missing blocker %q in %#v", want, intel.Blockers)
		}
	}
}

func TestStatusesRequiresRegressionCorpusAndRunEvidence(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["corp-admin"]}`), func(m *Manifest) {
		m.Regression = &Regression{Status: "passed", Passed: 3}
	})
	publisher.trust(t, root)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "incomplete" {
		t.Fatalf("state = %q, want incomplete blockers=%#v", app.State, app.Blockers)
	}
	if app.RegressionStatus != "passed" {
		t.Fatalf("regression status = %q, want passed", app.RegressionStatus)
	}
	if !hasString(app.Blockers, "regression evidence") {
		t.Fatalf("missing regression evidence blocker in %#v", app.Blockers)
	}
	if hasString(app.Blockers, "regression result") {
		t.Fatalf("unexpected regression result blocker for passed status in %#v", app.Blockers)
	}
}

func TestStatusesSeparatesDemoMechanicsFromProductionReadiness(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackage(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["demo"]}`))
	publisher.trust(t, root)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", app.State, app.Blockers)
	}
	readiness := app.ContentReadiness
	if readiness.ProductionReady {
		t.Fatalf("demo package should not be production-ready: %#v", readiness)
	}
	if readiness.EvidenceStatus != "demo-only" {
		t.Fatalf("readiness status = %q, want demo-only blockers=%#v", readiness.EvidenceStatus, readiness.Blockers)
	}
	if readiness.ProductionEvidenceStatus != "demo" {
		t.Fatalf("production evidence status = %q, want demo", readiness.ProductionEvidenceStatus)
	}
	if readiness.ReadinessLabel != "demo-only" || !strings.Contains(readiness.ReadinessDetail, "not approved") {
		t.Fatalf("readiness label/detail = %q/%q, want explicit demo-only production warning", readiness.ReadinessLabel, readiness.ReadinessDetail)
	}
	if readiness.Scope != "demo-only" || readiness.ProductionContent {
		t.Fatalf("readiness scope/content = %q/%v, want demo-only/false", readiness.Scope, readiness.ProductionContent)
	}
	if !hasString(readiness.Blockers, "production content scope") {
		t.Fatalf("missing production content scope blocker in %#v", readiness.Blockers)
	}
}

func TestStatusesReportsProductionReadyContentEvidencePerKind(t *testing.T) {
	for _, tc := range []struct {
		kind     string
		fileName string
		content  []byte
	}{
		{kind: "app-id", fileName: "apps.json", content: []byte(`{"apps":["prod"]}`)},
		{kind: "threat-id", fileName: "threats.json", content: []byte(`{"threats":["prod"]}`)},
		{kind: "intel-feeds", fileName: "feeds.json", content: []byte(`{"feeds":["prod"]}`)},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, tc.kind)
			publisher := writeSignedPackageWithMutator(t, dir, tc.kind, "1.0.0", tc.fileName, tc.content, func(m *Manifest) {
				addProductionEvidence(t, dir, m, requiredProductionEvidence(tc.kind))
			})
			publisher.trust(t, root)

			st, err := StatusFromDir(tc.kind, dir)
			if err != nil {
				t.Fatalf("StatusFromDir: %v", err)
			}
			if st.State != "verified" {
				t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
			}
			if !st.ContentReadiness.ProductionReady {
				t.Fatalf("production readiness not ready: %#v", st.ContentReadiness)
			}
			if st.ContentReadiness.EvidenceStatus != "passed" {
				t.Fatalf("evidence status = %q, want passed", st.ContentReadiness.EvidenceStatus)
			}
			if st.ContentReadiness.ProductionEvidenceStatus != "production-ready" {
				t.Fatalf("production evidence status = %q, want production-ready", st.ContentReadiness.ProductionEvidenceStatus)
			}
			if st.ContentReadiness.AttachedProductionEvidence != len(requiredProductionEvidence(tc.kind)) {
				t.Fatalf("attached production evidence = %d, want %d", st.ContentReadiness.AttachedProductionEvidence, len(requiredProductionEvidence(tc.kind)))
			}
			if st.ContentReadiness.ReadinessLabel != "production-ready" || !strings.Contains(st.ContentReadiness.ReadinessDetail, "production rollout") {
				t.Fatalf("readiness label/detail = %q/%q, want production-ready", st.ContentReadiness.ReadinessLabel, st.ContentReadiness.ReadinessDetail)
			}
			if len(st.ContentReadiness.Evidence) != len(requiredProductionEvidence(tc.kind)) {
				t.Fatalf("evidence count = %d, want %d", len(st.ContentReadiness.Evidence), len(requiredProductionEvidence(tc.kind)))
			}
		})
	}
}

func TestStatusesRequiresKindSpecificProductionEvidence(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "threat-id")
	publisher := writeSignedPackageWithMutator(t, dir, "threat-id", "1.0.0", "threats.json", []byte(`{"threats":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, []string{"threat-taxonomy", "license-review", "staged-rollout", "rollback-drill"})
	})
	publisher.trust(t, root)

	st, err := StatusFromDir("threat-id", dir)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("threat-id package should not be production-ready without kind-specific evidence: %#v", st.ContentReadiness)
	}
	if st.ContentReadiness.ReadinessLabel != "production-blocked" || !strings.Contains(st.ContentReadiness.ReadinessDetail, "not production-ready") {
		t.Fatalf("readiness label/detail = %q/%q, want production-blocked", st.ContentReadiness.ReadinessLabel, st.ContentReadiness.ReadinessDetail)
	}
	if st.ContentReadiness.ProductionEvidenceStatus != "production-blocked" {
		t.Fatalf("production evidence status = %q, want production-blocked", st.ContentReadiness.ProductionEvidenceStatus)
	}
	for _, want := range []string{"production evidence:pcap-regression-corpus", "production evidence:false-positive-regression"} {
		if !hasString(st.ContentReadiness.Blockers, want) {
			t.Fatalf("missing readiness blocker %q in %#v", want, st.ContentReadiness.Blockers)
		}
	}
}

func TestReadEvidenceReturnsBoundedPackageLocalJSON(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
	})
	publisher.trust(t, root)

	artifact, err := ReadEvidence(root, "app-id", "app-taxonomy")
	if err != nil {
		t.Fatalf("ReadEvidence: %v", err)
	}
	if artifact.Kind != "app-id" || artifact.PackageState != "verified" || artifact.PackageVersion != "1.0.0" {
		t.Fatalf("artifact metadata = %#v", artifact)
	}
	if artifact.ManifestSHA256 == "" {
		t.Fatal("missing manifest hash")
	}
	if artifact.Evidence.Type != "app-taxonomy" || artifact.Evidence.Artifact != "evidence/app-taxonomy.json" {
		t.Fatalf("evidence ref = %#v", artifact.Evidence)
	}
	if string(artifact.ContentJSON) != `{"type":"app-taxonomy","status":"passed"}` {
		t.Fatalf("content = %s", artifact.ContentJSON)
	}
}

func TestReadAppIDTaxonomyReturnsClassifierDefinitions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	taxonomyJSON := []byte(`{"type":"app-taxonomy","status":"passed","applications":[{"id":"corp-admin","display_name":"Corporate Admin","category":"business-app","engine_signals":["corp-admin"],"ports":[{"protocol":"tcp","ports":[{"start":8443,"end":8444}]}]}]}`)
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.2.3", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
		replaceProductionEvidenceArtifact(t, dir, m, "app-taxonomy", taxonomyJSON)
	})
	publisher.trust(t, root)

	taxonomy, err := ReadAppIDTaxonomy(root)
	if err != nil {
		t.Fatalf("ReadAppIDTaxonomy: %v", err)
	}
	if taxonomy.Kind != "app-id" || taxonomy.PackageVersion != "1.2.3" || taxonomy.ManifestSHA256 == "" {
		t.Fatalf("taxonomy metadata = %#v", taxonomy)
	}
	if len(taxonomy.Definitions) != 1 {
		t.Fatalf("definitions = %#v, want one", taxonomy.Definitions)
	}
	def := taxonomy.Definitions[0]
	if def.ID != "corp-admin" || def.Name != "Corporate Admin" || def.Category != "business-app" {
		t.Fatalf("definition identity = %#v", def)
	}
	if len(def.EngineSignals) != 1 || def.EngineSignals[0] != "corp-admin" {
		t.Fatalf("engine signals = %#v", def.EngineSignals)
	}
	if len(def.Ports) != 1 || def.Ports[0].Protocol != "tcp" || def.Ports[0].Start != 8443 || def.Ports[0].End != 8444 {
		t.Fatalf("ports = %#v", def.Ports)
	}
	if !strings.Contains(def.Source, "signed App-ID package 1.2.3@") {
		t.Fatalf("source = %q, want signed package metadata", def.Source)
	}
}

func TestReadThreatIDTaxonomyReturnsPackageMetadata(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "threat-id")
	taxonomyJSON := []byte(`{"type":"threat-taxonomy","status":"passed","package_version":"1.2.3","threats":[{"id":"ognfw-managed-exploit","name":"Managed Exploit Attempt","category":"exploit-attempt","severity":"critical","confidence":96,"signature_ids":[9000001],"evidence":["curated severity override"]}]}`)
	publisher := writeSignedPackageWithMutator(t, dir, "threat-id", "1.2.3", "threats.json", []byte(`{"threats":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("threat-id"))
		replaceProductionEvidenceArtifact(t, dir, m, "threat-taxonomy", taxonomyJSON)
	})
	publisher.trust(t, root)

	taxonomy, err := ReadThreatIDTaxonomy(root)
	if err != nil {
		t.Fatalf("ReadThreatIDTaxonomy: %v", err)
	}
	if taxonomy.Kind != "threat-id" || taxonomy.PackageVersion != "1.2.3" || taxonomy.ManifestSHA256 == "" {
		t.Fatalf("taxonomy metadata = %#v", taxonomy)
	}
	if len(taxonomy.Metadata) != 1 {
		t.Fatalf("metadata = %#v, want one", taxonomy.Metadata)
	}
	meta := taxonomy.Metadata[0]
	if meta.ID != "ognfw-managed-exploit" || meta.Name != "Managed Exploit Attempt" || meta.Category != "exploit-attempt" {
		t.Fatalf("metadata identity = %#v", meta)
	}
	if len(meta.SignatureIDs) != 1 || meta.SignatureIDs[0] != 9000001 {
		t.Fatalf("signature IDs = %#v", meta.SignatureIDs)
	}
	if meta.Confidence != 96 {
		t.Fatalf("confidence = %d, want 96", meta.Confidence)
	}
	if len(meta.Evidence) != 2 || !strings.HasPrefix(meta.Evidence[1], "signed Threat-ID package 1.2.3@") {
		t.Fatalf("evidence = %#v", meta.Evidence)
	}
}

func TestReadRegressionCorpusReturnsTypedSamples(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
	})
	publisher.trust(t, root)

	corpus, err := ReadRegressionCorpus(root, "app-id", "")
	if err != nil {
		t.Fatalf("ReadRegressionCorpus: %v", err)
	}
	if corpus.EvidenceType != "app-regression-corpus" || corpus.PackageVersion != "1.0.0" {
		t.Fatalf("corpus metadata = %#v", corpus)
	}
	if corpus.SampleCount != 1 || corpus.FailedSamples != 0 || len(corpus.Samples) != 1 {
		t.Fatalf("corpus counts = %#v", corpus)
	}
	if corpus.Samples[0].ID != "sample-1" || corpus.Samples[0].Expected != "corp-admin" || corpus.Samples[0].Observed != "corp-admin" || corpus.Samples[0].Verdict != "passed" {
		t.Fatalf("sample = %#v", corpus.Samples[0])
	}
}

func TestCompareRegressionCorpusReportsCandidateDiff(t *testing.T) {
	root := t.TempDir()
	currentDir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, currentDir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["current"]}`), func(m *Manifest) {
		addProductionEvidence(t, currentDir, m, requiredProductionEvidence("app-id"))
	})
	publisher.trust(t, root)

	previewDir := filepath.Join(t.TempDir(), "app-id-preview")
	previewContent := []byte(`{"apps":["preview"]}`)
	if err := os.MkdirAll(previewDir, 0o755); err != nil {
		t.Fatalf("mkdir preview: %v", err)
	}
	writeFile(t, filepath.Join(previewDir, "apps.json"), previewContent)
	writeSignedManifestWithMutator(t, previewDir, "app-id", "1.1.0", "apps.json", previewContent, publisher, func(m *Manifest) {
		addProductionEvidence(t, previewDir, m, requiredProductionEvidence("app-id"))
		payload := map[string]any{
			"type":            "app-regression-corpus",
			"status":          "passed",
			"package_version": "1.1.0",
			"samples": []map[string]any{
				{"id": "sample-1", "pcap_sha256": strings.Repeat("a", 64), "expected_app": "corp-admin", "observed_app": "corp-admin", "verdict": "passed"},
				{"id": "sample-2", "pcap_sha256": strings.Repeat("b", 64), "expected_app": "ssh", "observed_app": "unknown", "verdict": "failed"},
			},
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal preview corpus: %v", err)
		}
		replaceProductionEvidenceArtifact(t, previewDir, m, "app-regression-corpus", raw)
	})

	diff, err := CompareRegressionCorpus(root, "app-id", previewDir, "")
	if err != nil {
		t.Fatalf("CompareRegressionCorpus: %v", err)
	}
	if diff.Preview.PackageVersion != "1.1.0" || diff.Added != 1 || diff.Removed != 0 || diff.Changed != 0 || diff.FailedDelta != 1 {
		t.Fatalf("diff = %#v", diff)
	}
	if len(diff.SampleDiffs) != 1 || diff.SampleDiffs[0].ID != "sample-2" || diff.SampleDiffs[0].Change != "added" {
		t.Fatalf("sample diffs = %#v", diff.SampleDiffs)
	}
}

func TestReadEvidenceRejectsUnsafeRequestsAndArtifacts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
	})
	publisher.trust(t, root)

	for _, tc := range []struct {
		name         string
		kind         string
		evidenceType string
		want         error
	}{
		{name: "bad kind", kind: "unknown", evidenceType: "app-taxonomy", want: ErrInvalidKind},
		{name: "bad token", kind: "app-id", evidenceType: "../app-taxonomy", want: ErrInvalidEvidenceRequest},
		{name: "missing evidence", kind: "app-id", evidenceType: "not-attached", want: ErrEvidenceNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadEvidence(root, tc.kind, tc.evidenceType)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadEvidence error = %v, want %v", err, tc.want)
			}
		})
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, outside, []byte(`{"escaped":true}`))
	if err := os.Remove(filepath.Join(dir, "evidence", "app-taxonomy.json")); err != nil {
		t.Fatalf("remove evidence: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "evidence", "app-taxonomy.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := ReadEvidence(root, "app-id", "app-taxonomy")
	if !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("ReadEvidence symlink error = %v, want ErrInvalidPackage", err)
	}
}

func TestReadEvidenceRejectsOversizedJSON(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "intel-feeds")
	publisher := writeSignedPackageWithMutator(t, dir, "intel-feeds", "1.0.0", "feeds.json", []byte(`{"feeds":["prod"]}`), func(m *Manifest) {
		artifact := "evidence/feed-registry.json"
		raw := append([]byte(`{"payload":"`), bytes.Repeat([]byte("x"), MaxEvidenceArtifactBytes)...)
		raw = append(raw, []byte(`"}`)...)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		writeFile(t, filepath.Join(dir, artifact), raw)
		m.Files = append(m.Files, File{Path: artifact, SHA256: digest})
		m.ContentReadiness = &ContentReadiness{
			Scope:                      "production",
			ProductionContent:          true,
			RequiredProductionEvidence: requiredProductionEvidence("intel-feeds"),
			Evidence: []EvidenceRef{{
				Type:        "feed-registry",
				Artifact:    artifact,
				SHA256:      digest,
				GeneratedAt: "2026-06-17T12:03:00Z",
			}},
		}
	})
	publisher.trust(t, root)

	_, err := ReadEvidence(root, "intel-feeds", "feed-registry")
	if !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("ReadEvidence oversized error = %v, want ErrInvalidPackage", err)
	}
}

func TestStatusesRequiresProductionEvidenceDeclarationAndCanonicalArtifacts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
		m.ContentReadiness.RequiredProductionEvidence = nil
		m.ContentReadiness.Evidence[0].Artifact = "proofs/app-taxonomy.json"
	})
	publisher.trust(t, root)

	st, err := StatusFromDir("app-id", dir)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("package should not be production-ready with weak evidence declaration: %#v", st.ContentReadiness)
	}
	for _, want := range []string{"production evidence declaration", "production evidence artifact"} {
		if !hasString(st.ContentReadiness.Blockers, want) {
			t.Fatalf("missing readiness blocker %q in %#v", want, st.ContentReadiness.Blockers)
		}
	}
}

func TestStatusesRequiresProductionEvidenceArtifactsToBeJSON(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "intel-feeds")
	publisher := writeSignedPackageWithMutator(t, dir, "intel-feeds", "1.0.0", "feeds.json", []byte(`{"feeds":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("intel-feeds"))
		artifact := "evidence/feed-registry.json"
		raw := []byte("not-json")
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		writeFile(t, filepath.Join(dir, artifact), raw)
		for i := range m.Files {
			if m.Files[i].Path == artifact {
				m.Files[i].SHA256 = digest
			}
		}
		for i := range m.ContentReadiness.Evidence {
			if m.ContentReadiness.Evidence[i].Artifact == artifact {
				m.ContentReadiness.Evidence[i].SHA256 = digest
			}
		}
	})
	publisher.trust(t, root)

	st, err := StatusFromDir("intel-feeds", dir)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("package should not be production-ready with non-JSON evidence: %#v", st.ContentReadiness)
	}
	if !hasString(st.ContentReadiness.Blockers, "production evidence format") {
		t.Fatalf("missing production evidence format blocker in %#v", st.ContentReadiness.Blockers)
	}
}

func TestStatusesRequiresProductionEvidenceArtifactSemantics(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "intel-feeds")
	publisher := writeSignedPackageWithMutator(t, dir, "intel-feeds", "1.0.0", "feeds.json", []byte(`{"feeds":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("intel-feeds"))
		replaceProductionEvidenceArtifact(t, dir, m, "parser-tests", []byte(`{"type":"feed-registry","status":"failed"}`))
	})
	publisher.trust(t, root)

	st, err := StatusFromDir("intel-feeds", dir)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("package should not be production-ready with mismatched/failed evidence: %#v", st.ContentReadiness)
	}
	for _, want := range []string{"production evidence type:parser-tests", "production evidence verdict:parser-tests"} {
		if !hasString(st.ContentReadiness.Blockers, want) {
			t.Fatalf("missing production evidence blocker %q in %#v", want, st.ContentReadiness.Blockers)
		}
	}
}

func TestStatusesRequiresAppRegressionCorpusSemantics(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackageWithMutator(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["prod"]}`), func(m *Manifest) {
		addProductionEvidence(t, dir, m, requiredProductionEvidence("app-id"))
		payload := map[string]any{
			"type":            "app-regression-corpus",
			"status":          "passed",
			"package_version": "2.0.0",
			"samples": []map[string]any{{
				"pcap_sha256":  "not-a-sha",
				"expected_app": "",
				"observed_app": "corp-admin",
				"verdict":      "failed",
			}},
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal regression corpus: %v", err)
		}
		replaceProductionEvidenceArtifact(t, dir, m, "app-regression-corpus", raw)
	})
	publisher.trust(t, root)

	st, err := StatusFromDir("app-id", dir)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.State != "verified" {
		t.Fatalf("state = %q, want verified blockers=%#v", st.State, st.Blockers)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("package should not be production-ready with weak App-ID corpus evidence: %#v", st.ContentReadiness)
	}
	for _, want := range []string{
		"production evidence package version mismatch:app-regression-corpus",
		"production evidence sample hash:app-regression-corpus",
		"production evidence sample app:app-regression-corpus",
		"production evidence sample verdict:app-regression-corpus",
	} {
		if !hasString(st.ContentReadiness.Blockers, want) {
			t.Fatalf("missing App-ID corpus blocker %q in %#v", want, st.ContentReadiness.Blockers)
		}
	}
}

func TestStatusesRejectsSelfSignedPackageWithoutTrustedPublisher(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	writeSignedPackage(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["self-signed"]}`))

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State == "verified" {
		t.Fatalf("self-signed package should not verify without a trusted publisher key: %#v", app)
	}
	if app.SignatureStatus != "untrusted" {
		t.Fatalf("signature status = %q, want untrusted", app.SignatureStatus)
	}
	if !hasString(app.Blockers, "trusted publisher") {
		t.Fatalf("missing trusted publisher blocker in %#v", app.Blockers)
	}
}

func TestStatusesRejectsUnsafeOrMismatchedPackageFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "threat-id")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Kind:          "threat-id",
		Name:          "Threat package",
		Version:       "1.0.0",
		Source:        "Phragma content release pipeline",
		Files: []File{{
			Path:   "../outside.rules",
			SHA256: "bad",
		}},
		Signature:  &Signature{Algorithm: "ed25519", PublicKey: "bad", Signature: "bad"},
		Regression: &Regression{Status: "passed", Corpus: "pcap-regression", Passed: 1, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &Rollout{State: "canary"},
		Rollback:   &Rollback{Available: true},
		Provenance: []Provenance{{
			Name:                 "Phragma lab",
			URL:                  "https://example.test/content",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtr(true),
			AllowsRedistribution: boolPtr(true),
		}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), raw)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	threat := statuses[1]
	if threat.State != "invalid" {
		t.Fatalf("state = %q, want invalid blockers=%#v", threat.State, threat.Blockers)
	}
	if !hasString(threat.Blockers, "file path") {
		t.Fatalf("missing file path blocker in %#v", threat.Blockers)
	}
	if !hasString(threat.Blockers, "signed manifest") {
		t.Fatalf("missing signed manifest blocker in %#v", threat.Blockers)
	}
}

func TestStatusesRejectsReservedPackageFilePaths(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackage(t, dir, "app-id", "1.0.0", ".rollback/poison.json", []byte(`{"poison":true}`))
	publisher.trust(t, root)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "invalid" {
		t.Fatalf("state = %q, want invalid blockers=%#v", app.State, app.Blockers)
	}
	if !hasString(app.Blockers, "file path") {
		t.Fatalf("missing file path blocker in %#v", app.Blockers)
	}
	if _, err := os.Stat(filepath.Join(root, "app-id", ".rollback", "poison.json")); err != nil {
		t.Fatalf("reserved source fixture missing: %v", err)
	}
}

func TestStatusesRejectsSymlinkedManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	outside := t.TempDir()
	content := []byte(`{"apps":["outside-manifest"]}`)
	publisher := writeSignedPackage(t, outside, "app-id", "1.0.0", "apps.json", content)
	publisher.trust(t, root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "manifest.json"), filepath.Join(dir, "manifest.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	writeFile(t, filepath.Join(dir, "apps.json"), content)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "invalid" {
		t.Fatalf("state = %q, want invalid blockers=%#v", app.State, app.Blockers)
	}
	if !hasString(app.Blockers, "manifest path") {
		t.Fatalf("missing manifest path blocker in %#v", app.Blockers)
	}
}

func TestStatusesRejectsMismatchedSignaturePublicKey(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	publisher := writeSignedPackage(t, dir, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["trusted-signer"]}`))
	publisher.trust(t, root)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	manifest.Signature.PublicKey = base64.StdEncoding.EncodeToString(otherPub)
	raw, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), raw)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "invalid" {
		t.Fatalf("state = %q, want invalid blockers=%#v", app.State, app.Blockers)
	}
	if app.SignatureStatus != "invalid" {
		t.Fatalf("signature status = %q, want invalid", app.SignatureStatus)
	}
	if !hasString(app.Blockers, "signature invalid") {
		t.Fatalf("missing signature invalid blocker in %#v", app.Blockers)
	}
}

func TestStatusesRejectsIntermediateSymlinkPackageFilePath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app-id")
	outside := t.TempDir()
	content := []byte(`{"apps":["outside"]}`)
	writeFile(t, filepath.Join(outside, "apps.json"), content)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "payload")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	publisher := newTestPublisher(t, "test-key")
	writeSignedManifest(t, dir, "app-id", "1.0.0", "payload/apps.json", content, publisher)
	publisher.trust(t, root)

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	app := statuses[0]
	if app.State != "invalid" {
		t.Fatalf("state = %q, want invalid blockers=%#v", app.State, app.Blockers)
	}
	if !hasString(app.Blockers, "file path") {
		t.Fatalf("missing file path blocker in %#v", app.Blockers)
	}
}

func TestInstallVerifiedPackagePromotesIntoStore(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(t.TempDir(), "app-v1")
	publisher := writeSignedPackage(t, src, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["corp-admin"]}`))
	publisher.trust(t, root)

	result, err := Install(root, "app-id", src)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.Status.State != "verified" {
		t.Fatalf("installed state = %q blockers=%#v", result.Status.State, result.Status.Blockers)
	}
	if result.Status.Version != "1.0.0" {
		t.Fatalf("installed version = %q", result.Status.Version)
	}
	if result.RollbackCreated {
		t.Fatal("first install should not create a rollback backup")
	}
	if result.Status.RollbackAvailable {
		t.Fatal("first install should not report operational rollback availability")
	}
	raw, err := os.ReadFile(filepath.Join(root, "app-id", "apps.json"))
	if err != nil {
		t.Fatalf("read installed file: %v", err)
	}
	if string(raw) != `{"apps":["corp-admin"]}` {
		t.Fatalf("installed file = %s", raw)
	}
}

func TestInstallRejectsIntermediateSymlinkPackageFilePath(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(t.TempDir(), "app-symlink")
	outside := t.TempDir()
	content := []byte(`{"apps":["outside"]}`)
	writeFile(t, filepath.Join(outside, "apps.json"), content)
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "payload")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	publisher := newTestPublisher(t, "test-key")
	writeSignedManifest(t, src, "app-id", "1.0.0", "payload/apps.json", content, publisher)
	publisher.trust(t, root)

	_, err := Install(root, "app-id", src)
	if !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("Install error = %v, want ErrInvalidPackage", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "app-id", "payload", "apps.json")); !os.IsNotExist(statErr) {
		t.Fatalf("escaped package file was promoted, stat err = %v", statErr)
	}
}

func TestInstallRejectsSymlinkedManifestWithoutPromoting(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(t.TempDir(), "app-symlink-manifest")
	outside := t.TempDir()
	content := []byte(`{"apps":["outside-manifest"]}`)
	publisher := writeSignedPackage(t, outside, "app-id", "1.0.0", "apps.json", content)
	publisher.trust(t, root)
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "manifest.json"), filepath.Join(src, "manifest.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	writeFile(t, filepath.Join(src, "apps.json"), content)

	_, err := Install(root, "app-id", src)
	if !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("Install error = %v, want ErrInvalidPackage", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "app-id", "manifest.json")); !os.IsNotExist(statErr) {
		t.Fatalf("symlinked manifest package was promoted, stat err = %v", statErr)
	}
}

func TestInstallCreatesBackupAndRollbackRestoresPreviousPackage(t *testing.T) {
	root := t.TempDir()
	srcV1 := filepath.Join(t.TempDir(), "app-v1")
	srcV2 := filepath.Join(t.TempDir(), "app-v2")
	publisher := writeSignedPackage(t, srcV1, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, srcV2, "app-id", "2.0.0", "apps.json", []byte(`{"apps":["v2"]}`))
	publisher.trust(t, root)

	if _, err := Install(root, "app-id", srcV1); err != nil {
		t.Fatalf("Install v1: %v", err)
	}
	result, err := Install(root, "app-id", srcV2)
	if err != nil {
		t.Fatalf("Install v2: %v", err)
	}
	if !result.RollbackCreated {
		t.Fatal("second install should create a rollback backup")
	}
	if !result.Status.RollbackAvailable {
		t.Fatal("second install should report a verified rollback backup")
	}
	if _, err := os.Stat(filepath.Join(result.RollbackPath, "manifest.json")); err != nil {
		t.Fatalf("rollback manifest missing: %v", err)
	}

	rolledBack, err := RollbackPackage(root, "app-id")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolledBack.Status.Version != "1.0.0" {
		t.Fatalf("rollback version = %q, want 1.0.0", rolledBack.Status.Version)
	}
	if !rolledBack.Status.RollbackAvailable {
		t.Fatal("rollback should leave a verified local backup available")
	}
	if !rolledBack.RollbackCreated {
		t.Fatal("rollback should back up the current package before restoring")
	}
	if rolledBack.RestoredRollbackPath != result.RollbackPath {
		t.Fatalf("restored rollback path = %q, want selected backup %q", rolledBack.RestoredRollbackPath, result.RollbackPath)
	}
	if rolledBack.RollbackPath == "" || rolledBack.RollbackPath == rolledBack.RestoredRollbackPath {
		t.Fatalf("rollback created path = %q restored path = %q, want distinct paths", rolledBack.RollbackPath, rolledBack.RestoredRollbackPath)
	}
	raw, err := os.ReadFile(filepath.Join(root, "app-id", "apps.json"))
	if err != nil {
		t.Fatalf("read rolled back file: %v", err)
	}
	if string(raw) != `{"apps":["v1"]}` {
		t.Fatalf("rolled back file = %s", raw)
	}
}

func TestCorruptRollbackBackupIsNotAdvertisedOrSelected(t *testing.T) {
	root := t.TempDir()
	srcV1 := filepath.Join(t.TempDir(), "app-v1")
	srcV2 := filepath.Join(t.TempDir(), "app-v2")
	publisher := writeSignedPackage(t, srcV1, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, srcV2, "app-id", "2.0.0", "apps.json", []byte(`{"apps":["v2"]}`))
	publisher.trust(t, root)

	if _, err := Install(root, "app-id", srcV1); err != nil {
		t.Fatalf("Install v1: %v", err)
	}
	result, err := Install(root, "app-id", srcV2)
	if err != nil {
		t.Fatalf("Install v2: %v", err)
	}
	if !result.Status.RollbackAvailable {
		t.Fatal("verified backup should be advertised before tampering")
	}
	writeFile(t, filepath.Join(result.RollbackPath, "apps.json"), []byte(`{"apps":["tampered"]}`))

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if statuses[0].RollbackAvailable {
		t.Fatal("corrupt backup must not be advertised as rollback available")
	}
	_, err = RollbackPackage(root, "app-id")
	if !errors.Is(err, ErrNoRollback) {
		t.Fatalf("Rollback error = %v, want ErrNoRollback for corrupt-only backup", err)
	}
}

func TestInstallRejectsUnverifiedPackageWithoutReplacingCurrent(t *testing.T) {
	root := t.TempDir()
	srcV1 := filepath.Join(t.TempDir(), "app-v1")
	srcBad := filepath.Join(t.TempDir(), "app-bad")
	publisher := writeSignedPackage(t, srcV1, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, srcBad, "app-id", "2.0.0", "apps.json", []byte(`{"apps":["v2"]}`))
	publisher.trust(t, root)
	writeFile(t, filepath.Join(srcBad, "apps.json"), []byte(`{"apps":["tampered"]}`))

	if _, err := Install(root, "app-id", srcV1); err != nil {
		t.Fatalf("Install v1: %v", err)
	}
	_, err := Install(root, "app-id", srcBad)
	if !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("Install bad error = %v, want ErrInvalidPackage", err)
	}
	st, err := StatusFromDir("app-id", filepath.Join(root, "app-id"))
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.Version != "1.0.0" || st.State != "verified" {
		t.Fatalf("current package = version %q state %q", st.Version, st.State)
	}
	raw, err := os.ReadFile(filepath.Join(root, "app-id", "apps.json"))
	if err != nil {
		t.Fatalf("read current file: %v", err)
	}
	if string(raw) != `{"apps":["v1"]}` {
		t.Fatalf("current file = %s", raw)
	}
}

func TestInstallRestoresCurrentPackageWhenActivationRenameFails(t *testing.T) {
	root := t.TempDir()
	srcV1 := filepath.Join(t.TempDir(), "app-v1")
	srcV2 := filepath.Join(t.TempDir(), "app-v2")
	publisher := writeSignedPackage(t, srcV1, "app-id", "1.0.0", "apps.json", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, srcV2, "app-id", "2.0.0", "apps.json", []byte(`{"apps":["v2"]}`))
	publisher.trust(t, root)

	if _, err := Install(root, "app-id", srcV1); err != nil {
		t.Fatalf("Install v1: %v", err)
	}
	realRename := renamePackageDir
	t.Cleanup(func() { renamePackageDir = realRename })
	target := filepath.Clean(filepath.Join(root, "app-id"))
	stagingRoot := filepath.Clean(filepath.Join(root, ".staging"))
	failedActivation := false
	renamePackageDir = func(src, dst string) error {
		src = filepath.Clean(src)
		dst = filepath.Clean(dst)
		if !failedActivation && dst == target && strings.HasPrefix(src, stagingRoot+string(filepath.Separator)) {
			failedActivation = true
			return errors.New("injected activation failure")
		}
		return realRename(src, dst)
	}

	_, err := Install(root, "app-id", srcV2)
	if err == nil || !strings.Contains(err.Error(), "injected activation failure") {
		t.Fatalf("Install v2 error = %v, want injected activation failure", err)
	}
	st, err := StatusFromDir("app-id", target)
	if err != nil {
		t.Fatalf("StatusFromDir: %v", err)
	}
	if st.Version != "1.0.0" || st.State != "verified" {
		t.Fatalf("current package = version %q state %q blockers=%#v", st.Version, st.State, st.Blockers)
	}
	raw, err := os.ReadFile(filepath.Join(target, "apps.json"))
	if err != nil {
		t.Fatalf("read current file: %v", err)
	}
	if string(raw) != `{"apps":["v1"]}` {
		t.Fatalf("current file = %s", raw)
	}
}

func TestRollbackRequiresAvailableBackup(t *testing.T) {
	_, err := RollbackPackage(t.TempDir(), "app-id")
	if !errors.Is(err, ErrNoRollback) {
		t.Fatalf("Rollback error = %v, want ErrNoRollback", err)
	}
}

type testPublisher struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func newTestPublisher(t *testing.T, keyID string) testPublisher {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testPublisher{
		keyID: keyID,
		priv:  priv,
		pub:   priv.Public().(ed25519.PublicKey),
	}
}

//nolint:unparam // The kind parameter documents package-kind intent in each fixture.
func writeSignedPackage(t *testing.T, dir, kind, version, fileName string, content []byte) testPublisher {
	t.Helper()
	publisher := newTestPublisher(t, "test-key")
	publisher.writePackage(t, dir, kind, version, fileName, content)
	return publisher
}

func writeSignedPackageWithMutator(t *testing.T, dir, kind, version, fileName string, content []byte, mutate func(*Manifest)) testPublisher {
	t.Helper()
	publisher := newTestPublisher(t, "test-key")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	writeFile(t, filepath.Join(dir, fileName), content)
	writeSignedManifestWithMutator(t, dir, kind, version, fileName, content, publisher, mutate)
	return publisher
}

func (p testPublisher) trust(t *testing.T, root string) {
	t.Helper()
	writeTrustedPublisherKey(t, root, p.keyID, p.pub)
}

func (p testPublisher) writePackage(t *testing.T, dir, kind, version, fileName string, content []byte) {
	t.Helper()
	writeSignedPackageWithPrivateKey(t, dir, kind, version, fileName, content, p.keyID, p.priv)
}

func writeSignedPackageWithPrivateKey(t *testing.T, dir, kind, version, fileName string, content []byte, keyID string, priv ed25519.PrivateKey) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	writeFile(t, filepath.Join(dir, fileName), content)
	writeSignedManifest(t, dir, kind, version, fileName, content, testPublisher{keyID: keyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)})
}

func writeSignedManifest(t *testing.T, dir, kind, version, fileName string, content []byte, publisher testPublisher) {
	t.Helper()
	writeSignedManifestWithMutator(t, dir, kind, version, fileName, content, publisher, nil)
}

func writeSignedManifestWithMutator(t *testing.T, dir, kind, version, fileName string, content []byte, publisher testPublisher, mutate func(*Manifest)) {
	t.Helper()
	sum := sha256.Sum256(content)
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Kind:          kind,
		Name:          "Phragma " + kind + " test package",
		Version:       version,
		Source:        "Phragma content release pipeline",
		CreatedAt:     "2026-06-17T12:00:00Z",
		InstalledAt:   "2026-06-17T12:05:00Z",
		Files: []File{{
			Path:   fileName,
			SHA256: hex.EncodeToString(sum[:]),
		}},
		Regression: &Regression{Status: "passed", Corpus: "test corpus", Passed: 1, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &Rollout{State: "stable", Scope: "all"},
		Rollback:   &Rollback{Available: true},
		Provenance: []Provenance{{
			Name:                 "Phragma test",
			URL:                  "https://example.test/content",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtr(true),
			AllowsRedistribution: boolPtr(true),
		}},
		ContentReadiness: &ContentReadiness{
			Scope:                      "demo-only",
			ProductionContent:          false,
			RequiredProductionEvidence: requiredProductionEvidence(kind),
		},
	}
	if mutate != nil {
		mutate(&manifest)
	}
	payload, err := SignaturePayloadForTest(manifest)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	manifest.Signature = &Signature{
		Algorithm: "ed25519",
		KeyID:     publisher.keyID,
		PublicKey: base64.StdEncoding.EncodeToString(publisher.pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(publisher.priv, payload)),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), raw)
}

func addProductionEvidence(t *testing.T, dir string, manifest *Manifest, evidenceTypes []string) {
	t.Helper()
	manifest.ContentReadiness = &ContentReadiness{
		Scope:                      "production",
		ProductionContent:          true,
		RequiredProductionEvidence: requiredProductionEvidence(manifest.Kind),
	}
	for _, evidenceType := range evidenceTypes {
		artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
		raw := productionEvidencePayloadForTest(t, manifest.Kind, evidenceType, manifest.Version)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		writeFile(t, filepath.Join(dir, artifact), raw)
		manifest.Files = append(manifest.Files, File{
			Path:   artifact,
			SHA256: digest,
		})
		manifest.ContentReadiness.Evidence = append(manifest.ContentReadiness.Evidence, EvidenceRef{
			Type:        evidenceType,
			Artifact:    artifact,
			SHA256:      digest,
			GeneratedAt: "2026-06-17T12:03:00Z",
		})
	}
}

func productionEvidencePayloadForTest(t *testing.T, kind, evidenceType, version string) []byte {
	t.Helper()
	if kind != "app-id" || evidenceType != "app-regression-corpus" {
		return []byte(`{"type":"` + evidenceType + `","status":"passed"}`)
	}
	payload := map[string]any{
		"type":   evidenceType,
		"status": "passed",
	}
	payload["package_version"] = version
	payload["samples"] = []map[string]any{{
		"pcap_sha256":  strings.Repeat("a", 64),
		"expected_app": "corp-admin",
		"observed_app": "corp-admin",
		"verdict":      "passed",
	}}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal evidence payload: %v", err)
	}
	return raw
}

func replaceProductionEvidenceArtifact(t *testing.T, dir string, manifest *Manifest, evidenceType string, raw []byte) {
	t.Helper()
	artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	writeFile(t, filepath.Join(dir, artifact), raw)

	replacedFile := false
	for i := range manifest.Files {
		if manifest.Files[i].Path == artifact {
			manifest.Files[i].SHA256 = digest
			replacedFile = true
		}
	}
	if !replacedFile {
		t.Fatalf("manifest file %q not found", artifact)
	}
	if manifest.ContentReadiness == nil {
		t.Fatal("manifest content readiness missing")
	}
	replacedEvidence := false
	for i := range manifest.ContentReadiness.Evidence {
		if manifest.ContentReadiness.Evidence[i].Type == evidenceType {
			manifest.ContentReadiness.Evidence[i].SHA256 = digest
			replacedEvidence = true
		}
	}
	if !replacedEvidence {
		t.Fatalf("manifest evidence %q not found", evidenceType)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func writeTrustedPublisherKey(t *testing.T, root, keyID string, pub ed25519.PublicKey) {
	t.Helper()
	dir := filepath.Join(root, trustedKeyringDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir trusted keyring: %v", err)
	}
	writeFile(t, filepath.Join(dir, keyID+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)))
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

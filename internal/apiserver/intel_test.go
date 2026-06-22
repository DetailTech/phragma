package apiserver

import (
	"context"
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

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestIntelListContentPackagesReportsLocalOnlyDefaults(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	srv := &IntelServer{Store: st, ContentDir: filepath.Join(t.TempDir(), "content")}
	resp, err := srv.ListContentPackages(context.Background(), &openngfwv1.ListContentPackagesRequest{})
	if err != nil {
		t.Fatalf("ListContentPackages: %v", err)
	}
	if got, want := len(resp.GetPackages()), 3; got != want {
		t.Fatalf("package count = %d, want %d", got, want)
	}
	app := resp.GetPackages()[0]
	if app.GetKind() != "app-id" || app.GetState() != "local-only" {
		t.Fatalf("app package = %#v", app)
	}
	if app.GetManifestPath() != "" {
		t.Fatalf("viewer package status leaked manifest_path %q", app.GetManifestPath())
	}
	for _, want := range []string{"signed manifest", "package version/hash", "regression result", "staged rollout", "package rollback"} {
		if !hasProtoString(app.GetBlockers(), want) {
			t.Fatalf("missing blocker %q in %#v", want, app.GetBlockers())
		}
	}
	readiness := app.GetContentReadiness()
	if readiness == nil {
		t.Fatal("missing content readiness")
	}
	if readiness.GetEvidenceStatus() != "missing" || readiness.GetProductionReady() {
		t.Fatalf("readiness = %#v, want missing/not-ready", readiness)
	}
	if readiness.GetReadinessLabel() != "missing-readiness" || !strings.Contains(readiness.GetReadinessDetail(), "No signed content readiness") {
		t.Fatalf("readiness label/detail = %q/%q, want explicit missing readiness", readiness.GetReadinessLabel(), readiness.GetReadinessDetail())
	}
	for _, want := range []string{"app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"} {
		if !hasProtoString(readiness.GetRequiredProductionEvidence(), want) {
			t.Fatalf("missing required evidence %q in %#v", want, readiness.GetRequiredProductionEvidence())
		}
	}
	if !hasProtoString(readiness.GetBlockers(), "content readiness declaration") {
		t.Fatalf("missing readiness blocker in %#v", readiness.GetBlockers())
	}
}

func TestContentPackageInfoMapsContentReadiness(t *testing.T) {
	info := contentPackageInfo(contentpkg.Status{
		Kind:  "app-id",
		Name:  "Phragma App-ID catalog",
		State: "verified",
		ContentReadiness: contentpkg.ContentReadinessStatus{
			Scope:                      "production",
			ProductionContent:          true,
			ProductionReady:            true,
			EvidenceStatus:             "passed",
			ReadinessLabel:             "production-ready",
			ReadinessDetail:            "Signed production content evidence passed; this package is eligible for reviewed production rollout.",
			RequiredProductionEvidence: []string{"app-taxonomy", "license-review"},
			Evidence: []contentpkg.EvidenceRef{{
				Type:        "app-taxonomy",
				Artifact:    "evidence/app-taxonomy.json",
				SHA256:      strings.Repeat("a", 64),
				GeneratedAt: "2026-06-17T12:00:00Z",
			}},
		},
	})
	readiness := info.GetContentReadiness()
	if readiness == nil {
		t.Fatal("missing content readiness")
	}
	if readiness.GetScope() != "production" || !readiness.GetProductionContent() || !readiness.GetProductionReady() || readiness.GetEvidenceStatus() != "passed" {
		t.Fatalf("readiness mapped incorrectly: %#v", readiness)
	}
	if readiness.GetReadinessLabel() != "production-ready" || !strings.Contains(readiness.GetReadinessDetail(), "production rollout") {
		t.Fatalf("readiness label/detail mapped incorrectly: %#v", readiness)
	}
	if got := readiness.GetEvidence()[0]; got.GetType() != "app-taxonomy" || got.GetArtifact() != "evidence/app-taxonomy.json" || got.GetGeneratedAt() == "" {
		t.Fatalf("evidence mapped incorrectly: %#v", got)
	}
	if !hasProtoString(readiness.GetRequiredProductionEvidence(), "license-review") {
		t.Fatalf("required evidence missing: %#v", readiness.GetRequiredProductionEvidence())
	}
}

func TestIntelListContentPackagesReportsProductionReadiness(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writeProductionPackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", []byte(`{"apps":["prod"]}`))

	resp, err := (&IntelServer{Store: st, ContentDir: contentDir}).ListContentPackages(context.Background(), &openngfwv1.ListContentPackagesRequest{})
	if err != nil {
		t.Fatalf("ListContentPackages: %v", err)
	}
	app := resp.GetPackages()[0]
	if app.GetKind() != "app-id" || app.GetState() != "verified" {
		t.Fatalf("app package = %#v", app)
	}
	readiness := app.GetContentReadiness()
	if readiness.GetScope() != "production" || !readiness.GetProductionContent() || !readiness.GetProductionReady() {
		t.Fatalf("readiness = %#v, want production ready", readiness)
	}
	if readiness.GetEvidenceStatus() != "passed" {
		t.Fatalf("evidence status = %q, want passed", readiness.GetEvidenceStatus())
	}
	if readiness.GetReadinessLabel() != "production-ready" || !strings.Contains(readiness.GetReadinessDetail(), "production rollout") {
		t.Fatalf("readiness label/detail = %q/%q, want production-ready", readiness.GetReadinessLabel(), readiness.GetReadinessDetail())
	}
	if got, want := len(readiness.GetEvidence()), 6; got != want {
		t.Fatalf("evidence count = %d, want %d: %#v", got, want, readiness.GetEvidence())
	}
	if len(readiness.GetBlockers()) != 0 {
		t.Fatalf("unexpected readiness blockers: %#v", readiness.GetBlockers())
	}
	if !hasProtoString(readiness.GetRequiredProductionEvidence(), "app-regression-corpus") {
		t.Fatalf("required evidence missing: %#v", readiness.GetRequiredProductionEvidence())
	}
}

func TestIntelGetContentEvidenceReturnsBoundedJSONArtifact(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writeProductionPackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", []byte(`{"apps":["prod"]}`))

	resp, err := (&IntelServer{Store: st, ContentDir: contentDir}).GetContentEvidence(context.Background(), &openngfwv1.GetContentEvidenceRequest{
		Kind:         "app-id",
		EvidenceType: "app-taxonomy",
	})
	if err != nil {
		t.Fatalf("GetContentEvidence: %v", err)
	}
	if resp.GetKind() != "app-id" || resp.GetPackageState() != "verified" || resp.GetPackageVersion() != "1.0.0" {
		t.Fatalf("response metadata = %#v", resp)
	}
	if resp.GetManifestSha256() == "" {
		t.Fatal("missing manifest hash")
	}
	if resp.GetEvidence().GetArtifact() != "evidence/app-taxonomy.json" || strings.Contains(resp.GetEvidence().GetArtifact(), contentDir) {
		t.Fatalf("evidence artifact path leaked or wrong: %#v", resp.GetEvidence())
	}
	if resp.GetContentJson() != `{"type":"app-taxonomy","status":"passed"}` {
		t.Fatalf("content_json = %q", resp.GetContentJson())
	}
	if resp.GetBytes() != uint32(len(resp.GetContentJson())) {
		t.Fatalf("bytes = %d, want %d", resp.GetBytes(), len(resp.GetContentJson()))
	}
}

func TestIntelGetContentCorpusReturnsTypedRows(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writeProductionPackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", []byte(`{"apps":["prod"]}`))

	resp, err := (&IntelServer{Store: st, ContentDir: contentDir}).GetContentCorpus(context.Background(), &openngfwv1.GetContentCorpusRequest{
		Kind:  "app-id",
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("GetContentCorpus: %v", err)
	}
	if resp.GetKind() != "app-id" || resp.GetEvidenceType() != "app-regression-corpus" || resp.GetPackageVersion() != "1.0.0" {
		t.Fatalf("corpus metadata = %#v", resp)
	}
	if resp.GetSampleCount() != 1 || resp.GetFailedSamples() != 0 || len(resp.GetSamples()) != 1 {
		t.Fatalf("corpus counts = %#v", resp)
	}
	if got := resp.GetSamples()[0]; got.GetExpected() != "corp-admin" || got.GetObserved() != "corp-admin" || got.GetVerdict() != "passed" {
		t.Fatalf("sample = %#v", got)
	}
}

func TestIntelCompareContentPackageReturnsCorpusDiff(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	sourceDir := filepath.Join(importDir, "app-preview")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writeProductionPackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", []byte(`{"apps":["prod"]}`))
	publisher.writePackageWithMutator(t, sourceDir, "app-id", "1.1.0", []byte(`{"apps":["preview"]}`), func(m *contentpkg.Manifest) {
		addAPIProductionEvidenceForTest(t, sourceDir, m, "app-id", "1.1.0")
		replaceAPIProductionEvidenceForTest(t, sourceDir, m, "app-regression-corpus", []byte(`{"type":"app-regression-corpus","status":"passed","package_version":"1.1.0","samples":[{"id":"sample-1","pcap_sha256":"`+strings.Repeat("a", 64)+`","expected_app":"corp-admin","observed_app":"corp-admin","verdict":"passed"},{"id":"sample-2","pcap_sha256":"`+strings.Repeat("b", 64)+`","expected_app":"ssh","observed_app":"unknown","verdict":"failed"}]}`))
	})
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}

	resp, err := srv.CompareContentPackage(context.Background(), &openngfwv1.CompareContentPackageRequest{
		Kind:       "app-id",
		SourcePath: "app-preview",
	})
	if err != nil {
		t.Fatalf("CompareContentPackage: %v", err)
	}
	if resp.GetCurrentPackage().GetVersion() != "1.0.0" || resp.GetPreviewPackage().GetVersion() != "1.1.0" {
		t.Fatalf("package comparison = %#v", resp)
	}
	diff := resp.GetCorpusDiff()
	if diff.GetEvidenceType() != "app-regression-corpus" || diff.GetAdded() != 1 || diff.GetFailedDelta() != 1 {
		t.Fatalf("corpus diff = %#v", diff)
	}
	if len(diff.GetSampleDiffs()) != 1 || diff.GetSampleDiffs()[0].GetId() != "sample-2" {
		t.Fatalf("sample diffs = %#v", diff.GetSampleDiffs())
	}
}

func TestIntelGetContentEvidenceUsesStableErrors(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writeProductionPackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", []byte(`{"apps":["prod"]}`))
	srv := &IntelServer{Store: st, ContentDir: contentDir}

	for _, tc := range []struct {
		name         string
		kind         string
		evidenceType string
		want         codes.Code
	}{
		{name: "invalid kind", kind: "unknown", evidenceType: "app-taxonomy", want: codes.InvalidArgument},
		{name: "invalid evidence token", kind: "app-id", evidenceType: "../app-taxonomy", want: codes.InvalidArgument},
		{name: "missing evidence", kind: "app-id", evidenceType: "missing", want: codes.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.GetContentEvidence(context.Background(), &openngfwv1.GetContentEvidenceRequest{
				Kind:         tc.kind,
				EvidenceType: tc.evidenceType,
			})
			if grpcstatus.Code(err) != tc.want {
				t.Fatalf("code = %v, want %v err=%v", grpcstatus.Code(err), tc.want, err)
			}
		})
	}

	if err := os.WriteFile(filepath.Join(contentDir, "app-id", "evidence", "app-taxonomy.json"), []byte(`{"type":"tampered"}`), 0o644); err != nil {
		t.Fatalf("tamper evidence: %v", err)
	}
	_, err := srv.GetContentEvidence(context.Background(), &openngfwv1.GetContentEvidenceRequest{
		Kind:         "app-id",
		EvidenceType: "app-taxonomy",
	})
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("tampered code = %v, want FailedPrecondition err=%v", grpcstatus.Code(err), err)
	}
}

func TestIntelPreviewContentPackageVerifiesImportSourceWithoutMutation(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	sourceDir := filepath.Join(importDir, "app-preview")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, sourceDir, "app-id", "2.1.0", []byte(`{"apps":["preview"]}`))
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}

	resp, err := srv.PreviewContentPackage(context.Background(), &openngfwv1.PreviewContentPackageRequest{
		Kind:       "app-id",
		SourcePath: "app-preview",
	})
	if err != nil {
		t.Fatalf("PreviewContentPackage: %v", err)
	}
	pkg := resp.GetPackage()
	if pkg.GetKind() != "app-id" || pkg.GetState() != "verified" || pkg.GetVersion() != "2.1.0" {
		t.Fatalf("preview package = %#v, want verified app-id 2.1.0", pkg)
	}
	if pkg.GetManifestPath() != "" || strings.Contains(resp.GetDetail(), sourceDir) || strings.Contains(resp.GetDetail(), importDir) {
		t.Fatalf("preview leaked server-local path: package=%#v detail=%q", pkg, resp.GetDetail())
	}
	if _, err := os.Stat(filepath.Join(contentDir, "app-id", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("preview mutated installed package content: %v", err)
	}
	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("preview wrote audit entries: %#v", entries)
	}
}

func TestIntelPreviewContentPackageReportsSourceBlockers(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	sourceDir := filepath.Join(importDir, "app-incomplete")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "manifest.json"), []byte(`{"schema_version":"phragma.content.package.v1","kind":"app-id","name":"Preview App-ID"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}

	resp, err := srv.PreviewContentPackage(context.Background(), &openngfwv1.PreviewContentPackageRequest{
		Kind:       "app-id",
		SourcePath: sourceDir,
	})
	if err != nil {
		t.Fatalf("PreviewContentPackage incomplete: %v", err)
	}
	pkg := resp.GetPackage()
	if pkg.GetState() != "incomplete" || !hasProtoString(pkg.GetBlockers(), "semantic version") || !hasProtoString(pkg.GetBlockers(), "signed manifest") {
		t.Fatalf("preview package = %#v, want incomplete blockers", pkg)
	}
	if pkg.GetManifestPath() != "" {
		t.Fatalf("preview leaked manifest path %q", pkg.GetManifestPath())
	}
}

func TestIntelPreviewContentPackageRejectsUnsafeSource(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	outsideDir := filepath.Join(t.TempDir(), "outside-package")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, outsideDir, "app-id", "1.0.0", []byte(`{"apps":["outside"]}`))
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}

	_, err := srv.PreviewContentPackage(context.Background(), &openngfwv1.PreviewContentPackageRequest{
		Kind:       "app-id",
		SourcePath: outsideDir,
	})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("PreviewContentPackage code = %v, want InvalidArgument err=%v", grpcstatus.Code(err), err)
	}
	if strings.Contains(err.Error(), outsideDir) || strings.Contains(err.Error(), importDir) {
		t.Fatalf("preview error leaked rejected path: %v", err)
	}
	entries, auditErr := st.ListAudit(1)
	if auditErr != nil {
		t.Fatalf("ListAudit: %v", auditErr)
	}
	if len(entries) != 0 {
		t.Fatalf("preview rejection wrote audit entries: %#v", entries)
	}
}

func TestIntelContentPackageActionErrorsUseStableCodes(t *testing.T) {
	st := newIntelTestStore(t)
	srv := &IntelServer{Store: st, ContentDir: filepath.Join(t.TempDir(), "content")}

	_, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{
		Kind:       "unknown",
		SourcePath: "/missing",
	})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("install code = %v, want InvalidArgument error=%v", grpcstatus.Code(err), err)
	}

	_, err = srv.RollbackContentPackage(context.Background(), &openngfwv1.RollbackContentPackageRequest{Kind: "app-id", AckRollback: true})
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rollback code = %v, want FailedPrecondition error=%v", grpcstatus.Code(err), err)
	}

	entries, err := st.ListAudit(4)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("audit entries = %d, want 4", len(entries))
	}
	if entries[0].Action != "content-package-rollback-failed" || !strings.Contains(entries[0].Detail, "kind=app-id") {
		t.Fatalf("rollback failure audit = %#v", entries[0])
	}
	if entries[1].Action != "content-package-rollback-intent" || !strings.Contains(entries[1].Detail, "kind=app-id") {
		t.Fatalf("rollback intent audit = %#v", entries[1])
	}
	if entries[2].Action != "content-package-install-failed" || !strings.Contains(entries[2].Detail, "kind=unknown") {
		t.Fatalf("install failure audit = %#v", entries[2])
	}
	if entries[3].Action != "content-package-install-intent" || !strings.Contains(entries[3].Detail, "kind=unknown") {
		t.Fatalf("install intent audit = %#v", entries[3])
	}
	for _, entry := range entries {
		if entry.Actor != "local" || entry.ActorRole != "admin" || entry.AuthSource != "disabled-local" {
			t.Fatalf("audit identity = %#v", entry)
		}
	}
}

func TestIntelContentPackageRollbackRequiresAck(t *testing.T) {
	st := newIntelTestStore(t)
	srv := &IntelServer{Store: st, ContentDir: filepath.Join(t.TempDir(), "content")}

	_, err := srv.RollbackContentPackage(context.Background(), &openngfwv1.RollbackContentPackageRequest{Kind: "app-id"})
	if grpcstatus.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "ack_rollback is required") {
		t.Fatalf("rollback without ack error = %v, want InvalidArgument ack requirement", err)
	}
	entries, auditErr := st.ListAudit(2)
	if auditErr != nil {
		t.Fatalf("ListAudit: %v", auditErr)
	}
	checkAuditEntry(t, entries[0], "content-package-rollback-failed", "error='ack_rollback_required'")
	checkAuditEntry(t, entries[1], "content-package-rollback-intent", "kind=app-id")
}

func TestIntelContentPackageActionsAuditSuccess(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	srcRoot := t.TempDir()
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: srcRoot}
	v1 := filepath.Join(srcRoot, "app-v1")
	v2 := filepath.Join(srcRoot, "app-v2")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, v1, "app-id", "1.0.0", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, v2, "app-id", "2.0.0", []byte(`{"apps":["v2"]}`))

	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v1}); err != nil {
		t.Fatalf("InstallContentPackage v1: %v", err)
	}
	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v2}); err != nil {
		t.Fatalf("InstallContentPackage v2: %v", err)
	}
	rollbackResp, err := srv.RollbackContentPackage(context.Background(), &openngfwv1.RollbackContentPackageRequest{Kind: "app-id", AckRollback: true})
	if err != nil {
		t.Fatalf("RollbackContentPackage: %v", err)
	}
	if rollbackResp.GetRestoredRollbackPath() == "" {
		t.Fatalf("rollback response missing restored rollback path: %#v", rollbackResp)
	}
	if rollbackResp.GetRollbackPath() == "" || rollbackResp.GetRollbackPath() == rollbackResp.GetRestoredRollbackPath() {
		t.Fatalf("rollback response paths not distinct: rollback=%q restored=%q", rollbackResp.GetRollbackPath(), rollbackResp.GetRestoredRollbackPath())
	}

	entries, err := st.ListAudit(6)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("audit entries = %d, want 6", len(entries))
	}
	checkAuditEntry(t, entries[0], "content-package-rollback", "version=1.0.0", "rollback_created=true", "restored_rollback_path=")
	checkAuditEntry(t, entries[1], "content-package-rollback-intent", "kind=app-id")
	checkAuditEntry(t, entries[2], "content-package-install", "version=2.0.0", "rollback_created=true")
	checkAuditEntry(t, entries[3], "content-package-install-intent", "kind=app-id")
	checkAuditEntry(t, entries[4], "content-package-install", "version=1.0.0", "rollback_created=false")
	checkAuditEntry(t, entries[5], "content-package-install-intent", "kind=app-id")
}

func TestIntelContentPackageInstallDoesNotMutateWhenIntentAuditFails(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := t.TempDir()
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}
	sourceDir := filepath.Join(importDir, "app-v1")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, sourceDir, "app-id", "1.0.0", []byte(`{"apps":["v1"]}`))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: sourceDir})
	if grpcstatus.Code(err) != codes.Internal || !strings.Contains(err.Error(), "intent audit failed") {
		t.Fatalf("InstallContentPackage error = %v, want intent audit failure", err)
	}
	if _, err := os.Stat(filepath.Join(contentDir, "app-id", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("install mutated package content despite failed intent audit: %v", err)
	}
}

func TestIntelContentPackageRollbackDoesNotMutateWhenIntentAuditFails(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	srcRoot := t.TempDir()
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: srcRoot}
	v1 := filepath.Join(srcRoot, "app-v1")
	v2 := filepath.Join(srcRoot, "app-v2")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, v1, "app-id", "1.0.0", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, v2, "app-id", "2.0.0", []byte(`{"apps":["v2"]}`))

	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v1}); err != nil {
		t.Fatalf("InstallContentPackage v1: %v", err)
	}
	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v2}); err != nil {
		t.Fatalf("InstallContentPackage v2: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := srv.RollbackContentPackage(context.Background(), &openngfwv1.RollbackContentPackageRequest{Kind: "app-id", AckRollback: true})
	if grpcstatus.Code(err) != codes.Internal || !strings.Contains(err.Error(), "intent audit failed") {
		t.Fatalf("RollbackContentPackage error = %v, want intent audit failure", err)
	}
	statuses, err := contentpkg.Statuses(contentDir)
	if err != nil {
		t.Fatal(err)
	}
	app := contentPackageStatusByKind(t, statuses, "app-id")
	if app.Version != "2.0.0" {
		t.Fatalf("rollback mutated package content despite failed intent audit: version=%q", app.Version)
	}
}

func TestIntelContentPackageInstallRevertsWhenSuccessAuditFails(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	srcRoot := t.TempDir()
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: srcRoot}
	v1 := filepath.Join(srcRoot, "app-v1")
	v2 := filepath.Join(srcRoot, "app-v2")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, v1, "app-id", "1.0.0", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, v2, "app-id", "2.0.0", []byte(`{"apps":["v2"]}`))

	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v1}); err != nil {
		t.Fatalf("InstallContentPackage v1: %v", err)
	}
	withContentPackageAuditHook(t, func(st *store.Store, entry store.AuditEntry) error {
		if entry.Action == "content-package-install" && strings.Contains(entry.Detail, "version=2.0.0") {
			return errors.New("forced success audit failure")
		}
		return st.AppendAudit(entry)
	})

	_, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v2})
	if grpcstatus.Code(err) != codes.Internal || !strings.Contains(err.Error(), "installation was reverted") {
		t.Fatalf("InstallContentPackage error = %v, want reverted success audit failure", err)
	}
	statuses, statusErr := contentpkg.Statuses(contentDir)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	app := contentPackageStatusByKind(t, statuses, "app-id")
	if app.Version != "1.0.0" {
		t.Fatalf("install success-audit failure left unaudited package active: version=%q", app.Version)
	}
}

func TestIntelContentPackageRollbackRevertsWhenSuccessAuditFails(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	srcRoot := t.TempDir()
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: srcRoot}
	v1 := filepath.Join(srcRoot, "app-v1")
	v2 := filepath.Join(srcRoot, "app-v2")
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, v1, "app-id", "1.0.0", []byte(`{"apps":["v1"]}`))
	publisher.writePackage(t, v2, "app-id", "2.0.0", []byte(`{"apps":["v2"]}`))

	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v1}); err != nil {
		t.Fatalf("InstallContentPackage v1: %v", err)
	}
	if _, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: v2}); err != nil {
		t.Fatalf("InstallContentPackage v2: %v", err)
	}
	withContentPackageAuditHook(t, func(st *store.Store, entry store.AuditEntry) error {
		if entry.Action == "content-package-rollback" {
			return errors.New("forced rollback success audit failure")
		}
		return st.AppendAudit(entry)
	})

	_, err := srv.RollbackContentPackage(context.Background(), &openngfwv1.RollbackContentPackageRequest{Kind: "app-id", AckRollback: true})
	if grpcstatus.Code(err) != codes.Internal || !strings.Contains(err.Error(), "rollback was restored") {
		t.Fatalf("RollbackContentPackage error = %v, want restored success audit failure", err)
	}
	statuses, statusErr := contentpkg.Statuses(contentDir)
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	app := contentPackageStatusByKind(t, statuses, "app-id")
	if app.Version != "2.0.0" {
		t.Fatalf("rollback success-audit failure left unaudited package active: version=%q", app.Version)
	}
}

func TestIntelContentPackageInstallRejectsSourceOutsideImportDir(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	outsideDir := filepath.Join(t.TempDir(), "outside-package")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, outsideDir, "app-id", "1.0.0", []byte(`{"apps":["outside"]}`))

	_, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: outsideDir})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("InstallContentPackage code = %v, want InvalidArgument err=%v", grpcstatus.Code(err), err)
	}
	if strings.Contains(err.Error(), outsideDir) {
		t.Fatalf("client error leaked rejected path: %v", err)
	}
	entries, auditErr := st.ListAudit(2)
	if auditErr != nil {
		t.Fatalf("ListAudit: %v", auditErr)
	}
	checkAuditEntry(t, entries[0], "content-package-install-failed", "source='rejected'", "error='source_path_rejected'")
	checkAuditEntry(t, entries[1], "content-package-install-intent", "source='rejected'")
}

func TestIntelContentPackageInstallRejectsSymlinkEscapeFromImportDir(t *testing.T) {
	st := newIntelTestStore(t)
	contentDir := filepath.Join(t.TempDir(), "content")
	importDir := filepath.Join(t.TempDir(), "content-import")
	outsideDir := filepath.Join(t.TempDir(), "outside-package")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(importDir, "linked-package")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	srv := &IntelServer{Store: st, ContentDir: contentDir, ContentImportDir: importDir}
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, outsideDir, "app-id", "1.0.0", []byte(`{"apps":["outside"]}`))

	_, err := srv.InstallContentPackage(context.Background(), &openngfwv1.InstallContentPackageRequest{Kind: "app-id", SourcePath: "linked-package"})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("InstallContentPackage code = %v, want InvalidArgument err=%v", grpcstatus.Code(err), err)
	}
	if strings.Contains(err.Error(), outsideDir) || strings.Contains(err.Error(), linkPath) {
		t.Fatalf("client error leaked rejected path: %v", err)
	}
}

func hasProtoString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func contentPackageStatusByKind(t *testing.T, statuses []contentpkg.Status, kind string) contentpkg.Status {
	t.Helper()
	for _, st := range statuses {
		if st.Kind == kind {
			return st
		}
	}
	t.Fatalf("package kind %q not found in %#v", kind, statuses)
	return contentpkg.Status{}
}

func newIntelTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func checkAuditEntry(t *testing.T, entry store.AuditEntry, action string, details ...string) {
	t.Helper()
	if entry.Action != action {
		t.Fatalf("audit action = %q, want %q entry=%#v", entry.Action, action, entry)
	}
	if entry.Actor != "local" || entry.ActorRole != "admin" || entry.AuthSource != "disabled-local" {
		t.Fatalf("audit identity = %#v", entry)
	}
	for _, detail := range details {
		if !strings.Contains(entry.Detail, detail) {
			t.Fatalf("audit detail %q missing %q", entry.Detail, detail)
		}
	}
}

func withContentPackageAuditHook(t *testing.T, hook func(*store.Store, store.AuditEntry) error) {
	t.Helper()
	previous := appendContentPackageAudit
	appendContentPackageAudit = hook
	t.Cleanup(func() {
		appendContentPackageAudit = previous
	})
}

func boolPtr(value bool) *bool {
	return &value
}

type apiContentPublisher struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newAPIContentPublisher(t *testing.T) apiContentPublisher {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return apiContentPublisher{
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

func (p apiContentPublisher) trust(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".trust", "ed25519")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir trusted keyring: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api-test.pub"), []byte(base64.StdEncoding.EncodeToString(p.pub)), 0o644); err != nil {
		t.Fatalf("write trusted publisher key: %v", err)
	}
}

//nolint:unparam // The kind parameter keeps test package generation explicit at call sites.
func (p apiContentPublisher) writePackage(t *testing.T, dir, kind, version string, content []byte) {
	t.Helper()
	p.writePackageWithMutator(t, dir, kind, version, content, nil)
}

func (p apiContentPublisher) writeProductionPackage(t *testing.T, dir, kind, version string, content []byte) {
	t.Helper()
	p.writePackageWithMutator(t, dir, kind, version, content, func(m *contentpkg.Manifest) {
		m.ContentReadiness = &contentpkg.ContentReadiness{
			Scope:                      "production",
			ProductionContent:          true,
			RequiredProductionEvidence: apiRequiredProductionEvidence(kind),
		}
		for _, evidenceType := range apiRequiredProductionEvidence(kind) {
			artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
			raw := apiProductionEvidencePayloadForTest(t, kind, evidenceType, version)
			sum := sha256.Sum256(raw)
			digest := hex.EncodeToString(sum[:])
			if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
				t.Fatalf("mkdir evidence: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, artifact), raw, 0o644); err != nil {
				t.Fatalf("write evidence: %v", err)
			}
			m.Files = append(m.Files, contentpkg.File{Path: artifact, SHA256: digest})
			m.ContentReadiness.Evidence = append(m.ContentReadiness.Evidence, contentpkg.EvidenceRef{
				Type:        evidenceType,
				Artifact:    artifact,
				SHA256:      digest,
				GeneratedAt: "2026-06-17T12:03:00Z",
			})
		}
	})
}

func apiProductionEvidencePayloadForTest(t *testing.T, kind, evidenceType, version string) []byte {
	t.Helper()
	if kind != "app-id" || evidenceType != "app-regression-corpus" {
		return []byte(`{"type":"` + evidenceType + `","status":"passed"}`)
	}
	payload := map[string]any{
		"type":            evidenceType,
		"status":          "passed",
		"package_version": version,
		"samples": []map[string]any{{
			"pcap_sha256":  strings.Repeat("a", 64),
			"expected_app": "corp-admin",
			"observed_app": "corp-admin",
			"verdict":      "passed",
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal evidence payload: %v", err)
	}
	return raw
}

func addAPIProductionEvidenceForTest(t *testing.T, dir string, m *contentpkg.Manifest, kind, version string) {
	t.Helper()
	m.ContentReadiness = &contentpkg.ContentReadiness{
		Scope:                      "production",
		ProductionContent:          true,
		RequiredProductionEvidence: apiRequiredProductionEvidence(kind),
	}
	for _, evidenceType := range apiRequiredProductionEvidence(kind) {
		artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
		raw := apiProductionEvidencePayloadForTest(t, kind, evidenceType, version)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
			t.Fatalf("mkdir evidence: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, artifact), raw, 0o644); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
		m.Files = append(m.Files, contentpkg.File{Path: artifact, SHA256: digest})
		m.ContentReadiness.Evidence = append(m.ContentReadiness.Evidence, contentpkg.EvidenceRef{
			Type:        evidenceType,
			Artifact:    artifact,
			SHA256:      digest,
			GeneratedAt: "2026-06-17T12:03:00Z",
		})
	}
}

func replaceAPIProductionEvidenceForTest(t *testing.T, dir string, m *contentpkg.Manifest, evidenceType string, raw []byte) {
	t.Helper()
	artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, artifact), raw, 0o644); err != nil {
		t.Fatalf("write evidence replacement: %v", err)
	}
	for i := range m.Files {
		if m.Files[i].Path == artifact {
			m.Files[i].SHA256 = digest
		}
	}
	for i := range m.ContentReadiness.Evidence {
		if m.ContentReadiness.Evidence[i].Type == evidenceType {
			m.ContentReadiness.Evidence[i].SHA256 = digest
		}
	}
}

func (p apiContentPublisher) writePackageWithMutator(t *testing.T, dir, kind, version string, content []byte, mutate func(*contentpkg.Manifest)) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	fileName := "content.json"
	if err := os.WriteFile(filepath.Join(dir, fileName), content, 0o644); err != nil {
		t.Fatalf("write content: %v", err)
	}
	sum := sha256.Sum256(content)
	manifest := contentpkg.Manifest{
		SchemaVersion: contentpkg.SchemaVersion,
		Kind:          kind,
		Name:          "Phragma " + kind + " test package",
		Version:       version,
		Source:        "api test",
		CreatedAt:     "2026-06-17T12:00:00Z",
		InstalledAt:   "2026-06-17T12:05:00Z",
		Files: []contentpkg.File{{
			Path:   fileName,
			SHA256: hex.EncodeToString(sum[:]),
		}},
		Regression: &contentpkg.Regression{Status: "passed", Corpus: "api", Passed: 1, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &contentpkg.Rollout{State: "stable", Scope: "all"},
		Rollback:   &contentpkg.Rollback{Available: true},
		Provenance: []contentpkg.Provenance{{
			Name:                 "Phragma API test",
			URL:                  "https://example.invalid/phragma/api-test",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtr(true),
			AllowsRedistribution: boolPtr(true),
		}},
	}
	if mutate != nil {
		mutate(&manifest)
	}
	payload, err := contentpkg.SignaturePayloadForTest(manifest)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	manifest.Signature = &contentpkg.Signature{
		Algorithm: "ed25519",
		KeyID:     "api-test",
		PublicKey: base64.StdEncoding.EncodeToString(p.pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(p.priv, payload)),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func apiRequiredProductionEvidence(kind string) []string {
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

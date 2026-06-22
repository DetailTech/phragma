package contentpkg

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootlessContentPackageSmoke(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data", "content")
	publisher := newTestPublisher(t, "rootless-smoke")
	publisher.trust(t, root)
	t.Logf("content package smoke root: %s", root)

	demos := []struct {
		kind     string
		version  string
		fileName string
		content  []byte
	}{
		{kind: "app-id", version: "1.0.0", fileName: "apps.json", content: []byte(`{"apps":[{"id":"demo-ssh","name":"Demo SSH","category":"infrastructure"}]}`)},
		{kind: "threat-id", version: "1.0.0", fileName: "threats.json", content: []byte(`{"threats":[{"id":"demo-scan","severity":"medium"}]}`)},
		{kind: "intel-feeds", version: "1.0.0", fileName: "feeds.json", content: []byte(`{"feeds":[{"name":"demo-blocklist","license":"Apache-2.0"}]}`)},
	}

	for _, demo := range demos {
		src := filepath.Join(t.TempDir(), demo.kind+"-v1")
		publisher.writePackage(t, src, demo.kind, demo.version, demo.fileName, demo.content)

		result, err := Install(root, demo.kind, src)
		if err != nil {
			t.Fatalf("Install %s: %v", demo.kind, err)
		}
		requireVerifiedSmokeStatus(t, result.Status, demo.kind, demo.version)
		if result.RollbackCreated {
			t.Fatalf("%s first install unexpectedly created rollback backup", demo.kind)
		}
		t.Logf("installed verified %s package version=%s signature=%s regression=%s rollout=%s provenance=%d",
			result.Status.Kind,
			result.Status.Version,
			result.Status.SignatureStatus,
			result.Status.RegressionStatus,
			result.Status.RolloutState,
			len(result.Status.Provenance),
		)
	}

	statuses, err := Statuses(root)
	if err != nil {
		t.Fatalf("Statuses after first installs: %v", err)
	}
	for _, st := range statuses {
		requireVerifiedSmokeStatus(t, st, st.Kind, "1.0.0")
		if st.RollbackAvailable {
			t.Fatalf("%s should not advertise rollback until a verified backup exists", st.Kind)
		}
	}

	appV2 := filepath.Join(t.TempDir(), "app-id-v2")
	publisher.writePackage(t, appV2, "app-id", "2.0.0", "apps.json", []byte(`{"apps":[{"id":"demo-ssh","name":"Demo SSH v2","category":"infrastructure"}]}`))
	installedV2, err := Install(root, "app-id", appV2)
	if err != nil {
		t.Fatalf("Install app-id v2: %v", err)
	}
	requireVerifiedSmokeStatus(t, installedV2.Status, "app-id", "2.0.0")
	if !installedV2.RollbackCreated || installedV2.RollbackPath == "" {
		t.Fatalf("app-id v2 install did not create rollback backup: %#v", installedV2)
	}
	if !installedV2.Status.RollbackAvailable {
		t.Fatalf("app-id v2 install did not advertise verified rollback availability")
	}
	t.Logf("created verified rollback backup for app-id at %s", installedV2.RollbackPath)

	badRegression := filepath.Join(t.TempDir(), "app-id-bad-regression")
	badPublisher := writeSignedPackageWithMutator(t, badRegression, "app-id", "3.0.0", "apps.json", []byte(`{"apps":[{"id":"bad-regression"}]}`), func(m *Manifest) {
		m.Regression.Status = "failed"
		m.Regression.Failed = 1
	})
	badPublisher.trust(t, root)
	_, err = Install(root, "app-id", badRegression)
	if !errors.Is(err, ErrInvalidPackage) || !strings.Contains(err.Error(), "regression result") {
		t.Fatalf("Install bad regression error = %v, want ErrInvalidPackage with regression result", err)
	}

	rolledBack, err := RollbackPackage(root, "app-id")
	if err != nil {
		t.Fatalf("Rollback app-id: %v", err)
	}
	requireVerifiedSmokeStatus(t, rolledBack.Status, "app-id", "1.0.0")
	if !rolledBack.RollbackCreated || rolledBack.RollbackPath == "" {
		t.Fatalf("rollback did not preserve pre-rollback package: %#v", rolledBack)
	}
	if rolledBack.RestoredRollbackPath != installedV2.RollbackPath {
		t.Fatalf("restored rollback path = %q, want %q", rolledBack.RestoredRollbackPath, installedV2.RollbackPath)
	}
	t.Logf("rolled back app-id to version=%s restored=%s preserved=%s",
		rolledBack.Status.Version,
		rolledBack.RestoredRollbackPath,
		rolledBack.RollbackPath,
	)
}

func requireVerifiedSmokeStatus(t *testing.T, st Status, kind, version string) {
	t.Helper()
	if st.Kind != kind {
		t.Fatalf("kind = %q, want %q", st.Kind, kind)
	}
	if st.Version != version {
		t.Fatalf("%s version = %q, want %q", kind, st.Version, version)
	}
	if st.State != "verified" {
		t.Fatalf("%s state = %q, want verified blockers=%#v", kind, st.State, st.Blockers)
	}
	if st.SignatureStatus != "verified" {
		t.Fatalf("%s signature = %q, want verified", kind, st.SignatureStatus)
	}
	if st.RegressionStatus != "passed" {
		t.Fatalf("%s regression = %q, want passed", kind, st.RegressionStatus)
	}
	if st.RolloutState == "" {
		t.Fatalf("%s missing rollout state", kind)
	}
	if len(st.Provenance) == 0 {
		t.Fatalf("%s missing provenance", kind)
	}
	if st.ContentReadiness.ProductionReady {
		t.Fatalf("%s demo smoke package must not report production readiness: %#v", kind, st.ContentReadiness)
	}
	if st.ContentReadiness.EvidenceStatus != "demo-only" {
		t.Fatalf("%s readiness status = %q, want demo-only blockers=%#v", kind, st.ContentReadiness.EvidenceStatus, st.ContentReadiness.Blockers)
	}
	if st.ContentReadiness.ProductionEvidenceStatus != "demo" {
		t.Fatalf("%s production evidence status = %q, want demo", kind, st.ContentReadiness.ProductionEvidenceStatus)
	}
	if st.ContentReadiness.Scope != "demo-only" || st.ContentReadiness.ProductionContent {
		t.Fatalf("%s readiness scope/content = %q/%v, want demo-only/false", kind, st.ContentReadiness.Scope, st.ContentReadiness.ProductionContent)
	}
	for _, p := range st.Provenance {
		if p.Name == "" || p.URL == "" || p.License == "" || p.AllowsCommercialUse == nil || p.AllowsRedistribution == nil {
			t.Fatalf("%s incomplete provenance entry: %#v", kind, p)
		}
	}
}

package store

import (
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func policyWithComment(zone string) *openngfwv1.Policy {
	return &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: zone}}}
}

func TestCandidateLifecycle(t *testing.T) {
	s := openTestStore(t)

	if _, ok, err := s.GetCandidate(); err != nil || ok {
		t.Fatalf("fresh store should have no candidate (ok=%v err=%v)", ok, err)
	}

	want := policyWithComment("lan")
	if err := s.SetCandidate(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate not found after set (err=%v)", err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("candidate mismatch: got %v want %v", got, want)
	}
}

func TestCommitRollbackHistory(t *testing.T) {
	s := openTestStore(t)

	// Fresh node runs an empty policy at version 0.
	running, ver, err := s.GetRunning()
	if err != nil || ver != 0 || len(running.GetZones()) != 0 {
		t.Fatalf("fresh running = v%d %v err=%v", ver, running, err)
	}

	v1policy := policyWithComment("first")
	_ = s.SetCandidate(v1policy)
	id1, err := s.CommitVersion(v1policy, "tester", "first commit")
	if err != nil || id1 != 1 {
		t.Fatalf("first commit: id=%d err=%v", id1, err)
	}

	// Commit clears the candidate.
	if _, ok, _ := s.GetCandidate(); ok {
		t.Fatal("candidate should be cleared after commit")
	}

	v2policy := policyWithComment("second")
	id2, err := s.CommitVersion(v2policy, "tester", "second commit")
	if err != nil || id2 != 2 {
		t.Fatalf("second commit: id=%d err=%v", id2, err)
	}

	running, ver, err = s.GetRunning()
	if err != nil || ver != id2 || running.GetZones()[0].GetName() != "second" {
		t.Fatalf("running = v%d %v err=%v", ver, running, err)
	}

	// Historical version is intact.
	old, err := s.GetVersion(id1)
	if err != nil || old.GetZones()[0].GetName() != "first" {
		t.Fatalf("GetVersion(1) = %v err=%v", old, err)
	}
	if _, err := s.GetVersion(99); err == nil {
		t.Fatal("expected error for missing version")
	}

	infos, err := s.ListVersions(0)
	if err != nil || len(infos) != 2 {
		t.Fatalf("ListVersions = %v err=%v", infos, err)
	}
	if infos[0].ID != id2 || infos[1].ID != id1 {
		t.Fatalf("versions not newest-first: %v", infos)
	}
	if infos[1].Comment != "first commit" || infos[1].Actor != "tester" {
		t.Fatalf("version metadata wrong: %+v", infos[1])
	}
}

func TestAudit(t *testing.T) {
	s := openTestStore(t)
	for _, action := range []string{"set-candidate", "commit", "rollback"} {
		if err := s.AppendAudit(AuditEntry{Actor: "tester", Action: action, Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.ListAudit(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Action != "rollback" || entries[0].ID != 3 {
		t.Fatalf("audit entries = %+v", entries)
	}
	if entries[0].Time.IsZero() {
		t.Fatal("audit timestamp not set")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitVersion(policyWithComment("persisted"), "tester", "c"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	p, ver, err := s2.GetRunning()
	if err != nil || ver != 1 || p.GetZones()[0].GetName() != "persisted" {
		t.Fatalf("after reopen: v%d %v err=%v", ver, p, err)
	}
}

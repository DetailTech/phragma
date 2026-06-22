package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
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

func tamperAuditDetail(t *testing.T, s *Store, id uint64, detail string) {
	t.Helper()
	err := s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bktAudit)
		key := u64key(id)
		raw := audit.Get(key)
		if raw == nil {
			return fmt.Errorf("audit entry %d missing", id)
		}
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		e.Detail = detail
		tampered, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return audit.Put(key, tampered)
	})
	if err != nil {
		t.Fatal(err)
	}
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

func TestSetCandidateWithAuditRollsBackCandidateWhenAuditFails(t *testing.T) {
	s := openTestStore(t)

	original := policyWithComment("original")
	if err := s.SetCandidate(original); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(AuditEntry{
		Time:   time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "original",
	}); err != nil {
		t.Fatal(err)
	}
	tamperAuditDetail(t, s, 1, "tampered")

	err := s.SetCandidateWithAudit(policyWithComment("new-candidate"), AuditEntry{
		Time:   time.Date(2026, 6, 17, 12, 1, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "new-candidate",
	})
	if err == nil {
		t.Fatal("SetCandidateWithAudit succeeded with a broken audit chain")
	}
	if !strings.Contains(err.Error(), "entry hash mismatch") {
		t.Fatalf("SetCandidateWithAudit error = %q, want audit hash mismatch", err)
	}
	got, ok, err := s.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing after failed audited set (ok=%v err=%v)", ok, err)
	}
	if !proto.Equal(got, original) {
		t.Fatalf("candidate changed after failed audited set: got %v want %v", got, original)
	}
}

func TestSetCandidateWithAuditIfRevisionRejectsStaleCandidate(t *testing.T) {
	s := openTestStore(t)

	initialRevision, err := s.CandidateRevision()
	if err != nil {
		t.Fatalf("initial revision: %v", err)
	}
	if initialRevision != "none:0" {
		t.Fatalf("initial revision = %q, want none:0", initialRevision)
	}

	firstRevision, err := s.SetCandidateWithAuditIfRevision(policyWithComment("first"), initialRevision, AuditEntry{
		Time:   time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "first",
	})
	if err != nil {
		t.Fatalf("first guarded set: %v", err)
	}
	if firstRevision == "" || firstRevision == initialRevision {
		t.Fatalf("first revision = %q, initial = %q", firstRevision, initialRevision)
	}

	_, err = s.SetCandidateWithAuditIfRevision(policyWithComment("stale"), initialRevision, AuditEntry{
		Time:   time.Date(2026, 6, 22, 12, 1, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "stale",
	})
	if !errors.Is(err, ErrCandidateRevisionConflict) {
		t.Fatalf("stale guarded set error = %v, want ErrCandidateRevisionConflict", err)
	}
	got, ok, err := s.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing after stale write (ok=%v err=%v)", ok, err)
	}
	if got.GetZones()[0].GetName() != "first" {
		t.Fatalf("candidate changed after stale write: %v", got)
	}

	secondRevision, err := s.SetCandidateWithAuditIfRevision(policyWithComment("second"), firstRevision, AuditEntry{
		Time:   time.Date(2026, 6, 22, 12, 2, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "second",
	})
	if err != nil {
		t.Fatalf("second guarded set: %v", err)
	}
	if secondRevision == firstRevision {
		t.Fatalf("second revision did not change: %q", secondRevision)
	}
}

func TestChangeApprovalLifecycleBindsCandidateRevision(t *testing.T) {
	s := openTestStore(t)
	revision, err := s.SetCandidateWithAuditIfRevision(policyWithComment("first"), "", AuditEntry{
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "first",
	})
	if err != nil {
		t.Fatalf("set candidate: %v", err)
	}
	identity := ActorIdentity{Name: "approver", Role: "admin", AuthSource: "local-users-file"}
	approval, err := s.CreateChangeApproval(revision, identity, "approved for maintenance", true, true)
	if err != nil {
		t.Fatalf("CreateChangeApproval: %v", err)
	}
	if approval.ID == "" || approval.CandidateRevision != revision || approval.Actor != "approver" || !approval.AckRisk || !approval.AckRuntime {
		t.Fatalf("approval metadata wrong: %+v", approval)
	}
	active, err := s.ListChangeApprovals(ChangeApprovalFilter{CandidateRevision: revision})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != approval.ID {
		t.Fatalf("active approvals = %+v, want approval %s", active, approval.ID)
	}
	if _, err := s.CreateChangeApproval("sha256:stale", identity, "stale", true, true); !errors.Is(err, ErrChangeApprovalRevisionMismatch) {
		t.Fatalf("stale approval error = %v, want ErrChangeApprovalRevisionMismatch", err)
	}

	consumed, err := s.ConsumeChangeApproval(approval.ID, revision, ActorIdentity{Name: "operator", Role: "operator", AuthSource: "local-users-file"}, 9)
	if err != nil {
		t.Fatalf("ConsumeChangeApproval: %v", err)
	}
	if !consumed.Consumed || consumed.ConsumedVersion != 9 || consumed.ConsumedBy != "operator" {
		t.Fatalf("consumed approval metadata wrong: %+v", consumed)
	}
	if _, err := s.ConsumeChangeApproval(approval.ID, revision, ActorIdentity{Name: "operator"}, 10); !errors.Is(err, ErrChangeApprovalConsumed) {
		t.Fatalf("reuse approval error = %v, want ErrChangeApprovalConsumed", err)
	}
	active, err = s.ListChangeApprovals(ChangeApprovalFilter{CandidateRevision: revision})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("consumed approval returned without IncludeConsumed: %+v", active)
	}
	all, err := s.ListChangeApprovals(ChangeApprovalFilter{CandidateRevision: revision, IncludeConsumed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || !all[0].Consumed {
		t.Fatalf("include consumed approvals = %+v", all)
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

func TestCommitVersionWithIdentityRecordsRoleAndAuthSource(t *testing.T) {
	s := openTestStore(t)
	id, err := s.CommitVersionWithIdentity(policyWithComment("lan"), ActorIdentity{
		Name: "bob", Role: "operator", AuthSource: "local-users-file",
	}, "operator commit")
	if err != nil || id != 1 {
		t.Fatalf("commit: id=%d err=%v", id, err)
	}
	infos, err := s.ListVersions(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Actor != "bob" || infos[0].ActorRole != "operator" || infos[0].AuthSource != "local-users-file" {
		t.Fatalf("version identity metadata wrong: %+v", infos)
	}
}

func TestPreparePolicyApplyRecordsIntentBeforeActivation(t *testing.T) {
	s := openTestStore(t)
	identity := ActorIdentity{Name: "alice", Role: "admin", AuthSource: "local-users-file"}
	candidate := policyWithComment("prepared")
	if err := s.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}

	artifacts := []VersionArtifact{{Engine: "nftables", Name: "nftables", SizeBytes: 3, SHA256: "abc123"}}
	id, err := s.PreparePolicyApplyWithIdentity(candidate, identity, "commit", "prepare before engine apply", artifacts, 0)
	if err != nil || id != 1 {
		t.Fatalf("prepare: id=%d err=%v", id, err)
	}
	info, err := s.GetVersionInfo(id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Action != "commit" || info.State != "prepared" || info.LastKnownGood || !info.ActivatedAt.IsZero() {
		t.Fatalf("prepared metadata wrong: %+v", info)
	}
	if info.ArtifactSetSHA256 == "" || len(info.Artifacts) != 1 || info.Artifacts[0].SHA256 != "abc123" {
		t.Fatalf("prepared artifact metadata wrong: %+v", info)
	}
	running, ver, err := s.GetRunning()
	if err != nil || ver != 0 || len(running.GetZones()) != 0 {
		t.Fatalf("prepare should not activate running: v%d %v err=%v", ver, running, err)
	}
	if _, ok, err := s.GetCandidate(); err != nil || !ok {
		t.Fatalf("candidate should remain before activation (ok=%v err=%v)", ok, err)
	}
	prepared, err := s.GetVersion(id)
	if err != nil || prepared.GetZones()[0].GetName() != "prepared" {
		t.Fatalf("prepared version = %v err=%v", prepared, err)
	}
	intents, err := s.ListAuditFiltered(AuditFilter{Action: "commit-intent", Version: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].Detail != "prepare before engine apply" || intents[0].Actor != "alice" {
		t.Fatalf("intent audit entry wrong: %+v", intents)
	}
	successes, err := s.ListAuditFiltered(AuditFilter{Action: "commit", Version: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(successes) != 0 {
		t.Fatalf("success audit should not exist before activation: %+v", successes)
	}

	if err := s.ActivatePreparedVersion(id, identity, "commit", "prepare before engine apply"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	info, err = s.GetVersionInfo(id)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != "active" || !info.LastKnownGood || info.ActivatedAt.IsZero() {
		t.Fatalf("active metadata wrong: %+v", info)
	}
	running, ver, err = s.GetRunning()
	if err != nil || ver != id || running.GetZones()[0].GetName() != "prepared" {
		t.Fatalf("activated running = v%d %v err=%v", ver, running, err)
	}
	if _, ok, err := s.GetCandidate(); err != nil || ok {
		t.Fatalf("candidate should be cleared after activation (ok=%v err=%v)", ok, err)
	}
	successes, err = s.ListAuditFiltered(AuditFilter{Action: "commit", Version: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(successes) != 1 || successes[0].Detail != "prepare before engine apply" || successes[0].Actor != "alice" {
		t.Fatalf("success audit entry wrong: %+v", successes)
	}
}

func TestPreparePolicyApplyConsumesApprovalAtomically(t *testing.T) {
	s := openTestStore(t)
	identity := ActorIdentity{Name: "alice", Role: "admin", AuthSource: "local-users-file"}
	candidate := policyWithComment("approved")
	revision, err := s.SetCandidateWithAuditIfRevision(candidate, "", AuditEntry{
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := s.CreateChangeApproval(revision, identity, "approve approved", true, true)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.PreparePolicyApplyWithIdentityAndApproval(candidate, ActorIdentity{Name: "operator", Role: "operator", AuthSource: "local-users-file"}, "commit", "prepare approved", nil, 0, approval.ID, revision)
	if err != nil || id != 1 {
		t.Fatalf("prepare with approval: id=%d err=%v", id, err)
	}
	approvals, err := s.ListChangeApprovals(ChangeApprovalFilter{IncludeConsumed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 1 || !approvals[0].Consumed || approvals[0].ConsumedVersion != id || approvals[0].ConsumedBy != "operator" {
		t.Fatalf("approval not consumed by prepared version: %+v", approvals)
	}
}

func TestPreparePolicyApplyRollsBackVersionWhenAuditIntentFails(t *testing.T) {
	s := openTestStore(t)
	if err := s.AppendAudit(AuditEntry{
		Time:   time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "set-candidate",
		Detail: "original",
	}); err != nil {
		t.Fatal(err)
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bktAudit)
		key := u64key(1)
		raw := audit.Get(key)
		if raw == nil {
			return errors.New("audit entry 1 missing")
		}
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		e.Detail = "tampered"
		tampered, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return audit.Put(key, tampered)
	})
	if err != nil {
		t.Fatal(err)
	}

	id, err := s.PreparePolicyApplyWithIdentity(policyWithComment("prepared"), ActorIdentity{Name: "alice"}, "commit", "should fail", nil, 0)
	if err == nil {
		t.Fatal("prepare succeeded with a broken audit chain")
	}
	if id != 0 {
		t.Fatalf("failed prepare id = %d, want 0", id)
	}
	if !strings.Contains(err.Error(), "entry hash mismatch") {
		t.Fatalf("prepare error = %q, want audit hash mismatch", err)
	}
	if _, err := s.GetVersion(1); err == nil {
		t.Fatal("prepared version persisted even though audit intent failed")
	}
	infos, err := s.ListVersions(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("version metadata persisted after failed prepare: %+v", infos)
	}
}

func TestVersionRecoveryMetadataPersistsAndBackfillsLastKnownGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CommitVersion(policyWithComment("persisted"), "tester", "initial")
	if err != nil {
		t.Fatal(err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bktMeta).Delete(keyLastKnown); err != nil {
			return err
		}
		key := u64key(id)
		raw := tx.Bucket(bktVersionInfo).Get(key)
		var info VersionInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return err
		}
		info.State = ""
		info.ActivatedAt = time.Time{}
		info.StateDetail = ""
		encoded, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return tx.Bucket(bktVersionInfo).Put(key, encoded)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	info, err := s.GetVersionInfo(id)
	if err != nil {
		t.Fatal(err)
	}
	if !info.LastKnownGood || info.State != "active" || info.ActivatedAt.IsZero() || info.StateDetail == "" {
		t.Fatalf("backfilled metadata wrong: %+v", info)
	}
}

func TestAudit(t *testing.T) {
	s := openTestStore(t)
	for _, action := range []string{"set-candidate", "commit", "rollback"} {
		if err := s.AppendAudit(AuditEntry{Actor: "tester", ActorRole: "operator", AuthSource: "local-users-file", Action: action, Detail: "x"}); err != nil {
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
	if entries[0].ActorRole != "operator" || entries[0].AuthSource != "local-users-file" {
		t.Fatalf("audit identity metadata wrong: %+v", entries[0])
	}
}

func TestAuditHashChainLinksEntries(t *testing.T) {
	s := openTestStore(t)
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for i, action := range []string{"set-candidate", "commit", "rollback"} {
		if err := s.AppendAudit(AuditEntry{
			Time:       base.Add(time.Duration(i) * time.Minute),
			Actor:      "tester",
			ActorRole:  "operator",
			AuthSource: "local-users-file",
			Action:     action,
			Detail:     "x",
			Version:    uint64(i + 1),
		}); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := s.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d audit entries, want 3", len(entries))
	}
	oldest, middle, newest := entries[2], entries[1], entries[0]
	if oldest.PreviousHash != "" {
		t.Fatalf("oldest previous hash = %q, want genesis empty hash", oldest.PreviousHash)
	}
	if middle.PreviousHash != oldest.EntryHash {
		t.Fatalf("middle previous hash = %q, want oldest hash %q", middle.PreviousHash, oldest.EntryHash)
	}
	if newest.PreviousHash != middle.EntryHash {
		t.Fatalf("newest previous hash = %q, want middle hash %q", newest.PreviousHash, middle.EntryHash)
	}
	seen := map[string]uint64{}
	for _, e := range entries {
		if len(e.EntryHash) != 64 {
			t.Fatalf("entry %d hash length = %d, want sha256 hex", e.ID, len(e.EntryHash))
		}
		if previousID, ok := seen[e.EntryHash]; ok {
			t.Fatalf("entries %d and %d have duplicate hash %q", previousID, e.ID, e.EntryHash)
		}
		seen[e.EntryHash] = e.ID
	}
	if err := s.VerifyAuditIntegrity(); err != nil {
		t.Fatalf("VerifyAuditIntegrity: %v", err)
	}
	report, err := s.AuditIntegrity()
	if err != nil {
		t.Fatalf("AuditIntegrity: %v", err)
	}
	if report.EntryCount != 3 || report.LatestEntryHash != newest.EntryHash {
		t.Fatalf("AuditIntegrity report = %+v, want count 3 latest %q", report, newest.EntryHash)
	}
}

func TestAuditHashesDeterministicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, action := range []string{"set-candidate", "commit"} {
		if err := s.AppendAudit(AuditEntry{
			Time:    base.Add(time.Duration(i) * time.Minute),
			Actor:   "tester",
			Action:  action,
			Detail:  "stable",
			Version: uint64(i + 1),
		}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 {
		t.Fatalf("got %d audit entries before reopen, want 2", len(before))
	}
	headHash := before[0].EntryHash
	if err := s.VerifyAuditIntegrity(); err != nil {
		t.Fatalf("VerifyAuditIntegrity before reopen: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	after, err := s2.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("got %d audit entries after reopen, want %d", len(after), len(before))
	}
	for i := range before {
		if after[i].ID != before[i].ID || after[i].PreviousHash != before[i].PreviousHash || after[i].EntryHash != before[i].EntryHash {
			t.Fatalf("entry %d changed after reopen: before=%+v after=%+v", i, before[i], after[i])
		}
	}
	if err := s2.AppendAudit(AuditEntry{Time: base.Add(2 * time.Minute), Actor: "tester", Action: "rollback", Detail: "after reopen"}); err != nil {
		t.Fatal(err)
	}
	latest, err := s2.ListAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if latest[0].PreviousHash != headHash {
		t.Fatalf("post-reopen previous hash = %q, want prior head hash %q", latest[0].PreviousHash, headHash)
	}
}

func TestVerifyAuditIntegrityDetectsManualTampering(t *testing.T) {
	s := openTestStore(t)
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	for i, action := range []string{"set-candidate", "commit", "rollback"} {
		if err := s.AppendAudit(AuditEntry{
			Time:   base.Add(time.Duration(i) * time.Minute),
			Actor:  "tester",
			Action: action,
			Detail: "original",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.VerifyAuditIntegrity(); err != nil {
		t.Fatalf("VerifyAuditIntegrity before tamper: %v", err)
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bktAudit)
		key := u64key(2)
		raw := audit.Get(key)
		if raw == nil {
			return errors.New("audit entry 2 missing")
		}
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		e.Detail = "tampered"
		tampered, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return audit.Put(key, tampered)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.VerifyAuditIntegrity()
	if err == nil {
		t.Fatal("VerifyAuditIntegrity succeeded after manual tampering")
	}
	if !strings.Contains(err.Error(), "entry 2") || !strings.Contains(err.Error(), "entry hash mismatch") {
		t.Fatalf("tamper error = %q, want entry 2 hash mismatch", err)
	}
}

func TestOpenRejectsTamperedAuditHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(AuditEntry{
		Time:   time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		Actor:  "tester",
		Action: "commit",
		Detail: "original",
	}); err != nil {
		t.Fatal(err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bktAudit)
		raw := audit.Get(u64key(1))
		if raw == nil {
			return errors.New("audit entry 1 missing")
		}
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		e.Detail = "tampered"
		tampered, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return audit.Put(u64key(1), tampered)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("Open succeeded after audit hash tampering")
	}
	if !strings.Contains(err.Error(), "audit integrity entry 1") || !strings.Contains(err.Error(), "entry hash mismatch") {
		t.Fatalf("Open error = %q, want entry 1 hash mismatch", err)
	}
}

func TestAuditFiltering(t *testing.T) {
	s := openTestStore(t)
	base := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	entries := []AuditEntry{
		{Time: base.Add(-3 * time.Hour), Actor: "alice", ActorRole: "admin", AuthSource: "local-users-file", Action: "set-candidate", Detail: "2 zones"},
		{Time: base.Add(-2 * time.Hour), Actor: "bob", ActorRole: "operator", AuthSource: "oidc", Action: "commit", Detail: "initial", Version: 7},
		{Time: base.Add(-1 * time.Hour), Actor: "alice", ActorRole: "admin", AuthSource: "local-users-file", Action: "rollback-failed", Detail: "validation blocked", Version: 8},
	}
	for _, e := range entries {
		if err := s.AppendAudit(e); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name   string
		filter AuditFilter
		want   []string
	}{
		{name: "actor substring", filter: AuditFilter{Actor: "ali"}, want: []string{"rollback-failed", "set-candidate"}},
		{name: "action exact", filter: AuditFilter{Action: "commit"}, want: []string{"commit"}},
		{name: "version", filter: AuditFilter{Version: 8}, want: []string{"rollback-failed"}},
		{name: "query detail", filter: AuditFilter{Query: "initial"}, want: []string{"commit"}},
		{name: "query auth source", filter: AuditFilter{Query: "oidc"}, want: []string{"commit"}},
		{name: "since", filter: AuditFilter{Since: base.Add(-90 * time.Minute)}, want: []string{"rollback-failed"}},
		{name: "until", filter: AuditFilter{Until: base.Add(-90 * time.Minute)}, want: []string{"commit", "set-candidate"}},
		{name: "limit after filter", filter: AuditFilter{Actor: "alice", Limit: 1}, want: []string{"rollback-failed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ListAuditFiltered(tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries (%+v), want %d", len(got), got, len(tt.want))
			}
			for i, want := range tt.want {
				if got[i].Action != want {
					t.Fatalf("entry %d action = %q, want %q (all %+v)", i, got[i].Action, want, got)
				}
			}
		})
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

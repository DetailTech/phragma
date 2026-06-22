package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// BackupSnapshot is appliance-owned policy backup metadata. Policy bytes are
// kept in the store record and returned only by GetBackupSnapshot.
type BackupSnapshot struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"created_at"`
	Actor             string    `json:"actor"`
	ActorRole         string    `json:"actor_role,omitempty"`
	AuthSource        string    `json:"auth_source,omitempty"`
	Comment           string    `json:"comment,omitempty"`
	Source            string    `json:"source"`
	SourceVersion     uint64    `json:"source_version,omitempty"`
	RunningVersion    uint64    `json:"running_version,omitempty"`
	CandidateRevision string    `json:"candidate_revision,omitempty"`
	PolicySHA256      string    `json:"policy_sha256"`
	PolicySizeBytes   uint64    `json:"policy_size_bytes"`
}

type backupSnapshotRecord struct {
	BackupSnapshot
	Policy []byte `json:"policy"`
}

// CreateBackupSnapshot records a durable appliance-owned policy snapshot and
// appends the matching audit entry in the same transaction.
func (s *Store) CreateBackupSnapshot(p *openngfwv1.Policy, meta BackupSnapshot, audit AuditEntry) (BackupSnapshot, error) {
	if p == nil {
		return BackupSnapshot{}, fmt.Errorf("policy is required")
	}
	raw, err := proto.Marshal(p)
	if err != nil {
		return BackupSnapshot{}, fmt.Errorf("marshal snapshot policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	meta.Comment = strings.TrimSpace(meta.Comment)
	meta.Source = strings.TrimSpace(meta.Source)
	if meta.Source == "" {
		meta.Source = "running"
	}
	var out BackupSnapshot
	err = s.db.Update(func(tx *bolt.Tx) error {
		snapshots := tx.Bucket(bktSnapshots)
		seq, err := snapshots.NextSequence()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		meta.ID = fmt.Sprintf("snap-%d", seq)
		meta.CreatedAt = now
		meta.PolicySHA256 = fmt.Sprintf("%x", sum[:])
		meta.PolicySizeBytes = uint64(len(raw))
		record := backupSnapshotRecord{BackupSnapshot: meta, Policy: raw}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := snapshots.Put(u64key(seq), encoded); err != nil {
			return err
		}
		audit.Action = "backup-snapshot-create"
		audit.Detail = strings.TrimSpace(audit.Detail)
		if audit.Detail == "" {
			audit.Detail = fmt.Sprintf("snapshot %s from %s", meta.ID, meta.Source)
		}
		if audit.Time.IsZero() {
			audit.Time = now
		}
		if err := appendAuditTx(tx, audit); err != nil {
			return err
		}
		out = meta
		return nil
	})
	return out, err
}

// ListBackupSnapshots returns snapshot metadata newest first.
func (s *Store) ListBackupSnapshots(limit int) ([]BackupSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []BackupSnapshot
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktSnapshots).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var record backupSnapshotRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			out = append(out, record.BackupSnapshot)
		}
		return nil
	})
	return out, err
}

// GetBackupSnapshot returns snapshot metadata plus a cloned policy.
func (s *Store) GetBackupSnapshot(id string) (BackupSnapshot, *openngfwv1.Policy, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return BackupSnapshot{}, nil, fmt.Errorf("snapshot id is required")
	}
	var (
		snapshot BackupSnapshot
		policy   = &openngfwv1.Policy{}
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktSnapshots).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var record backupSnapshotRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			if record.ID != id {
				continue
			}
			if err := proto.Unmarshal(record.Policy, policy); err != nil {
				return err
			}
			snapshot = record.BackupSnapshot
			return nil
		}
		return fmt.Errorf("snapshot %s not found", id)
	})
	if err != nil {
		return BackupSnapshot{}, nil, err
	}
	return snapshot, policy, nil
}

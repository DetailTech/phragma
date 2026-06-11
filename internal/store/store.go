// Package store persists policy versions, the shared candidate, and the
// audit log in an embedded bbolt database.
//
// Decision (build plan §13 OPEN, resolved for v1): bbolt over SQLite.
// The access pattern is versioned blobs + append-only log — a pure-Go
// key/value store fits exactly and keeps builds CGO-free and static.
package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

var (
	bktMeta        = []byte("meta")
	bktVersions    = []byte("versions")
	bktVersionInfo = []byte("version_info")
	bktCandidate   = []byte("candidate")
	bktAudit       = []byte("audit")

	keyRunning   = []byte("running")
	keyCandidate = []byte("policy")
)

// VersionInfo is the metadata recorded with each committed version.
type VersionInfo struct {
	ID        uint64    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Actor     string    `json:"actor"`
	Comment   string    `json:"comment"`
}

// AuditEntry is one append-only audit record.
type AuditEntry struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Detail  string    `json:"detail"`
	Version uint64    `json:"version,omitempty"`
}

// Store wraps the bbolt database.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if necessary) the database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bktMeta, bktVersions, bktVersionInfo, bktCandidate, bktAudit} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init store: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// SetCandidate replaces the candidate policy.
func (s *Store) SetCandidate(p *openngfwv1.Policy) error {
	raw, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal candidate: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktCandidate).Put(keyCandidate, raw)
	})
}

// GetCandidate returns the candidate policy, or ok=false if none is set.
func (s *Store) GetCandidate() (p *openngfwv1.Policy, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bktCandidate).Get(keyCandidate)
		if raw == nil {
			return nil
		}
		p = &openngfwv1.Policy{}
		ok = true
		return proto.Unmarshal(raw, p)
	})
	return p, ok, err
}

// GetRunning returns the running policy and its version id. A fresh node
// returns an empty policy with version 0.
func (s *Store) GetRunning() (*openngfwv1.Policy, uint64, error) {
	var (
		p  = &openngfwv1.Policy{}
		id uint64
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(bktMeta).Get(keyRunning)
		if cur == nil {
			return nil
		}
		id = binary.BigEndian.Uint64(cur)
		raw := tx.Bucket(bktVersions).Get(cur)
		if raw == nil {
			return fmt.Errorf("running version %d missing from store", id)
		}
		return proto.Unmarshal(raw, p)
	})
	return p, id, err
}

// GetVersion returns a historical policy by version id.
func (s *Store) GetVersion(id uint64) (*openngfwv1.Policy, error) {
	p := &openngfwv1.Policy{}
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bktVersions).Get(u64key(id))
		if raw == nil {
			return fmt.Errorf("version %d not found", id)
		}
		return proto.Unmarshal(raw, p)
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// CommitVersion records p as the new running version, clears the
// candidate, and returns the new version id. The caller is responsible
// for having applied p to the engines first — the store only records
// what was made live.
func (s *Store) CommitVersion(p *openngfwv1.Policy, actor, comment string) (uint64, error) {
	raw, err := proto.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("marshal policy: %w", err)
	}
	var id uint64
	err = s.db.Update(func(tx *bolt.Tx) error {
		versions := tx.Bucket(bktVersions)
		id, _ = versions.NextSequence()
		key := u64key(id)
		if err := versions.Put(key, raw); err != nil {
			return err
		}
		info, err := json.Marshal(VersionInfo{ID: id, CreatedAt: time.Now().UTC(), Actor: actor, Comment: comment})
		if err != nil {
			return err
		}
		if err := tx.Bucket(bktVersionInfo).Put(key, info); err != nil {
			return err
		}
		if err := tx.Bucket(bktMeta).Put(keyRunning, key); err != nil {
			return err
		}
		return tx.Bucket(bktCandidate).Delete(keyCandidate)
	})
	return id, err
}

// ListVersions returns version metadata, newest first, at most limit.
func (s *Store) ListVersions(limit int) ([]VersionInfo, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []VersionInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktVersionInfo).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var vi VersionInfo
			if err := json.Unmarshal(v, &vi); err != nil {
				return err
			}
			out = append(out, vi)
		}
		return nil
	})
	return out, err
}

// AppendAudit records one audit entry. Failures here are surfaced — a
// change that cannot be audited must not be reported as clean.
func (s *Store) AppendAudit(e AuditEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bktAudit)
		id, _ := audit.NextSequence()
		e.ID = id
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return audit.Put(u64key(id), raw)
	})
}

// ListAudit returns audit entries, newest first, at most limit.
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktAudit).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var e AuditEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

func u64key(id uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], id)
	return k[:]
}

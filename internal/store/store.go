// Package store persists policy versions, the shared candidate, and the
// audit log in an embedded bbolt database.
//
// Decision (build plan §13 OPEN, resolved for v1): bbolt over SQLite.
// The access pattern is versioned blobs + append-only log — a pure-Go
// key/value store fits exactly and keeps builds CGO-free and static.
package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	policyidentity "github.com/detailtech/oss-ngfw/internal/policy"
)

var (
	bktMeta        = []byte("meta")
	bktVersions    = []byte("versions")
	bktVersionInfo = []byte("version_info")
	bktCandidate   = []byte("candidate")
	bktAudit       = []byte("audit")
	bktApprovals   = []byte("approvals")
	bktReports     = []byte("compliance_reports")
	bktSnapshots   = []byte("backup_snapshots")

	keyRunning   = []byte("running")
	keyLastKnown = []byte("last_known_good")
	keyCandidate = []byte("policy")
	keyHAState   = []byte("ha_state")
)

const auditHashPayloadVersion = "openngfw.audit.v1"

// ErrCandidateRevisionConflict is returned when a candidate write used a stale
// optimistic-concurrency token.
var ErrCandidateRevisionConflict = errors.New("candidate revision conflict")

var (
	// ErrChangeApprovalNotFound is returned when a commit references an
	// approval id that does not exist.
	ErrChangeApprovalNotFound = errors.New("change approval not found")
	// ErrChangeApprovalConsumed is returned when a commit attempts to reuse an
	// approval that was already bound to a prepared version.
	ErrChangeApprovalConsumed = errors.New("change approval already consumed")
	// ErrChangeApprovalRevisionMismatch is returned when an approval was issued
	// for a different candidate revision.
	ErrChangeApprovalRevisionMismatch = errors.New("change approval candidate revision mismatch")
)

// VersionInfo is the metadata recorded with each committed version.
type VersionInfo struct {
	ID                uint64            `json:"id"`
	CreatedAt         time.Time         `json:"created_at"`
	Actor             string            `json:"actor"`
	ActorRole         string            `json:"actor_role,omitempty"`
	AuthSource        string            `json:"auth_source,omitempty"`
	Comment           string            `json:"comment"`
	Action            string            `json:"action,omitempty"`
	SourceVersion     uint64            `json:"source_version,omitempty"`
	State             string            `json:"state,omitempty"`
	ArtifactSetSHA256 string            `json:"artifact_set_sha256,omitempty"`
	Artifacts         []VersionArtifact `json:"artifacts,omitempty"`
	LastKnownGood     bool              `json:"-"`
	ActivatedAt       time.Time         `json:"activated_at,omitempty"`
	StateDetail       string            `json:"state_detail,omitempty"`
}

// VersionArtifact is the stable metadata for one rendered engine artifact.
// It deliberately excludes artifact bytes.
type VersionArtifact struct {
	Engine    string `json:"engine"`
	Name      string `json:"name"`
	SizeBytes uint64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// AuditEntry is one append-only audit record.
type AuditEntry struct {
	ID         uint64    `json:"id"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	ActorRole  string    `json:"actor_role,omitempty"`
	AuthSource string    `json:"auth_source,omitempty"`
	Action     string    `json:"action"`
	Detail     string    `json:"detail"`
	Version    uint64    `json:"version,omitempty"`
	// PreviousHash and EntryHash form a tamper-evident hash chain over stable
	// audit fields. Callers do not set these; AppendAudit computes them.
	PreviousHash string `json:"previous_hash"`
	EntryHash    string `json:"entry_hash"`
}

// ChangeApproval is a durable governance approval for one candidate revision.
type ChangeApproval struct {
	ID                   string    `json:"id"`
	CandidateRevision    string    `json:"candidate_revision"`
	Actor                string    `json:"actor"`
	ActorRole            string    `json:"actor_role,omitempty"`
	AuthSource           string    `json:"auth_source,omitempty"`
	Comment              string    `json:"comment"`
	AckRisk              bool      `json:"ack_risk"`
	AckRuntime           bool      `json:"ack_runtime"`
	CreatedAt            time.Time `json:"created_at"`
	Consumed             bool      `json:"consumed,omitempty"`
	ConsumedVersion      uint64    `json:"consumed_version,omitempty"`
	ConsumedAt           time.Time `json:"consumed_at,omitempty"`
	ConsumedBy           string    `json:"consumed_by,omitempty"`
	ConsumedByRole       string    `json:"consumed_by_role,omitempty"`
	ConsumedByAuthSource string    `json:"consumed_by_auth_source,omitempty"`
}

// ChangeApprovalFilter restricts approval queries. Empty fields are ignored.
type ChangeApprovalFilter struct {
	CandidateRevision string
	IncludeConsumed   bool
	Limit             int
}

// HighAvailabilityState is node-local HA control-plane state. It is separate
// from policy version state because it records the local role marker only; it
// must not imply VIP ownership, peer fencing, or connection-state sync.
type HighAvailabilityState struct {
	Role                           string    `json:"role"`
	PreviousRole                   string    `json:"previous_role,omitempty"`
	ActivatedAt                    time.Time `json:"activated_at,omitempty"`
	Actor                          string    `json:"actor,omitempty"`
	ActorRole                      string    `json:"actor_role,omitempty"`
	AuthSource                     string    `json:"auth_source,omitempty"`
	Comment                        string    `json:"comment,omitempty"`
	Source                         string    `json:"source,omitempty"`
	RunningPolicyVersion           uint64    `json:"running_policy_version,omitempty"`
	LastKnownGoodVersion           uint64    `json:"last_known_good_version,omitempty"`
	PeerID                         string    `json:"peer_id,omitempty"`
	PeerLastHeartbeatSeconds       uint64    `json:"peer_last_heartbeat_seconds,omitempty"`
	PreflightPeerPolicyVersion     uint64    `json:"preflight_peer_policy_version,omitempty"`
	PreflightPeerArtifactSetSHA256 string    `json:"preflight_peer_artifact_set_sha256,omitempty"`
	PreflightFailoverState         string    `json:"preflight_failover_state,omitempty"`
	PreflightFailoverEligible      bool      `json:"preflight_failover_eligible,omitempty"`
	FencingClaim                   string    `json:"fencing_claim,omitempty"`
	FencingProvider                string    `json:"fencing_provider,omitempty"`
	FencingEvidenceID              string    `json:"fencing_evidence_id,omitempty"`
	FencingEvidenceAt              time.Time `json:"fencing_evidence_at,omitempty"`
	FencingEvidenceDetail          string    `json:"fencing_evidence_detail,omitempty"`
	TransportClaim                 string    `json:"transport_claim,omitempty"`
	TransportVIP                   string    `json:"transport_vip,omitempty"`
	TransportInterface             string    `json:"transport_interface,omitempty"`
	TransportRoutes                []string  `json:"transport_routes,omitempty"`
	TransportGARPState             string    `json:"transport_garp_state,omitempty"`
	TransportGARPDetail            string    `json:"transport_garp_detail,omitempty"`
	TransportNeighborState         string    `json:"transport_neighbor_state,omitempty"`
	TransportNeighborDetail        string    `json:"transport_neighbor_detail,omitempty"`
	TransportEvidenceAt            time.Time `json:"transport_evidence_at,omitempty"`
	TransportEvidenceDetail        string    `json:"transport_evidence_detail,omitempty"`
	ConntrackSyncClaim             string    `json:"conntrack_sync_claim,omitempty"`
	ConntrackSyncProvider          string    `json:"conntrack_sync_provider,omitempty"`
	ConntrackSyncEvidenceID        string    `json:"conntrack_sync_evidence_id,omitempty"`
	ConntrackSyncEvidenceAt        time.Time `json:"conntrack_sync_evidence_at,omitempty"`
	ConntrackSyncEvidenceDetail    string    `json:"conntrack_sync_evidence_detail,omitempty"`
}

// AuditFilter restricts audit-log queries. Empty fields are ignored.
type AuditFilter struct {
	Limit   int
	Actor   string
	Action  string
	Version uint64
	Since   time.Time
	Until   time.Time
	Query   string
}

// ActorIdentity records the control-plane identity metadata used for
// version history and audit events.
type ActorIdentity struct {
	Name       string
	Role       string
	AuthSource string
}

// AuditIntegrityReport is an operator-visible summary of the audit hash chain.
type AuditIntegrityReport struct {
	EntryCount      int
	LatestEntryHash string
}

// ComplianceReportRecord is a retained, unsigned server-side compliance
// report generated from current audit/version/log state.
type ComplianceReportRecord struct {
	ID                  string            `json:"id"`
	SchemaVersion       string            `json:"schema_version"`
	GeneratedAt         time.Time         `json:"generated_at"`
	GeneratedBy         string            `json:"generated_by"`
	GeneratedByRole     string            `json:"generated_by_role,omitempty"`
	AuthSource          string            `json:"auth_source,omitempty"`
	Profile             string            `json:"profile"`
	ProfileLabel        string            `json:"profile_label"`
	Title               string            `json:"title"`
	Source              string            `json:"source"`
	Unsigned            bool              `json:"unsigned"`
	Signed              bool              `json:"signed"`
	ServerStored        bool              `json:"server_stored"`
	RetentionEnforced   bool              `json:"retention_enforced"`
	AuditEntryCount     int               `json:"audit_entry_count"`
	VersionCount        int               `json:"version_count"`
	SystemLogEntryCount int               `json:"system_log_entry_count"`
	EntryHashes         []string          `json:"entry_hashes,omitempty"`
	LatestAuditHash     string            `json:"latest_audit_hash,omitempty"`
	Filters             map[string]string `json:"filters,omitempty"`
	PayloadSHA256       string            `json:"payload_sha256"`
	Payload             []byte            `json:"payload,omitempty"`
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
		for _, b := range [][]byte{bktMeta, bktVersions, bktVersionInfo, bktCandidate, bktAudit, bktApprovals, bktReports, bktSnapshots} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		audit := tx.Bucket(bktAudit)
		if err := backfillAuditHashes(audit); err != nil {
			return err
		}
		if _, err := auditTipHash(audit); err != nil {
			return err
		}
		return backfillLastKnownGood(tx)
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
	p, _, _ = normalizePolicyIdentities(p)
	raw, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal candidate: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktCandidate).Put(keyCandidate, raw)
	})
}

// SetCandidateWithAudit replaces the candidate policy and records the change
// in the same transaction. If the audit chain cannot be extended, the candidate
// mutation is rolled back with the transaction.
func (s *Store) SetCandidateWithAudit(p *openngfwv1.Policy, e AuditEntry) error {
	_, err := s.SetCandidateWithAuditIfRevision(p, "", e)
	return err
}

// SetCandidateWithAuditIfRevision replaces the candidate policy when expected
// is empty or matches the current candidate revision, and records the audit
// entry in the same transaction.
func (s *Store) SetCandidateWithAuditIfRevision(p *openngfwv1.Policy, expected string, e AuditEntry) (string, error) {
	p, ruleReport, itemReport := normalizePolicyIdentities(p)
	e.Detail = appendPolicyIdentityAuditDetail(e.Detail, ruleReport, itemReport)
	raw, err := proto.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal candidate: %w", err)
	}
	nextRevision := candidateBlobRevision(raw)
	err = s.db.Update(func(tx *bolt.Tx) error {
		currentRevision := candidateRevisionTx(tx)
		if expected != "" && expected != currentRevision {
			return ErrCandidateRevisionConflict
		}
		if err := tx.Bucket(bktCandidate).Put(keyCandidate, raw); err != nil {
			return err
		}
		return appendAuditTx(tx, e)
	})
	if err != nil {
		return "", err
	}
	return nextRevision, nil
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

// CandidateRevision returns the current optimistic-concurrency token for the
// candidate workspace. A missing candidate is still represented by a stable
// token scoped to the current running version.
func (s *Store) CandidateRevision() (revision string, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		revision = candidateRevisionTx(tx)
		return nil
	})
	return revision, err
}

// CreateChangeApproval records one approval for the exact candidate revision
// presented to the approver. The approval and audit entry are committed in the
// same transaction.
func (s *Store) CreateChangeApproval(candidateRevision string, identity ActorIdentity, comment string, ackRisk, ackRuntime bool) (ChangeApproval, error) {
	candidateRevision = strings.TrimSpace(candidateRevision)
	comment = strings.TrimSpace(comment)
	if candidateRevision == "" {
		return ChangeApproval{}, fmt.Errorf("candidate revision is required")
	}
	if comment == "" {
		return ChangeApproval{}, fmt.Errorf("approval comment is required")
	}
	var approval ChangeApproval
	err := s.db.Update(func(tx *bolt.Tx) error {
		currentRevision := candidateRevisionTx(tx)
		if candidateRevision != currentRevision {
			return ErrChangeApprovalRevisionMismatch
		}
		approvals := tx.Bucket(bktApprovals)
		id, err := approvals.NextSequence()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		approval = ChangeApproval{
			ID:                fmt.Sprintf("%d", id),
			CandidateRevision: candidateRevision,
			Actor:             identity.Name,
			ActorRole:         identity.Role,
			AuthSource:        identity.AuthSource,
			Comment:           comment,
			AckRisk:           ackRisk,
			AckRuntime:        ackRuntime,
			CreatedAt:         now,
		}
		raw, err := json.Marshal(approval)
		if err != nil {
			return err
		}
		if err := approvals.Put(u64key(id), raw); err != nil {
			return err
		}
		return appendAuditTx(tx, AuditEntry{
			Time:       now,
			Actor:      identity.Name,
			ActorRole:  identity.Role,
			AuthSource: identity.AuthSource,
			Action:     "change-approval-create",
			Detail:     fmt.Sprintf("approval %s for candidate %s: %s", approval.ID, candidateRevision, comment),
		})
	})
	return approval, err
}

// ListChangeApprovals returns approval records newest first.
func (s *Store) ListChangeApprovals(filter ChangeApprovalFilter) ([]ChangeApproval, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []ChangeApproval
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktApprovals).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var approval ChangeApproval
			if err := json.Unmarshal(v, &approval); err != nil {
				return err
			}
			if filter.CandidateRevision != "" && approval.CandidateRevision != filter.CandidateRevision {
				continue
			}
			if approval.Consumed && !filter.IncludeConsumed {
				continue
			}
			out = append(out, approval)
		}
		return nil
	})
	return out, err
}

// ConsumeChangeApproval binds an existing approval to a prepared version. It is
// used by tests and reconciliation helpers; the live commit path consumes the
// approval inside PreparePolicyApplyWithIdentityAndApproval so the durable
// intent and approval consumption are atomic.
func (s *Store) ConsumeChangeApproval(id, candidateRevision string, identity ActorIdentity, version uint64) (ChangeApproval, error) {
	var approval ChangeApproval
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		approval, err = consumeChangeApprovalTx(tx, id, candidateRevision, identity, version, time.Now().UTC())
		return err
	})
	return approval, err
}

func candidateRevisionTx(tx *bolt.Tx) string {
	raw := tx.Bucket(bktCandidate).Get(keyCandidate)
	if raw != nil {
		return candidateBlobRevision(raw)
	}
	var running uint64
	if cur := tx.Bucket(bktMeta).Get(keyRunning); len(cur) == 8 {
		running = binary.BigEndian.Uint64(cur)
	}
	return fmt.Sprintf("none:%d", running)
}

func candidateBlobRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func appendRuleIdentityAuditDetail(detail string, report policyidentity.RuleIdentityReport) string {
	if !report.Changed() {
		return detail
	}
	suffix := fmt.Sprintf("rule-id-backfill added=%d normalized=%d deduped=%d", report.Added, report.Normalized, report.Deduped)
	if strings.TrimSpace(detail) == "" {
		return suffix
	}
	return detail + "; " + suffix
}

func appendPolicyItemIdentityAuditDetail(detail string, report policyidentity.PolicyItemIdentityReport) string {
	if !report.Changed() {
		return detail
	}
	suffix := fmt.Sprintf("policy-item-id-backfill host_input_added=%d host_input_normalized=%d host_input_deduped=%d source_nat_added=%d source_nat_normalized=%d source_nat_deduped=%d destination_nat_added=%d destination_nat_normalized=%d destination_nat_deduped=%d",
		report.HostInputAdded,
		report.HostInputNormalized,
		report.HostInputDeduped,
		report.SourceNatAdded,
		report.SourceNatNormalized,
		report.SourceNatDeduped,
		report.DestinationNatAdded,
		report.DestinationNatNormalized,
		report.DestinationNatDeduped,
	)
	if strings.TrimSpace(detail) == "" {
		return suffix
	}
	return detail + "; " + suffix
}

func appendPolicyIdentityAuditDetail(detail string, ruleReport policyidentity.RuleIdentityReport, itemReport policyidentity.PolicyItemIdentityReport) string {
	detail = appendRuleIdentityAuditDetail(detail, ruleReport)
	return appendPolicyItemIdentityAuditDetail(detail, itemReport)
}

func normalizePolicyIdentities(p *openngfwv1.Policy) (*openngfwv1.Policy, policyidentity.RuleIdentityReport, policyidentity.PolicyItemIdentityReport) {
	p, ruleReport := policyidentity.NormalizeRuleIDs(p)
	p, itemReport := policyidentity.NormalizePolicyItemIDs(p)
	return p, ruleReport, itemReport
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
// candidate, and returns the new version id. It is an immediate store-only
// transition used by bootstrap/tests; live engine apply paths should use
// PreparePolicyApplyWithIdentity followed by ActivatePreparedVersion so a
// durable version and audit intent exist before runtime state changes.
func (s *Store) CommitVersion(p *openngfwv1.Policy, actor, comment string) (uint64, error) {
	return s.CommitVersionWithIdentity(p, ActorIdentity{Name: actor}, comment)
}

// CommitVersionWithIdentity records p as running with full actor metadata.
func (s *Store) CommitVersionWithIdentity(p *openngfwv1.Policy, identity ActorIdentity, comment string) (uint64, error) {
	p, ruleReport, itemReport := normalizePolicyIdentities(p)
	comment = appendPolicyIdentityAuditDetail(comment, ruleReport, itemReport)
	raw, err := proto.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("marshal policy: %w", err)
	}
	var id uint64
	err = s.db.Update(func(tx *bolt.Tx) error {
		versions := tx.Bucket(bktVersions)
		id, err = versions.NextSequence()
		if err != nil {
			return err
		}
		key := u64key(id)
		if err := versions.Put(key, raw); err != nil {
			return err
		}
		now := time.Now().UTC()
		info, err := json.Marshal(VersionInfo{
			ID: id, CreatedAt: now,
			Actor: identity.Name, ActorRole: identity.Role, AuthSource: identity.AuthSource,
			Comment:     comment,
			Action:      "bootstrap",
			State:       "active",
			ActivatedAt: now,
			StateDetail: "Store-only version activated as last-known-good.",
		})
		if err != nil {
			return err
		}
		if err := tx.Bucket(bktVersionInfo).Put(key, info); err != nil {
			return err
		}
		if err := tx.Bucket(bktMeta).Put(keyRunning, key); err != nil {
			return err
		}
		if err := tx.Bucket(bktMeta).Put(keyLastKnown, key); err != nil {
			return err
		}
		return tx.Bucket(bktCandidate).Delete(keyCandidate)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// PreparePolicyApplyWithIdentity persists the target policy as a historical
// version and appends an audit intent in the same transaction. It deliberately
// does not update the running pointer or clear the candidate; callers should
// only activate the prepared version after runtime engines apply successfully.
func (s *Store) PreparePolicyApplyWithIdentity(p *openngfwv1.Policy, identity ActorIdentity, action, comment string, artifacts []VersionArtifact, sourceVersion uint64) (uint64, error) {
	return s.PreparePolicyApplyWithIdentityAndApproval(p, identity, action, comment, artifacts, sourceVersion, "", "")
}

// PreparePolicyApplyWithIdentityAndApproval persists the target policy as a
// prepared version, optionally consumes a matching approval, and appends the
// audit intent in one transaction.
func (s *Store) PreparePolicyApplyWithIdentityAndApproval(p *openngfwv1.Policy, identity ActorIdentity, action, comment string, artifacts []VersionArtifact, sourceVersion uint64, approvalID, candidateRevision string) (uint64, error) {
	p, ruleReport, itemReport := normalizePolicyIdentities(p)
	comment = appendPolicyIdentityAuditDetail(comment, ruleReport, itemReport)
	raw, err := proto.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("marshal policy: %w", err)
	}
	artifacts = normalizeVersionArtifacts(artifacts)
	var id uint64
	err = s.db.Update(func(tx *bolt.Tx) error {
		versions := tx.Bucket(bktVersions)
		id, err = versions.NextSequence()
		if err != nil {
			return err
		}
		key := u64key(id)
		if err := versions.Put(key, raw); err != nil {
			return err
		}
		info, err := json.Marshal(VersionInfo{
			ID: id, CreatedAt: time.Now().UTC(),
			Actor: identity.Name, ActorRole: identity.Role, AuthSource: identity.AuthSource,
			Comment:           comment,
			Action:            action,
			SourceVersion:     sourceVersion,
			State:             "prepared",
			ArtifactSetSHA256: versionArtifactSetHash(artifacts),
			Artifacts:         artifacts,
			StateDetail:       "Durable intent recorded; waiting for runtime engine apply.",
		})
		if err != nil {
			return err
		}
		if err := tx.Bucket(bktVersionInfo).Put(key, info); err != nil {
			return err
		}
		if strings.TrimSpace(approvalID) != "" {
			if _, err := consumeChangeApprovalTx(tx, approvalID, candidateRevision, identity, id, time.Now().UTC()); err != nil {
				return err
			}
		}
		return appendAuditTx(tx, AuditEntry{
			Actor:      identity.Name,
			ActorRole:  identity.Role,
			AuthSource: identity.AuthSource,
			Action:     action + "-intent",
			Detail:     comment,
			Version:    id,
		})
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ActivatePreparedVersion marks an already prepared version as running, clears
// the candidate, and records the success audit entry in one transaction.
func (s *Store) ActivatePreparedVersion(id uint64, identity ActorIdentity, action, comment string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := u64key(id)
		if raw := tx.Bucket(bktVersions).Get(key); raw == nil {
			return fmt.Errorf("prepared version %d not found", id)
		}
		rawInfo := tx.Bucket(bktVersionInfo).Get(key)
		if rawInfo == nil {
			return fmt.Errorf("prepared version %d metadata not found", id)
		}
		var info VersionInfo
		if err := json.Unmarshal(rawInfo, &info); err != nil {
			return err
		}
		now := time.Now().UTC()
		info.State = "active"
		info.ActivatedAt = now
		info.StateDetail = "Runtime engine apply completed; version activated as last-known-good."
		encoded, err := json.Marshal(info)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bktVersionInfo).Put(key, encoded); err != nil {
			return err
		}
		if err := tx.Bucket(bktMeta).Put(keyRunning, key); err != nil {
			return err
		}
		if err := tx.Bucket(bktMeta).Put(keyLastKnown, key); err != nil {
			return err
		}
		if err := tx.Bucket(bktCandidate).Delete(keyCandidate); err != nil {
			return err
		}
		return appendAuditTx(tx, AuditEntry{
			Actor:      identity.Name,
			ActorRole:  identity.Role,
			AuthSource: identity.AuthSource,
			Action:     action,
			Detail:     comment,
			Version:    id,
		})
	})
}

// MarkVersionState updates recovery metadata for a prepared version that could
// not be activated. It is best-effort from the caller's perspective, but this
// method itself returns failures so tests and future reconciliation jobs can
// detect broken metadata writes.
func (s *Store) MarkVersionState(id uint64, state, detail string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := u64key(id)
		raw := tx.Bucket(bktVersionInfo).Get(key)
		if raw == nil {
			return fmt.Errorf("version %d metadata not found", id)
		}
		var info VersionInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return err
		}
		info.State = strings.TrimSpace(state)
		info.StateDetail = strings.TrimSpace(detail)
		encoded, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return tx.Bucket(bktVersionInfo).Put(key, encoded)
	})
}

// GetVersionInfo returns recovery/version metadata for one policy version.
func (s *Store) GetVersionInfo(id uint64) (VersionInfo, error) {
	var info VersionInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		key := u64key(id)
		raw := tx.Bucket(bktVersionInfo).Get(key)
		if raw == nil {
			return fmt.Errorf("version %d metadata not found", id)
		}
		if err := json.Unmarshal(raw, &info); err != nil {
			return err
		}
		if info.State == "" {
			info.State = "unknown"
		}
		info.LastKnownGood = info.ID != 0 && info.ID == metaVersionID(tx.Bucket(bktMeta), keyLastKnown)
		return nil
	})
	return info, err
}

// ListVersions returns version metadata, newest first, at most limit.
func (s *Store) ListVersions(limit int) ([]VersionInfo, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []VersionInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		lkgID := metaVersionID(tx.Bucket(bktMeta), keyLastKnown)
		c := tx.Bucket(bktVersionInfo).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var vi VersionInfo
			if err := json.Unmarshal(v, &vi); err != nil {
				return err
			}
			if vi.State == "" {
				vi.State = "unknown"
			}
			vi.LastKnownGood = vi.ID != 0 && vi.ID == lkgID
			out = append(out, vi)
		}
		return nil
	})
	return out, err
}

func metaVersionID(meta *bolt.Bucket, key []byte) uint64 {
	raw := meta.Get(key)
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// GetHighAvailabilityState returns the persisted node-local HA marker.
func (s *Store) GetHighAvailabilityState() (HighAvailabilityState, bool, error) {
	var state HighAvailabilityState
	ok := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bktMeta).Get(keyHAState)
		if raw == nil {
			return nil
		}
		ok = true
		return json.Unmarshal(raw, &state)
	})
	return state, ok, err
}

// SetHighAvailabilityState persists the node-local HA marker.
func (s *Store) SetHighAvailabilityState(state HighAvailabilityState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put(keyHAState, raw)
	})
}

// SetHighAvailabilityStateWithAudit persists the node-local HA marker and
// records the success audit entry in one transaction.
func (s *Store) SetHighAvailabilityStateWithAudit(state HighAvailabilityState, e AuditEntry) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bktMeta).Put(keyHAState, raw); err != nil {
			return err
		}
		return appendAuditTx(tx, e)
	})
}

func backfillLastKnownGood(tx *bolt.Tx) error {
	meta := tx.Bucket(bktMeta)
	if meta.Get(keyLastKnown) != nil {
		return nil
	}
	running := meta.Get(keyRunning)
	if len(running) != 8 {
		return nil
	}
	if raw := tx.Bucket(bktVersions).Get(running); raw == nil {
		return nil
	}
	if err := meta.Put(keyLastKnown, running); err != nil {
		return err
	}
	rawInfo := tx.Bucket(bktVersionInfo).Get(running)
	if rawInfo == nil {
		return nil
	}
	var info VersionInfo
	if err := json.Unmarshal(rawInfo, &info); err != nil {
		return err
	}
	changed := false
	if info.State == "" {
		info.State = "active"
		changed = true
	}
	if info.ActivatedAt.IsZero() && !info.CreatedAt.IsZero() {
		info.ActivatedAt = info.CreatedAt
		changed = true
	}
	if info.StateDetail == "" {
		info.StateDetail = "Recovered last-known-good pointer from the running policy version."
		changed = true
	}
	if !changed {
		return nil
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return tx.Bucket(bktVersionInfo).Put(running, encoded)
}

func normalizeVersionArtifacts(artifacts []VersionArtifact) []VersionArtifact {
	out := make([]VersionArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		artifact.Engine = strings.TrimSpace(artifact.Engine)
		artifact.Name = strings.TrimSpace(artifact.Name)
		artifact.SHA256 = strings.TrimSpace(artifact.SHA256)
		if artifact.Engine == "" && artifact.Name == "" && artifact.SHA256 == "" && artifact.SizeBytes == 0 {
			continue
		}
		out = append(out, artifact)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func versionArtifactSetHash(artifacts []VersionArtifact) string {
	if len(artifacts) == 0 {
		return ""
	}
	h := sha256.New()
	for _, artifact := range normalizeVersionArtifacts(artifacts) {
		_, _ = h.Write([]byte(artifact.Engine))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(artifact.Name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(artifact.SHA256))
		_, _ = h.Write([]byte{0})
		_, _ = fmt.Fprintf(h, "%d", artifact.SizeBytes)
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// AppendAudit records one audit entry. Failures here are surfaced — a
// change that cannot be audited must not be reported as clean.
func (s *Store) AppendAudit(e AuditEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return appendAuditTx(tx, e)
	})
}

func appendAuditTx(tx *bolt.Tx, e AuditEntry) error {
	audit := tx.Bucket(bktAudit)
	previousHash, err := auditTipHash(audit)
	if err != nil {
		return err
	}
	id, err := audit.NextSequence()
	if err != nil {
		return err
	}
	e.ID = id
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.PreviousHash = previousHash
	e.EntryHash = ""
	entryHash, err := auditEntryHash(e)
	if err != nil {
		return err
	}
	e.EntryHash = entryHash
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return audit.Put(u64key(id), raw)
}

// ListAudit returns audit entries, newest first, at most limit.
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	return s.ListAuditFiltered(AuditFilter{Limit: limit})
}

// ListAuditFiltered returns matching audit entries, newest first.
func (s *Store) ListAuditFiltered(filter AuditFilter) ([]AuditEntry, error) {
	limit := filter.Limit
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
			if !auditMatches(e, filter) {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// VerifyAuditIntegrity validates the persisted audit hash chain from oldest to newest.
func (s *Store) VerifyAuditIntegrity() error {
	return s.db.View(func(tx *bolt.Tx) error {
		_, err := auditTipHash(tx.Bucket(bktAudit))
		return err
	})
}

// AuditIntegrity validates the audit hash chain and returns summary evidence.
func (s *Store) AuditIntegrity() (AuditIntegrityReport, error) {
	var report AuditIntegrityReport
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		report, err = auditIntegrityReport(tx.Bucket(bktAudit))
		return err
	})
	return report, err
}

// SaveComplianceReport stores an unsigned generated compliance report. The
// record ID is caller-assigned so the API can return it before export.
func (s *Store) SaveComplianceReport(record ComplianceReportRecord) error {
	record.ID = strings.TrimSpace(record.ID)
	if record.ID == "" {
		return errors.New("compliance report id is required")
	}
	if record.GeneratedAt.IsZero() {
		record.GeneratedAt = time.Now().UTC()
	}
	if len(record.Payload) == 0 {
		return errors.New("compliance report payload is required")
	}
	sum := sha256.Sum256(record.Payload)
	record.PayloadSHA256 = fmt.Sprintf("%x", sum[:])
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return tx.Bucket(bktReports).Put([]byte(record.ID), raw)
	})
}

// DeleteComplianceReport removes one retained compliance report by ID.
func (s *Store) DeleteComplianceReport(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("compliance report id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bktReports)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("compliance report %q not found", id)
		}
		return b.Delete([]byte(id))
	})
}

// ListComplianceReports returns newest reports first. Payload bytes are omitted
// from list results so report exports stay explicit.
func (s *Store) ListComplianceReports(limit int) ([]ComplianceReportRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []ComplianceReportRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bktReports).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var record ComplianceReportRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			record.Payload = nil
			out = append(out, record)
		}
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].GeneratedAt.After(out[j].GeneratedAt)
		})
		return nil
	})
	return out, err
}

// GetComplianceReport returns one retained report including its payload.
func (s *Store) GetComplianceReport(id string) (ComplianceReportRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return ComplianceReportRecord{}, errors.New("compliance report id is required")
	}
	var record ComplianceReportRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bktReports).Get([]byte(id))
		if raw == nil {
			return fmt.Errorf("compliance report %q not found", id)
		}
		return json.Unmarshal(raw, &record)
	})
	return record, err
}

func auditMatches(e AuditEntry, filter AuditFilter) bool {
	if filter.Actor != "" && !containsFold(e.Actor, filter.Actor) {
		return false
	}
	if filter.Action != "" && !strings.EqualFold(e.Action, filter.Action) {
		return false
	}
	if filter.Version != 0 && e.Version != filter.Version {
		return false
	}
	if !filter.Since.IsZero() && e.Time.Before(filter.Since) {
		return false
	}
	if !filter.Until.IsZero() && e.Time.After(filter.Until) {
		return false
	}
	if filter.Query != "" {
		haystack := strings.Join([]string{
			e.Actor,
			e.ActorRole,
			e.AuthSource,
			e.Action,
			e.Detail,
			fmt.Sprintf("%d", e.Version),
		}, "\n")
		if !containsFold(haystack, filter.Query) {
			return false
		}
	}
	return true
}

func consumeChangeApprovalTx(tx *bolt.Tx, id, candidateRevision string, identity ActorIdentity, version uint64, consumedAt time.Time) (ChangeApproval, error) {
	id = strings.TrimSpace(id)
	candidateRevision = strings.TrimSpace(candidateRevision)
	if id == "" {
		return ChangeApproval{}, ErrChangeApprovalNotFound
	}
	parsedID, err := parseApprovalID(id)
	if err != nil {
		return ChangeApproval{}, ErrChangeApprovalNotFound
	}
	approvals := tx.Bucket(bktApprovals)
	raw := approvals.Get(u64key(parsedID))
	if raw == nil {
		return ChangeApproval{}, ErrChangeApprovalNotFound
	}
	var approval ChangeApproval
	if err := json.Unmarshal(raw, &approval); err != nil {
		return ChangeApproval{}, err
	}
	if approval.Consumed {
		return ChangeApproval{}, ErrChangeApprovalConsumed
	}
	if candidateRevision == "" || approval.CandidateRevision != candidateRevision {
		return ChangeApproval{}, ErrChangeApprovalRevisionMismatch
	}
	approval.Consumed = true
	approval.ConsumedVersion = version
	approval.ConsumedAt = consumedAt
	approval.ConsumedBy = identity.Name
	approval.ConsumedByRole = identity.Role
	approval.ConsumedByAuthSource = identity.AuthSource
	encoded, err := json.Marshal(approval)
	if err != nil {
		return ChangeApproval{}, err
	}
	if err := approvals.Put(u64key(parsedID), encoded); err != nil {
		return ChangeApproval{}, err
	}
	return approval, nil
}

func parseApprovalID(id string) (uint64, error) {
	var parsed uint64
	for _, r := range id {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid approval id")
		}
		parsed = parsed*10 + uint64(r-'0')
	}
	if parsed == 0 {
		return 0, fmt.Errorf("invalid approval id")
	}
	return parsed, nil
}

type auditHashPayload struct {
	Schema       string `json:"schema"`
	ID           uint64 `json:"id"`
	Time         string `json:"time"`
	Actor        string `json:"actor"`
	ActorRole    string `json:"actor_role"`
	AuthSource   string `json:"auth_source"`
	Action       string `json:"action"`
	Detail       string `json:"detail"`
	Version      uint64 `json:"version"`
	PreviousHash string `json:"previous_hash"`
}

func backfillAuditHashes(audit *bolt.Bucket) error {
	type pendingUpdate struct {
		key []byte
		raw []byte
	}

	var updates []pendingUpdate
	previousHash := ""
	c := audit.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var e AuditEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return fmt.Errorf("decode audit entry for hash migration: %w", err)
		}
		keyID, err := auditKeyID(k)
		if err != nil {
			return err
		}
		if e.ID == 0 {
			e.ID = keyID
		}
		if e.EntryHash != "" {
			previousHash = e.EntryHash
			continue
		}
		e.PreviousHash = previousHash
		e.EntryHash = ""
		entryHash, err := auditEntryHash(e)
		if err != nil {
			return err
		}
		e.EntryHash = entryHash
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		keyCopy := append([]byte(nil), k...)
		updates = append(updates, pendingUpdate{key: keyCopy, raw: raw})
		previousHash = e.EntryHash
	}

	for _, update := range updates {
		if err := audit.Put(update.key, update.raw); err != nil {
			return err
		}
	}
	return nil
}

func auditTipHash(audit *bolt.Bucket) (string, error) {
	report, err := auditIntegrityReport(audit)
	if err != nil {
		return "", err
	}
	return report.LatestEntryHash, nil
}

func auditIntegrityReport(audit *bolt.Bucket) (AuditIntegrityReport, error) {
	var report AuditIntegrityReport
	previousHash := ""
	c := audit.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		keyID, err := auditKeyID(k)
		if err != nil {
			return report, err
		}
		var e AuditEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return report, fmt.Errorf("decode audit entry %d: %w", keyID, err)
		}
		if e.ID != keyID {
			return report, fmt.Errorf("audit integrity entry %d: key id %d does not match entry id %d", keyID, keyID, e.ID)
		}
		if e.PreviousHash != previousHash {
			return report, fmt.Errorf("audit integrity entry %d: previous hash mismatch", e.ID)
		}
		if e.EntryHash == "" {
			return report, fmt.Errorf("audit integrity entry %d: missing entry hash", e.ID)
		}
		expectedHash, err := auditEntryHash(e)
		if err != nil {
			return report, err
		}
		if e.EntryHash != expectedHash {
			return report, fmt.Errorf("audit integrity entry %d: entry hash mismatch", e.ID)
		}
		previousHash = e.EntryHash
		report.EntryCount++
	}
	report.LatestEntryHash = previousHash
	return report, nil
}

func auditEntryHash(e AuditEntry) (string, error) {
	payload := auditHashPayload{
		Schema:       auditHashPayloadVersion,
		ID:           e.ID,
		Time:         e.Time.UTC().Round(0).Format(time.RFC3339Nano),
		Actor:        e.Actor,
		ActorRole:    e.ActorRole,
		AuthSource:   e.AuthSource,
		Action:       e.Action,
		Detail:       e.Detail,
		Version:      e.Version,
		PreviousHash: e.PreviousHash,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:]), nil
}

func auditKeyID(k []byte) (uint64, error) {
	if len(k) != 8 {
		return 0, fmt.Errorf("audit integrity: invalid key length %d", len(k))
	}
	return binary.BigEndian.Uint64(k), nil
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func u64key(id uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], id)
	return k[:]
}

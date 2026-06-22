package apiserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/store"
)

const (
	investigationCaseSchema       = "phragma.investigation.case-record.v1"
	investigationCaseAPISchema    = "phragma.investigation.case-api.v1"
	investigationSynthesisSchema  = "phragma.investigation.server-synthesis.v1"
	defaultInvestigationCaseLimit = 50
	maxInvestigationCaseLimit     = 100
	maxInvestigationCaseRecords   = 100
	maxInvestigationEvidenceItems = 200
	maxInvestigationStringLength  = 8192
	maxInvestigationTargetRoute   = 1000
	maxInvestigationSynthesisFlow = 12
)

var (
	investigationCaseFileMu sync.Mutex
	investigationCaseIDRE   = regexp.MustCompile(`^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$`)
	secretLikeRE            = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|secret|client[_-]?secret)\s*[:=]\s*[^\s"',;}&]+)`)
	localPathLikeRE         = regexp.MustCompile(`(?i)(^|[\s"'({=,;])/(?:var/lib|var/log(?:/openngfw)?|etc(?:/openngfw|/phragma)?|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+|opt/[^'"\s,;}]+|data/[^'"\s,;}]+)[^'"\s,;}]*`)
)

// InvestigationCaseHandler serves the bounded JSON custody API used by the
// WebUI while the canonical protobuf surface catches up.
func (s *SystemService) InvestigationCaseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/investigation/cases")
		switch {
		case path == "" || path == "/":
			switch r.Method {
			case http.MethodGet:
				s.handleListInvestigationCases(w, r)
			case http.MethodPost:
				s.handleCreateInvestigationCase(w, r)
			default:
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
			}
		case strings.HasSuffix(path, "/evidence"):
			if r.Method != http.MethodPost {
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/evidence")
			s.handleAddInvestigationEvidence(w, r, id)
		default:
			switch r.Method {
			case http.MethodGet:
				s.handleGetInvestigationCase(w, r, strings.TrimPrefix(path, "/"))
			case http.MethodPatch:
				s.handlePatchInvestigationCase(w, r, strings.TrimPrefix(path, "/"))
			default:
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
		}
	})
}

func (s *SystemService) handleListInvestigationCases(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.investigationCaseIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	limit := investigationCaseLimit(r.URL.Query().Get("limit"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	index, err := s.readInvestigationCaseIndex()
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "CASE_STORE_READ_FAILED", err.Error())
		return
	}
	records := append([]investigationCaseRecord(nil), index.Cases...)
	sort.Slice(records, func(i, j int) bool {
		return records[i].UpdatedAt > records[j].UpdatedAt
	})
	summaries := make([]investigationCaseSummary, 0, min(limit, len(records)))
	for _, record := range records {
		if state != "" && !strings.EqualFold(record.State, state) {
			continue
		}
		record.refreshSummary()
		summaries = append(summaries, record.summary())
		if len(summaries) >= limit {
			break
		}
	}
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": investigationCaseAPISchema,
		"cases":         summaries,
		"hasMore":       len(summaries) < matchingInvestigationCaseCount(records, state),
	})
}

func (s *SystemService) handleGetInvestigationCase(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := s.investigationCaseIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	id, err := normalizeInvestigationCaseID(id)
	if err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_CASE_ID", err.Error())
		return
	}
	index, err := s.readInvestigationCaseIndex()
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "CASE_STORE_READ_FAILED", err.Error())
		return
	}
	record, ok := index.find(id)
	if !ok {
		investigationJSONError(w, http.StatusNotFound, "CASE_NOT_FOUND", "investigation case not found")
		return
	}
	record.refreshSummary()
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": investigationCaseAPISchema,
		"case":          record,
	})
}

func (s *SystemService) handleCreateInvestigationCase(w http.ResponseWriter, r *http.Request) {
	id, ok := s.investigationCaseIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "AUDIT_STORE_UNAVAILABLE", "audit store is required for investigation custody")
		return
	}
	var req createInvestigationCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	now := time.Now().UTC()
	record := investigationCaseRecord{
		SchemaVersion: investigationCaseSchema,
		ID:            newInvestigationCaseID(now),
		Title:         normalizeInvestigationTitle(req.Title, req.Packet),
		State:         "open",
		CreatedAt:     now.Format(time.RFC3339Nano),
		UpdatedAt:     now.Format(time.RFC3339Nano),
		CreatedBy:     id.Name,
		CreatedByRole: id.Role.String(),
		AuthSource:    id.AuthSource,
		Packet:        sanitizeInvestigationMap(req.Packet),
		Evidence:      normalizeInvestigationEvidence(req.Evidence, now, id),
	}
	record.refreshSummary()
	if err := s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
		index.Cases = append([]investigationCaseRecord{record}, index.Cases...)
		if len(index.Cases) > maxInvestigationCaseRecords {
			index.Cases = index.Cases[:maxInvestigationCaseRecords]
		}
		return nil
	}); err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "CASE_STORE_WRITE_FAILED", err.Error())
		return
	}
	if err := s.auditInvestigationCase(id, "investigation-case-create", record.ID, fmt.Sprintf("title=%q evidence_count=%d", record.Title, len(record.Evidence))); err != nil {
		_ = s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
			index.remove(record.ID)
			return nil
		})
		investigationJSONError(w, http.StatusInternalServerError, "CASE_AUDIT_FAILED", err.Error())
		return
	}
	w.Header().Set("Location", "/v1/investigation/cases/"+record.ID)
	investigationWriteJSON(w, http.StatusCreated, map[string]any{
		"schemaVersion": investigationCaseAPISchema,
		"case":          record,
	})
}

func (s *SystemService) handleAddInvestigationEvidence(w http.ResponseWriter, r *http.Request, caseID string) {
	id, ok := s.investigationCaseIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "AUDIT_STORE_UNAVAILABLE", "audit store is required for investigation custody")
		return
	}
	caseID, err := normalizeInvestigationCaseID(caseID)
	if err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_CASE_ID", err.Error())
		return
	}
	var req addInvestigationEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	if len(req.Evidence) == 0 {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_EVIDENCE", "evidence must include at least one item")
		return
	}
	now := time.Now().UTC()
	var updated investigationCaseRecord
	var previous investigationCaseRecord
	if err := s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
		record, ok := index.find(caseID)
		if !ok {
			return investigationCaseNotFound{}
		}
		previous = record
		next := normalizeInvestigationEvidence(req.Evidence, now, id)
		if len(record.Evidence)+len(next) > maxInvestigationEvidenceItems {
			return investigationEvidenceLimitExceeded{}
		}
		record.Evidence = append(record.Evidence, next...)
		record.UpdatedAt = now.Format(time.RFC3339Nano)
		record.refreshSummary()
		updated = record
		index.replace(record)
		return nil
	}); err != nil {
		if errors.As(err, &investigationCaseNotFound{}) {
			investigationJSONError(w, http.StatusNotFound, "CASE_NOT_FOUND", "investigation case not found")
			return
		}
		if errors.As(err, &investigationEvidenceLimitExceeded{}) {
			investigationJSONError(w, http.StatusRequestEntityTooLarge, "EVIDENCE_LIMIT_EXCEEDED", fmt.Sprintf("case evidence limit exceeded: max %d items", maxInvestigationEvidenceItems))
			return
		}
		investigationJSONError(w, http.StatusInternalServerError, "CASE_STORE_WRITE_FAILED", err.Error())
		return
	}
	if err := s.auditInvestigationCase(id, "investigation-case-add-evidence", updated.ID, fmt.Sprintf("evidence_count=%d", len(updated.Evidence))); err != nil {
		_ = s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
			index.replace(previous)
			return nil
		})
		investigationJSONError(w, http.StatusInternalServerError, "CASE_AUDIT_FAILED", err.Error())
		return
	}
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": investigationCaseAPISchema,
		"case":          updated,
	})
}

func (s *SystemService) handlePatchInvestigationCase(w http.ResponseWriter, r *http.Request, caseID string) {
	id, ok := s.investigationCaseIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "AUDIT_STORE_UNAVAILABLE", "audit store is required for investigation custody")
		return
	}
	caseID, err := normalizeInvestigationCaseID(caseID)
	if err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_CASE_ID", err.Error())
		return
	}
	var req patchInvestigationCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	now := time.Now().UTC()
	var updated investigationCaseRecord
	var previous investigationCaseRecord
	var changes []string
	if err := s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
		record, ok := index.find(caseID)
		if !ok {
			return investigationCaseNotFound{}
		}
		previous = record
		next, applied, err := applyInvestigationCasePatch(record, req, now, id)
		if err != nil {
			return err
		}
		changes = applied
		next.refreshSummary()
		updated = next
		index.replace(next)
		return nil
	}); err != nil {
		if errors.As(err, &investigationCaseNotFound{}) {
			investigationJSONError(w, http.StatusNotFound, "CASE_NOT_FOUND", "investigation case not found")
			return
		}
		var invalid investigationCasePatchInvalid
		if errors.As(err, &invalid) {
			investigationJSONError(w, http.StatusBadRequest, invalid.Code, invalid.Message)
			return
		}
		investigationJSONError(w, http.StatusInternalServerError, "CASE_STORE_WRITE_FAILED", err.Error())
		return
	}
	if err := s.auditInvestigationCase(id, "investigation-case-update", updated.ID, investigationCasePatchAuditDetail(previous, updated, changes)); err != nil {
		_ = s.updateInvestigationCaseIndex(func(index *investigationCaseIndex) error {
			index.replace(previous)
			return nil
		})
		investigationJSONError(w, http.StatusInternalServerError, "CASE_AUDIT_FAILED", err.Error())
		return
	}
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": investigationCaseAPISchema,
		"case":          updated,
	})
}

func (s *SystemService) investigationCaseIdentity(w http.ResponseWriter, r *http.Request, minRole authz.Role) (authz.Identity, bool) {
	if !s.Status.AuthEnabled {
		return authz.RequestIdentity(r.Context(), false), true
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "missing bearer token")
		return authz.Identity{}, false
	}
	if s.Auth == nil {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication is not configured")
		return authz.Identity{}, false
	}
	id, ok := s.Auth.AuthenticateBearer(token)
	if !ok {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid bearer token")
		return authz.Identity{}, false
	}
	if id.Role < minRole {
		investigationJSONError(w, http.StatusForbidden, "FORBIDDEN", "role does not permit investigation case custody")
		return authz.Identity{}, false
	}
	return id, true
}

func (s *SystemService) investigationCaseStorePath() string {
	base := strings.TrimSpace(s.Status.DataDir)
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "investigation-cases", "cases.json")
}

func (s *SystemService) readInvestigationCaseIndex() (investigationCaseIndex, error) {
	investigationCaseFileMu.Lock()
	defer investigationCaseFileMu.Unlock()
	return readInvestigationCaseIndexFile(s.investigationCaseStorePath())
}

func (s *SystemService) updateInvestigationCaseIndex(fn func(*investigationCaseIndex) error) error {
	investigationCaseFileMu.Lock()
	defer investigationCaseFileMu.Unlock()
	path := s.investigationCaseStorePath()
	index, err := readInvestigationCaseIndexFile(path)
	if err != nil {
		return err
	}
	if err := fn(&index); err != nil {
		return err
	}
	index.SchemaVersion = investigationCaseSchema
	index.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create investigation case directory: %w", err)
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode investigation cases: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o640); err != nil {
		return fmt.Errorf("write investigation case index: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace investigation case index: %w", err)
	}
	return nil
}

func readInvestigationCaseIndexFile(path string) (investigationCaseIndex, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return investigationCaseIndex{SchemaVersion: investigationCaseSchema}, nil
		}
		return investigationCaseIndex{}, fmt.Errorf("read investigation case index: %w", err)
	}
	var index investigationCaseIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return investigationCaseIndex{}, fmt.Errorf("decode investigation case index: %w", err)
	}
	if index.SchemaVersion == "" {
		index.SchemaVersion = investigationCaseSchema
	}
	return index, nil
}

func (s *SystemService) auditInvestigationCase(id authz.Identity, action, caseID, detail string) error {
	if s.Store == nil {
		return errors.New("audit store is not configured")
	}
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      id.Name,
		ActorRole:  id.Role.String(),
		AuthSource: id.AuthSource,
		Action:     action,
		Detail:     strings.TrimSpace("case_id=" + caseID + " " + detail),
	})
}

type investigationCaseIndex struct {
	SchemaVersion string                    `json:"schemaVersion"`
	UpdatedAt     string                    `json:"updatedAt,omitempty"`
	Cases         []investigationCaseRecord `json:"cases"`
}

func (i *investigationCaseIndex) find(id string) (investigationCaseRecord, bool) {
	for _, record := range i.Cases {
		if record.ID == id {
			return record, true
		}
	}
	return investigationCaseRecord{}, false
}

func (i *investigationCaseIndex) replace(record investigationCaseRecord) {
	for index := range i.Cases {
		if i.Cases[index].ID == record.ID {
			i.Cases[index] = record
			return
		}
	}
}

func (i *investigationCaseIndex) remove(id string) {
	next := i.Cases[:0]
	for _, record := range i.Cases {
		if record.ID == id {
			continue
		}
		next = append(next, record)
	}
	i.Cases = next
}

type investigationCaseRecord struct {
	SchemaVersion  string                  `json:"schemaVersion"`
	ID             string                  `json:"id"`
	Title          string                  `json:"title"`
	State          string                  `json:"state"`
	CreatedAt      string                  `json:"createdAt"`
	UpdatedAt      string                  `json:"updatedAt"`
	ResolutionNote string                  `json:"resolutionNote,omitempty"`
	ResolvedAt     string                  `json:"resolvedAt,omitempty"`
	ResolvedBy     string                  `json:"resolvedBy,omitempty"`
	CreatedBy      string                  `json:"createdBy"`
	CreatedByRole  string                  `json:"createdByRole"`
	AuthSource     string                  `json:"authSource"`
	EvidenceCount  int                     `json:"evidenceCount"`
	Summary        map[string]any          `json:"summary"`
	Synthesis      investigationSynthesis  `json:"synthesis"`
	Packet         map[string]any          `json:"packet,omitempty"`
	Evidence       []investigationEvidence `json:"evidence"`
}

func (r *investigationCaseRecord) refreshSummary() {
	r.EvidenceCount = len(r.Evidence)
	if r.Summary == nil {
		r.Summary = map[string]any{}
	}
	r.Summary["evidenceCount"] = len(r.Evidence)
	if summary, ok := r.Packet["summary"].(map[string]any); ok {
		if itemCount, ok := summary["itemCount"]; ok {
			r.Summary["packetItemCount"] = itemCount
		}
		if rootCause, ok := summary["rootCause"]; ok {
			r.Summary["rootCause"] = rootCause
		}
	}
	r.Synthesis = synthesizeInvestigationCase(*r)
	r.Summary["serverSynthesis"] = map[string]any{
		"state":             r.Synthesis.State,
		"confidenceLevel":   r.Synthesis.Confidence.Level,
		"confidenceScore":   r.Synthesis.Confidence.Score,
		"flowGroupCount":    r.Synthesis.Coverage.FlowGroups,
		"correlationKeys":   r.Synthesis.Coverage.CorrelationKeys,
		"readyActionCount":  len(r.Synthesis.Actions),
		"limitationCount":   len(r.Synthesis.Limitations),
		"serverRecordCount": r.Synthesis.Coverage.ServerRetainedRecords,
	}
}

func (r investigationCaseRecord) summary() investigationCaseSummary {
	return investigationCaseSummary{
		ID:             r.ID,
		Title:          r.Title,
		State:          r.State,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		ResolutionNote: r.ResolutionNote,
		ResolvedAt:     r.ResolvedAt,
		ResolvedBy:     r.ResolvedBy,
		CreatedBy:      r.CreatedBy,
		CreatedByRole:  r.CreatedByRole,
		AuthSource:     r.AuthSource,
		EvidenceCount:  r.EvidenceCount,
		Summary:        r.Summary,
		Synthesis:      r.Synthesis,
	}
}

type investigationCaseSummary struct {
	ID             string                 `json:"id"`
	Title          string                 `json:"title"`
	State          string                 `json:"state"`
	CreatedAt      string                 `json:"createdAt"`
	UpdatedAt      string                 `json:"updatedAt"`
	ResolutionNote string                 `json:"resolutionNote,omitempty"`
	ResolvedAt     string                 `json:"resolvedAt,omitempty"`
	ResolvedBy     string                 `json:"resolvedBy,omitempty"`
	CreatedBy      string                 `json:"createdBy"`
	CreatedByRole  string                 `json:"createdByRole"`
	AuthSource     string                 `json:"authSource"`
	EvidenceCount  int                    `json:"evidenceCount"`
	Summary        map[string]any         `json:"summary,omitempty"`
	Synthesis      investigationSynthesis `json:"synthesis"`
}

type investigationEvidence struct {
	ID        string                      `json:"id"`
	AddedAt   string                      `json:"addedAt"`
	AddedBy   string                      `json:"addedBy"`
	Kind      string                      `json:"kind"`
	Title     string                      `json:"title"`
	SubjectID string                      `json:"subjectId,omitempty"`
	Target    *investigationTargetSummary `json:"target,omitempty"`
	Payload   map[string]any              `json:"payload"`
}

type investigationTargetSummary struct {
	Kind          string `json:"kind,omitempty"`
	Key           string `json:"key,omitempty"`
	Route         string `json:"route,omitempty"`
	RouteRedacted bool   `json:"routeRedacted,omitempty"`
	Source        string `json:"source,omitempty"`
	Title         string `json:"title,omitempty"`
	PinnedAt      string `json:"pinnedAt,omitempty"`
	CollectedAt   string `json:"collectedAt,omitempty"`
	AddedAt       string `json:"addedAt,omitempty"`
}

type investigationSynthesis struct {
	SchemaVersion string                           `json:"schemaVersion"`
	Source        string                           `json:"source"`
	State         string                           `json:"state"`
	Status        string                           `json:"status"`
	Detail        string                           `json:"detail"`
	Confidence    investigationSynthesisConfidence `json:"confidence"`
	Coverage      investigationSynthesisCoverage   `json:"coverage"`
	Limitations   []string                         `json:"limitations"`
	Actions       []investigationSynthesisAction   `json:"actions"`
	Flows         []investigationSynthesisFlow     `json:"flows"`
	MutatesPolicy bool                             `json:"mutatesPolicy"`
	CreatesTicket bool                             `json:"createsTicket"`
}

type investigationSynthesisConfidence struct {
	Score float64  `json:"score"`
	Level string   `json:"level"`
	Basis []string `json:"basis"`
}

type investigationSynthesisCoverage struct {
	EvidenceRecords       int `json:"evidenceRecords"`
	ServerRetainedRecords int `json:"serverRetainedRecords"`
	CorrelationKeys       int `json:"correlationKeys"`
	FlowGroups            int `json:"flowGroups"`
	MultiRecordGroups     int `json:"multiRecordGroups"`
	CaptureProofRecords   int `json:"captureProofRecords"`
	OwnerRouteRecords     int `json:"ownerRouteRecords"`
}

type investigationSynthesisAction struct {
	ID         string   `json:"id"`
	Owner      string   `json:"owner"`
	Label      string   `json:"label"`
	Href       string   `json:"href,omitempty"`
	Confidence string   `json:"confidence"`
	FlowKeys   []string `json:"flowKeys,omitempty"`
	Detail     string   `json:"detail"`
	Safe       bool     `json:"safe"`
}

type investigationSynthesisFlow struct {
	Key            string   `json:"key"`
	Title          string   `json:"title"`
	RecordCount    int      `json:"recordCount"`
	Kinds          []string `json:"kinds"`
	Tuple          string   `json:"tuple,omitempty"`
	CaptureProof   bool     `json:"captureProof"`
	OwnerRoutes    []string `json:"ownerRoutes,omitempty"`
	CandidateHints []string `json:"candidateHints,omitempty"`
	Limitations    []string `json:"limitations,omitempty"`
}

type createInvestigationCaseRequest struct {
	Title    string           `json:"title"`
	Packet   map[string]any   `json:"packet"`
	Evidence []map[string]any `json:"evidence"`
}

type addInvestigationEvidenceRequest struct {
	Evidence []map[string]any `json:"evidence"`
}

type patchInvestigationCaseRequest struct {
	Title          *string `json:"title,omitempty"`
	State          *string `json:"state,omitempty"`
	ResolutionNote *string `json:"resolutionNote,omitempty"`
}

type investigationCaseNotFound struct{}

func (investigationCaseNotFound) Error() string { return "investigation case not found" }

type investigationEvidenceLimitExceeded struct{}

func (investigationEvidenceLimitExceeded) Error() string { return "case evidence limit exceeded" }

type investigationCasePatchInvalid struct {
	Code    string
	Message string
}

func (e investigationCasePatchInvalid) Error() string { return e.Message }

func normalizeInvestigationCaseID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !investigationCaseIDRE.MatchString(id) {
		return "", fmt.Errorf("invalid investigation case id")
	}
	return id, nil
}

func normalizeInvestigationTitle(title string, packet map[string]any) string {
	title = strings.TrimSpace(title)
	if title == "" {
		if summary, ok := packet["summary"].(map[string]any); ok {
			if rootCause, ok := summary["rootCause"].(map[string]any); ok {
				title = strings.TrimSpace(fmt.Sprint(rootCause["title"]))
			}
		}
	}
	if title == "" {
		title = "Investigation case"
	}
	return truncateInvestigationString(title, 160)
}

func normalizeInvestigationCaseState(state string) (string, error) {
	state = strings.ToLower(strings.TrimSpace(state))
	switch state {
	case "open", "investigating", "resolved", "closed":
		return state, nil
	default:
		return "", investigationCasePatchInvalid{Code: "INVALID_CASE_STATE", Message: "investigation case state must be open, investigating, resolved, or closed"}
	}
}

func applyInvestigationCasePatch(record investigationCaseRecord, req patchInvestigationCaseRequest, now time.Time, id authz.Identity) (investigationCaseRecord, []string, error) {
	changes := []string{}
	if req.Title == nil && req.State == nil && req.ResolutionNote == nil {
		return investigationCaseRecord{}, nil, investigationCasePatchInvalid{Code: "INVALID_CASE_PATCH", Message: "patch must include title, state, or resolutionNote"}
	}
	if req.Title != nil {
		title := truncateInvestigationString(redactInvestigationString(strings.TrimSpace(*req.Title)), 160)
		if title == "" {
			return investigationCaseRecord{}, nil, investigationCasePatchInvalid{Code: "INVALID_CASE_PATCH", Message: "title must not be empty"}
		}
		if title != record.Title {
			record.Title = title
			changes = append(changes, "title")
		}
	}
	if req.ResolutionNote != nil {
		note := truncateInvestigationString(redactInvestigationString(strings.TrimSpace(*req.ResolutionNote)), maxInvestigationStringLength)
		if note != record.ResolutionNote {
			record.ResolutionNote = note
			changes = append(changes, "resolution_note")
		}
	}
	if req.State != nil {
		state, err := normalizeInvestigationCaseState(*req.State)
		if err != nil {
			return investigationCaseRecord{}, nil, err
		}
		if state != record.State {
			oldState := record.State
			record.State = state
			changes = append(changes, "state")
			if (state == "resolved" || state == "closed") && oldState != state {
				record.ResolvedAt = now.Format(time.RFC3339Nano)
				record.ResolvedBy = id.Name
			}
			if state != "resolved" && state != "closed" {
				record.ResolvedAt = ""
				record.ResolvedBy = ""
			}
		}
	}
	if (record.State == "resolved" || record.State == "closed") && strings.TrimSpace(record.ResolutionNote) == "" {
		return investigationCaseRecord{}, nil, investigationCasePatchInvalid{Code: "INVALID_CASE_PATCH", Message: "resolutionNote is required when resolving or closing an investigation case"}
	}
	if len(changes) == 0 {
		return investigationCaseRecord{}, nil, investigationCasePatchInvalid{Code: "INVALID_CASE_PATCH", Message: "patch did not change investigation case state"}
	}
	record.UpdatedAt = now.Format(time.RFC3339Nano)
	return record, changes, nil
}

func investigationCasePatchAuditDetail(previous, updated investigationCaseRecord, changes []string) string {
	return fmt.Sprintf(
		"changes=%s old_state=%s new_state=%s title_changed=%t resolution_note_set=%t",
		strings.Join(changes, ","),
		previous.State,
		updated.State,
		previous.Title != updated.Title,
		strings.TrimSpace(updated.ResolutionNote) != "",
	)
}

func normalizeInvestigationEvidence(items []map[string]any, now time.Time, id authz.Identity) []investigationEvidence {
	out := make([]investigationEvidence, 0, len(items))
	for _, item := range items {
		payload := sanitizeInvestigationMap(item)
		kind := truncateInvestigationString(strings.TrimSpace(fmt.Sprint(payload["kind"])), 80)
		title := truncateInvestigationString(strings.TrimSpace(fmt.Sprint(payload["title"])), 200)
		subjectID := ""
		if subject, ok := payload["subject"].(map[string]any); ok {
			subjectID = truncateInvestigationString(strings.TrimSpace(fmt.Sprint(subject["id"])), 200)
		}
		if kind == "" {
			kind = "evidence"
		}
		if title == "" {
			title = "Investigation evidence"
		}
		target := investigationTargetSummaryFromPayload(payload, now)
		out = append(out, investigationEvidence{
			ID:        newInvestigationEvidenceID(now),
			AddedAt:   now.Format(time.RFC3339Nano),
			AddedBy:   id.Name,
			Kind:      kind,
			Title:     title,
			SubjectID: subjectID,
			Target:    &target,
			Payload:   payload,
		})
		if len(out) >= maxInvestigationEvidenceItems {
			break
		}
	}
	return out
}

func synthesizeInvestigationCase(record investigationCaseRecord) investigationSynthesis {
	groups := map[string][]investigationEvidence{}
	order := []string{}
	captureProof := 0
	ownerRoutes := 0
	for _, evidence := range record.Evidence {
		key := investigationEvidenceCorrelationKey(evidence)
		if key == "" {
			key = "record:" + evidence.ID
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], evidence)
		if investigationEvidenceHasCaptureProof(evidence) {
			captureProof++
		}
		if evidence.Target != nil && evidence.Target.Route != "" {
			ownerRoutes++
		}
	}
	sort.Strings(order)
	flows := make([]investigationSynthesisFlow, 0, min(len(order), maxInvestigationSynthesisFlow))
	multiRecordGroups := 0
	actionsByKey := map[string]investigationSynthesisAction{}
	for _, key := range order {
		group := groups[key]
		if len(group) > 1 {
			multiRecordGroups++
		}
		flow := investigationSynthesisFlowFromGroup(key, group)
		flows = append(flows, flow)
		for _, action := range investigationSynthesisActionsForFlow(flow, group) {
			if _, ok := actionsByKey[action.ID+"|"+action.Href]; ok {
				continue
			}
			actionsByKey[action.ID+"|"+action.Href] = action
		}
		if len(flows) >= maxInvestigationSynthesisFlow {
			break
		}
	}
	actions := make([]investigationSynthesisAction, 0, len(actionsByKey))
	for _, action := range actionsByKey {
		actions = append(actions, action)
	}
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].Owner == actions[j].Owner {
			return actions[i].Label < actions[j].Label
		}
		return actions[i].Owner < actions[j].Owner
	})
	if len(actions) > 8 {
		actions = actions[:8]
	}
	coverage := investigationSynthesisCoverage{
		EvidenceRecords:       len(record.Evidence),
		ServerRetainedRecords: len(record.Evidence),
		CorrelationKeys:       len(order),
		FlowGroups:            len(groups),
		MultiRecordGroups:     multiRecordGroups,
		CaptureProofRecords:   captureProof,
		OwnerRouteRecords:     ownerRoutes,
	}
	confidence := investigationSynthesisConfidenceForCoverage(coverage, len(actions))
	limitations := investigationSynthesisLimitations(coverage, len(actions), len(order)-len(flows))
	state := "empty"
	status := "no retained evidence"
	detail := "No retained case evidence records are available for server-backed synthesis."
	if coverage.EvidenceRecords > 0 {
		state = "server-records-review"
		status = "server synthesis needs review"
		detail = "Retained server evidence was grouped into candidate-safe owner-workspace handoffs for operator review."
		if coverage.MultiRecordGroups > 0 && coverage.CaptureProofRecords > 0 && len(actions) > 0 {
			state = "server-multi-flow-ready"
			status = "server multi-flow synthesis ready"
			detail = "Multiple retained evidence records correlate across one or more flows; owner-workspace actions are review-only and candidate-safe."
		}
	}
	return investigationSynthesis{
		SchemaVersion: investigationSynthesisSchema,
		Source:        "retained-server-records",
		State:         state,
		Status:        status,
		Detail:        detail,
		Confidence:    confidence,
		Coverage:      coverage,
		Limitations:   limitations,
		Actions:       actions,
		Flows:         flows,
		MutatesPolicy: false,
		CreatesTicket: false,
	}
}

func investigationEvidenceCorrelationKey(evidence investigationEvidence) string {
	payload := evidence.Payload
	packet := investigationMapFromAny(payload["packet"])
	artifacts := investigationMapFromAny(packet["artifacts"])
	summary := investigationMapFromAny(payload["summary"])
	subject := investigationMapFromAny(payload["subject"])
	tuple := investigationMapFromAny(subject["tuple"])
	flow := investigationMapFromAny(artifacts["flow"])
	alert := investigationMapFromAny(artifacts["alert"])
	query := investigationMapFromAny(artifacts["query"])
	capturePlan := investigationMapFromAny(artifacts["capturePlan"])
	flowID := investigationFirstString(
		summary["flowId"],
		summary["sampleFlowId"],
		tuple["flowId"],
		flow["flowId"],
		alert["flowId"],
		query["flowId"],
		capturePlan["flowId"],
		evidence.SubjectID,
	)
	if flowID != "" {
		return "flow:" + flowID
	}
	srcIP := investigationFirstString(summary["srcIp"], summary["sampleSrcIp"], tuple["srcIp"], flow["srcIp"], alert["srcIp"], query["srcIp"], capturePlan["srcIp"])
	destIP := investigationFirstString(summary["destIp"], tuple["destIp"], flow["destIp"], alert["destIp"], query["destIp"], capturePlan["destIp"])
	protocol := investigationFirstString(summary["protocol"], tuple["protocol"], flow["protocol"], alert["protocol"], query["protocol"], capturePlan["protocol"])
	destPort := investigationFirstString(summary["destPort"], tuple["destPort"], flow["destPort"], alert["destPort"], query["destPort"], capturePlan["destPort"])
	if srcIP != "" && destIP != "" {
		return "tuple:" + strings.Join([]string{protocol, srcIP, destIP, destPort}, "|")
	}
	if evidence.Target != nil && evidence.Target.Key != "" {
		return "target:" + evidence.Target.Key
	}
	return ""
}

func investigationSynthesisFlowFromGroup(key string, group []investigationEvidence) investigationSynthesisFlow {
	kinds := make([]string, 0, len(group))
	routes := []string{}
	hints := []string{}
	limitations := []string{}
	captureProof := false
	for _, evidence := range group {
		kinds = append(kinds, evidence.Kind)
		if evidence.Target != nil && evidence.Target.Route != "" {
			routes = append(routes, evidence.Target.Route)
		}
		if hint := investigationEvidenceCandidateHint(evidence); hint != "" {
			hints = append(hints, hint)
		}
		if investigationEvidenceHasCaptureProof(evidence) {
			captureProof = true
		}
	}
	if !captureProof {
		limitations = append(limitations, "packet proof not retained for this flow group")
	}
	if len(routes) == 0 {
		limitations = append(limitations, "no safe owner route retained for this flow group")
	}
	return investigationSynthesisFlow{
		Key:            truncateInvestigationString(key, 240),
		Title:          investigationSynthesisFlowTitle(group),
		RecordCount:    len(group),
		Kinds:          uniqueStrings(kinds),
		Tuple:          investigationSynthesisTupleLabel(group),
		CaptureProof:   captureProof,
		OwnerRoutes:    uniqueStrings(routes),
		CandidateHints: uniqueStrings(hints),
		Limitations:    limitations,
	}
}

func investigationSynthesisFlowTitle(group []investigationEvidence) string {
	for _, evidence := range group {
		if strings.TrimSpace(evidence.Title) != "" {
			return evidence.Title
		}
	}
	return "Retained evidence group"
}

func investigationSynthesisTupleLabel(group []investigationEvidence) string {
	for _, evidence := range group {
		payload := evidence.Payload
		packet := investigationMapFromAny(payload["packet"])
		artifacts := investigationMapFromAny(packet["artifacts"])
		subject := investigationMapFromAny(payload["subject"])
		tuple := investigationMapFromAny(subject["tuple"])
		flow := investigationMapFromAny(artifacts["flow"])
		query := investigationMapFromAny(artifacts["query"])
		srcIP := investigationFirstString(tuple["srcIp"], flow["srcIp"], query["srcIp"])
		destIP := investigationFirstString(tuple["destIp"], flow["destIp"], query["destIp"])
		if srcIP == "" || destIP == "" {
			continue
		}
		protocol := investigationFirstString(tuple["protocol"], flow["protocol"], query["protocol"])
		srcPort := investigationFirstString(tuple["srcPort"], flow["srcPort"], query["srcPort"])
		destPort := investigationFirstString(tuple["destPort"], flow["destPort"], query["destPort"])
		return strings.TrimSpace(fmt.Sprintf("%s %s:%s -> %s:%s", protocol, srcIP, srcPort, destIP, destPort))
	}
	return ""
}

func investigationEvidenceHasCaptureProof(evidence investigationEvidence) bool {
	if strings.EqualFold(evidence.Kind, "capture") {
		return true
	}
	payload := evidence.Payload
	packet := investigationMapFromAny(payload["packet"])
	artifacts := investigationMapFromAny(packet["artifacts"])
	summary := investigationMapFromAny(payload["summary"])
	captureJob := investigationMapFromAny(artifacts["captureJob"])
	capturePlan := investigationMapFromAny(artifacts["capturePlan"])
	return investigationFirstString(summary["captureState"], captureJob["state"], capturePlan["outputPath"], capturePlan["interface"]) != ""
}

func investigationEvidenceCandidateHint(evidence investigationEvidence) string {
	payload := evidence.Payload
	summary := investigationMapFromAny(payload["summary"])
	packet := investigationMapFromAny(payload["packet"])
	artifacts := investigationMapFromAny(packet["artifacts"])
	running := investigationMapFromAny(artifacts["running"])
	candidate := investigationMapFromAny(artifacts["candidate"])
	runningVerdict := investigationFirstString(summary["runningVerdict"], running["verdict"])
	candidateVerdict := investigationFirstString(summary["candidateVerdict"], candidate["verdict"])
	if runningVerdict != "" && candidateVerdict != "" && runningVerdict != candidateVerdict {
		return "candidate decision differs from running policy"
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(summary["state"])), "candidate") {
		return "candidate review evidence retained"
	}
	return ""
}

func investigationSynthesisActionsForFlow(flow investigationSynthesisFlow, group []investigationEvidence) []investigationSynthesisAction {
	out := []investigationSynthesisAction{}
	if len(flow.OwnerRoutes) > 0 {
		out = append(out, investigationSynthesisAction{
			ID:         "source-evidence",
			Owner:      "Source",
			Label:      "Open retained source evidence",
			Href:       flow.OwnerRoutes[0],
			Confidence: actionConfidence(flow),
			FlowKeys:   []string{flow.Key},
			Detail:     "Return to the retained source workflow; no policy or ticket mutation is performed.",
			Safe:       true,
		})
	}
	if stringsContainFold(flow.Kinds, "alert") {
		out = append(out, investigationSynthesisAction{
			ID:         "threat-review",
			Owner:      "Threats",
			Label:      "Review threat exception scope",
			Href:       firstRouteWithPrefix(flow.OwnerRoutes, "#/threats"),
			Confidence: actionConfidence(flow),
			FlowKeys:   []string{flow.Key},
			Detail:     "Review false-positive scope in Threats candidate workflow only.",
			Safe:       true,
		})
	}
	if len(flow.CandidateHints) > 0 || stringsContainFold(flow.Kinds, "nat-path") {
		out = append(out, investigationSynthesisAction{
			ID:         "candidate-compare",
			Owner:      "Rules",
			Label:      "Compare candidate policy path",
			Href:       firstRouteWithPrefix(flow.OwnerRoutes, "#/rules"),
			Confidence: actionConfidence(flow),
			FlowKeys:   []string{flow.Key},
			Detail:     "Use candidate comparison before any staged policy change; running policy is not mutated.",
			Safe:       true,
		})
	}
	return out
}

func investigationSynthesisConfidenceForCoverage(coverage investigationSynthesisCoverage, actionCount int) investigationSynthesisConfidence {
	score := 0.20
	basis := []string{"server-retained evidence records"}
	if coverage.MultiRecordGroups > 0 {
		score += 0.20
		basis = append(basis, "multiple related records grouped")
	}
	if coverage.CaptureProofRecords > 0 {
		score += 0.20
		basis = append(basis, "packet proof retained")
	}
	if coverage.OwnerRouteRecords > 0 {
		score += 0.20
		basis = append(basis, "owner workspace routes retained")
	}
	if actionCount > 0 {
		score += 0.10
		basis = append(basis, "candidate-safe owner actions available")
	}
	if score > 0.90 {
		score = 0.90
	}
	level := "low"
	if score >= 0.75 {
		level = "high"
	} else if score >= 0.50 {
		level = "medium"
	}
	return investigationSynthesisConfidence{Score: score, Level: level, Basis: basis}
}

func investigationSynthesisLimitations(coverage investigationSynthesisCoverage, actionCount, omittedGroups int) []string {
	limitations := []string{
		"review-only synthesis; does not create authoritative tickets",
		"does not commit, publish, or mutate running policy",
		"unsigned synthesis; legal hold and immutable custody remain hardening work",
	}
	if coverage.CaptureProofRecords == 0 {
		limitations = append(limitations, "no retained packet proof records were found")
	}
	if coverage.OwnerRouteRecords == 0 || actionCount == 0 {
		limitations = append(limitations, "no candidate-safe owner route could be derived for at least one group")
	}
	if omittedGroups > 0 {
		limitations = append(limitations, fmt.Sprintf("%d additional retained group(s) omitted by bounded synthesis limit", omittedGroups))
	}
	return limitations
}

func actionConfidence(flow investigationSynthesisFlow) string {
	if flow.CaptureProof && len(flow.OwnerRoutes) > 0 && flow.RecordCount > 1 {
		return "high"
	}
	if len(flow.OwnerRoutes) > 0 || flow.CaptureProof {
		return "medium"
	}
	return "low"
}

func firstRouteWithPrefix(routes []string, prefix string) string {
	for _, route := range routes {
		if strings.HasPrefix(route, prefix) {
			return route
		}
	}
	return ""
}

func stringsContainFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) || strings.Contains(strings.ToLower(value), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func investigationTargetSummaryFromPayload(payload map[string]any, now time.Time) investigationTargetSummary {
	target := investigationMapFromAny(payload["target"])
	packet := investigationMapFromAny(payload["packet"])
	payloadSource := investigationMapFromAny(payload["source"])
	packetSource := investigationMapFromAny(packet["source"])
	subject := investigationMapFromAny(payload["subject"])

	routeRaw := investigationFirstString(
		target["route"],
		target["redactedRoute"],
		investigationMapFromAny(target["source"])["route"],
		payloadSource["route"],
		payloadSource["redactedRoute"],
		packetSource["route"],
		packetSource["redactedRoute"],
	)
	route := normalizeInvestigationTargetRoute(routeRaw)
	routeRedacted := investigationBoolFromAny(target["routeRedacted"]) ||
		investigationBoolFromAny(payloadSource["routeRedacted"]) ||
		investigationBoolFromAny(packetSource["routeRedacted"]) ||
		(routeRaw != "" && route == "")

	return investigationTargetSummary{
		Kind:          truncateInvestigationString(redactInvestigationString(investigationFirstString(target["kind"], payload["kind"], packet["kind"])), 80),
		Key:           truncateInvestigationString(redactInvestigationString(investigationFirstString(target["key"], payload["key"])), 240),
		Route:         route,
		RouteRedacted: routeRedacted,
		Source:        truncateInvestigationString(redactInvestigationString(investigationFirstString(target["source"], target["interface"], payloadSource["interface"], packetSource["interface"])), 80),
		Title:         truncateInvestigationString(redactInvestigationString(investigationFirstString(target["title"], payload["title"], subject["label"], packet["title"])), 240),
		PinnedAt:      truncateInvestigationString(redactInvestigationString(investigationFirstString(target["pinnedAt"], payload["pinnedAt"])), 80),
		CollectedAt:   truncateInvestigationString(redactInvestigationString(investigationFirstString(target["collectedAt"], payload["collectedAt"], packet["collectedAt"])), 80),
		AddedAt:       now.Format(time.RFC3339Nano),
	}
}

func normalizeInvestigationTargetRoute(value string) string {
	value = strings.TrimSpace(redactInvestigationString(value))
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return ""
	}
	if !strings.HasPrefix(value, "#/") {
		return ""
	}
	return truncateInvestigationString(value, maxInvestigationTargetRoute)
}

func investigationMapFromAny(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func investigationFirstString(values ...any) string {
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" {
			continue
		}
		return text
	}
	return ""
}

func investigationBoolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func sanitizeInvestigationValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[truncateInvestigationString(key, 120)] = sanitizeInvestigationValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, min(len(v), maxInvestigationEvidenceItems))
		for _, item := range v {
			out = append(out, sanitizeInvestigationValue(item))
			if len(out) >= maxInvestigationEvidenceItems {
				break
			}
		}
		return out
	case string:
		return redactInvestigationString(truncateInvestigationString(v, maxInvestigationStringLength))
	default:
		return v
	}
}

func sanitizeInvestigationMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	clean, ok := sanitizeInvestigationValue(value).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return clean
}

func redactInvestigationString(value string) string {
	value = secretLikeRE.ReplaceAllString(value, "[redacted]")
	value = localPathLikeRE.ReplaceAllString(value, "$1[server-local path redacted]")
	return value
}

func truncateInvestigationString(value string, maxLength int) string {
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength]
}

func investigationCaseLimit(raw string) int {
	if raw == "" {
		return defaultInvestigationCaseLimit
	}
	var limit int
	if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil || limit <= 0 {
		return defaultInvestigationCaseLimit
	}
	if limit > maxInvestigationCaseLimit {
		return maxInvestigationCaseLimit
	}
	return limit
}

func matchingInvestigationCaseCount(records []investigationCaseRecord, state string) int {
	count := 0
	for _, record := range records {
		if state == "" || strings.EqualFold(record.State, state) {
			count++
		}
	}
	return count
}

func newInvestigationCaseID(now time.Time) string {
	return "case-" + now.Format("20060102T150405Z") + "-" + randomHex(4)
}

func newInvestigationEvidenceID(now time.Time) string {
	return "ev-" + now.Format("20060102T150405.000000000Z") + "-" + randomHex(4)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(buf)
}

func investigationWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func investigationJSONError(w http.ResponseWriter, status int, code, message string) {
	investigationWriteJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

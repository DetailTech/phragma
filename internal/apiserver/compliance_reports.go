package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/compliance"
	"github.com/detailtech/oss-ngfw/internal/store"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const complianceReportAPISchema = "phragma.compliance.report-api.v1"

var reportIDRE = regexp.MustCompile(`^report-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

type createComplianceReportRequest struct {
	Profile      string `json:"profile"`
	Title        string `json:"title"`
	AuditLimit   int    `json:"auditLimit"`
	VersionLimit int    `json:"versionLimit"`
	LogLimit     int    `json:"logLimit"`
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	Version      string `json:"version"`
	Since        string `json:"since"`
	Until        string `json:"until"`
	Query        string `json:"query"`
}

// ListComplianceReports returns retained report summaries to an authorized viewer.
func (s *SystemService) ListComplianceReports(ctx context.Context, req *openngfwv1.ListComplianceReportsRequest) (*openngfwv1.ListComplianceReportsResponse, error) {
	if _, err := s.complianceGRPCIdentity(ctx, authz.RoleViewer); err != nil {
		return nil, err
	}
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.Internal, "store is required for compliance reports")
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	records, err := s.Store.ListComplianceReports(limit)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read compliance reports: %v", err)
	}
	out := &openngfwv1.ListComplianceReportsResponse{SchemaVersion: complianceReportAPISchema}
	for _, record := range records {
		out.Reports = append(out.Reports, complianceReportSummaryProto(record))
	}
	return out, nil
}

// GetComplianceReport returns one retained compliance report summary.
func (s *SystemService) GetComplianceReport(ctx context.Context, req *openngfwv1.GetComplianceReportRequest) (*openngfwv1.GetComplianceReportResponse, error) {
	if _, err := s.complianceGRPCIdentity(ctx, authz.RoleViewer); err != nil {
		return nil, err
	}
	record, err := s.lookupComplianceReportGRPC(req.GetId())
	if err != nil {
		return nil, err
	}
	return &openngfwv1.GetComplianceReportResponse{
		SchemaVersion: complianceReportAPISchema,
		Report:        complianceReportSummaryProto(record),
	}, nil
}

// ExportComplianceReport returns one retained report and its JSON payload.
func (s *SystemService) ExportComplianceReport(ctx context.Context, req *openngfwv1.ExportComplianceReportRequest) (*openngfwv1.ExportComplianceReportResponse, error) {
	if _, err := s.complianceGRPCIdentity(ctx, authz.RoleViewer); err != nil {
		return nil, err
	}
	record, err := s.lookupComplianceReportGRPC(req.GetId())
	if err != nil {
		return nil, err
	}
	return &openngfwv1.ExportComplianceReportResponse{
		SchemaVersion: complianceReportAPISchema,
		Report:        complianceReportSummaryProto(record),
		Filename:      record.ID + ".json",
		ContentType:   "application/json",
		Payload:       append([]byte(nil), record.Payload...),
	}, nil
}

// CreateComplianceReport captures current evidence and retains an unsigned report.
func (s *SystemService) CreateComplianceReport(ctx context.Context, req *openngfwv1.CreateComplianceReportRequest) (*openngfwv1.CreateComplianceReportResponse, error) {
	id, err := s.complianceGRPCIdentity(ctx, authz.RoleOperator)
	if err != nil {
		return nil, err
	}
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.Internal, "store is required for compliance reports")
	}
	reportReq, err := complianceRequestFromProto(req)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "invalid report request: %v", err)
	}
	reportReq = compliance.NormalizeRequest(reportReq)
	audit, err := s.Store.ListAuditFiltered(store.AuditFilter{
		Limit:   reportReq.AuditLimit,
		Actor:   reportReq.Actor,
		Action:  reportReq.Action,
		Version: reportReq.Version,
		Since:   reportReq.Since,
		Until:   reportReq.Until,
		Query:   reportReq.Query,
	})
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read audit entries: %v", err)
	}
	versions, err := s.Store.ListVersions(reportReq.VersionLimit)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read versions: %v", err)
	}
	integrity, integrityErr := s.Store.AuditIntegrity()
	logEntries, logSummary := s.complianceSystemLogs(ctx, reportReq)
	record, err := compliance.NewReport(reportReq, store.ActorIdentity{Name: id.Name, Role: id.Role.String(), AuthSource: id.AuthSource}, compliance.SourceState{
		AuditEntries:     audit,
		Versions:         versions,
		AuditIntegrity:   integrity,
		IntegrityOK:      integrityErr == nil,
		IntegrityError:   errorText(integrityErr),
		SystemLogs:       logEntries,
		SystemLogSummary: logSummary,
	}, time.Now().UTC())
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "build compliance report: %v", err)
	}
	record.PayloadSHA256 = complianceReportPayloadSHA(record.Payload)
	if err := s.Store.SaveComplianceReport(record); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "store compliance report: %v", err)
	}
	if err := s.Store.AppendAudit(store.AuditEntry{
		Time:       time.Now().UTC(),
		Actor:      id.Name,
		ActorRole:  id.Role.String(),
		AuthSource: id.AuthSource,
		Action:     "compliance-report-create",
		Detail:     fmt.Sprintf("report=%s profile=%s audit_entries=%d versions=%d system_logs=%d unsigned=true server_stored=true grpc=true", record.ID, record.Profile, record.AuditEntryCount, record.VersionCount, record.SystemLogEntryCount),
	}); err != nil {
		_ = s.Store.DeleteComplianceReport(record.ID)
		return nil, grpcstatus.Errorf(codes.Internal, "audit compliance report creation: %v", err)
	}
	return &openngfwv1.CreateComplianceReportResponse{
		SchemaVersion: complianceReportAPISchema,
		Report:        complianceReportSummaryProto(record),
	}, nil
}

// ComplianceReportHandler serves retained report records while the protobuf
// contract catches up. Reports are server-retained but intentionally unsigned.
func (s *SystemService) ComplianceReportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/compliance/reports")
		switch {
		case path == "" || path == "/":
			switch r.Method {
			case http.MethodGet:
				s.handleListComplianceReports(w, r)
			case http.MethodPost:
				s.handleCreateComplianceReport(w, r)
			default:
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
			}
		case strings.HasSuffix(path, "/export"):
			if r.Method != http.MethodGet {
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/export")
			s.handleExportComplianceReport(w, r, id)
		default:
			if r.Method != http.MethodGet {
				investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			s.handleGetComplianceReport(w, r, strings.TrimPrefix(path, "/"))
		}
	})
}

func (s *SystemService) handleListComplianceReports(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.complianceReportIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_STORE_UNAVAILABLE", "store is required for compliance reports")
		return
	}
	limit := intQuery(r, "limit", 50, 100)
	records, err := s.Store.ListComplianceReports(limit)
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_STORE_READ_FAILED", err.Error())
		return
	}
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": complianceReportAPISchema,
		"reports":       complianceReportSummaries(records),
	})
}

func (s *SystemService) handleGetComplianceReport(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := s.complianceReportIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	record, ok := s.lookupComplianceReport(w, id)
	if !ok {
		return
	}
	investigationWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": complianceReportAPISchema,
		"report":        complianceReportSummary(record),
	})
}

func (s *SystemService) handleExportComplianceReport(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := s.complianceReportIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	record, ok := s.lookupComplianceReport(w, id)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", record.ID+".json"))
	if digest := complianceReportDigest(record); digest != "" {
		w.Header().Set("X-Phragma-Payload-Sha256", digest)
		w.Header().Set("ETag", `"`+digest+`"`)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(record.Payload)
}

func (s *SystemService) handleCreateComplianceReport(w http.ResponseWriter, r *http.Request) {
	id, ok := s.complianceReportIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_STORE_UNAVAILABLE", "store is required for compliance reports")
		return
	}
	var body createComplianceReportRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	req, err := complianceRequestFromBody(body)
	if err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_REPORT_REQUEST", err.Error())
		return
	}
	req = compliance.NormalizeRequest(req)
	audit, err := s.Store.ListAuditFiltered(store.AuditFilter{
		Limit:   req.AuditLimit,
		Actor:   req.Actor,
		Action:  req.Action,
		Version: req.Version,
		Since:   req.Since,
		Until:   req.Until,
		Query:   req.Query,
	})
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_AUDIT_READ_FAILED", err.Error())
		return
	}
	versions, err := s.Store.ListVersions(req.VersionLimit)
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_VERSION_READ_FAILED", err.Error())
		return
	}
	integrity, integrityErr := s.Store.AuditIntegrity()
	logEntries, logSummary := s.complianceSystemLogs(r.Context(), req)
	record, err := compliance.NewReport(req, store.ActorIdentity{Name: id.Name, Role: id.Role.String(), AuthSource: id.AuthSource}, compliance.SourceState{
		AuditEntries:     audit,
		Versions:         versions,
		AuditIntegrity:   integrity,
		IntegrityOK:      integrityErr == nil,
		IntegrityError:   errorText(integrityErr),
		SystemLogs:       logEntries,
		SystemLogSummary: logSummary,
	}, time.Now().UTC())
	if err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_BUILD_FAILED", err.Error())
		return
	}
	record.PayloadSHA256 = complianceReportPayloadSHA(record.Payload)
	if err := s.Store.SaveComplianceReport(record); err != nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_STORE_WRITE_FAILED", err.Error())
		return
	}
	if err := s.Store.AppendAudit(store.AuditEntry{
		Time:       time.Now().UTC(),
		Actor:      id.Name,
		ActorRole:  id.Role.String(),
		AuthSource: id.AuthSource,
		Action:     "compliance-report-create",
		Detail:     fmt.Sprintf("report=%s profile=%s audit_entries=%d versions=%d system_logs=%d unsigned=true server_stored=true", record.ID, record.Profile, record.AuditEntryCount, record.VersionCount, record.SystemLogEntryCount),
	}); err != nil {
		_ = s.Store.DeleteComplianceReport(record.ID)
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_AUDIT_FAILED", err.Error())
		return
	}
	w.Header().Set("Location", "/v1/compliance/reports/"+record.ID)
	investigationWriteJSON(w, http.StatusCreated, map[string]any{
		"schemaVersion": complianceReportAPISchema,
		"report":        complianceReportSummary(record),
	})
}

func (s *SystemService) lookupComplianceReport(w http.ResponseWriter, id string) (store.ComplianceReportRecord, bool) {
	if s.Store == nil {
		investigationJSONError(w, http.StatusInternalServerError, "REPORT_STORE_UNAVAILABLE", "store is required for compliance reports")
		return store.ComplianceReportRecord{}, false
	}
	id = strings.TrimSpace(id)
	if !reportIDRE.MatchString(id) {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_REPORT_ID", "report id is invalid")
		return store.ComplianceReportRecord{}, false
	}
	record, err := s.Store.GetComplianceReport(id)
	if err != nil {
		investigationJSONError(w, http.StatusNotFound, "REPORT_NOT_FOUND", "compliance report not found")
		return store.ComplianceReportRecord{}, false
	}
	return record, true
}

func (s *SystemService) complianceSystemLogs(ctx context.Context, req compliance.Request) ([]compliance.SystemLogEntry, compliance.SystemLogSummary) {
	logReq := &openngfwv1.ListSystemLogsRequest{Limit: uint32(req.LogLimit)}
	if !req.Since.IsZero() {
		logReq.Since = req.Since.Format(time.RFC3339)
	}
	if !req.Until.IsZero() {
		logReq.Until = req.Until.Format(time.RFC3339)
	}
	resp, err := s.ListSystemLogs(ctx, logReq)
	if err != nil {
		return nil, compliance.SystemLogSummary{Warnings: []string{err.Error()}}
	}
	var entries []compliance.SystemLogEntry
	for _, entry := range resp.GetEntries() {
		entries = append(entries, compliance.SystemLogEntry{
			Timestamp: entry.GetTimestamp(),
			Source:    entry.GetSource(),
			Severity:  entry.GetSeverity(),
			Message:   entry.GetMessage(),
		})
	}
	summary := compliance.SystemLogSummary{}
	if resp.GetSummary() != nil {
		summary.ScannedFiles = resp.GetSummary().GetScannedFiles()
		summary.ScannedLines = resp.GetSummary().GetScannedLines()
		summary.Truncated = resp.GetSummary().GetTruncated()
		summary.Warnings = resp.GetSummary().GetWarnings()
	}
	return entries, summary
}

func (s *SystemService) complianceGRPCIdentity(ctx context.Context, minRole authz.Role) (authz.Identity, error) {
	id := authz.RequestIdentity(ctx, s.Status.AuthEnabled)
	if s.Status.AuthEnabled && id.Role == 0 {
		return authz.Identity{}, grpcstatus.Error(codes.Unauthenticated, "missing authenticated identity")
	}
	if id.Role < minRole {
		return authz.Identity{}, grpcstatus.Error(codes.PermissionDenied, "role does not permit compliance report custody")
	}
	return id, nil
}

func (s *SystemService) lookupComplianceReportGRPC(id string) (store.ComplianceReportRecord, error) {
	if s.Store == nil {
		return store.ComplianceReportRecord{}, grpcstatus.Error(codes.Internal, "store is required for compliance reports")
	}
	id = strings.TrimSpace(id)
	if !reportIDRE.MatchString(id) {
		return store.ComplianceReportRecord{}, grpcstatus.Error(codes.InvalidArgument, "report id is invalid")
	}
	record, err := s.Store.GetComplianceReport(id)
	if err != nil {
		return store.ComplianceReportRecord{}, grpcstatus.Error(codes.NotFound, "compliance report not found")
	}
	return record, nil
}

func (s *SystemService) complianceReportIdentity(w http.ResponseWriter, r *http.Request, minRole authz.Role) (authz.Identity, bool) {
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
		investigationJSONError(w, http.StatusForbidden, "FORBIDDEN", "role does not permit compliance report custody")
		return authz.Identity{}, false
	}
	return id, true
}

func complianceRequestFromProto(req *openngfwv1.CreateComplianceReportRequest) (compliance.Request, error) {
	var since time.Time
	var until time.Time
	if req.GetSince() != nil {
		since = req.GetSince().AsTime()
	}
	if req.GetUntil() != nil {
		until = req.GetUntil().AsTime()
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return compliance.Request{}, fmt.Errorf("since must be at or before until")
	}
	return compliance.Request{
		Profile:      req.GetProfile(),
		Title:        req.GetTitle(),
		AuditLimit:   int(req.GetAuditLimit()),
		VersionLimit: int(req.GetVersionLimit()),
		LogLimit:     int(req.GetLogLimit()),
		Actor:        req.GetActor(),
		Action:       req.GetAction(),
		Version:      req.GetVersion(),
		Since:        since,
		Until:        until,
		Query:        req.GetQuery(),
	}, nil
}

func complianceRequestFromBody(body createComplianceReportRequest) (compliance.Request, error) {
	version, err := optionalUint(body.Version, "version")
	if err != nil {
		return compliance.Request{}, err
	}
	since, err := optionalReportTime(body.Since, "since")
	if err != nil {
		return compliance.Request{}, err
	}
	until, err := optionalReportTime(body.Until, "until")
	if err != nil {
		return compliance.Request{}, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return compliance.Request{}, fmt.Errorf("since must be at or before until")
	}
	return compliance.Request{
		Profile:      body.Profile,
		Title:        body.Title,
		AuditLimit:   body.AuditLimit,
		VersionLimit: body.VersionLimit,
		LogLimit:     body.LogLimit,
		Actor:        body.Actor,
		Action:       body.Action,
		Version:      version,
		Since:        since,
		Until:        until,
		Query:        body.Query,
	}, nil
}

func complianceReportSummaryProto(record store.ComplianceReportRecord) *openngfwv1.ComplianceReportSummary {
	return &openngfwv1.ComplianceReportSummary{
		Id:                  record.ID,
		SchemaVersion:       record.SchemaVersion,
		GeneratedAt:         timestamppb.New(record.GeneratedAt.UTC()),
		GeneratedBy:         record.GeneratedBy,
		GeneratedByRole:     record.GeneratedByRole,
		AuthSource:          record.AuthSource,
		Profile:             record.Profile,
		ProfileLabel:        record.ProfileLabel,
		Title:               record.Title,
		Source:              record.Source,
		Unsigned:            record.Unsigned,
		Signed:              record.Signed,
		ServerStored:        record.ServerStored,
		RetentionEnforced:   record.RetentionEnforced,
		AuditEntryCount:     uint32(record.AuditEntryCount),
		VersionCount:        uint32(record.VersionCount),
		SystemLogEntryCount: uint32(record.SystemLogEntryCount),
		EntryHashes:         append([]string(nil), record.EntryHashes...),
		LatestAuditHash:     record.LatestAuditHash,
		Filters:             copyStringMap(record.Filters),
		PayloadSha256:       record.PayloadSHA256,
		ExportPath:          "/v1/compliance/reports/" + record.ID + "/export",
	}
}

func complianceReportPayloadSHA(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func complianceReportDigest(record store.ComplianceReportRecord) string {
	digest := strings.TrimSpace(record.PayloadSHA256)
	if digest != "" {
		return digest
	}
	return complianceReportPayloadSHA(record.Payload)
}

func complianceReportSummaries(records []store.ComplianceReportRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		out = append(out, complianceReportSummary(record))
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func complianceReportSummary(record store.ComplianceReportRecord) map[string]any {
	return map[string]any{
		"id":                  record.ID,
		"schemaVersion":       record.SchemaVersion,
		"generatedAt":         record.GeneratedAt.UTC().Format(time.RFC3339Nano),
		"generatedBy":         record.GeneratedBy,
		"generatedByRole":     record.GeneratedByRole,
		"authSource":          record.AuthSource,
		"profile":             record.Profile,
		"profileLabel":        record.ProfileLabel,
		"title":               record.Title,
		"source":              record.Source,
		"unsigned":            record.Unsigned,
		"signed":              record.Signed,
		"serverStored":        record.ServerStored,
		"retentionEnforced":   record.RetentionEnforced,
		"auditEntryCount":     record.AuditEntryCount,
		"versionCount":        record.VersionCount,
		"systemLogEntryCount": record.SystemLogEntryCount,
		"entryHashes":         record.EntryHashes,
		"latestAuditHash":     record.LatestAuditHash,
		"filters":             record.Filters,
		"payloadSha256":       record.PayloadSHA256,
		"exportPath":          "/v1/compliance/reports/" + record.ID + "/export",
	}
}

func optionalUint(value, field string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	out, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned integer", field)
	}
	return out, nil
}

func optionalReportTime(value, field string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	out, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", field)
	}
	return out, nil
}

func intQuery(r *http.Request, key string, fallback, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

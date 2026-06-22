package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/store"
)

const (
	ReportSchemaVersion = "phragma.compliance.report-record.v1"
	defaultAuditLimit   = 300
	maxAuditLimit       = 1000
	defaultVersionLimit = 100
	maxVersionLimit     = 250
	defaultLogLimit     = 100
	maxLogLimit         = 300
)

var (
	secretRE = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|secret|client[_-]?secret)\s*[:=]\s*[^\s"',;}]+)`)
	pathRE   = regexp.MustCompile(`(?i)(^|[\s"'({=,;])/(?:var/lib|var/log(?:/openngfw)?|etc(?:/openngfw|/phragma)?|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+|opt/[^'"\s,;}]+|data/[^'"\s,;}]+)[^'"\s,;}]*`)
)

type Request struct {
	Profile      string
	Title        string
	AuditLimit   int
	VersionLimit int
	LogLimit     int
	Actor        string
	Action       string
	Version      uint64
	Since        time.Time
	Until        time.Time
	Query        string
}

type SystemLogEntry struct {
	Timestamp string `json:"timestamp,omitempty"`
	Source    string `json:"source,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Message   string `json:"message,omitempty"`
}

type SystemLogSummary struct {
	ScannedFiles uint32   `json:"scanned_files,omitempty"`
	ScannedLines uint32   `json:"scanned_lines,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

type SourceState struct {
	AuditEntries   []store.AuditEntry
	Versions       []store.VersionInfo
	AuditIntegrity store.AuditIntegrityReport
	IntegrityOK    bool
	IntegrityError string
	SystemLogs     []SystemLogEntry
	SystemLogSummary
}

func NewReport(req Request, identity store.ActorIdentity, state SourceState, now time.Time) (store.ComplianceReportRecord, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	req = NormalizeRequest(req)
	profileLabel := ProfileLabel(req.Profile)
	payload := map[string]any{
		"schemaVersion": ReportSchemaVersion,
		"generatedAt":   now.Format(time.RFC3339Nano),
		"source":        "server-generated",
		"unsigned":      true,
		"custody": map[string]any{
			"serverStored":      true,
			"signed":            false,
			"retentionEnforced": false,
			"note":              "Server-retained operational report; signed custody, legal retention, and external evidence hardening are deferred.",
		},
		"profile": map[string]any{
			"id":    req.Profile,
			"label": profileLabel,
		},
		"title":   req.Title,
		"filters": filters(req),
		"audit": map[string]any{
			"integrity": map[string]any{
				"ok":              state.IntegrityOK,
				"entryCount":      state.AuditIntegrity.EntryCount,
				"latestEntryHash": state.AuditIntegrity.LatestEntryHash,
				"detail":          integrityDetail(state.IntegrityOK, state.IntegrityError),
			},
			"entries": auditEntries(state.AuditEntries),
		},
		"versions":    versions(state.Versions),
		"systemLogs":  systemLogs(state.SystemLogs, state.SystemLogSummary),
		"compliance":  complianceSummary(req.Profile, state),
		"limitations": []string{"Report is server-retained but unsigned.", "Report does not verify fleet, backup, telemetry sink, or App-ID evidence.", "Retention enforcement and signed chain-of-custody remain hardening work."},
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return store.ComplianceReportRecord{}, err
	}
	entryHashes := make([]string, 0, len(state.AuditEntries))
	for _, entry := range state.AuditEntries {
		if entry.EntryHash != "" {
			entryHashes = append(entryHashes, entry.EntryHash)
		}
	}
	return store.ComplianceReportRecord{
		ID:                  newID(now),
		SchemaVersion:       ReportSchemaVersion,
		GeneratedAt:         now,
		GeneratedBy:         sanitize(identity.Name),
		GeneratedByRole:     sanitize(identity.Role),
		AuthSource:          sanitize(identity.AuthSource),
		Profile:             req.Profile,
		ProfileLabel:        profileLabel,
		Title:               req.Title,
		Source:              "server-generated",
		Unsigned:            true,
		Signed:              false,
		ServerStored:        true,
		RetentionEnforced:   false,
		AuditEntryCount:     len(state.AuditEntries),
		VersionCount:        len(state.Versions),
		SystemLogEntryCount: len(state.SystemLogs),
		EntryHashes:         entryHashes,
		LatestAuditHash:     state.AuditIntegrity.LatestEntryHash,
		Filters:             filters(req),
		Payload:             append(raw, '\n'),
	}, nil
}

func NormalizeRequest(req Request) Request {
	req.Profile = normalizeProfile(req.Profile)
	req.Title = cleanDefault(req.Title, ProfileLabel(req.Profile)+" compliance report")
	req.AuditLimit = clamp(req.AuditLimit, defaultAuditLimit, maxAuditLimit)
	req.VersionLimit = clamp(req.VersionLimit, defaultVersionLimit, maxVersionLimit)
	req.LogLimit = clamp(req.LogLimit, defaultLogLimit, maxLogLimit)
	req.Actor = sanitize(req.Actor)
	req.Action = sanitize(req.Action)
	req.Query = sanitize(req.Query)
	return req
}

func ProfileLabel(profile string) string {
	switch normalizeProfile(profile) {
	case "change-control":
		return "Change control"
	case "privileged-access":
		return "Privileged access"
	case "content-lifecycle":
		return "Content lifecycle"
	case "incident-evidence":
		return "Incident evidence"
	default:
		return "Operational"
	}
}

func normalizeProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "change-control", "privileged-access", "content-lifecycle", "incident-evidence":
		return strings.ToLower(strings.TrimSpace(profile))
	default:
		return "operational"
	}
}

func clamp(value, fallback, max int) int {
	if value <= 0 {
		value = fallback
	}
	if value > max {
		return max
	}
	return value
}

func cleanDefault(value, fallback string) string {
	value = sanitize(value)
	if value == "" {
		return fallback
	}
	if len(value) > 160 {
		return strings.TrimSpace(value[:160])
	}
	return value
}

func filters(req Request) map[string]string {
	out := map[string]string{
		"profile":      req.Profile,
		"auditLimit":   fmt.Sprintf("%d", req.AuditLimit),
		"versionLimit": fmt.Sprintf("%d", req.VersionLimit),
		"logLimit":     fmt.Sprintf("%d", req.LogLimit),
	}
	if req.Actor != "" {
		out["actor"] = req.Actor
	}
	if req.Action != "" {
		out["action"] = req.Action
	}
	if req.Version != 0 {
		out["version"] = fmt.Sprintf("%d", req.Version)
	}
	if !req.Since.IsZero() {
		out["since"] = req.Since.UTC().Format(time.RFC3339)
	}
	if !req.Until.IsZero() {
		out["until"] = req.Until.UTC().Format(time.RFC3339)
	}
	if req.Query != "" {
		out["query"] = req.Query
	}
	return out
}

func auditEntries(entries []store.AuditEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"id":           entry.ID,
			"time":         entry.Time.UTC().Format(time.RFC3339Nano),
			"actor":        sanitize(entry.Actor),
			"actorRole":    sanitize(entry.ActorRole),
			"authSource":   sanitize(entry.AuthSource),
			"action":       sanitize(entry.Action),
			"detail":       sanitize(entry.Detail),
			"version":      entry.Version,
			"previousHash": entry.PreviousHash,
			"entryHash":    entry.EntryHash,
		})
	}
	return out
}

func versions(infos []store.VersionInfo) []map[string]any {
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		out = append(out, map[string]any{
			"id":                info.ID,
			"createdAt":         info.CreatedAt.UTC().Format(time.RFC3339Nano),
			"actor":             sanitize(info.Actor),
			"actorRole":         sanitize(info.ActorRole),
			"authSource":        sanitize(info.AuthSource),
			"comment":           sanitize(info.Comment),
			"action":            sanitize(info.Action),
			"sourceVersion":     info.SourceVersion,
			"state":             sanitize(info.State),
			"artifactSetSha256": info.ArtifactSetSHA256,
			"lastKnownGood":     info.LastKnownGood,
		})
	}
	return out
}

func systemLogs(entries []SystemLogEntry, summary SystemLogSummary) map[string]any {
	out := make([]SystemLogEntry, 0, len(entries))
	for _, entry := range entries {
		entry.Message = sanitize(entry.Message)
		out = append(out, entry)
	}
	return map[string]any{
		"summary": summary,
		"entries": out,
	}
}

func complianceSummary(profile string, state SourceState) map[string]any {
	controls := []map[string]any{
		control("audit-integrity", state.IntegrityOK, integrityDetail(state.IntegrityOK, state.IntegrityError)),
		control("audit-window", len(state.AuditEntries) > 0, fmt.Sprintf("%d audit entries retained in report payload", len(state.AuditEntries))),
		control("version-history", len(state.Versions) > 0, fmt.Sprintf("%d policy versions retained in report payload", len(state.Versions))),
		control("log-context", len(state.SystemLogs) > 0, fmt.Sprintf("%d local system log entries retained when available", len(state.SystemLogs))),
		control("custody-boundary", false, "server-retained report is unsigned and not retention-enforced"),
	}
	passed := 0
	for _, item := range controls {
		if item["status"] == "passed" {
			passed++
		}
	}
	return map[string]any{
		"profile":      normalizeProfile(profile),
		"profileLabel": ProfileLabel(profile),
		"scope":        "server-retained-audit-version-log-window",
		"controlCount": len(controls),
		"passed":       passed,
		"review":       len(controls) - passed,
		"controls":     controls,
	}
}

func control(id string, ok bool, detail string) map[string]any {
	status := "review"
	if ok {
		status = "passed"
	}
	return map[string]any{"id": id, "status": status, "detail": detail}
}

func integrityDetail(ok bool, errText string) string {
	if ok {
		return "audit hash chain verified"
	}
	if errText != "" {
		return sanitize(errText)
	}
	return "audit hash chain needs review"
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)
	value = secretRE.ReplaceAllString(value, "[redacted]")
	value = pathRE.ReplaceAllString(value, "${1}[redacted-path]")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 2048 {
		return strings.TrimSpace(value[:2048])
	}
	return value
}

func newID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "report-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

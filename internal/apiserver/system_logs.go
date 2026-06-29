package apiserver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

const (
	systemLogsSchemaVersion = "openngfw.system_logs.v1"
	defaultSystemLogLimit   = 100
	maxSystemLogLimit       = 500
	maxSystemLogFiles       = 32
	maxSystemLogLineBytes   = 16 * 1024
	maxSystemLogScanLines   = 20000
)

var (
	logSecretAssignmentRE = regexp.MustCompile(`(?i)\b([a-z0-9_-]*(?:token|secret|password|authorization|cookie)|saml_response)=\S+`)
	logBearerRE           = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	logPathRE             = regexp.MustCompile(`(?:/[A-Za-z0-9._~@%+=:,;-]+){2,}`)
)

type systemLogCandidate struct {
	path   string
	file   string
	source string
	engine string
}

type parsedSystemLogLine struct {
	timestamp time.Time
	severity  string
	message   string
	facility  string
}

func (s *SystemService) ListSystemLogs(_ context.Context, req *openngfwv1.ListSystemLogsRequest) (*openngfwv1.ListSystemLogsResponse, error) {
	if req == nil {
		req = &openngfwv1.ListSystemLogsRequest{}
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultSystemLogLimit
	}
	if limit > maxSystemLogLimit {
		limit = maxSystemLogLimit
	}
	since, err := parseOptionalLogTime(req.GetSince(), "since")
	if err != nil {
		return nil, err
	}
	until, err := parseOptionalLogTime(req.GetUntil(), "until")
	if err != nil {
		return nil, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return nil, grpcstatus.Error(codes.InvalidArgument, "since must be before until")
	}

	filter := systemLogFilter{
		source:   normalizeLogFacet(req.GetSource()),
		engine:   strings.ToLower(strings.TrimSpace(req.GetEngine())),
		severity: normalizeLogSeverity(req.GetSeverity()),
		query:    strings.ToLower(strings.TrimSpace(req.GetQuery())),
		since:    since,
		until:    until,
	}
	resp := &openngfwv1.ListSystemLogsResponse{
		SchemaVersion: systemLogsSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Summary:       &openngfwv1.SystemLogSummary{},
	}

	candidates, warnings := s.systemLogCandidates()
	resp.Summary.Warnings = append(resp.Summary.Warnings, warnings...)
	if len(candidates) == 0 {
		resp.Summary.Warnings = append(resp.Summary.Warnings, "no readable OpenNGFW system log files were found under the configured log root")
		return resp, nil
	}
	for _, candidate := range candidates {
		if !filter.fileAllowed(candidate) {
			continue
		}
		resp.Summary.ScannedFiles++
		if err := scanSystemLogFile(candidate, filter, limit, resp); err != nil {
			resp.Summary.Warnings = append(resp.Summary.Warnings, fmt.Sprintf("%s could not be read: %v", candidate.file, err))
		}
		if len(resp.Entries) >= limit {
			resp.Summary.Truncated = true
			break
		}
		if resp.Summary.ScannedLines >= maxSystemLogScanLines {
			resp.Summary.Truncated = true
			resp.Summary.Warnings = append(resp.Summary.Warnings, "system log scan line cap reached before all files were inspected")
			break
		}
	}
	sort.SliceStable(resp.Entries, func(i, j int) bool {
		left, right := resp.Entries[i].GetTimestamp(), resp.Entries[j].GetTimestamp()
		if left == "" || right == "" {
			return i < j
		}
		return left > right
	})
	if len(resp.Entries) > limit {
		resp.Entries = resp.Entries[:limit]
		resp.Summary.Truncated = true
	}
	finalizeSystemLogSummary(resp.Summary, resp.Entries)
	return resp, nil
}

type systemLogFilter struct {
	source   string
	engine   string
	severity string
	query    string
	since    time.Time
	until    time.Time
}

func (f systemLogFilter) fileAllowed(candidate systemLogCandidate) bool {
	if f.source != "" && f.source != "all" && candidate.source != f.source {
		return false
	}
	if f.engine != "" && candidate.engine != f.engine {
		return false
	}
	return true
}

func (f systemLogFilter) lineAllowed(line parsedSystemLogLine) bool {
	if f.severity != "" && f.severity != "all" && line.severity != f.severity {
		return false
	}
	if !line.timestamp.IsZero() {
		if !f.since.IsZero() && line.timestamp.Before(f.since) {
			return false
		}
		if !f.until.IsZero() && line.timestamp.After(f.until) {
			return false
		}
	}
	if f.query != "" && !strings.Contains(strings.ToLower(line.message), f.query) {
		return false
	}
	return true
}

func (s *SystemService) systemLogCandidates() ([]systemLogCandidate, []string) {
	root := strings.TrimSpace(s.Status.LogDir)
	if root == "" {
		root = "/var/log/openngfw"
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, []string{"configured log root could not be resolved"}
	}
	info, err := os.Stat(cleanRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, []string{"configured log root is not present"}
		}
		return nil, []string{"configured log root could not be inspected"}
	}
	if !info.IsDir() {
		return nil, []string{"configured log root is not a directory"}
	}

	var candidates []systemLogCandidate
	var warnings []string
	err = filepath.WalkDir(cleanRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, "a log directory entry could not be inspected")
			return nil
		}
		if path == cleanRoot {
			return nil
		}
		if entry.IsDir() {
			rel, _ := filepath.Rel(cleanRoot, path)
			if strings.Count(rel, string(os.PathSeparator)) >= 2 {
				return filepath.SkipDir
			}
			return nil
		}
		if len(candidates) >= maxSystemLogFiles {
			return filepath.SkipAll
		}
		if entry.Type()&os.ModeType != 0 {
			return nil
		}
		rel, err := filepath.Rel(cleanRoot, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil
		}
		file := filepath.ToSlash(rel)
		if !systemLogFileAllowed(file) {
			return nil
		}
		source, engine := classifySystemLogFile(file)
		candidates = append(candidates, systemLogCandidate{path: path, file: file, source: source, engine: engine})
		return nil
	})
	if err != nil {
		warnings = append(warnings, "log root scan stopped before all files were inspected")
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftInfo, leftErr := os.Stat(candidates[i].path)
		rightInfo, rightErr := os.Stat(candidates[j].path)
		if leftErr == nil && rightErr == nil && !leftInfo.ModTime().Equal(rightInfo.ModTime()) {
			return leftInfo.ModTime().After(rightInfo.ModTime())
		}
		return candidates[i].file < candidates[j].file
	})
	return candidates, warnings
}

func systemLogFileAllowed(file string) bool {
	base := strings.ToLower(filepath.Base(file))
	if strings.HasPrefix(base, ".") {
		return false
	}
	if strings.HasSuffix(base, ".log") || strings.HasSuffix(base, ".jsonl") || strings.HasSuffix(base, ".json") {
		return true
	}
	return strings.HasPrefix(base, "openngfw") || strings.HasPrefix(base, "controld") || strings.HasPrefix(base, "suricata") || strings.HasPrefix(base, "vector")
}

func classifySystemLogFile(file string) (string, string) {
	lower := strings.ToLower(file)
	engineNames := []string{"suricata", "vector", "frr", "strongswan", "wireguard", "nftables", "routes", "netdev"}
	for _, engine := range engineNames {
		if strings.Contains(lower, engine) {
			return "engine", engine
		}
	}
	if strings.Contains(lower, "audit") {
		return "audit", ""
	}
	if strings.Contains(lower, "dataplane") || strings.Contains(lower, "nft") || strings.Contains(lower, "conntrack") {
		return "dataplane", ""
	}
	return "system", ""
}

func scanSystemLogFile(candidate systemLogCandidate, filter systemLogFilter, limit int, resp *openngfwv1.ListSystemLogsResponse) error {
	file, err := os.Open(candidate.path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), maxSystemLogLineBytes)
	var lineNo uint32
	for scanner.Scan() {
		lineNo++
		resp.Summary.ScannedLines++
		if resp.Summary.ScannedLines > maxSystemLogScanLines {
			break
		}
		parsed := parseSystemLogLine(scanner.Text())
		if parsed.message == "" {
			continue
		}
		if !filter.lineAllowed(parsed) {
			continue
		}
		resp.Summary.MatchedLines++
		entry := &openngfwv1.SystemLogEntry{
			Id:        systemLogEntryID(candidate.file, lineNo, parsed.message),
			Timestamp: parsed.timestamp.Format(time.RFC3339Nano),
			Source:    candidate.source,
			Engine:    candidate.engine,
			Severity:  parsed.severity,
			Message:   parsed.message,
			Facility:  parsed.facility,
			File:      candidate.file,
			Line:      lineNo,
		}
		if parsed.timestamp.IsZero() {
			entry.Timestamp = ""
		}
		resp.Entries = append(resp.Entries, entry)
		if len(resp.Entries) >= limit {
			break
		}
	}
	scanErr := scanner.Err()
	closeErr := file.Close()
	if scanErr != nil {
		return scanErr
	}
	if closeErr != nil {
		return fmt.Errorf("close system log file %q: %w", candidate.file, closeErr)
	}
	return nil
}

func parseSystemLogLine(raw string) parsedSystemLogLine {
	redacted := redactSystemLogText(strings.TrimSpace(raw))
	if redacted == "" {
		return parsedSystemLogLine{}
	}
	if parsed, ok := parseJSONSystemLogLine(redacted); ok {
		return parsed
	}
	timestamp, rest := splitLeadingTimestamp(redacted)
	return parsedSystemLogLine{
		timestamp: timestamp,
		severity:  inferLogSeverity(rest),
		message:   strings.TrimSpace(rest),
	}
}

func parseJSONSystemLogLine(raw string) (parsedSystemLogLine, bool) {
	if !strings.HasPrefix(raw, "{") {
		return parsedSystemLogLine{}, false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return parsedSystemLogLine{}, false
	}
	msg := firstStringField(obj, "message", "msg", "detail", "error")
	if msg == "" {
		msg = raw
	}
	ts, _ := parseLogTime(firstStringField(obj, "timestamp", "time", "ts", "created_at"))
	sev := normalizeLogSeverity(firstStringField(obj, "severity", "level", "lvl"))
	if sev == "" {
		sev = inferLogSeverity(msg)
	}
	return parsedSystemLogLine{
		timestamp: ts,
		severity:  sev,
		message:   redactSystemLogText(msg),
		facility:  redactSystemLogText(firstStringField(obj, "facility", "component", "logger", "module")),
	}, true
}

func firstStringField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := obj[key]; ok {
			switch t := v.(type) {
			case string:
				return strings.TrimSpace(t)
			case json.Number:
				return t.String()
			case float64:
				return strconv.FormatFloat(t, 'f', -1, 64)
			}
		}
	}
	return ""
}

func splitLeadingTimestamp(raw string) (time.Time, string) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return time.Time{}, raw
	}
	candidates := []string{fields[0]}
	if len(fields) > 1 {
		candidates = append(candidates, fields[0]+" "+fields[1])
	}
	for _, candidate := range candidates {
		if ts, ok := parseLogTime(strings.Trim(candidate, "[]")); ok {
			return ts, strings.TrimSpace(strings.TrimPrefix(raw, candidate))
		}
	}
	return time.Time{}, raw
}

func parseOptionalLogTime(value, field string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if ts, ok := parseLogTime(value); ok {
		return ts, nil
	}
	return time.Time{}, grpcstatus.Errorf(codes.InvalidArgument, "%s must be RFC3339", field)
}

func parseLogTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000-0700", "2006-01-02 15:04:05"}
	for _, format := range formats {
		if ts, err := time.Parse(format, value); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func normalizeLogFacet(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "any":
		return ""
	case "system", "engine", "audit", "dataplane":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeLogSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "any":
		return ""
	case "warning", "warn":
		return "warn"
	case "err", "error", "failed", "failure":
		return "error"
	case "crit", "critical", "fatal", "panic":
		return "critical"
	case "notice":
		return "notice"
	case "debug":
		return "debug"
	default:
		return "info"
	}
}

func inferLogSeverity(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") || strings.Contains(lower, "critical"):
		return "critical"
	case strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "denied"):
		return "error"
	case strings.Contains(lower, "warn"):
		return "warn"
	case strings.Contains(lower, "debug") || strings.Contains(lower, "trace"):
		return "debug"
	case strings.Contains(lower, "notice"):
		return "notice"
	default:
		return "info"
	}
}

func redactSystemLogText(value string) string {
	value = strings.TrimSpace(value)
	value = logBearerRE.ReplaceAllString(value, "Bearer [redacted]")
	value = logSecretAssignmentRE.ReplaceAllString(value, "$1=[redacted]")
	value = logPathRE.ReplaceAllStringFunc(value, func(path string) string {
		base := filepath.Base(path)
		if base == "." || base == string(os.PathSeparator) || base == "" {
			return "[path-redacted]"
		}
		return "[path-redacted]/" + base
	})
	return value
}

func systemLogEntryID(file string, line uint32, message string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", file, line, message)))
	return hex.EncodeToString(sum[:8])
}

func finalizeSystemLogSummary(summary *openngfwv1.SystemLogSummary, entries []*openngfwv1.SystemLogEntry) {
	sourceSet := map[string]struct{}{}
	severitySet := map[string]struct{}{}
	engineSet := map[string]struct{}{}
	for _, entry := range entries {
		if entry.GetSource() != "" {
			sourceSet[entry.GetSource()] = struct{}{}
		}
		if entry.GetSeverity() != "" {
			severitySet[entry.GetSeverity()] = struct{}{}
		}
		if entry.GetEngine() != "" {
			engineSet[entry.GetEngine()] = struct{}{}
		}
	}
	summary.Sources = sortedKeys(sourceSet)
	summary.Severities = sortedKeys(severitySet)
	summary.Engines = sortedKeys(engineSet)
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

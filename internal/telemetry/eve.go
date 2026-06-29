// Package telemetry reads engine event streams. The API serves recent
// Suricata EVE alerts and flows after normalizing them into OpenNGFW
// App-ID and Threat-ID fields; long-term analytics belong to the
// Vector → ClickHouse pipeline.
package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/appid"
	"github.com/detailtech/oss-ngfw/internal/threatid"
)

// Alert is one Suricata alert event.
type Alert struct {
	Timestamp        time.Time
	Signature        string
	SignatureID      int64
	Severity         int
	Category         string
	SrcIP            string
	SrcPort          int
	DestIP           string
	DestPort         int
	Proto            string
	Action           string
	ThreatID         string
	ThreatName       string
	ThreatCategory   string
	ThreatSeverity   string
	ThreatConfidence uint32
	ThreatEvidence   []string
	PolicyVersion    uint64
	PolicyStamp      string
	PolicyFreshness  string
	PolicySource     string
	FlowID           string
}

// AlertFilter restricts recent alert queries. Empty fields are ignored.
type AlertFilter struct {
	Limit          int
	Offset         int
	SrcIP          string
	DestIP         string
	IP             string
	Protocol       string
	Action         string
	Severity       uint32
	ThreatSeverity string
	SignatureID    int64
	Port           uint32
	Since          time.Time
	Until          time.Time
	Query          string
	FlowID         string
}

// PageInfo describes one cursor page over a filtered telemetry view.
type PageInfo struct {
	NextCursor   string
	HasMore      bool
	TotalMatches int
}

// eveEvent mirrors the EVE JSON fields we consume.
type eveEvent struct {
	Timestamp       string                 `json:"timestamp"`
	EventType       string                 `json:"event_type"`
	SrcIP           string                 `json:"src_ip"`
	SrcPort         int                    `json:"src_port"`
	DestIP          string                 `json:"dest_ip"`
	DestPort        int                    `json:"dest_port"`
	Proto           string                 `json:"proto"`
	FlowID          json.RawMessage        `json:"flow_id"`
	PolicyVersion   uint64                 `json:"policy_version"`
	PolicyStamp     string                 `json:"policy_stamp"`
	PolicyFreshness string                 `json:"policy_freshness"`
	Phragma         telemetryPolicyContext `json:"phragma"`
	OpenNGFW        telemetryPolicyContext `json:"openngfw"`
	Alert           struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

type telemetryPolicyContext struct {
	PolicyVersion        uint64 `json:"policy_version"`
	ConfigVersion        uint64 `json:"config_version"`
	RunningPolicyVersion uint64 `json:"running_policy_version"`
	PolicyStamp          string `json:"policy_stamp"`
	PolicyFreshness      string `json:"policy_freshness"`
	Stamp                string `json:"stamp"`
	Freshness            string `json:"freshness"`
	Source               string `json:"source"`
}

// EventPolicyStamp records the policy version and provenance attached to an
// engine event.
type EventPolicyStamp struct {
	Version   uint64
	Stamp     string
	Freshness string
	Source    string
}

// maxTail bounds how much of a large EVE file is scanned (newest part).
const maxTail = 16 << 20 // 16 MiB

// ReadAlerts returns up to limit alert events from the EVE file at path,
// newest first. A missing file yields an empty list — IDS may simply be
// disabled or not have logged yet.
func ReadAlerts(path string, limit int) ([]Alert, error) {
	return ReadAlertsFiltered(path, AlertFilter{Limit: limit})
}

// ReadAlertsFiltered returns matching alert events, newest first. A missing
// file yields an empty list because IDS may simply be disabled or idle.
func ReadAlertsFiltered(path string, filter AlertFilter) ([]Alert, error) {
	return ReadAlertsFilteredWithThreatMetadata(path, filter, nil)
}

// ReadAlertsFilteredWithThreatMetadata returns matching alert events using
// supplied signed Threat-ID package metadata before built-in classification.
func ReadAlertsFilteredWithThreatMetadata(path string, filter AlertFilter, metadata []threatid.PackageMetadata) ([]Alert, error) {
	alerts, _, err := ReadAlertsFilteredPageWithThreatMetadata(path, filter, metadata)
	return alerts, err
}

// ReadAlertsFilteredPageWithThreatMetadata returns one cursor page of matching
// alerts. Cursors are opaque decimal offsets into the filtered newest-first
// recent-tail view.
func ReadAlertsFilteredPageWithThreatMetadata(path string, filter AlertFilter, metadata []threatid.PackageMetadata) ([]Alert, PageInfo, error) {
	limit := normalizedLimit(filter.Limit)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, PageInfo{}, nil
	}
	if err != nil {
		return nil, PageInfo{}, err
	}
	defer func() { _ = f.Close() }()

	if fi, err := f.Stat(); err == nil && fi.Size() > maxTail {
		if _, err := f.Seek(fi.Size()-maxTail, io.SeekStart); err != nil {
			return nil, PageInfo{}, err
		}
		// Skip the (likely partial) first line after seeking.
		r := bufio.NewReader(f)
		_, _ = r.ReadString('\n')
		return scanAlerts(r, filter, limit, metadata)
	}
	return scanAlerts(bufio.NewReader(f), filter, limit, metadata)
}

func scanAlerts(r io.Reader, filter AlertFilter, limit int, metadata []threatid.PackageMetadata) ([]Alert, PageInfo, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var alerts []Alert
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev eveEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // tolerate partial/corrupt lines in a live file
		}
		if ev.EventType != "alert" {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", ev.Timestamp)
		if err != nil {
			ts = time.Time{}
		}
		policy := eventPolicyStamp(
			ev.PolicyVersion,
			ev.PolicyStamp,
			ev.PolicyFreshness,
			ev.Phragma,
			ev.OpenNGFW,
		)
		alerts = append(alerts, Alert{
			Timestamp:       ts,
			Signature:       ev.Alert.Signature,
			SignatureID:     ev.Alert.SignatureID,
			Severity:        ev.Alert.Severity,
			Category:        ev.Alert.Category,
			SrcIP:           ev.SrcIP,
			SrcPort:         ev.SrcPort,
			DestIP:          ev.DestIP,
			DestPort:        ev.DestPort,
			Proto:           ev.Proto,
			Action:          ev.Alert.Action,
			FlowID:          rawIDString(ev.FlowID),
			PolicyVersion:   policy.Version,
			PolicyStamp:     policy.Stamp,
			PolicyFreshness: policy.Freshness,
			PolicySource:    policy.Source,
		})
		threat := threatid.ClassifyWithMetadata(ev.Alert.Signature, ev.Alert.SignatureID, ev.Alert.Category, ev.Alert.Severity, ev.Alert.Action, metadata)
		alerts[len(alerts)-1].ThreatID = threat.ID
		alerts[len(alerts)-1].ThreatName = threat.Name
		alerts[len(alerts)-1].ThreatCategory = threat.Category
		alerts[len(alerts)-1].ThreatSeverity = threat.Severity
		alerts[len(alerts)-1].ThreatConfidence = threat.Confidence
		alerts[len(alerts)-1].ThreatEvidence = threat.Evidence
	}
	if err := sc.Err(); err != nil {
		return nil, PageInfo{}, fmt.Errorf("scan eve file: %w", err)
	}
	// Newest first, capped at limit.
	for i, j := 0, len(alerts)-1; i < j; i, j = i+1, j-1 {
		alerts[i], alerts[j] = alerts[j], alerts[i]
	}
	offset := normalizedOffset(filter.Offset)
	filtered := make([]Alert, 0, min(limit, len(alerts)))
	totalMatches := 0
	for _, alert := range alerts {
		if !alertMatches(alert, filter) {
			continue
		}
		totalMatches++
		if totalMatches <= offset {
			continue
		}
		if len(filtered) == limit {
			continue
		}
		filtered = append(filtered, alert)
	}
	page := pageInfo(offset, len(filtered), totalMatches)
	return filtered, page, nil
}

// Flow is one Suricata flow record with its app-layer label.
type Flow struct {
	Timestamp       time.Time
	SrcIP           string
	SrcPort         int
	DestIP          string
	DestPort        int
	Proto           string
	AppProto        string
	BytesToServer   uint64
	BytesToClient   uint64
	Packets         uint64
	AppID           string
	AppName         string
	AppCategory     string
	AppConfidence   uint32
	AppEvidence     []string
	PolicyVersion   uint64
	PolicyStamp     string
	PolicyFreshness string
	PolicySource    string
	FlowID          string
}

// FlowFilter restricts recent flow queries. Empty fields are ignored.
type FlowFilter struct {
	Limit    int
	Offset   int
	SrcIP    string
	DestIP   string
	IP       string
	Protocol string
	App      string
	Port     uint32
	Since    time.Time
	Until    time.Time
	Query    string
	FlowID   string
}

type eveFlowEvent struct {
	Timestamp       string                 `json:"timestamp"`
	EventType       string                 `json:"event_type"`
	SrcIP           string                 `json:"src_ip"`
	SrcPort         int                    `json:"src_port"`
	DestIP          string                 `json:"dest_ip"`
	DestPort        int                    `json:"dest_port"`
	Proto           string                 `json:"proto"`
	AppProto        string                 `json:"app_proto"`
	FlowID          json.RawMessage        `json:"flow_id"`
	PolicyVersion   uint64                 `json:"policy_version"`
	PolicyStamp     string                 `json:"policy_stamp"`
	PolicyFreshness string                 `json:"policy_freshness"`
	Phragma         telemetryPolicyContext `json:"phragma"`
	OpenNGFW        telemetryPolicyContext `json:"openngfw"`
	Flow            struct {
		PktsToserver  uint64 `json:"pkts_toserver"`
		PktsToclient  uint64 `json:"pkts_toclient"`
		BytesToserver uint64 `json:"bytes_toserver"`
		BytesToclient uint64 `json:"bytes_toclient"`
	} `json:"flow"`
}

// ReadFlows returns up to limit flow events from the EVE file, newest
// first. App labels come from the engine's app-layer classification.
func ReadFlows(path string, limit int) ([]Flow, error) {
	return ReadFlowsFiltered(path, FlowFilter{Limit: limit})
}

// ReadFlowsFiltered returns matching flow events, newest first.
func ReadFlowsFiltered(path string, filter FlowFilter) ([]Flow, error) {
	return ReadFlowsFilteredWithAppDefinitions(path, filter, nil)
}

// ReadFlowsFilteredWithAppDefinitions returns matching flow events using the
// supplied OpenNGFW App-ID definitions before built-in classification.
func ReadFlowsFilteredWithAppDefinitions(path string, filter FlowFilter, appDefinitions []appid.Definition) ([]Flow, error) {
	flows, _, err := ReadFlowsFilteredPageWithAppDefinitions(path, filter, appDefinitions)
	return flows, err
}

// ReadFlowsFilteredPageWithAppDefinitions returns one cursor page of matching
// flows. Cursors are opaque decimal offsets into the filtered newest-first
// recent-tail view.
func ReadFlowsFilteredPageWithAppDefinitions(path string, filter FlowFilter, appDefinitions []appid.Definition) ([]Flow, PageInfo, error) {
	limit := normalizedLimit(filter.Limit)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, PageInfo{}, nil
	}
	if err != nil {
		return nil, PageInfo{}, err
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if fi, err := f.Stat(); err == nil && fi.Size() > maxTail {
		if _, err := f.Seek(fi.Size()-maxTail, io.SeekStart); err != nil {
			return nil, PageInfo{}, err
		}
		br := bufio.NewReader(f)
		_, _ = br.ReadString('\n')
		r = br
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var flows []Flow
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev eveFlowEvent
		if err := json.Unmarshal(line, &ev); err != nil || ev.EventType != "flow" {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", ev.Timestamp)
		if err != nil {
			ts = time.Time{}
		}
		policy := eventPolicyStamp(
			ev.PolicyVersion,
			ev.PolicyStamp,
			ev.PolicyFreshness,
			ev.Phragma,
			ev.OpenNGFW,
		)
		flows = append(flows, Flow{
			Timestamp: ts, SrcIP: ev.SrcIP, SrcPort: ev.SrcPort,
			DestIP: ev.DestIP, DestPort: ev.DestPort, Proto: ev.Proto,
			AppProto:      ev.AppProto,
			BytesToServer: ev.Flow.BytesToserver, BytesToClient: ev.Flow.BytesToclient,
			Packets:         ev.Flow.PktsToserver + ev.Flow.PktsToclient,
			FlowID:          rawIDString(ev.FlowID),
			PolicyVersion:   policy.Version,
			PolicyStamp:     policy.Stamp,
			PolicyFreshness: policy.Freshness,
			PolicySource:    policy.Source,
		})
		app := appid.ClassifyWithDefinitions(ev.AppProto, ev.Proto, ev.DestPort, appDefinitions)
		flows[len(flows)-1].AppID = app.ID
		flows[len(flows)-1].AppName = app.Name
		flows[len(flows)-1].AppCategory = app.Category
		flows[len(flows)-1].AppConfidence = app.Confidence
		flows[len(flows)-1].AppEvidence = app.Evidence
	}
	if err := sc.Err(); err != nil {
		return nil, PageInfo{}, fmt.Errorf("scan eve file: %w", err)
	}
	for i, j := 0, len(flows)-1; i < j; i, j = i+1, j-1 {
		flows[i], flows[j] = flows[j], flows[i]
	}
	offset := normalizedOffset(filter.Offset)
	filtered := make([]Flow, 0, min(limit, len(flows)))
	totalMatches := 0
	for _, flow := range flows {
		if !flowMatches(flow, filter) {
			continue
		}
		totalMatches++
		if totalMatches <= offset {
			continue
		}
		if len(filtered) == limit {
			continue
		}
		filtered = append(filtered, flow)
	}
	page := pageInfo(offset, len(filtered), totalMatches)
	return filtered, page, nil
}

func rawIDString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(raw))
}

func eventPolicyStamp(direct uint64, directStamp, directFreshness string, contexts ...telemetryPolicyContext) EventPolicyStamp {
	if direct != 0 {
		return EventPolicyStamp{
			Version:   direct,
			Stamp:     firstNonEmpty(directStamp, fmt.Sprintf("v%d", direct)),
			Freshness: strings.TrimSpace(directFreshness),
			Source:    "event.policy_version",
		}
	}
	for _, ctx := range contexts {
		if ctx.PolicyVersion != 0 {
			return policyStampFromContext(ctx.PolicyVersion, "event policy_version", ctx)
		}
		if ctx.ConfigVersion != 0 {
			return policyStampFromContext(ctx.ConfigVersion, "event config_version", ctx)
		}
		if ctx.RunningPolicyVersion != 0 {
			return policyStampFromContext(ctx.RunningPolicyVersion, "event running_policy_version", ctx)
		}
	}
	return EventPolicyStamp{
		Stamp:     strings.TrimSpace(directStamp),
		Freshness: strings.TrimSpace(directFreshness),
	}
}

func policyStampFromContext(version uint64, source string, ctx telemetryPolicyContext) EventPolicyStamp {
	return EventPolicyStamp{
		Version:   version,
		Stamp:     firstNonEmpty(ctx.PolicyStamp, ctx.Stamp, fmt.Sprintf("v%d", version)),
		Freshness: firstNonEmpty(ctx.PolicyFreshness, ctx.Freshness),
		Source:    firstNonEmpty(ctx.Source, source),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return ""
}

func alertMatches(a Alert, filter AlertFilter) bool {
	if filter.SrcIP != "" && a.SrcIP != filter.SrcIP {
		return false
	}
	if filter.DestIP != "" && a.DestIP != filter.DestIP {
		return false
	}
	if filter.IP != "" && a.SrcIP != filter.IP && a.DestIP != filter.IP {
		return false
	}
	if filter.Protocol != "" && !strings.EqualFold(a.Proto, filter.Protocol) {
		return false
	}
	if filter.Action != "" && !strings.EqualFold(a.Action, filter.Action) {
		return false
	}
	if filter.Severity != 0 && uint32(a.Severity) != filter.Severity {
		return false
	}
	if filter.ThreatSeverity != "" && !strings.EqualFold(a.ThreatSeverity, filter.ThreatSeverity) {
		return false
	}
	if filter.SignatureID != 0 && a.SignatureID != filter.SignatureID {
		return false
	}
	if filter.Port != 0 && uint32(a.SrcPort) != filter.Port && uint32(a.DestPort) != filter.Port {
		return false
	}
	if filter.FlowID != "" && a.FlowID != filter.FlowID {
		return false
	}
	if !timeInRange(a.Timestamp, filter.Since, filter.Until) {
		return false
	}
	if filter.Query != "" && !containsFold(strings.Join([]string{
		a.SrcIP,
		a.DestIP,
		a.Proto,
		a.Action,
		a.Signature,
		a.Category,
		a.ThreatID,
		a.ThreatName,
		a.ThreatCategory,
		a.ThreatSeverity,
		a.FlowID,
		strings.Join(a.ThreatEvidence, "\n"),
	}, "\n"), filter.Query) {
		return false
	}
	return true
}

func flowMatches(f Flow, filter FlowFilter) bool {
	if filter.SrcIP != "" && f.SrcIP != filter.SrcIP {
		return false
	}
	if filter.DestIP != "" && f.DestIP != filter.DestIP {
		return false
	}
	if filter.IP != "" && f.SrcIP != filter.IP && f.DestIP != filter.IP {
		return false
	}
	if filter.Protocol != "" && !strings.EqualFold(f.Proto, filter.Protocol) {
		return false
	}
	if filter.App != "" && !containsFold(strings.Join([]string{
		f.AppID,
		f.AppName,
		f.AppCategory,
		f.AppProto,
		strings.Join(f.AppEvidence, "\n"),
	}, "\n"), filter.App) {
		return false
	}
	if filter.Port != 0 && uint32(f.SrcPort) != filter.Port && uint32(f.DestPort) != filter.Port {
		return false
	}
	if filter.FlowID != "" && f.FlowID != filter.FlowID {
		return false
	}
	if !timeInRange(f.Timestamp, filter.Since, filter.Until) {
		return false
	}
	if filter.Query != "" && !containsFold(strings.Join([]string{
		f.SrcIP,
		f.DestIP,
		f.Proto,
		f.AppProto,
		f.AppID,
		f.AppName,
		f.AppCategory,
		f.FlowID,
		strings.Join(f.AppEvidence, "\n"),
	}, "\n"), filter.Query) {
		return false
	}
	return true
}

func normalizedLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	return limit
}

func normalizedOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func pageInfo(offset, returned, total int) PageInfo {
	next := offset + returned
	info := PageInfo{TotalMatches: total, HasMore: next < total}
	if info.HasMore {
		info.NextCursor = fmt.Sprintf("%d", next)
	}
	return info
}

func timeInRange(ts, since, until time.Time) bool {
	if ts.IsZero() {
		return since.IsZero() && until.IsZero()
	}
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

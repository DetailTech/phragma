// Package telemetry reads engine event streams. The API serves recent
// alerts straight from Suricata's EVE file; long-term analytics belong
// to the Vector → ClickHouse pipeline.
package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Alert is one Suricata alert event.
type Alert struct {
	Timestamp   time.Time
	Signature   string
	SignatureID int64
	Severity    int
	Category    string
	SrcIP       string
	SrcPort     int
	DestIP      string
	DestPort    int
	Proto       string
	Action      string
}

// eveEvent mirrors the EVE JSON fields we consume.
type eveEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// maxTail bounds how much of a large EVE file is scanned (newest part).
const maxTail = 16 << 20 // 16 MiB

// ReadAlerts returns up to limit alert events from the EVE file at path,
// newest first. A missing file yields an empty list — IDS may simply be
// disabled or not have logged yet.
func ReadAlerts(path string, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if fi, err := f.Stat(); err == nil && fi.Size() > maxTail {
		if _, err := f.Seek(fi.Size()-maxTail, io.SeekStart); err != nil {
			return nil, err
		}
		// Skip the (likely partial) first line after seeking.
		r := bufio.NewReader(f)
		_, _ = r.ReadString('\n')
		return scanAlerts(r, limit)
	}
	return scanAlerts(bufio.NewReader(f), limit)
}

func scanAlerts(r io.Reader, limit int) ([]Alert, error) {
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
		alerts = append(alerts, Alert{
			Timestamp:   ts,
			Signature:   ev.Alert.Signature,
			SignatureID: ev.Alert.SignatureID,
			Severity:    ev.Alert.Severity,
			Category:    ev.Alert.Category,
			SrcIP:       ev.SrcIP,
			SrcPort:     ev.SrcPort,
			DestIP:      ev.DestIP,
			DestPort:    ev.DestPort,
			Proto:       ev.Proto,
			Action:      ev.Alert.Action,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan eve file: %w", err)
	}
	// Newest first, capped at limit.
	for i, j := 0, len(alerts)-1; i < j; i, j = i+1, j-1 {
		alerts[i], alerts[j] = alerts[j], alerts[i]
	}
	if len(alerts) > limit {
		alerts = alerts[:limit]
	}
	return alerts, nil
}

// Flow is one Suricata flow record with its app-layer label.
type Flow struct {
	Timestamp     time.Time
	SrcIP         string
	SrcPort       int
	DestIP        string
	DestPort      int
	Proto         string
	AppProto      string
	BytesToServer uint64
	BytesToClient uint64
	Packets       uint64
}

type eveFlowEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Flow      struct {
		PktsToserver  uint64 `json:"pkts_toserver"`
		PktsToclient  uint64 `json:"pkts_toclient"`
		BytesToserver uint64 `json:"bytes_toserver"`
		BytesToclient uint64 `json:"bytes_toclient"`
	} `json:"flow"`
}

// ReadFlows returns up to limit flow events from the EVE file, newest
// first. App labels come from the engine's app-layer classification.
func ReadFlows(path string, limit int) ([]Flow, error) {
	if limit <= 0 {
		limit = 100
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if fi, err := f.Stat(); err == nil && fi.Size() > maxTail {
		if _, err := f.Seek(fi.Size()-maxTail, io.SeekStart); err != nil {
			return nil, err
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
		flows = append(flows, Flow{
			Timestamp: ts, SrcIP: ev.SrcIP, SrcPort: ev.SrcPort,
			DestIP: ev.DestIP, DestPort: ev.DestPort, Proto: ev.Proto,
			AppProto:      ev.AppProto,
			BytesToServer: ev.Flow.BytesToserver, BytesToClient: ev.Flow.BytesToclient,
			Packets: ev.Flow.PktsToserver + ev.Flow.PktsToclient,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan eve file: %w", err)
	}
	for i, j := 0, len(flows)-1; i < j; i, j = i+1, j-1 {
		flows[i], flows[j] = flows[j], flows[i]
	}
	if len(flows) > limit {
		flows = flows[:limit]
	}
	return flows, nil
}

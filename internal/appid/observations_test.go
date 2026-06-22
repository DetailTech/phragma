package appid

import (
	"testing"
	"time"
)

func TestBuildObservationsQueuesUnknownAndKeepsPortHintAsEvidence(t *testing.T) {
	app := Classify("weird-proto", "TCP", 443)
	observations := BuildObservations([]ObservedFlow{observed("2026-06-11T10:00:00Z", "TCP", 443, "weird-proto", app)}, ObservationOptions{})
	if len(observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(observations))
	}
	got := observations[0]
	if got.Kind != ObservationKindUnknown {
		t.Fatalf("Kind = %q, want unknown", got.Kind)
	}
	if got.AppID != "unknown" || got.AppConfidence != 35 {
		t.Fatalf("unexpected app fields: %#v", got)
	}
	if got.EngineSignalSource != "suricata.app_proto" {
		t.Fatalf("EngineSignalSource = %q", got.EngineSignalSource)
	}
	if got.SuggestedApplication.ID != "weird-proto" {
		t.Fatalf("suggestion ID = %q, want weird-proto", got.SuggestedApplication.ID)
	}
	if len(got.SuggestedApplication.EngineSignals) != 1 || got.SuggestedApplication.EngineSignals[0] != "weird-proto" {
		t.Fatalf("suggestion signals = %#v", got.SuggestedApplication.EngineSignals)
	}
	if got.QueueID == "" {
		t.Fatal("expected stable queue ID")
	}
}

func TestBuildObservationsQueuesLowConfidencePortOnly(t *testing.T) {
	app := Classify("", "TCP", 443)
	observations := BuildObservations([]ObservedFlow{observed("2026-06-11T10:00:00Z", "TCP", 443, "", app)}, ObservationOptions{})
	if len(observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(observations))
	}
	got := observations[0]
	if got.Kind != ObservationKindLowConfidence {
		t.Fatalf("Kind = %q, want low_confidence", got.Kind)
	}
	if got.AppID != "ssl" || got.AppConfidence != 60 {
		t.Fatalf("unexpected app fields: %#v", got)
	}
	if got.SuggestedApplication.ID != "ssl-443" || len(got.SuggestedApplication.Ports) != 1 {
		t.Fatalf("unexpected suggestion: %#v", got.SuggestedApplication)
	}
}

func TestBuildObservationsQueuesConflictingEvidence(t *testing.T) {
	app := Classify("http", "TCP", 443)
	observations := BuildObservations([]ObservedFlow{observed("2026-06-11T10:00:00Z", "TCP", 443, "http", app)}, ObservationOptions{})
	if len(observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(observations))
	}
	got := observations[0]
	if got.Kind != ObservationKindConflictingEvidence {
		t.Fatalf("Kind = %q, want conflicting_evidence", got.Kind)
	}
	if got.AppID != "web-browsing" || got.AppConfidence != 80 {
		t.Fatalf("unexpected app fields: %#v", got)
	}
}

func TestBuildObservationsGroupsWithStableIDsAndCounters(t *testing.T) {
	app := Classify("weird-proto", "TCP", 8443)
	flows := []ObservedFlow{
		observed("2026-06-11T10:00:02Z", "TCP", 8443, "weird-proto", app),
		observed("2026-06-11T10:00:01Z", "TCP", 8443, "weird-proto", app),
	}
	flows[0].BytesToServer = 100
	flows[0].BytesToClient = 200
	flows[0].Packets = 3
	flows[0].FlowID = "newest"
	flows[0].SrcPort = 41000
	flows[1].BytesToServer = 10
	flows[1].BytesToClient = 20
	flows[1].Packets = 2
	flows[1].FlowID = "oldest"
	flows[1].SrcPort = 40000
	a := BuildObservations(flows, ObservationOptions{})
	b := BuildObservations([]ObservedFlow{flows[1], flows[0]}, ObservationOptions{})
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("got %d/%d observations, want one each", len(a), len(b))
	}
	if a[0].QueueID != b[0].QueueID {
		t.Fatalf("queue IDs changed with input order: %q vs %q", a[0].QueueID, b[0].QueueID)
	}
	if a[0].Count != 2 || a[0].Bytes != 330 || a[0].Packets != 5 {
		t.Fatalf("unexpected counters: %#v", a[0])
	}
	if a[0].SampleFlowID != "newest" {
		t.Fatalf("SampleFlowID = %q, want newest", a[0].SampleFlowID)
	}
	if a[0].SampleSrcPort != 41000 {
		t.Fatalf("SampleSrcPort = %d, want newest source port 41000", a[0].SampleSrcPort)
	}
	if !a[0].FirstSeen.Before(a[0].LastSeen) {
		t.Fatalf("first/last not preserved: %v %v", a[0].FirstSeen, a[0].LastSeen)
	}
}

func TestBuildObservationsSuppressesHighConfidenceCustomSignal(t *testing.T) {
	app := ClassifyWithDefinitions("corp-admin", "TCP", 8443, []Definition{{
		ID:            "corp-admin",
		Name:          "Corporate Admin",
		Category:      "business-app",
		EngineSignals: []string{"corp-admin"},
	}})
	observations := BuildObservations([]ObservedFlow{observed("2026-06-11T10:00:00Z", "TCP", 8443, "corp-admin", app)}, ObservationOptions{})
	if len(observations) != 0 {
		t.Fatalf("got %#v, want no observations", observations)
	}
}

//nolint:unparam // The protocol argument keeps observation fixtures explicit.
func observed(ts, proto string, port int, signal string, app Result) ObservedFlow {
	t, _ := time.Parse(time.RFC3339, ts)
	return ObservedFlow{
		Timestamp:     t,
		SrcIP:         "10.0.1.10",
		SrcPort:       40000,
		DestIP:        "10.0.2.20",
		DestPort:      port,
		Protocol:      proto,
		EngineSignal:  signal,
		AppID:         app.ID,
		AppName:       app.Name,
		AppCategory:   app.Category,
		AppConfidence: app.Confidence,
		AppEvidence:   app.Evidence,
	}
}

package appid

import "testing"

func TestClassifyUsesEngineSignalAsEvidence(t *testing.T) {
	got := Classify("HTTP", "TCP", 8080)
	if got.ID != "web-browsing" {
		t.Fatalf("ID = %q, want web-browsing", got.ID)
	}
	if got.Confidence != 95 {
		t.Fatalf("confidence = %d, want 95", got.Confidence)
	}
	if len(got.Evidence) != 3 || got.Evidence[0] != "engine signal suricata.app_proto=http" || got.Evidence[2] != "port heuristic tcp/8080 confirms web-browsing" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyReducesConfidenceWhenPortHeuristicConflicts(t *testing.T) {
	got := Classify("http", "TCP", 443)
	if got.ID != "web-browsing" {
		t.Fatalf("ID = %q, want web-browsing", got.ID)
	}
	if got.Confidence != 80 {
		t.Fatalf("confidence = %d, want 80", got.Confidence)
	}
	if len(got.Evidence) != 3 || got.Evidence[2] != "port heuristic tcp/443 suggests ssl; reduced confidence for engine signal http -> web-browsing" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyFallsBackToPortHeuristic(t *testing.T) {
	got := Classify("", "TCP", 443)
	if got.ID != "ssl" {
		t.Fatalf("ID = %q, want ssl", got.ID)
	}
	if got.Confidence != 60 {
		t.Fatalf("confidence = %d, want 60", got.Confidence)
	}
	if len(got.Evidence) != 2 || got.Evidence[1] != "port heuristic tcp/443 -> ssl" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyPreservesUnknownEngineSignal(t *testing.T) {
	got := Classify("weird-proto", "TCP", 12345)
	if got.ID != "unknown" {
		t.Fatalf("ID = %q, want unknown", got.ID)
	}
	if got.Confidence != 35 {
		t.Fatalf("confidence = %d, want 35", got.Confidence)
	}
	if len(got.Evidence) != 2 || got.Evidence[1] != "no OpenNGFW taxonomy match for engine signal" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyDoesNotPromoteUnmappedEngineSignalToPortOnlyAppID(t *testing.T) {
	got := Classify("weird-proto", "TCP", 443)
	if got.ID != "unknown" {
		t.Fatalf("ID = %q, want unknown", got.ID)
	}
	if got.Confidence != 35 {
		t.Fatalf("confidence = %d, want 35", got.Confidence)
	}
	if len(got.Evidence) != 3 || got.Evidence[2] != "port heuristic tcp/443 suggests ssl but engine signal is unmapped; retaining unknown App-ID" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyWithDefinitionsUsesCustomEngineSignal(t *testing.T) {
	got := ClassifyWithDefinitions("corp-admin", "TCP", 8443, []Definition{{
		ID:            "corp-admin",
		Name:          "Corporate Admin",
		Category:      "business-app",
		EngineSignals: []string{"corp-admin"},
		Ports:         []PortMatch{{Protocol: "tcp", Start: 8443}},
	}})
	if got.ID != "corp-admin" {
		t.Fatalf("ID = %q, want corp-admin", got.ID)
	}
	if got.Confidence != 92 {
		t.Fatalf("confidence = %d, want 92", got.Confidence)
	}
	if len(got.Evidence) != 2 || got.Evidence[1] != "custom OpenNGFW App-ID taxonomy match corp-admin -> corp-admin" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyWithDefinitionsUsesCustomPortOnlyWithoutEngineSignal(t *testing.T) {
	defs := []Definition{{
		ID:       "corp-admin",
		Name:     "Corporate Admin",
		Category: "business-app",
		Ports:    []PortMatch{{Protocol: "tcp", Start: 8443}},
	}}
	got := ClassifyWithDefinitions("", "TCP", 8443, defs)
	if got.ID != "corp-admin" {
		t.Fatalf("ID = %q, want corp-admin", got.ID)
	}
	if got.Confidence != 65 {
		t.Fatalf("confidence = %d, want 65", got.Confidence)
	}
	if len(got.Evidence) != 2 || got.Evidence[1] != "custom OpenNGFW port heuristic tcp/8443 -> corp-admin" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}

	withEngine := ClassifyWithDefinitions("tls", "TCP", 8443, defs)
	if withEngine.ID != "ssl" {
		t.Fatalf("known engine signal should remain authoritative, got %#v", withEngine)
	}
}

package threatid

import "testing"

func TestClassifyNormalizesSuricataAlert(t *testing.T) {
	got := Classify("ET EXPLOIT Test Attack", 9000001, "Misc Attack", 1, "blocked")
	if got.ID != "suricata-sid-9000001" {
		t.Fatalf("ID = %q, want suricata-sid-9000001", got.ID)
	}
	if got.Category != "exploit-attempt" {
		t.Fatalf("Category = %q, want exploit-attempt", got.Category)
	}
	if got.Severity != "critical" {
		t.Fatalf("Severity = %q, want critical", got.Severity)
	}
	if got.Confidence != 85 {
		t.Fatalf("Confidence = %d, want 85", got.Confidence)
	}
	if len(got.Evidence) < 5 || got.Evidence[0] != "engine signal suricata.signature_id=9000001" {
		t.Fatalf("unexpected evidence: %#v", got.Evidence)
	}
}

func TestClassifyMapsCredentialAttack(t *testing.T) {
	got := Classify("SSH brute force login", 42, "Attempted Login", 2, "allowed")
	if got.Category != "credential-attack" {
		t.Fatalf("Category = %q, want credential-attack", got.Category)
	}
	if got.Severity != "high" {
		t.Fatalf("Severity = %q, want high", got.Severity)
	}
	if got.Confidence != 80 {
		t.Fatalf("Confidence = %d, want 80", got.Confidence)
	}
}

func TestClassifyHandlesSparseAlert(t *testing.T) {
	got := Classify("", 0, "", 0, "")
	if got.ID != "unknown-threat" {
		t.Fatalf("ID = %q, want unknown-threat", got.ID)
	}
	if got.Name != "Unknown Threat" {
		t.Fatalf("Name = %q, want Unknown Threat", got.Name)
	}
	if got.Category != "suspicious" {
		t.Fatalf("Category = %q, want suspicious", got.Category)
	}
	if got.Severity != "info" {
		t.Fatalf("Severity = %q, want info", got.Severity)
	}
	if got.Confidence != 45 {
		t.Fatalf("Confidence = %d, want 45", got.Confidence)
	}
}

func TestClassifyWithMetadataEnrichesMatchingSID(t *testing.T) {
	got := ClassifyWithMetadata("ET EXPLOIT Test Attack", 9000001, "Misc Attack", 1, "blocked", []PackageMetadata{{
		ID:           "ognfw-threat-9000001",
		Name:         "Managed Exploit Attempt",
		Category:     "exploit-attempt",
		Severity:     "critical",
		Confidence:   96,
		SignatureIDs: []int64{9000001},
		Evidence:     []string{"signed Threat-ID package 1.2.3@abc123"},
	}})
	if got.ID != "ognfw-threat-9000001" {
		t.Fatalf("ID = %q, want package-backed ID", got.ID)
	}
	if got.Name != "Managed Exploit Attempt" {
		t.Fatalf("Name = %q, want package-backed name", got.Name)
	}
	if got.Confidence != 96 {
		t.Fatalf("Confidence = %d, want 96", got.Confidence)
	}
	if got.Evidence[len(got.Evidence)-1] != "signed Threat-ID package 1.2.3@abc123" {
		t.Fatalf("package evidence missing: %#v", got.Evidence)
	}
}

func TestReplayComparesExpectedAndObservedEvidence(t *testing.T) {
	got := Replay([]ReplaySample{{
		ID:          "sample-1",
		Source:      "operator-sample",
		Signature:   "ET EXPLOIT Test Attack",
		SignatureID: 9000001,
		Category:    "Misc Attack",
		Severity:    1,
		Action:      "blocked",
		Expected: ReplayExpected{
			SignatureID: 9000001,
			ThreatID:    "ognfw-threat-9000001",
			Verdict:     "block",
		},
	}}, []PackageMetadata{{
		ID:           "ognfw-threat-9000001",
		Name:         "Managed Exploit Attempt",
		Category:     "exploit-attempt",
		Severity:     "critical",
		Confidence:   96,
		SignatureIDs: []int64{9000001},
		Evidence:     []string{"signed Threat-ID package 1.2.3@abc123"},
	}})
	if len(got) != 1 {
		t.Fatalf("results = %d, want 1", len(got))
	}
	if !got[0].Passed || !got[0].SignatureMatched || !got[0].ThreatIDMatched || !got[0].VerdictMatched {
		t.Fatalf("expected replay pass, got %#v", got[0])
	}
	if got[0].ObservedVerdict != "blocked" {
		t.Fatalf("verdict = %q, want blocked", got[0].ObservedVerdict)
	}
}

func TestReplayReportsMismatchesWithoutCertificationClaim(t *testing.T) {
	got := Replay([]ReplaySample{{
		ID:          "sample-2",
		Source:      "recent-alert",
		Signature:   "ET WEB suspicious",
		SignatureID: 42,
		Category:    "Web Application Attack",
		Severity:    3,
		Action:      "allowed",
		Expected: ReplayExpected{
			SignatureID: 9000001,
			ThreatID:    "phragma.expected",
			Verdict:     "blocked",
		},
	}}, nil)
	if len(got) != 1 {
		t.Fatalf("results = %d, want 1", len(got))
	}
	if got[0].Passed || got[0].SignatureMatched || got[0].ThreatIDMatched || got[0].VerdictMatched {
		t.Fatalf("expected replay mismatch, got %#v", got[0])
	}
	if len(got[0].Warnings) != 3 {
		t.Fatalf("warnings = %#v, want 3 mismatch warnings", got[0].Warnings)
	}
	if len(got[0].Evidence) < 2 || got[0].Evidence[1] != "bounded metadata replay; no packet payload or malware artifact executed" {
		t.Fatalf("missing non-payload evidence disclaimer: %#v", got[0].Evidence)
	}
}

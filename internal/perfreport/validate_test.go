package perfreport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSummaryAcceptsCanonicalReport(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "forwarding-large-flow",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"ping_avg_ms": 0.41,
		"connection_churn": {"attempts": "100"},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only"
	}`))
	if !result.Valid() {
		t.Fatalf("expected valid summary, got errors: %#v", result.Errors)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %#v", result.Warnings)
	}
}

func TestValidateSummaryAcceptsLegacySchemaWithWarning(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "openngfw.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "forwarding-large-flow",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only"
	}`))
	if !result.Valid() {
		t.Fatalf("expected legacy summary to remain valid, got errors: %#v", result.Errors)
	}
	if !contains(result.Warnings, "legacy") {
		t.Fatalf("expected legacy schema warning, got %#v", result.Warnings)
	}
}

func TestValidateSummaryRejectsSecurityServiceInspectionContradictions(t *testing.T) {
	for name, body := range map[string]string{
		"none cannot be fully inspected": `{
			"schema_version": "phragma.perf.v1",
			"generated_at": "2026-06-17T05:00:00Z",
			"profile": "ids-prevent-large-flow",
			"security_services": "none",
			"inspection_state": "fully-inspected",
			"target": {"ip": "10.0.2.20", "port": 5201},
			"duration_seconds": 60,
			"parallel_streams": 16,
			"tcp_bits_per_second": 1000000000,
			"tcp_gbps": 1.0,
			"tcp_retransmits": 0,
			"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
		}`,
		"suricata cannot be not inspected": `{
			"schema_version": "phragma.perf.v1",
			"generated_at": "2026-06-17T05:00:00Z",
			"profile": "cloud-throughput",
			"security_services": "suricata-prevent",
			"inspection_state": "not-inspected",
			"target": {"ip": "10.0.2.20", "port": 5201},
			"duration_seconds": 60,
			"parallel_streams": 16,
			"tcp_bits_per_second": 1000000000,
			"tcp_gbps": 1.0,
			"tcp_retransmits": 0,
			"claim_scope": "measured environment only throughput evidence"
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			result := ValidateSummary([]byte(body))
			if result.Valid() {
				t.Fatal("expected inconsistent security_services and inspection_state to be invalid")
			}
			if !contains(result.Errors, "security_services") {
				t.Fatalf("expected security_services error, got %#v", result.Errors)
			}
		})
	}
}

func TestValidateSummaryWarnsWhenChurnOmitsConntrackEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "forwarding-connection-churn",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"claim_scope": "measured environment only"
	}`))
	if !result.Valid() {
		t.Fatalf("expected missing conntrack evidence to warn only, got errors: %#v", result.Errors)
	}
	if !contains(result.Warnings, "conntrack_evidence") {
		t.Fatalf("expected conntrack evidence warning, got %#v", result.Warnings)
	}
}

func TestValidateSummaryWarnsWhenThroughputOmitsConntrackEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "cloud-throughput",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"claim_scope": "measured environment only throughput evidence"
	}`))
	if !result.Valid() {
		t.Fatalf("expected missing conntrack evidence to warn only, got errors: %#v", result.Errors)
	}
	if !contains(result.Warnings, "conntrack_evidence is recommended for throughput") {
		t.Fatalf("expected throughput conntrack evidence warning, got %#v", result.Warnings)
	}
}

func TestValidateSummaryRejectsInvalidConntrackEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "forwarding-large-flow",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"conntrack_evidence": {
			"state": "",
			"status_captured": false,
			"current_entries": -1,
			"max_entries": -1,
			"usage_percent": -1
		},
		"claim_scope": "measured environment only"
	}`))
	if result.Valid() {
		t.Fatal("expected invalid conntrack evidence")
	}
	for _, want := range []string{
		"conntrack_evidence.status_captured",
		"conntrack_evidence.state",
		"conntrack_evidence.current_entries",
		"conntrack_evidence.max_entries",
		"conntrack_evidence.usage_percent",
	} {
		if !contains(result.Errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, result.Errors)
		}
	}
}

func TestValidateSummaryWarnsOnDegradedHostTuningEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "cloud-throughput",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"host_tuning_evidence": {
			"state": "degraded",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only throughput evidence"
	}`))
	if !result.Valid() {
		t.Fatalf("expected degraded host tuning evidence to warn only, got errors: %#v", result.Errors)
	}
	if !contains(result.Warnings, "host_tuning_evidence state is degraded") {
		t.Fatalf("expected host tuning warning, got %#v", result.Warnings)
	}
	gate := EvaluatePublicationGate(result, false)
	if gate.State != GateBad {
		t.Fatalf("expected degraded host tuning to block publication, got %#v", gate)
	}
	steps := RecommendRepairSteps(result, false)
	if !containsRepairTitle(steps, "Apply the throughput tuning profile") {
		t.Fatalf("expected throughput tuning repair step, got %#v", steps)
	}
}

func TestValidateSummaryWarnsOnNonCanonicalInspectionState(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "local-netns-forwarding",
		"security_services": "none",
		"inspection_state": "forwarding-only",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 20,
		"parallel_streams": 8,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"claim_scope": "single-host netns"
	}`))
	if !result.Valid() {
		t.Fatalf("expected non-canonical inspection state to remain valid, got %#v", result.Errors)
	}
	if len(result.Warnings) != 3 {
		t.Fatalf("expected three warnings, got %#v", result.Warnings)
	}
	if !contains(result.Warnings, "conntrack_evidence") {
		t.Fatalf("expected conntrack evidence warning, got %#v", result.Warnings)
	}
	if !contains(result.Warnings, "host_tuning_evidence") {
		t.Fatalf("expected host tuning evidence warning, got %#v", result.Warnings)
	}
}

func TestValidateSummaryRejectsInspectionEvidenceMismatch(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"inspection_evidence": {
			"state": "failed-open",
			"status_captured": true,
			"inspection_state": "failed-open",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "failed",
			"failure_behavior": "fail-open"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`))
	if result.Valid() {
		t.Fatal("expected inspection evidence mismatch to be invalid")
	}
	if !contains(result.Errors, "inspection_evidence.inspection_state") {
		t.Fatalf("expected inspection_state mismatch, got %#v", result.Errors)
	}
	if !contains(result.Errors, "inspection_evidence.state") {
		t.Fatalf("expected inspection state support error, got %#v", result.Errors)
	}
}

func TestValidateSummaryAcceptsFlowtableEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"flowtable_evidence": {
			"host_state": "ready",
			"runtime_state": "active",
			"status_captured": true,
			"nft_ruleset_captured": true,
			"flowtable_declared": true,
			"offload_rule_present": true
		},
		"claim_scope": "flowtable forwarding benchmark"
	}`))
	if !result.Valid() {
		t.Fatalf("expected valid summary, got errors: %#v", result.Errors)
	}
}

func TestValidateSummaryRejectsFlowtableProfileWithoutEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"claim_scope": "flowtable forwarding benchmark"
	}`))
	if result.Valid() {
		t.Fatal("expected flowtable profile without evidence to be invalid")
	}
	if !contains(result.Errors, "flowtable_evidence") {
		t.Fatalf("expected flowtable_evidence error, got %#v", result.Errors)
	}
}

func TestValidateSummaryFileChecksAdjacentIperfEvidence(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "cloud-throughput",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "iperf3.json"), []byte(`{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 4, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1001000000, "retransmits": 7}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("expected valid artifact, got errors: %#v", result.Errors)
	}
}

func TestValidateSummaryFileRejectsSummaryThatDoesNotMatchIperfEvidence(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "cloud-throughput",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 2000000000,
		"tcp_gbps": 2.0,
		"tcp_retransmits": 9,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "iperf3.json"), []byte(`{
		"start": {
			"connecting_to": {"host": "10.0.2.21", "port": 5202},
			"test_start": {"num_streams": 3, "duration": 30}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1001000000, "retransmits": 7}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if result.Valid() {
		t.Fatal("expected raw-artifact mismatch errors")
	}
	for _, want := range []string{"tcp_bits_per_second", "tcp_gbps", "tcp_retransmits", "target.ip", "target.port", "duration_seconds", "parallel_streams"} {
		if !contains(result.Errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, result.Errors)
		}
	}
}

func TestValidateSummaryFileChecksStatusAndNftEvidence(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"flowtable_evidence": {
			"host_state": "ready",
			"runtime_state": "active",
			"status_captured": true,
			"nft_ruleset_captured": true,
			"flowtable_declared": true,
			"offload_rule_present": true
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"claim_scope": "measured environment only flowtable throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeMatchingIperf(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ngfw-status-active.txt"), []byte(`policy dataplane:
  running policy:  v1
  throughput path: Flowtable fast path
  flowtable host:  ready
  flowtable live:  active
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nft-openngfw-active.txt"), []byte(`table inet openngfw {
  flowtable fastpath {
    hook ingress priority filter
    devices = { ens4, ens5 }
  }
  chain forward {
    ct state established,related flow add @fastpath counter packets 2 bytes 200 comment "flow-offload"
  }
}`), 0o600); err != nil {
		t.Fatalf("write active nft: %v", err)
	}
	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("expected valid artifact, got errors: %#v", result.Errors)
	}
}

func TestValidateSummaryFileRejectsOversizedSummary(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, make([]byte, maxSummaryArtifactBytes+1), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	_, err := ValidateSummaryFile(summaryPath)
	if err == nil || !contains([]string{err.Error()}, "over the") {
		t.Fatalf("expected oversized summary error, got %v", err)
	}
}

func TestValidateSummaryFileRejectsOversizedAdjacentIperf(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "cloud-throughput",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "iperf3.json"), make([]byte, maxIperfArtifactBytes+1), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if result.Valid() || !contains(result.Errors, "read iperf3.json") || !contains(result.Errors, "over the") {
		t.Fatalf("expected oversized iperf validation error, got errors=%#v warnings=%#v", result.Errors, result.Warnings)
	}
}

func TestValidateSummaryFileRejectsAmbiguousStatusAndNftArtifacts(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"flowtable_evidence": {
			"host_state": "ready",
			"runtime_state": "active",
			"status_captured": true,
			"nft_ruleset_captured": true,
			"flowtable_declared": true,
			"offload_rule_present": true
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"claim_scope": "measured environment only flowtable throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeMatchingIperf(t, dir)
	status := []byte(`policy dataplane:
  flowtable host:  ready
  flowtable live:  active
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`)
	for _, name := range []string{"ngfw-status-active.txt", "ngfw-status-final.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), status, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	nft := []byte(`table inet openngfw {
  flowtable fastpath {
    hook ingress priority filter
  }
  chain forward {
    ct state established,related flow add @fastpath counter packets 2 bytes 200 comment "flow-offload"
  }
}`)
	for _, name := range []string{"nft-openngfw-active.txt", "nft-openngfw-final.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nft, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if result.Valid() {
		t.Fatal("expected ambiguous artifacts to block verification")
	}
	if !contains(result.Errors, "multiple status artifacts found") || !contains(result.Errors, "ngfw-status-final.txt") {
		t.Fatalf("expected status ambiguity error, got errors=%#v warnings=%#v", result.Errors, result.Warnings)
	}
	if !contains(result.Errors, "multiple nftables artifacts found") || !contains(result.Errors, "nft-openngfw-final.txt") {
		t.Fatalf("expected nft ambiguity error, got errors=%#v warnings=%#v", result.Errors, result.Warnings)
	}
}

func TestValidateSummaryFileChecksInspectionStatusEvidence(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "active",
			"failure_behavior": "fail-closed"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeMatchingIperf(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ngfw-status-active.txt"), []byte(`policy dataplane:
  inspection:      IPS prevent
  inspection ready:ready
  inspection eng:  suricata managed/active
  fail behavior:   fail-closed
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("expected valid artifact, got errors: %#v", result.Errors)
	}
}

func TestValidateSummaryFileRejectsInspectionStatusMismatch(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "active",
			"failure_behavior": "fail-closed"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeMatchingIperf(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ngfw-status-active.txt"), []byte(`policy dataplane:
  inspection:      IPS prevent
  inspection ready:failed-open
  inspection eng:  suricata managed/failed
  fail behavior:   fail-open
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if result.Valid() {
		t.Fatal("expected inspection runtime evidence mismatch errors")
	}
	for _, want := range []string{"inspection_evidence.state", "inspection_evidence.inspection_state", "engine_state", "failure_behavior"} {
		if !contains(result.Errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, result.Errors)
		}
	}
}

func TestValidateSummaryFileRejectsStatusAndNftMismatch(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 4,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 7,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"flowtable_evidence": {
			"host_state": "ready",
			"runtime_state": "active",
			"status_captured": true,
			"nft_ruleset_captured": true,
			"flowtable_declared": true,
			"offload_rule_present": true
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"claim_scope": "measured environment only flowtable throughput evidence"
	}`), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeMatchingIperf(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ngfw-status-active.txt"), []byte(`policy dataplane:
  flowtable host:  degraded
  flowtable live:  inactive
  kernel tuning:  degraded
  state table:    warning 99/1048576 entries (4.2%)
`), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nft-openngfw-final.txt"), []byte(`table inet openngfw {
  chain forward {
    ct state established,related accept
  }
}`), 0o600); err != nil {
		t.Fatalf("write nft: %v", err)
	}

	result, err := ValidateSummaryFile(summaryPath)
	if err != nil {
		t.Fatalf("ValidateSummaryFile returned error: %v", err)
	}
	if result.Valid() {
		t.Fatal("expected runtime evidence mismatch errors")
	}
	for _, want := range []string{"conntrack_evidence.state", "current_entries", "usage_percent", "host_tuning_evidence.state", "host_state", "runtime_state", "flowtable_declared", "offload_rule_present"} {
		if !contains(result.Errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, result.Errors)
		}
	}
}

func TestValidateSummaryRejectsMissingAndInvalidFields(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "wrong",
		"generated_at": "not-a-time",
		"profile": "",
		"security_services": "",
		"inspection_state": "",
		"target": {"ip": "", "port": 0},
		"duration_seconds": 0,
		"parallel_streams": 0,
		"tcp_bits_per_second": -1,
		"tcp_gbps": -1,
		"tcp_retransmits": -1,
		"claim_scope": ""
	}`))
	if result.Valid() {
		t.Fatal("expected invalid summary")
	}
	for _, want := range []string{
		"schema_version",
		"generated_at",
		"profile",
		"security_services",
		"inspection_state",
		"target.ip",
		"target.port",
		"duration_seconds",
		"parallel_streams",
		"tcp_bits_per_second",
		"tcp_gbps",
		"tcp_retransmits",
		"claim_scope",
	} {
		if !contains(result.Errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, result.Errors)
		}
	}
}

func writeMatchingIperf(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "iperf3.json"), []byte(`{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 4, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1001000000, "retransmits": 7}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}
}

func TestEvaluatePublicationGateAcceptsCleanFullyInspectedEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "active",
			"failure_behavior": "fail-closed"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`))
	gate := EvaluatePublicationGate(result, true)
	if !gate.Publishable() || gate.Label != "publishable" {
		t.Fatalf("expected publishable gate, got %#v", gate)
	}
}

func TestEvaluatePublicationGateWarnsForLocalRegressionEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "local-netns-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 20,
		"parallel_streams": 8,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "single-host Linux network namespace benchmark; not a cloud-NIC throughput claim"
	}`))
	gate := EvaluatePublicationGate(result, false)
	if gate.State != GateWarn || gate.Label != "review required" {
		t.Fatalf("expected review-required gate, got %#v", gate)
	}
}

func TestEvaluatePublicationGateBlocksStrictWarnings(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "local-netns-forwarding",
		"security_services": "none",
		"inspection_state": "forwarding-only",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 20,
		"parallel_streams": 8,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"claim_scope": "single-host netns"
	}`))
	gate := EvaluatePublicationGate(result, true)
	if gate.State != GateBad || gate.Label != "blocked" {
		t.Fatalf("expected blocked strict gate, got %#v", gate)
	}
}

func TestEvaluatePublicationGateBlocksFlowtableClaimWithoutEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"claim_scope": "flowtable forwarding benchmark"
	}`))
	gate := EvaluatePublicationGate(result, false)
	if gate.State != GateBad {
		t.Fatalf("expected blocked flowtable gate, got %#v", gate)
	}
}

func TestEvaluatePublicationGateBlocksDegradedConntrackEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "active",
			"failure_behavior": "fail-closed"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "degraded",
			"status_captured": true,
			"current_entries": 950,
			"max_entries": 1000,
			"usage_percent": 95.0
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`))
	gate := EvaluatePublicationGate(result, false)
	if gate.State != GateBad {
		t.Fatalf("expected blocked conntrack gate, got %#v", gate)
	}
}

func TestRecommendRepairStepsArchivesCleanEvidence(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected",
			"engine_name": "suricata",
			"engine_mode": "managed",
			"engine_state": "active",
			"failure_behavior": "fail-closed"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
	}`))
	steps := RecommendRepairSteps(result, true)
	if len(steps) != 1 {
		t.Fatalf("expected one archive step, got %#v", steps)
	}
	if steps[0].Level != "low" || steps[0].Title != "Archive this evidence with the run artifacts" {
		t.Fatalf("expected low archive step, got %#v", steps[0])
	}
}

func TestRecommendRepairStepsCoversFastPathAndStatePressure(t *testing.T) {
	result := ValidateSummary([]byte(`{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "flowtable-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true,
			"profile": "throughput"
		},
		"conntrack_evidence": {
			"state": "degraded",
			"status_captured": true,
			"current_entries": 950,
			"max_entries": 1000,
			"usage_percent": 95.0
		},
		"flowtable_evidence": {
			"host_state": "ready",
			"runtime_state": "inactive",
			"status_captured": true,
			"nft_ruleset_captured": false,
			"flowtable_declared": false,
			"offload_rule_present": false
		},
		"claim_scope": "flowtable forwarding benchmark"
	}`))
	steps := RecommendRepairSteps(result, false)
	for _, title := range []string{
		"Fix blocking evidence errors",
		"Prove the flowtable fast path",
		"Resolve state-table pressure",
		"Align the claim with inspection state",
	} {
		if !containsRepairTitle(steps, title) {
			t.Fatalf("expected repair step %q, got %#v", title, steps)
		}
	}
	for i, step := range steps {
		if i > 0 && repairLevelRank(steps[i-1].Level) > repairLevelRank(step.Level) {
			t.Fatalf("repair steps are not sorted by severity: %#v", steps)
		}
	}
}

func containsRepairTitle(steps []RepairStep, title string) bool {
	for _, step := range steps {
		if step.Title == title {
			return true
		}
	}
	return false
}

func contains(items []string, needle string) bool {
	for _, item := range items {
		if len(item) >= len(needle) {
			for i := 0; i <= len(item)-len(needle); i++ {
				if item[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}

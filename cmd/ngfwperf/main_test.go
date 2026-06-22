package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPublishableAcceptsCleanEvidence(t *testing.T) {
	path := writeSummaryWithIperf(t, `{
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
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 16, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	writeStatus(t, filepath.Dir(path), "  inspection:      IPS prevent\n  inspection ready:ready\n  inspection eng:  suricata managed/active\n  fail behavior:   fail-closed\n  kernel tuning:  ready\n  state table:    ready 25/1048576 entries (0.002%)\n")
	out, err := executeForTest("verify", "--publishable", "--strict", path)
	if err != nil {
		t.Fatalf("verify --publishable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "gate: publishable") {
		t.Fatalf("expected publishable gate output, got:\n%s", out)
	}
}

func TestVerifyPublishableDirectoryAcceptsCleanReleaseEvidence(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "20260617T050000Z-ids-prevent")
	path := writeSummaryWithIperfInDir(t, runDir, `{
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
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 16, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	writeStatus(t, filepath.Dir(path), "  inspection:      IPS prevent\n  inspection ready:ready\n  inspection eng:  suricata managed/active\n  fail behavior:   fail-closed\n  kernel tuning:  ready\n  state table:    ready 25/1048576 entries (0.002%)\n")

	out, err := executeForTest("verify", "--publishable", "--strict", root)
	if err != nil {
		t.Fatalf("verify release dir: %v\n%s", err, out)
	}
	if !strings.Contains(out, "publication gate: 0 failure(s)") {
		t.Fatalf("expected clean publication gate, got:\n%s", out)
	}
}

func TestVerifyPublishableDirectoryRejectsMixedRegressionEvidence(t *testing.T) {
	root := t.TempDir()
	writeSummaryWithIperfInDir(t, filepath.Join(root, "release-good"), `{
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
			"inspection_state": "fully-inspected"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with full profile context"
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 16, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	writeStatus(t, filepath.Join(root, "release-good"), "  inspection:      IPS prevent\n  inspection ready:ready\n  kernel tuning:  ready\n  state table:    ready 25/1048576 entries (0.002%)\n")
	writeSummaryInDir(t, filepath.Join(root, "regression-only"), `{
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
	}`)

	out, err := executeForTest("verify", "--publishable", root)
	if err == nil {
		t.Fatalf("expected mixed release dir to fail publishable gate:\n%s", out)
	}
	if !strings.Contains(out, "publication gate:") || !strings.Contains(out, "failure(s)") {
		t.Fatalf("expected publication gate failure output, got:\n%s", out)
	}
}

func TestStageReleaseCopiesOnlyPublishableEvidence(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "20260617T050000Z-ids-prevent")
	writePublishableRun(t, runDir)
	releaseDir := filepath.Join(root, "release-results")

	out, err := executeForTest("stage-release", "--release-dir", releaseDir, runDir)
	if err != nil {
		t.Fatalf("stage-release: %v\n%s", err, out)
	}
	stagedSummary := filepath.Join(releaseDir, filepath.Base(runDir), "summary.json")
	if _, err := os.Stat(stagedSummary); err != nil {
		t.Fatalf("staged summary missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(releaseDir, filepath.Base(runDir), "iperf3.json")); err != nil {
		t.Fatalf("staged raw iperf missing: %v", err)
	}
	if !strings.Contains(out, "staged publishable benchmark evidence") || !strings.Contains(out, filepath.ToSlash(stagedSummary)) {
		t.Fatalf("stage-release output missing staged summary path:\n%s", out)
	}
}

func TestVerifyRejectsAmbiguousAdjacentArtifacts(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "20260617T050000Z-ids-prevent")
	writePublishableRun(t, runDir)
	if err := os.WriteFile(filepath.Join(runDir, "ngfw-status-final.txt"), []byte("  inspection:      IPS prevent\n"), 0o600); err != nil {
		t.Fatalf("write ambiguous status: %v", err)
	}

	out, err := executeForTest("verify", "--publishable", "--strict", runDir)
	if err == nil {
		t.Fatalf("verify accepted ambiguous adjacent status artifact:\n%s", out)
	}
	if !strings.Contains(out, "multiple status artifacts found") || !strings.Contains(out, "ngfw-status-final.txt") {
		t.Fatalf("expected ambiguous status error, got:\n%s", out)
	}
}

func TestStageReleaseRejectsNonPublishableEvidence(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "local-regression")
	writeSummaryInDir(t, runDir, `{
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
	}`)
	releaseDir := filepath.Join(root, "release-results")

	out, err := executeForTest("stage-release", "--release-dir", releaseDir, runDir)
	if err == nil {
		t.Fatalf("stage-release accepted non-publishable evidence:\n%s", out)
	}
	if !strings.Contains(out, "gate:") || !strings.Contains(err.Error(), "refusing to stage release evidence") {
		t.Fatalf("expected publication gate refusal, err=%v out=\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(releaseDir, filepath.Base(runDir))); !os.IsNotExist(statErr) {
		t.Fatalf("non-publishable run was staged; stat err = %v", statErr)
	}
}

func TestVerifyRejectsSummaryThatDoesNotMatchRawIperf(t *testing.T) {
	path := writeSummaryWithIperf(t, `{
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
		"tcp_retransmits": 0,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "measured environment only throughput evidence"
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 4, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	out, err := executeForTest("verify", path)
	if err == nil {
		t.Fatalf("expected raw iperf mismatch failure, got success:\n%s", out)
	}
	if !strings.Contains(out, "tcp_bits_per_second") || !strings.Contains(out, "iperf3.json") {
		t.Fatalf("expected raw iperf mismatch output, got:\n%s", out)
	}
	if !strings.Contains(out, "next action high: Fix blocking evidence errors") ||
		!strings.Contains(out, "Regenerate the summary from the raw artifacts") {
		t.Fatalf("expected repair guidance for raw iperf mismatch, got:\n%s", out)
	}
}

func TestVerifyPublishableRejectsScopedLocalEvidence(t *testing.T) {
	path := writeSummary(t, `{
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
	}`)
	out, err := executeForTest("verify", "--publishable", path)
	if err == nil {
		t.Fatalf("expected publishable gate failure, got success:\n%s", out)
	}
	if !strings.Contains(out, "gate: review required") || !strings.Contains(out, "cloud-NIC") {
		t.Fatalf("expected review-required gate output, got:\n%s", out)
	}
	if !strings.Contains(out, "next action medium: Tighten the claim scope") ||
		!strings.Contains(out, "next action medium: Align the claim with inspection state") {
		t.Fatalf("expected publication repair guidance, got:\n%s", out)
	}
	if strings.Contains(out, "Usage:") {
		t.Fatalf("verify gate failure should not print usage, got:\n%s", out)
	}
}

func TestVerifyQuietSuppressesRepairActions(t *testing.T) {
	path := writeSummaryWithIperf(t, `{
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
		"tcp_retransmits": 0,
		"claim_scope": "measured environment only throughput evidence"
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 4, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	out, err := executeForTest("verify", "--quiet", path)
	if err == nil {
		t.Fatalf("expected raw iperf mismatch failure, got success")
	}
	if strings.Contains(out, "next action") || strings.Contains(out, "warning:") || strings.Contains(out, "error:") {
		t.Fatalf("quiet verify should suppress operator output, got:\n%s", out)
	}
}

func TestVerifyDefaultAcceptsScopedLocalEvidence(t *testing.T) {
	path := writeSummary(t, `{
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
	}`)
	out, err := executeForTest("verify", path)
	if err != nil {
		t.Fatalf("default verify should accept valid scoped evidence: %v\n%s", err, out)
	}
	if strings.Contains(out, "publication gate") {
		t.Fatalf("default verify should not print publication gate, got:\n%s", out)
	}
}

func TestCheckCitationsAcceptsPublishableReleaseSummary(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "perf", "release-results", "20260617T050000Z-ids-prevent")
	writePublishableRun(t, runDir)
	doc := writeDoc(t, root, "release-notes.md", "Release benchmark: perf/release-results/20260617T050000Z-ids-prevent/summary.json")

	out, err := executeForTest("check-citations", "--root", root, doc)
	if err != nil {
		t.Fatalf("check-citations should accept publishable release evidence: %v\n%s", err, out)
	}
	if !strings.Contains(out, "is release-citable") || !strings.Contains(out, "0 failure(s)") {
		t.Fatalf("expected release-citable output, got:\n%s", out)
	}
}

func TestCheckCitationsRejectsRawResultsSummary(t *testing.T) {
	root := t.TempDir()
	doc := writeDoc(t, root, "release-notes.md", "Do not cite raw archive evidence: perf/results/20260617T050000Z-ids-prevent/summary.json")

	out, err := executeForTest("check-citations", "--root", root, doc)
	if err == nil {
		t.Fatalf("check-citations accepted raw perf/results citation:\n%s", out)
	}
	if !strings.Contains(out, "engineering benchmark archive") || !strings.Contains(out, "benchmark citation check failed") {
		t.Fatalf("expected raw archive refusal, got:\n%serr=%v", out, err)
	}
}

func TestCheckCitationsRejectsNonPublishableReleaseSummary(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "perf", "release-results", "local-regression")
	writeSummaryInDir(t, runDir, `{
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
		"claim_scope": "single-host Linux network namespace benchmark; not a cloud-NIC throughput claim"
	}`)
	doc := writeDoc(t, root, "release-notes.md", "Bad citation: perf/release-results/local-regression/summary.json")

	out, err := executeForTest("check-citations", "--root", root, doc)
	if err == nil {
		t.Fatalf("check-citations accepted non-publishable release citation:\n%s", out)
	}
	if !strings.Contains(out, "is not release-citable") || !strings.Contains(out, "publication gate=") {
		t.Fatalf("expected non-publishable release refusal, got:\n%serr=%v", out, err)
	}
}

func TestCheckCitationsNoPerformanceClaimsRejectsUncitedClaimText(t *testing.T) {
	root := t.TempDir()
	doc := writeDoc(t, root, "release-notes.md", "Release notes: forwarding throughput reached 10 Gbps with lower latency.")

	out, err := executeForTest("check-citations", "--root", root, "--no-performance-claims", doc)
	if err == nil {
		t.Fatalf("check-citations accepted no-claims release notes with performance text:\n%s", out)
	}
	if !strings.Contains(out, "performance claim is not allowed") || !strings.Contains(out, "benchmark citation check failed") {
		t.Fatalf("expected no-performance-claims refusal, got:\n%serr=%v", out, err)
	}
}

func TestCheckCitationsNoPerformanceClaimsAllowsBoundaryText(t *testing.T) {
	root := t.TempDir()
	doc := writeDoc(t, root, "release-notes.md", "This tag publishes no throughput, latency, connection-rate, or comparison claims.")

	out, err := executeForTest("check-citations", "--root", root, "--no-performance-claims", doc)
	if err != nil {
		t.Fatalf("check-citations rejected no-claims boundary text: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 failure(s)") {
		t.Fatalf("expected zero failures, got:\n%s", out)
	}
}

func executeForTest(args ...string) (string, error) {
	cmd := newRoot()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func writeSummary(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	return path
}

func writeSummaryWithIperf(t *testing.T, summary, iperf string) string {
	t.Helper()
	path := writeSummary(t, summary)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "iperf3.json"), []byte(iperf+"\n"), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}
	return path
}

func writeSummaryWithIperfInDir(t *testing.T, dir, summary, iperf string) string {
	t.Helper()
	path := writeSummaryInDir(t, dir, summary)
	if err := os.WriteFile(filepath.Join(dir, "iperf3.json"), []byte(iperf+"\n"), 0o600); err != nil {
		t.Fatalf("write iperf: %v", err)
	}
	return path
}

func writeSummaryInDir(t *testing.T, dir, summary string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir run dir: %v", err)
	}
	path := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(path, []byte(summary+"\n"), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	return path
}

func writeDoc(t *testing.T, root, name, body string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatalf("write doc: %v", err)
	}
	return path
}

//nolint:unparam // Returning the summary path keeps this helper useful for tests that need it.
func writePublishableRun(t *testing.T, dir string) string {
	t.Helper()
	path := writeSummaryWithIperfInDir(t, dir, `{
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
	}`, `{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 16, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`)
	writeStatus(t, filepath.Dir(path), "  inspection:      IPS prevent\n  inspection ready:ready\n  inspection eng:  suricata managed/active\n  fail behavior:   fail-closed\n  kernel tuning:  ready\n  state table:    ready 25/1048576 entries (0.002%)\n")
	return path
}

func writeStatus(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ngfw-status-active.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("write status: %v", err)
	}
}

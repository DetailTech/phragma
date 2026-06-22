package perfreport

import "testing"

func TestPerformanceClaimFindingsAllowsNoClaimsBoundaryText(t *testing.T) {
	text := "This tag publishes no throughput, latency, connection-rate, or comparison claims.\n"

	if findings := PerformanceClaimFindings(text); len(findings) != 0 {
		t.Fatalf("PerformanceClaimFindings() = %#v, want no findings", findings)
	}
}

func TestPerformanceClaimFindingsFlagsPositiveReleaseClaims(t *testing.T) {
	text := "Release notes: forwarding throughput reached 10 Gbps with lower latency.\n"

	findings := PerformanceClaimFindings(text)
	if len(findings) == 0 {
		t.Fatal("PerformanceClaimFindings() returned no findings, want performance claim findings")
	}
	if findings[0].Line != 1 {
		t.Fatalf("finding line = %d, want 1", findings[0].Line)
	}
}

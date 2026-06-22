package perfreport

import (
	"fmt"
	"regexp"
	"strings"
)

// ClaimFinding identifies release-facing performance language that needs
// publishable benchmark evidence before it can be shipped.
type ClaimFinding struct {
	Line int
	Term string
	Text string
}

func (f ClaimFinding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("line %d contains performance claim term %q: %s", f.Line, f.Term, f.Text)
	}
	return fmt.Sprintf("contains performance claim term %q: %s", f.Term, f.Text)
}

var performanceClaimTermRE = regexp.MustCompile(`(?i)\b(throughput|latency|connection[- ]?rate|gbps|mbps|gbit/s|mbit/s|pps|packets per second|requests per second|rps|qps|fast(?:er|est)?|performance|benchmark(?:ed|s)?)\b`)

var noPerformanceClaimContext = []string{
	"no performance claim",
	"no performance claims",
	"no throughput",
	"no latency",
	"no connection-rate",
	"no connection rate",
	"no comparison claims",
	"publishes no",
	"publish no",
	"must not",
	"do not",
	"does not claim",
	"does not certify",
	"not a performance result",
	"not a performance claim",
	"not a cloud-nic throughput claim",
	"not release-citable",
	"not publishable",
	"without claiming",
	"cannot claim",
}

// PerformanceClaimFindings returns positive-looking performance claim language.
// It intentionally allows explicit no-claims and not-a-claim boundary wording.
func PerformanceClaimFindings(text string) []ClaimFinding {
	var findings []ClaimFinding
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || noPerformanceClaimLine(trimmed) {
			continue
		}
		for _, match := range performanceClaimTermRE.FindAllString(trimmed, -1) {
			findings = append(findings, ClaimFinding{
				Line: i + 1,
				Term: strings.ToLower(match),
				Text: trimmed,
			})
		}
	}
	return findings
}

func noPerformanceClaimLine(line string) bool {
	normalized := strings.ToLower(line)
	for _, phrase := range noPerformanceClaimContext {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

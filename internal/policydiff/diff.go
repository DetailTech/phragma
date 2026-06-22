// Package policydiff provides stable policy line diffs shared by API and CLI.
package policydiff

import (
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/yaml"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// Lines returns typed diff lines between two policy snapshots.
func Lines(from, to *openngfwv1.Policy) ([]*openngfwv1.PolicyDiffLine, bool, error) {
	fromLines, err := policyYAMLLines(from)
	if err != nil {
		return nil, false, err
	}
	toLines, err := policyYAMLLines(to)
	if err != nil {
		return nil, false, err
	}
	if strings.Join(fromLines, "\n") == strings.Join(toLines, "\n") {
		return nil, false, nil
	}
	return lineDiff(fromLines, toLines), true, nil
}

// TextLines renders typed diff lines in the CLI/WebUI unified-ish format.
func TextLines(fromLabel, toLabel string, lines []*openngfwv1.PolicyDiffLine) []string {
	out := []string{"--- " + fromLabel, "+++ " + toLabel}
	for _, line := range lines {
		out = append(out, TextLine(line))
	}
	return out
}

// TextLine renders a single typed diff line.
func TextLine(line *openngfwv1.PolicyDiffLine) string {
	prefix := "  "
	switch line.GetType() {
	case openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_ADD:
		prefix = "+ "
	case openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_DELETE:
		prefix = "- "
	}
	return prefix + line.GetText()
}

func policyYAMLLines(policy *openngfwv1.Policy) ([]string, error) {
	p := clonePolicy(policy)
	jsonBytes, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(p)
	if err != nil {
		return nil, err
	}
	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return nil, err
	}
	text := strings.TrimRight(string(yamlBytes), "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}

func lineDiff(a, b []string) []*openngfwv1.PolicyDiffLine {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out []*openngfwv1.PolicyDiffLine
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, diffLine(openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_CONTEXT, a[i]))
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, diffLine(openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_DELETE, a[i]))
			i++
		default:
			out = append(out, diffLine(openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_ADD, b[j]))
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, diffLine(openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_DELETE, a[i]))
	}
	for ; j < len(b); j++ {
		out = append(out, diffLine(openngfwv1.PolicyDiffLineType_POLICY_DIFF_LINE_TYPE_ADD, b[j]))
	}
	return out
}

func diffLine(t openngfwv1.PolicyDiffLineType, text string) *openngfwv1.PolicyDiffLine {
	return &openngfwv1.PolicyDiffLine{Type: t, Text: text}
}

func clonePolicy(p *openngfwv1.Policy) *openngfwv1.Policy {
	if p == nil {
		return &openngfwv1.Policy{}
	}
	return proto.Clone(p).(*openngfwv1.Policy)
}

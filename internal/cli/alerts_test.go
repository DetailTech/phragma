package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPrintAlertsResponseIncludesThreatPackageProvenance(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	printAlertsResponse(cmd, &openngfwv1.ListAlertsResponse{
		RunningPolicyVersion: 9,
		Alerts: []*openngfwv1.Alert{{
			Time:               timestamppb.New(mustTestTime(t, "2026-06-21T10:15:00Z")),
			ThreatId:           "phragma.test.webshell",
			ThreatSeverity:     "high",
			Action:             "blocked",
			SrcIp:              "10.0.1.10",
			SrcPort:            51515,
			DestIp:             "10.0.2.20",
			DestPort:           443,
			SignatureId:        9000001,
			ThreatConfidence:   96,
			FlowId:             "eve-flow-1",
			PolicyVersion:      9,
			PolicyVersionKnown: true,
			Signature:          "ET TEST Webshell",
			ThreatEvidence: []string{
				"engine signal suricata.signature_id=9000001",
				"signed Threat-ID package 7.8.9@" + strings.Repeat("b", 64),
			},
		}},
	})
	text := out.String()
	for _, want := range []string{
		"policy-context: running v9",
		"phragma.test.webshell",
		"sid=9000001",
		"flow_id=eve-flow-1",
		"event_policy=v9",
		"threat-id-package: version=7.8.9 manifest=bbbbbbbbbbbbbbbb",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func TestThreatPackageProvenanceSuppressesPathLikeEvidence(t *testing.T) {
	version, manifest := threatPackageProvenance([]string{
		"signed Threat-ID package /var/lib/openngfw/content/threat-id",
		"evidence token=secret",
	})
	if version != "" || manifest != "" {
		t.Fatalf("path-like provenance = %q/%q, want empty", version, manifest)
	}
}

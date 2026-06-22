package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPrintSessions(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printSessions(cmd, &openngfwv1.ListSessionsResponse{
		State:  "ready",
		Detail: "1 live session(s) matched",
		Sessions: []*openngfwv1.ConntrackSession{{
			Family:         "ipv4",
			Protocol:       "TCP",
			State:          "ESTABLISHED",
			TimeoutSeconds: 431999,
			SrcIp:          "10.0.1.20",
			SrcPort:        41400,
			DestIp:         "10.0.2.20",
			DestPort:       8080,
			ReplySrcIp:     "10.0.2.20",
			ReplySrcPort:   8080,
			ReplyDestIp:    "10.0.1.20",
			ReplyDestPort:  41400,
			Packets:        9,
			Bytes:          700,
			Assured:        true,
		}},
	})

	out := buf.String()
	for _, want := range []string{
		"conntrack ready: 1 live session(s) matched",
		"TCP",
		"ESTABLISHED",
		"10.0.1.20:41400 -> 10.0.2.20:8080",
		"reply 10.0.2.20:8080 -> 10.0.1.20:41400",
		"pkts=9 bytes=700 B",
		"assured timeout=431999s ipv4",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintSessionsEmptyDegraded(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printSessions(cmd, &openngfwv1.ListSessionsResponse{
		State:  "degraded",
		Detail: "conntrack command is missing; install conntrack-tools to inspect live sessions",
	})

	out := buf.String()
	for _, want := range []string{
		"conntrack degraded: conntrack command is missing",
		"no live sessions",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

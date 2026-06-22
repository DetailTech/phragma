package conntrack

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const sampleConntrack = `ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.1.20 dst=10.0.2.20 sport=41400 dport=8080 packets=5 bytes=400 src=10.0.2.20 dst=10.0.1.20 sport=8080 dport=41400 packets=4 bytes=300 [ASSURED] mark=0 use=1
ipv4     2 udp      17 28 src=10.0.1.21 dst=10.0.2.53 sport=55331 dport=53 packets=1 bytes=64 src=10.0.2.53 dst=10.0.1.21 sport=53 dport=55331 packets=1 bytes=96 mark=0 use=1
ipv4     2 icmp     1 29 src=10.0.1.22 dst=10.0.2.22 type=8 code=0 id=1234 packets=1 bytes=84 src=10.0.2.22 dst=10.0.1.22 type=0 code=0 id=1234 packets=1 bytes=84 mark=0 use=1
`

func TestParseExtendedConntrackSessions(t *testing.T) {
	sessions := Parse(sampleConntrack, Filter{})
	if len(sessions) != 3 {
		t.Fatalf("sessions = %d, want 3: %#v", len(sessions), sessions)
	}
	tcp := sessions[0]
	if tcp.Protocol != "TCP" || tcp.State != "ESTABLISHED" || tcp.TimeoutSeconds != 431999 {
		t.Fatalf("unexpected tcp identity: %#v", tcp)
	}
	if tcp.SrcIP != "10.0.1.20" || tcp.SrcPort != 41400 || tcp.DestIP != "10.0.2.20" || tcp.DestPort != 8080 {
		t.Fatalf("unexpected original tuple: %#v", tcp)
	}
	if tcp.ReplySrcIP != "10.0.2.20" || tcp.ReplySrcPort != 8080 || tcp.ReplyDestIP != "10.0.1.20" || tcp.ReplyDestPort != 41400 {
		t.Fatalf("unexpected reply tuple: %#v", tcp)
	}
	if tcp.Packets != 9 || tcp.Bytes != 700 || !tcp.Assured {
		t.Fatalf("unexpected counters/assured: %#v", tcp)
	}
	icmp := sessions[2]
	if icmp.Protocol != "ICMP" || icmp.SrcIP != "10.0.1.22" || icmp.ReplySrcIP != "10.0.2.22" || icmp.Packets != 2 {
		t.Fatalf("icmp without ports parsed incorrectly: %#v", icmp)
	}
}

func TestParseFiltersSessions(t *testing.T) {
	sessions := Parse(sampleConntrack, Filter{
		IP:       "10.0.2.53",
		Protocol: "udp",
		Port:     53,
		Query:    "10.0.1.21",
	})
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %#v", len(sessions), sessions)
	}
	if sessions[0].Protocol != "UDP" || sessions[0].DestPort != 53 {
		t.Fatalf("unexpected filtered session: %#v", sessions[0])
	}
}

func TestParseFiltersExactOriginalTuple(t *testing.T) {
	sessions := Parse(sampleConntrack, Filter{
		SrcIP:    "10.0.1.20",
		SrcPort:  41400,
		DestIP:   "10.0.2.20",
		DestPort: 8080,
		Protocol: "tcp",
	})
	if len(sessions) != 1 || sessions[0].SrcPort != 41400 || sessions[0].DestPort != 8080 {
		t.Fatalf("sessions = %#v, want exact TCP original tuple", sessions)
	}
	if got := Parse(sampleConntrack, Filter{
		SrcIP:    "10.0.1.20",
		SrcPort:  51515,
		DestIP:   "10.0.2.20",
		DestPort: 8080,
		Protocol: "tcp",
	}); len(got) != 0 {
		t.Fatalf("sessions = %#v, want source-port mismatch to filter out", got)
	}
}

func TestParseAppliesLimitAfterFilter(t *testing.T) {
	sessions := Parse(sampleConntrack, Filter{Protocol: "tcp", Limit: 1})
	if len(sessions) != 1 || sessions[0].Protocol != "TCP" {
		t.Fatalf("sessions = %#v, want one TCP session", sessions)
	}
}

func TestListReportsMissingConntrackAsDegraded(t *testing.T) {
	result, err := List(context.Background(), func(string) (string, error) {
		return "", errors.New("not found")
	}, nil, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "degraded" || !strings.Contains(result.Detail, "missing") {
		t.Fatalf("result = %#v, want degraded missing command", result)
	}
}

func TestListReportsPermissionAsUnavailable(t *testing.T) {
	result, err := List(context.Background(), func(name string) (string, error) {
		return "/usr/sbin/" + name, nil
	}, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("conntrack v1.4.7: Operation failed: sorry, you must be root or get CAP_NET_ADMIN capability to do this"), errors.New("exit status 1")
	}, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "unavailable" || !strings.Contains(result.Detail, "must be root") {
		t.Fatalf("result = %#v, want unavailable permission detail", result)
	}
}

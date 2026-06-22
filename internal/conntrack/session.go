// Package conntrack reads the Linux conntrack table for live session
// visibility. It treats conntrack as dataplane state evidence, not as the
// source of policy truth.
package conntrack

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Runner executes a command and returns its combined output.
type Runner func(context.Context, string, ...string) ([]byte, error)

// Filter restricts live session queries. Empty fields are ignored.
type Filter struct {
	Limit    int
	Offset   int
	SrcIP    string
	SrcPort  uint32
	DestIP   string
	DestPort uint32
	IP       string
	Protocol string
	Port     uint32
	State    string
	Query    string
}

// Result is the state-table query outcome.
type Result struct {
	State        string
	Detail       string
	Sessions     []Session
	NextCursor   string
	HasMore      bool
	TotalMatches uint32
}

// Session is one live conntrack entry normalized to the original and reply
// 5-tuples. Packets/bytes aggregate the original and reply directions when
// extended counters are available.
type Session struct {
	Family         string
	Protocol       string
	State          string
	TimeoutSeconds uint32
	SrcIP          string
	SrcPort        uint32
	DestIP         string
	DestPort       uint32
	ReplySrcIP     string
	ReplySrcPort   uint32
	ReplyDestIP    string
	ReplyDestPort  uint32
	Packets        uint64
	Bytes          uint64
	Assured        bool
	Raw            string
}

// List returns live sessions from conntrack -L. Missing conntrack or
// insufficient runtime permissions are returned as degraded/unavailable state
// rather than hard RPC errors so operators can see why data is absent.
func List(ctx context.Context, lookup func(string) (string, error), run Runner, filter Filter) (Result, error) {
	if lookup == nil {
		lookup = exec.LookPath
	}
	if _, err := lookup("conntrack"); err != nil {
		return Result{State: "degraded", Detail: "conntrack command is missing; install conntrack-tools to inspect live sessions"}, nil
	}
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	out, err := run(ctx, "conntrack", "-L", "-o", "extended")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(strings.ToLower(msg), "must be root") || strings.Contains(strings.ToLower(msg), "permission") {
			return Result{State: "unavailable", Detail: "conntrack table cannot be read by this process: " + msg}, nil
		}
		// An empty table is a normal operational state on quiet systems.
		if strings.Contains(strings.ToLower(msg), "0 flow entries") {
			return Result{State: "ready", Detail: "conntrack table is empty"}, nil
		}
		return Result{}, fmt.Errorf("list conntrack sessions: %s", msg)
	}
	sessions, page := ParsePage(string(out), filter)
	return Result{
		State:        "ready",
		Detail:       fmt.Sprintf("%d live session(s) matched", page.TotalMatches),
		Sessions:     sessions,
		NextCursor:   page.NextCursor,
		HasMore:      page.HasMore,
		TotalMatches: uint32(page.TotalMatches),
	}, nil
}

// Parse normalizes conntrack -L output and applies filters.
func Parse(output string, filter Filter) []Session {
	sessions, _ := ParsePage(output, filter)
	return sessions
}

// PageInfo describes one cursor page over a filtered conntrack snapshot.
type PageInfo struct {
	NextCursor   string
	HasMore      bool
	TotalMatches int
}

// ParsePage normalizes conntrack -L output and returns one cursor page of
// matching sessions. Cursors are opaque decimal offsets into this snapshot.
func ParsePage(output string, filter Filter) ([]Session, PageInfo) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	var sessions []Session
	totalMatches := 0
	for _, line := range strings.Split(output, "\n") {
		session, ok := parseLine(strings.TrimSpace(line))
		if !ok || !matches(session, filter) {
			continue
		}
		totalMatches++
		if totalMatches <= offset {
			continue
		}
		if len(sessions) == limit {
			continue
		}
		sessions = append(sessions, session)
	}
	next := offset + len(sessions)
	page := PageInfo{TotalMatches: totalMatches, HasMore: next < totalMatches}
	if page.HasMore {
		page.NextCursor = strconv.Itoa(next)
	}
	return sessions, page
}

func parseLine(line string) (Session, bool) {
	if line == "" || strings.HasPrefix(line, "conntrack v") {
		return Session{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Session{}, false
	}
	s := Session{Raw: line}
	idx := 0
	if fields[idx] == "ipv4" || fields[idx] == "ipv6" {
		s.Family = fields[idx]
		idx += 2 // skip family and L3 protocol number
	}
	if idx >= len(fields) {
		return Session{}, false
	}
	s.Protocol = strings.ToUpper(fields[idx])
	idx++
	if idx < len(fields) && isUint(fields[idx]) {
		idx++ // L4 protocol number
	}
	if idx < len(fields) && isUint(fields[idx]) {
		timeout, _ := strconv.ParseUint(fields[idx], 10, 32)
		s.TimeoutSeconds = uint32(timeout)
		idx++
	}
	if idx < len(fields) && !strings.Contains(fields[idx], "=") && !strings.HasPrefix(fields[idx], "[") {
		s.State = fields[idx]
		idx++
	}

	tuple := 0
	for ; idx < len(fields); idx++ {
		token := fields[idx]
		if token == "[ASSURED]" {
			s.Assured = true
			continue
		}
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		switch key {
		case "src":
			if s.SrcIP != "" {
				tuple = 1
			}
			if tuple == 0 {
				s.SrcIP = value
			} else {
				s.ReplySrcIP = value
			}
		case "dst":
			if tuple == 0 {
				s.DestIP = value
			} else {
				s.ReplyDestIP = value
			}
		case "sport":
			if tuple == 0 {
				s.SrcPort = parsePort(value)
			} else {
				s.ReplySrcPort = parsePort(value)
			}
		case "dport":
			if tuple == 0 {
				s.DestPort = parsePort(value)
			} else {
				s.ReplyDestPort = parsePort(value)
			}
		case "packets":
			s.Packets += parseUint64(value)
		case "bytes":
			s.Bytes += parseUint64(value)
		}
	}
	if s.SrcIP == "" || s.DestIP == "" {
		return Session{}, false
	}
	return s, true
}

func matches(s Session, filter Filter) bool {
	if filter.SrcIP != "" && s.SrcIP != filter.SrcIP {
		return false
	}
	if filter.SrcPort != 0 && s.SrcPort != filter.SrcPort {
		return false
	}
	if filter.DestIP != "" && s.DestIP != filter.DestIP {
		return false
	}
	if filter.DestPort != 0 && s.DestPort != filter.DestPort {
		return false
	}
	if filter.IP != "" && s.SrcIP != filter.IP && s.DestIP != filter.IP && s.ReplySrcIP != filter.IP && s.ReplyDestIP != filter.IP {
		return false
	}
	if filter.Protocol != "" && !strings.EqualFold(s.Protocol, filter.Protocol) {
		return false
	}
	if filter.Port != 0 && s.SrcPort != filter.Port && s.DestPort != filter.Port && s.ReplySrcPort != filter.Port && s.ReplyDestPort != filter.Port {
		return false
	}
	if filter.State != "" && !strings.EqualFold(s.State, filter.State) {
		return false
	}
	if filter.Query != "" && !containsFold(strings.Join([]string{
		s.Family,
		s.Protocol,
		s.State,
		s.SrcIP,
		s.DestIP,
		s.ReplySrcIP,
		s.ReplyDestIP,
		s.Raw,
	}, "\n"), filter.Query) {
		return false
	}
	return true
}

func isUint(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func parsePort(value string) uint32 {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func parseUint64(value string) uint64 {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

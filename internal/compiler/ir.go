// Package compiler turns a validated Policy into the engine-neutral
// intermediate representation (IR). Renderers consume only the IR, never
// the raw policy — this seam is what lets new datapath backends (eBPF,
// VPP) slot in later without touching the model (build plan §5).
package compiler

import "net/netip"

// IR is the fully resolved form of a policy: every name reference is
// expanded to concrete values, disabled rules are dropped, and wildcard
// ("any") matches are represented as empty slices.
type IR struct {
	Zones  []ZoneIR
	Rules  []RuleIR
	SNAT   []SNATIR
	DNAT   []DNATIR
	Routes []RouteIR
}

// ZoneIR is a zone with its member interfaces.
type ZoneIR struct {
	Name       string
	Interfaces []string
}

// RuleIR is one filtering rule. Empty slices mean "match any".
type RuleIR struct {
	Name        string
	FromIfaces  []string // resolved from from_zones
	ToIfaces    []string // resolved from to_zones
	SrcPrefixes []netip.Prefix
	DstPrefixes []netip.Prefix
	Services    []ServiceMatch
	Action      RuleAction
	Log         bool
}

// RuleAction is the verdict a rule applies to matching traffic.
type RuleAction int

// Rule verdicts.
const (
	ActionAllow RuleAction = iota + 1
	ActionDeny
	ActionReject
)

// ServiceMatch matches one protocol with optional port ranges.
type ServiceMatch struct {
	Protocol Proto
	Ports    []PortRange // empty = all ports (TCP/UDP), always empty otherwise
}

// Proto is the L4 protocol of a service match.
type Proto int

// Service protocols.
const (
	ProtoTCP Proto = iota + 1
	ProtoUDP
	ProtoICMP
	ProtoAny
)

// PortRange is inclusive; Start == End for a single port.
type PortRange struct {
	Start uint16
	End   uint16
}

// SNATIR is a resolved source-NAT entry.
type SNATIR struct {
	Name        string
	OutIfaces   []string // empty = any
	SrcPrefix   *netip.Prefix
	Masquerade  bool
	TranslateTo netip.Addr // valid when !Masquerade
}

// DNATIR is a resolved destination-NAT entry.
type DNATIR struct {
	Name        string
	InIfaces    []string // empty = any
	Protocol    Proto    // TCP or UDP
	Ports       []PortRange
	MatchDst    netip.Addr
	TranslateTo netip.Addr
	ToPort      uint16 // 0 = keep original
}

// RouteIR is a resolved static route.
type RouteIR struct {
	Destination netip.Prefix
	Via         netip.Addr // zero value = none
	Interface   string
	Metric      uint32
}

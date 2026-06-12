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
	Zones     []ZoneIR
	Rules     []RuleIR
	SNAT      []SNATIR
	DNAT      []DNATIR
	Routes    []RouteIR
	IDs       *IDsIR
	Telemetry *TelemetryIR
	Routing   *RoutingIR
	VPN       *VPNIR
	Intel     *IntelIR
	Network   *NetworkIR
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

// IDsIR is the resolved IDS/IPS configuration; nil when disabled.
type IDsIR struct {
	// Prevent selects inline NFQUEUE mode; false = passive detect.
	Prevent bool
	// Interfaces sniffed in detect mode.
	Interfaces []string
	HomeNets   []netip.Prefix
	RuleFiles  []string
	QueueNum   uint16
}

// TelemetryIR is the resolved telemetry configuration; nil when disabled.
type TelemetryIR struct {
	ClickHouseURL string
	Database      string
}

// RoutingIR is the resolved dynamic-routing configuration; nil when no
// protocol is enabled.
type RoutingIR struct {
	BGP  *BGPIR
	OSPF *OSPFIR
}

// BGPIR is the resolved BGP configuration.
type BGPIR struct {
	ASN       uint32
	RouterID  string
	Neighbors []BGPNeighborIR
	Announce  []netip.Prefix
}

// BGPNeighborIR is one BGP peer.
type BGPNeighborIR struct {
	Address     netip.Addr
	RemoteASN   uint32
	Description string
}

// OSPFIR is the resolved OSPF configuration.
type OSPFIR struct {
	RouterID string
	Areas    []OSPFAreaIR
}

// OSPFAreaIR is one OSPF area with its advertised networks.
type OSPFAreaIR struct {
	Area     string
	Networks []netip.Prefix
}

// VPNIR is the resolved VPN configuration; nil when nothing is defined.
type VPNIR struct {
	IPsec     []IpsecIR
	Wireguard []WireguardIR
}

// IpsecIR is one swanctl connection.
type IpsecIR struct {
	Name          string
	LocalAddress  string
	RemoteAddress string
	LocalSubnets  []netip.Prefix
	RemoteSubnets []netip.Prefix
	PSKFile       string
	IKEProposal   string
	ESPProposal   string
	Initiate      bool
}

// WireguardIR is one managed WireGuard interface.
type WireguardIR struct {
	Name           string
	Address        netip.Prefix
	ListenPort     uint16
	PrivateKeyFile string
	Peers          []WireguardPeerIR
}

// WireguardPeerIR is one WireGuard peer.
type WireguardPeerIR struct {
	Name       string
	PublicKey  string
	Endpoint   string
	AllowedIPs []netip.Prefix
	Keepalive  uint16
}

// IntelIR marks threat-intel enforcement; nil when no feeds are
// enabled. Set contents are dynamic (intel updater), so the IR only
// carries enablement for the renderer to declare sets and drop rules.
type IntelIR struct {
	Enabled bool
}

// NetworkIR is the resolved global network configuration; nil when
// nothing is managed.
type NetworkIR struct {
	// Links lists interfaces whose MTU is managed, in deterministic
	// order (zone order, then overrides for non-zone interfaces).
	Links []LinkIR
	// ClampMSS adds a forward-chain MSS-to-PMTU clamp.
	ClampMSS bool
	// OffloadOffIfaces lists interfaces whose NIC offloads are disabled
	// for IDS accuracy (detect mode only).
	OffloadOffIfaces []string
	// MaxMTU is the largest managed MTU; the IDS capture size derives
	// from it (0 when no MTU is managed).
	MaxMTU uint32
}

// LinkIR is one managed interface link setting.
type LinkIR struct {
	Interface string
	MTU       uint32
}

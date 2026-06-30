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
	Zones                []ZoneIR
	Rules                []RuleIR
	AppIDDrops           []AppIDDropIR
	AppIDControls        []AppIDControlIR
	SecurityProfileRules []SecurityProfileRuleIR
	QoSControls          []QoSControlIR
	ZoneProtections      []ZoneProtectionIR
	SNAT                 []SNATIR
	DNAT                 []DNATIR
	Routes               []RouteIR
	IDs                  *IDsIR
	Telemetry            *TelemetryIR
	Routing              *RoutingIR
	VPN                  *VPNIR
	Intel                *IntelIR
	Network              *NetworkIR
	Proxy                *ProxyIR
	// HostInputDefault is the default verdict for traffic destined to the
	// firewall appliance itself. Zero means the legacy default: allow.
	HostInputDefault RuleAction
	HostInputRules   []RuleIR
}

// AppIDDropIR is a Suricata-backed L7 deny rule generated from a
// signal-only App-ID policy rule.
type AppIDDropIR struct {
	RuleName     string
	Application  string
	EngineSignal string
	SID          uint32
}

// AppIDControlIR is a Suricata-backed application signal control generated
// from an App-ID policy rule. It carries the L3/L4 scope current engines can
// enforce; zone scope remains an nftables-only path constraint.
type AppIDControlIR struct {
	RuleName     string
	RuleID       string
	Application  string
	EngineSignal string
	Action       RuleAction
	SrcPrefixes  []netip.Prefix
	DstPrefixes  []netip.Prefix
	Service      ServiceMatch
	SID          uint32
}

// SecurityProfileRuleIR is a Suricata-backed inspection evidence rule derived
// from a blocking security profile attached to an allowed policy rule. It does
// not claim to replace TLS brokers, URL databases, DNS sinkholes, or file
// engines; it makes the fail-closed inspection boundary observable.
type SecurityProfileRuleIR struct {
	RuleName    string
	ProfileName string
	Control     string
	Protocol    string
	SID         uint32
}

// ZoneIR is a zone with its member interfaces.
type ZoneIR struct {
	Name                  string
	Interfaces            []string
	ZoneProtectionProfile string
}

// ProxyIR is a bounded Envoy/Coraza-style deployment plan. It is render-only
// until the active proxy rollout hardening item is closed.
type ProxyIR struct {
	VirtualServices []VirtualServiceIR `json:"virtualServices"`
	WAFPolicies     []WAFPolicyIR      `json:"wafPolicies"`
}

// VirtualServiceIR is one rendered reverse-proxy virtual service.
type VirtualServiceIR struct {
	Name        string          `json:"name"`
	Enabled     bool            `json:"enabled"`
	Hostnames   []string        `json:"hostnames"`
	Listener    ProxyListenerIR `json:"listener"`
	Routes      []ProxyRouteIR  `json:"routes"`
	Description string          `json:"description,omitempty"`
}

// ProxyListenerIR is the bind and TLS configuration for a virtual service.
type ProxyListenerIR struct {
	BindAddress  string `json:"bindAddress"`
	Port         uint32 `json:"port"`
	TLS          bool   `json:"tls"`
	TLSSecretRef string `json:"tlsSecretRef,omitempty"`
}

// ProxyRouteIR maps a path prefix to proxy backends and an optional WAF policy.
type ProxyRouteIR struct {
	Name                 string           `json:"name"`
	PathPrefix           string           `json:"pathPrefix"`
	Backends             []ProxyBackendIR `json:"backends"`
	WAFPolicy            string           `json:"wafPolicy,omitempty"`
	RequireMTLSToBackend bool             `json:"requireMtlsToBackend"`
	StripPrefix          bool             `json:"stripPrefix"`
}

// ProxyBackendIR is one weighted upstream target for a proxy route.
type ProxyBackendIR struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Weight uint32 `json:"weight"`
}

// WAFPolicyIR is a rendered web-application-firewall policy.
type WAFPolicyIR struct {
	Name               string         `json:"name"`
	Mode               string         `json:"mode"`
	RuleSets           []WAFRuleSetIR `json:"ruleSets"`
	RequestBodyLimitKB uint32         `json:"requestBodyLimitKb"`
	AuditLogging       bool           `json:"auditLogging"`
	RedactRequestBody  bool           `json:"redactRequestBody"`
	Description        string         `json:"description,omitempty"`
}

// WAFRuleSetIR identifies one pinned rule-set artifact used by a WAF policy.
type WAFRuleSetIR struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	SHA256  string `json:"sha256"`
}

// RuleIR is one filtering rule. Empty slices mean "match any".
type RuleIR struct {
	ID           string
	Name         string
	FromIfaces   []string // resolved from from_zones
	ToIfaces     []string // resolved from to_zones
	SrcPrefixes  []netip.Prefix
	DstPrefixes  []netip.Prefix
	MatchContext RuleMatchContextIR
	Applications []string
	AppIDSignals []AppIDSignalIR
	AppIDOnly    bool
	// SecurityProfiles keeps the policy profile refs that materially require
	// inline inspection for this rule.
	SecurityProfiles   []string
	InspectionRequired bool
	QoSProfile         string
	Services           []ServiceMatch
	Action             RuleAction
	Log                bool
}

// QoSControlIR is plan-only shaping intent carried from a rule attachment.
// It is deterministic renderer input, not proof that tc is active.
type QoSControlIR struct {
	RuleName                string
	RuleID                  string
	ProfileName             string
	MaxBandwidthKbps        uint64
	GuaranteedBandwidthKbps uint64
	Priority                string
	DSCPMark                uint32
	BurstKBytes             uint32
}

// ZoneProtectionIR is plan-only DoS protection intent carried from a zone
// attachment. It is deterministic renderer input, not live enforcement proof.
type ZoneProtectionIR struct {
	ZoneName                 string
	Interfaces               []string
	ProfileName              string
	Enabled                  bool
	SynFloodPPS              uint64
	UDPFloodPPS              uint64
	ICMPFloodPPS             uint64
	MaxConcurrentConnections uint64
	Action                   string
	AuditLog                 bool
}

// RuleMatchContextIR carries bounded User-ID and device-posture match labels
// through compiler/explain metadata. Dataplane provider ingestion and live
// posture freshness remain outside this IR.
type RuleMatchContextIR struct {
	Users         []string
	Groups        []string
	Devices       []string
	PostureLabels []string
}

// AppIDSignalIR keeps the engine signals referenced by one application.
type AppIDSignalIR struct {
	Application string
	Signals     []string
}

// RuleAction is the verdict a rule applies to matching traffic.
type RuleAction int

// Rule verdicts.
const (
	// ActionAllow permits matching traffic.
	ActionAllow RuleAction = iota + 1
	// ActionDeny drops matching traffic.
	ActionDeny
	// ActionReject rejects matching traffic.
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
	// ProtoTCP matches TCP traffic.
	ProtoTCP Proto = iota + 1
	// ProtoUDP matches UDP traffic.
	ProtoUDP
	// ProtoICMP matches ICMP traffic.
	ProtoICMP
	// ProtoAny matches any supported protocol.
	ProtoAny
)

// PortRange is inclusive; Start == End for a single port.
type PortRange struct {
	Start uint16
	End   uint16
}

// SNATIR is a resolved source-NAT entry.
type SNATIR struct {
	ID          string
	Name        string
	OutIfaces   []string // empty = any
	SrcPrefix   *netip.Prefix
	Masquerade  bool
	TranslateTo netip.Addr // valid when !Masquerade
}

// DNATIR is a resolved destination-NAT entry.
type DNATIR struct {
	ID          string
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
	// FailOpen selects nftables queue bypass + Suricata fail-open. When false
	// in prevent mode, queue failure blocks traffic instead of bypassing.
	FailOpen bool
	// Interfaces sniffed in detect mode.
	Interfaces []string
	HomeNets   []netip.Prefix
	RuleFiles  []string
	Exceptions []IDSExceptionIR
	QueueNum   uint16
	// QueueCount is the number of consecutive NFQUEUEs (base QueueNum) the
	// inline IPS fans out across, one per Suricata worker, for multi-core
	// throughput. 0/1 means a single queue. Set by the render pipeline
	// from the host CPU count; the pure renderers just consume it.
	QueueCount uint16
}

// IDSExceptionIR is a resolved false-positive suppression owned by
// OpenNGFW policy and rendered to the active IDS engine.
type IDSExceptionIR struct {
	Name        string
	SignatureID int64
	ThreatID    string
	Description string
	Owner       string
	TicketID    string
	ReviewDate  string
	ExpiresAt   string
	PCAPSHA256  string
	Regression  string
	Track       string
	Address     netip.Prefix
}

// TelemetryIR is the resolved telemetry configuration; nil when disabled.
type TelemetryIR struct {
	ClickHouseURL string
	Database      string
	Exports       []TelemetryExportIR
}

const (
	// TelemetryExportTypeJSONFile writes telemetry as JSON files.
	TelemetryExportTypeJSONFile = "TELEMETRY_EXPORT_TYPE_JSON_FILE"
	// TelemetryExportTypeJSONTCP sends telemetry as JSON over TCP.
	TelemetryExportTypeJSONTCP = "TELEMETRY_EXPORT_TYPE_JSON_TCP"
	// TelemetryExportTypeJSONUDP sends telemetry as JSON over UDP.
	TelemetryExportTypeJSONUDP = "TELEMETRY_EXPORT_TYPE_JSON_UDP"
)

// TelemetryExportIR is one resolved Vector export sink.
type TelemetryExportIR struct {
	Name   string
	Type   string
	Target string
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
	// FlowOffloadDevices lists interfaces eligible for nftables flowtable
	// acceleration of established forwarded flows. Empty means disabled.
	FlowOffloadDevices []string
	// MaxMTU is the largest managed MTU; the IDS capture size derives
	// from it (0 when no MTU is managed).
	MaxMTU uint32
}

// LinkIR is one managed interface link setting.
type LinkIR struct {
	Interface string
	MTU       uint32
}

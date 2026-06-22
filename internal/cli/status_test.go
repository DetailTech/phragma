package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPrintStatusIncludesFlowtablePolicyPosture(t *testing.T) {
	out := printStatusForTest(
		statusWithFlowtableCapability("ready"),
		&openngfwv1.GetPolicyResponse{
			Version: 7,
			Policy: &openngfwv1.Policy{
				Zones: []*openngfwv1.Zone{
					{Name: "lan", Interfaces: []string{"eth1"}},
					{Name: "wan", Interfaces: []string{"eth0"}},
				},
				Network: &openngfwv1.Network{EnableFlowOffload: true},
			},
		},
	)

	for _, want := range []string{
		"policy dataplane:",
		"running policy:  v7",
		"throughput path: flowtable fast path",
		"inspection:      disabled",
		"fast-path ifaces: eth0, eth1",
		"flowtable host:  ready",
		"flowtable live:  active",
		"state table:    ready 100/1048576 entries (0.0%)",
		"flowtable devs:  eth0, eth1",
		"flowtable hits:  10 packets / 1000 bytes",
		"counter policy: v7",
		"top counters:",
		"rule:lan-to-wan              8 packets / 800 B",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsDataplaneCounterItemIDs(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Dataplane.Counters = []*openngfwv1.DataplaneCounter{
		{Comment: "rule:lan-to-wan id=rule-lan-to-wan", Kind: "rule", Name: "lan-to-wan", RuleId: "rule-lan-to-wan", ItemId: "rule-lan-to-wan", Packets: 8, Bytes: 800},
		{Comment: "snat:lan-egress id=snat-lan-egress", Kind: "snat", Name: "lan-egress", ItemId: "snat-lan-egress", Packets: 4, Bytes: 400},
		{Comment: "dnat:web-vip id=dnat-web-vip", Kind: "dnat", Name: "web-vip", ItemId: "dnat-web-vip", Packets: 3, Bytes: 300},
		{Comment: "host-input:mgmt-ssh id=host-input-mgmt-ssh", Kind: "host-input", Name: "mgmt-ssh", ItemId: "host-input-mgmt-ssh", Packets: 2, Bytes: 200},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Version: 7, Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"rule:lan-to-wan id=rule-lan-to-wan",
		"snat:lan-egress id=snat-lan-egress",
		"dnat:web-vip id=dnat-web-vip",
		"host-input:mgmt-ssh id=host-input-mgmt-ssh",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsManagementRateIdentity(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Management = &openngfwv1.ManagementPlaneStatus{
		RateLimitClientIdentity: "rightmost-untrusted-x-forwarded-for",
		TrustedProxyCidrs:       []string{"10.0.0.0/24"},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"rate identity:   rightmost-untrusted-x-forwarded-for",
		"trusted proxies: 10.0.0.0/24",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsHighAvailabilityReadiness(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.HighAvailability = &openngfwv1.HighAvailabilityStatus{
		State:                          "degraded",
		Mode:                           "active-passive",
		Role:                           "active",
		NodeId:                         "fw-a",
		PeerId:                         "fw-b",
		PeerAddress:                    "10.0.0.12:9443",
		RunningPolicyVersion:           9,
		LastKnownGoodVersion:           8,
		LastKnownGoodState:             "active",
		LastKnownGoodArtifactSetSha256: "abcdef1234567890abcdef1234567890",
		Sync: &openngfwv1.HighAvailabilitySyncStatus{
			State:                 "degraded",
			Detail:                "peer heartbeat is stale",
			LocalVersion:          9,
			PeerVersion:           8,
			PeerArtifactSetSha256: "1234567890abcdef1234567890abcdef",
			SecondsSinceHeartbeat: 125,
		},
		Replication: &openngfwv1.HighAvailabilityReplicationStatus{
			Enabled:          true,
			State:            "blocked",
			Detail:           "Last automatic replication attempt did not apply a policy.",
			LastAttemptAt:    "2026-06-20T15:06:00Z",
			LastSuccessAt:    "2026-06-20T15:04:00Z",
			LastError:        "HA peer heartbeat is unreachable: connection refused",
			LastPeerVersion:  8,
			LastLocalVersion: 9,
		},
		Failover: &openngfwv1.HighAvailabilityFailoverStatus{
			State:    "planned",
			Eligible: false,
			Detail:   "failover is blocked until heartbeat, policy, and external cutover checks are ready",
		},
		Blockers: []string{"HA peer heartbeat is stale."},
		Detail:   "Active/passive HA contract is exposed for readiness review.",
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})
	if strings.Contains(strings.ToLower(out), "not implemented") {
		t.Fatalf("HA status output should describe implemented guarded controls, not stale not-implemented wording:\n%s", out)
	}

	for _, want := range []string{
		"ha:",
		"mode/role:      active-passive / active",
		"state:          degraded",
		"nodes:          fw-a -> fw-b (10.0.0.12:9443)",
		"policy:         running v9 / lkg v8 active",
		"artifact set:   abcdef1234567890",
		"sync:           degraded - peer heartbeat is stale",
		"peer policy:    v8",
		"peer artifact:  1234567890abcdef",
		"heartbeat age:  2m5s",
		"replication:    blocked enabled=true",
		"replicated:     peer v8 -> local v9",
		"repl success:   2026-06-20T15:04:00Z",
		"repl attempt:   2026-06-20T15:06:00Z",
		"repl error:     HA peer heartbeat is unreachable: connection refused",
		"failover:       planned eligible=false",
		"failover note:  failover is blocked until heartbeat, policy, and external cutover checks are ready",
		"blocker:        HA peer heartbeat is stale.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusFlagsFlowtableInspectionConflict(t *testing.T) {
	out := printStatusForTest(
		statusWithFlowtableCapability("ready"),
		&openngfwv1.GetPolicyResponse{
			Version: 3,
			Policy: &openngfwv1.Policy{
				Zones:   []*openngfwv1.Zone{{Name: "lan", Interfaces: []string{"eth1"}}},
				Network: &openngfwv1.Network{EnableFlowOffload: true},
				Ids:     &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT},
			},
		},
	)

	for _, want := range []string{
		"throughput path: invalid: flowtable conflicts with IDS/IPS",
		"inspection:      IDS detect",
		"validation rejects this policy",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusWarnsWhenFlowtableHostIsNotReady(t *testing.T) {
	out := printStatusForTest(
		statusWithFlowtableCapability("degraded"),
		&openngfwv1.GetPolicyResponse{
			Version: 4,
			Policy: &openngfwv1.Policy{
				Zones:   []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
				Network: &openngfwv1.Network{EnableFlowOffload: true},
			},
		},
	)

	for _, want := range []string{
		"flowtable host:  degraded",
		"action:          host flowtable readiness is degraded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusWarnsWhenFlowtableRuntimeIsNotActive(t *testing.T) {
	out := printStatusForTest(
		statusWithFlowtableCapabilities("ready", "inactive"),
		&openngfwv1.GetPolicyResponse{
			Version: 5,
			Policy: &openngfwv1.Policy{
				Zones:   []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
				Network: &openngfwv1.Network{EnableFlowOffload: true},
			},
		},
	)

	for _, want := range []string{
		"flowtable host:  ready",
		"flowtable live:  inactive",
		"action:          runtime flowtable evidence is inactive",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsEbpfMilestoneReadiness(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Dataplane.Ebpf = &openngfwv1.EbpfDataplaneStatus{
		State:          "ready",
		Detail:         "host prerequisites are ready",
		AttachState:    "ready",
		AttachDetail:   "XDP and tc attach prerequisites are present",
		RendererState:  "planned",
		RendererDetail: "plan-only renderer scaffolding; nftables remains authoritative",
		SupportedHooks: []string{"xdp", "tc"},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"eBPF host:      ready",
		"eBPF attach:    ready",
		"eBPF renderer:  planned",
		"eBPF hooks:     xdp, tc",
		"eBPF renderer detail: plan-only renderer scaffolding",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsLiveEngineDetail(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Engines = []*openngfwv1.EngineStatus{{
		Name:   "suricata",
		Mode:   "managed",
		State:  "failed",
		Role:   "IDS/IPS matching engine",
		Detail: "process is not running after an unexpected exit; last error: exit status 42",
	}}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"suricata",
		"failed",
		"process is not running after an unexpected exit",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsInspectionReadiness(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Inspection = &openngfwv1.InspectionStatus{
		State:            "failed-open",
		IdsEnabled:       true,
		IdsMode:          openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior:  openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
		InspectionState:  "ips-prevent",
		EngineName:       "suricata",
		EngineMode:       "managed",
		EngineState:      "failed",
		EngineRequired:   true,
		BypassPossible:   true,
		BypassReason:     "ids.failure_behavior is fail-open; queued packets bypass inspection.",
		DegradedBehavior: "fail-open: degraded inspection preserves availability but traffic can bypass userspace prevention.",
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{
		Version: 9,
		Policy: &openngfwv1.Policy{
			Ids: &openngfwv1.Ids{
				Enabled:         true,
				Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
				FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
			},
		},
	})

	for _, want := range []string{
		"inspection:      IPS prevent",
		"inspection ready:failed-open",
		"inspection eng:  suricata managed/failed",
		"fail behavior:   fail-open",
		"bypass reason:   ids.failure_behavior is fail-open",
		"degraded mode:   fail-open",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsRoutingRuntimeEvidence(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Routing = &openngfwv1.RoutingRuntimeStatus{
		Frr: &openngfwv1.FrrRuntimeStatus{
			State:  "active",
			Detail: "1 BGP neighbor(s), 1 OSPF neighbor(s)",
			BgpNeighbors: []*openngfwv1.BgpNeighborRuntimeStatus{{
				Peer:             "198.51.100.2",
				RemoteAsn:        65002,
				State:            "Established",
				Uptime:           "00:14:02",
				PrefixesReceived: 12,
			}},
			OspfNeighbors: []*openngfwv1.OspfNeighborRuntimeStatus{{
				NeighborId: "10.0.0.2",
				Address:    "10.0.0.2",
				Interface:  "eth1",
				State:      "Full/DROther",
				DeadTime:   "00:00:33",
			}},
		},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"routing runtime:",
		"frr:           active - 1 BGP neighbor(s), 1 OSPF neighbor(s)",
		"bgp:           198.51.100.2 established AS65002 12 pfx up 00:14:02",
		"ospf:          10.0.0.2 full/drother eth1 10.0.0.2 dead 00:00:33",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsWireGuardRuntime(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Vpn = &openngfwv1.VpnRuntimeStatus{
		Wireguard: &openngfwv1.WireGuardRuntimeStatus{
			State:  "active",
			Detail: "1 WireGuard interface(s), 1/2 peer(s) with recorded handshakes",
			Interfaces: []*openngfwv1.WireGuardInterfaceStatus{{
				Name:            "wg0",
				State:           "active",
				PeerCount:       2,
				ActivePeerCount: 1,
				Peers: []*openngfwv1.WireGuardPeerStatus{{
					PublicKey:                  "abcdefghijklmnopqrstuvwxyz=",
					Endpoint:                   "203.0.113.10:51820",
					LatestHandshakeUnixSeconds: 1780000000,
					LatestHandshakeAgeSeconds:  90,
					RxBytes:                    100,
					TxBytes:                    200,
					State:                      "handshook",
				}},
			}},
		},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"vpn runtime:",
		"wireguard:     active - 1 WireGuard interface(s), 1/2 peer(s) with recorded handshakes",
		"wg0:           active 1/2 peer(s)",
		"abcdefghijkl:  handshook; endpoint 203.0.113.10:51820; handshake 1m30s ago; 100 B rx / 200 B tx",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsIPsecRuntime(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Vpn = &openngfwv1.VpnRuntimeStatus{
		Ipsec: &openngfwv1.IpsecRuntimeStatus{
			State:  "active",
			Detail: "1 IPsec tunnel(s), 1 with established IKE and 1 installed CHILD SA(s)",
			Tunnels: []*openngfwv1.IpsecTunnelRuntimeStatus{{
				Name:                  "site-b",
				State:                 "active",
				Detail:                "IKE established with 1/1 installed CHILD SA(s)",
				IkeState:              "established",
				ChildSaCount:          1,
				InstalledChildSaCount: 1,
			}},
		},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"vpn runtime:",
		"ipsec:         active - 1 IPsec tunnel(s), 1 with established IKE and 1 installed CHILD SA(s)",
		"site-b:        active; ike established; child SAs 1/1 installed; IKE established with 1/1 installed CHILD SA(s)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusHandlesNoRunningPolicy(t *testing.T) {
	out := printStatusForTest(statusWithFlowtableCapability("ready"), nil)

	for _, want := range []string{
		"controld dev (test)",
		"policy dataplane:",
		"running policy:  none",
		"stage, validate, and commit a candidate",
		"capabilities:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusIncludesHostResources(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Host = &openngfwv1.HostResourceStatus{
		State:                "degraded",
		CpuCount:             4,
		Load1:                2.5,
		Load5:                1.25,
		Load15:               0.5,
		Load1PerCpu:          0.625,
		MemoryTotalBytes:     4 * 1024 * 1024,
		MemoryAvailableBytes: 1024 * 1024,
		MemoryUsedPercent:    75,
		Interfaces: []*openngfwv1.HostInterfaceCounter{{
			Name:     "ens4",
			State:    "degraded",
			RxErrors: 1,
			TxErrors: 2,
			RxDrops:  3,
			TxDrops:  4,
		}},
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"host resources:  degraded",
		"host load:       2.50 1.25 0.50 (0.62/CPU)",
		"host memory:     75.0% used (3.0 MB / 4.0 MB)",
		"host ifaces:     ens4 3 err/7 drop",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintStatusShowsConntrackCapacityPressure(t *testing.T) {
	st := statusWithFlowtableCapability("ready")
	st.Dataplane.Conntrack = &openngfwv1.ConntrackTableStatus{
		State:          "degraded",
		Detail:         "950 of 1000 conntrack entries used (95.0%); state table is near or over capacity",
		CurrentEntries: 950,
		MaxEntries:     1000,
		UsagePercent:   95,
	}
	out := printStatusForTest(st, &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}})

	for _, want := range []string{
		"state table:    degraded 950/1000 entries (95.0%)",
		"state detail:   950 of 1000 conntrack entries used",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func printStatusForTest(st *openngfwv1.GetStatusResponse, running *openngfwv1.GetPolicyResponse) string {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printStatus(cmd, st, running)
	return buf.String()
}

func statusWithFlowtableCapability(state string) *openngfwv1.GetStatusResponse {
	return statusWithFlowtableCapabilities(state, "active")
}

func statusWithFlowtableCapabilities(hostState, runtimeState string) *openngfwv1.GetStatusResponse {
	flowtable := &openngfwv1.FlowtableStatus{
		HostState:     hostState,
		HostDetail:    "test capability",
		RuntimeState:  runtimeState,
		RuntimeDetail: "test runtime evidence",
	}
	if runtimeState == "active" {
		flowtable.Devices = []string{"eth0", "eth1"}
		flowtable.Packets = 10
		flowtable.Bytes = 1000
		flowtable.FlowtableDeclared = true
		flowtable.OffloadRulePresent = true
	}
	return &openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{
			Version:         "dev",
			Commit:          "test",
			ActiveDataplane: "nftables/conntrack",
		},
		Dataplane: &openngfwv1.DataplaneStatus{
			ActiveDataplane: "nftables/conntrack",
			Flowtable:       flowtable,
			Conntrack: &openngfwv1.ConntrackTableStatus{
				State:          "ready",
				Detail:         "100 of 1048576 conntrack entries used (0.0%); capacity headroom is available",
				CurrentEntries: 100,
				MaxEntries:     1048576,
				UsagePercent:   0.01,
			},
			Counters: []*openngfwv1.DataplaneCounter{
				{Comment: "flow-offload", Kind: "flow-offload", Name: "flow-offload", Packets: 10, Bytes: 1000},
				{Comment: "rule:lan-to-wan", Kind: "rule", Name: "lan-to-wan", Packets: 8, Bytes: 800},
				{Comment: "default-drop", Kind: "default", Name: "default-drop", Packets: 1, Bytes: 60},
			},
		},
		Capabilities: []*openngfwv1.SystemCapability{
			{
				Name:   "nftables flowtable fast path",
				State:  hostState,
				Detail: "test capability",
			},
			{
				Name:   "nftables flowtable runtime",
				State:  runtimeState,
				Detail: "test runtime evidence",
			},
		},
	}
}

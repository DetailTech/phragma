package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newStatusCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show controld runtime posture and managed engine coverage",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).GetStatus(ctx, &openngfwv1.GetStatusRequest{})
			if err != nil {
				return fmt.Errorf("query status: %w", err)
			}
			running, err := openngfwv1.NewPolicyServiceClient(conn).GetPolicy(ctx, &openngfwv1.GetPolicyRequest{
				Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
			})
			if err != nil && status.Code(err) != codes.NotFound {
				return fmt.Errorf("query running policy: %w", err)
			}
			printStatus(cmd, resp, running)
			return nil
		},
	}
}

func printStatus(cmd *cobra.Command, st *openngfwv1.GetStatusResponse, running *openngfwv1.GetPolicyResponse) {
	rt := st.GetRuntime()
	cmd.Printf("controld %s (%s)\n", value(rt.GetVersion()), value(rt.GetCommit()))
	cmd.Printf("  uptime:          %s\n", seconds(rt.GetUptimeSeconds()))
	cmd.Printf("  dataplane:       %s\n", value(rt.GetActiveDataplane()))
	cmd.Printf("  gRPC:            %s\n", value(rt.GetGrpcListen()))
	cmd.Printf("  WebUI/REST:      %s\n", value(rt.GetHttpListen()))
	cmd.Printf("  tls/auth/dryrun: %t / %t / %t\n", rt.GetTlsEnabled(), rt.GetAuthEnabled(), rt.GetDryRun())
	if mgmt := st.GetManagement(); mgmt != nil {
		cmd.Printf("  rate identity:   %s\n", value(mgmt.GetRateLimitClientIdentity()))
		if proxies := mgmt.GetTrustedProxyCidrs(); len(proxies) > 0 {
			cmd.Printf("  trusted proxies: %s\n", strings.Join(proxies, ", "))
		}
	}
	cmd.Printf("  inspection:      %d worker(s) on %d CPU(s)\n", rt.GetInspectionWorkers(), rt.GetHostCpus())
	printHostResources(cmd, st.GetHost())

	if running != nil {
		printPolicyDataplane(cmd, st, running)
	} else {
		printNoRunningPolicy(cmd)
	}
	printRoutingRuntime(cmd, st.GetRouting())
	printVpnRuntime(cmd, st.GetVpn())
	printHighAvailabilityStatus(cmd, st.GetHighAvailability())

	if warnings := st.GetWarnings(); len(warnings) > 0 {
		cmd.Println("\nwarnings:")
		for _, w := range warnings {
			cmd.Printf("  [%s] %s", strings.ToUpper(value(w.GetSeverity())), w.GetMessage())
			if w.GetAction() != "" {
				cmd.Printf(" Action: %s", w.GetAction())
			}
			cmd.Println()
		}
	}

	if caps := st.GetCapabilities(); len(caps) > 0 {
		cmd.Println("\ncapabilities:")
		for _, c := range caps {
			cmd.Printf("  %-30s %-14s %s\n", c.GetName(), c.GetState(), c.GetDetail())
		}
	}

	if engines := st.GetEngines(); len(engines) > 0 {
		cmd.Println("\nengines:")
		for _, e := range engines {
			detail := e.GetRole()
			if e.GetDetail() != "" {
				detail = e.GetDetail()
			}
			cmd.Printf("  %-12s %-10s %-22s %s\n", e.GetName(), e.GetMode(), e.GetState(), detail)
		}
	}
}

func printNoRunningPolicy(cmd *cobra.Command) {
	cmd.Println("\npolicy dataplane:")
	cmd.Println("  running policy:  none")
	cmd.Println("  detail:          no running policy is committed yet; stage, validate, and commit a candidate before relying on enforcement")
}

func printHostResources(cmd *cobra.Command, host *openngfwv1.HostResourceStatus) {
	if host == nil {
		return
	}
	cmd.Printf("  host resources:  %s\n", value(host.GetState()))
	if host.GetLoad1() > 0 || host.GetLoad5() > 0 || host.GetLoad15() > 0 {
		cmd.Printf("  host load:       %.2f %.2f %.2f (%.2f/CPU)\n",
			host.GetLoad1(), host.GetLoad5(), host.GetLoad15(), host.GetLoad1PerCpu())
	}
	if host.GetMemoryTotalBytes() > 0 {
		used := host.GetMemoryTotalBytes() - host.GetMemoryAvailableBytes()
		if host.GetMemoryAvailableBytes() > host.GetMemoryTotalBytes() {
			used = 0
		}
		cmd.Printf("  host memory:     %.1f%% used (%s / %s)\n",
			host.GetMemoryUsedPercent(), humanBytes(used), humanBytes(host.GetMemoryTotalBytes()))
	}
	if interfaces := host.GetInterfaces(); len(interfaces) > 0 {
		var degraded []string
		for _, iface := range interfaces {
			if iface.GetState() == "ready" {
				continue
			}
			drops := iface.GetRxDrops() + iface.GetTxDrops()
			errors := iface.GetRxErrors() + iface.GetTxErrors()
			degraded = append(degraded, fmt.Sprintf("%s %d err/%d drop", iface.GetName(), errors, drops))
		}
		if len(degraded) == 0 {
			cmd.Printf("  host ifaces:     %d clean\n", len(interfaces))
		} else {
			if len(degraded) > 4 {
				degraded = degraded[:4]
			}
			cmd.Printf("  host ifaces:     %s\n", strings.Join(degraded, "; "))
		}
	}
}

type cliDataplanePosture struct {
	label       string
	inspection  string
	interfaces  []string
	description string
}

type cliFlowtableStatus struct {
	state   string
	detail  string
	devices []string
	packets uint64
	bytes   uint64
}

func printPolicyDataplane(cmd *cobra.Command, st *openngfwv1.GetStatusResponse, running *openngfwv1.GetPolicyResponse) {
	policy := running.GetPolicy()
	posture := cliPolicyDataplanePosture(policy)
	flowHost := flowtableHostStatus(st)
	flowRuntime := flowtableRuntimeStatus(st)
	cmd.Println("\npolicy dataplane:")
	cmd.Printf("  running policy:  v%d\n", running.GetVersion())
	cmd.Printf("  throughput path: %s\n", posture.label)
	cmd.Printf("  inspection:      %s\n", posture.inspection)
	printInspectionStatus(cmd, st.GetInspection())
	cmd.Printf("  fast-path ifaces:%s\n", indentedList(posture.interfaces))
	cmd.Printf("  flowtable host:  %s\n", value(flowHost.state))
	cmd.Printf("  flowtable live:  %s\n", value(flowRuntime.state))
	if tuning := st.GetDataplane().GetKernelTuning(); tuning != nil {
		cmd.Printf("  kernel tuning:  %s\n", value(tuning.GetState()))
		printKernelTuningDetails(cmd, tuning)
	}
	if conntrack := st.GetDataplane().GetConntrack(); conntrack != nil {
		printConntrackCapacity(cmd, conntrack)
	}
	if ebpf := st.GetDataplane().GetEbpf(); ebpf != nil {
		cmd.Printf("  eBPF host:      %s\n", value(ebpf.GetState()))
		printEbpfDetails(cmd, ebpf)
	}
	if len(flowRuntime.devices) > 0 {
		cmd.Printf("  flowtable devs:  %s\n", strings.Join(flowRuntime.devices, ", "))
	}
	if flowRuntime.packets > 0 || flowRuntime.bytes > 0 {
		cmd.Printf("  flowtable hits:  %d packets / %d bytes\n", flowRuntime.packets, flowRuntime.bytes)
	}
	counterVersion := st.GetDataplane().GetRunningPolicyVersion()
	if counterVersion == 0 {
		counterVersion = running.GetVersion()
	}
	printDataplaneCounters(cmd, st.GetDataplane().GetCounters(), counterVersion)
	cmd.Printf("  detail:          %s\n", posture.description)
	if policy.GetNetwork().GetEnableFlowOffload() && flowHost.state != "" && !readyState(flowHost.state) {
		cmd.Printf("  action:          host flowtable readiness is %s; resolve before relying on the fast path\n", value(flowHost.state))
	}
	if policy.GetNetwork().GetEnableFlowOffload() && flowRuntime.state != "" && flowRuntime.state != "active" {
		cmd.Printf("  action:          runtime flowtable evidence is %s; re-commit the policy and inspect nftables before relying on the fast path\n", value(flowRuntime.state))
	}
}

func printConntrackCapacity(cmd *cobra.Command, conntrack *openngfwv1.ConntrackTableStatus) {
	if conntrack.GetMaxEntries() > 0 {
		cmd.Printf("  state table:    %s %d/%d entries (%.1f%%)\n",
			value(conntrack.GetState()), conntrack.GetCurrentEntries(), conntrack.GetMaxEntries(), conntrack.GetUsagePercent())
	} else {
		cmd.Printf("  state table:    %s\n", value(conntrack.GetState()))
	}
	if conntrack.GetState() != "" && conntrack.GetState() != "ready" && conntrack.GetDetail() != "" {
		cmd.Printf("  state detail:   %s\n", conntrack.GetDetail())
	}
}

func printDataplaneCounters(cmd *cobra.Command, counters []*openngfwv1.DataplaneCounter, runningVersion uint64) {
	if len(counters) == 0 {
		return
	}
	relevant := make([]*openngfwv1.DataplaneCounter, 0, len(counters))
	for _, counter := range counters {
		if counter.GetKind() == "rule" || counter.GetKind() == "host-input" || counter.GetKind() == "snat" || counter.GetKind() == "dnat" || counter.GetKind() == "default" || counter.GetKind() == "ips" {
			relevant = append(relevant, counter)
		}
	}
	if len(relevant) == 0 {
		return
	}
	if runningVersion != 0 {
		cmd.Printf("  counter policy: v%d\n", runningVersion)
	}
	cmd.Println("  top counters:")
	for i, counter := range relevant {
		if i >= 5 {
			return
		}
		label := counter.GetComment()
		if counter.GetKind() == "rule" || counter.GetKind() == "host-input" || counter.GetKind() == "snat" || counter.GetKind() == "dnat" {
			label = counter.GetKind() + ":" + counter.GetName()
			if counter.GetItemId() != "" {
				label += " id=" + counter.GetItemId()
			} else if counter.GetRuleId() != "" {
				label += " id=" + counter.GetRuleId()
			}
		}
		cmd.Printf("    %-28s %d packets / %s\n", label, counter.GetPackets(), humanBytes(counter.GetBytes()))
	}
}

func printInspectionStatus(cmd *cobra.Command, inspection *openngfwv1.InspectionStatus) {
	if inspection == nil {
		return
	}
	cmd.Printf("  inspection ready:%s\n", value(inspection.GetState()))
	if inspection.GetEngineName() != "" || inspection.GetEngineState() != "" {
		cmd.Printf("  inspection eng:  %s %s/%s\n",
			value(inspection.GetEngineName()), value(inspection.GetEngineMode()), value(inspection.GetEngineState()))
	}
	if inspection.GetFailureBehavior() != openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED {
		cmd.Printf("  fail behavior:   %s\n", idsFailureBehaviorLabel(inspection.GetFailureBehavior()))
	}
	if inspection.GetBypassPossible() && inspection.GetBypassReason() != "" {
		cmd.Printf("  bypass reason:   %s\n", inspection.GetBypassReason())
	}
	if inspection.GetDegradedBehavior() != "" && inspection.GetState() != "disabled" {
		cmd.Printf("  degraded mode:   %s\n", inspection.GetDegradedBehavior())
	}
}

func printRoutingRuntime(cmd *cobra.Command, routing *openngfwv1.RoutingRuntimeStatus) {
	if routing == nil || routing.GetFrr() == nil || routing.GetFrr().GetState() == "" || routing.GetFrr().GetState() == "not-configured" {
		return
	}
	frr := routing.GetFrr()
	cmd.Println("\nrouting runtime:")
	cmd.Printf("  frr:           %s", value(frr.GetState()))
	if frr.GetDetail() != "" {
		cmd.Printf(" - %s", frr.GetDetail())
	}
	cmd.Println()
	for i, peer := range frr.GetBgpNeighbors() {
		if i >= 5 {
			cmd.Printf("  bgp:           ... %d more neighbor(s)\n", len(frr.GetBgpNeighbors())-i)
			break
		}
		parts := []string{strings.ToLower(value(peer.GetState()))}
		if peer.GetRemoteAsn() > 0 {
			parts = append(parts, fmt.Sprintf("AS%d", peer.GetRemoteAsn()))
		}
		if peer.GetPrefixesReceived() > 0 {
			parts = append(parts, fmt.Sprintf("%d pfx", peer.GetPrefixesReceived()))
		}
		if peer.GetUptime() != "" {
			parts = append(parts, "up "+peer.GetUptime())
		}
		cmd.Printf("  %-14s %s %s\n", "bgp:", value(peer.GetPeer()), strings.Join(parts, " "))
	}
	for i, neighbor := range frr.GetOspfNeighbors() {
		if i >= 5 {
			cmd.Printf("  ospf:          ... %d more neighbor(s)\n", len(frr.GetOspfNeighbors())-i)
			break
		}
		parts := []string{strings.ToLower(value(neighbor.GetState()))}
		if neighbor.GetInterface() != "" {
			parts = append(parts, neighbor.GetInterface())
		}
		if neighbor.GetAddress() != "" {
			parts = append(parts, neighbor.GetAddress())
		}
		if neighbor.GetDeadTime() != "" {
			parts = append(parts, "dead "+neighbor.GetDeadTime())
		}
		cmd.Printf("  %-14s %s %s\n", "ospf:", value(neighbor.GetNeighborId()), strings.Join(parts, " "))
	}
}

func printVpnRuntime(cmd *cobra.Command, vpn *openngfwv1.VpnRuntimeStatus) {
	if vpn == nil {
		return
	}
	wg := vpn.GetWireguard()
	ipsec := vpn.GetIpsec()
	showWG := wg != nil && wg.GetState() != "" && wg.GetState() != "not-configured"
	showIPsec := ipsec != nil && ipsec.GetState() != "" && ipsec.GetState() != "not-configured"
	if !showWG && !showIPsec {
		return
	}
	cmd.Println("\nvpn runtime:")
	if showWG {
		cmd.Printf("  wireguard:     %s", value(wg.GetState()))
		if wg.GetDetail() != "" {
			cmd.Printf(" - %s", wg.GetDetail())
		}
		cmd.Println()
		for _, iface := range wg.GetInterfaces() {
			cmd.Printf("  %-14s %s %d/%d peer(s)\n", iface.GetName()+":", value(iface.GetState()), iface.GetActivePeerCount(), iface.GetPeerCount())
			for i, peer := range iface.GetPeers() {
				if i >= 3 {
					cmd.Printf("    ... %d more peer(s)\n", len(iface.GetPeers())-i)
					break
				}
				parts := []string{value(peer.GetState())}
				if peer.GetEndpoint() != "" {
					parts = append(parts, "endpoint "+peer.GetEndpoint())
				}
				if peer.GetLatestHandshakeUnixSeconds() > 0 {
					parts = append(parts, "handshake "+seconds(peer.GetLatestHandshakeAgeSeconds())+" ago")
				}
				if peer.GetRxBytes() > 0 || peer.GetTxBytes() > 0 {
					parts = append(parts, humanBytes(peer.GetRxBytes())+" rx / "+humanBytes(peer.GetTxBytes())+" tx")
				}
				cmd.Printf("    %-14s %s\n", shortKey(peer.GetPublicKey())+":", strings.Join(parts, "; "))
			}
		}
	}
	if showIPsec {
		cmd.Printf("  ipsec:         %s", value(ipsec.GetState()))
		if ipsec.GetDetail() != "" {
			cmd.Printf(" - %s", ipsec.GetDetail())
		}
		cmd.Println()
		for i, tunnel := range ipsec.GetTunnels() {
			if i >= 5 {
				cmd.Printf("    ... %d more tunnel(s)\n", len(ipsec.GetTunnels())-i)
				break
			}
			parts := []string{value(tunnel.GetState())}
			if tunnel.GetIkeState() != "" {
				parts = append(parts, "ike "+strings.ToLower(tunnel.GetIkeState()))
			}
			if tunnel.GetChildSaCount() > 0 || tunnel.GetInstalledChildSaCount() > 0 {
				parts = append(parts, fmt.Sprintf("child SAs %d/%d installed", tunnel.GetInstalledChildSaCount(), tunnel.GetChildSaCount()))
			}
			if tunnel.GetDetail() != "" {
				parts = append(parts, tunnel.GetDetail())
			}
			cmd.Printf("  %-14s %s\n", tunnel.GetName()+":", strings.Join(parts, "; "))
		}
	}
}

func printHighAvailabilityStatus(cmd *cobra.Command, ha *openngfwv1.HighAvailabilityStatus) {
	if ha == nil || ha.GetState() == "" {
		return
	}
	cmd.Println("\nha:")
	cmd.Printf("  mode/role:      %s / %s\n", value(ha.GetMode()), value(ha.GetRole()))
	cmd.Printf("  state:          %s\n", value(ha.GetState()))
	if ha.GetNodeId() != "" || ha.GetPeerId() != "" || ha.GetPeerAddress() != "" {
		cmd.Printf("  nodes:          %s -> %s", value(ha.GetNodeId()), value(ha.GetPeerId()))
		if ha.GetPeerAddress() != "" {
			cmd.Printf(" (%s)", ha.GetPeerAddress())
		}
		cmd.Println()
	}
	cmd.Printf("  policy:         running v%d / lkg v%d %s\n",
		ha.GetRunningPolicyVersion(), ha.GetLastKnownGoodVersion(), value(ha.GetLastKnownGoodState()))
	if ha.GetLastKnownGoodArtifactSetSha256() != "" {
		cmd.Printf("  artifact set:   %s\n", shortHAHash(ha.GetLastKnownGoodArtifactSetSha256()))
	}
	if sync := ha.GetSync(); sync != nil && sync.GetState() != "" {
		cmd.Printf("  sync:           %s", value(sync.GetState()))
		if sync.GetDetail() != "" {
			cmd.Printf(" - %s", sync.GetDetail())
		}
		cmd.Println()
		if sync.GetPeerVersion() > 0 {
			cmd.Printf("  peer policy:    v%d\n", sync.GetPeerVersion())
		}
		if sync.GetPeerArtifactSetSha256() != "" {
			cmd.Printf("  peer artifact:  %s\n", shortHAHash(sync.GetPeerArtifactSetSha256()))
		}
		if sync.GetSecondsSinceHeartbeat() > 0 {
			cmd.Printf("  heartbeat age:  %s\n", seconds(sync.GetSecondsSinceHeartbeat()))
		}
	}
	if replication := ha.GetReplication(); replication != nil && replication.GetState() != "" {
		cmd.Printf("  replication:    %s enabled=%t\n", value(replication.GetState()), replication.GetEnabled())
		if replication.GetLastPeerVersion() > 0 || replication.GetLastLocalVersion() > 0 {
			cmd.Printf("  replicated:     peer v%d -> local v%d\n", replication.GetLastPeerVersion(), replication.GetLastLocalVersion())
		}
		if replication.GetLastSuccessAt() != "" {
			cmd.Printf("  repl success:   %s\n", replication.GetLastSuccessAt())
		}
		if replication.GetLastAttemptAt() != "" {
			cmd.Printf("  repl attempt:   %s\n", replication.GetLastAttemptAt())
		}
		if replication.GetLastError() != "" {
			cmd.Printf("  repl error:     %s\n", replication.GetLastError())
		} else if replication.GetDetail() != "" {
			cmd.Printf("  repl detail:    %s\n", replication.GetDetail())
		}
	}
	if failover := ha.GetFailover(); failover != nil && failover.GetState() != "" {
		cmd.Printf("  failover:       %s eligible=%t\n", value(failover.GetState()), failover.GetEligible())
		if failover.GetDetail() != "" {
			cmd.Printf("  failover note:  %s\n", failover.GetDetail())
		}
	}
	for i, blocker := range ha.GetBlockers() {
		if i >= 4 {
			cmd.Printf("  blocker:        ... %d more\n", len(ha.GetBlockers())-i)
			break
		}
		cmd.Printf("  blocker:        %s\n", blocker)
	}
	if ha.GetDetail() != "" {
		cmd.Printf("  detail:         %s\n", ha.GetDetail())
	}
}

func shortHAHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16]
}

func idsFailureBehaviorLabel(fb openngfwv1.IdsFailureBehavior) string {
	switch fb {
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN:
		return "fail-open"
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED:
		return "fail-closed"
	default:
		return "unspecified"
	}
}

func printKernelTuningDetails(cmd *cobra.Command, tuning *openngfwv1.KernelTuningStatus) {
	if tuning.GetState() == "ready" {
		return
	}
	if tuning.GetDetail() != "" {
		cmd.Printf("  tuning detail:  %s\n", tuning.GetDetail())
	}
	var shown int
	for _, check := range tuning.GetChecks() {
		if check.GetState() == "ready" {
			continue
		}
		cmd.Printf("  tuning check:   %s=%s want %s (%s)\n",
			check.GetKey(), value(check.GetCurrent()), value(check.GetRecommended()), value(check.GetState()))
		shown++
		if shown >= 4 {
			break
		}
	}
}

func printEbpfDetails(cmd *cobra.Command, ebpf *openngfwv1.EbpfDataplaneStatus) {
	if ebpf.GetAttachState() != "" {
		cmd.Printf("  eBPF attach:    %s\n", value(ebpf.GetAttachState()))
	}
	if ebpf.GetRendererState() != "" {
		cmd.Printf("  eBPF renderer:  %s\n", value(ebpf.GetRendererState()))
	}
	if hooks := ebpf.GetSupportedHooks(); len(hooks) > 0 {
		cmd.Printf("  eBPF hooks:     %s\n", strings.Join(hooks, ", "))
	}
	if ebpf.GetState() != "ready" && ebpf.GetDetail() != "" {
		cmd.Printf("  eBPF detail:    %s\n", ebpf.GetDetail())
	}
	if ebpf.GetAttachState() != "" && ebpf.GetAttachState() != "ready" && ebpf.GetAttachDetail() != "" {
		cmd.Printf("  eBPF attach detail: %s\n", ebpf.GetAttachDetail())
	}
	if ebpf.GetRendererDetail() != "" {
		cmd.Printf("  eBPF renderer detail: %s\n", ebpf.GetRendererDetail())
	}
	var shown int
	for _, probe := range append(append([]*openngfwv1.EbpfProbe{}, ebpf.GetProbes()...), ebpf.GetAttachProbes()...) {
		if probe.GetState() == "ready" {
			continue
		}
		cmd.Printf("  eBPF check:     %s (%s): %s\n",
			probe.GetName(), value(probe.GetState()), value(probe.GetDetail()))
		shown++
		if shown >= 4 {
			break
		}
	}
}

func cliPolicyDataplanePosture(policy *openngfwv1.Policy) cliDataplanePosture {
	interfaces := zoneInterfaces(policy)
	flow := policy.GetNetwork().GetEnableFlowOffload()
	ids := policy.GetIds().GetEnabled()
	if flow && ids {
		return cliDataplanePosture{
			label:       "invalid: flowtable conflicts with IDS/IPS",
			inspection:  idsLabel(policy.GetIds()),
			interfaces:  interfaces,
			description: "offloaded flows can bypass inspection; validation rejects this policy",
		}
	}
	if flow && len(interfaces) == 0 {
		return cliDataplanePosture{
			label:       "invalid: flowtable has no zone interfaces",
			inspection:  idsLabel(policy.GetIds()),
			interfaces:  interfaces,
			description: "assign interfaces to zones before enabling flowtable acceleration",
		}
	}
	if flow {
		return cliDataplanePosture{
			label:       "flowtable fast path",
			inspection:  "disabled",
			interfaces:  interfaces,
			description: "established L3/L4 forwarding can use nftables flowtable acceleration",
		}
	}
	if ids {
		return cliDataplanePosture{
			label:       "inspection path",
			inspection:  idsLabel(policy.GetIds()),
			interfaces:  interfaces,
			description: "flowtable acceleration is unavailable while IDS/IPS is enabled",
		}
	}
	return cliDataplanePosture{
		label:       "standard forwarding",
		inspection:  "disabled",
		interfaces:  interfaces,
		description: "standard nftables/conntrack forwarding path",
	}
}

func idsLabel(ids *openngfwv1.Ids) string {
	if ids == nil || !ids.GetEnabled() {
		return "disabled"
	}
	if ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT {
		return "IPS prevent"
	}
	return "IDS detect"
}

func zoneInterfaces(policy *openngfwv1.Policy) []string {
	seen := map[string]bool{}
	for _, zone := range policy.GetZones() {
		for _, ifc := range zone.GetInterfaces() {
			if ifc != "" {
				seen[ifc] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ifc := range seen {
		out = append(out, ifc)
	}
	sort.Strings(out)
	return out
}

func capability(caps []*openngfwv1.SystemCapability, name string) *openngfwv1.SystemCapability {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap
		}
	}
	return nil
}

func flowtableHostStatus(st *openngfwv1.GetStatusResponse) cliFlowtableStatus {
	flowtable := st.GetDataplane().GetFlowtable()
	if flowtable.GetHostState() != "" {
		return cliFlowtableStatus{
			state:  flowtable.GetHostState(),
			detail: flowtable.GetHostDetail(),
		}
	}
	capabilityStatus := capability(st.GetCapabilities(), "nftables flowtable fast path")
	return cliFlowtableStatus{
		state:  capabilityStatus.GetState(),
		detail: capabilityStatus.GetDetail(),
	}
}

func flowtableRuntimeStatus(st *openngfwv1.GetStatusResponse) cliFlowtableStatus {
	flowtable := st.GetDataplane().GetFlowtable()
	if flowtable.GetRuntimeState() != "" {
		return cliFlowtableStatus{
			state:   flowtable.GetRuntimeState(),
			detail:  flowtable.GetRuntimeDetail(),
			devices: flowtable.GetDevices(),
			packets: flowtable.GetPackets(),
			bytes:   flowtable.GetBytes(),
		}
	}
	capabilityStatus := capability(st.GetCapabilities(), "nftables flowtable runtime")
	return cliFlowtableStatus{
		state:  capabilityStatus.GetState(),
		detail: capabilityStatus.GetDetail(),
	}
}

func readyState(state string) bool {
	return state == "ready" || state == "active"
}

func indentedList(items []string) string {
	if len(items) == 0 {
		return " none"
	}
	return " " + strings.Join(items, ", ")
}

func value(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

func seconds(n uint64) string {
	days := n / 86400
	n %= 86400
	hours := n / 3600
	n %= 3600
	mins := n / 60
	secs := n % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm%ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n) / unit
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	var idx int
	for value >= unit && idx < len(units)-1 {
		value /= unit
		idx++
	}
	if value < 10 {
		return fmt.Sprintf("%.1f %s", value, units[idx])
	}
	return fmt.Sprintf("%.0f %s", value, units[idx])
}

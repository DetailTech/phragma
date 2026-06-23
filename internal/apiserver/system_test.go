package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/releaseacceptance"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestSystemStatusReportsRuntimePosture(t *testing.T) {
	started := time.Now().Add(-90 * time.Second).UTC()
	sysctlRoot := writeSysctlFixture(t, map[string]string{
		"net.ipv4.ip_forward":              "1",
		"net.ipv4.conf.all.rp_filter":      "0",
		"net.ipv4.conf.default.rp_filter":  "0",
		"net.netfilter.nf_conntrack_count": "128",
		"net.netfilter.nf_conntrack_max":   "1048576",
		"net.core.somaxconn":               "4096",
	})
	sysfsRoot := writeSysfsFixture(t, []string{
		"kernel/btf/vmlinux",
		"fs/bpf/",
		"fs/cgroup/cgroup.controllers",
		"class/net/",
	})
	procRoot := writeProcFixture(t, procFixture{
		loadavg: "1.60 0.80 0.40 1/200 12345\n",
		meminfo: "MemTotal:       16384000 kB\n" +
			"MemAvailable:    12288000 kB\n",
		netDev: `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  eth1: 3000 30 0 0 0 0 0 0 4000 40 0 0 0 0 0 0
`,
	})
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:             started,
		GRPCListen:            "127.0.0.1:9443",
		HTTPListen:            "127.0.0.1:8080",
		TLSEnabled:            true,
		AuthEnabled:           true,
		DryRun:                false,
		DataDir:               "/var/lib/openngfw",
		LogDir:                "/var/log/openngfw",
		InspectionWorkers:     8,
		HostCPUs:              16,
		ActiveDataplane:       "nftables/conntrack",
		RateLimitRPM:          600,
		RateLimitBurst:        120,
		TrustedProxyCIDRs:     []string{"10.0.0.0/24", "10.0.0.0/24"},
		HTTPMaxBodyBytes:      10 << 20,
		HTTPMaxHeaderBytes:    1 << 20,
		HTTPReadHeaderTimeout: 10 * time.Second,
		HTTPReadTimeout:       15 * time.Second,
		HTTPWriteTimeout:      30 * time.Second,
		HTTPIdleTimeout:       2 * time.Minute,
		GRPCMaxRecvBytes:      16 << 20,
		GRPCMaxSendBytes:      16 << 20,
		SysctlRoot:            sysctlRoot,
		SysfsRoot:             sysfsRoot,
		ProcRoot:              procRoot,
		Engines: []SystemEngine{
			{Name: "nftables", Role: "stateful firewall"},
			{Name: "suricata", Role: "IDS/IPS"},
		},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if resp.GetRuntime().GetGrpcListen() != "127.0.0.1:9443" {
		t.Fatalf("unexpected gRPC listener: %q", resp.GetRuntime().GetGrpcListen())
	}
	if resp.GetRuntime().GetInspectionWorkers() != 8 {
		t.Fatalf("unexpected inspection workers: %d", resp.GetRuntime().GetInspectionWorkers())
	}
	if len(resp.GetEngines()) != 2 {
		t.Fatalf("expected 2 engine statuses, got %d", len(resp.GetEngines()))
	}
	if resp.GetEngines()[0].GetMode() != "managed" {
		t.Fatalf("expected managed mode, got %q", resp.GetEngines()[0].GetMode())
	}
	if len(resp.GetCapabilities()) == 0 {
		t.Fatal("expected capabilities")
	}
	if got := capabilityState(resp.GetCapabilities(), "nftables flowtable fast path"); got != "ready" {
		t.Fatalf("flowtable capability = %q, want ready", got)
	}
	if got := resp.GetDataplane().GetActiveDataplane(); got != "nftables/conntrack" {
		t.Fatalf("dataplane active_dataplane = %q, want nftables/conntrack", got)
	}
	if got := resp.GetDataplane().GetFlowtable().GetHostState(); got != "ready" {
		t.Fatalf("dataplane flowtable host state = %q, want ready", got)
	}
	if got := resp.GetManagement().GetRateLimitRequestsPerMinute(); got != 600 {
		t.Fatalf("management rate limit = %d, want 600", got)
	}
	if got := resp.GetManagement().GetRateLimitClientIdentity(); got != "rightmost-untrusted-x-forwarded-for" {
		t.Fatalf("management rate identity = %q, want rightmost-untrusted-x-forwarded-for", got)
	}
	if got := resp.GetManagement().GetTrustedProxyCidrs(); len(got) != 1 || got[0] != "10.0.0.0/24" {
		t.Fatalf("management trusted proxies = %#v, want [10.0.0.0/24]", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Management plane guardrails"); got != "ready" {
		t.Fatalf("management guardrail capability = %q, want ready", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Kernel forwarding tuning"); got != "ready" {
		t.Fatalf("kernel tuning capability = %q, want ready", got)
	}
	if got := resp.GetDataplane().GetKernelTuning().GetState(); got != "ready" {
		t.Fatalf("kernel tuning structured state = %q, want ready", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Conntrack state-table capacity"); got != "ready" {
		t.Fatalf("conntrack capacity capability = %q, want ready", got)
	}
	conntrack := resp.GetDataplane().GetConntrack()
	if got := conntrack.GetState(); got != "ready" {
		t.Fatalf("conntrack capacity state = %q, want ready", got)
	}
	if got := conntrack.GetCurrentEntries(); got != 128 {
		t.Fatalf("conntrack entries = %d, want 128", got)
	}
	if got := conntrack.GetMaxEntries(); got != 1048576 {
		t.Fatalf("conntrack max = %d, want 1048576", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Linux eBPF XDP/tc host readiness"); got != "ready" {
		t.Fatalf("eBPF host readiness capability = %q, want ready", got)
	}
	if got := resp.GetDataplane().GetEbpf().GetState(); got != "ready" {
		t.Fatalf("structured eBPF state = %q, want ready", got)
	}
	if got := len(resp.GetDataplane().GetEbpf().GetProbes()); got != 7 {
		t.Fatalf("eBPF probe count = %d, want 7", got)
	}
	if got := resp.GetDataplane().GetEbpf().GetAttachState(); got != "ready" {
		t.Fatalf("eBPF attach_state = %q, want ready", got)
	}
	if got := len(resp.GetDataplane().GetEbpf().GetAttachProbes()); got != 4 {
		t.Fatalf("eBPF attach probe count = %d, want 4", got)
	}
	if got := resp.GetDataplane().GetEbpf().GetRendererState(); got != "planned" {
		t.Fatalf("eBPF renderer_state = %q, want planned", got)
	}
	if got := resp.GetDataplane().GetEbpf().GetSupportedHooks(); len(got) != 2 || got[0] != "xdp" || got[1] != "tc" {
		t.Fatalf("eBPF supported hooks = %#v, want xdp/tc", got)
	}
	if got := len(resp.GetDataplane().GetKernelTuning().GetChecks()); got != 5 {
		t.Fatalf("kernel tuning check count = %d, want 5", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Host resource telemetry"); got != "ready" {
		t.Fatalf("host resource capability = %q, want ready", got)
	}
	host := resp.GetHost()
	if got := host.GetCpuCount(); got != 16 {
		t.Fatalf("host cpu count = %d, want 16", got)
	}
	if got := host.GetLoad1(); got != 1.60 {
		t.Fatalf("host load1 = %v, want 1.60", got)
	}
	if got := host.GetMemoryTotalBytes(); got != 16384000*1024 {
		t.Fatalf("host memory total = %d, want %d", got, uint64(16384000*1024))
	}
	if got := len(host.GetInterfaces()); got != 2 {
		t.Fatalf("host interfaces = %d, want 2", got)
	}
	if host.GetInterfaces()[0].GetName() != "eth0" || host.GetInterfaces()[0].GetRxBytes() != 1000 || host.GetInterfaces()[1].GetTxBytes() != 4000 {
		t.Fatalf("unexpected host interface counters: %#v", host.GetInterfaces())
	}
	if len(resp.GetWarnings()) != 1 || resp.GetWarnings()[0].GetSeverity() != "info" {
		t.Fatalf("expected only eBPF info warning, got %#v", resp.GetWarnings())
	}
}

func TestParseDataplaneCountersExtractsRuleIDMetadata(t *testing.T) {
	counters := parseDataplaneCounters(`
ip saddr 10.0.0.0/24 counter packets 3 bytes 300 comment "rule:allow-web id=rule-allow-web app-id=web-browsing"
ip saddr 10.0.1.0/24 counter packets 2 bytes 200 comment "rule:allow-web id=rule-allow-web app-id=web-browsing"
counter packets 1 bytes 100 comment "host-input:mgmt-ssh id=host-input-mgmt-ssh"
ip saddr 10.0.0.10 counter packets 4 bytes 400 comment "snat:lan-egress id=snat-lan-egress"
ip daddr 203.0.113.10 counter packets 5 bytes 500 comment "dnat:web-vip id=dnat-web-vip"
counter packets 1 bytes 100 comment "host-input:legacy-ssh"
`)
	if len(counters) != 5 {
		t.Fatalf("counters = %d, want 5: %#v", len(counters), counters)
	}
	ruleCounter := counterByComment(counters, "rule:allow-web id=rule-allow-web app-id=web-browsing")
	if ruleCounter == nil {
		t.Fatalf("rule counter not found: %#v", counters)
	}
	if got, want := ruleCounter.GetName(), "allow-web"; got != want {
		t.Fatalf("rule counter name = %q, want %q", got, want)
	}
	if got, want := ruleCounter.GetRuleId(), "rule-allow-web"; got != want {
		t.Fatalf("rule counter id = %q, want %q", got, want)
	}
	if got, want := ruleCounter.GetItemId(), "rule-allow-web"; got != want {
		t.Fatalf("rule counter item id = %q, want %q", got, want)
	}
	if got, want := ruleCounter.GetPackets(), uint64(5); got != want {
		t.Fatalf("rule counter packets = %d, want %d", got, want)
	}
	for _, tc := range []struct {
		comment string
		kind    string
		name    string
		itemID  string
	}{
		{
			comment: "host-input:mgmt-ssh id=host-input-mgmt-ssh",
			kind:    "host-input",
			name:    "mgmt-ssh",
			itemID:  "host-input-mgmt-ssh",
		},
		{
			comment: "snat:lan-egress id=snat-lan-egress",
			kind:    "snat",
			name:    "lan-egress",
			itemID:  "snat-lan-egress",
		},
		{
			comment: "dnat:web-vip id=dnat-web-vip",
			kind:    "dnat",
			name:    "web-vip",
			itemID:  "dnat-web-vip",
		},
		{
			comment: "host-input:legacy-ssh",
			kind:    "host-input",
			name:    "legacy-ssh",
			itemID:  "",
		},
	} {
		counter := counterByComment(counters, tc.comment)
		if counter == nil {
			t.Fatalf("counter %q not found: %#v", tc.comment, counters)
		}
		if got := counter.GetKind(); got != tc.kind {
			t.Fatalf("%s kind = %q, want %q", tc.comment, got, tc.kind)
		}
		if got := counter.GetName(); got != tc.name {
			t.Fatalf("%s name = %q, want %q", tc.comment, got, tc.name)
		}
		if got := counter.GetRuleId(); got != "" {
			t.Fatalf("%s rule id = %q, want empty", tc.comment, got)
		}
		if got := counter.GetItemId(); got != tc.itemID {
			t.Fatalf("%s item id = %q, want %q", tc.comment, got, tc.itemID)
		}
	}
}

func TestSystemStatusReportsIPsecRuntimeEvidence(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		Engines: []SystemEngine{{Name: "strongswan", Role: "IPsec VPN"}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "swanctl" {
				return nil, fmt.Errorf("command %s is not stubbed", name)
			}
			if strings.Join(args, " ") != "--list-sas" {
				t.Fatalf("unexpected swanctl args: %v", args)
			}
			return []byte(`site-b: #1, ESTABLISHED, IKEv2, 497e0d6f_i 41e7f531_r*
  site-b-child: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
dr-site: #2, CONNECTING, IKEv2
`), nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "IPsec runtime evidence"); got != "active" {
		t.Fatalf("IPsec runtime capability = %q, want active", got)
	}
	ipsec := resp.GetVpn().GetIpsec()
	if ipsec.GetState() != "active" {
		t.Fatalf("ipsec state = %q, want active: %#v", ipsec.GetState(), ipsec)
	}
	if !strings.Contains(ipsec.GetDetail(), "2 IPsec tunnel(s), 1 with established IKE and 1 installed CHILD SA(s)") {
		t.Fatalf("unexpected ipsec detail: %q", ipsec.GetDetail())
	}
	if len(ipsec.GetTunnels()) != 2 {
		t.Fatalf("expected 2 IPsec tunnels, got %d", len(ipsec.GetTunnels()))
	}
	site := ipsec.GetTunnels()[1]
	if site.GetName() != "site-b" || site.GetState() != "active" || site.GetIkeState() != "established" {
		t.Fatalf("unexpected active tunnel: %#v", site)
	}
	if site.GetChildSaCount() != 1 || site.GetInstalledChildSaCount() != 1 {
		t.Fatalf("unexpected CHILD SA counts: %#v", site)
	}
	for _, warning := range resp.GetWarnings() {
		if strings.Contains(warning.GetMessage(), "IPsec runtime evidence is unavailable") {
			t.Fatalf("active IPsec evidence should not emit unavailable warning: %#v", warning)
		}
	}
}

func TestProveNetworkPathReportsKernelRouteAndWireGuardRuntime(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		Engines: []SystemEngine{{Name: "wireguard", Role: "WireGuard VPN"}, {Name: "frr", Role: "dynamic routing"}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "ip":
				switch strings.Join(args, " ") {
				case "-j route get 10.99.0.2 from 10.99.0.1":
					return []byte(`[{"dst":"10.99.0.2","dev":"wg0","prefsrc":"10.99.0.1","protocol":"static","table":"main","type":"unicast","scope":"global","flags":["rt_offload"]}]`), nil
				case "-j -d link show dev wg0":
					return []byte(`[{"ifindex":7,"ifname":"wg0","master":"vrf-blue","linkinfo":{"info_kind":"wireguard"}}]`), nil
				default:
					t.Fatalf("unexpected ip args: %v", args)
				}
			case "wg":
				switch strings.Join(args, " ") {
				case "show interfaces":
					return []byte("wg0\n"), nil
				case "show wg0 peers":
					return []byte("pubkey1\n"), nil
				case "show wg0 latest-handshakes":
					return []byte("pubkey1 1780000000\n"), nil
				case "show wg0 transfer":
					return []byte("pubkey1 100 200\n"), nil
				case "show wg0 endpoints":
					return []byte("pubkey1 203.0.113.10:51820\n"), nil
				default:
					t.Fatalf("unexpected wg args: %v", args)
				}
			case "vtysh":
				if strings.Join(args, " ") != "-c show ip route 10.99.0.2 json" {
					t.Fatalf("unexpected vtysh args: %v", args)
				}
				return []byte(`{"10.99.0.2/32":[{"prefix":"10.99.0.2/32","nexthops":[{"interfaceName":"wg0"}]}]}`), nil
			default:
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return nil, nil
		},
	}}

	resp, err := svc.ProveNetworkPath(context.Background(), &openngfwv1.ProveNetworkPathRequest{
		SrcIp:           "10.99.0.1",
		DestIp:          "10.99.0.2",
		SourceInterface: "wg0",
		Tunnel: &openngfwv1.NetworkPathTunnelRef{
			Kind:          "wireguard",
			Interface:     "wg0",
			Peer:          "laptop",
			PeerPublicKey: "pubkey1",
		},
	})
	if err != nil {
		t.Fatalf("ProveNetworkPath returned error: %v", err)
	}
	if resp.GetState() != "ready" {
		t.Fatalf("state = %q, want ready (%s)", resp.GetState(), resp.GetDetail())
	}
	if got := resp.GetRoute().GetDev(); got != "wg0" {
		t.Fatalf("route dev = %q, want wg0", got)
	}
	if got := resp.GetVpn().GetState(); got != "handshook" {
		t.Fatalf("vpn state = %q, want handshook", got)
	}
	if got := resp.GetVpn().GetPeer(); got != "laptop" {
		t.Fatalf("vpn peer = %q, want laptop", got)
	}
	if got := strings.Join(resp.GetEvidence(), "\n"); !strings.Contains(got, "route_table=main") ||
		!strings.Contains(got, "route_interface_index=7") ||
		!strings.Contains(got, "route_interface_master=vrf-blue") ||
		!strings.Contains(got, "route_interface_kind=wireguard") ||
		!strings.Contains(got, "route_type=unicast") ||
		!strings.Contains(got, "route_scope=global") ||
		!strings.Contains(got, "masquerade_egress_observed_source=10.99.0.1") ||
		!strings.Contains(got, "frr_route_proof=observed") ||
		!strings.Contains(got, "vpn_correlation=matched WireGuard interface wg0 peer pubkey1") {
		t.Fatalf("evidence missing proof depth: %#v", resp.GetEvidence())
	}
	if got := resp.GetVpn().GetCorrelation(); got != "matched WireGuard interface wg0 peer pubkey1" {
		t.Fatalf("vpn correlation = %q", got)
	}
	if len(resp.GetLimitations()) == 0 || !strings.Contains(strings.Join(resp.GetLimitations(), "\n"), "active_probe_not_sent") {
		t.Fatalf("limitations missing passive proof boundary: %#v", resp.GetLimitations())
	}
	if !strings.Contains(resp.GetCliHandoff(), "ngfwctl system network-path prove") || !strings.Contains(resp.GetApiHandoff(), "/v1/system/network-path:prove") {
		t.Fatalf("handoff missing CLI/API context: cli=%q api=%q", resp.GetCliHandoff(), resp.GetApiHandoff())
	}
	if len(resp.GetWarnings()) != 0 {
		t.Fatalf("warnings = %#v, want none", resp.GetWarnings())
	}
}

func TestProveNetworkPathReportsIpsecRouteDeviceMismatch(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		Engines: []SystemEngine{{Name: "strongswan", Role: "IPsec VPN"}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "ip":
				switch strings.Join(args, " ") {
				case "-j route get 10.200.0.10 from 10.0.0.10":
					return []byte(`[{"dst":"10.200.0.10","gateway":"198.51.100.1","dev":"ens3","prefsrc":"10.0.0.10","protocol":"static","table":254}]`), nil
				case "-j -d link show dev ens3":
					return []byte(`[{"ifindex":2,"ifname":"ens3","linkinfo":{"info_kind":"ether"}}]`), nil
				default:
					t.Fatalf("unexpected ip args: %v", args)
				}
			case "swanctl":
				if strings.Join(args, " ") != "--list-sas" {
					t.Fatalf("unexpected swanctl args: %v", args)
				}
				return []byte(`site-b: #1, ESTABLISHED, IKEv2
  site-b-child: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
`), nil
			default:
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return nil, nil
		},
	}}

	resp, err := svc.ProveNetworkPath(context.Background(), &openngfwv1.ProveNetworkPathRequest{
		SrcIp:           "10.0.0.10",
		DestIp:          "10.200.0.10",
		SourceInterface: "xfrm0",
		Tunnel:          &openngfwv1.NetworkPathTunnelRef{Kind: "ipsec", Name: "site-b"},
	})
	if err != nil {
		t.Fatalf("ProveNetworkPath returned error: %v", err)
	}
	if resp.GetState() != "degraded" {
		t.Fatalf("state = %q, want degraded; detail=%q route=%#v vpn=%#v warnings=%#v", resp.GetState(), resp.GetDetail(), resp.GetRoute(), resp.GetVpn(), resp.GetWarnings())
	}
	if got := resp.GetRoute().GetDev(); got != "ens3" {
		t.Fatalf("route dev = %q, want ens3", got)
	}
	if got := resp.GetVpn().GetInstalledChildSaCount(); got != 1 {
		t.Fatalf("installed child SAs = %d, want 1", got)
	}
	if !strings.Contains(strings.Join(resp.GetWarnings(), "\n"), "route_device_mismatch=ens3 expected=xfrm0") {
		t.Fatalf("warnings missing route mismatch: %#v", resp.GetWarnings())
	}
	if len(resp.GetMismatches()) != 1 {
		t.Fatalf("mismatches = %#v, want one route mismatch", resp.GetMismatches())
	}
	mismatch := resp.GetMismatches()[0]
	if mismatch.GetSeverity() != "warning" || mismatch.GetSubject() != "route" || !strings.Contains(mismatch.GetDetail(), "route_device_mismatch=ens3 expected=xfrm0") {
		t.Fatalf("unexpected mismatch: %#v", mismatch)
	}
	if got := resp.GetVpn().GetCorrelation(); got != "matched IPsec tunnel site-b with 1/1 installed CHILD SAs" {
		t.Fatalf("vpn correlation = %q", got)
	}
}

func TestProveNetworkPathRejectsInvalidInputs(t *testing.T) {
	svc := &SystemService{}
	tests := []struct {
		name string
		req  *openngfwv1.ProveNetworkPathRequest
	}{
		{name: "bad source", req: &openngfwv1.ProveNetworkPathRequest{SrcIp: "not-ip", DestIp: "10.0.0.1"}},
		{name: "bad destination", req: &openngfwv1.ProveNetworkPathRequest{SrcIp: "10.0.0.1", DestIp: "not-ip"}},
		{name: "bad interface", req: &openngfwv1.ProveNetworkPathRequest{SrcIp: "10.0.0.1", DestIp: "10.0.0.2", SourceInterface: "../eth0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ProveNetworkPath(context.Background(), tt.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
			}
		})
	}
}

func TestParseSwanctlListSAsClassifiesIPsecTunnels(t *testing.T) {
	tunnels := parseSwanctlListSAs([]byte(`waiting-site: #2, CONNECTING, IKEv2
site-b: #1, ESTABLISHED, IKEv2, 497e0d6f_i 41e7f531_r*
  site-b-child: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
established-empty: #3, ESTABLISHED, IKEv2
`))
	if len(tunnels) != 3 {
		t.Fatalf("expected 3 tunnels, got %d: %#v", len(tunnels), tunnels)
	}
	byName := map[string]*openngfwv1.IpsecTunnelRuntimeStatus{}
	for _, tunnel := range tunnels {
		byName[tunnel.GetName()] = tunnel
	}
	if got := byName["site-b"]; got.GetState() != "active" || got.GetInstalledChildSaCount() != 1 || got.GetChildSaCount() != 1 {
		t.Fatalf("site-b classification = %#v, want active with 1/1 CHILD SA", got)
	}
	if got := byName["established-empty"]; got.GetState() != "waiting" || got.GetIkeState() != "established" {
		t.Fatalf("established-empty classification = %#v, want waiting/established", got)
	}
	if got := byName["waiting-site"]; got.GetState() != "waiting" || got.GetIkeState() != "connecting" {
		t.Fatalf("waiting-site classification = %#v, want waiting/connecting", got)
	}
}

func TestSystemHighAvailabilityStatusReportsStandaloneLKG(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	version, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "known good baseline")
	if err != nil {
		t.Fatalf("commit version: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		HighAvailabilityMode:   "standalone",
		HighAvailabilityNodeID: "fw-a",
	}}

	resp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	ha := resp.GetStatus()
	if resp.GetSchemaVersion() != "phragma.ha.status.v1" || ha == nil {
		t.Fatalf("HA response missing schema/status: %+v", resp)
	}
	if ha.GetState() != "standalone" || ha.GetMode() != "standalone" || ha.GetRole() != "standalone" {
		t.Fatalf("standalone HA state wrong: %+v", ha)
	}
	if ha.GetNodeId() != "fw-a" {
		t.Fatalf("node_id = %q, want fw-a", ha.GetNodeId())
	}
	if ha.GetRunningPolicyVersion() != version || ha.GetLastKnownGoodVersion() != version || ha.GetLastKnownGoodState() != "active" {
		t.Fatalf("policy recovery metadata wrong: %+v", ha)
	}
	if ha.GetSync().GetState() != "not_configured" || ha.GetFailover().GetEligible() {
		t.Fatalf("standalone sync/failover wrong: %+v", ha)
	}
}

func TestSystemStatusEmbedsDegradedActivePassiveHA(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		HighAvailabilityMode:   "active-passive",
		HighAvailabilityRole:   "active",
		HighAvailabilityNodeID: "fw-a",
		HighAvailabilityPeerID: "fw-b",
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	ha := resp.GetHighAvailability()
	if ha == nil {
		t.Fatal("GetStatus high_availability missing")
	}
	if ha.GetState() != "degraded" || ha.GetMode() != "active-passive" || ha.GetRole() != "active" {
		t.Fatalf("HA status wrong: %+v", ha)
	}
	if !containsString(ha.GetBlockers(), "HA peer address is not configured.") {
		t.Fatalf("HA blockers = %v, want missing peer address", ha.GetBlockers())
	}
	if got := capabilityState(resp.GetCapabilities(), "Active/passive HA readiness"); got != "degraded" {
		t.Fatalf("HA capability = %q, want degraded", got)
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Active/passive HA is not ready.") {
		t.Fatalf("HA warning missing: %+v", resp.GetWarnings())
	}
}

func TestSystemHighAvailabilityStatusReportsPeerHeartbeatSync(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	version, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "lan"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "known good baseline")
	if err != nil {
		t.Fatalf("commit version: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "active",
		HighAvailabilityNodeID:              "fw-a",
		HighAvailabilityPeerID:              "fw-b",
		HighAvailabilityPeerAddress:         "https://fw-b.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
	}}
	_, hasLKG := svc.lastKnownGoodVersionInfo()
	if !hasLKG {
		t.Fatal("expected LKG metadata")
	}
	lkg, _ := svc.lastKnownGoodVersionInfo()
	svc.Status.HighAvailabilityPeerEvidence = func(context.Context) (*HighAvailabilityPeerEvidence, error) {
		return &HighAvailabilityPeerEvidence{
			NodeID:               "fw-b",
			Role:                 "passive",
			RunningPolicyVersion: version,
			ArtifactSetSHA256:    lkg.ArtifactSetSHA256,
			LastHeartbeat:        time.Now().Add(-5 * time.Second),
			Detail:               "peer heartbeat sampled from /v1/system/ha/status",
		}, nil
	}

	resp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	ha := resp.GetStatus()
	if ha.GetSync().GetState() != "synced" {
		t.Fatalf("sync state = %q, want synced: %+v", ha.GetSync().GetState(), ha)
	}
	if ha.GetState() != "ready" || !ha.GetFailover().GetEligible() || ha.GetFailover().GetState() != "ready" {
		t.Fatalf("HA readiness/failover not ready for synced active/passive pair: %+v", ha)
	}
	if ha.GetSync().GetPeerVersion() != version || ha.GetSync().GetPeerArtifactSetSha256() != lkg.ArtifactSetSHA256 {
		t.Fatalf("peer sync evidence wrong: %+v", ha.GetSync())
	}
	if ha.GetSync().GetSecondsSinceHeartbeat() == 0 {
		t.Fatalf("seconds_since_heartbeat not populated: %+v", ha.GetSync())
	}
	if containsString(ha.GetBlockers(), "HA peer heartbeat source is not configured.") {
		t.Fatalf("unexpected missing source blocker: %+v", ha.GetBlockers())
	}
	if len(ha.GetBlockers()) != 0 || len(ha.GetFailover().GetBlockers()) != 0 {
		t.Fatalf("synced active/passive HA should not report blockers: %+v failover=%+v", ha.GetBlockers(), ha.GetFailover())
	}
}

func TestSystemHighAvailabilityStatusRequiresLKGForReadiness(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "active",
		HighAvailabilityNodeID:              "fw-a",
		HighAvailabilityPeerID:              "fw-b",
		HighAvailabilityPeerAddress:         "https://fw-b.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-b",
				Role:                 "passive",
				RunningPolicyVersion: 1,
				ArtifactSetSHA256:    strings.Repeat("a", 64),
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
			}, nil
		},
	}}

	resp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	ha := resp.GetStatus()
	if ha.GetState() != "degraded" || ha.GetFailover().GetEligible() {
		t.Fatalf("HA should be degraded without LKG metadata: %+v", ha)
	}
	if !containsString(ha.GetBlockers(), "Last-known-good policy metadata is missing.") {
		t.Fatalf("missing LKG blocker: %+v", ha.GetBlockers())
	}
}

func TestSystemHighAvailabilityStatusDegradesStaleOrSameRolePeer(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "active",
		HighAvailabilityNodeID:              "fw-a",
		HighAvailabilityPeerID:              "fw-b",
		HighAvailabilityPeerAddress:         "https://fw-b.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Second,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-b",
				Role:                 "active",
				RunningPolicyVersion: 11,
				ArtifactSetSHA256:    strings.Repeat("b", 64),
				LastHeartbeat:        time.Now().Add(-5 * time.Second),
			}, nil
		},
	}}

	resp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	ha := resp.GetStatus()
	if ha.GetState() != "degraded" || ha.GetSync().GetState() != "degraded" {
		t.Fatalf("HA should be degraded for stale same-role peer: %+v", ha)
	}
	if !containsSubstring(ha.GetBlockers(), "HA peer heartbeat is stale") {
		t.Fatalf("stale heartbeat blocker missing: %+v", ha.GetBlockers())
	}
	if !containsString(ha.GetBlockers(), "HA peer role matches local role; active/passive requires opposite roles.") {
		t.Fatalf("same-role blocker missing: %+v", ha.GetBlockers())
	}
}

func TestSystemHighAvailabilityStatusDegradesUnreachablePeer(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		HighAvailabilityMode:        "active-passive",
		HighAvailabilityRole:        "passive",
		HighAvailabilityNodeID:      "fw-b",
		HighAvailabilityPeerID:      "fw-a",
		HighAvailabilityPeerAddress: "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return nil, errors.New("connection refused")
		},
	}}

	resp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	ha := resp.GetStatus()
	if ha.GetSync().GetState() != "degraded" {
		t.Fatalf("sync state = %q, want degraded", ha.GetSync().GetState())
	}
	if !containsSubstring(ha.GetBlockers(), "HA peer heartbeat is unreachable") {
		t.Fatalf("unreachable blocker missing: %+v", ha.GetBlockers())
	}
}

func TestSystemPullHighAvailabilityPolicyAppliesActivePeerPolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	localVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "local"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "local baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	policyServer := NewPolicyServer(st, engines.NewSupervisor(), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		name := "empty"
		if len(p.GetZones()) > 0 {
			name = p.GetZones()[0].GetName()
		}
		return map[string][]byte{"nftables": []byte(name)}, nil
	})
	peerPolicy := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "peer-active"}}}
	peerArtifactSet := testVersionArtifactSetHash("nftables", []byte("peer-active"))
	svc := &SystemService{Store: st, Policy: policyServer, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: 7,
				ArtifactSetSHA256:    peerArtifactSet,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "active peer heartbeat",
			}, nil
		},
		HighAvailabilityPeerPolicy: func(context.Context) (*openngfwv1.GetPolicyResponse, error) {
			return &openngfwv1.GetPolicyResponse{Policy: peerPolicy, Version: 7}, nil
		},
	}}

	resp, err := svc.PullHighAvailabilityPolicy(context.Background(), &openngfwv1.PullHighAvailabilityPolicyRequest{
		Comment:    "replicate from active",
		AckPull:    true,
		AckRisk:    true,
		AckRuntime: true,
	})
	if err != nil {
		t.Fatalf("PullHighAvailabilityPolicy: %v", err)
	}
	if resp.GetPreviousVersion() != localVersion || resp.GetPeerVersion() != 7 || resp.GetVersion() <= localVersion {
		t.Fatalf("version metadata wrong: %+v", resp)
	}
	if info := resp.GetVersionInfo(); info.GetAction() != "ha-policy-pull" || info.GetSourceVersion() != 7 || info.GetState() != "active" {
		t.Fatalf("version info wrong: %+v", info)
	}
	if resp.GetAfter().GetSync().GetState() != "synced" || resp.GetAfter().GetSync().GetLocalVersion() != 7 {
		t.Fatalf("after HA sync wrong: %+v", resp.GetAfter().GetSync())
	}
	running, runningVersion, err := st.GetRunning()
	if err != nil {
		t.Fatalf("read running: %v", err)
	}
	if runningVersion != resp.GetVersion() || len(running.GetZones()) != 1 || running.GetZones()[0].GetName() != "peer-active" {
		t.Fatalf("running policy/version = v%d %+v, want pulled peer policy v%d", runningVersion, running, resp.GetVersion())
	}
	if _, ok, err := st.GetCandidate(); err != nil || ok {
		t.Fatalf("candidate should be cleared after successful HA pull (ok=%v err=%v)", ok, err)
	}
	assertPolicyAuditAction(t, st, "ha-policy-pull-intent", resp.GetVersion(), "replicate from active")
	assertPolicyAuditAction(t, st, "ha-policy-pull", resp.GetVersion(), "replicate from active")
	if !strings.Contains(resp.GetDetail(), "Pulled active peer policy v7") {
		t.Fatalf("detail = %q", resp.GetDetail())
	}
}

func TestSystemAutomaticHighAvailabilityReplicationAppliesActivePeerPolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	localVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "local"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "local baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	policyServer := NewPolicyServer(st, engines.NewSupervisor(), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		name := "empty"
		if len(p.GetZones()) > 0 {
			name = p.GetZones()[0].GetName()
		}
		return map[string][]byte{"nftables": []byte(name)}, nil
	})
	peerPolicy := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "peer-auto"}}}
	peerArtifactSet := testVersionArtifactSetHash("nftables", []byte("peer-auto"))
	svc := &SystemService{Store: st, Policy: policyServer, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityAutoReplicate:       true,
		HighAvailabilityReplicationComment:  "auto replicate from active",
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: 9,
				ArtifactSetSHA256:    peerArtifactSet,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "active peer heartbeat",
			}, nil
		},
		HighAvailabilityPeerPolicy: func(context.Context) (*openngfwv1.GetPolicyResponse, error) {
			return &openngfwv1.GetPolicyResponse{Policy: peerPolicy, Version: 9}, nil
		},
	}}

	resp, err := svc.RunHighAvailabilityReplicationOnce(context.Background())
	if err != nil {
		t.Fatalf("RunHighAvailabilityReplicationOnce: %v", err)
	}
	if resp.GetPreviousVersion() != localVersion || resp.GetPeerVersion() != 9 || resp.GetVersion() <= localVersion {
		t.Fatalf("version metadata wrong: %+v", resp)
	}
	running, runningVersion, err := st.GetRunning()
	if err != nil {
		t.Fatalf("read running: %v", err)
	}
	if runningVersion != resp.GetVersion() || len(running.GetZones()) != 1 || running.GetZones()[0].GetName() != "peer-auto" {
		t.Fatalf("running policy/version = v%d %+v, want auto-replicated peer policy v%d", runningVersion, running, resp.GetVersion())
	}
	statusResp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	replication := statusResp.GetStatus().GetReplication()
	if !replication.GetEnabled() || replication.GetState() != "replicated" || replication.GetLastPeerVersion() != 9 || replication.GetLastLocalVersion() != resp.GetVersion() {
		t.Fatalf("replication status wrong: %+v", replication)
	}
	assertPolicyAuditAction(t, st, "ha-policy-pull", resp.GetVersion(), "auto replicate from active")
}

func TestSystemAutomaticHighAvailabilityReplicationRecordsBlockedAttempt(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "local"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "local baseline"); err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	svc := &SystemService{Store: st, Policy: NewPolicyServer(st, engines.NewSupervisor(), func(_ *openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": []byte("unused")}, nil
	}), Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityAutoReplicate:       true,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return nil, errors.New("peer unavailable")
		},
		HighAvailabilityPeerPolicy: func(context.Context) (*openngfwv1.GetPolicyResponse, error) {
			t.Fatal("peer policy should not be fetched when heartbeat is unavailable")
			return nil, nil
		},
	}}

	_, err = svc.RunHighAvailabilityReplicationOnce(context.Background())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "HA peer heartbeat is unreachable") {
		t.Fatalf("error = %v, want peer heartbeat failed precondition", err)
	}
	statusResp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus: %v", err)
	}
	replication := statusResp.GetStatus().GetReplication()
	if !replication.GetEnabled() || replication.GetState() != "blocked" || !strings.Contains(replication.GetLastError(), "HA peer heartbeat is unreachable") || replication.GetLastAttemptAt() == "" {
		t.Fatalf("replication status wrong after blocked attempt: %+v", replication)
	}
}

func TestSystemActivateHighAvailabilityFailoverPersistsActiveRole(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	runningVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "replicated"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "replicated baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	lkg, err := st.GetVersionInfo(runningVersion)
	if err != nil {
		t.Fatalf("read lkg: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: runningVersion,
				ArtifactSetSHA256:    lkg.ArtifactSetSHA256,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "active peer heartbeat",
			}, nil
		},
	}}

	resp, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if err != nil {
		t.Fatalf("ActivateHighAvailabilityFailover: %v", err)
	}
	if resp.GetBefore().GetRole() != "passive" || !resp.GetBefore().GetFailover().GetEligible() {
		t.Fatalf("before status not eligible passive: %+v", resp.GetBefore())
	}
	if resp.GetAfter().GetRole() != "active" {
		t.Fatalf("after role = %q, want active: %+v", resp.GetAfter().GetRole(), resp.GetAfter())
	}
	if resp.GetRunningPolicyVersion() != runningVersion || resp.GetLastKnownGoodVersion() != runningVersion {
		t.Fatalf("response versions wrong: %+v", resp)
	}
	state, ok, err := st.GetHighAvailabilityState()
	if err != nil || !ok {
		t.Fatalf("read HA state ok=%v err=%v", ok, err)
	}
	if state.Role != "active" || state.PreviousRole != "passive" || state.RunningPolicyVersion != runningVersion || state.FencingClaim != "not_performed" || state.TransportClaim != "not_performed" {
		t.Fatalf("persisted HA state wrong: %+v", state)
	}
	if state.PreflightPeerPolicyVersion != runningVersion || state.PreflightPeerArtifactSetSHA256 != lkg.ArtifactSetSHA256 || state.PreflightFailoverState != "ready" || !state.PreflightFailoverEligible {
		t.Fatalf("persisted HA preflight evidence wrong: %+v", state)
	}
	if !strings.Contains(resp.GetDetail(), "after HA preflight") || !strings.Contains(resp.GetAfter().GetFailover().GetDetail(), "post-activation review") {
		t.Fatalf("activation response did not expose preflight/post-activation review detail: %+v", resp)
	}
	if got := strings.Join(resp.GetAfter().GetFailover().GetBlockers(), " "); !strings.Contains(got, "active/passive requires opposite roles") {
		t.Fatalf("post-activation same-role blocker missing from after status: %+v", resp.GetAfter())
	}
	foundExternalWarning := false
	for _, warning := range resp.GetAfter().GetWarnings() {
		if strings.Contains(warning.GetAction(), "Verify peer fencing") {
			foundExternalWarning = true
			break
		}
	}
	if !foundExternalWarning {
		t.Fatalf("post-activation external-control warning missing: %+v", resp.GetAfter().GetWarnings())
	}
	statusResp, err := svc.GetHighAvailabilityStatus(context.Background(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		t.Fatalf("GetHighAvailabilityStatus after activation: %v", err)
	}
	if statusResp.GetStatus().GetRole() != "active" {
		t.Fatalf("durable role override not reflected in status: %+v", statusResp.GetStatus())
	}
	assertPolicyAuditAction(t, st, "ha-failover-activate-intent", runningVersion, "manual failover")
	assertPolicyAuditAction(t, st, "ha-failover-activate", runningVersion, "manual failover")
}

func TestSystemActivateHighAvailabilityFailoverPersistsFencingEvidence(t *testing.T) {
	st, runningVersion, lkg := haActivationStore(t)
	defer func() { _ = st.Close() }()
	observedAt := time.Date(2026, 6, 21, 15, 30, 0, 0, time.UTC)
	svc := &SystemService{Store: st, Status: haActivationStatusConfig(runningVersion, lkg.ArtifactSetSHA256)}
	svc.Status.HighAvailabilityFencingEvidence = func(context.Context) (*HighAvailabilityFencingEvidence, error) {
		return &HighAvailabilityFencingEvidence{
			Provider:   "operator-runbook",
			Claim:      "peer_power_off_verified",
			PeerID:     "fw-a",
			EvidenceID: "change-1234",
			ObservedAt: observedAt,
			Detail:     "Operator verified fw-a is fenced through the approved runbook.",
		}, nil
	}

	resp, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover with fencing evidence",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if err != nil {
		t.Fatalf("ActivateHighAvailabilityFailover: %v", err)
	}
	state, ok, err := st.GetHighAvailabilityState()
	if err != nil || !ok {
		t.Fatalf("read HA state ok=%v err=%v", ok, err)
	}
	if state.FencingClaim != "peer_power_off_verified" || state.FencingProvider != "operator-runbook" || state.FencingEvidenceID != "change-1234" || !state.FencingEvidenceAt.Equal(observedAt) {
		t.Fatalf("persisted fencing evidence wrong: %+v", state)
	}
	if !strings.Contains(state.FencingEvidenceDetail, "approved runbook") || !strings.Contains(resp.GetAfter().GetDetail(), "approved runbook") {
		t.Fatalf("activation response/state missing fencing evidence detail: state=%+v after=%+v", state, resp.GetAfter())
	}
	fencing := resp.GetAfter().GetFencingEvidence()
	if fencing.GetState() != "recorded" || fencing.GetProvider() != "operator-runbook" || fencing.GetClaim() != "peer_power_off_verified" || fencing.GetEvidenceId() != "change-1234" || fencing.GetObservedAt() != observedAt.Format(time.RFC3339) {
		t.Fatalf("activation response fencing evidence wrong: %+v", fencing)
	}
	if !strings.Contains(fencing.GetDetail(), "approved runbook") {
		t.Fatalf("activation response fencing evidence detail missing runbook: %+v", fencing)
	}
	assertPolicyAuditAction(t, st, "ha-failover-activate", runningVersion, "manual failover with fencing evidence")
}

func TestSystemActivateHighAvailabilityFailoverRejectsUnprovenFencingEvidenceBeforePromotion(t *testing.T) {
	st, runningVersion, lkg := haActivationStore(t)
	defer func() { _ = st.Close() }()
	promoter := &fakeHAPromoter{result: engines.HAPromotionResult{TransportClaim: "linux_local_vip_route_promoted"}}
	svc := &SystemService{Store: st, Status: haActivationStatusConfig(runningVersion, lkg.ArtifactSetSHA256)}
	svc.Status.HighAvailabilityPromoter = promoter
	svc.Status.HighAvailabilityFencingEvidence = func(context.Context) (*HighAvailabilityFencingEvidence, error) {
		return &HighAvailabilityFencingEvidence{
			Provider: "operator-runbook",
			Claim:    "not_performed",
			PeerID:   "fw-a",
			Detail:   "operator has not completed fencing",
		}, nil
	}

	_, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover without fencing proof",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not prove peer fencing") {
		t.Fatalf("ActivateHighAvailabilityFailover err = %v", err)
	}
	if promoter.calls != 0 {
		t.Fatalf("promoter calls = %d, want 0 before unproven fencing evidence", promoter.calls)
	}
	if state, ok, err := st.GetHighAvailabilityState(); err != nil || ok {
		t.Fatalf("HA active role should not persist after unproven fencing evidence, ok=%v err=%v state=%+v", ok, err, state)
	}
	assertPolicyAuditAction(t, st, "ha-failover-activate-intent", runningVersion, "manual failover without fencing proof")
	if hasAuditAction(t, st, "ha-failover-activate") {
		t.Fatal("unexpected activation audit after rejected fencing evidence")
	}
}

func TestSystemActivateHighAvailabilityFailoverPromotesVIPBeforePersistingActiveRole(t *testing.T) {
	st, runningVersion, lkg := haActivationStore(t)
	defer func() { _ = st.Close() }()
	promoter := &fakeHAPromoter{result: engines.HAPromotionResult{
		VIP:            "192.0.2.10/32",
		Interface:      "eth0",
		Routes:         []string{"198.51.100.0/24 via 192.0.2.1 dev eth0 metric 50"},
		GARPState:      "sent",
		GARPDetail:     "sent 1 gratuitous ARP announcement for 192.0.2.10 on eth0",
		NeighborState:  "sampled",
		NeighborDetail: "neighbor table sample after VIP promotion: []",
		ObservedAt:     time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		TransportClaim: "linux_local_vip_route_promoted",
	}}
	svc := &SystemService{Store: st, Status: haActivationStatusConfig(runningVersion, lkg.ArtifactSetSHA256)}
	svc.Status.HighAvailabilityPromoter = promoter
	svc.Status.HighAvailabilityConntrackSync = func(context.Context) (*HighAvailabilityConntrackSyncEvidence, error) {
		return &HighAvailabilityConntrackSyncEvidence{
			Provider:   "conntrackd",
			Claim:      "synced",
			PeerID:     "fw-a",
			EvidenceID: "ct-sync-1",
			ObservedAt: time.Date(2026, 6, 22, 12, 0, 1, 0, time.UTC),
			Detail:     "conntrackd reported state table synchronized before local activation.",
		}, nil
	}

	resp, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover with local VIP",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if err != nil {
		t.Fatalf("ActivateHighAvailabilityFailover: %v", err)
	}
	if promoter.calls != 1 {
		t.Fatalf("promoter calls = %d, want 1", promoter.calls)
	}
	state, ok, err := st.GetHighAvailabilityState()
	if err != nil || !ok {
		t.Fatalf("read HA state ok=%v err=%v", ok, err)
	}
	if state.TransportClaim != "linux_local_vip_route_promoted" || state.TransportGARPState != "sent" || state.TransportNeighborState != "sampled" || state.ConntrackSyncClaim != "synced" {
		t.Fatalf("persisted HA evidence wrong: %+v", state)
	}
	if !strings.Contains(resp.GetAfter().GetDetail(), "Linux-local VIP/route promotion completed") {
		t.Fatalf("activation response missing promotion detail: %+v", resp.GetAfter())
	}
	if resp.GetAfter().GetTransportEvidence().GetState() != "promoted" || resp.GetAfter().GetTransportEvidence().GetGarpState() != "sent" {
		t.Fatalf("transport evidence missing from activation response: %+v", resp.GetAfter().GetTransportEvidence())
	}
	if resp.GetAfter().GetConntrackSync().GetState() != "synced" || resp.GetAfter().GetConntrackSync().GetProvider() != "conntrackd" {
		t.Fatalf("conntrack sync evidence missing from activation response: %+v", resp.GetAfter().GetConntrackSync())
	}
	assertPolicyAuditAction(t, st, "ha-failover-activate", runningVersion, "manual failover with local VIP")
}

func TestSystemActivateHighAvailabilityFailoverDoesNotPersistActiveRoleWhenPromotionFails(t *testing.T) {
	st, runningVersion, lkg := haActivationStore(t)
	defer func() { _ = st.Close() }()
	svc := &SystemService{Store: st, Status: haActivationStatusConfig(runningVersion, lkg.ArtifactSetSHA256)}
	svc.Status.HighAvailabilityPromoter = &fakeHAPromoter{err: errors.New("ip addr replace failed")}

	_, err := svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover with local VIP",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "HA VIP/route promotion failed") {
		t.Fatalf("ActivateHighAvailabilityFailover err = %v", err)
	}
	if state, ok, err := st.GetHighAvailabilityState(); err != nil || ok {
		t.Fatalf("HA active role should not persist after promotion failure, ok=%v err=%v state=%+v", ok, err, state)
	}
	assertPolicyAuditAction(t, st, "ha-failover-activate-intent", runningVersion, "manual failover with local VIP")
	for _, action := range []string{"ha-failover-activate"} {
		if hasAuditAction(t, st, action) {
			t.Fatalf("unexpected audit action %q after failed promotion", action)
		}
	}
}

func TestSystemActivateHighAvailabilityFailoverRejectsMissingAcks(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		HighAvailabilityMode: "active-passive",
		HighAvailabilityRole: "passive",
	}}
	_, err = svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{Comment: "manual failover"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ack_failover is required") {
		t.Fatalf("error = %v, want ack_failover failed precondition", err)
	}
}

func haActivationStore(t *testing.T) (*store.Store, uint64, store.VersionInfo) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runningVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "replicated"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "replicated baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	lkg, err := st.GetVersionInfo(runningVersion)
	if err != nil {
		t.Fatalf("read lkg: %v", err)
	}
	return st, runningVersion, lkg
}

func haActivationStatusConfig(runningVersion uint64, artifactSet string) SystemStatusConfig {
	return SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: runningVersion,
				ArtifactSetSHA256:    artifactSet,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "active peer heartbeat",
			}, nil
		},
	}
}

type fakeHAPromoter struct {
	calls  int
	result engines.HAPromotionResult
	err    error
}

func (f *fakeHAPromoter) Promote(context.Context) (engines.HAPromotionResult, error) {
	f.calls++
	if f.err != nil {
		return engines.HAPromotionResult{}, f.err
	}
	return f.result, nil
}

func hasAuditAction(t *testing.T, st *store.Store, action string) bool {
	t.Helper()
	entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditFiltered(%s): %v", action, err)
	}
	return len(entries) > 0
}

func TestSystemActivateHighAvailabilityFailoverRejectsSplitBrainPreflightEvidence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	runningVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "replicated"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "replicated baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	lkg, err := st.GetVersionInfo(runningVersion)
	if err != nil {
		t.Fatalf("read lkg: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "passive",
				RunningPolicyVersion: runningVersion,
				ArtifactSetSHA256:    lkg.ArtifactSetSHA256,
				LastHeartbeat:        time.Now().Add(-2 * time.Second),
				Detail:               "peer reports passive during preflight",
			}, nil
		},
	}}

	_, err = svc.ActivateHighAvailabilityFailover(context.Background(), &openngfwv1.ActivateHighAvailabilityFailoverRequest{
		Comment:            "manual failover",
		AckFailover:        true,
		AckExternalCutover: true,
		AckExternalFencing: true,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "active/passive requires opposite roles") {
		t.Fatalf("error = %v, want split-brain preflight failed precondition", err)
	}
	if state, ok, err := st.GetHighAvailabilityState(); err != nil || ok {
		t.Fatalf("HA state should not persist on failed preflight ok=%v state=%+v err=%v", ok, state, err)
	}
	for _, action := range []string{"ha-failover-activate-intent", "ha-failover-activate"} {
		entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
		if err != nil {
			t.Fatalf("ListAuditFiltered(%s): %v", action, err)
		}
		if len(entries) != 0 {
			t.Fatalf("audit action %s should not be recorded on failed preflight: %+v", action, entries)
		}
	}
}

func TestSystemPullHighAvailabilityPolicyRejectsDirtyCandidateBeforePeerFetch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "local"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "local baseline"); err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	if err := st.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "staged"}}}); err != nil {
		t.Fatalf("set candidate: %v", err)
	}
	peerFetches := 0
	svc := &SystemService{Store: st, Policy: NewPolicyServer(st, engines.NewSupervisor(), func(_ *openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": []byte("unused")}, nil
	}), Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: 7,
				ArtifactSetSHA256:    strings.Repeat("a", 64),
				LastHeartbeat:        time.Now(),
			}, nil
		},
		HighAvailabilityPeerPolicy: func(context.Context) (*openngfwv1.GetPolicyResponse, error) {
			peerFetches++
			return &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}, Version: 7}, nil
		},
	}}

	_, err = svc.PullHighAvailabilityPolicy(context.Background(), &openngfwv1.PullHighAvailabilityPolicyRequest{
		Comment: "replicate from active",
		AckPull: true,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "local candidate has staged changes") {
		t.Fatalf("error = %v, want dirty candidate failed precondition", err)
	}
	if peerFetches != 0 {
		t.Fatalf("peer policy fetches = %d, want 0 before dirty candidate is resolved", peerFetches)
	}
}

func TestSystemPullHighAvailabilityPolicyRejectsCandidateStagedDuringPeerFetch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()
	localVersion, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "local"}},
	}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "local"}, "local baseline")
	if err != nil {
		t.Fatalf("commit local version: %v", err)
	}
	policyServer := NewPolicyServer(st, engines.NewSupervisor(), func(p *openngfwv1.Policy) (map[string][]byte, error) {
		name := "empty"
		if len(p.GetZones()) > 0 {
			name = p.GetZones()[0].GetName()
		}
		return map[string][]byte{"nftables": []byte(name)}, nil
	})
	stagedPolicy := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "operator-staged"}}}
	peerFetches := 0
	svc := &SystemService{Store: st, Policy: policyServer, Status: SystemStatusConfig{
		HighAvailabilityMode:                "active-passive",
		HighAvailabilityRole:                "passive",
		HighAvailabilityNodeID:              "fw-b",
		HighAvailabilityPeerID:              "fw-a",
		HighAvailabilityPeerAddress:         "https://fw-a.example/v1/system/ha/status",
		HighAvailabilityHeartbeatStaleAfter: time.Minute,
		HighAvailabilityPeerEvidence: func(context.Context) (*HighAvailabilityPeerEvidence, error) {
			return &HighAvailabilityPeerEvidence{
				NodeID:               "fw-a",
				Role:                 "active",
				RunningPolicyVersion: 7,
				ArtifactSetSHA256:    strings.Repeat("a", 64),
				LastHeartbeat:        time.Now(),
			}, nil
		},
		HighAvailabilityPeerPolicy: func(ctx context.Context) (*openngfwv1.GetPolicyResponse, error) {
			peerFetches++
			if _, err := policyServer.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: stagedPolicy}); err != nil {
				t.Fatalf("stage candidate during peer fetch: %v", err)
			}
			return &openngfwv1.GetPolicyResponse{
				Policy:  &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "peer-active"}}},
				Version: 7,
			}, nil
		},
	}}

	_, err = svc.PullHighAvailabilityPolicy(context.Background(), &openngfwv1.PullHighAvailabilityPolicyRequest{
		Comment:    "replicate from active",
		AckPull:    true,
		AckRisk:    true,
		AckRuntime: true,
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "local candidate has staged changes") {
		t.Fatalf("error = %v, want dirty candidate failed precondition", err)
	}
	if peerFetches != 1 {
		t.Fatalf("peer policy fetches = %d, want 1", peerFetches)
	}
	candidate, ok, err := st.GetCandidate()
	if err != nil || !ok || len(candidate.GetZones()) != 1 || candidate.GetZones()[0].GetName() != "operator-staged" {
		t.Fatalf("candidate after failed HA pull = ok=%v err=%v policy=%+v, want staged policy preserved", ok, err, candidate)
	}
	running, runningVersion, err := st.GetRunning()
	if err != nil {
		t.Fatalf("read running: %v", err)
	}
	if runningVersion != localVersion || len(running.GetZones()) != 1 || running.GetZones()[0].GetName() != "local" {
		t.Fatalf("running after failed HA pull = v%d %+v, want local v%d", runningVersion, running, localVersion)
	}
}

func TestSystemStatusReportsContentPackageReadiness(t *testing.T) {
	contentDir := t.TempDir()
	publisher := newSystemContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, filepath.Join(contentDir, "app-id"), "app-id", "1.0.0", "apps.json", []byte(`{"apps":["corp-admin"]}`))
	publisher.writePackage(t, filepath.Join(contentDir, "threat-id"), "threat-id", "1.0.0", "threats.json", []byte(`{"threats":["test"]}`))
	publisher.writePackage(t, filepath.Join(contentDir, "intel-feeds"), "intel-feeds", "1.0.0", "feeds.json", []byte(`{"feeds":["test"]}`))
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		ContentDir:  contentDir,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Content package verification"); got != "ready" {
		t.Fatalf("content package capability = %q, want ready detail=%q", got, capabilityDetail(resp.GetCapabilities(), "Content package verification"))
	}
	if hasWarning(resp.GetWarnings(), "warning", "Content package verification is incomplete.") {
		t.Fatalf("unexpected content package warning in %#v", resp.GetWarnings())
	}
}

func TestReleaseAcceptanceStatusReportsConfiguredNoPerformanceClaims(t *testing.T) {
	dir := t.TempDir()
	svc := &SystemService{Status: SystemStatusConfig{
		ReleaseAcceptanceManifestPath: filepath.Join(dir, "release", "acceptance.json"),
		ReleaseEvidenceDir:            filepath.Join(dir, "release", "evidence"),
		ReleaseNoPerformanceClaims:    true,
	}}

	resp, err := svc.GetReleaseAcceptanceStatus(context.Background(), &openngfwv1.GetReleaseAcceptanceStatusRequest{})
	if err != nil {
		t.Fatalf("GetReleaseAcceptanceStatus returned error: %v", err)
	}
	if resp.GetReady() || resp.GetState() != "blocked" {
		t.Fatalf("release status ready/state = %v/%q, want blocked", resp.GetReady(), resp.GetState())
	}
	if resp.GetManifestPresent() {
		t.Fatal("manifest_present = true, want false")
	}
	if got := resp.GetSummary().GetNotApplicable(); got != 1 {
		t.Fatalf("not_applicable count = %d, want 1", got)
	}
	var benchmark *openngfwv1.ReleaseAcceptanceCheckStatus
	var protoVerify *openngfwv1.ReleaseAcceptanceCheckStatus
	for _, check := range resp.GetChecks() {
		if check.GetName() == "release-benchmark" {
			benchmark = check
		}
		if check.GetName() == "proto-verify" {
			protoVerify = check
		}
	}
	if benchmark == nil {
		t.Fatal("release-benchmark status missing")
	}
	if benchmark.GetState() != "not_applicable" || benchmark.GetEvidencePath() != "" || benchmark.GetArtifact() != "" {
		t.Fatalf("release-benchmark = %+v, want not_applicable without evidence path or artifact", benchmark)
	}
	if benchmark.GetNextCommand() != nil || !strings.Contains(benchmark.GetNextAction(), "No evidence artifact is required") {
		t.Fatalf("release-benchmark remediation = %q %#v, want action without command", benchmark.GetNextAction(), benchmark.GetNextCommand())
	}
	if protoVerify == nil {
		t.Fatal("proto-verify status missing")
	}
	if !strings.Contains(protoVerify.GetNextAction(), "Record real evidence for proto-verify") {
		t.Fatalf("proto-verify next_action = %q, want record guidance", protoVerify.GetNextAction())
	}
	if got := protoVerify.GetNextCommand(); len(got) == 0 || got[0] != "go" || got[len(got)-2] != "make" || got[len(got)-1] != "proto-verify" {
		t.Fatalf("proto-verify next_command = %#v, want ngfwrelease record command ending in make proto-verify", got)
	}
	if len(resp.GetProblems()) == 0 {
		t.Fatal("problems empty, want missing manifest/evidence blockers")
	}
	recordability := resp.GetRecordability()
	if recordability == nil {
		t.Fatal("recordability missing")
	}
	if recordability.GetReady() {
		t.Fatalf("recordability ready = true, want blocked in test checkout with non-release commit metadata")
	}
	if recordability.GetRecordCommit() == "" {
		t.Fatalf("recordability record_commit empty: %+v", recordability)
	}
	if len(recordability.GetProblems()) == 0 {
		t.Fatalf("recordability problems empty: %+v", recordability)
	}
	if len(recordability.GetAllowedDirtyPaths()) > 0 && recordability.GetAllowedDirtyPaths()[0] == "" {
		t.Fatalf("recordability allowed dirty paths include empty path: %+v", recordability)
	}
}

func TestReleaseAcceptanceStatusMapsBenchmarkSummary(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("mkdir manifest dir: %v", err)
	}
	raw, err := json.MarshalIndent(map[string]any{
		"schema_version":  "phragma.release.acceptance.v1",
		"release_version": "v-test",
		"commit":          "0123456789abcdef0123456789abcdef01234567",
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":              "release-benchmark",
			"status":            "passed",
			"artifact":          "evidence/release-benchmark.txt",
			"benchmark_summary": "perf/release-results/run-1/summary.json",
			"ran_at":            "2026-06-18T12:00:00Z",
		}},
	}, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	writeSystemFile(t, manifestPath, append(raw, '\n'))
	svc := &SystemService{Status: SystemStatusConfig{
		ReleaseAcceptanceManifestPath: manifestPath,
		ReleaseEvidenceDir:            filepath.Join(dir, "release", "evidence"),
	}}

	resp, err := svc.GetReleaseAcceptanceStatus(context.Background(), &openngfwv1.GetReleaseAcceptanceStatusRequest{})
	if err != nil {
		t.Fatalf("GetReleaseAcceptanceStatus returned error: %v", err)
	}
	for _, check := range resp.GetChecks() {
		if check.GetName() == "release-benchmark" {
			if check.GetBenchmarkSummary() != "perf/release-results/run-1/summary.json" {
				t.Fatalf("benchmark summary = %q, want manifest value", check.GetBenchmarkSummary())
			}
			return
		}
	}
	t.Fatal("release-benchmark status missing")
}

func TestReleaseAcceptanceStatusMapsRecordability(t *testing.T) {
	report := releaseacceptance.StatusReport{
		SchemaVersion: "openngfw.release_acceptance.status.v1",
		GeneratedAt:   "2026-06-18T00:00:00Z",
		State:         "blocked",
		Summary:       releaseacceptance.StatusSummary{},
		Recordability: &releaseacceptance.RecordabilityStatus{
			Ready:              false,
			GitHead:            "1111111111111111111111111111111111111111",
			RecordCommit:       "2222222222222222222222222222222222222222",
			AllowedDirtyPaths:  []string{"release/evidence/"},
			DirtySourcePaths:   []string{" M internal/apiserver/system.go"},
			StaleEvidencePaths: []string{"release/evidence/proto-verify.txt (evidence commit 1111111111111111111111111111111111111111 != record commit 2222222222222222222222222222222222222222)"},
			Problems:           []string{"release source tree has uncommitted changes outside allowed release artifact paths"},
		},
	}

	resp := releaseAcceptanceStatusProto(report)
	recordability := resp.GetRecordability()
	if recordability == nil {
		t.Fatal("recordability missing")
	}
	if recordability.GetReady() {
		t.Fatal("recordability ready = true, want blocked")
	}
	if got := recordability.GetGitHead(); got != "1111111111111111111111111111111111111111" {
		t.Fatalf("git_head = %q, want mapped head", got)
	}
	if got := recordability.GetRecordCommit(); got != "2222222222222222222222222222222222222222" {
		t.Fatalf("record_commit = %q, want mapped record commit", got)
	}
	if got := recordability.GetAllowedDirtyPaths(); len(got) != 1 || got[0] != "release/evidence/" {
		t.Fatalf("allowed_dirty_paths = %#v, want mapped allowlist", got)
	}
	if got := recordability.GetDirtySourcePaths(); len(got) != 1 || got[0] != " M internal/apiserver/system.go" {
		t.Fatalf("dirty_source_paths = %#v, want blocking dirty source path", got)
	}
	if got := recordability.GetStaleEvidencePaths(); len(got) != 1 || !strings.Contains(got[0], "release/evidence/proto-verify.txt") || !strings.Contains(got[0], "record commit") {
		t.Fatalf("stale_evidence_paths = %#v, want mapped stale evidence path", got)
	}
	if got := recordability.GetProblems(); len(got) != 1 || !strings.Contains(got[0], "uncommitted changes") {
		t.Fatalf("problems = %#v, want mapped blocking problem", got)
	}
}

func TestReleaseAcceptanceStatusProtoRedactsServerLocalEvidenceDisclosure(t *testing.T) {
	report := releaseacceptance.StatusReport{
		SchemaVersion:   "openngfw.release_acceptance.status.v1",
		GeneratedAt:     "2026-06-22T00:00:00Z",
		ManifestPath:    "/tmp/openngfw-smoke/release/acceptance.json",
		EvidenceDir:     "/home/opc/oss-ngfw/release/evidence",
		ManifestPresent: false,
		State:           "blocked",
		Summary:         releaseacceptance.StatusSummary{Missing: 1},
		Problems: []string{
			"release acceptance manifest /tmp/openngfw-smoke/release/acceptance.json is missing",
			"record failed with Authorization: Bearer release-secret-token",
		},
		Checks: []releaseacceptance.CheckStatus{{
			Name:         "webui-enterprise-smoke",
			State:        "missing",
			Artifact:     "evidence/webui-enterprise-smoke.txt",
			EvidencePath: "/home/opc/oss-ngfw/release/evidence/webui-enterprise-smoke.txt",
			Detail:       "smoke manifest at /tmp/openngfw-webui-smoke/webui-smoke-evidence.json token=release-secret",
			Problems:     []string{"stdout references /home/opc/oss-ngfw/release/evidence/webui-enterprise-smoke.txt"},
			NextAction:   "Record real evidence from /home/opc/oss-ngfw before acceptance.",
			NextCommand:  []string{"go", "run", "./cmd/ngfwrelease", "record", "--evidence-dir", "/home/opc/oss-ngfw/release/evidence", "--token=release-secret", "--check", "webui-enterprise-smoke", "--", "make", "webui-enterprise-smoke"},
		}},
		Recordability: &releaseacceptance.RecordabilityStatus{
			Ready:             false,
			GitHead:           "1111111111111111111111111111111111111111",
			RecordCommit:      "2222222222222222222222222222222222222222",
			AllowedDirtyPaths: []string{"/home/opc/oss-ngfw/release/evidence"},
			DirtySourcePaths:  []string{"/Users/operator/oss-ngfw/internal/apiserver/system.go"},
			Problems:          []string{"source tree at /home/opc/oss-ngfw has uncommitted changes"},
		},
	}

	resp := releaseAcceptanceStatusProto(report)
	encoded, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	text := string(encoded)
	for _, leaked := range []string{"/home/opc", "/tmp/openngfw", "/Users/operator", "release-secret-token", "token=release-secret", "--token=release-secret"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("release acceptance response leaked %q:\n%s", leaked, text)
		}
	}
	for _, want := range []string{"webui-enterprise-smoke", "[server-local path redacted]", "token=[redacted]", "Bearer [redacted]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("release acceptance response missing %q:\n%s", want, text)
		}
	}
}

func TestSystemStatusWarnsOnContentPackageBlockers(t *testing.T) {
	contentDir := t.TempDir()
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		ContentDir:  contentDir,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Content package verification"); got != "degraded" {
		t.Fatalf("content package capability = %q, want degraded detail=%q", got, capabilityDetail(resp.GetCapabilities(), "Content package verification"))
	}
	if !strings.Contains(capabilityDetail(resp.GetCapabilities(), "Content package verification"), "blocker") {
		t.Fatalf("content package detail missing blocker count: %q", capabilityDetail(resp.GetCapabilities(), "Content package verification"))
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Content package verification is incomplete.") {
		t.Fatalf("missing content package warning in %#v", resp.GetWarnings())
	}
	warnings := runtimeReadinessWarnings(resp, nil, nil)
	if !containsSubstring(warnings, "Content package verification is incomplete.") {
		t.Fatalf("runtime readiness warnings missing content package warning: %#v", warnings)
	}
}

func TestSystemStatusReportsDegradedHostResources(t *testing.T) {
	procRoot := writeProcFixture(t, procFixture{
		loadavg: "3.00 2.00 1.00 1/100 12\n",
		meminfo: "MemTotal:        8192000 kB\n" +
			"MemAvailable:    4096000 kB\n",
		netDev: `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  ens4: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0
`,
	})
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		HostCPUs:    2,
		ProcRoot:    procRoot,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Host resource telemetry"); got != "degraded" {
		t.Fatalf("host resource capability = %q, want degraded", got)
	}
	host := resp.GetHost()
	if got := host.GetState(); got != "degraded" {
		t.Fatalf("host resource state = %q, want degraded", got)
	}
	if got := host.GetLoad1PerCpu(); got != 1.5 {
		t.Fatalf("host load1 per cpu = %v, want 1.5", got)
	}
	if got := len(host.GetInterfaces()); got != 1 {
		t.Fatalf("host interfaces = %d, want 1", got)
	}
	if got := host.GetInterfaces()[0].GetState(); got != "degraded" {
		t.Fatalf("interface state = %q, want degraded", got)
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Host resource telemetry is degraded.") {
		t.Fatalf("missing host resource warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsDegradedEbpfReadiness(t *testing.T) {
	sysfsRoot := writeSysfsFixture(t, []string{"fs/bpf/"})
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		SysfsRoot:   sysfsRoot,
		CommandLookup: func(name string) (string, error) {
			if name == "ip" || name == "tc" {
				return "/usr/sbin/" + name, nil
			}
			return "", errors.New("not found")
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Linux eBPF XDP/tc host readiness"); got != "degraded" {
		t.Fatalf("eBPF host readiness capability = %q, want degraded", got)
	}
	ebpf := resp.GetDataplane().GetEbpf()
	if got := ebpf.GetState(); got != "degraded" {
		t.Fatalf("structured eBPF state = %q, want degraded", got)
	}
	var degraded []string
	for _, probe := range ebpf.GetProbes() {
		if probe.GetState() == "degraded" {
			degraded = append(degraded, probe.GetName())
		}
	}
	for _, want := range []string{"bpftool", "clang", "Kernel BTF", "cgroup v2 BPF hooks"} {
		if !containsString(degraded, want) {
			t.Fatalf("missing degraded eBPF probe %q in %v", want, degraded)
		}
	}
	if got := ebpf.GetAttachState(); got != "degraded" {
		t.Fatalf("eBPF attach_state = %q, want degraded", got)
	}
	if !containsString(ebpf.GetBlockers(), "BPF runtime inspection") || !containsString(ebpf.GetBlockers(), "Network link inventory") {
		t.Fatalf("eBPF blockers = %v, want attach blockers", ebpf.GetBlockers())
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Linux eBPF XDP/tc host readiness is incomplete.") {
		t.Fatalf("missing eBPF readiness warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsEbpfRuntimeEvidenceWithoutChangingActiveDataplane(t *testing.T) {
	sysfsRoot := writeSysfsFixture(t, []string{
		"kernel/btf/vmlinux",
		"fs/bpf/",
		"fs/cgroup/cgroup.controllers",
		"class/net/",
	})
	artifactDir := t.TempDir()
	plan := []byte("state=planned\nauthoritative_renderer=nftables\nsupported_hooks=xdp,tc\n")
	if err := os.WriteFile(filepath.Join(artifactDir, "ebpf-plan.txt"), plan, 0o600); err != nil {
		t.Fatalf("write eBPF plan artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "system-status-ebpf.json"), []byte(`{"state":"ready","attach_state":"ready","renderer_state":"planned"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write eBPF status artifact: %v", err)
	}
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:                 time.Now().UTC(),
		AuthEnabled:               true,
		TLSEnabled:                true,
		ActiveDataplane:           "nftables/conntrack",
		SysfsRoot:                 sysfsRoot,
		EbpfPinRoot:               "/sys/fs/bpf/openngfw",
		EbpfArtifactDir:           artifactDir,
		EbpfAttachProbeInterfaces: []string{"ens5"},
		EbpfRuntimeProbes:         true,
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "bpftool" {
				return []byte{}, nil
			}
			if strings.Join(args, " ") != "net" {
				t.Fatalf("unexpected bpftool command args: %v", args)
			}
			return []byte(strings.Join([]string{
				"xdp:",
				"ens5(2) prog/xdp id 10 name xdp_ingress",
				"tc:",
				"ens5(2) clsact/ingress prog/tc id 11 name tc_ingress",
				"",
			}, "\n")), nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := resp.GetDataplane().GetActiveDataplane(); got != "nftables/conntrack" {
		t.Fatalf("active dataplane = %q, want nftables/conntrack", got)
	}
	ebpf := resp.GetDataplane().GetEbpf()
	if got := ebpf.GetState(); got != "ready" {
		t.Fatalf("eBPF state = %q, want ready", got)
	}
	if got := ebpf.GetAttachState(); got != "ready" {
		t.Fatalf("eBPF attach_state = %q, want ready", got)
	}
	if !strings.Contains(ebpf.GetAttachDetail(), "/sys/fs/bpf/openngfw") {
		t.Fatalf("eBPF attach detail = %q, want pin root", ebpf.GetAttachDetail())
	}
	if got := ebpf.GetEvidenceScope(); got != "host-prerequisites,attach-prerequisites,renderer-scaffold,runtime-probes" {
		t.Fatalf("eBPF evidence scope = %q, want runtime probes", got)
	}
	if len(ebpf.GetAttachments()) != 2 {
		t.Fatalf("eBPF attachments = %d, want 2: %#v", len(ebpf.GetAttachments()), ebpf.GetAttachments())
	}
	if got := ebpf.GetAttachments()[0].GetState(); got != "attached" {
		t.Fatalf("first eBPF attachment state = %q, want attached", got)
	}
	if got := ebpf.GetAttachments()[0].GetProgramId(); got != "10" {
		t.Fatalf("first eBPF program id = %q, want 10", got)
	}
	if got := ebpf.GetAttachments()[1].GetProgramName(); got != "tc_ingress" {
		t.Fatalf("second eBPF program name = %q, want tc_ingress", got)
	}
	artifacts := ebpf.GetArtifacts()
	if len(artifacts) != 2 {
		t.Fatalf("eBPF artifacts = %d, want 2: %#v", len(artifacts), artifacts)
	}
	var planArtifact *openngfwv1.EbpfArtifact
	for _, artifact := range artifacts {
		if artifact.GetName() == "ebpf-plan.txt" {
			planArtifact = artifact
		}
	}
	if planArtifact == nil {
		t.Fatalf("missing ebpf-plan.txt artifact in %#v", artifacts)
	}
	sum := sha256.Sum256(plan)
	if got := planArtifact.GetSha256(); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("eBPF plan digest = %q, want %q", got, hex.EncodeToString(sum[:]))
	}
}

func TestSystemStatusEbpfRuntimeProbesRespectOptIn(t *testing.T) {
	sysfsRoot := writeSysfsFixture(t, []string{
		"kernel/btf/vmlinux",
		"fs/bpf/",
		"fs/cgroup/cgroup.controllers",
		"class/net/",
	})
	var commandRuns int
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:                 time.Now().UTC(),
		AuthEnabled:               true,
		TLSEnabled:                true,
		SysfsRoot:                 sysfsRoot,
		EbpfAttachProbeInterfaces: []string{"ens5"},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "bpftool" {
				commandRuns++
			}
			return []byte("unexpected\n"), nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if commandRuns != 0 {
		t.Fatalf("eBPF runtime probes ran %d time(s), want 0", commandRuns)
	}
	if got := len(resp.GetDataplane().GetEbpf().GetAttachments()); got != 0 {
		t.Fatalf("eBPF attachments = %d, want 0 without runtime probes", got)
	}
}

func TestSystemIdentityReportsLocalAdminWhenAuthDisabled(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{AuthEnabled: false}}
	resp, err := svc.GetIdentity(context.Background(), &openngfwv1.GetIdentityRequest{})
	if err != nil {
		t.Fatalf("GetIdentity returned error: %v", err)
	}
	if resp.GetActor() != "local" || resp.GetRole() != "admin" || resp.GetAuthEnabled() {
		t.Fatalf("identity = %#v, want local/admin with auth disabled", resp)
	}
	if got := strings.Join(resp.GetCapabilities(), ","); got != "read,write,admin" {
		t.Fatalf("capabilities = %q, want read,write,admin", got)
	}
}

func TestSystemIdentityReportsAuthenticatedRole(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(users, []byte(`users:
  - name: bob
    token: operator-token-012345678
    role: operator
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := authz.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Status: SystemStatusConfig{AuthEnabled: true}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer operator-token-012345678"))
	var resp *openngfwv1.GetIdentityResponse
	_, err = auth.UnaryInterceptor()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetIdentity"},
		func(ctx context.Context, _ any) (any, error) {
			var err error
			resp, err = svc.GetIdentity(ctx, &openngfwv1.GetIdentityRequest{})
			return nil, err
		})
	if err != nil {
		t.Fatalf("interceptor/GetIdentity returned error: %v", err)
	}
	if resp.GetActor() != "bob" || resp.GetRole() != "operator" || !resp.GetAuthEnabled() || resp.GetAuthSource() != authz.AuthSourceLocalUsersFile {
		t.Fatalf("identity = %#v, want bob/operator with auth enabled", resp)
	}
	if got := strings.Join(resp.GetCapabilities(), ","); got != "read,write" {
		t.Fatalf("capabilities = %q, want read,write", got)
	}
}

func TestSystemIdentityReportsOIDCSessionSource(t *testing.T) {
	auth := authz.NewAuthenticator()
	auth.SetSessionLookup(func(token string) (authz.Identity, bool) {
		if token != "session-token-012345678" {
			return authz.Identity{}, false
		}
		return authz.Identity{Name: "dana", Role: authz.RoleAdmin, AuthSource: authz.AuthSourceOIDCSession}, true
	})
	svc := &SystemService{Status: SystemStatusConfig{AuthEnabled: true}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer session-token-012345678"))
	var resp *openngfwv1.GetIdentityResponse
	_, err := auth.UnaryInterceptor()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetIdentity"},
		func(ctx context.Context, _ any) (any, error) {
			var err error
			resp, err = svc.GetIdentity(ctx, &openngfwv1.GetIdentityRequest{})
			return nil, err
		})
	if err != nil {
		t.Fatalf("interceptor/GetIdentity returned error: %v", err)
	}
	if resp.GetActor() != "dana" || resp.GetRole() != "admin" || resp.GetAuthSource() != authz.AuthSourceOIDCSession {
		t.Fatalf("identity = %#v, want dana/admin/oidc-session", resp)
	}
	if got := strings.Join(resp.GetCapabilities(), ","); got != "read,write,admin" {
		t.Fatalf("capabilities = %q, want read,write,admin", got)
	}
}

func systemTokenHashString(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestAccessAdministrationReportsSafeLoadedLocalInventory(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.yaml")
	hashedToken := systemTokenHashString("operator-token-012345678")
	if err := os.WriteFile(users, []byte(`users:
  - name: alice
    token: admin-token-0123456789
    role: admin
  - name: bob
    token_hash: `+hashedToken+`
    role: operator
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := authz.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(users); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Auth: auth, Status: SystemStatusConfig{AuthEnabled: true}}

	resp, err := svc.GetAccessAdministration(context.Background(), &openngfwv1.GetAccessAdministrationRequest{})
	if err != nil {
		t.Fatalf("GetAccessAdministration returned error: %v", err)
	}
	if !resp.GetAuthEnabled() {
		t.Fatal("auth_enabled = false, want true")
	}
	if got := len(resp.GetLocalUsers()); got != 2 {
		t.Fatalf("local users = %d, want 2", got)
	}
	if resp.GetLocalUsers()[0].GetName() != "alice" || resp.GetLocalUsers()[0].GetRole() != "admin" {
		t.Fatalf("first local user = %#v, want alice/admin", resp.GetLocalUsers()[0])
	}
	if resp.GetLocalUsers()[0].GetTokenMaterial() != "plaintext-token-redacted" ||
		resp.GetLocalUsers()[1].GetTokenMaterial() != "prehashed-token-redacted" {
		t.Fatalf("token material = %#v, want redacted local token posture", resp.GetLocalUsers())
	}
	if resp.GetBreakGlass().GetState() != "ready" {
		t.Fatalf("break-glass state = %q, want ready", resp.GetBreakGlass().GetState())
	}
	if !containsString(resp.GetBlockers(), "OIDC browser SSO is not configured.") {
		t.Fatalf("missing OIDC blocker in %#v", resp.GetBlockers())
	}
	bodyBytes, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)
	for _, secret := range []string{
		"admin-token-0123456789",
		"operator-token-012345678",
		hashedToken,
		strings.TrimPrefix(hashedToken, "sha256:"),
		"token_hash",
		"client_secret",
		"csrf",
		users,
		filepath.Dir(users),
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("access administration response leaked %q in %s", secret, body)
		}
	}
}

func TestRunOIDCPreflightRequiresOIDC(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{AuthEnabled: true}}
	_, err := svc.RunOIDCPreflight(context.Background(), &openngfwv1.RunOIDCPreflightRequest{})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("missing OIDC code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestRunOIDCPreflightReportsReadySanitizedEvidence(t *testing.T) {
	provider := newSystemOIDCPreflightProvider(t)
	defer provider.Close()
	oidcAuth, err := authz.NewOIDCAuthenticator(context.Background(), authz.OIDCConfig{
		Issuer:            provider.URL,
		ClientID:          "openngfw-web",
		ClientSecret:      "client-secret-value",
		RedirectURL:       "https://fw.example.com/v1/auth/oidc/callback",
		RoleClaim:         "groups",
		DefaultRole:       "viewer",
		Scopes:            []string{"openid", "profile", "email"},
		CookieName:        "openngfw_session",
		CookieSecure:      true,
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		SessionTTL:        time.Hour,
		MaxStates:         16,
		MaxSessions:       16,
	})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	svc := &SystemService{OIDC: oidcAuth, Status: SystemStatusConfig{AuthEnabled: true}}

	resp, err := svc.RunOIDCPreflight(context.Background(), &openngfwv1.RunOIDCPreflightRequest{})
	if err != nil {
		t.Fatalf("RunOIDCPreflight: %v", err)
	}
	if resp.GetState() != "ready" || resp.GetLabel() != "ready" {
		t.Fatalf("preflight state = %q/%q, want ready", resp.GetState(), resp.GetLabel())
	}
	if resp.GetSchemaVersion() != "openngfw.oidc-preflight.v1" || resp.GetGeneratedAt() == "" {
		t.Fatalf("preflight metadata missing: %#v", resp)
	}
	if resp.GetOidc().GetIssuer() != provider.URL || resp.GetOidc().GetClientId() != "openngfw-web" || !resp.GetOidc().GetCookieSecure() {
		t.Fatalf("OIDC inventory = %#v, want non-secret configured posture", resp.GetOidc())
	}
	wantChecks := map[string]string{
		"provider-discovery": "ok",
		"redirect-callback":  "ok",
		"session-cookie":     "ok",
		"scopes":             "ok",
		"role-mapping":       "ok",
		"trusted-proxy":      "ok",
		"session-limits":     "ok",
		"session-capacity":   "ok",
	}
	for _, check := range resp.GetChecks() {
		want, ok := wantChecks[check.GetId()]
		if !ok {
			t.Fatalf("unexpected preflight check %#v", check)
		}
		if check.GetClass() != want {
			t.Fatalf("check %s class = %q, want %q (%#v)", check.GetId(), check.GetClass(), want, check)
		}
		delete(wantChecks, check.GetId())
	}
	if len(wantChecks) != 0 {
		t.Fatalf("missing checks: %#v", wantChecks)
	}
	bodyBytes, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)
	for _, secret := range []string{
		"client-secret-value",
		"openngfw_session",
		"/v1/auth/oidc/callback",
		"redirectUrl",
		"redirect_url",
		"cookieName",
		"cookie_name",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("OIDC preflight leaked %q in %s", secret, body)
		}
	}
}

func TestRunOIDCPreflightBlocksInsecureCookie(t *testing.T) {
	provider := newSystemOIDCPreflightProvider(t)
	defer provider.Close()
	oidcAuth, err := authz.NewOIDCAuthenticator(context.Background(), authz.OIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "openngfw-web",
		ClientSecret: "client-secret-value",
		RedirectURL:  "https://fw.example.com/v1/auth/oidc/callback",
		CookieSecure: false,
		SessionTTL:   time.Hour,
		MaxStates:    16,
		MaxSessions:  16,
	})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	svc := &SystemService{OIDC: oidcAuth, Status: SystemStatusConfig{AuthEnabled: true}}

	resp, err := svc.RunOIDCPreflight(context.Background(), &openngfwv1.RunOIDCPreflightRequest{})
	if err != nil {
		t.Fatalf("RunOIDCPreflight: %v", err)
	}
	if resp.GetState() != "blocked" {
		t.Fatalf("preflight state = %q, want blocked", resp.GetState())
	}
	if !containsString(resp.GetBlockers(), "OIDC browser sessions are not using Secure cookies.") {
		t.Fatalf("missing secure-cookie blocker in %#v", resp.GetBlockers())
	}
}

func TestOIDCProviderConfigLifecyclePersistsAuditsAndRedacts(t *testing.T) {
	provider := newSystemOIDCPreflightProvider(t)
	defer provider.Close()
	dir := t.TempDir()
	users := filepath.Join(dir, "users.yaml")
	if err := os.WriteFile(users, []byte(`users:
  - name: alice
    token: admin-token-0123456789
    role: admin
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := authz.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(dir, "oidc-secret")
	if err := os.WriteFile(secretFile, []byte("super-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	accessConfig := filepath.Join(dir, "access.json")
	st := newSystemAuditStore(t)
	svc := &SystemService{
		Store:            st,
		Auth:             auth,
		LocalUsersFile:   users,
		AccessConfigFile: accessConfig,
		Status:           SystemStatusConfig{AuthEnabled: true},
	}
	cfg := &openngfwv1.OIDCProviderConfig{
		Enabled:          true,
		Issuer:           provider.URL,
		ClientId:         "openngfw-web",
		ClientSecretFile: secretFile,
		RedirectUrl:      "https://firewall.example.com/v1/auth/oidc/callback",
		RoleClaim:        "groups",
		DefaultRole:      "viewer",
		Scopes:           []string{"openid", "profile", "email"},
	}
	valid, err := svc.ValidateOIDCProviderConfig(context.Background(), &openngfwv1.ValidateOIDCProviderConfigRequest{Config: cfg})
	if err != nil {
		t.Fatalf("ValidateOIDCProviderConfig: %v", err)
	}
	if valid.GetState() != "ready" {
		t.Fatalf("validation = %#v, want ready", valid)
	}
	setResp, err := svc.SetOIDCProviderConfig(context.Background(), &openngfwv1.SetOIDCProviderConfigRequest{
		Config: cfg, AckOidcChange: true, Comment: "configure runtime provider",
	})
	if err != nil {
		t.Fatalf("SetOIDCProviderConfig: %v", err)
	}
	if !setResp.GetConfig().GetEnabled() || setResp.GetConfig().GetClientSecretFile() != "" || !setResp.GetConfig().GetClientSecretFileConfigured() {
		t.Fatalf("set response leaked or missed secret file posture: %#v", setResp.GetConfig())
	}
	if !svc.Status.OIDCEnabled || !svc.Status.OIDCCookieSecure || svc.CurrentOIDC() == nil {
		t.Fatalf("runtime OIDC not enabled in service status")
	}
	bodyBytes, err := protojson.Marshal(setResp)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)
	for _, leaked := range []string{secretFile, "super-secret", filepath.Dir(secretFile)} {
		if strings.Contains(body, leaked) {
			t.Fatalf("set response leaked %q in %s", leaked, body)
		}
	}
	onDisk, err := os.ReadFile(accessConfig)
	if err != nil {
		t.Fatalf("read persisted access config: %v", err)
	}
	if !strings.Contains(string(onDisk), secretFile) || strings.Contains(string(onDisk), "super-secret") {
		t.Fatalf("persisted config should include secret file path only, got %s", string(onDisk))
	}
	disableResp, err := svc.DisableOIDCProvider(context.Background(), &openngfwv1.DisableOIDCProviderRequest{
		AckDisableOidc: true, Comment: "disable runtime provider",
	})
	if err != nil {
		t.Fatalf("DisableOIDCProvider: %v", err)
	}
	if !disableResp.GetDisabled() || svc.CurrentOIDC() != nil || svc.Status.OIDCEnabled || svc.Status.OIDCCookieSecure {
		t.Fatalf("disable response/state wrong: %#v status=%#v", disableResp, svc.Status)
	}
	for _, action := range []string{"access-oidc-provider-set", "access-oidc-provider-disable"} {
		entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatalf("missing audit action %s", action)
		}
		if strings.Contains(entries[0].Detail, secretFile) || strings.Contains(entries[0].Detail, "super-secret") {
			t.Fatalf("audit action %s leaked secret material: %#v", action, entries[0])
		}
	}
}

func TestSAMLProviderConfigLifecyclePreservesOIDCAndRedacts(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.yaml")
	if err := os.WriteFile(users, []byte(`users:
  - name: alice
    token: admin-token-0123456789
    role: admin
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := authz.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	accessConfig := filepath.Join(dir, "access.json")
	st := newSystemAuditStore(t)
	svc := &SystemService{
		Store:            st,
		Auth:             auth,
		LocalUsersFile:   users,
		AccessConfigFile: accessConfig,
		OIDCProviderConfig: authz.OIDCProviderConfig{
			Enabled:     true,
			Issuer:      "https://oidc.example.com",
			ClientID:    "openngfw-web",
			RedirectURL: "https://fw.example.com/v1/auth/oidc/callback",
		},
		Status: SystemStatusConfig{AuthEnabled: true},
	}
	if err := authz.SaveOIDCProviderConfig(accessConfig, svc.OIDCProviderConfig); err != nil {
		t.Fatalf("seed OIDC config: %v", err)
	}
	fingerprint := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := &openngfwv1.SAMLProviderConfig{
		Enabled:                true,
		IdpEntityId:            "https://idp.example.com/saml",
		SsoUrl:                 "https://idp.example.com/sso",
		SpEntityId:             "https://fw.example.com/ui",
		AcsUrl:                 "https://fw.example.com/v1/auth/saml/acs",
		RoleAttribute:          "groups",
		DefaultRole:            "viewer",
		CertificateFingerprint: fingerprint,
	}
	valid, err := svc.ValidateSAMLProviderConfig(context.Background(), &openngfwv1.ValidateSAMLProviderConfigRequest{Config: cfg})
	if err != nil {
		t.Fatalf("ValidateSAMLProviderConfig: %v", err)
	}
	if valid.GetState() != "ready" || len(valid.GetWarnings()) != 0 {
		t.Fatalf("validation = %#v, want ready without runtime warning", valid)
	}
	setResp, err := svc.SetSAMLProviderConfig(context.Background(), &openngfwv1.SetSAMLProviderConfigRequest{
		Config: cfg, AckSamlChange: true, Comment: "prepare saml provider",
	})
	if err != nil {
		t.Fatalf("SetSAMLProviderConfig: %v", err)
	}
	if !setResp.GetConfig().GetEnabled() || setResp.GetConfig().GetCertificateFingerprint() != "" || !setResp.GetConfig().GetCertificateFingerprintConfigured() {
		t.Fatalf("set response leaked or missed fingerprint posture: %#v", setResp.GetConfig())
	}
	if !setResp.GetSaml().GetRuntimeAvailable() {
		t.Fatalf("SAML runtime should be active: %#v", setResp.GetSaml())
	}
	bodyBytes, err := protojson.Marshal(setResp)
	if err != nil {
		t.Fatal(err)
	}
	if body := string(bodyBytes); strings.Contains(body, fingerprint) {
		t.Fatalf("set response leaked certificate fingerprint: %s", body)
	}
	loadedOIDC, err := authz.LoadOIDCProviderConfig(accessConfig)
	if err != nil {
		t.Fatalf("load preserved OIDC config: %v", err)
	}
	if loadedOIDC.Issuer != "https://oidc.example.com" || loadedOIDC.ClientID != "openngfw-web" {
		t.Fatalf("SAML save did not preserve OIDC config: %#v", loadedOIDC)
	}
	loadedSAML, err := authz.LoadSAMLProviderConfig(accessConfig)
	if err != nil {
		t.Fatalf("load SAML config: %v", err)
	}
	if !loadedSAML.Enabled || loadedSAML.CertificateFingerprint != fingerprint {
		t.Fatalf("persisted SAML config = %#v, want enabled with fingerprint stored locally", loadedSAML)
	}
	admin, err := svc.GetAccessAdministration(context.Background(), &openngfwv1.GetAccessAdministrationRequest{})
	if err != nil {
		t.Fatalf("GetAccessAdministration: %v", err)
	}
	if !admin.GetSaml().GetEnabled() || !admin.GetSaml().GetRuntimeAvailable() || !admin.GetSaml().GetCertificateFingerprintConfigured() {
		t.Fatalf("SAML inventory = %#v, want configured runtime-active posture", admin.GetSaml())
	}
	disableResp, err := svc.DisableSAMLProvider(context.Background(), &openngfwv1.DisableSAMLProviderRequest{
		AckDisableSaml: true, Comment: "disable saml provider",
	})
	if err != nil {
		t.Fatalf("DisableSAMLProvider: %v", err)
	}
	if !disableResp.GetDisabled() {
		t.Fatalf("disable response = %#v, want disabled", disableResp)
	}
	for _, action := range []string{"access-saml-provider-set", "access-saml-provider-disable"} {
		entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatalf("missing audit action %s", action)
		}
		if strings.Contains(entries[0].Detail, fingerprint) || strings.Contains(strings.ToLower(entries[0].Detail), "saml_response") {
			t.Fatalf("audit action %s leaked SAML secret material: %#v", action, entries[0])
		}
	}
}

func newSystemOIDCPreflightProvider(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var server *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"authorization_endpoint":                server.URL + "/authorize",
			"token_endpoint":                        server.URL + "/token",
			"jwks_uri":                              server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}); err != nil {
			t.Fatalf("write discovery: %v", err)
		}
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": []any{}}); err != nil {
			t.Fatalf("write jwks: %v", err)
		}
	})
	server = httptest.NewServer(mux)
	return server
}

func TestLocalUserLifecycleMutationsAreAuditedAndRefreshAuth(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(users, []byte(`users:
  - name: alice
    token: admin-token-0123456789
    role: admin
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := authz.Load(users)
	if err != nil {
		t.Fatal(err)
	}
	st := newSystemAuditStore(t)
	svc := &SystemService{Store: st, Auth: auth, LocalUsersFile: users, Status: SystemStatusConfig{AuthEnabled: true}}

	_, err = svc.CreateLocalUser(context.Background(), &openngfwv1.CreateLocalUserRequest{
		Name: "bob", Role: "operator", AckLocalUserChange: true,
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("missing comment code = %v, want InvalidArgument (err=%v)", got, err)
	}

	created, err := svc.CreateLocalUser(context.Background(), &openngfwv1.CreateLocalUserRequest{
		Name: "bob", Role: "operator", AckLocalUserChange: true, Comment: "add automation operator",
	})
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	if created.GetUser().GetName() != "bob" || created.GetUser().GetRole() != "operator" || !created.GetUser().GetEnabled() || !created.GetUser().GetEditable() || created.GetOneTimeToken() == "" {
		t.Fatalf("create response wrong: %#v", created)
	}
	if _, err := systemAuthCall(t, svc.Auth, created.GetOneTimeToken(), "/openngfw.v1.PolicyService/Commit"); err != nil {
		t.Fatalf("created token rejected: %v", err)
	}

	rotated, err := svc.RotateLocalUserToken(context.Background(), &openngfwv1.RotateLocalUserTokenRequest{
		Name: "bob", AckRotateToken: true, Comment: "rotate after handoff",
	})
	if err != nil {
		t.Fatalf("RotateLocalUserToken: %v", err)
	}
	if rotated.GetOneTimeToken() == "" || rotated.GetOneTimeToken() == created.GetOneTimeToken() {
		t.Fatalf("rotate one-time token wrong: %#v", rotated)
	}
	if _, err := systemAuthCall(t, svc.Auth, created.GetOneTimeToken(), "/openngfw.v1.PolicyService/GetPolicy"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old token code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}

	updated, err := svc.UpdateLocalUser(context.Background(), &openngfwv1.UpdateLocalUserRequest{
		Name: "bob", Role: "viewer", AckLocalUserChange: true, Comment: "reduce role",
	})
	if err != nil {
		t.Fatalf("UpdateLocalUser: %v", err)
	}
	if updated.GetUser().GetRole() != "viewer" {
		t.Fatalf("updated role = %q, want viewer", updated.GetUser().GetRole())
	}
	if _, err := systemAuthCall(t, svc.Auth, rotated.GetOneTimeToken(), "/openngfw.v1.PolicyService/Commit"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer token code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	disabled, err := svc.DisableLocalUser(context.Background(), &openngfwv1.DisableLocalUserRequest{
		Name: "bob", AckDisableUser: true, Comment: "remove temporary access",
	})
	if err != nil {
		t.Fatalf("DisableLocalUser bob: %v", err)
	}
	if disabled.GetUser().GetEnabled() {
		t.Fatalf("disabled user still enabled: %#v", disabled.GetUser())
	}
	if _, err := systemAuthCall(t, svc.Auth, rotated.GetOneTimeToken(), "/openngfw.v1.PolicyService/GetPolicy"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("disabled token code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}

	_, err = svc.DisableLocalUser(context.Background(), &openngfwv1.DisableLocalUserRequest{
		Name: "alice", AckDisableUser: true, Comment: "bad idea",
	})
	if got := status.Code(err); got != codes.InvalidArgument || !strings.Contains(err.Error(), "at least one enabled local admin") {
		t.Fatalf("last-admin disable err = %v, code=%v; want InvalidArgument guard", err, got)
	}

	resp, err := svc.GetAccessAdministration(context.Background(), &openngfwv1.GetAccessAdministrationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)
	for _, secret := range []string{created.GetOneTimeToken(), rotated.GetOneTimeToken(), users, filepath.Dir(users)} {
		if strings.Contains(body, secret) {
			t.Fatalf("access inventory leaked %q in %s", secret, body)
		}
	}
	for _, action := range []string{
		"access-local-user-create",
		"access-local-user-rotate-token",
		"access-local-user-update",
		"access-local-user-disable",
		"access-local-user-disable-failed",
	} {
		entries, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 5})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatalf("missing audit action %s", action)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Detail, created.GetOneTimeToken()) || strings.Contains(entry.Detail, rotated.GetOneTimeToken()) || strings.Contains(entry.Detail, users) {
				t.Fatalf("audit detail leaked sensitive material: %#v", entry)
			}
		}
	}
}

func TestAccessAdministrationReportsDisabledAuthBreakGlass(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{AuthEnabled: false}}
	resp, err := svc.GetAccessAdministration(context.Background(), &openngfwv1.GetAccessAdministrationRequest{})
	if err != nil {
		t.Fatalf("GetAccessAdministration returned error: %v", err)
	}
	if resp.GetAuthEnabled() {
		t.Fatal("auth_enabled = true, want false")
	}
	if resp.GetBreakGlass().GetState() != "active" {
		t.Fatalf("break-glass state = %q, want active", resp.GetBreakGlass().GetState())
	}
	if !strings.Contains(resp.GetBreakGlass().GetDetail(), "local callers are treated as admin") {
		t.Fatalf("break-glass detail = %q, want local-admin explanation", resp.GetBreakGlass().GetDetail())
	}
	if !containsString(resp.GetBlockers(), "API authentication is disabled; local callers are treated as admin.") {
		t.Fatalf("missing disabled-auth blocker in %#v", resp.GetBlockers())
	}
	for _, blocker := range resp.GetBlockers() {
		if strings.Contains(strings.ToLower(blocker), "not implemented") {
			t.Fatalf("access administration blocker kept stale not-implemented wording: %q", blocker)
		}
	}
}

func TestRevokeAccessSessionRequiresSessionIDAckAndExistingSession(t *testing.T) {
	st := newSystemAuditStore(t)
	svc := &SystemService{Store: st, Status: SystemStatusConfig{AuthEnabled: true}}

	_, err := svc.RevokeAccessSession(context.Background(), &openngfwv1.RevokeAccessSessionRequest{AckRevokeSession: true})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("missing session_id code = %v, want InvalidArgument (err=%v)", got, err)
	}

	_, err = svc.RevokeAccessSession(context.Background(), &openngfwv1.RevokeAccessSessionRequest{SessionId: "oidc-session-sha256:test"})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("missing ack code = %v, want FailedPrecondition (err=%v)", got, err)
	}

	_, err = svc.RevokeAccessSession(context.Background(), &openngfwv1.RevokeAccessSessionRequest{
		SessionId:        "oidc-session-sha256:test",
		AckRevokeSession: true,
	})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("missing session code = %v, want NotFound (err=%v)", got, err)
	}

	entries, err := st.ListAudit(3)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d, want 3", len(entries))
	}
	for _, entry := range entries {
		if entry.Action != "access-session-revoke-failed" || entry.Actor != "local" || entry.ActorRole != "admin" || entry.AuthSource != authz.AuthSourceDisabledLocal {
			t.Fatalf("unexpected access revoke failure audit entry: %#v", entry)
		}
	}
}

func TestSystemStatusWarnsForNonProductionPosture(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		HTTPListen:  "127.0.0.1:8080",
		TLSEnabled:  false,
		AuthEnabled: false,
		DryRun:      true,
		Engines:     []SystemEngine{{Name: "nftables", Role: "stateful firewall"}},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	seen := map[string]bool{}
	for _, w := range resp.GetWarnings() {
		seen[w.GetMessage()] = true
	}
	for _, want := range []string{
		"The daemon is running in dry-run mode; commits do not change the host firewall.",
		"API authentication is disabled; local callers are treated as admin.",
		"WebUI and REST gateway TLS is disabled.",
	} {
		if !seen[want] {
			t.Fatalf("missing warning %q in %#v", want, resp.GetWarnings())
		}
	}
	if resp.GetEngines()[0].GetMode() != "dry-run" {
		t.Fatalf("expected dry-run mode, got %q", resp.GetEngines()[0].GetMode())
	}
}

func TestSystemStatusWarnsForDisabledManagementGuardrails(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:             time.Now().UTC(),
		HTTPListen:            "127.0.0.1:8080",
		TLSEnabled:            true,
		AuthEnabled:           true,
		OIDCEnabled:           true,
		OIDCCookieSecure:      false,
		RateLimitRPM:          0,
		HTTPMaxBodyBytes:      0,
		GRPCMaxRecvBytes:      0,
		GRPCMaxSendBytes:      0,
		HTTPReadHeaderTimeout: 0,
		HTTPReadTimeout:       0,
		HTTPWriteTimeout:      0,
		HTTPIdleTimeout:       0,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if resp.GetManagement().GetRateLimitEnabled() {
		t.Fatal("rate limit should report disabled")
	}
	if got := capabilityState(resp.GetCapabilities(), "Management plane guardrails"); got != "degraded" {
		t.Fatalf("management guardrail capability = %q, want degraded", got)
	}
	if !hasWarning(resp.GetWarnings(), "critical", "OIDC browser sessions are not using Secure cookies.") {
		t.Fatalf("missing critical OIDC cookie warning in %#v", resp.GetWarnings())
	}
	for _, want := range []string{
		"API rate limiting is disabled.",
		"REST/WebUI request body size is not explicitly capped.",
		"Direct gRPC message size limits are not fully explicit.",
		"REST/WebUI HTTP timeouts are not fully configured.",
	} {
		if !hasWarning(resp.GetWarnings(), "warning", want) {
			t.Fatalf("missing warning %q in %#v", want, resp.GetWarnings())
		}
	}
}

func TestSystemStatusAcceptsSecureOIDCCookiesBehindReverseProxy(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:             time.Now().UTC(),
		HTTPListen:            "127.0.0.1:8080",
		TLSEnabled:            false,
		AuthEnabled:           true,
		OIDCEnabled:           true,
		OIDCCookieSecure:      true,
		RateLimitRPM:          600,
		RateLimitBurst:        120,
		HTTPMaxBodyBytes:      10 << 20,
		GRPCMaxRecvBytes:      16 << 20,
		GRPCMaxSendBytes:      16 << 20,
		HTTPReadHeaderTimeout: 10 * time.Second,
		HTTPReadTimeout:       15 * time.Second,
		HTTPWriteTimeout:      30 * time.Second,
		HTTPIdleTimeout:       2 * time.Minute,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if hasWarning(resp.GetWarnings(), "critical", "OIDC browser sessions are not using Secure cookies.") {
		t.Fatalf("unexpected insecure OIDC cookie warning in %#v", resp.GetWarnings())
	}
	detail := capabilityDetail(resp.GetCapabilities(), "Management plane guardrails")
	if strings.Contains(detail, "OIDC session cookie not secure") {
		t.Fatalf("management detail = %q, should not flag secure upstream OIDC cookie", detail)
	}
}

func TestSystemStatusWarnsForSocketPeerRateLimitOnExposedREST(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:             time.Now().UTC(),
		HTTPListen:            "0.0.0.0:8443",
		TLSEnabled:            true,
		AuthEnabled:           true,
		RateLimitRPM:          600,
		RateLimitBurst:        120,
		HTTPMaxBodyBytes:      10 << 20,
		GRPCMaxRecvBytes:      16 << 20,
		GRPCMaxSendBytes:      16 << 20,
		HTTPReadHeaderTimeout: 10 * time.Second,
		HTTPReadTimeout:       15 * time.Second,
		HTTPWriteTimeout:      30 * time.Second,
		HTTPIdleTimeout:       2 * time.Minute,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := resp.GetManagement().GetRateLimitClientIdentity(); got != "socket-peer" {
		t.Fatalf("management rate identity = %q, want socket-peer", got)
	}
	if !hasWarning(resp.GetWarnings(), "warning", "REST/WebUI rate limiting keys clients by socket peer only.") {
		t.Fatalf("missing socket-peer warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsDegradedKernelTuning(t *testing.T) {
	sysctlRoot := writeSysctlFixture(t, map[string]string{
		"net.ipv4.ip_forward":              "0",
		"net.ipv4.conf.all.rp_filter":      "1",
		"net.ipv4.conf.default.rp_filter":  "1",
		"net.netfilter.nf_conntrack_count": "1",
		"net.netfilter.nf_conntrack_max":   "262144",
		"net.core.somaxconn":               "128",
	})
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:        time.Now().UTC(),
		AuthEnabled:      true,
		TLSEnabled:       true,
		SysctlRoot:       sysctlRoot,
		SysctlConfigPath: "/etc/sysctl.d/99-openngfw.conf",
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Kernel forwarding tuning"); got != "degraded" {
		t.Fatalf("kernel tuning capability = %q, want degraded", got)
	}
	tuning := resp.GetDataplane().GetKernelTuning()
	if got := tuning.GetState(); got != "degraded" {
		t.Fatalf("kernel tuning state = %q, want degraded", got)
	}
	if got := tuning.GetSysctlConfigPath(); got != "/etc/sysctl.d/99-openngfw.conf" {
		t.Fatalf("sysctl config path = %q, want installer path", got)
	}
	if len(tuning.GetChecks()) != 5 {
		t.Fatalf("kernel tuning checks = %d, want 5", len(tuning.GetChecks()))
	}
	for _, check := range tuning.GetChecks() {
		if check.GetState() != "degraded" {
			t.Fatalf("check %s state = %q, want degraded", check.GetKey(), check.GetState())
		}
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Kernel forwarding/high-throughput tuning is not ready.") {
		t.Fatalf("missing kernel tuning warning in %#v", resp.GetWarnings())
	}
}

func TestTuneHostPreviewThroughputProfile(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		SysctlConfigPath: "/etc/sysctl.d/99-openngfw.conf",
	}}
	resp, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{Profile: "throughput"})
	if err != nil {
		t.Fatalf("TuneHost preview returned error: %v", err)
	}
	if resp.GetProfile() != "throughput" {
		t.Fatalf("profile = %q, want throughput", resp.GetProfile())
	}
	if resp.GetWroteConfig() || resp.GetAppliedLive() {
		t.Fatalf("preview should not mutate host: %#v", resp)
	}
	if !strings.Contains(resp.GetConfigText(), "# profile: throughput") ||
		!strings.Contains(resp.GetConfigText(), "net.netfilter.nf_conntrack_max = 4194304") {
		t.Fatalf("throughput config missing expected values:\n%s", resp.GetConfigText())
	}
	if !hasTuneResult(resp.GetResults(), "net.core.netdev_max_backlog", "planned") {
		t.Fatalf("missing planned netdev backlog result in %#v", resp.GetResults())
	}
}

func TestTuneHostRequiresAcknowledgementForMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf")
	svc := &SystemService{Status: SystemStatusConfig{SysctlConfigPath: path}}
	_, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{Write: true})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("config should not be written without ack, stat err=%v", statErr)
	}
}

func TestTuneHostRejectsDryRunMutation(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{DryRun: true}}
	_, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{Write: true, AckHostChange: true})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestTuneHostWritesAndAppliesThroughputProfile(t *testing.T) {
	sysctlRoot := writeSysctlFixture(t, map[string]string{
		"net.ipv4.ip_forward":              "0",
		"net.ipv4.conf.all.rp_filter":      "1",
		"net.ipv4.conf.default.rp_filter":  "1",
		"net.netfilter.nf_conntrack_count": "1",
		"net.netfilter.nf_conntrack_max":   "262144",
		"net.core.somaxconn":               "128",
		"net.core.netdev_max_backlog":      "1024",
	})
	configPath := filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf")
	var commands []string
	svc := &SystemService{Status: SystemStatusConfig{
		SysctlRoot:       sysctlRoot,
		SysctlConfigPath: configPath,
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return []byte(strings.Join(args, " ") + "\n"), nil
		},
	}}
	resp, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{
		Profile:       "throughput",
		Write:         true,
		Apply:         true,
		AckHostChange: true,
	})
	if err != nil {
		t.Fatalf("TuneHost write/apply returned error: %v", err)
	}
	if !resp.GetWroteConfig() || !resp.GetAppliedLive() {
		t.Fatalf("expected write/apply response, got %#v", resp)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if !strings.Contains(string(raw), "# profile: throughput") {
		t.Fatalf("written config is not throughput profile:\n%s", raw)
	}
	for _, want := range []string{
		"sysctl -w net.netfilter.nf_conntrack_max=4194304",
		"sysctl -w net.core.somaxconn=8192",
		"sysctl -w net.core.netdev_max_backlog=250000",
	} {
		if !containsString(commands, want) {
			t.Fatalf("missing command %q in %#v", want, commands)
		}
	}
	if !hasTuneResult(resp.GetResults(), "net.netfilter.nf_conntrack_max", "applied") ||
		!hasTuneResult(resp.GetResults(), "net.core.netdev_max_backlog", "applied") {
		t.Fatalf("expected applied tune results, got %#v", resp.GetResults())
	}
}

func TestListSystemLogsFiltersAndRedactsBoundedLogRoot(t *testing.T) {
	logDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(logDir, "controld.log"), []byte(strings.Join([]string{
		"2026-06-20T12:00:00Z info controld started",
		"2026-06-20T12:01:00Z error token=super-secret failed to open /var/log/openngfw/private/state.db",
		"2026-06-20T12:02:00Z warn ignored unrelated event",
	}, "\n")), 0o640); err != nil {
		t.Fatalf("write controld log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "suricata.log"), []byte(`{"timestamp":"2026-06-20T12:03:00Z","level":"warning","message":"suricata engine degraded Authorization: Bearer abc.def access_token=writer-secret"}`+"\n"), 0o640); err != nil {
		t.Fatalf("write suricata log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "secret.txt"), []byte("do not scan"), 0o640); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	svc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}
	resp, err := svc.ListSystemLogs(context.Background(), &openngfwv1.ListSystemLogsRequest{
		Limit:    10,
		Source:   "engine",
		Engine:   "suricata",
		Severity: "warn",
		Query:    "degraded",
	})
	if err != nil {
		t.Fatalf("ListSystemLogs: %v", err)
	}
	if got := len(resp.GetEntries()); got != 1 {
		t.Fatalf("entries = %d, want 1: %#v", got, resp.GetEntries())
	}
	entry := resp.GetEntries()[0]
	if entry.GetSource() != "engine" || entry.GetEngine() != "suricata" || entry.GetSeverity() != "warn" {
		t.Fatalf("entry facets = source=%q engine=%q severity=%q", entry.GetSource(), entry.GetEngine(), entry.GetSeverity())
	}
	bodyBytes, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	body := string(bodyBytes)
	for _, forbidden := range []string{"abc.def", "writer-secret", "super-secret", logDir, "/var/log/openngfw/private/state.db"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("system log response leaked %q in %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "Bearer [redacted]") {
		t.Fatalf("system log response did not carry redacted bearer marker: %s", body)
	}
	if !strings.Contains(body, "access_token=[redacted]") {
		t.Fatalf("system log response did not carry redacted access-token marker: %s", body)
	}
}

func TestListSystemLogsRejectsInvalidTimeAndCapsLimit(t *testing.T) {
	logDir := t.TempDir()
	lines := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		lines = append(lines, fmt.Sprintf("2026-06-20T12:00:%02dZ info event %d", i, i))
	}
	if err := os.WriteFile(filepath.Join(logDir, "openngfw.log"), []byte(strings.Join(lines, "\n")), 0o640); err != nil {
		t.Fatalf("write log: %v", err)
	}
	svc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}
	if _, err := svc.ListSystemLogs(context.Background(), &openngfwv1.ListSystemLogsRequest{Since: "yesterday"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid since error = %v, want InvalidArgument", err)
	}
	resp, err := svc.ListSystemLogs(context.Background(), &openngfwv1.ListSystemLogsRequest{Limit: 3})
	if err != nil {
		t.Fatalf("ListSystemLogs: %v", err)
	}
	if got := len(resp.GetEntries()); got != 3 {
		t.Fatalf("entries = %d, want capped request limit 3", got)
	}
	if !resp.GetSummary().GetTruncated() {
		t.Fatalf("summary.truncated = false, want true")
	}
}

func TestListSystemLogsUnavailableRootReturnsWarning(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{LogDir: filepath.Join(t.TempDir(), "missing")}}
	resp, err := svc.ListSystemLogs(context.Background(), &openngfwv1.ListSystemLogsRequest{})
	if err != nil {
		t.Fatalf("ListSystemLogs: %v", err)
	}
	if len(resp.GetEntries()) != 0 {
		t.Fatalf("entries = %#v, want none", resp.GetEntries())
	}
	if !containsSubstring(resp.GetSummary().GetWarnings(), "log root") {
		t.Fatalf("warnings = %#v, want log root warning", resp.GetSummary().GetWarnings())
	}
}

func TestPlanPacketCaptureBuildsBoundedFlowCommand(t *testing.T) {
	logDir := t.TempDir()
	svc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}

	resp, err := svc.PlanPacketCapture(context.Background(), &openngfwv1.PlanPacketCaptureRequest{
		Interface:       "ens5",
		Protocol:        openngfwv1.Protocol_PROTOCOL_TCP,
		SrcIp:           "10.0.1.20",
		SrcPort:         51515,
		DestIp:          "10.0.2.20",
		DestPort:        443,
		DurationSeconds: 600,
		PacketCount:     0,
		SnaplenBytes:    999999,
		Label:           "flow check",
		FlowId:          "eve-42",
	})
	if err != nil {
		t.Fatalf("PlanPacketCapture returned error: %v", err)
	}
	plan := resp.GetPlan()
	if plan.GetInterface() != "ens5" {
		t.Fatalf("interface = %q, want ens5", plan.GetInterface())
	}
	if plan.GetDurationSeconds() != maxCaptureDuration {
		t.Fatalf("duration = %d, want %d", plan.GetDurationSeconds(), maxCaptureDuration)
	}
	if plan.GetPacketCount() != defaultCapturePackets {
		t.Fatalf("packet count = %d, want %d", plan.GetPacketCount(), defaultCapturePackets)
	}
	if plan.GetSnaplenBytes() != maxCaptureSnaplen {
		t.Fatalf("snaplen = %d, want %d", plan.GetSnaplenBytes(), maxCaptureSnaplen)
	}
	if plan.GetFlowId() != "eve-42" {
		t.Fatalf("flow_id = %q, want eve-42", plan.GetFlowId())
	}
	wantFilter := "tcp and ((src host 10.0.1.20 and src port 51515 and dst host 10.0.2.20 and dst port 443) or (src host 10.0.2.20 and src port 443 and dst host 10.0.1.20 and dst port 51515))"
	if plan.GetBpfFilter() != wantFilter {
		t.Fatalf("filter = %q, want %q", plan.GetBpfFilter(), wantFilter)
	}
	if !strings.Contains(plan.GetOutputPath(), filepath.Join(logDir, "pcap", "phragma-flow-check-")) {
		t.Fatalf("output path = %q, want log pcap path", plan.GetOutputPath())
	}
	if got := strings.Join(plan.GetCommandArgv(), " "); !strings.Contains(got, "-i ens5") || !strings.Contains(got, "-w "+plan.GetOutputPath()) {
		t.Fatalf("command argv = %q", got)
	}
	if !strings.Contains(plan.GetCommand(), "timeout 60s tcpdump") {
		t.Fatalf("command = %q, want manual timeout wrapper", plan.GetCommand())
	}
	if len(plan.GetWarnings()) != 0 {
		t.Fatalf("warnings = %#v, want none", plan.GetWarnings())
	}
}

func TestPlanPacketCaptureRejectsInvalidInputs(t *testing.T) {
	svc := &SystemService{}
	_, err := svc.PlanPacketCapture(context.Background(), &openngfwv1.PlanPacketCaptureRequest{
		Interface: "eth0;rm -rf /",
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
	_, err = svc.PlanPacketCapture(context.Background(), &openngfwv1.PlanPacketCaptureRequest{
		SrcIp: "not an ip",
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument for IP (err=%v)", got, err)
	}
	_, err = svc.PlanPacketCapture(context.Background(), &openngfwv1.PlanPacketCaptureRequest{
		FlowId: "bad flow id",
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument for flow_id (err=%v)", got, err)
	}
}

func TestStartPacketCaptureRequiresAck(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := &SystemService{Store: st}
	_, err = svc.StartPacketCapture(context.Background(), &openngfwv1.StartPacketCaptureRequest{
		Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
		SrcIp:    "10.0.1.20",
		DestIp:   "10.0.2.20",
	})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "packet-capture-failed" || !strings.Contains(entries[0].Detail, "acknowledgement") {
		t.Fatalf("audit entries = %#v, want acknowledgement failure", entries)
	}
}

func TestStartPacketCaptureRejectedAttemptFailsIfAuditFails(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st}
	_, err = svc.StartPacketCapture(context.Background(), &openngfwv1.StartPacketCaptureRequest{
		Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
		SrcIp:    "10.0.1.20",
		DestIp:   "10.0.2.20",
	})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", got, err)
	}
	if !strings.Contains(err.Error(), "packet capture rejected but audit write failed") {
		t.Fatalf("error = %v, want rejected/audit failure detail", err)
	}
}

func TestStartPacketCaptureRejectsDryRun(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{DryRun: true}}
	_, err := svc.StartPacketCapture(context.Background(), &openngfwv1.StartPacketCaptureRequest{
		Protocol:   openngfwv1.Protocol_PROTOCOL_TCP,
		SrcIp:      "10.0.1.20",
		DestIp:     "10.0.2.20",
		AckCapture: true,
	})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestStartPacketCaptureRunsTcpdumpAndAudits(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var commands []string
	logDir := t.TempDir()
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			LogDir: logDir,
			CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
				commands = append(commands, name+" "+strings.Join(args, " "))
				for i, arg := range args {
					if arg == "-w" && i+1 < len(args) {
						if err := os.WriteFile(args[i+1], []byte("pcap-bytes"), 0o640); err != nil {
							return nil, err
						}
					}
				}
				return []byte("captured 1 packet\n"), nil
			},
		},
	}
	resp, err := svc.StartPacketCapture(context.Background(), &openngfwv1.StartPacketCaptureRequest{
		Interface:       "ens5",
		Protocol:        openngfwv1.Protocol_PROTOCOL_UDP,
		SrcIp:           "10.0.1.20",
		SrcPort:         53000,
		DestIp:          "10.0.2.53",
		DestPort:        53,
		DurationSeconds: 2,
		PacketCount:     10,
		SnaplenBytes:    128,
		Label:           "dns-test",
		FlowId:          "eve-dns-1",
		AckCapture:      true,
	})
	if err != nil {
		t.Fatalf("StartPacketCapture returned error: %v", err)
	}
	job := resp.GetJob()
	if job.GetState() != "completed" || job.GetBytesWritten() != uint64(len("pcap-bytes")) {
		t.Fatalf("job = %#v, want completed with bytes", job)
	}
	if job.GetSha256() != "ee9338e23f71e4aaaccb58f34b0e07c029855ae1416c122bcdb0b7042809c474" {
		t.Fatalf("job sha256 = %q, want pcap hash", job.GetSha256())
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "tcpdump -i ens5") || !strings.Contains(commands[0], "udp and ((src host 10.0.1.20") {
		t.Fatalf("commands = %#v", commands)
	}
	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "packet-capture" ||
		!strings.Contains(entries[0].Detail, "completed") ||
		!strings.Contains(entries[0].Detail, "flow_id=eve-dns-1") ||
		!strings.Contains(entries[0].Detail, "sha256=ee9338e23f71e4aaaccb58f34b0e07c029855ae1416c122bcdb0b7042809c474") {
		t.Fatalf("audit entries = %#v, want completed packet-capture with sha256", entries)
	}
	listResp, err := svc.ListPacketCaptures(context.Background(), &openngfwv1.ListPacketCapturesRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListPacketCaptures returned error: %v", err)
	}
	if len(listResp.GetCaptures()) != 1 {
		t.Fatalf("listed captures = %d, want 1", len(listResp.GetCaptures()))
	}
	if got := listResp.GetCaptures()[0].GetPlan(); got.GetSrcIp() != "10.0.1.20" || got.GetDestIp() != "10.0.2.53" || got.GetDestPort() != 53 || got.GetFlowId() != "eve-dns-1" {
		t.Fatalf("listed capture plan = %#v, want preserved tuple metadata", got)
	}
}

func TestListPacketCapturesIndexesRecentArtifacts(t *testing.T) {
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(captureDir, "phragma-old-20260618T120000Z.pcap")
	newPath := filepath.Join(captureDir, "phragma-new-20260618T121500Z.pcap")
	if err := os.WriteFile(oldPath, []byte("old-pcap"), 0o640); err != nil {
		t.Fatal(err)
	}
	newBytes := []byte("new-pcap-bytes")
	if err := os.WriteFile(newPath, newBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writePacketCaptureMetadata(&openngfwv1.PacketCaptureJob{
		Plan: &openngfwv1.PacketCapturePlan{OutputPath: oldPath, FlowId: "eve-old"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writePacketCaptureMetadata(&openngfwv1.PacketCaptureJob{
		Plan: &openngfwv1.PacketCapturePlan{OutputPath: newPath, FlowId: "eve-new"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(captureDir, "notes.txt"), []byte("skip"), 0o640); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	newTime := time.Date(2026, 6, 18, 12, 15, 0, 0, time.UTC)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}

	resp, err := svc.ListPacketCaptures(context.Background(), &openngfwv1.ListPacketCapturesRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListPacketCaptures returned error: %v", err)
	}
	if resp.GetCaptureDir() != captureDir {
		t.Fatalf("capture_dir = %q, want %q", resp.GetCaptureDir(), captureDir)
	}
	captures := resp.GetCaptures()
	if len(captures) != 1 {
		t.Fatalf("captures = %d, want 1: %#v", len(captures), captures)
	}
	capture := captures[0]
	if capture.GetId() != "phragma-new-20260618T121500Z" || capture.GetArtifactId() != capture.GetId() {
		t.Fatalf("capture ids = id:%q artifact:%q, want newest artifact id", capture.GetId(), capture.GetArtifactId())
	}
	if capture.GetFilename() != "phragma-new-20260618T121500Z.pcap" {
		t.Fatalf("filename = %q", capture.GetFilename())
	}
	if capture.GetDownloadPath() != "/v1/system/packet-captures/phragma-new-20260618T121500Z/download" {
		t.Fatalf("download_path = %q", capture.GetDownloadPath())
	}
	if capture.GetMediaType() != captureMediaType {
		t.Fatalf("media_type = %q, want %q", capture.GetMediaType(), captureMediaType)
	}
	if capture.GetCompletedAt() != newTime.Format(time.RFC3339Nano) {
		t.Fatalf("completed_at = %q, want %q", capture.GetCompletedAt(), newTime.Format(time.RFC3339Nano))
	}
	if capture.GetBytesWritten() != uint64(len(newBytes)) {
		t.Fatalf("bytes_written = %d, want %d", capture.GetBytesWritten(), len(newBytes))
	}
	sum := sha256.Sum256(newBytes)
	if capture.GetSha256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %q, want %x", capture.GetSha256(), sum)
	}
	if capture.GetPlan().GetOutputPath() != newPath {
		t.Fatalf("output_path = %q, want %q", capture.GetPlan().GetOutputPath(), newPath)
	}
	if capture.GetPlan().GetFlowId() != "eve-new" {
		t.Fatalf("flow_id = %q, want eve-new", capture.GetPlan().GetFlowId())
	}

	filtered, err := svc.ListPacketCaptures(context.Background(), &openngfwv1.ListPacketCapturesRequest{Limit: 1, FlowId: "eve-old"})
	if err != nil {
		t.Fatalf("ListPacketCaptures filtered returned error: %v", err)
	}
	if len(filtered.GetCaptures()) != 1 || filtered.GetCaptures()[0].GetArtifactId() != "phragma-old-20260618T120000Z" {
		t.Fatalf("filtered captures = %#v, want old flow artifact despite newer unrelated artifact", filtered.GetCaptures())
	}
}

func TestSetPacketCaptureRetentionUpdatesSidecarAndAudit(t *testing.T) {
	st := newSystemAuditStore(t)
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(captureDir, "phragma-retain-20260618T121500Z.pcap")
	pcapBytes := []byte("pcap-retain-bytes")
	if err := os.WriteFile(capturePath, pcapBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writePacketCaptureMetadata(&openngfwv1.PacketCaptureJob{
		Id:          "phragma-retain-20260618T121500Z",
		State:       "completed",
		Detail:      "packet capture completed",
		Plan:        &openngfwv1.PacketCapturePlan{OutputPath: capturePath, FlowId: "eve-retain-1"},
		CompletedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: logDir}}
	retainUntil := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339)

	resp, err := svc.SetPacketCaptureRetention(context.Background(), &openngfwv1.SetPacketCaptureRetentionRequest{
		Id:                 "phragma-retain-20260618T121500Z",
		State:              openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
		RetainUntil:        retainUntil,
		RetentionReason:    "IR case validated by operator",
		CaseId:             "INC-2026-001",
		AckRetentionChange: true,
	})
	if err != nil {
		t.Fatalf("SetPacketCaptureRetention returned error: %v", err)
	}
	job := resp.GetJob()
	if job.GetArtifactId() != "phragma-retain-20260618T121500Z" {
		t.Fatalf("artifact_id = %q", job.GetArtifactId())
	}
	retention := job.GetRetention()
	if retention.GetState() != openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED ||
		retention.GetRetainUntil() != retainUntil ||
		retention.GetRetentionReason() != "IR case validated by operator" ||
		retention.GetCaseId() != "INC-2026-001" ||
		retention.GetUpdatedAt() == "" ||
		retention.GetUpdatedBy() != "local" {
		t.Fatalf("retention = %#v, want retained metadata", retention)
	}
	sum := sha256.Sum256(pcapBytes)
	if job.GetSha256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %q, want %x", job.GetSha256(), sum)
	}
	afterBytes, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(pcapBytes) {
		t.Fatalf("pcap bytes changed: got %q want %q", afterBytes, pcapBytes)
	}
	sidecar, err := readPacketCaptureMetadata(capturePath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if sidecar.GetRetention().GetState() != openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED ||
		sidecar.GetRetention().GetRetainUntil() != retainUntil {
		t.Fatalf("sidecar retention = %#v", sidecar.GetRetention())
	}
	listResp, err := svc.ListPacketCaptures(context.Background(), &openngfwv1.ListPacketCapturesRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListPacketCaptures returned error: %v", err)
	}
	if got := listResp.GetCaptures()[0].GetRetention(); got.GetCaseId() != "INC-2026-001" || got.GetRetainUntil() != retainUntil {
		t.Fatalf("listed retention = %#v", got)
	}
	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "packet-capture-retention" {
		t.Fatalf("audit entries = %#v, want packet-capture-retention", entries)
	}
	for _, want := range []string{"artifact_id=phragma-retain-20260618T121500Z", "state=PACKET_CAPTURE_RETENTION_STATE_RETAINED", "case_id=INC-2026-001", "flow_id=eve-retain-1"} {
		if !strings.Contains(entries[0].Detail, want) {
			t.Fatalf("audit detail %q missing %q", entries[0].Detail, want)
		}
	}
	if strings.Contains(entries[0].Detail, captureDir) || strings.Contains(entries[0].Detail, "output=") || strings.Contains(entries[0].Detail, "filter=") {
		t.Fatalf("audit detail leaked capture path/filter: %q", entries[0].Detail)
	}
}

func TestSetPacketCaptureRetentionReleaseClearsRetainUntil(t *testing.T) {
	st := newSystemAuditStore(t)
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(captureDir, "phragma-release-20260618T121500Z.pcap")
	pcapBytes := []byte("pcap-release-bytes")
	if err := os.WriteFile(capturePath, pcapBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	retainUntil := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if err := writePacketCaptureMetadata(&openngfwv1.PacketCaptureJob{
		Id:    "phragma-release-20260618T121500Z",
		State: "completed",
		Plan:  &openngfwv1.PacketCapturePlan{OutputPath: capturePath, FlowId: "eve-release-1"},
		Retention: &openngfwv1.PacketCaptureRetention{
			State:           openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
			RetainUntil:     retainUntil,
			RetentionReason: "previous hold",
			CaseId:          "INC-2026-002",
		},
	}); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: logDir}}

	resp, err := svc.SetPacketCaptureRetention(context.Background(), &openngfwv1.SetPacketCaptureRetentionRequest{
		Id:                 "phragma-release-20260618T121500Z",
		State:              openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED,
		RetentionReason:    "case review complete",
		CaseId:             "INC-2026-002",
		AckRetentionChange: true,
	})
	if err != nil {
		t.Fatalf("SetPacketCaptureRetention release returned error: %v", err)
	}
	retention := resp.GetJob().GetRetention()
	if retention.GetState() != openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED ||
		retention.GetRetainUntil() != "" ||
		retention.GetRetentionReason() != "case review complete" {
		t.Fatalf("retention = %#v, want released with cleared retain_until", retention)
	}
	afterBytes, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(pcapBytes) {
		t.Fatalf("pcap bytes changed: got %q want %q", afterBytes, pcapBytes)
	}
}

func TestSetPacketCaptureRetentionValidation(t *testing.T) {
	st := newSystemAuditStore(t)
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	captureID := "phragma-validate-20260618T121500Z"
	capturePath := filepath.Join(captureDir, captureID+".pcap")
	if err := os.WriteFile(capturePath, []byte("pcap-validate"), 0o640); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: logDir}}
	validUntil := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	validRequest := func() *openngfwv1.SetPacketCaptureRetentionRequest {
		return &openngfwv1.SetPacketCaptureRetentionRequest{
			Id:                 captureID,
			State:              openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
			RetainUntil:        validUntil,
			RetentionReason:    "validated incident evidence",
			CaseId:             "INC-VALIDATE",
			AckRetentionChange: true,
		}
	}

	tests := []struct {
		name   string
		mutate func(*openngfwv1.SetPacketCaptureRetentionRequest)
		want   codes.Code
	}{
		{"missing acknowledgement", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.AckRetentionChange = false }, codes.FailedPrecondition},
		{"unsafe artifact id", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.Id = "../secret" }, codes.InvalidArgument},
		{"missing artifact", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.Id = "missing-capture" }, codes.NotFound},
		{"unspecified state", func(r *openngfwv1.SetPacketCaptureRetentionRequest) {
			r.State = openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_UNSPECIFIED
		}, codes.InvalidArgument},
		{"missing retain until", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetainUntil = "" }, codes.InvalidArgument},
		{"non utc retain until", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetainUntil = "2026-06-19T12:00:00-04:00" }, codes.InvalidArgument},
		{"past retain until", func(r *openngfwv1.SetPacketCaptureRetentionRequest) {
			r.RetainUntil = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
		}, codes.InvalidArgument},
		{"empty reason", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetentionReason = "  " }, codes.InvalidArgument},
		{"oversized reason", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetentionReason = strings.Repeat("x", 257) }, codes.InvalidArgument},
		{"control reason", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetentionReason = "case\nbreak" }, codes.InvalidArgument},
		{"path reason", func(r *openngfwv1.SetPacketCaptureRetentionRequest) {
			r.RetentionReason = "/var/log/openngfw/pcap/file.pcap"
		}, codes.InvalidArgument},
		{"secret reason", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.RetentionReason = "Bearer abc123" }, codes.InvalidArgument},
		{"unsafe case id", func(r *openngfwv1.SetPacketCaptureRetentionRequest) { r.CaseId = "INC/42" }, codes.InvalidArgument},
		{"release with retain until", func(r *openngfwv1.SetPacketCaptureRetentionRequest) {
			r.State = openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED
		}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validRequest()
			tt.mutate(req)
			_, err := svc.SetPacketCaptureRetention(context.Background(), req)
			if got := status.Code(err); got != tt.want {
				t.Fatalf("code = %v, want %v (err=%v)", got, tt.want, err)
			}
		})
	}

	noAuditSvc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}
	_, err := noAuditSvc.SetPacketCaptureRetention(context.Background(), validRequest())
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("no audit store code = %v, want Internal (err=%v)", got, err)
	}
}

func TestSetPacketCaptureRetentionRejectsUnsafeSidecar(t *testing.T) {
	st := newSystemAuditStore(t)
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	captureID := "phragma-sidecar-20260618T121500Z"
	capturePath := filepath.Join(captureDir, captureID+".pcap")
	if err := os.WriteFile(capturePath, []byte("pcap-sidecar"), 0o640); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: logDir}}
	req := &openngfwv1.SetPacketCaptureRetentionRequest{
		Id:                 captureID,
		State:              openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
		RetainUntil:        time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		RetentionReason:    "validated incident evidence",
		AckRetentionChange: true,
	}
	if err := os.WriteFile(packetCaptureMetadataPath(capturePath), []byte("{bad-json"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := svc.SetPacketCaptureRetention(context.Background(), req)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("corrupted sidecar code = %v, want FailedPrecondition (err=%v)", got, err)
	}

	data, err := (protojson.MarshalOptions{EmitUnpopulated: false}).Marshal(&openngfwv1.PacketCaptureJob{
		Plan: &openngfwv1.PacketCapturePlan{OutputPath: filepath.Join(captureDir, "different-artifact.pcap")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packetCaptureMetadataPath(capturePath), data, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err = svc.SetPacketCaptureRetention(context.Background(), req)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("mismatched sidecar code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}

func TestDownloadPacketCaptureReturnsPcapBytesAndRejectsUnsafeID(t *testing.T) {
	logDir := t.TempDir()
	captureDir := filepath.Join(logDir, "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x01, 0x02}
	if err := os.WriteFile(filepath.Join(captureDir, "phragma-flow-20260618T121500Z.pcap"), body, 0o640); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Status: SystemStatusConfig{LogDir: logDir}}

	resp, err := svc.DownloadPacketCapture(context.Background(), &openngfwv1.DownloadPacketCaptureRequest{Id: "phragma-flow-20260618T121500Z"})
	if err != nil {
		t.Fatalf("DownloadPacketCapture returned error: %v", err)
	}
	if resp.GetContentType() != captureMediaType {
		t.Fatalf("content_type = %q, want %q", resp.GetContentType(), captureMediaType)
	}
	if string(resp.GetData()) != string(body) {
		t.Fatalf("data = %#v, want %#v", resp.GetData(), body)
	}

	_, err = svc.DownloadPacketCapture(context.Background(), &openngfwv1.DownloadPacketCaptureRequest{Id: "../secret"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("unsafe id code = %v, want InvalidArgument (err=%v)", got, err)
	}
	_, err = svc.DownloadPacketCapture(context.Background(), &openngfwv1.DownloadPacketCaptureRequest{Id: "missing"})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("missing id code = %v, want NotFound (err=%v)", got, err)
	}
}

func TestStartPacketCaptureFailsIfCompletionAuditFails(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	logDir := t.TempDir()
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			LogDir: logDir,
			CommandRun: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				for i, arg := range args {
					if arg == "-w" && i+1 < len(args) {
						if err := os.WriteFile(args[i+1], []byte("pcap-bytes"), 0o640); err != nil {
							return nil, err
						}
					}
				}
				return []byte("captured 1 packet\n"), nil
			},
		},
	}
	_, err = svc.StartPacketCapture(context.Background(), &openngfwv1.StartPacketCaptureRequest{
		Interface:       "ens5",
		Protocol:        openngfwv1.Protocol_PROTOCOL_TCP,
		SrcIp:           "10.0.1.20",
		SrcPort:         51515,
		DestIp:          "10.0.2.20",
		DestPort:        443,
		DurationSeconds: 2,
		PacketCount:     10,
		SnaplenBytes:    128,
		Label:           "audit-failure",
		AckCapture:      true,
	})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", got, err)
	}
	if !strings.Contains(err.Error(), "packet capture completed but audit write failed") {
		t.Fatalf("error = %v, want completed/audit failure detail", err)
	}
}

func TestTuneHostAuditsSuccessfulMutation(t *testing.T) {
	st := newSystemAuditStore(t)
	configPath := filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf")
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			SysctlConfigPath: configPath,
		},
	}

	resp, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{
		Profile:       "throughput",
		Write:         true,
		AckHostChange: true,
	})
	if err != nil {
		t.Fatalf("TuneHost write returned error: %v", err)
	}
	if !resp.GetWroteConfig() || resp.GetAppliedLive() {
		t.Fatalf("expected write-only response, got %#v", resp)
	}

	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Action != "system-tune" || entry.Actor != "local" || entry.ActorRole != "admin" || entry.AuthSource != authz.AuthSourceDisabledLocal {
		t.Fatalf("unexpected audit identity/action: %#v", entry)
	}
	for _, want := range []string{"profile=throughput", "write=true", "apply=false", "results=6", "applied=0", "skipped=0"} {
		if !strings.Contains(entry.Detail, want) {
			t.Fatalf("audit detail %q missing %q", entry.Detail, want)
		}
	}
}

func TestTuneHostAuditsApplyFailure(t *testing.T) {
	st := newSystemAuditStore(t)
	sysctlRoot := writeSysctlFixture(t, map[string]string{
		"net.ipv4.ip_forward":              "0",
		"net.ipv4.conf.all.rp_filter":      "1",
		"net.ipv4.conf.default.rp_filter":  "1",
		"net.netfilter.nf_conntrack_count": "1",
		"net.netfilter.nf_conntrack_max":   "262144",
		"net.core.somaxconn":               "128",
		"net.core.netdev_max_backlog":      "1024",
	})
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			SysctlRoot:       sysctlRoot,
			SysctlConfigPath: filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf"),
			CommandRun: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return nil, errors.New("sysctl denied")
			},
		},
	}

	_, err := svc.TuneHost(context.Background(), &openngfwv1.TuneHostRequest{
		Profile:       "throughput",
		Apply:         true,
		AckHostChange: true,
	})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}

	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Action != "system-tune-failed" || entry.Actor != "local" || entry.ActorRole != "admin" || entry.AuthSource != authz.AuthSourceDisabledLocal {
		t.Fatalf("unexpected audit identity/action: %#v", entry)
	}
	for _, want := range []string{"profile=throughput", "write=false", "apply=true", "stage=apply", "sysctl_denied"} {
		if !strings.Contains(entry.Detail, want) {
			t.Fatalf("audit detail %q missing %q", entry.Detail, want)
		}
	}
}

func TestSystemStatusWarnsForConntrackCapacityPressure(t *testing.T) {
	sysctlRoot := writeSysctlFixture(t, map[string]string{
		"net.ipv4.ip_forward":              "1",
		"net.ipv4.conf.all.rp_filter":      "0",
		"net.ipv4.conf.default.rp_filter":  "0",
		"net.netfilter.nf_conntrack_count": "950",
		"net.netfilter.nf_conntrack_max":   "1000",
		"net.core.somaxconn":               "4096",
	})
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		SysctlRoot:  sysctlRoot,
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Conntrack state-table capacity"); got != "degraded" {
		t.Fatalf("conntrack capacity capability = %q, want degraded", got)
	}
	conntrack := resp.GetDataplane().GetConntrack()
	if got := conntrack.GetState(); got != "degraded" {
		t.Fatalf("conntrack capacity state = %q, want degraded", got)
	}
	if got := conntrack.GetCurrentEntries(); got != 950 {
		t.Fatalf("conntrack entries = %d, want 950", got)
	}
	if got := conntrack.GetMaxEntries(); got != 1000 {
		t.Fatalf("conntrack max = %d, want 1000", got)
	}
	if got := conntrack.GetUsagePercent(); got != 95 {
		t.Fatalf("conntrack usage = %v, want 95", got)
	}
	if !hasWarning(resp.GetWarnings(), "critical", "Conntrack state table is near or over capacity.") {
		t.Fatalf("missing conntrack capacity warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsMissingEnginePrerequisites(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{
			{Name: "nftables", Role: "stateful firewall", Dependencies: []string{"nft"}},
			{Name: "wireguard", Role: "WireGuard VPN", Dependencies: []string{"ip", "wg"}},
		},
		CommandLookup: func(name string) (string, error) {
			if name == "ip" {
				return "/usr/sbin/ip", nil
			}
			return "", errors.New("not found")
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := resp.GetEngines()[0].GetState(); got != "missing-prerequisites" {
		t.Fatalf("nftables state = %q, want missing-prerequisites", got)
	}
	if got := resp.GetEngines()[1].GetState(); got != "missing-prerequisites" {
		t.Fatalf("wireguard state = %q, want missing-prerequisites", got)
	}

	var prereqState string
	for _, cap := range resp.GetCapabilities() {
		if cap.GetName() == "Engine prerequisites" {
			prereqState = cap.GetState()
		}
	}
	if prereqState != "degraded" {
		t.Fatalf("Engine prerequisites capability = %q, want degraded", prereqState)
	}
	if got := capabilityState(resp.GetCapabilities(), "Stateful firewall"); got != "degraded" {
		t.Fatalf("Stateful firewall capability = %q, want degraded", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "Live conntrack sessions"); got != "degraded" {
		t.Fatalf("Live conntrack sessions capability = %q, want degraded", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "nftables flowtable fast path"); got != "degraded" {
		t.Fatalf("flowtable capability = %q, want degraded", got)
	}

	seen := map[string]bool{}
	for _, w := range resp.GetWarnings() {
		seen[w.GetMessage()] = true
	}
	for _, want := range []string{
		"Engine prerequisites missing for nftables: nft.",
		"Engine prerequisites missing for wireguard: wg.",
	} {
		if !seen[want] {
			t.Fatalf("missing warning %q in %#v", want, resp.GetWarnings())
		}
	}
}

func TestSystemStatusReportsLiveEngineRuntime(t *testing.T) {
	started := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	lastExit := started.Add(30 * time.Second)
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   started,
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{{
			Name:         "suricata",
			Role:         "IDS/IPS matching engine",
			Dependencies: []string{"suricata"},
			Runtime: func() EngineRuntime {
				return EngineRuntime{
					State:       "running",
					PID:         1234,
					Restarts:    1,
					MaxRestarts: 3,
					StartedAt:   started.Add(time.Minute),
					LastExitAt:  lastExit,
					LastExitErr: "exit status 42",
					LastUptime:  10 * time.Second,
				}
			},
		}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	engine := engineByName(resp.GetEngines(), "suricata")
	if engine == nil {
		t.Fatal("missing suricata engine status")
	}
	if got := engine.GetState(); got != "active" {
		t.Fatalf("suricata state = %q, want active", got)
	}
	for _, want := range []string{"process running", "pid 1234", "auto-restarts 1/3", "last error: exit status 42"} {
		if !strings.Contains(engine.GetDetail(), want) {
			t.Fatalf("missing %q in detail %q", want, engine.GetDetail())
		}
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Engine suricata auto-restarted 1 time(s) since last apply.") {
		t.Fatalf("missing restart warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsFailedEngineRuntime(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{{
			Name:         "vector",
			Role:         "telemetry shipping",
			Dependencies: []string{"vector"},
			Runtime: func() EngineRuntime {
				return EngineRuntime{
					State:       "failed",
					Restarts:    3,
					MaxRestarts: 3,
					LastExitAt:  time.Date(2026, 6, 17, 11, 0, 0, 0, time.UTC),
					LastExitErr: "exit status 1",
					LastUptime:  2 * time.Minute,
				}
			},
		}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	engine := engineByName(resp.GetEngines(), "vector")
	if engine == nil {
		t.Fatal("missing vector engine status")
	}
	if got := engine.GetState(); got != "failed" {
		t.Fatalf("vector state = %q, want failed", got)
	}
	if !strings.Contains(engine.GetDetail(), "process is not running after an unexpected exit") {
		t.Fatalf("detail does not explain failed process: %q", engine.GetDetail())
	}
	if !hasWarning(resp.GetWarnings(), "critical", "Engine vector is not running after an unexpected exit.") {
		t.Fatalf("missing critical failed-engine warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsDegradedEngineDataplaneEvidence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &openngfwv1.Policy{
		Ids: &openngfwv1.Ids{
			Enabled:         true,
			Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
			FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
			Exceptions: []*openngfwv1.IdsException{{
				Name:        "fp-test",
				SignatureId: 9000001,
				ThreatId:    "TID-9000001",
			}},
		},
		Telemetry: &openngfwv1.Telemetry{Enabled: true},
		Proxy: &openngfwv1.Proxy{
			VirtualServices: []*openngfwv1.VirtualService{{Name: "admin", Enabled: true}},
		},
	}
	if _, err := st.CommitVersionWithIdentity(policy, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "engine evidence"); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{
			{
				Name:         "suricata",
				Role:         "IDS/IPS matching engine",
				Dependencies: []string{"suricata"},
				Runtime:      func() EngineRuntime { return EngineRuntime{State: "failed", LastExitErr: "exit status 1"} },
			},
			{
				Name:         "vector",
				Role:         "telemetry shipping",
				Dependencies: []string{"vector"},
				Runtime:      func() EngineRuntime { return EngineRuntime{State: "failed", LastExitErr: "exit status 2"} },
			},
		},
		CommandLookup: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "Degraded engine dataplane evidence"); got != "degraded" {
		t.Fatalf("Degraded engine dataplane evidence capability = %q, want degraded", got)
	}
	detail := capabilityDetail(resp.GetCapabilities(), "Degraded engine dataplane evidence")
	for _, want := range []string{"suricata=failed", "vector=failed", "proxy=not-reported", "failure=IDS_FAILURE_BEHAVIOR_FAIL_OPEN", "false_positive_exceptions=1", "no signed field-evidence custody", "no production certification claim"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("missing %q in degraded engine detail: %s", want, detail)
		}
	}
	if !hasWarning(resp.GetWarnings(), "warning", "Degraded engine dataplane evidence affects policy posture.") {
		t.Fatalf("missing degraded engine warning in %#v", resp.GetWarnings())
	}
}

func TestTelemetryExportStatusReportsRunningPolicySinks(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &openngfwv1.Policy{Telemetry: &openngfwv1.Telemetry{
		Enabled:       true,
		ClickhouseUrl: "https://clickhouse.example:8443?cluster=prod",
		Database:      "openngfw_prod",
		Exports: []*openngfwv1.TelemetryExport{
			{
				Name:    "siem-json",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
				Target:  "siem.example:5514",
			},
			{
				Name:    "soc-json",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP,
				Target:  "soc.example:5514",
			},
		},
	}}
	if _, err := st.CommitVersionWithIdentity(policy, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "telemetry export policy"); err != nil {
		t.Fatalf("commit telemetry policy: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		Engines: []SystemEngine{{
			Name: "vector",
			Role: "telemetry shipping",
			Runtime: func() EngineRuntime {
				return EngineRuntime{State: "running", PID: 4200}
			},
		}},
	}}

	resp, err := svc.GetTelemetryExportStatus(context.Background(), &openngfwv1.GetTelemetryExportStatusRequest{})
	if err != nil {
		t.Fatalf("GetTelemetryExportStatus returned error: %v", err)
	}
	if resp.GetSchemaVersion() != "phragma.telemetry.export.status.v1" {
		t.Fatalf("schema_version = %q", resp.GetSchemaVersion())
	}
	if got := resp.GetState(); got != "configured" {
		t.Fatalf("state = %q, want configured; detail=%q warnings=%#v", got, resp.GetDetail(), resp.GetWarnings())
	}
	if !resp.GetTelemetryEnabled() || resp.GetRunningPolicyVersion() != 1 {
		t.Fatalf("telemetry/version = %t/%d, want true/1", resp.GetTelemetryEnabled(), resp.GetRunningPolicyVersion())
	}
	if got := resp.GetVector().GetState(); got != "active" {
		t.Fatalf("vector state = %q, want active", got)
	}
	if got := resp.GetClickhouse().GetEndpoint(); got != "https://clickhouse.example:8443?cluster=prod" {
		t.Fatalf("clickhouse endpoint = %q", got)
	}
	if got := resp.GetClickhouse().GetDatabase(); got != "openngfw_prod" {
		t.Fatalf("clickhouse database = %q", got)
	}
	if len(resp.GetExports()) != 2 {
		t.Fatalf("exports = %d, want 2", len(resp.GetExports()))
	}
	if got := resp.GetExports()[0].GetEvidenceState(); got != "configured-unverified" {
		t.Fatalf("stream evidence state = %q, want configured-unverified", got)
	}
	if !hasWarning(resp.GetWarnings(), "info", "Telemetry export \"siem-json\" requires sink-side verification.") {
		t.Fatalf("missing sink-side verification warning in %#v", resp.GetWarnings())
	}
}

func TestTelemetryExportStatusReportsDisabledPolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st}

	resp, err := svc.GetTelemetryExportStatus(context.Background(), &openngfwv1.GetTelemetryExportStatusRequest{})
	if err != nil {
		t.Fatalf("GetTelemetryExportStatus returned error: %v", err)
	}
	if got := resp.GetState(); got != "disabled" {
		t.Fatalf("state = %q, want disabled", got)
	}
	if resp.GetTelemetryEnabled() {
		t.Fatal("telemetry_enabled = true, want false")
	}
	if got := resp.GetClickhouse().GetEvidenceState(); got != "disabled" {
		t.Fatalf("clickhouse evidence state = %q, want disabled", got)
	}
}

func TestTelemetryExportStatusDegradesStoppedVectorWhenTelemetryEnabled(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{Telemetry: &openngfwv1.Telemetry{Enabled: true}}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "telemetry enabled"); err != nil {
		t.Fatalf("commit telemetry policy: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		Engines: []SystemEngine{{
			Name: "vector",
			Role: "telemetry shipping",
			Runtime: func() EngineRuntime {
				return EngineRuntime{State: "stopped"}
			},
		}},
	}}

	resp, err := svc.GetTelemetryExportStatus(context.Background(), &openngfwv1.GetTelemetryExportStatusRequest{})
	if err != nil {
		t.Fatalf("GetTelemetryExportStatus returned error: %v", err)
	}
	if got := resp.GetState(); got != "degraded" {
		t.Fatalf("state = %q, want degraded", got)
	}
	if got := resp.GetVector().GetState(); got != "degraded" {
		t.Fatalf("vector state = %q, want degraded", got)
	}
	if !hasWarning(resp.GetWarnings(), "critical", "Vector telemetry engine is not ready for export delivery.") {
		t.Fatalf("missing Vector warning in %#v", resp.GetWarnings())
	}
}

func TestVerifyTelemetryExportAppendsConfiguredJSONFileProof(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "proof-%Y-%m-%d.json")
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &openngfwv1.Policy{Telemetry: &openngfwv1.Telemetry{
		Enabled: true,
		Exports: []*openngfwv1.TelemetryExport{{
			Name:    "local-json",
			Enabled: true,
			Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
			Target:  target,
		}},
	}}
	if _, err := st.CommitVersionWithIdentity(policy, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "telemetry export policy"); err != nil {
		t.Fatalf("commit telemetry policy: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{TelemetryExportRoot: root}}

	resp, err := svc.VerifyTelemetryExport(context.Background(), &openngfwv1.VerifyTelemetryExportRequest{
		ExportName:   "local-json",
		Reason:       "ticket=CHG-1 token=secret /home/opc/private",
		AckTestEvent: true,
	})
	if err != nil {
		t.Fatalf("VerifyTelemetryExport returned error: %v", err)
	}
	if got := resp.GetState(); got != "written" {
		t.Fatalf("state = %q, want written: %#v", got, resp)
	}
	checked := telemetryExpandFileTarget(target, time.Now().UTC())
	raw, err := os.ReadFile(checked)
	if err != nil {
		t.Fatalf("read proof file: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"event_type":"openngfw.telemetry.verify"`) || !strings.Contains(text, resp.GetProof().GetProofId()) {
		t.Fatalf("proof file missing event/proof id: %s", text)
	}
	if strings.Contains(text, "secret") || strings.Contains(text, "/home/opc/private") {
		t.Fatalf("proof event leaked secret/local path: %s", text)
	}
	if resp.GetProof().GetEventHash() == "" || resp.GetProof().GetBytes() == 0 {
		t.Fatalf("missing proof hash/bytes: %#v", resp.GetProof())
	}
}

func TestVerifyTelemetryExportSendsConfiguredTCPProof(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- err.Error()
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &openngfwv1.Policy{Telemetry: &openngfwv1.Telemetry{
		Enabled: true,
		Exports: []*openngfwv1.TelemetryExport{{
			Name:    "siem-json",
			Enabled: true,
			Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
			Target:  ln.Addr().String(),
		}},
	}}
	if _, err := st.CommitVersionWithIdentity(policy, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "telemetry export policy"); err != nil {
		t.Fatalf("commit telemetry policy: %v", err)
	}
	svc := &SystemService{Store: st}

	resp, err := svc.VerifyTelemetryExport(context.Background(), &openngfwv1.VerifyTelemetryExportRequest{
		Type:         openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
		Target:       ln.Addr().String(),
		Reason:       "receiver smoke",
		AckTestEvent: true,
	})
	if err != nil {
		t.Fatalf("VerifyTelemetryExport returned error: %v", err)
	}
	if got := resp.GetState(); got != "delivered" {
		t.Fatalf("state = %q, want delivered: %#v", got, resp)
	}
	select {
	case text := <-received:
		if !strings.Contains(text, resp.GetProof().GetProofId()) || !strings.Contains(text, "openngfw.telemetry.verify") {
			t.Fatalf("listener received wrong event: %s", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not receive proof event")
	}
}

func TestVerifyTelemetryExportRejectsMissingAckAndUnknownExport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{Telemetry: &openngfwv1.Telemetry{Enabled: true}}, store.ActorIdentity{Name: "admin", Role: "admin", AuthSource: "test"}, "telemetry enabled"); err != nil {
		t.Fatalf("commit telemetry policy: %v", err)
	}
	svc := &SystemService{Store: st}
	if _, err := svc.VerifyTelemetryExport(context.Background(), &openngfwv1.VerifyTelemetryExportRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing ack error = %v, want FailedPrecondition", err)
	}
	_, err = svc.VerifyTelemetryExport(context.Background(), &openngfwv1.VerifyTelemetryExportRequest{ExportName: "missing", AckTestEvent: true})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown export error = %v, want NotFound", err)
	}
}

func TestTelemetryLocalFileEvidenceExpandsDatePatternUnderConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "eve-%Y-%m-%d.json")
	checked := telemetryExpandFileTarget(target, time.Now().UTC())
	writeSystemFile(t, checked, []byte(`{"event_type":"alert"}`+"\n"))

	evidence := telemetryLocalFileEvidence(SystemStatusConfig{TelemetryExportRoot: root}, target)
	if !evidence.GetPresent() {
		t.Fatalf("evidence present = false, want true: %#v", evidence)
	}
	if evidence.GetPath() != checked {
		t.Fatalf("evidence path = %q, want %q", evidence.GetPath(), checked)
	}
	if evidence.GetSizeBytes() == 0 || evidence.GetModifiedAt() == "" || evidence.GetError() != "" {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestTelemetryLocalFileEvidenceRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "eve.json")
	writeSystemFile(t, outside, []byte(`{"event_type":"alert"}`+"\n"))
	target := filepath.Join(root, "eve.json")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	evidence := telemetryLocalFileEvidence(SystemStatusConfig{TelemetryExportRoot: root}, target)
	if evidence.GetError() == "" || !strings.Contains(evidence.GetError(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection, got %#v", evidence)
	}
	if evidence.GetPresent() {
		t.Fatalf("symlink evidence present = true, want false: %#v", evidence)
	}
}

func TestSystemStatusTreatsStoppedSupervisedEngineAsReady(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{{
			Name:         "suricata",
			Role:         "IDS/IPS matching engine",
			Dependencies: []string{"suricata"},
			Runtime:      func() EngineRuntime { return EngineRuntime{State: "stopped"} },
		}},
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	engine := engineByName(resp.GetEngines(), "suricata")
	if engine == nil {
		t.Fatal("missing suricata engine status")
	}
	if got := engine.GetState(); got != "ready" {
		t.Fatalf("suricata state = %q, want ready", got)
	}
	if !strings.Contains(engine.GetDetail(), "starts when policy enables this engine") {
		t.Fatalf("detail does not explain stopped process: %q", engine.GetDetail())
	}
	if hasWarning(resp.GetWarnings(), "warning", "Engine suricata") || hasWarning(resp.GetWarnings(), "critical", "Engine suricata") {
		t.Fatalf("stopped engine should not produce warning: %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsInspectionFailOpenBypass(t *testing.T) {
	st := newSystemAuditStore(t)
	commitInspectionPolicy(t, st, &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
	})
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			StartedAt:   time.Now().UTC(),
			AuthEnabled: true,
			TLSEnabled:  true,
			Engines: []SystemEngine{{
				Name:         "suricata",
				Role:         "IDS/IPS matching engine",
				Dependencies: []string{"suricata"},
				Runtime:      func() EngineRuntime { return EngineRuntime{State: "failed", LastExitErr: "exit status 1"} },
			}},
			CommandLookup: func(name string) (string, error) {
				return "/usr/sbin/" + name, nil
			},
		},
	}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	inspection := resp.GetInspection()
	if got := inspection.GetState(); got != "failed-open" {
		t.Fatalf("inspection state = %q, want failed-open: %#v", got, inspection)
	}
	if !inspection.GetBypassPossible() || !strings.Contains(inspection.GetBypassReason(), "fail-open") {
		t.Fatalf("inspection bypass not visible: %#v", inspection)
	}
	if got := capabilityState(resp.GetCapabilities(), "Inspection policy readiness"); got != "degraded" {
		t.Fatalf("inspection capability = %q, want degraded", got)
	}
	if !hasWarning(resp.GetWarnings(), "critical", "IPS prevent is degraded fail-open") {
		t.Fatalf("missing fail-open warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsInspectionFailClosedImpact(t *testing.T) {
	st := newSystemAuditStore(t)
	commitInspectionPolicy(t, st, &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	})
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			StartedAt:   time.Now().UTC(),
			AuthEnabled: true,
			TLSEnabled:  true,
			Engines: []SystemEngine{{
				Name:         "suricata",
				Role:         "IDS/IPS matching engine",
				Dependencies: []string{"suricata"},
				Runtime:      func() EngineRuntime { return EngineRuntime{State: "stopped"} },
			}},
			CommandLookup: func(name string) (string, error) {
				return "/usr/sbin/" + name, nil
			},
		},
	}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	inspection := resp.GetInspection()
	if got := inspection.GetState(); got != "failed-closed" {
		t.Fatalf("inspection state = %q, want failed-closed: %#v", got, inspection)
	}
	if inspection.GetBypassPossible() || !strings.Contains(inspection.GetDegradedBehavior(), "fail-closed") {
		t.Fatalf("inspection fail-closed behavior not visible: %#v", inspection)
	}
	if got := inspection.GetEngineState(); got != "ready" {
		t.Fatalf("engine state = %q, want prerequisite-ready/stopped", got)
	}
	if !hasWarning(resp.GetWarnings(), "critical", "IPS prevent is degraded fail-closed") {
		t.Fatalf("missing fail-closed warning in %#v", resp.GetWarnings())
	}
}

func TestSystemStatusReportsFlowtableSimulationInDryRunWithoutNft(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		DryRun:      true,
		AuthEnabled: true,
		TLSEnabled:  true,
		CommandLookup: func(_ string) (string, error) {
			return "", errors.New("not found")
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "nftables flowtable fast path"); got != "simulation" {
		t.Fatalf("flowtable capability = %q, want simulation", got)
	}
}

func TestSystemStatusReportsActiveFlowtableRuntimeEvidence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CommitVersion(&openngfwv1.Policy{}, "tester", "baseline"); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "nft" || strings.Join(args, " ") != "list table inet openngfw" {
				t.Fatalf("unexpected command %s %v", name, args)
			}
			return []byte(`table inet openngfw {
	flowtable fastpath {
		hook ingress priority filter
		devices = { "eth0", "eth1" }
	}
	chain forward {
		ct state established,related counter packets 10 bytes 1000 flow add @fastpath accept comment "flow-offload"
		iifname "eth1" oifname "eth0" ip saddr 10.10.0.0/24 counter packets 3 bytes 300 accept comment "rule:lan-to-wan"
		iifname "eth1" oifname "eth0" ip6 saddr 2001:db8:10::/64 counter packets 5 bytes 500 accept comment "rule:lan-to-wan"
		ip daddr @intel4 counter packets 2 bytes 120 drop comment "intel-block-dst"
		counter packets 1 bytes 60 comment "default-drop"
	}
}`), nil
		},
	}, Store: st}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := resp.GetDataplane().GetRunningPolicyVersion(); got != 1 {
		t.Fatalf("dataplane running policy version = %d, want 1", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "nftables flowtable runtime"); got != "active" {
		t.Fatalf("runtime flowtable capability = %q, want active", got)
	}
	if detail := capabilityDetail(resp.GetCapabilities(), "nftables flowtable runtime"); !strings.Contains(detail, "runtime ruleset contains flowtable fastpath") {
		t.Fatalf("runtime detail did not include evidence: %q", detail)
	}
	flowtable := resp.GetDataplane().GetFlowtable()
	if got := flowtable.GetRuntimeState(); got != "active" {
		t.Fatalf("structured runtime state = %q, want active", got)
	}
	if got := strings.Join(flowtable.GetDevices(), ","); got != "eth0,eth1" {
		t.Fatalf("structured devices = %q, want eth0,eth1", got)
	}
	if !flowtable.GetFlowtableDeclared() || !flowtable.GetOffloadRulePresent() {
		t.Fatalf("structured proof flags = declared:%t offload:%t, want both true", flowtable.GetFlowtableDeclared(), flowtable.GetOffloadRulePresent())
	}
	if flowtable.GetPackets() != 10 || flowtable.GetBytes() != 1000 {
		t.Fatalf("structured counters = %d packets / %d bytes, want 10 / 1000", flowtable.GetPackets(), flowtable.GetBytes())
	}
	ruleCounter := counterByComment(resp.GetDataplane().GetCounters(), "rule:lan-to-wan")
	if ruleCounter == nil {
		t.Fatalf("missing aggregated rule counter in %#v", resp.GetDataplane().GetCounters())
	}
	if ruleCounter.GetKind() != "rule" || ruleCounter.GetName() != "lan-to-wan" {
		t.Fatalf("rule counter identity = %s/%s, want rule/lan-to-wan", ruleCounter.GetKind(), ruleCounter.GetName())
	}
	if ruleCounter.GetPackets() != 8 || ruleCounter.GetBytes() != 800 {
		t.Fatalf("rule counter aggregate = %d packets / %d bytes, want 8 / 800", ruleCounter.GetPackets(), ruleCounter.GetBytes())
	}
	if got := counterByComment(resp.GetDataplane().GetCounters(), "intel-block-dst"); got == nil || got.GetKind() != "intel" {
		t.Fatalf("missing classified intel counter: %#v", resp.GetDataplane().GetCounters())
	}
}

func TestSystemStatusReportsInactiveFlowtableRuntimeWhenTableMissing(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("Error: No such file or directory"), errors.New("exit status 1")
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if got := capabilityState(resp.GetCapabilities(), "nftables flowtable runtime"); got != "inactive" {
		t.Fatalf("runtime flowtable capability = %q, want inactive", got)
	}
	if got := resp.GetDataplane().GetFlowtable().GetRuntimeState(); got != "inactive" {
		t.Fatalf("structured runtime state = %q, want inactive", got)
	}
	if resp.GetDataplane().GetFlowtable().GetFlowtableDeclared() || resp.GetDataplane().GetFlowtable().GetOffloadRulePresent() {
		t.Fatalf("inactive runtime should not report proof flags: %#v", resp.GetDataplane().GetFlowtable())
	}
}

func TestSystemStatusReportsWireGuardRuntimeEvidence(t *testing.T) {
	handshake := uint64(time.Now().Add(-90 * time.Second).Unix())
	svc := &SystemService{Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{
			{Name: "wireguard", Role: "WireGuard VPN", Dependencies: []string{"ip", "wg"}},
		},
		CommandLookup: func(name string) (string, error) {
			if name == "wg" {
				return "/usr/bin/wg", nil
			}
			return "", errors.New("not found")
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "wg" {
				t.Fatalf("unexpected command %s %v", name, args)
			}
			switch strings.Join(args, " ") {
			case "show interfaces":
				return []byte("wg0\n"), nil
			case "show wg0 peers":
				return []byte("peer-a=\npeer-b=\n"), nil
			case "show wg0 latest-handshakes":
				return []byte("peer-a= " + strconv.FormatUint(handshake, 10) + "\npeer-b= 0\n"), nil
			case "show wg0 transfer":
				return []byte("peer-a= 100 200\npeer-b= 0 0\n"), nil
			case "show wg0 endpoints":
				return []byte("peer-a= 203.0.113.10:51820\npeer-b= (none)\n"), nil
			default:
				t.Fatalf("unexpected wg args %v", args)
			}
			return nil, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	wg := resp.GetVpn().GetWireguard()
	if got := wg.GetState(); got != "active" {
		t.Fatalf("wireguard runtime state = %q, want active", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "WireGuard runtime evidence"); got != "active" {
		t.Fatalf("wireguard runtime capability = %q, want active", got)
	}
	if len(wg.GetInterfaces()) != 1 {
		t.Fatalf("wireguard interfaces = %#v, want one", wg.GetInterfaces())
	}
	iface := wg.GetInterfaces()[0]
	if iface.GetName() != "wg0" || iface.GetPeerCount() != 2 || iface.GetActivePeerCount() != 1 {
		t.Fatalf("wireguard interface = %#v, want wg0 with 1/2 active peers", iface)
	}
	peer := iface.GetPeers()[0]
	if peer.GetPublicKey() != "peer-a=" || peer.GetEndpoint() != "203.0.113.10:51820" {
		t.Fatalf("wireguard peer identity = %#v", peer)
	}
	if peer.GetLatestHandshakeUnixSeconds() != handshake || peer.GetRxBytes() != 100 || peer.GetTxBytes() != 200 {
		t.Fatalf("wireguard peer counters = %#v", peer)
	}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	if strings.Contains(string(raw), "private") || strings.Contains(string(raw), "preshared") {
		t.Fatalf("wireguard runtime response leaked key material fields: %s", raw)
	}
}

func TestSystemStatusReportsFrrRoutingRuntimeEvidence(t *testing.T) {
	st := newSystemAuditStore(t)
	if _, err := st.CommitVersion(&openngfwv1.Policy{
		Routing: &openngfwv1.Routing{
			Bgp: &openngfwv1.Bgp{
				Enabled:  true,
				Asn:      65001,
				RouterId: "192.0.2.1",
				Neighbors: []*openngfwv1.BgpNeighbor{{
					Address:   "198.51.100.2",
					RemoteAsn: 65002,
				}},
			},
			Ospf: &openngfwv1.Ospf{
				Enabled:  true,
				RouterId: "192.0.2.1",
				Areas: []*openngfwv1.OspfArea{{
					Area:     "0.0.0.0",
					Networks: []string{"10.10.0.0/24"},
				}},
			},
		},
	}, "tester", "routing policy"); err != nil {
		t.Fatalf("commit routing policy: %v", err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{
		StartedAt:   time.Now().UTC(),
		AuthEnabled: true,
		TLSEnabled:  true,
		Engines: []SystemEngine{
			{Name: "frr", Role: "dynamic routing", Dependencies: []string{"vtysh"}},
		},
		CommandLookup: func(name string) (string, error) {
			if name == "vtysh" {
				return "/usr/bin/vtysh", nil
			}
			return "", errors.New("not found")
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "vtysh" {
				t.Fatalf("unexpected command %s %v", name, args)
			}
			switch strings.Join(args, " ") {
			case "-c show bgp ipv4 unicast summary json":
				return []byte(`{
					"ipv4Unicast": {
						"peers": {
							"198.51.100.2": {
								"remoteAs": 65002,
								"state": "Established",
								"peerUptime": "00:14:02",
								"pfxRcd": 12,
								"description": "upstream"
							}
						}
					}
				}`), nil
			case "-c show ip ospf neighbor json":
				return []byte(`{
					"neighbors": {
						"10.0.0.2": [{
							"nbrState": "Full/DROther",
							"address": "10.0.0.2",
							"ifaceName": "eth1",
							"deadTime": "00:00:33"
						}]
					}
				}`), nil
			default:
				t.Fatalf("unexpected vtysh args %v", args)
			}
			return nil, nil
		},
	}}

	resp, err := svc.GetStatus(context.Background(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	frr := resp.GetRouting().GetFrr()
	if got := frr.GetState(); got != "active" {
		t.Fatalf("FRR runtime state = %q, want active", got)
	}
	if got := capabilityState(resp.GetCapabilities(), "FRR routing runtime evidence"); got != "active" {
		t.Fatalf("FRR runtime capability = %q, want active", got)
	}
	if len(frr.GetBgpNeighbors()) != 1 {
		t.Fatalf("BGP neighbors = %#v, want one", frr.GetBgpNeighbors())
	}
	bgp := frr.GetBgpNeighbors()[0]
	if bgp.GetPeer() != "198.51.100.2" || bgp.GetRemoteAsn() != 65002 || bgp.GetState() != "Established" || bgp.GetPrefixesReceived() != 12 {
		t.Fatalf("BGP neighbor evidence = %#v", bgp)
	}
	if len(frr.GetOspfNeighbors()) != 1 {
		t.Fatalf("OSPF neighbors = %#v, want one", frr.GetOspfNeighbors())
	}
	ospf := frr.GetOspfNeighbors()[0]
	if ospf.GetNeighborId() != "10.0.0.2" || ospf.GetInterface() != "eth1" || ospf.GetState() != "Full/DROther" {
		t.Fatalf("OSPF neighbor evidence = %#v", ospf)
	}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	for _, forbidden := range []string{"router bgp", "router ospf", "password", "secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("routing runtime response leaked raw config material %q: %s", forbidden, raw)
		}
	}
}

func TestRuntimeReadinessWarningsArePolicyAwareForFlowtable(t *testing.T) {
	standard := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}}}
	flowtable := &openngfwv1.Policy{
		Zones:   []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Network: &openngfwv1.Network{EnableFlowOffload: true},
	}
	status := &openngfwv1.GetStatusResponse{
		Dataplane: &openngfwv1.DataplaneStatus{
			Flowtable: &openngfwv1.FlowtableStatus{
				HostState:     "ready",
				HostDetail:    "host can apply flowtables",
				RuntimeState:  "inactive",
				RuntimeDetail: "runtime ruleset has no flowtable fast path",
			},
		},
	}

	newFlowtableWarnings := runtimeReadinessWarnings(status, flowtable, standard)
	if containsSubstring(newFlowtableWarnings, "nftables flowtable runtime is inactive") {
		t.Fatalf("new flowtable candidate should not require pre-commit runtime evidence: %#v", newFlowtableWarnings)
	}

	runningFlowtableWarnings := runtimeReadinessWarnings(status, flowtable, flowtable)
	if !containsSubstring(runningFlowtableWarnings, "nftables flowtable runtime is inactive") {
		t.Fatalf("running flowtable policy should require runtime evidence acknowledgement: %#v", runningFlowtableWarnings)
	}

	status.GetDataplane().Flowtable.HostState = "simulation"
	status.GetDataplane().Flowtable.HostDetail = "nft command is missing"
	hostWarnings := runtimeReadinessWarnings(status, flowtable, standard)
	if !containsSubstring(hostWarnings, "nftables flowtable fast path is simulation") {
		t.Fatalf("flowtable target should require host readiness acknowledgement: %#v", hostWarnings)
	}
}

func TestRuntimeReadinessWarningsArePolicyAwareForIDSContent(t *testing.T) {
	standard := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}}}
	idsEnabled := &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Ids:   &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT},
	}
	svc := &SystemService{
		Status: SystemStatusConfig{
			ContentDir:  t.TempDir(),
			AuthEnabled: true,
		},
	}

	standardWarnings, err := svc.RuntimeReadinessWarnings(context.Background(), standard, standard)
	if err != nil {
		t.Fatalf("RuntimeReadinessWarnings standard: %v", err)
	}
	if containsSubstring(standardWarnings, "IDS/IPS is enabled but Threat-ID content readiness") {
		t.Fatalf("IDS content warning should not apply when target policy disables IDS: %#v", standardWarnings)
	}

	idsWarnings, err := svc.RuntimeReadinessWarnings(context.Background(), idsEnabled, standard)
	if err != nil {
		t.Fatalf("RuntimeReadinessWarnings ids: %v", err)
	}
	if !containsSubstring(idsWarnings, "IDS/IPS is enabled but Threat-ID content is not production-ready") {
		t.Fatalf("IDS target should require content readiness acknowledgement: %#v", idsWarnings)
	}
	if !containsSubstring(idsWarnings, "evidence_status=missing") {
		t.Fatalf("IDS content warning should include readiness detail: %#v", idsWarnings)
	}
}

func TestSystemRuntimeReadinessPreflight(t *testing.T) {
	svc := &SystemService{Status: SystemStatusConfig{DryRun: true, AuthEnabled: true}}
	resp, err := svc.CheckRuntimeReadiness(context.Background(), &openngfwv1.CheckRuntimeReadinessRequest{
		Operation:     "rollback",
		TargetPolicy:  &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "known-good"}}},
		RunningPolicy: &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "current"}}},
	})
	if err != nil {
		t.Fatalf("CheckRuntimeReadiness: %v", err)
	}
	if resp.GetSchemaVersion() != "phragma.runtime-readiness.v1" {
		t.Fatalf("schema = %q", resp.GetSchemaVersion())
	}
	if resp.GetOperation() != "rollback" {
		t.Fatalf("operation = %q, want rollback", resp.GetOperation())
	}
	if !resp.GetRequiresAck() || resp.GetLabel() != "not ready" || resp.GetCls() != "bad" {
		t.Fatalf("preflight readiness = label:%q cls:%q ack:%v", resp.GetLabel(), resp.GetCls(), resp.GetRequiresAck())
	}
	if !containsSubstring(resp.GetWarnings(), "dry-run mode") {
		t.Fatalf("warnings missing dry-run item: %#v", resp.GetWarnings())
	}
	if len(resp.GetItems()) == 0 {
		t.Fatal("expected runtime readiness action items")
	}
	var dryRunItem *openngfwv1.RuntimeReadinessItem
	for _, item := range resp.GetItems() {
		if strings.Contains(item.GetTitle(), "dry-run mode") {
			dryRunItem = item
			break
		}
	}
	if dryRunItem == nil {
		t.Fatalf("items missing dry-run action: %#v", resp.GetItems())
	}
	if dryRunItem.GetId() == "" || dryRunItem.GetLevel() != "high" || dryRunItem.GetCommand() != "ngfwctl status" {
		t.Fatalf("dry-run item = %#v", dryRunItem)
	}

	ready := runtimeReadinessPreflight("commit", nil)
	if ready.GetRequiresAck() || ready.GetLabel() != "ready" || ready.GetCls() != "ok" || len(ready.GetItems()) != 0 {
		t.Fatalf("ready preflight = %#v", ready)
	}
	if !strings.Contains(ready.GetDetail(), "commit") {
		t.Fatalf("ready detail = %q", ready.GetDetail())
	}

	unavailable := runtimeReadinessUnavailablePreflight("rollback", errors.New("status endpoint unavailable"))
	if !unavailable.GetRequiresAck() || unavailable.GetLabel() != "unknown" || unavailable.GetCls() != "warn" {
		t.Fatalf("unavailable preflight = %#v", unavailable)
	}
	if unavailable.GetItems()[0].GetId() != "runtime-status-unavailable" {
		t.Fatalf("unavailable item = %#v", unavailable.GetItems())
	}
	if !strings.Contains(unavailable.GetDetail(), "rollback") {
		t.Fatalf("unavailable detail = %q", unavailable.GetDetail())
	}
}

func engineByName(engines []*openngfwv1.EngineStatus, name string) *openngfwv1.EngineStatus {
	for _, engine := range engines {
		if engine.GetName() == name {
			return engine
		}
	}
	return nil
}

func counterByComment(counters []*openngfwv1.DataplaneCounter, comment string) *openngfwv1.DataplaneCounter {
	for _, counter := range counters {
		if counter.GetComment() == comment {
			return counter
		}
	}
	return nil
}

func hasWarning(warnings []*openngfwv1.StatusWarning, severity, messagePrefix string) bool {
	for _, warning := range warnings {
		if warning.GetSeverity() == severity && strings.HasPrefix(warning.GetMessage(), messagePrefix) {
			return true
		}
	}
	return false
}

func capabilityState(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetState()
		}
	}
	return ""
}

func capabilityDetail(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetDetail()
		}
	}
	return ""
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsSubstring(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}

func newSystemAuditStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

//nolint:unparam // Returning the actor keeps the helper useful for successful-auth assertions.
func systemAuthCall(t *testing.T, a *authz.Authenticator, token, method string) (string, error) {
	t.Helper()
	ctx := context.Background()
	if token != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	}
	var actorSeen string
	_, err := a.UnaryInterceptor()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, _ any) (any, error) {
			actorSeen = authz.Actor(ctx)
			return nil, nil
		})
	return actorSeen, err
}

type systemContentPublisher struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSystemContentPublisher(t *testing.T) systemContentPublisher {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return systemContentPublisher{
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

func (p systemContentPublisher) trust(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".trust", "ed25519")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir trusted keyring: %v", err)
	}
	writeSystemFile(t, filepath.Join(dir, "system-test.pub"), []byte(base64.StdEncoding.EncodeToString(p.pub)))
}

func (p systemContentPublisher) writePackage(t *testing.T, dir, kind, version, fileName string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	writeSystemFile(t, filepath.Join(dir, fileName), content)
	sum := sha256.Sum256(content)
	manifest := contentpkg.Manifest{
		SchemaVersion: contentpkg.SchemaVersion,
		Kind:          kind,
		Name:          "Phragma " + kind + " test package",
		Version:       version,
		Source:        "system test",
		CreatedAt:     "2026-06-17T12:00:00Z",
		InstalledAt:   "2026-06-17T12:05:00Z",
		Files: []contentpkg.File{{
			Path:   fileName,
			SHA256: hex.EncodeToString(sum[:]),
		}},
		Regression: &contentpkg.Regression{Status: "passed", Corpus: "system", Passed: 1, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &contentpkg.Rollout{State: "stable", Scope: "all"},
		Rollback:   &contentpkg.Rollback{Available: true},
		Provenance: []contentpkg.Provenance{{
			Name:                 "Phragma system test",
			URL:                  "https://example.invalid/phragma/system-test",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtr(true),
			AllowsRedistribution: boolPtr(true),
		}},
	}
	payload, err := contentpkg.SignaturePayloadForTest(manifest)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	manifest.Signature = &contentpkg.Signature{
		Algorithm: "ed25519",
		KeyID:     "system-test",
		PublicKey: base64.StdEncoding.EncodeToString(p.pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(p.priv, payload)),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	writeSystemFile(t, filepath.Join(dir, "manifest.json"), raw)
}

func writeSystemFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func commitInspectionPolicy(t *testing.T, st *store.Store, ids *openngfwv1.Ids) {
	t.Helper()
	if _, err := st.CommitVersionWithIdentity(&openngfwv1.Policy{Ids: ids}, store.ActorIdentity{Name: "test", Role: "admin", AuthSource: "test"}, "inspection test policy"); err != nil {
		t.Fatalf("commit inspection policy: %v", err)
	}
}

func hasTuneResult(items []*openngfwv1.TuneHostResult, key, state string) bool {
	for _, item := range items {
		if item.GetKey() == key && item.GetState() == state {
			return true
		}
	}
	return false
}

func testVersionArtifactSetHash(name string, content []byte) string {
	sum := sha256.Sum256(content)
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(hex.EncodeToString(sum[:])))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.FormatUint(uint64(len(content)), 10)))
	_, _ = h.Write([]byte{0})
	return hex.EncodeToString(h.Sum(nil))
}

type procFixture struct {
	loadavg string
	meminfo string
	netDev  string
}

func writeProcFixture(t *testing.T, fixture procFixture) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"loadavg": fixture.loadavg,
		"meminfo": fixture.meminfo,
		"net/dev": fixture.netDev,
	}
	for rel, value := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeSysctlFixture(t *testing.T, values map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for key, value := range values {
		path := filepath.Join(root, strings.ReplaceAll(key, ".", string(os.PathSeparator)))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeSysfsFixture(t *testing.T, paths []string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range paths {
		path := filepath.Join(root, rel)
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

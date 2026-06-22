package netdev

import (
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderEmpty(t *testing.T) {
	got, err := Render(&compiler.IR{})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(got), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("empty IR must render no directives, got %q", line)
		}
	}
}

func TestRender(t *testing.T) {
	ir := &compiler.IR{Network: &compiler.NetworkIR{
		Links: []compiler.LinkIR{
			{Interface: "eth0", MTU: 1500},
			{Interface: "eth1", MTU: 9000},
		},
		OffloadOffIfaces: []string{"eth1"},
		MaxMTU:           9000,
	}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"link eth0 mtu 1500",
		"link eth1 mtu 9000",
		"offload eth1 off",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("artifact missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderTrafficControlPlanOnlyPosture(t *testing.T) {
	ir := &compiler.IR{
		QoSControls: []compiler.QoSControlIR{{
			RuleName:                "allow-voice",
			ProfileName:             "voice-priority",
			MaxBandwidthKbps:        50_000,
			GuaranteedBandwidthKbps: 10_000,
			Priority:                "high",
			DSCPMark:                46,
			BurstKBytes:             1024,
		}},
		ZoneProtections: []compiler.ZoneProtectionIR{{
			ZoneName:                 "wan",
			Interfaces:               []string{"eth0"},
			ProfileName:              "internet-edge",
			Enabled:                  true,
			SynFloodPPS:              20_000,
			UDPFloodPPS:              50_000,
			ICMPFloodPPS:             10_000,
			MaxConcurrentConnections: 1_000_000,
			Action:                   "alert",
			AuditLog:                 true,
		}},
	}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"qos-plan rule allow-voice profile voice-priority state planned runtime unsupported max-kbps 50000 guaranteed-kbps 10000 priority high dscp 46 burst-kbytes 1024",
		"zone-protection-plan zone wan profile internet-edge state planned runtime unsupported enabled true action alert audit-log true interfaces eth0 syn-pps 20000 udp-pps 50000 icmp-pps 10000 max-connections 1000000",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("artifact missing %q:\n%s", want, cfg)
		}
	}
}

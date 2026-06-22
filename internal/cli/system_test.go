package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	httpbody "google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/tuning"
)

func TestSystemTunePreviewMakesNoChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "99-openngfw.conf")
	opts := systemTuneOptions{configPath: path, sysctlRoot: t.TempDir()}
	out, err := runSystemTuneForTest(opts)
	if err != nil {
		t.Fatalf("runSystemTune returned error: %v", err)
	}
	for _, want := range []string{
		"OpenNGFW appliance sysctl baseline:",
		"profile: appliance",
		"net.ipv4.ip_forward = 1",
		"No changes made.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config file should not exist, stat err=%v", err)
	}
}

func TestSystemTuneWritesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf")
	opts := systemTuneOptions{configPath: path, sysctlRoot: t.TempDir(), write: true}
	out, err := runSystemTuneForTest(opts)
	if err != nil {
		t.Fatalf("runSystemTune returned error: %v", err)
	}
	if !strings.Contains(out, "wrote "+path) || !strings.Contains(out, "Verify with: ngfwctl status") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(raw) != tuning.ConfigText() {
		t.Fatalf("config mismatch:\n%s", raw)
	}
}

func TestSystemTuneAppliesExposedKeys(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"net.ipv4.ip_forward", "net.core.somaxconn"} {
		path := filepath.Join(root, strings.ReplaceAll(key, ".", string(os.PathSeparator)))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir fixture: %v", err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	var calls []string
	opts := systemTuneOptions{
		configPath: filepath.Join(t.TempDir(), "99-openngfw.conf"),
		sysctlRoot: root,
		apply:      true,
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...)...)
			return []byte("ok\n"), nil
		},
	}
	out, err := runSystemTuneForTest(opts)
	if err != nil {
		t.Fatalf("runSystemTune returned error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{
		"sysctl", "-w", "net.ipv4.ip_forward=1",
		"sysctl", "-w", "net.core.somaxconn=4096",
	}) {
		t.Fatalf("calls = %#v", calls)
	}
	for _, want := range []string{
		"applied net.ipv4.ip_forward=1",
		"skipped net.ipv4.conf.all.rp_filter",
		"applied net.core.somaxconn=4096",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemTuneThroughputProfileAppliesLargerHeadroom(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{
		"net.netfilter.nf_conntrack_max",
		"net.core.somaxconn",
		"net.core.netdev_max_backlog",
	} {
		path := filepath.Join(root, strings.ReplaceAll(key, ".", string(os.PathSeparator)))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir fixture: %v", err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	var calls []string
	opts := systemTuneOptions{
		configPath: filepath.Join(t.TempDir(), "99-openngfw.conf"),
		profile:    tuning.ThroughputProfile,
		sysctlRoot: root,
		apply:      true,
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...)...)
			return []byte("ok\n"), nil
		},
	}
	out, err := runSystemTuneForTest(opts)
	if err != nil {
		t.Fatalf("runSystemTune returned error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{
		"sysctl", "-w", "net.netfilter.nf_conntrack_max=4194304",
		"sysctl", "-w", "net.core.somaxconn=8192",
		"sysctl", "-w", "net.core.netdev_max_backlog=250000",
	}) {
		t.Fatalf("calls = %#v", calls)
	}
	for _, want := range []string{
		"profile: throughput",
		"net.netfilter.nf_conntrack_max = 4194304",
		"applied net.core.netdev_max_backlog=250000",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemCapturePlansThroughAPI(t *testing.T) {
	client := &fakeSystemCaptureClient{
		planResp: &openngfwv1.PlanPacketCaptureResponse{
			Plan: &openngfwv1.PacketCapturePlan{
				Interface:       "ens5",
				Protocol:        openngfwv1.Protocol_PROTOCOL_TCP,
				SrcIp:           "10.0.1.20",
				SrcPort:         51515,
				DestIp:          "10.0.2.20",
				DestPort:        443,
				DurationSeconds: 5,
				PacketCount:     10,
				SnaplenBytes:    128,
				FlowId:          "eve-web-1",
				OutputPath:      "/var/log/openngfw/pcap/phragma-web.pcap",
				BpfFilter:       "tcp and host 10.0.1.20",
				Command:         "sudo timeout 5s tcpdump -i ens5 -w /var/log/openngfw/pcap/phragma-web.pcap",
			},
		},
	}
	out, err := runSystemCaptureForTest(client, systemCaptureOptions{
		iface:           "ens5",
		protocol:        "tcp",
		srcIP:           "10.0.1.20",
		srcPort:         51515,
		destIP:          "10.0.2.20",
		destPort:        443,
		durationSeconds: 5,
		packetCount:     10,
		snaplenBytes:    128,
		label:           "web",
		flowID:          "eve-web-1",
	})
	if err != nil {
		t.Fatalf("runSystemCapture returned error: %v", err)
	}
	req := client.planReq
	if req == nil || req.GetInterface() != "ens5" || req.GetProtocol() != openngfwv1.Protocol_PROTOCOL_TCP ||
		req.GetSrcIp() != "10.0.1.20" || req.GetSrcPort() != 51515 || req.GetDestIp() != "10.0.2.20" ||
		req.GetDestPort() != 443 || req.GetDurationSeconds() != 5 || req.GetPacketCount() != 10 ||
		req.GetSnaplenBytes() != 128 || req.GetLabel() != "web" || req.GetFlowId() != "eve-web-1" {
		t.Fatalf("plan request = %#v", req)
	}
	if client.startReq != nil {
		t.Fatalf("start request should not be sent in plan mode: %#v", client.startReq)
	}
	for _, want := range []string{
		"packet capture plan",
		"interface:       ens5",
		"scope:           10.0.1.20:51515 <-> 10.0.2.20:443",
		"flow id:         eve-web-1",
		"limits:          5s, 10 packets, 128 byte snaplen",
		"sudo timeout 5s tcpdump",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemAutomationReplayPlanRequiresInput(t *testing.T) {
	_, err := runSystemAutomationReplayPlanForTest(systemAutomationReplayOptions{})
	if err == nil || !strings.Contains(err.Error(), "--recording or --runbook is required") {
		t.Fatalf("expected input error, got %v", err)
	}
}

func TestSystemAutomationReplayPlanApplyAuthorityGrantsCandidateOnly(t *testing.T) {
	runbook := filepath.Join(t.TempDir(), "runbook.sh")
	if err := os.WriteFile(runbook, []byte(`curl -sk -X PUT -d '{"expectedCandidateRevision":"sha256:current","policy":{"rules":[]}}' https://127.0.0.1:8080/v1/candidate`), 0o600); err != nil {
		t.Fatalf("write runbook: %v", err)
	}
	out, err := runSystemAutomationReplayPlanForTest(systemAutomationReplayOptions{
		runbookPath:       runbook,
		mode:              "apply-authority",
		candidateRevision: "sha256:current",
		ackAuthority:      true,
		ackNoLiveApply:    true,
		ackCandidateOnly:  true,
		ackRevision:       true,
		outJSON:           true,
	})
	if err != nil {
		t.Fatalf("runSystemAutomationReplayPlan returned error: %v", err)
	}
	for _, want := range []string{
		`"schemaVersion": "phragma.automation.replay-validation.v1"`,
		`"schemaVersion": "phragma.automation.replay-execution-plan.v1"`,
		`"mode": "apply-authority"`,
		`"authorityGranted": true`,
		`"candidateOnlySteps": 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemAutomationReplayPlanExecuteModeBuildsRequestOnly(t *testing.T) {
	runbook := filepath.Join(t.TempDir(), "runbook.sh")
	if err := os.WriteFile(runbook, []byte(`curl -sk -X PUT -d '{"expectedCandidateRevision":"sha256:current","policy":{"rules":[]}}' https://127.0.0.1:8080/v1/candidate`), 0o600); err != nil {
		t.Fatalf("write runbook: %v", err)
	}
	out, err := runSystemAutomationReplayPlanForTest(systemAutomationReplayOptions{
		runbookPath:       runbook,
		mode:              "execute",
		candidateRevision: "sha256:current",
		ackAuthority:      true,
		ackNoLiveApply:    true,
		ackCandidateOnly:  true,
		ackRevision:       true,
		outJSON:           false,
	})
	if err != nil {
		t.Fatalf("runSystemAutomationReplayPlan returned error: %v", err)
	}
	for _, want := range []string{
		"replay plan: mode=execute",
		"authority: requested=true granted=true",
		"candidate-only=1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemAutomationReplayPlanBlocksLiveApply(t *testing.T) {
	runbook := filepath.Join(t.TempDir(), "runbook.sh")
	if err := os.WriteFile(runbook, []byte(`ngfwctl commit --ack-risk --ack-runtime -m replay`), 0o600); err != nil {
		t.Fatalf("write runbook: %v", err)
	}
	out, err := runSystemAutomationReplayPlanForTest(systemAutomationReplayOptions{runbookPath: runbook, mode: "dry-run", outJSON: false})
	if err != nil {
		t.Fatalf("runSystemAutomationReplayPlan returned error: %v", err)
	}
	if !strings.Contains(out, "blocked=1") || !strings.Contains(out, "authority: requested=false granted=false") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestSystemCaptureStartRequiresAck(t *testing.T) {
	client := &fakeSystemCaptureClient{}
	_, err := runSystemCaptureForTest(client, systemCaptureOptions{start: true, protocol: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "--ack-capture is required") {
		t.Fatalf("expected ack error, got %v", err)
	}
	if client.startReq != nil || client.planReq != nil {
		t.Fatalf("client should not be called without ack: plan=%#v start=%#v", client.planReq, client.startReq)
	}
}

func TestSystemCaptureStartsThroughAPI(t *testing.T) {
	client := &fakeSystemCaptureClient{
		startResp: &openngfwv1.StartPacketCaptureResponse{
			Job: &openngfwv1.PacketCaptureJob{
				Id:           "pcap-1",
				State:        "completed",
				Detail:       "packet capture completed",
				BytesWritten: 2048,
				Sha256:       "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
				Plan: &openngfwv1.PacketCapturePlan{
					FlowId:     "eve-dns-1",
					OutputPath: "/var/log/openngfw/pcap/phragma-dns.pcap",
				},
			},
		},
	}
	out, err := runSystemCaptureForTest(client, systemCaptureOptions{
		iface:           "ens5",
		protocol:        "udp",
		srcIP:           "10.0.1.20",
		srcPort:         53000,
		destIP:          "10.0.2.53",
		destPort:        53,
		durationSeconds: 2,
		packetCount:     25,
		snaplenBytes:    256,
		label:           "dns",
		flowID:          "eve-dns-1",
		start:           true,
		ackCapture:      true,
	})
	if err != nil {
		t.Fatalf("runSystemCapture returned error: %v", err)
	}
	req := client.startReq
	if req == nil || !req.GetAckCapture() || req.GetProtocol() != openngfwv1.Protocol_PROTOCOL_UDP ||
		req.GetDestPort() != 53 || req.GetLabel() != "dns" || req.GetFlowId() != "eve-dns-1" {
		t.Fatalf("start request = %#v", req)
	}
	for _, want := range []string{
		"packet capture job",
		"id:              pcap-1",
		"state:           completed",
		"bytes:           2.0 KB",
		"sha256:          aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		"flow id:         eve-dns-1",
		"output:          /var/log/openngfw/pcap/phragma-dns.pcap",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemCaptureListsArtifactsThroughAPI(t *testing.T) {
	client := &fakeSystemCaptureClient{
		listResp: &openngfwv1.ListPacketCapturesResponse{
			CaptureDir: "/var/log/openngfw/pcap",
			Captures: []*openngfwv1.PacketCaptureJob{{
				Id:           "job-ignored",
				ArtifactId:   "phragma-web-20260618T121500Z",
				State:        "completed",
				Detail:       "pcap indexed from disk",
				CompletedAt:  "2026-06-18T12:15:01Z",
				BytesWritten: 4096,
				Sha256:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				Filename:     "phragma-web-20260618T121500Z.pcap",
				DownloadPath: "/v1/system/packet-captures/phragma-web-20260618T121500Z/download",
				MediaType:    "application/vnd.tcpdump.pcap",
				Retention: &openngfwv1.PacketCaptureRetention{
					State:           openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
					RetainUntil:     "2026-07-19T15:00:00Z",
					RetentionReason: "incident review",
					CaseId:          "IR-2026-001",
					UpdatedAt:       "2026-06-19T15:00:00Z",
					UpdatedBy:       "alice",
				},
				Plan: &openngfwv1.PacketCapturePlan{
					FlowId:     "eve-web-1",
					OutputPath: "/var/log/openngfw/pcap/phragma-web-20260618T121500Z.pcap",
				},
			}},
		},
	}
	out, err := runSystemCaptureListForTest(client, systemCaptureOptions{limit: 3, flowID: "eve-web-1"})
	if err != nil {
		t.Fatalf("runSystemCaptureList returned error: %v", err)
	}
	if client.listReq == nil || client.listReq.GetLimit() != 3 || client.listReq.GetFlowId() != "eve-web-1" {
		t.Fatalf("list request = %#v", client.listReq)
	}
	if client.planReq != nil || client.startReq != nil || client.downloadReq != nil {
		t.Fatalf("unexpected capture calls: plan=%#v start=%#v download=%#v", client.planReq, client.startReq, client.downloadReq)
	}
	for _, want := range []string{
		"packet capture artifacts",
		"capture dir:     /var/log/openngfw/pcap",
		"id:            phragma-web-20260618T121500Z",
		"state:         completed",
		"bytes:         4.0 KB",
		"sha256:        00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"filename:      phragma-web-20260618T121500Z.pcap",
		"flow id:       eve-web-1",
		"download:      /v1/system/packet-captures/phragma-web-20260618T121500Z/download",
		"media type:    application/vnd.tcpdump.pcap",
		"retention:     retained",
		"retain until:  2026-07-19T15:00:00Z",
		"case id:       IR-2026-001",
		"reason:        incident review",
		"updated:       2026-06-19T15:00:00Z by alice",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemCaptureDownloadWritesBytes(t *testing.T) {
	client := &fakeSystemCaptureClient{
		downloadResp: &httpbody.HttpBody{
			ContentType: "application/vnd.tcpdump.pcap",
			Data:        []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x01, 0x02},
		},
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	out, err := runSystemCaptureDownloadForTest(client, systemCaptureOptions{
		artifactID: "phragma-web-20260618T121500Z",
		outputPath: path,
	})
	if err != nil {
		t.Fatalf("runSystemCaptureDownload returned error: %v", err)
	}
	if client.downloadReq == nil || client.downloadReq.GetId() != "phragma-web-20260618T121500Z" {
		t.Fatalf("download request = %#v", client.downloadReq)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded pcap: %v", err)
	}
	if !bytes.Equal(raw, client.downloadResp.GetData()) {
		t.Fatalf("downloaded bytes = %#v, want %#v", raw, client.downloadResp.GetData())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat downloaded pcap: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("downloaded pcap mode = %v, want 0600", got)
	}
	for _, want := range []string{
		"downloaded packet capture phragma-web-20260618T121500Z",
		path,
		"6 B",
		"application/vnd.tcpdump.pcap",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemCaptureDownloadRequiresOutput(t *testing.T) {
	client := &fakeSystemCaptureClient{}
	_, err := runSystemCaptureDownloadForTest(client, systemCaptureOptions{artifactID: "phragma-web"})
	if err == nil || !strings.Contains(err.Error(), "--output is required") {
		t.Fatalf("expected output error, got %v", err)
	}
	if client.downloadReq != nil {
		t.Fatalf("download request should not be sent without output: %#v", client.downloadReq)
	}
}

func TestSystemCaptureRetainUpdatesMetadataThroughAPI(t *testing.T) {
	client := &fakeSystemCaptureClient{
		retentionResp: &openngfwv1.SetPacketCaptureRetentionResponse{
			Job: &openngfwv1.PacketCaptureJob{
				Id:           "job-1",
				ArtifactId:   "phragma-web-20260618T121500Z",
				State:        "completed",
				BytesWritten: 4096,
				Retention: &openngfwv1.PacketCaptureRetention{
					State:           openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
					RetainUntil:     "2026-07-19T15:00:00Z",
					RetentionReason: "incident review",
					CaseId:          "IR-2026-001",
					UpdatedAt:       "2026-06-19T15:00:00Z",
					UpdatedBy:       "alice",
				},
			},
		},
	}
	out, err := runSystemCaptureRetentionForTest(client, systemCaptureOptions{
		artifactID:      "phragma-web-20260618T121500Z",
		retainUntil:     "2026-07-19T15:00:00Z",
		retentionReason: "incident review",
		caseID:          "IR-2026-001",
		ackRetention:    true,
	}, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED)
	if err != nil {
		t.Fatalf("runSystemCaptureRetention returned error: %v", err)
	}
	req := client.retentionReq
	if req == nil || req.GetId() != "phragma-web-20260618T121500Z" ||
		req.GetState() != openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED ||
		req.GetRetainUntil() != "2026-07-19T15:00:00Z" || req.GetRetentionReason() != "incident review" ||
		req.GetCaseId() != "IR-2026-001" || !req.GetAckRetentionChange() {
		t.Fatalf("retention request = %#v", req)
	}
	if client.planReq != nil || client.startReq != nil || client.listReq != nil || client.downloadReq != nil {
		t.Fatalf("unexpected capture calls: plan=%#v start=%#v list=%#v download=%#v", client.planReq, client.startReq, client.listReq, client.downloadReq)
	}
	for _, want := range []string{
		"packet capture job",
		"artifact id:     phragma-web-20260618T121500Z",
		"retention:     retained",
		"retain until:  2026-07-19T15:00:00Z",
		"case id:       IR-2026-001",
		"reason:        incident review",
		"updated:       2026-06-19T15:00:00Z by alice",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemCaptureReleaseClearsRetainUntilThroughAPI(t *testing.T) {
	client := &fakeSystemCaptureClient{
		retentionResp: &openngfwv1.SetPacketCaptureRetentionResponse{
			Job: &openngfwv1.PacketCaptureJob{
				Id:        "phragma-web-20260618T121500Z",
				State:     "completed",
				Retention: &openngfwv1.PacketCaptureRetention{State: openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED, RetentionReason: "case closed"},
			},
		},
	}
	out, err := runSystemCaptureRetentionForTest(client, systemCaptureOptions{
		artifactID:      "phragma-web-20260618T121500Z",
		retainUntil:     "2026-07-19T15:00:00Z",
		retentionReason: "case closed",
		ackRetention:    true,
	}, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED)
	if err != nil {
		t.Fatalf("runSystemCaptureRetention returned error: %v", err)
	}
	req := client.retentionReq
	if req == nil || req.GetState() != openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED ||
		req.GetRetainUntil() != "" || req.GetRetentionReason() != "case closed" || !req.GetAckRetentionChange() {
		t.Fatalf("release request = %#v", req)
	}
	if !strings.Contains(out, "retention:     released") || !strings.Contains(out, "reason:        case closed") {
		t.Fatalf("release output missing retention summary:\n%s", out)
	}
}

func TestSystemCaptureRetentionRequiresAckReasonAndRetainUntil(t *testing.T) {
	client := &fakeSystemCaptureClient{}
	if _, err := runSystemCaptureRetentionForTest(client, systemCaptureOptions{artifactID: "phragma-web", retainUntil: "2026-07-19T15:00:00Z", ackRetention: true}, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED); err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("expected reason error, got %v", err)
	}
	if _, err := runSystemCaptureRetentionForTest(client, systemCaptureOptions{artifactID: "phragma-web", retentionReason: "incident review", ackRetention: true}, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED); err == nil || !strings.Contains(err.Error(), "--retain-until is required") {
		t.Fatalf("expected retain-until error, got %v", err)
	}
	if _, err := runSystemCaptureRetentionForTest(client, systemCaptureOptions{artifactID: "phragma-web", retainUntil: "2026-07-19T15:00:00Z", retentionReason: "incident review"}, openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED); err == nil || !strings.Contains(err.Error(), "--ack-retention-change is required") {
		t.Fatalf("expected ack error, got %v", err)
	}
	if client.retentionReq != nil {
		t.Fatalf("retention request should not be sent after local validation errors: %#v", client.retentionReq)
	}
}

func TestSystemHAPullPolicyRequiresMessageAndAck(t *testing.T) {
	client := &fakeSystemHAClient{}
	if _, err := runSystemHAPullPolicyForTest(client, systemHAOptions{ackPull: true}); err == nil || !strings.Contains(err.Error(), "--message is required") {
		t.Fatalf("expected message error, got %v", err)
	}
	if _, err := runSystemHAPullPolicyForTest(client, systemHAOptions{comment: "replicate"}); err == nil || !strings.Contains(err.Error(), "--ack-pull is required") {
		t.Fatalf("expected ack error, got %v", err)
	}
	if client.req != nil {
		t.Fatalf("client should not be called without message and ack: %#v", client.req)
	}
}

func TestSystemHAStatusPrintsCutoverPlan(t *testing.T) {
	client := &fakeSystemHAClient{statusResp: &openngfwv1.GetHighAvailabilityStatusResponse{
		GeneratedAt: "2026-06-21T12:00:00Z",
		Status: &openngfwv1.HighAvailabilityStatus{
			State:                          "ready",
			Role:                           "passive",
			Mode:                           "active-passive",
			NodeId:                         "fw-b",
			PeerId:                         "fw-a",
			PeerAddress:                    "https://fw-a.example/v1/system/ha/status",
			RunningPolicyVersion:           9,
			LastKnownGoodVersion:           9,
			LastKnownGoodState:             "active",
			LastKnownGoodArtifactSetSha256: strings.Repeat("b", 64),
			Sync: &openngfwv1.HighAvailabilitySyncStatus{
				State:                 "synced",
				LocalVersion:          9,
				PeerVersion:           9,
				PeerArtifactSetSha256: strings.Repeat("c", 64),
				SecondsSinceHeartbeat: 12,
				Detail:                "peer heartbeat fresh and artifacts match",
			},
			Replication: &openngfwv1.HighAvailabilityReplicationStatus{
				State:            "replicated",
				Enabled:          true,
				LastPeerVersion:  9,
				LastLocalVersion: 9,
				LastSuccessAt:    "2026-06-21T11:59:00Z",
				Detail:           "Last automatic replication applied peer policy v9 locally as v9.",
			},
			FencingEvidence: &openngfwv1.HighAvailabilityFencingEvidenceStatus{
				State:      "recorded",
				Provider:   "operator-runbook",
				Claim:      "peer_power_off_verified",
				PeerId:     "fw-a",
				EvidenceId: "change-1234",
				ObservedAt: "2026-06-21T11:58:00Z",
				Detail:     "Read-only external evidence recorded; OpenNGFW did not fence the peer.",
			},
			Failover: &openngfwv1.HighAvailabilityFailoverStatus{
				State:    "ready",
				Eligible: true,
				Detail:   "Manual active/passive recovery is eligible.",
			},
			Detail: "Active/passive HA readiness is satisfied.",
		},
	}}
	out, err := runSystemHAStatusForTest(client, systemHAOptions{})
	if err != nil {
		t.Fatalf("runSystemHAStatus returned error: %v", err)
	}
	if client.statusReq == nil {
		t.Fatalf("status request was not sent")
	}
	for _, want := range []string{
		"HA status",
		"generated at:    2026-06-21T12:00:00Z",
		"mode/role:       active-passive / passive",
		"peer:            fw-a (https://fw-a.example/v1/system/ha/status)",
		"policy:          running v9 / lkg v9 active",
		"sync versions:   local v9 / peer v9",
		"heartbeat age:   12s",
		"replication:     replicated enabled=true",
		"fencing:         recorded",
		"fencing proof:   provider=operator-runbook claim=peer_power_off_verified",
		"fencing id:      change-1234",
		"fencing detail:  Read-only external evidence recorded; OpenNGFW did not fence the peer.",
		"failover:        ready eligible=true",
		"cutover plan:",
		"preflight: ready from peer heartbeat, policy sync, and LKG evidence",
		"traffic: move VIP/route ownership using the site runbook after activation",
		"fencing: verify provider-backed peer fencing evidence; this API records evidence but does not fence the peer",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemHAStatusPrintsBlockedCutoverPlan(t *testing.T) {
	client := &fakeSystemHAClient{statusResp: &openngfwv1.GetHighAvailabilityStatusResponse{
		Status: &openngfwv1.HighAvailabilityStatus{
			State:                "degraded",
			Role:                 "passive",
			Mode:                 "active-passive",
			RunningPolicyVersion: 4,
			LastKnownGoodState:   "missing",
			Sync: &openngfwv1.HighAvailabilitySyncStatus{
				State:  "degraded",
				Detail: "HA peer heartbeat source could not be queried.",
			},
			Failover: &openngfwv1.HighAvailabilityFailoverStatus{
				State:    "blocked",
				Eligible: false,
				Detail:   "Manual active/passive recovery is blocked.",
				Blockers: []string{"HA peer heartbeat is unreachable"},
			},
			Blockers: []string{"Last-known-good policy metadata is missing."},
		},
	}}
	out, err := runSystemHAStatusForTest(client, systemHAOptions{})
	if err != nil {
		t.Fatalf("runSystemHAStatus returned error: %v", err)
	}
	for _, want := range []string{
		"failover:        blocked eligible=false",
		"failover blocks: HA peer heartbeat is unreachable",
		"blocker:         Last-known-good policy metadata is missing.",
		"preflight: blocked; do not move VIPs or routes",
		"VIP/route cutover remains external and must wait for eligible server evidence",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemHAPullPolicyCallsAPIAndPrintsSummary(t *testing.T) {
	client := &fakeSystemHAClient{resp: &openngfwv1.PullHighAvailabilityPolicyResponse{
		Version:               3,
		PreviousVersion:       2,
		PeerVersion:           7,
		PeerArtifactSetSha256: strings.Repeat("a", 64),
		VersionInfo:           &openngfwv1.VersionInfo{Action: "ha-policy-pull", State: "active"},
		Before:                &openngfwv1.HighAvailabilityStatus{Role: "passive", RunningPolicyVersion: 2, Sync: &openngfwv1.HighAvailabilitySyncStatus{State: "degraded"}},
		After:                 &openngfwv1.HighAvailabilityStatus{Role: "passive", RunningPolicyVersion: 3, Sync: &openngfwv1.HighAvailabilitySyncStatus{State: "synced"}},
		Detail:                "Pulled active peer policy v7 and applied it locally as v3.",
	}}
	out, err := runSystemHAPullPolicyForTest(client, systemHAOptions{
		comment:    "replicate from active",
		ackPull:    true,
		ackRisk:    true,
		ackRuntime: true,
	})
	if err != nil {
		t.Fatalf("runSystemHAPullPolicy returned error: %v", err)
	}
	if client.req == nil || client.req.GetComment() != "replicate from active" || !client.req.GetAckPull() || !client.req.GetAckRisk() || !client.req.GetAckRuntime() {
		t.Fatalf("request = %#v", client.req)
	}
	for _, want := range []string{
		"HA policy pull",
		"previous version: v2",
		"new version:      v3",
		"peer version:     v7",
		"peer artifact:    aaaaaaaaaaaaaaaa",
		"action:           ha-policy-pull",
		"state:            active",
		"before:           passive/degraded v2",
		"after:            passive/synced v3",
		"Pulled active peer policy v7",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemHAActivatePassiveRequiresMessageAndAcks(t *testing.T) {
	client := &fakeSystemHAClient{}
	if _, err := runSystemHAActivatePassiveForTest(client, systemHAOptions{ackFailover: true, ackExternalCutover: true, ackExternalFencing: true}); err == nil || !strings.Contains(err.Error(), "--message is required") {
		t.Fatalf("expected message error, got %v", err)
	}
	if _, err := runSystemHAActivatePassiveForTest(client, systemHAOptions{comment: "manual failover", ackExternalCutover: true, ackExternalFencing: true}); err == nil || !strings.Contains(err.Error(), "--ack-failover is required") {
		t.Fatalf("expected failover ack error, got %v", err)
	}
	if _, err := runSystemHAActivatePassiveForTest(client, systemHAOptions{comment: "manual failover", ackFailover: true, ackExternalFencing: true}); err == nil || !strings.Contains(err.Error(), "--ack-external-cutover is required") {
		t.Fatalf("expected external cutover ack error, got %v", err)
	}
	if _, err := runSystemHAActivatePassiveForTest(client, systemHAOptions{comment: "manual failover", ackFailover: true, ackExternalCutover: true}); err == nil || !strings.Contains(err.Error(), "--ack-external-fencing is required") {
		t.Fatalf("expected external fencing ack error, got %v", err)
	}
	if client.activateReq != nil {
		t.Fatalf("client should not be called without message and acks: %#v", client.activateReq)
	}
}

func TestSystemHAActivatePassiveCallsAPIAndPrintsSummary(t *testing.T) {
	client := &fakeSystemHAClient{activateResp: &openngfwv1.ActivateHighAvailabilityFailoverResponse{
		ActivatedAt:          "2026-06-20T15:04:05Z",
		RunningPolicyVersion: 9,
		LastKnownGoodVersion: 9,
		Before:               &openngfwv1.HighAvailabilityStatus{Role: "passive", RunningPolicyVersion: 9, Failover: &openngfwv1.HighAvailabilityFailoverStatus{State: "ready", Detail: "Manual recovery is eligible."}},
		After:                &openngfwv1.HighAvailabilityStatus{Role: "active", RunningPolicyVersion: 9, Failover: &openngfwv1.HighAvailabilityFailoverStatus{State: "blocked", Detail: "Post-activation review required.", Blockers: []string{"HA peer role matches local role; active/passive requires opposite roles."}}},
		Detail:               "Marked passive node fw-b active using running policy v9 after HA preflight.",
	}}
	out, err := runSystemHAActivatePassiveForTest(client, systemHAOptions{
		comment:            "manual failover",
		ackFailover:        true,
		ackExternalCutover: true,
		ackExternalFencing: true,
	})
	if err != nil {
		t.Fatalf("runSystemHAActivatePassive returned error: %v", err)
	}
	if client.activateReq == nil ||
		client.activateReq.GetComment() != "manual failover" ||
		!client.activateReq.GetAckFailover() ||
		!client.activateReq.GetAckExternalCutover() ||
		!client.activateReq.GetAckExternalFencing() {
		t.Fatalf("request = %#v", client.activateReq)
	}
	for _, want := range []string{
		"HA failover activation",
		"activated at:     2026-06-20T15:04:05Z",
		"running policy:   v9",
		"before:           passive/ready v9",
		"after:            active/blocked v9",
		"preflight:        Manual recovery is eligible.",
		"post-check:       Post-activation review required.",
		"post-blockers:    HA peer role matches local role",
		"traffic cutover:  external acknowledged; verify outside API",
		"peer fencing:     external acknowledged; verify outside API",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestSystemEbpfReadinessCommandReportsEvidence(t *testing.T) {
	client := &fakeSystemStatusClient{resp: &openngfwv1.GetStatusResponse{
		Dataplane: &openngfwv1.DataplaneStatus{
			Ebpf: &openngfwv1.EbpfDataplaneStatus{
				State:               "ready",
				Detail:              "host prerequisites are ready",
				AttachState:         "ready",
				AttachDetail:        "XDP and tc attach prerequisites are present",
				RendererState:       "planned",
				RendererDetail:      "plan-only renderer; nftables remains authoritative",
				SupportedHooks:      []string{"xdp", "tc"},
				EvidenceScope:       "host-prerequisites,attach-prerequisites,renderer-scaffold",
				EvidenceCollectedAt: "2026-06-20T10:00:00Z",
				Probes: []*openngfwv1.EbpfProbe{{
					Name:   "bpftool",
					Key:    "bpftool",
					State:  "ready",
					Detail: "bpftool is installed",
				}},
				AttachProbes: []*openngfwv1.EbpfProbe{{
					Name:   "tc",
					Key:    "tc",
					State:  "ready",
					Detail: "tc is installed",
				}},
				Attachments: []*openngfwv1.EbpfAttachment{{
					Interface:   "ens5",
					Hook:        "xdp",
					State:       "observed",
					ProgramId:   "42",
					ProgramName: "xdp_probe",
					Detail:      "runtime probe observed",
				}},
				Artifacts: []*openngfwv1.EbpfArtifact{{
					Name:   "manifest.txt",
					Kind:   "attach-drill",
					State:  "ready",
					Sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					Detail: "field evidence manifest indexed",
				}},
			},
		},
	}}
	out, err := runSystemEbpfReadinessForTest(client, systemEbpfReadinessOptions{})
	if err != nil {
		t.Fatalf("runSystemEbpfReadiness returned error: %v", err)
	}
	if client.req == nil {
		t.Fatal("GetStatus was not called")
	}
	for _, want := range []string{
		"eBPF readiness",
		"host:            ready",
		"attach:          ready",
		"renderer:        planned",
		"hooks:           xdp, tc",
		"evidence scope:  host-prerequisites,attach-prerequisites,renderer-scaffold",
		"host probes:",
		"bpftool                  ready",
		"attach probes:",
		"tc                       ready",
		"attachments:",
		"ens5     xdp  observed",
		"artifacts:",
		"manifest.txt             attach-drill ready",
		"sha256:abcdef1234567890",
		"active dataplane: nftables/conntrack",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemEbpfReadinessCommandReportsDegradedBlockers(t *testing.T) {
	client := &fakeSystemStatusClient{resp: &openngfwv1.GetStatusResponse{
		Dataplane: &openngfwv1.DataplaneStatus{
			Ebpf: &openngfwv1.EbpfDataplaneStatus{
				State:          "degraded",
				Detail:         "missing command bpftool",
				AttachState:    "degraded",
				AttachDetail:   "missing command tc",
				RendererState:  "planned",
				RendererDetail: "plan-only renderer; nftables remains authoritative",
				SupportedHooks: []string{"xdp", "tc"},
				Blockers:       []string{"bpftool is required", "tc is required"},
				Probes: []*openngfwv1.EbpfProbe{{
					Name:   "bpftool",
					State:  "degraded",
					Detail: "missing command bpftool",
				}},
			},
		},
	}}
	out, err := runSystemEbpfReadinessForTest(client, systemEbpfReadinessOptions{})
	if err != nil {
		t.Fatalf("runSystemEbpfReadiness returned error: %v", err)
	}
	for _, want := range []string{
		"host:            degraded",
		"attach:          degraded",
		"blockers:",
		"- bpftool is required",
		"- tc is required",
		"bpftool                  degraded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemEbpfReadinessCommandJSON(t *testing.T) {
	client := &fakeSystemStatusClient{resp: &openngfwv1.GetStatusResponse{
		Dataplane: &openngfwv1.DataplaneStatus{
			Ebpf: &openngfwv1.EbpfDataplaneStatus{
				State:         "ready",
				AttachState:   "ready",
				RendererState: "planned",
			},
		},
	}}
	out, err := runSystemEbpfReadinessForTest(client, systemEbpfReadinessOptions{outJSON: true})
	if err != nil {
		t.Fatalf("runSystemEbpfReadiness returned error: %v", err)
	}
	for _, want := range []string{`"state":\s*"ready"`, `"attach_state":\s*"ready"`, `"renderer_state":\s*"planned"`} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Fatalf("missing %q in JSON output:\n%s", want, out)
		}
	}
}

func TestSystemEbpfReadinessCommandPropagatesStatusError(t *testing.T) {
	client := &fakeSystemStatusClient{err: fmt.Errorf("down")}
	_, err := runSystemEbpfReadinessForTest(client, systemEbpfReadinessOptions{})
	if err == nil || !strings.Contains(err.Error(), "query eBPF readiness: down") {
		t.Fatalf("expected wrapped status error, got %v", err)
	}
}

func TestSystemTelemetryExportStatusPrintsPassiveEvidence(t *testing.T) {
	client := &fakeSystemTelemetryClient{resp: &openngfwv1.GetTelemetryExportStatusResponse{
		SchemaVersion:        "phragma.telemetry.export.status.v1",
		GeneratedAt:          "2026-06-19T15:05:00Z",
		State:                "configured",
		Detail:               "Telemetry export sinks are rendered from the running policy.",
		TelemetryEnabled:     true,
		RunningPolicyVersion: 7,
		Vector:               &openngfwv1.TelemetryVectorRuntimeStatus{State: "active", Detail: "process running pid 4200"},
		Clickhouse: &openngfwv1.TelemetryClickHouseSinkStatus{
			Configured:     true,
			Endpoint:       "https://clickhouse.example:8443",
			Database:       "openngfw_prod",
			EvidenceState:  "configured-unverified",
			EvidenceDetail: "row delivery requires ClickHouse-side evidence",
		},
		Exports: []*openngfwv1.TelemetryExportSinkStatus{
			{
				Name:           "local-json",
				Configured:     true,
				Type:           openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
				Target:         "/var/log/openngfw/exports/eve.json",
				Protocol:       "file",
				EvidenceState:  "receiving",
				EvidenceDetail: "file is present with 128 bytes",
				File: &openngfwv1.TelemetryLocalFileEvidence{
					Path:       "/var/log/openngfw/exports/eve.json",
					Present:    true,
					SizeBytes:  128,
					ModifiedAt: "2026-06-19T15:04:00Z",
				},
			},
			{
				Name:           "siem-json",
				Configured:     true,
				Type:           openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
				Target:         "siem.example:5514",
				Protocol:       "tcp",
				EvidenceState:  "configured-unverified",
				EvidenceDetail: "receiver proof required",
			},
		},
		Warnings: []*openngfwv1.StatusWarning{{Severity: "info", Message: "Telemetry export \"siem-json\" requires sink-side verification.", Action: "Collect SIEM receiver counts."}},
	}}

	out, err := runSystemTelemetryExportStatusForTest(client, systemTelemetryOptions{})
	if err != nil {
		t.Fatalf("runSystemTelemetryExportStatus returned error: %v", err)
	}
	if client.req == nil {
		t.Fatal("GetTelemetryExportStatus was not called")
	}
	for _, want := range []string{
		"telemetry export status",
		"state:           configured",
		"running policy:  v7",
		"vector:          active - process running pid 4200",
		"clickhouse:      configured-unverified",
		"target:        https://clickhouse.example:8443/openngfw_prod",
		"local-json",
		"json-file",
		"receiving",
		"128 B",
		"siem-json",
		"configured-unverified",
		"requires sink-side verification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestSystemTelemetryExportStatusPrintsJSON(t *testing.T) {
	client := &fakeSystemTelemetryClient{resp: &openngfwv1.GetTelemetryExportStatusResponse{
		SchemaVersion:        "phragma.telemetry.export.status.v1",
		State:                "disabled",
		TelemetryEnabled:     false,
		RunningPolicyVersion: 0,
	}}
	out, err := runSystemTelemetryExportStatusForTest(client, systemTelemetryOptions{outJSON: true})
	if err != nil {
		t.Fatalf("runSystemTelemetryExportStatus json returned error: %v", err)
	}
	if !strings.Contains(out, `"schema_version"`) || !strings.Contains(out, `"phragma.telemetry.export.status.v1"`) || !strings.Contains(out, `"state"`) || !strings.Contains(out, `"disabled"`) {
		t.Fatalf("json output missing telemetry export status:\n%s", out)
	}
}

func TestSystemReleaseAcceptanceStatusPrintsOperatorSummary(t *testing.T) {
	client := &fakeSystemReleaseAcceptanceClient{resp: &openngfwv1.GetReleaseAcceptanceStatusResponse{
		SchemaVersion:   "phragma.release_acceptance.status.v1",
		GeneratedAt:     "2026-06-20T15:30:00Z",
		ManifestPath:    "/tmp/openngfw-smoke/release/acceptance.json",
		EvidenceDir:     "/home/opc/oss-ngfw/release/evidence",
		ManifestPresent: true,
		Ready:           false,
		State:           "blocked",
		Summary: &openngfwv1.ReleaseAcceptanceStatusSummary{
			Passed:        1,
			Recorded:      2,
			Missing:       3,
			Invalid:       4,
			NotApplicable: 5,
			Todo:          6,
		},
		Problems: []string{"proto-verify evidence is missing from /home/opc/oss-ngfw/release/evidence and token=release-secret"},
		Checks: []*openngfwv1.ReleaseAcceptanceCheckStatus{{
			Name:             "proto-verify",
			State:            "missing",
			Artifact:         "release/evidence/proto-verify.json",
			EvidencePath:     "/home/opc/oss-ngfw/release/evidence/proto-verify.json",
			RanAt:            "2026-06-20T15:29:00Z",
			Detail:           "recorded artifact not found at /tmp/openngfw-smoke/proto-verify.json",
			NextAction:       "Record proto verification evidence from /home/opc/oss-ngfw.",
			NextCommand:      []string{"make", "proto-verify", "TOKEN=release-secret"},
			BenchmarkSummary: "no performance claims recorded",
			Problems:         []string{"artifact missing at /home/opc/oss-ngfw/release/evidence/proto-verify.json"},
		}},
		Recordability: &openngfwv1.ReleaseAcceptanceRecordabilityStatus{
			Ready:             false,
			GitHead:           "abc123",
			RecordCommit:      "abc123",
			AllowedDirtyPaths: []string{"docs/CURRENT_PROGRESS.md"},
			DirtySourcePaths:  []string{"/Users/operator/oss-ngfw/internal/cli/system.go"},
			StaleEvidencePaths: []string{
				"release/evidence/proto-verify.txt (evidence commit deadbeef != record commit abc123)",
			},
			Problems: []string{"working tree at /home/opc/oss-ngfw has non-allowed source changes"},
		},
	}}

	out, err := runSystemReleaseAcceptanceStatusForTest(client, systemReleaseAcceptanceOptions{})
	if err != nil {
		t.Fatalf("runSystemReleaseAcceptanceStatus returned error: %v", err)
	}
	if client.req == nil {
		t.Fatal("GetReleaseAcceptanceStatus was not called")
	}
	for _, want := range []string{
		"release acceptance status",
		"state:           blocked",
		"ready:           no",
		"manifest:        present ([server-local path redacted])",
		"evidence dir:    [server-local path redacted]",
		"summary:         passed=1 recorded=2 missing=3 invalid=4 not_applicable=5 todo=6",
		"recordability:   blocked",
		"scope:         source-control acceptance only; does not prove functional generation or accept release evidence",
		"git head:      abc123",
		"dirty paths:   [server-local path redacted]",
		"stale evidence: release/evidence/proto-verify.txt (evidence commit deadbeef != record commit abc123)",
		"proto-verify evidence is missing from [server-local path redacted] and token=[redacted]",
		"proto-verify",
		"functional:  make proto-status && make proto-verify validate generated proto/gateway/OpenAPI consistency",
		"source:      blocked (1 dirty source path(s), 1 problem(s)); release evidence is not acceptable until proto inputs",
		"artifact:    release/evidence/proto-verify.json",
		"benchmark:   no performance claims recorded",
		"next:        Record proto verification evidence from [server-local path redacted]",
		"next cmd:    make proto-verify TOKEN=[redacted]",
		"artifact missing at [server-local path redacted]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	for _, leaked := range []string{"/home/opc", "/tmp/openngfw", "/Users/operator", "release-secret"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("release status output leaked %q:\n%s", leaked, out)
		}
	}
}

func TestSystemReleaseAcceptanceStatusPrintsJSON(t *testing.T) {
	client := &fakeSystemReleaseAcceptanceClient{resp: &openngfwv1.GetReleaseAcceptanceStatusResponse{
		SchemaVersion: "phragma.release_acceptance.status.v1",
		State:         "ready",
		Ready:         true,
		Summary:       &openngfwv1.ReleaseAcceptanceStatusSummary{NotApplicable: 1},
		Checks: []*openngfwv1.ReleaseAcceptanceCheckStatus{{
			Name:        "proto-verify",
			State:       "passed",
			NextCommand: []string{"make", "proto-verify"},
		}},
	}}
	out, err := runSystemReleaseAcceptanceStatusForTest(client, systemReleaseAcceptanceOptions{outJSON: true})
	if err != nil {
		t.Fatalf("runSystemReleaseAcceptanceStatus json returned error: %v", err)
	}
	if !strings.Contains(out, `"schema_version"`) || !strings.Contains(out, `"phragma.release_acceptance.status.v1"`) || !strings.Contains(out, `"state"`) || !strings.Contains(out, `"ready"`) || !strings.Contains(out, `"not_applicable"`) || !strings.Contains(out, `"next_command"`) {
		t.Fatalf("json output missing release acceptance status:\n%s", out)
	}
}

func TestSystemReleaseAcceptanceStatusPropagatesStatusError(t *testing.T) {
	client := &fakeSystemReleaseAcceptanceClient{err: fmt.Errorf("down")}
	_, err := runSystemReleaseAcceptanceStatusForTest(client, systemReleaseAcceptanceOptions{})
	if err == nil || !strings.Contains(err.Error(), "query release acceptance status: down") {
		t.Fatalf("expected wrapped release acceptance status error, got %v", err)
	}
}

func TestSystemLogsPrintsFilteredRedactedEntries(t *testing.T) {
	client := &fakeSystemLogsClient{resp: &openngfwv1.ListSystemLogsResponse{
		SchemaVersion: "openngfw.system_logs.v1",
		Summary: &openngfwv1.SystemLogSummary{
			ScannedFiles: 2,
			ScannedLines: 50,
			MatchedLines: 1,
			Sources:      []string{"engine"},
			Engines:      []string{"suricata"},
			Severities:   []string{"warn"},
			Warnings:     []string{"one unreadable log file skipped"},
		},
		Entries: []*openngfwv1.SystemLogEntry{{
			Id:        "abc123",
			Timestamp: "2026-06-20T12:03:00Z",
			Source:    "engine",
			Engine:    "suricata",
			Severity:  "warn",
			Message:   "suricata engine degraded Bearer [redacted]",
			Facility:  "suricata",
			File:      "suricata.log",
			Line:      42,
		}},
	}}
	out, err := runSystemLogsForTest(client, systemLogsOptions{limit: 25, source: "engine", engine: "suricata", severity: "warn", query: "degraded"})
	if err != nil {
		t.Fatalf("runSystemLogs returned error: %v", err)
	}
	if client.req == nil || client.req.GetLimit() != 25 || client.req.GetSource() != "engine" || client.req.GetEngine() != "suricata" || client.req.GetSeverity() != "warn" || client.req.GetQuery() != "degraded" {
		t.Fatalf("unexpected request: %#v", client.req)
	}
	for _, want := range []string{
		"system logs",
		"scanned:         2 files, 50 lines",
		"matched:         1 lines",
		"sources:         engine",
		"engines:         suricata",
		"severities:      warn",
		"one unreadable log file skipped",
		"suricata engine degraded Bearer [redacted]",
		"file:         suricata.log:42",
		"id:           abc123",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/var/log") || strings.Contains(out, "abc.def") {
		t.Fatalf("system logs output leaked sensitive detail:\n%s", out)
	}
}

func TestSystemLogsPrintsJSON(t *testing.T) {
	client := &fakeSystemLogsClient{resp: &openngfwv1.ListSystemLogsResponse{
		SchemaVersion: "openngfw.system_logs.v1",
		Summary:       &openngfwv1.SystemLogSummary{MatchedLines: 0},
	}}
	out, err := runSystemLogsForTest(client, systemLogsOptions{outJSON: true})
	if err != nil {
		t.Fatalf("runSystemLogs json returned error: %v", err)
	}
	if !strings.Contains(out, `"schema_version"`) || !strings.Contains(out, `"openngfw.system_logs.v1"`) {
		t.Fatalf("json output missing system logs response:\n%s", out)
	}
}

func TestSystemNetworkPathProvePrintsPassiveProofDetails(t *testing.T) {
	client := &fakeSystemNetworkPathClient{resp: &openngfwv1.ProveNetworkPathResponse{
		State:                "degraded",
		Detail:               "kernel route was found with proof warning(s)",
		GeneratedAt:          "2026-06-22T15:04:05Z",
		RunningPolicyVersion: 7,
		Route: &openngfwv1.NetworkPathRouteProof{
			State:           "degraded",
			Destination:     "10.200.0.10",
			Gateway:         "198.51.100.1",
			Dev:             "ens3",
			PreferredSource: "10.0.0.10",
			Protocol:        "static",
			Table:           "254",
			Detail:          "kernel route dev ens3 differs from expected interface xfrm0",
		},
		Vpn: &openngfwv1.NetworkPathVpnProof{
			Kind:                  "ipsec",
			State:                 "active",
			MatchedTunnel:         "site-b",
			ChildSaCount:          1,
			InstalledChildSaCount: 1,
			Correlation:           "matched IPsec tunnel site-b with 1/1 installed CHILD SAs",
			Detail:                "IPsec tunnel site-b has installed CHILD SAs",
		},
		Mismatches: []*openngfwv1.NetworkPathMismatch{{
			Severity: "warning",
			Subject:  "route",
			Detail:   "route_device_mismatch=ens3 expected=xfrm0",
		}},
		Evidence: []string{
			"route_interface_index=2",
			"route_interface_identity=dev:ens3",
			"frr_route_proof=observed",
			"masquerade_egress_observed_source=10.0.0.10",
		},
		Warnings:    []string{"route_device_mismatch=ens3 expected=xfrm0"},
		Limitations: []string{"passive_route_lookup_only", "active_probe_not_sent"},
		CliHandoff:  "ngfwctl system network-path prove --src '10.0.0.10' --dst '10.200.0.10'",
		ApiHandoff:  "POST /v1/system/network-path:prove\n{\"srcIp\":\"10.0.0.10\"}",
	}}
	out, err := runSystemNetworkPathProveForTest(client, systemNetworkPathOptions{
		srcIP:           "10.0.0.10",
		destIP:          "10.200.0.10",
		protocol:        "udp",
		destPort:        4500,
		sourceInterface: "xfrm0",
		tunnelKind:      "ipsec",
		tunnelName:      "site-b",
	})
	if err != nil {
		t.Fatalf("runSystemNetworkPathProve returned error: %v", err)
	}
	if client.req == nil || client.req.GetProtocol() != openngfwv1.Protocol_PROTOCOL_UDP || client.req.GetDestPort() != 4500 || client.req.GetTunnel().GetName() != "site-b" {
		t.Fatalf("unexpected request: %#v", client.req)
	}
	for _, want := range []string{
		"network path proof: degraded",
		"gateway:        198.51.100.1",
		"preferred src:  10.0.0.10",
		"protocol/table: static/254",
		"correlation:    matched IPsec tunnel site-b with 1/1 installed CHILD SAs",
		"[warning] route: route_device_mismatch=ens3 expected=xfrm0",
		"evidence:",
		"route_interface_index=2",
		"frr_route_proof=observed",
		"masquerade_egress_observed_source=10.0.0.10",
		"limitations:      passive_route_lookup_only; active_probe_not_sent",
		"cli handoff:      ngfwctl system network-path prove",
		"api handoff:      POST /v1/system/network-path:prove",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func runSystemTuneForTest(opts systemTuneOptions) (string, error) {
	cmd := systemTuneCommandForTest(&opts)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

func systemTuneCommandForTest(opts *systemTuneOptions) *cobra.Command {
	return &cobra.Command{
		Use:           "tune",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.configPath == "" {
				return fmt.Errorf("test config path is required")
			}
			return runSystemTune(cmd.Context(), cmd, *opts)
		},
	}
}

func runSystemCaptureForTest(client systemCaptureClient, opts systemCaptureOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemCapture(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemAutomationReplayPlanForTest(opts systemAutomationReplayOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemAutomationReplayPlan(cmd, opts)
	return out.String(), err
}

func runSystemCaptureListForTest(client systemCaptureClient, opts systemCaptureOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemCaptureList(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemCaptureDownloadForTest(client systemCaptureClient, opts systemCaptureOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemCaptureDownload(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemCaptureRetentionForTest(client systemCaptureClient, opts systemCaptureOptions, state openngfwv1.PacketCaptureRetentionState) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemCaptureRetention(context.Background(), cmd, client, opts, state)
	return out.String(), err
}

func runSystemHAStatusForTest(client systemHAClient, opts systemHAOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemHAStatus(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemHAPullPolicyForTest(client systemHAClient, opts systemHAOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemHAPullPolicy(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemHAActivatePassiveForTest(client systemHAClient, opts systemHAOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemHAActivatePassive(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemTelemetryExportStatusForTest(client systemTelemetryClient, opts systemTelemetryOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemTelemetryExportStatus(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemReleaseAcceptanceStatusForTest(client systemReleaseAcceptanceClient, opts systemReleaseAcceptanceOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemReleaseAcceptanceStatus(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemLogsForTest(client systemLogsClient, opts systemLogsOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemLogs(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemEbpfReadinessForTest(client systemStatusClient, opts systemEbpfReadinessOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemEbpfReadiness(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runSystemNetworkPathProveForTest(client systemNetworkPathClient, opts systemNetworkPathOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runSystemNetworkPathProve(context.Background(), cmd, client, opts)
	return out.String(), err
}

type fakeSystemCaptureClient struct {
	planReq       *openngfwv1.PlanPacketCaptureRequest
	planResp      *openngfwv1.PlanPacketCaptureResponse
	planErr       error
	startReq      *openngfwv1.StartPacketCaptureRequest
	startResp     *openngfwv1.StartPacketCaptureResponse
	startErr      error
	listReq       *openngfwv1.ListPacketCapturesRequest
	listResp      *openngfwv1.ListPacketCapturesResponse
	listErr       error
	downloadReq   *openngfwv1.DownloadPacketCaptureRequest
	downloadResp  *httpbody.HttpBody
	downloadErr   error
	retentionReq  *openngfwv1.SetPacketCaptureRetentionRequest
	retentionResp *openngfwv1.SetPacketCaptureRetentionResponse
	retentionErr  error
}

type fakeSystemHAClient struct {
	statusReq    *openngfwv1.GetHighAvailabilityStatusRequest
	statusResp   *openngfwv1.GetHighAvailabilityStatusResponse
	statusErr    error
	req          *openngfwv1.PullHighAvailabilityPolicyRequest
	resp         *openngfwv1.PullHighAvailabilityPolicyResponse
	err          error
	activateReq  *openngfwv1.ActivateHighAvailabilityFailoverRequest
	activateResp *openngfwv1.ActivateHighAvailabilityFailoverResponse
	activateErr  error
}

type fakeSystemTelemetryClient struct {
	req  *openngfwv1.GetTelemetryExportStatusRequest
	resp *openngfwv1.GetTelemetryExportStatusResponse
	err  error
}

type fakeSystemReleaseAcceptanceClient struct {
	req  *openngfwv1.GetReleaseAcceptanceStatusRequest
	resp *openngfwv1.GetReleaseAcceptanceStatusResponse
	err  error
}

type fakeSystemLogsClient struct {
	req  *openngfwv1.ListSystemLogsRequest
	resp *openngfwv1.ListSystemLogsResponse
	err  error
}

type fakeSystemStatusClient struct {
	req  *openngfwv1.GetStatusRequest
	resp *openngfwv1.GetStatusResponse
	err  error
}

type fakeSystemNetworkPathClient struct {
	req  *openngfwv1.ProveNetworkPathRequest
	resp *openngfwv1.ProveNetworkPathResponse
	err  error
}

func (f *fakeSystemStatusClient) GetStatus(_ context.Context, req *openngfwv1.GetStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetStatusResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.GetStatusResponse{}, nil
}

func (f *fakeSystemNetworkPathClient) ProveNetworkPath(_ context.Context, req *openngfwv1.ProveNetworkPathRequest, _ ...grpc.CallOption) (*openngfwv1.ProveNetworkPathResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.ProveNetworkPathResponse{}, nil
}

func (f *fakeSystemHAClient) GetHighAvailabilityStatus(_ context.Context, req *openngfwv1.GetHighAvailabilityStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetHighAvailabilityStatusResponse, error) {
	f.statusReq = req
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.statusResp != nil {
		return f.statusResp, nil
	}
	return &openngfwv1.GetHighAvailabilityStatusResponse{}, nil
}

func (f *fakeSystemTelemetryClient) GetTelemetryExportStatus(_ context.Context, req *openngfwv1.GetTelemetryExportStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetTelemetryExportStatusResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeSystemReleaseAcceptanceClient) GetReleaseAcceptanceStatus(_ context.Context, req *openngfwv1.GetReleaseAcceptanceStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetReleaseAcceptanceStatusResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.GetReleaseAcceptanceStatusResponse{}, nil
}

func (f *fakeSystemLogsClient) ListSystemLogs(_ context.Context, req *openngfwv1.ListSystemLogsRequest, _ ...grpc.CallOption) (*openngfwv1.ListSystemLogsResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.ListSystemLogsResponse{}, nil
}

func (f *fakeSystemHAClient) PullHighAvailabilityPolicy(_ context.Context, req *openngfwv1.PullHighAvailabilityPolicyRequest, _ ...grpc.CallOption) (*openngfwv1.PullHighAvailabilityPolicyResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.PullHighAvailabilityPolicyResponse{}, nil
}

func (f *fakeSystemHAClient) ActivateHighAvailabilityFailover(_ context.Context, req *openngfwv1.ActivateHighAvailabilityFailoverRequest, _ ...grpc.CallOption) (*openngfwv1.ActivateHighAvailabilityFailoverResponse, error) {
	f.activateReq = req
	if f.activateErr != nil {
		return nil, f.activateErr
	}
	if f.activateResp != nil {
		return f.activateResp, nil
	}
	return &openngfwv1.ActivateHighAvailabilityFailoverResponse{}, nil
}

func (f *fakeSystemCaptureClient) PlanPacketCapture(_ context.Context, req *openngfwv1.PlanPacketCaptureRequest, _ ...grpc.CallOption) (*openngfwv1.PlanPacketCaptureResponse, error) {
	f.planReq = req
	if f.planErr != nil {
		return nil, f.planErr
	}
	if f.planResp != nil {
		return f.planResp, nil
	}
	return &openngfwv1.PlanPacketCaptureResponse{}, nil
}

func (f *fakeSystemCaptureClient) StartPacketCapture(_ context.Context, req *openngfwv1.StartPacketCaptureRequest, _ ...grpc.CallOption) (*openngfwv1.StartPacketCaptureResponse, error) {
	f.startReq = req
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.startResp != nil {
		return f.startResp, nil
	}
	return &openngfwv1.StartPacketCaptureResponse{}, nil
}

func (f *fakeSystemCaptureClient) ListPacketCaptures(_ context.Context, req *openngfwv1.ListPacketCapturesRequest, _ ...grpc.CallOption) (*openngfwv1.ListPacketCapturesResponse, error) {
	f.listReq = req
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listResp != nil {
		return f.listResp, nil
	}
	return &openngfwv1.ListPacketCapturesResponse{}, nil
}

func (f *fakeSystemCaptureClient) DownloadPacketCapture(_ context.Context, req *openngfwv1.DownloadPacketCaptureRequest, _ ...grpc.CallOption) (*httpbody.HttpBody, error) {
	f.downloadReq = req
	if f.downloadErr != nil {
		return nil, f.downloadErr
	}
	if f.downloadResp != nil {
		return f.downloadResp, nil
	}
	return &httpbody.HttpBody{}, nil
}

func (f *fakeSystemCaptureClient) SetPacketCaptureRetention(_ context.Context, req *openngfwv1.SetPacketCaptureRetentionRequest, _ ...grpc.CallOption) (*openngfwv1.SetPacketCaptureRetentionResponse, error) {
	f.retentionReq = req
	if f.retentionErr != nil {
		return nil, f.retentionErr
	}
	if f.retentionResp != nil {
		return f.retentionResp, nil
	}
	return &openngfwv1.SetPacketCaptureRetentionResponse{}, nil
}

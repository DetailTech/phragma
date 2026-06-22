//go:build integration

// Packet-capture end-to-end test: the SystemService starts a bounded real
// tcpdump capture, observes generated loopback traffic, writes the pcap, and
// records the audited privileged action.
package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/store"
)

type captureResult struct {
	resp *openngfwv1.StartPacketCaptureResponse
	err  error
}

func requirePacketCaptureHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("packet capture integration test requires Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("packet capture integration test requires root")
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("packet capture integration test requires tcpdump")
	}
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("loopback interface lo is unavailable")
	}
}

func TestPacketCaptureStartCapturesLoopbackTraffic(t *testing.T) {
	requirePacketCaptureHost(t)

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := &apiserver.SystemService{
		Store: st,
		Status: apiserver.SystemStatusConfig{
			LogDir: filepath.Join(dir, "log"),
		},
	}

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	srcPort := client.LocalAddr().(*net.UDPAddr).Port
	dst := server.LocalAddr().(*net.UDPAddr)
	req := &openngfwv1.StartPacketCaptureRequest{
		Interface:       "lo",
		Protocol:        openngfwv1.Protocol_PROTOCOL_UDP,
		SrcIp:           "127.0.0.1",
		SrcPort:         uint32(srcPort),
		DestIp:          "127.0.0.1",
		DestPort:        uint32(dst.Port),
		DurationSeconds: 5,
		PacketCount:     1,
		SnaplenBytes:    256,
		Label:           "it-loopback",
		AckCapture:      true,
	}

	done := make(chan captureResult, 1)
	go func() {
		resp, err := svc.StartPacketCapture(context.Background(), req)
		done <- captureResult{resp: resp, err: err}
	}()

	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 80; i++ {
		if _, err := client.WriteToUDP([]byte(fmt.Sprintf("phragma-capture-%02d", i)), dst); err != nil {
			t.Fatal(err)
		}
		select {
		case result := <-done:
			assertCompletedPacketCapture(t, result, st, dst.Port, dir)
			return
		default:
		}
		time.Sleep(40 * time.Millisecond)
	}

	select {
	case result := <-done:
		assertCompletedPacketCapture(t, result, st, dst.Port, dir)
	case <-time.After(8 * time.Second):
		t.Fatal("packet capture did not complete")
	}
}

func assertCompletedPacketCapture(t *testing.T, result captureResult, st *store.Store, dstPort int, dir string) {
	t.Helper()
	if result.err != nil {
		t.Fatalf("StartPacketCapture returned error: %v", result.err)
	}
	if result.resp == nil || result.resp.GetJob() == nil {
		t.Fatalf("StartPacketCapture returned empty response: %#v", result.resp)
	}
	job := result.resp.GetJob()
	if job.GetState() != "completed" {
		t.Fatalf("job state = %q, want completed: %#v", job.GetState(), job)
	}
	plan := job.GetPlan()
	if plan.GetOutputPath() == "" {
		t.Fatal("capture output path is empty")
	}
	if want := filepath.Join(dir, "log", "pcap", "phragma-it-loopback-"); !strings.Contains(plan.GetOutputPath(), want) {
		t.Fatalf("output path = %q, want prefix containing %q", plan.GetOutputPath(), want)
	}
	if job.GetBytesWritten() == 0 {
		t.Fatalf("bytes written = 0 for %s", plan.GetOutputPath())
	}
	if job.GetSha256() == "" {
		t.Fatalf("sha256 is empty for %s", plan.GetOutputPath())
	}

	out, err := exec.Command("tcpdump", "-nn", "-r", plan.GetOutputPath(), "-c", "1").CombinedOutput()
	if err != nil {
		t.Fatalf("tcpdump could not read captured packet: %v\n%s", err, out)
	}
	decoded := string(out)
	if !strings.Contains(decoded, "127.0.0.1") || !strings.Contains(decoded, strconv.Itoa(dstPort)) {
		t.Fatalf("decoded capture does not include expected loopback tuple for port %d:\n%s", dstPort, decoded)
	}

	entries, err := st.ListAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "packet-capture" {
		t.Fatalf("audit entries = %#v, want packet-capture", entries)
	}
	if !strings.Contains(entries[0].Detail, "completed") || !strings.Contains(entries[0].Detail, plan.GetOutputPath()) {
		t.Fatalf("audit detail = %q, want completed capture with output path", entries[0].Detail)
	}
}

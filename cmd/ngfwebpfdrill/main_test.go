package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteProbesCommand(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"write-probes", "--build-dir", dir}, &stdout, &stderr); err != nil {
		t.Fatalf("write-probes failed: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "xdp_probe_source=") || !strings.Contains(stdout.String(), "tc_probe_source=") {
		t.Fatalf("unexpected stdout:\n%s", stdout.String())
	}
	assertContains(t, filepath.Join(dir, "xdp_probe.c"), "XDP_PASS")
	assertContains(t, filepath.Join(dir, "tc_probe.c"), "TC_ACT_OK")
}

func TestManifestCommand(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"write-probes", "--build-dir", dir}, &stdout, &stderr); err != nil {
		t.Fatalf("write-probes failed: %v", err)
	}
	for name, body := range map[string]string{
		"xdp_probe.o": "xdp object bytes",
		"tc_probe.o":  "tc object bytes",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	manifestPath := filepath.Join(dir, "manifest.txt")
	if err := run([]string{"manifest", "--build-dir", dir, "--iface", "dummy0", "--output", manifestPath}, &stdout, &stderr); err != nil {
		t.Fatalf("manifest failed: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "manifest="+manifestPath) {
		t.Fatalf("unexpected stdout:\n%s", stdout.String())
	}
	assertContains(t, manifestPath, "drill_schema=phragma.ebpf.ol9.attach-drill.v1")
	assertContains(t, manifestPath, "active_dataplane=nftables/conntrack")
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"unknown"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), `unknown command "unknown"`) {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func assertContains(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(body), want) {
		t.Fatalf("%s missing %q:\n%s", path, want, string(body))
	}
}

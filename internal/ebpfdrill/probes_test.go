package ebpfdrill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeSourcesArePassThroughGPLPrograms(t *testing.T) {
	for name, source := range map[string]string{
		"xdp": XDPProbeSource,
		"tc":  TCProbeSource,
	} {
		if !strings.Contains(source, `char _license[] SEC("license") = "GPL";`) {
			t.Fatalf("%s probe source missing GPL license declaration:\n%s", name, source)
		}
	}
	for _, want := range []string{`SEC("xdp")`, "XDP_PASS"} {
		if !strings.Contains(XDPProbeSource, want) {
			t.Fatalf("XDP probe source missing %q:\n%s", want, XDPProbeSource)
		}
	}
	for _, want := range []string{`SEC("tc")`, "TC_ACT_OK"} {
		if !strings.Contains(TCProbeSource, want) {
			t.Fatalf("tc probe source missing %q:\n%s", want, TCProbeSource)
		}
	}
}

func TestWriteProbeSources(t *testing.T) {
	dir := t.TempDir()
	paths, err := WriteProbeSources(dir)
	if err != nil {
		t.Fatalf("WriteProbeSources failed: %v", err)
	}
	if paths.XDPSource != filepath.Join(dir, XDPProbeFile) {
		t.Fatalf("unexpected XDP source path: %s", paths.XDPSource)
	}
	assertFileContains(t, paths.XDPSource, "XDP_PASS")
	assertFileContains(t, paths.TCSource, "TC_ACT_OK")
}

func TestManifestPreservesAttachDrillContract(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteProbeSources(dir); err != nil {
		t.Fatalf("WriteProbeSources failed: %v", err)
	}
	for name, body := range map[string]string{
		XDPObjectFile: "xdp object bytes",
		TCObjectFile:  "tc object bytes",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	manifest, err := Manifest(DefaultManifestOptions(dir, "dummy0"))
	if err != nil {
		t.Fatalf("Manifest failed: %v", err)
	}
	for _, want := range []string{
		"drill_tool=release/ebpf-ol9-attach-drill.sh",
		"first_party_helper=cmd/ngfwebpfdrill",
		"drill_mode=run",
		"drill_schema=phragma.ebpf.ol9.attach-drill.v1",
		"interface=dummy0",
		"xdp_probe_source=xdp_probe.c",
		"xdp_probe_object=xdp_probe.o",
		"tc_probe_source=tc_probe.c",
		"tc_probe_object=tc_probe.o",
		"active_dataplane=nftables/conntrack",
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("manifest missing %q:\n%s", want, manifest)
		}
	}
	for _, forbidden := range []string{dir, "missing"} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("manifest leaked unexpected text %q:\n%s", forbidden, manifest)
		}
	}
}

func TestManifestRequiresInterfaceAndObjects(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteProbeSources(dir); err != nil {
		t.Fatalf("WriteProbeSources failed: %v", err)
	}
	if _, err := Manifest(DefaultManifestOptions(dir, "")); err == nil || !strings.Contains(err.Error(), "interface is required") {
		t.Fatalf("expected interface error, got %v", err)
	}
	if _, err := Manifest(DefaultManifestOptions(dir, "dummy0")); err == nil || !strings.Contains(err.Error(), "hash XDP object") {
		t.Fatalf("expected missing object error, got %v", err)
	}
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(body), want) {
		t.Fatalf("%s missing %q:\n%s", path, want, string(body))
	}
}

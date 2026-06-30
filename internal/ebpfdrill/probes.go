// Package ebpfdrill owns the minimal loadable probes used by the OL9 attach
// drill. These probes are pass-through evidence artifacts; they are not the
// active dataplane and do not replace nftables/conntrack.
package ebpfdrill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// XDPProbeFile is the generated XDP probe source filename.
	XDPProbeFile = "xdp_probe.c"
	// TCProbeFile is the generated traffic-control probe source filename.
	TCProbeFile = "tc_probe.c"

	// XDPObjectFile is the expected compiled XDP object filename.
	XDPObjectFile = "xdp_probe.o"
	// TCObjectFile is the expected compiled traffic-control object filename.
	TCObjectFile = "tc_probe.o"

	// ManifestSchema identifies the attach-drill evidence manifest format.
	ManifestSchema = "phragma.ebpf.ol9.attach-drill.v1"
	// ActiveDataplane names the production dataplane that the drill does not replace.
	ActiveDataplane = "nftables/conntrack"

	// XDPProbeSource is the pass-through XDP program used by the attach drill.
	XDPProbeSource = `#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int xdp_probe(struct xdp_md *ctx) {
  return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
`

	// TCProbeSource is the pass-through traffic-control program used by the attach drill.
	TCProbeSource = `#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("tc")
int tc_probe(struct __sk_buff *skb) {
  return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
`
)

// ProbePaths contains the generated probe source paths.
type ProbePaths struct {
	XDPSource string
	TCSource  string
}

// ManifestOptions identifies the drill interface and source and object artifacts.
type ManifestOptions struct {
	Interface     string
	XDPSourcePath string
	XDPObjectPath string
	TCSourcePath  string
	TCObjectPath  string
}

// WriteProbeSources writes the first-party pass-through probes into buildDir.
func WriteProbeSources(buildDir string) (ProbePaths, error) {
	buildDir = strings.TrimSpace(buildDir)
	if buildDir == "" {
		return ProbePaths{}, fmt.Errorf("build dir is required")
	}
	if err := os.MkdirAll(buildDir, 0o700); err != nil {
		return ProbePaths{}, fmt.Errorf("create build dir: %w", err)
	}
	paths := ProbePaths{
		XDPSource: filepath.Join(buildDir, XDPProbeFile),
		TCSource:  filepath.Join(buildDir, TCProbeFile),
	}
	if err := os.WriteFile(paths.XDPSource, []byte(XDPProbeSource), 0o600); err != nil {
		return ProbePaths{}, fmt.Errorf("write XDP probe source: %w", err)
	}
	if err := os.WriteFile(paths.TCSource, []byte(TCProbeSource), 0o600); err != nil {
		return ProbePaths{}, fmt.Errorf("write tc probe source: %w", err)
	}
	return paths, nil
}

// DefaultManifestOptions derives the standard drill artifact paths for buildDir.
func DefaultManifestOptions(buildDir, iface string) ManifestOptions {
	return ManifestOptions{
		Interface:     iface,
		XDPSourcePath: filepath.Join(buildDir, XDPProbeFile),
		XDPObjectPath: filepath.Join(buildDir, XDPObjectFile),
		TCSourcePath:  filepath.Join(buildDir, TCProbeFile),
		TCObjectPath:  filepath.Join(buildDir, TCObjectFile),
	}
}

// Manifest renders a custody manifest after hashing all drill artifacts.
func Manifest(opts ManifestOptions) (string, error) {
	if strings.TrimSpace(opts.Interface) == "" {
		return "", fmt.Errorf("interface is required")
	}
	xdpSourceHash, err := sha256File(opts.XDPSourcePath)
	if err != nil {
		return "", fmt.Errorf("hash XDP source: %w", err)
	}
	xdpObjectHash, err := sha256File(opts.XDPObjectPath)
	if err != nil {
		return "", fmt.Errorf("hash XDP object: %w", err)
	}
	tcSourceHash, err := sha256File(opts.TCSourcePath)
	if err != nil {
		return "", fmt.Errorf("hash tc source: %w", err)
	}
	tcObjectHash, err := sha256File(opts.TCObjectPath)
	if err != nil {
		return "", fmt.Errorf("hash tc object: %w", err)
	}

	return fmt.Sprintf(`drill_tool=release/ebpf-ol9-attach-drill.sh
first_party_helper=cmd/ngfwebpfdrill
drill_mode=run
drill_schema=%s
interface=%s
xdp_probe_source=%s
xdp_probe_source_sha256=%s
xdp_probe_object=%s
xdp_probe_object_sha256=%s
tc_probe_source=%s
tc_probe_source_sha256=%s
tc_probe_object=%s
tc_probe_object_sha256=%s
active_dataplane=%s
`,
		ManifestSchema,
		opts.Interface,
		filepath.Base(opts.XDPSourcePath),
		xdpSourceHash,
		filepath.Base(opts.XDPObjectPath),
		xdpObjectHash,
		filepath.Base(opts.TCSourcePath),
		tcSourceHash,
		filepath.Base(opts.TCObjectPath),
		tcObjectHash,
		ActiveDataplane,
	), nil
}

// WriteManifest renders and writes the attach-drill custody manifest.
func WriteManifest(path string, opts ManifestOptions) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("manifest output path is required")
	}
	manifest, err := Manifest(opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func sha256File(path string) (digest string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

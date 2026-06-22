package tuning

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigTextContainsCanonicalBaseline(t *testing.T) {
	text := ConfigText()
	for _, want := range []string{
		"# profile: appliance",
		"net.ipv4.ip_forward = 1",
		"net.ipv4.conf.all.rp_filter = 0",
		"net.ipv4.conf.default.rp_filter = 0",
		"net.netfilter.nf_conntrack_max = 1048576",
		"net.core.somaxconn = 4096",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in config:\n%s", want, text)
		}
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatal("config text must end with newline")
	}
}

func TestConfigTextForThroughputProfile(t *testing.T) {
	text, err := ConfigTextForProfile(ThroughputProfile)
	if err != nil {
		t.Fatalf("ConfigTextForProfile returned error: %v", err)
	}
	for _, want := range []string{
		"# profile: throughput",
		"net.netfilter.nf_conntrack_max = 4194304",
		"net.core.somaxconn = 8192",
		"net.core.netdev_max_backlog = 250000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in config:\n%s", want, text)
		}
	}
}

func TestConfigTextRejectsUnknownProfile(t *testing.T) {
	_, err := ConfigTextForProfile("oversized")
	if err == nil || !strings.Contains(err.Error(), "valid profiles: appliance, throughput") {
		t.Fatalf("expected valid profile error, got %v", err)
	}
}

func TestWriteConfigCreatesParentAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl.d", "99-openngfw.conf")
	if err := WriteConfig(path); err != nil {
		t.Fatalf("WriteConfig returned error: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(raw) != ConfigText() {
		t.Fatalf("config mismatch:\n%s", raw)
	}
}

func TestApplyLiveAppliesExposedKeysAndSkipsMissing(t *testing.T) {
	root := t.TempDir()
	exposed := []string{
		"net.ipv4.ip_forward",
		"net.netfilter.nf_conntrack_max",
	}
	for _, key := range exposed {
		path := filepath.Join(root, strings.ReplaceAll(key, ".", string(os.PathSeparator)))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir fixture: %v", err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	var calls []string
	results, err := ApplyLive(context.Background(), root, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...)...)
		return []byte(strings.Join(append([]string{name}, args...), " ")), nil
	})
	if err != nil {
		t.Fatalf("ApplyLive returned error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{
		"sysctl", "-w", "net.ipv4.ip_forward=1",
		"sysctl", "-w", "net.netfilter.nf_conntrack_max=1048576",
	}) {
		t.Fatalf("calls = %#v", calls)
	}
	if len(results) != len(Requirements) {
		t.Fatalf("results = %d, want %d", len(results), len(Requirements))
	}
	var applied, skipped int
	for _, result := range results {
		if result.Applied {
			applied++
		}
		if result.Skipped {
			skipped++
		}
	}
	if applied != 2 || skipped != len(Requirements)-2 {
		t.Fatalf("applied=%d skipped=%d", applied, skipped)
	}
}

func TestApplyLiveThroughputProfile(t *testing.T) {
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
	results, err := ApplyLiveProfile(context.Background(), root, ThroughputProfile, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...)...)
		return []byte(strings.Join(append([]string{name}, args...), " ")), nil
	})
	if err != nil {
		t.Fatalf("ApplyLiveProfile returned error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{
		"sysctl", "-w", "net.netfilter.nf_conntrack_max=4194304",
		"sysctl", "-w", "net.core.somaxconn=8192",
		"sysctl", "-w", "net.core.netdev_max_backlog=250000",
	}) {
		t.Fatalf("calls = %#v", calls)
	}
	if len(results) != len(Requirements)+1 {
		t.Fatalf("results = %d, want throughput baseline plus netdev backlog", len(results))
	}
}

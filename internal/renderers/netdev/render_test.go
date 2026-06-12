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

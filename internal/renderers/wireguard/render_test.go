package wireguard

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderEmpty(t *testing.T) {
	got, err := Render(&compiler.IR{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), InterfaceMarker) {
		t.Fatalf("empty IR must render no interfaces: %q", got)
	}
}

func TestRender(t *testing.T) {
	ir := &compiler.IR{VPN: &compiler.VPNIR{Wireguard: []compiler.WireguardIR{{
		Name:           "wg0",
		Address:        netip.MustParsePrefix("10.99.0.1/24"),
		ListenPort:     51820,
		PrivateKeyFile: "/etc/openngfw/keys/wg0.key",
		Peers: []compiler.WireguardPeerIR{{
			Name:       "laptop",
			PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Endpoint:   "203.0.113.5:51820",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			Keepalive:  25,
		}},
	}}}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"interface wg0",
		"address 10.99.0.1/24",
		"listen-port 51820",
		"private-key-file /etc/openngfw/keys/wg0.key",
		"peer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"  endpoint 203.0.113.5:51820",
		"  allowed-ips 10.99.0.2/32",
		"  keepalive 25",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("artifact missing %q:\n%s", want, cfg)
		}
	}
}

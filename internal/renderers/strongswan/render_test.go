package strongswan

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderDisabled(t *testing.T) {
	got, err := Render(&compiler.IR{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ModeMarker+ModeDisabled+"\n" {
		t.Fatalf("disabled artifact = %q", got)
	}
}

func TestRender(t *testing.T) {
	ir := &compiler.IR{VPN: &compiler.VPNIR{IPsec: []compiler.IpsecIR{{
		Name:          "site-b",
		LocalAddress:  "198.51.100.1",
		RemoteAddress: "203.0.113.1",
		LocalSubnets:  []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		RemoteSubnets: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.30.0.0/24")},
		PSKFile:       "/etc/openngfw/secrets/site-b.conf",
		IKEProposal:   "aes256-sha256-modp2048",
		ESPProposal:   "aes256-sha256-modp2048",
		Initiate:      true,
	}}}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		"site-b {",
		"local_addrs = 198.51.100.1",
		"remote_addrs = 203.0.113.1",
		"proposals = aes256-sha256-modp2048",
		"local_ts = 10.10.0.0/24",
		"remote_ts = 10.20.0.0/24,10.30.0.0/24",
		"start_action = start",
		"include /etc/openngfw/secrets/site-b.conf",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "secret") && strings.Contains(cfg, "= \"") {
		t.Error("artifact must never contain literal secrets")
	}
}

func TestResponderUsesTrap(t *testing.T) {
	ir := &compiler.IR{VPN: &compiler.VPNIR{IPsec: []compiler.IpsecIR{{
		Name: "passive", LocalAddress: "%any", RemoteAddress: "203.0.113.1",
		LocalSubnets:  []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		RemoteSubnets: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
		PSKFile:       "/etc/openngfw/secrets/p.conf",
		IKEProposal:   "aes256-sha256-modp2048", ESPProposal: "aes256-sha256-modp2048",
	}}}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "start_action = trap") {
		t.Errorf("responder tunnel must use trap, got:\n%s", got)
	}
}

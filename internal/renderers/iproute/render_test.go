package iproute

import (
	"net/netip"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRender(t *testing.T) {
	ir := &compiler.IR{Routes: []compiler.RouteIR{
		{Destination: netip.MustParsePrefix("192.168.50.0/24"), Via: netip.MustParseAddr("10.10.0.254")},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Via: netip.MustParseAddr("198.51.100.1"), Interface: "eth0", Metric: 100},
		{Destination: netip.MustParsePrefix("10.99.0.0/16"), Interface: "eth2"},
	}}
	got, err := Render(ir)
	if err != nil {
		t.Fatal(err)
	}
	want := `route replace 192.168.50.0/24 via 10.10.0.254
route replace 0.0.0.0/0 via 198.51.100.1 dev eth0 metric 100
route replace 10.99.0.0/16 dev eth2
`
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderEmpty(t *testing.T) {
	got, err := Render(&compiler.IR{})
	if err != nil || len(got) != 0 {
		t.Errorf("empty IR should render empty script, got %q err %v", got, err)
	}
}

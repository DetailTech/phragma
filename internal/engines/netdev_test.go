package engines

import (
	"context"
	"testing"
)

func TestParseNetdev(t *testing.T) {
	artifact := []byte("# header\nlink eth0 mtu 9000\noffload eth1 off\n")
	got, err := parseNetdev(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].kind != "link" || got[0].mtu != "9000" || got[1].kind != "offload" || got[1].iface != "eth1" {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestParseNetdevRejectsJunk(t *testing.T) {
	for _, bad := range []string{"link eth0 9000\n", "offload eth1 on\n", "bogus\n"} {
		if _, err := parseNetdev([]byte(bad)); err == nil {
			t.Errorf("expected parse error for %q", bad)
		}
	}
}

func TestNetdevValidateEmptyArtifact(t *testing.T) {
	n := &Netdev{}
	if err := n.Validate(context.Background(), []byte("# nothing managed\n")); err != nil {
		t.Fatal(err)
	}
}

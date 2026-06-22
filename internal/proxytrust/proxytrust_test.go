package proxytrust

import "testing"

func TestNewNormalizesAndDeduplicatesCIDRs(t *testing.T) {
	set, err := New([]string{" 10.0.0.1/24 ", "10.0.0.0/24", "", "2001:db8::1/64"})
	if err != nil {
		t.Fatal(err)
	}
	got := set.NormalizedCIDRs()
	want := []string{"10.0.0.0/24", "2001:db8::/64"}
	if len(got) != len(want) {
		t.Fatalf("normalized = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized = %#v, want %#v", got, want)
		}
	}
}

func TestNewRejectsInvalidCIDR(t *testing.T) {
	if _, err := New([]string{"10.0.0.5"}); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}

func TestTrustsRemoteAddr(t *testing.T) {
	set, err := New([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !set.TrustsRemoteAddr("10.0.0.10:443") {
		t.Fatal("expected proxy peer to be trusted")
	}
	if set.TrustsRemoteAddr("203.0.113.10:443") {
		t.Fatal("expected public peer to be untrusted")
	}
}

func TestForwardedClientIPUsesRightmostUntrustedAddress(t *testing.T) {
	set, err := New([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if got := set.ForwardedClientIP("198.51.100.1, 198.51.100.2, 10.0.0.10"); got != "198.51.100.2" {
		t.Fatalf("ForwardedClientIP() = %q, want rightmost untrusted", got)
	}
	if got := set.ForwardedClientIP("10.0.0.20, 10.0.0.10"); got != "10.0.0.20" {
		t.Fatalf("ForwardedClientIP() = %q, want leftmost all-trusted", got)
	}
	if got := set.ForwardedClientIP("198.51.100.1, not-an-ip"); got != "" {
		t.Fatalf("ForwardedClientIP() = %q, want invalid chain ignored", got)
	}
}

func TestForwardedProtoRequiresTrustedPeer(t *testing.T) {
	set, err := New([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if got := set.ForwardedProto("10.0.0.10:443", "https, http"); got != "https" {
		t.Fatalf("ForwardedProto() = %q, want https", got)
	}
	if got := set.ForwardedProto("203.0.113.10:443", "https"); got != "" {
		t.Fatalf("ForwardedProto() = %q, want untrusted peer ignored", got)
	}
	if got := set.ForwardedProto("10.0.0.10:443", "ftp"); got != "" {
		t.Fatalf("ForwardedProto() = %q, want invalid scheme ignored", got)
	}
}

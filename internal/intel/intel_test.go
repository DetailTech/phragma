package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestCheckEnableLicenseGate(t *testing.T) {
	spamhaus, ok := Lookup("spamhaus-drop")
	if !ok {
		t.Fatal("spamhaus-drop missing from registry")
	}
	// Non-commercial deployment: fine.
	if err := CheckEnable(spamhaus, false); err != nil {
		t.Errorf("non-commercial use should be allowed: %v", err)
	}
	// Commercial deployment: the registry must refuse.
	if err := CheckEnable(spamhaus, true); err == nil {
		t.Error("commercial use of a non-commercial feed must be refused")
	}

	feodo, _ := Lookup("feodo-tracker")
	if err := CheckEnable(feodo, true); err != nil {
		t.Errorf("CC0 feed must allow commercial use: %v", err)
	}
}

func TestRegistryComplete(t *testing.T) {
	for _, f := range Builtins() {
		if f.Name == "" || f.URL == "" || f.License == "" || f.Description == "" {
			t.Errorf("feed %+v has incomplete registry metadata", f)
		}
	}
}

func TestParseFormats(t *testing.T) {
	input := `# comment
; also comment
192.0.2.1
198.51.100.0/24
203.0.113.7 ; SBL12345
2001:db8::/32

junk line that is not an ip
`
	prefixes, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1/32", "198.51.100.0/24", "203.0.113.7/32", "2001:db8::/32"}
	if len(prefixes) != len(want) {
		t.Fatalf("parsed %v, want %v", prefixes, want)
	}
	for i, w := range want {
		if prefixes[i].String() != w {
			t.Errorf("prefixes[%d] = %s, want %s", i, prefixes[i], w)
		}
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# test feed\n192.0.2.10\n192.0.2.0/28\n"))
	}))
	defer srv.Close()

	prefixes, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %v", prefixes)
	}
}

func TestEnabledFeedsLicenseEnforcement(t *testing.T) {
	in := &openngfwv1.Intel{
		CommercialUse: true,
		Feeds:         []*openngfwv1.FeedEnable{{Name: "spamhaus-drop", Enabled: true}},
	}
	if _, err := EnabledFeeds(in); err == nil {
		t.Fatal("EnabledFeeds must enforce the license gate")
	}

	in.CommercialUse = false
	feeds, err := EnabledFeeds(in)
	if err != nil || len(feeds) != 1 {
		t.Fatalf("feeds=%v err=%v", feeds, err)
	}
}

func TestEnabledFeedsUnknown(t *testing.T) {
	in := &openngfwv1.Intel{Feeds: []*openngfwv1.FeedEnable{{Name: "nope", Enabled: true}}}
	if _, err := EnabledFeeds(in); err == nil {
		t.Fatal("unknown feed must error")
	}
}

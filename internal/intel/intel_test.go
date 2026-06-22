package intel

import (
	"context"
	"io"
	"net/http"
	"net/netip"
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
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("# test feed\n192.0.2.10\n192.0.2.0/28\n")),
			Header:     make(http.Header),
		}, nil
	})}

	prefixes, err := Fetch(context.Background(), client, "https://feeds.example.com/blocklist.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %v", prefixes)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestFetchRejectsUnsafeFeedURLs(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/feed.txt",
		"http://10.0.0.10/feed.txt",
		"http://169.254.169.254/opc/v2/instance/",
		"http://[::1]/feed.txt",
		"http://metadata.google.internal/feed.txt",
		"http://feed.local/blocklist.txt",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := Fetch(context.Background(), nil, raw); err == nil {
				t.Fatalf("expected unsafe feed URL %q to be rejected", raw)
			}
		})
	}
}

func TestDefaultHTTPClientRejectsUnsafeRedirect(t *testing.T) {
	client := DefaultHTTPClient()
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://127.0.0.1/feed.txt"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	if _, err := Fetch(context.Background(), client, "https://feeds.example.com/blocklist.txt"); err == nil {
		t.Fatal("expected unsafe redirect destination to be rejected")
	}
}

func TestNormalizePrefixesRemovesNestedIntervals(t *testing.T) {
	in := map[netip.Prefix]bool{
		netip.MustParsePrefix("204.236.0.0/14"):  true,
		netip.MustParsePrefix("204.236.0.0/16"):  true,
		netip.MustParsePrefix("204.236.10.0/24"): true,
		netip.MustParsePrefix("198.51.100.4/24"): true, // host bits should be masked
		netip.MustParsePrefix("198.51.100.0/25"): true,
		netip.MustParsePrefix("2001:db8::/32"):   true,
		netip.MustParsePrefix("2001:db8:1::/48"): true,
	}

	got := normalizePrefixes(in)
	want := []string{"198.51.100.0/24", "204.236.0.0/14", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("normalizePrefixes = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("normalizePrefixes[%d] = %s, want %s (all: %v)", i, got[i], w, got)
		}
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

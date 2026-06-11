//go:build integration

// M4 end-to-end test: a blocklist feed served over HTTP is enforced as
// an nftables set by the intel updater, blocks live traffic, and is
// toggleable through policy. The feed-license registry gate is also
// exercised through the real commit path.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/intel"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestM4IntelEnforcement(t *testing.T) {
	requireRoot(t)
	setupTopology(t)
	startEchoServer(t)

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sup := engines.NewSupervisor(
		&engines.Nftables{StateDir: dir},
		&engines.Routes{StateDir: dir},
	)
	opts := renderers.DefaultOptions(dir, filepath.Join(dir, "log"))
	srv := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
	updater := &intel.Updater{RunningPolicy: func() (*openngfwv1.Policy, error) {
		p, _, err := st.GetRunning()
		return p, err
	}}

	// Feed server: blocklists the client's IP.
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# test blocklist\n" + clientIP + "\n"))
	}))
	defer feed.Close()

	// 1. Allow policy with the custom feed enabled.
	pol := allowPolicy()
	pol.Intel = &openngfwv1.Intel{
		CustomFeeds: []*openngfwv1.CustomFeed{{Name: "test-blocklist", Url: feed.URL}},
	}
	mustCommit(t, srv, pol, "enable intel")

	// Sets exist but are empty until the updater runs: traffic passes.
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("traffic should pass before the blocklist is populated")
	}

	n, err := updater.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 programmed entry, got %d", n)
	}
	if tcpReachable(serverIP, 8080) {
		t.Fatal("blocklisted client IP was not dropped")
	}
	ruleset := run(t, "nft", "list", "table", "inet", "openngfw")
	if !strings.Contains(ruleset, clientIP) {
		t.Fatalf("client IP missing from intel set:\n%s", ruleset)
	}

	// 2. Toggle the feed off through policy: traffic passes again.
	mustCommit(t, srv, allowPolicy(), "disable intel")
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("disabling intel did not restore traffic")
	}

	// 3. License gate: a commercial deployment cannot commit a policy
	// enabling a non-commercial feed.
	gated := allowPolicy()
	gated.Intel = &openngfwv1.Intel{
		CommercialUse: true,
		Feeds:         []*openngfwv1.FeedEnable{{Name: "spamhaus-drop", Enabled: true}},
	}
	ctx := context.Background()
	if _, err := srv.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: gated}); err != nil {
		t.Fatal(err)
	}
	_, err = srv.Commit(ctx, &openngfwv1.CommitRequest{Comment: "must fail"})
	if err == nil || !strings.Contains(err.Error(), "forbids commercial use") {
		t.Fatalf("license gate did not block the commit: %v", err)
	}
}

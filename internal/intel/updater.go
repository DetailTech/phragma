package intel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// Set names inside the openngfw nftables table. The policy renderer
// declares them whenever intel is enabled; the updater only swaps their
// elements — never the ruleset.
const (
	SetV4 = "intel4"
	SetV6 = "intel6"
)

// Updater fetches enabled feeds and programs the blocklist sets. Set
// contents are dynamic data, not policy: they bypass candidate/commit
// by design and are repopulated after every commit (table replace
// clears sets).
type Updater struct {
	// NftBinary defaults to "nft".
	NftBinary string
	// Client defaults to DefaultHTTPClient().
	Client *http.Client
	// RunningPolicy returns the current running policy.
	RunningPolicy func() (*openngfwv1.Policy, error)

	mu          sync.Mutex
	lastEntries int
	lastRefresh time.Time
}

// Status returns the last refresh result.
func (u *Updater) Status() (entries int, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastEntries, u.lastRefresh
}

// Refresh fetches all enabled feeds and atomically replaces the
// blocklist sets. It returns the number of programmed entries.
func (u *Updater) Refresh(ctx context.Context) (int, error) {
	pol, err := u.RunningPolicy()
	if err != nil {
		return 0, fmt.Errorf("read running policy: %w", err)
	}
	feeds, err := EnabledFeeds(pol.GetIntel())
	if err != nil {
		return 0, err
	}
	if len(feeds) == 0 {
		return 0, nil
	}

	client := u.Client
	if client == nil {
		client = DefaultHTTPClient()
	}

	merged := map[netip.Prefix]bool{}
	for _, f := range feeds {
		prefixes, err := Fetch(ctx, client, f.URL)
		if err != nil {
			// One dead feed must not zero out protection from the rest,
			// but the failure is surfaced in logs and the error return.
			slog.Error("intel feed fetch failed", "feed", f.Name, "error", err)
			continue
		}
		slog.Info("intel feed fetched", "feed", f.Name, "entries", len(prefixes))
		for _, p := range prefixes {
			merged[p] = true
		}
	}

	var v4, v6 []string
	for p := range merged {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)

	if err := u.applySets(ctx, v4, v6); err != nil {
		return 0, err
	}
	u.mu.Lock()
	u.lastEntries = len(v4) + len(v6)
	u.lastRefresh = time.Now().UTC()
	u.mu.Unlock()
	return len(v4) + len(v6), nil
}

// applySets builds one atomic nft script that flushes and refills both
// sets.
func (u *Updater) applySets(ctx context.Context, v4, v6 []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet openngfw %s\n", SetV4)
	fmt.Fprintf(&b, "flush set inet openngfw %s\n", SetV6)
	for _, chunk := range chunks(v4, 1000) {
		fmt.Fprintf(&b, "add element inet openngfw %s { %s }\n", SetV4, strings.Join(chunk, ", "))
	}
	for _, chunk := range chunks(v6, 1000) {
		fmt.Fprintf(&b, "add element inet openngfw %s { %s }\n", SetV6, strings.Join(chunk, ", "))
	}

	bin := u.NftBinary
	if bin == "" {
		bin = "nft"
	}
	tmp, err := os.CreateTemp("", "openngfw-intel-*.nft")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, bin, "-f", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("program intel sets: %w: %s", err, out)
	}
	return nil
}

func chunks(items []string, size int) [][]string {
	var out [][]string
	for len(items) > size {
		out = append(out, items[:size])
		items = items[size:]
	}
	if len(items) > 0 {
		out = append(out, items)
	}
	return out
}

// EnabledFeeds resolves the policy's intel section against the registry,
// enforcing license constraints.
func EnabledFeeds(intel *openngfwv1.Intel) ([]Feed, error) {
	if intel == nil {
		return nil, nil
	}
	var out []Feed
	for _, fe := range intel.GetFeeds() {
		if !fe.GetEnabled() {
			continue
		}
		f, ok := Lookup(fe.GetName())
		if !ok {
			return nil, fmt.Errorf("unknown intel feed %q", fe.GetName())
		}
		if err := CheckEnable(f, intel.GetCommercialUse()); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	for _, cf := range intel.GetCustomFeeds() {
		out = append(out, Feed{
			Name: cf.GetName(), URL: cf.GetUrl(), Description: cf.GetDescription(),
			License: "operator-provided", AllowCommercial: true, AllowRedistribution: false, Custom: true,
		})
	}
	return out, nil
}

// Run refreshes on interval until ctx is done. trigger forces an
// immediate refresh (e.g. right after a commit).
func (u *Updater) Run(ctx context.Context, interval time.Duration, trigger <-chan struct{}) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-trigger:
		}
		if n, err := u.Refresh(ctx); err != nil {
			slog.Error("intel refresh failed", "error", err)
		} else if n > 0 {
			slog.Info("intel sets refreshed", "entries", n)
		}
	}
}

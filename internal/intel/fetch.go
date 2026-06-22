package intel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// maxFeedBytes bounds a single feed download.
const maxFeedBytes = 32 << 20 // 32 MiB

// Fetch downloads a feed and parses it as one IP or CIDR per line.
// Comment lines (#, ;) and inline trailing comments are tolerated, so
// the common firewall-feed formats (abuse.ch, ET, Spamhaus) all parse.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]netip.Prefix, error) {
	u, err := ValidateFeedURL(rawURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = DefaultHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OpenNGFW-intel/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch feed: HTTP %d", resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, maxFeedBytes))
}

// ValidateFeedURL enforces the baseline egress policy for operator-defined
// threat-intel feeds before validation or runtime fetch can use the URL.
func ValidateFeedURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("must be an http(s) URL")
	}
	if u.User != nil {
		return nil, errors.New("must not include URL userinfo; store feed credentials outside policy")
	}
	host := u.Hostname()
	if feedHostBlocked(host) {
		return nil, errors.New("must not target loopback, private, link-local, local, or metadata destinations")
	}
	return u, nil
}

func feedHostBlocked(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") {
		return true
	}
	if h == "metadata" || h == "metadata.google.internal" || h == "metadata.oraclecloud.com" {
		return true
	}
	if strings.Contains(h, "%") {
		return true
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast()
}

// Parse reads a plain-text blocklist.
func Parse(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Spamhaus DROP uses "CIDR ; SBL-id"; ET uses bare IPs/CIDRs.
		if i := strings.IndexAny(line, " ;\t"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if pfx, err := netip.ParsePrefix(line); err == nil {
			out = append(out, pfx)
			continue
		}
		if addr, err := netip.ParseAddr(line); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
		// Unparseable lines are skipped: feeds mix in headers and
		// occasionally junk; one bad line must not kill the refresh.
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// DefaultHTTPClient is tuned for feed downloads.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if _, err := ValidateFeedURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}

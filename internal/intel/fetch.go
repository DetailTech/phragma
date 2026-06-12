package intel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxFeedBytes bounds a single feed download.
const maxFeedBytes = 32 << 20 // 32 MiB

// Fetch downloads a feed and parses it as one IP or CIDR per line.
// Comment lines (#, ;) and inline trailing comments are tolerated, so
// the common firewall-feed formats (abuse.ch, ET, Spamhaus) all parse.
func Fetch(ctx context.Context, client *http.Client, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OpenNGFW-intel/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, maxFeedBytes))
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
	return &http.Client{Timeout: 60 * time.Second}
}

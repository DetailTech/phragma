// Package proxytrust centralizes trusted reverse-proxy header handling.
package proxytrust

import (
	"fmt"
	"net"
	"strings"
)

// Set contains the normalized CIDRs whose immediate peer headers may be
// trusted.
type Set struct {
	networks   []*net.IPNet
	normalized []string
}

// New parses and de-duplicates trusted proxy CIDRs.
func New(raw []string) (Set, error) {
	var set Set
	seen := map[string]bool{}
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return Set{}, fmt.Errorf("invalid trusted proxy CIDR %q: %w", item, err)
		}
		key := network.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		set.networks = append(set.networks, network)
		set.normalized = append(set.normalized, key)
	}
	return set, nil
}

// NormalizedCIDRs returns canonical CIDR strings suitable for logs and status.
func (s Set) NormalizedCIDRs() []string {
	if len(s.normalized) == 0 {
		return nil
	}
	out := make([]string, len(s.normalized))
	copy(out, s.normalized)
	return out
}

// TrustsRemoteAddr reports whether an immediate peer address is trusted.
func (s Set) TrustsRemoteAddr(remoteAddr string) bool {
	return s.TrustsHost(RemoteHost(remoteAddr))
}

// TrustsHost reports whether host is inside the trusted proxy set.
func (s Set) TrustsHost(host string) bool {
	if len(s.networks) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ForwardedClientIP returns the rightmost untrusted valid address from an
// X-Forwarded-For chain, or the leftmost address when the whole chain is trusted.
func (s Set) ForwardedClientIP(header string) string {
	if header == "" {
		return ""
	}
	var ips []net.IP
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip)
			continue
		}
		host, _, err := net.SplitHostPort(part)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				ips = append(ips, ip)
				continue
			}
		}
		return ""
	}
	if len(ips) == 0 {
		return ""
	}
	for i := len(ips) - 1; i >= 0; i-- {
		if !s.TrustsHost(ips[i].String()) {
			return ips[i].String()
		}
	}
	return ips[0].String()
}

// ForwardedProto returns a trusted X-Forwarded-Proto value from the immediate
// peer, constrained to the schemes the management API accepts.
func (s Set) ForwardedProto(remoteAddr, header string) string {
	if !s.TrustsRemoteAddr(remoteAddr) {
		return ""
	}
	proto := strings.TrimSpace(strings.Split(header, ",")[0])
	proto = strings.ToLower(proto)
	if proto == "http" || proto == "https" {
		return proto
	}
	return ""
}

// RemoteHost extracts the host part from a remote address when it includes a
// port, falling back to the raw value for already-host-only callers.
func RemoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}

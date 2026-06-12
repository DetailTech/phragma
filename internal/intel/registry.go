// Package intel implements threat-feed federation: a license-aware feed
// registry, fetchers, and the nftables blocklist updater. We federate
// established feeds — we never rebuild their infrastructure (build plan
// §10). CrowdSec integrates alongside via its own firewall bouncer; the
// registry records it for license/attribution tracking.
package intel

import "fmt"

// Feed describes one threat feed and its license constraints. The
// constraints gate enablement: a deployment declaring commercial use
// cannot enable a non-commercial feed.
type Feed struct {
	Name        string
	Description string
	URL         string
	// License is a human-readable license identifier or summary.
	License string
	// AllowCommercial permits use in commercial deployments.
	AllowCommercial bool
	// AllowRedistribution permits re-serving the feed content.
	AllowRedistribution bool
	// Attribution that must accompany use, if any.
	Attribution string
	// Custom marks operator-defined feeds (license is their concern).
	Custom bool
}

// builtins is the feed-license registry. Constraints recorded here are
// summaries — operators remain responsible for reading the upstream
// terms before enabling a feed in production.
var builtins = []Feed{
	{
		Name:                "feodo-tracker",
		Description:         "abuse.ch Feodo Tracker botnet C2 IP blocklist",
		URL:                 "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
		License:             "CC0 (abuse.ch)",
		AllowCommercial:     true,
		AllowRedistribution: true,
		Attribution:         "abuse.ch Feodo Tracker",
	},
	{
		Name:                "sslbl-ips",
		Description:         "abuse.ch SSL Blacklist botnet C2 IPs",
		URL:                 "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
		License:             "CC0 (abuse.ch)",
		AllowCommercial:     true,
		AllowRedistribution: true,
		Attribution:         "abuse.ch SSLBL",
	},
	{
		Name:                "et-block-ips",
		Description:         "Emerging Threats known-compromised IP blocklist",
		URL:                 "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
		License:             "ET Open (BSD-style, see license terms)",
		AllowCommercial:     true,
		AllowRedistribution: false,
		Attribution:         "Emerging Threats / Proofpoint ET Open",
	},
	{
		Name:                "spamhaus-drop",
		Description:         "Spamhaus DROP (Don't Route Or Peer) hijacked netblocks",
		URL:                 "https://www.spamhaus.org/drop/drop.txt",
		License:             "Spamhaus DROP terms: free for non-commercial use only",
		AllowCommercial:     false,
		AllowRedistribution: false,
		Attribution:         "Spamhaus DROP",
	},
}

// Builtins returns the registry contents (copy).
func Builtins() []Feed {
	out := make([]Feed, len(builtins))
	copy(out, builtins)
	return out
}

// Lookup finds a built-in feed by name.
func Lookup(name string) (Feed, bool) {
	for _, f := range builtins {
		if f.Name == name {
			return f, true
		}
	}
	return Feed{}, false
}

// CheckEnable enforces license constraints for enabling feed under the
// declared use. This is the M4 DoD gate: enabling a feed whose license
// forbids the intended use must fail.
func CheckEnable(f Feed, commercialUse bool) error {
	if commercialUse && !f.AllowCommercial {
		return fmt.Errorf("feed %q license (%s) forbids commercial use; deployment declares commercial_use", f.Name, f.License)
	}
	return nil
}

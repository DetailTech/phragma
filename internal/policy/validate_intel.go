package policy

import (
	"net/url"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/intel"
)

func (v *validator) checkIntel(in *openngfwv1.Intel) {
	if in == nil {
		return
	}
	seen := map[string]bool{}
	for _, fe := range in.GetFeeds() {
		f, ok := intel.Lookup(fe.GetName())
		if !ok {
			v.errf("intel: unknown feed %q (see 'ngfwctl intel feeds' for the registry)", fe.GetName())
			continue
		}
		if seen[fe.GetName()] {
			v.errf("intel: duplicate feed %q", fe.GetName())
			continue
		}
		seen[fe.GetName()] = true
		if !fe.GetEnabled() {
			continue
		}
		// The feed-license gate: declared use must be compatible.
		if err := intel.CheckEnable(f, in.GetCommercialUse()); err != nil {
			v.errf("intel: %v", err)
		}
	}
	for _, cf := range in.GetCustomFeeds() {
		if !v.checkName("intel custom feed", cf.GetName()) {
			continue
		}
		if _, builtin := intel.Lookup(cf.GetName()); builtin || seen[cf.GetName()] {
			v.errf("intel: custom feed %q collides with another feed", cf.GetName())
			continue
		}
		seen[cf.GetName()] = true
		u, err := url.Parse(cf.GetUrl())
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			v.errf("intel: custom feed %q url must be http(s)", cf.GetName())
		}
	}
	if iv := in.GetRefreshIntervalMinutes(); iv != 0 && iv < 5 {
		v.errf("intel: refresh_interval_minutes must be >= 5 (got %d)", iv)
	}
}

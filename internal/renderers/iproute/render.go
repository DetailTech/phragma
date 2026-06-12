// Package iproute renders static routes from the IR into an `ip -batch`
// script. Each line uses `route replace` so re-applying is idempotent;
// removal of stale managed routes is handled by the route engine, which
// diffs against the previously applied set.
package iproute

import (
	"fmt"
	"strings"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

// Render produces the batch script. One line per route, deterministic
// order (policy order).
func Render(ir *compiler.IR) ([]byte, error) {
	var b strings.Builder
	for _, r := range ir.Routes {
		b.WriteString(Line(r))
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// Line renders a single route as an ip-batch statement (without newline).
func Line(r compiler.RouteIR) string {
	parts := []string{"route", "replace", r.Destination.String()}
	if r.Via.IsValid() {
		parts = append(parts, "via", r.Via.String())
	}
	if r.Interface != "" {
		parts = append(parts, "dev", r.Interface)
	}
	if r.Metric != 0 {
		parts = append(parts, "metric", fmt.Sprintf("%d", r.Metric))
	}
	return strings.Join(parts, " ")
}

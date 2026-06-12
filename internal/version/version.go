// Package version exposes build metadata injected at link time.
package version

// These are overridden via -ldflags at build time; see the Makefile.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a single-line human-readable version string.
func String() string {
	return Version + " (commit " + Commit + ", built " + BuildDate + ")"
}

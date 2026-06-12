// Package webui serves the read-first management UI (M5). It is a
// static single page that consumes the REST gateway — strictly a client
// of the canonical API, no server-side state. Policy *editing* in the
// UI is a later step and must flow through candidate/commit like every
// other client.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var static embed.FS

// Handler serves the UI under /ui/.
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		// embed is compile-time; this cannot fail at runtime.
		panic(err)
	}
	return http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
}

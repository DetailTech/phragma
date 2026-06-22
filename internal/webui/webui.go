// Package webui serves the embedded management UI. It is a static single page
// that consumes the REST gateway as a client of the canonical API. Policy
// editing flows through candidate/validate/commit like every other client.
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

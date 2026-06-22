package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesEmbeddedAPISpec(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ui/api-spec.yaml", nil)
	rec := httptest.NewRecorder()

	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`swagger: "2.0"`,
		"title: Phragma Control Plane API",
		"/v1/system/release-acceptance/status:",
		"/v1/auth/oidc/status:",
		"/v1/auth/logout:",
		"X-Phragma-CSRF",
		"BearerAuth:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("embedded API spec missing %q", want)
		}
	}
}

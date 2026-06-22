package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLimitRequestBodyRejectsLargeContentLength(t *testing.T) {
	called := false
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), 4)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/candidate", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("wrapped handler was called for oversized request")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestLimitRequestBodyAllowsSmallRequest(t *testing.T) {
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			t.Fatal("request body unexpectedly nil")
		}
		w.WriteHeader(http.StatusNoContent)
	}), 4)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/candidate", strings.NewReader("1234"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestLimitRequestBodyDisabled(t *testing.T) {
	called := false
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), 0)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/candidate", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("wrapped handler was not called when body limit disabled")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestValidateServerLimitsRejectsNegativeValues(t *testing.T) {
	cfg := config{rateLimitRPM: -1}
	if err := validateServerLimits(cfg); err == nil || !strings.Contains(err.Error(), "--rate-limit-rpm") {
		t.Fatalf("negative rate-limit-rpm error = %v, want rejection", err)
	}
	cfg = config{rateLimitBurst: -1}
	if err := validateServerLimits(cfg); err == nil || !strings.Contains(err.Error(), "--rate-limit-burst") {
		t.Fatalf("negative rate-limit-burst error = %v, want rejection", err)
	}
	cfg = config{rateLimitRPM: 1, rateLimitMaxClients: 0}
	if err := validateServerLimits(cfg); err == nil || !strings.Contains(err.Error(), "--rate-limit-max-clients") {
		t.Fatalf("non-positive rate-limit-max-clients error = %v, want rejection", err)
	}
	cfg = config{httpMaxBodyBytes: -1}
	if err := validateServerLimits(cfg); err == nil {
		t.Fatal("expected negative HTTP body limit to be rejected")
	}
	cfg = config{httpReadTimeout: -time.Second}
	if err := validateServerLimits(cfg); err == nil {
		t.Fatal("expected negative HTTP timeout to be rejected")
	}
}

func TestNewHTTPServerUsesConfiguredLimits(t *testing.T) {
	cfg := config{
		httpMaxHeaderBytes:    2048,
		httpReadHeaderTimeout: time.Second,
		httpReadTimeout:       2 * time.Second,
		httpWriteTimeout:      3 * time.Second,
		httpIdleTimeout:       4 * time.Second,
	}
	srv := newHTTPServer("127.0.0.1:8080", http.NotFoundHandler(), cfg)

	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("MaxHeaderBytes = %d, want 2048", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 1s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 2*time.Second {
		t.Fatalf("ReadTimeout = %s, want 2s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 3*time.Second {
		t.Fatalf("WriteTimeout = %s, want 3s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 4*time.Second {
		t.Fatalf("IdleTimeout = %s, want 4s", srv.IdleTimeout)
	}
}

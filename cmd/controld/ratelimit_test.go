package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestRateLimiterHTTP(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             2,
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if code := serveLimitedHTTP(handler, "198.51.100.10:51515"); code != http.StatusNoContent {
		t.Fatalf("first request status = %d, want 204", code)
	}
	if code := serveLimitedHTTP(handler, "198.51.100.10:51515"); code != http.StatusNoContent {
		t.Fatalf("second request status = %d, want 204", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/system/status", nil)
	req.RemoteAddr = "198.51.100.10:51515"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}

	now = now.Add(time.Second)
	if code := serveLimitedHTTP(handler, "198.51.100.10:51515"); code != http.StatusNoContent {
		t.Fatalf("refilled request status = %d, want 204", code)
	}
}

func TestRateLimiterHTTPWhenExemptsStaticWebUIAssets(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTPWhen(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), shouldRateLimitManagementHTTP)

	for i := 0; i < 4; i++ {
		if code := serveLimitedHTTPPath(handler, "198.51.100.10:51515", "/ui/js/views/traffic.js"); code != http.StatusNoContent {
			t.Fatalf("static WebUI asset request %d status = %d, want 204", i+1, code)
		}
	}
	if code := serveLimitedHTTPPath(handler, "198.51.100.10:51515", "/v1/system/status"); code != http.StatusNoContent {
		t.Fatalf("first API request status = %d, want 204", code)
	}
	if code := serveLimitedHTTPPath(handler, "198.51.100.10:51515", "/v1/system/status"); code != http.StatusTooManyRequests {
		t.Fatalf("second API request status = %d, want 429", code)
	}
}

func TestRateLimiterSeparatesClients(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if code := serveLimitedHTTP(handler, "198.51.100.10:51515"); code != http.StatusNoContent {
		t.Fatalf("first client status = %d, want 204", code)
	}
	if code := serveLimitedHTTP(handler, "198.51.100.10:51516"); code != http.StatusTooManyRequests {
		t.Fatalf("same client status = %d, want 429", code)
	}
	if code := serveLimitedHTTP(handler, "198.51.100.11:51515"); code != http.StatusNoContent {
		t.Fatalf("different client status = %d, want 204", code)
	}
}

func TestRateLimiterCapsClientBuckets(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		MaxClients:        2,
		Now:               func() time.Time { return now },
	})

	for _, key := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12"} {
		if allowed, retryAfter := limiter.allow(key); !allowed {
			t.Fatalf("first request for %s denied, retry after %s", key, retryAfter)
		}
		now = now.Add(time.Second)
	}
	if len(limiter.clients) != 2 {
		t.Fatalf("tracked clients = %d, want 2", len(limiter.clients))
	}
	if _, ok := limiter.clients["198.51.100.10"]; ok {
		t.Fatal("oldest client bucket was not evicted")
	}
	for _, key := range []string{"198.51.100.11", "198.51.100.12"} {
		if _, ok := limiter.clients[key]; !ok {
			t.Fatalf("client bucket %s missing after cap enforcement", key)
		}
	}
}

func TestRateLimiterUnaryInterceptor(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		Now:               func() time.Time { return now },
	})
	interceptor := limiter.UnaryInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 9443}})
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler); err != nil {
		t.Fatalf("first gRPC request returned error: %v", err)
	}
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second gRPC status = %s, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
}

func TestRateLimiterUnaryInterceptorInternalBypass(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		InternalBypass:    "gateway-secret",
		Now:               func() time.Time { return now },
	})
	interceptor := limiter.UnaryInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443}})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(gatewayRateLimitBypassMetadata, "gateway-secret"))
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	for i := 0; i < 3; i++ {
		if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler); err != nil {
			t.Fatalf("bypassed gRPC request %d returned error: %v", i+1, err)
		}
	}

	directCtx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443}})
	if _, err := interceptor(directCtx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler); err != nil {
		t.Fatalf("direct gRPC request after bypassed gateway calls returned error: %v", err)
	}
}

func TestRateLimiterUnaryInterceptorRejectsWrongInternalBypass(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		InternalBypass:    "gateway-secret",
		Now:               func() time.Time { return now },
	})
	interceptor := limiter.UnaryInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443}})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(gatewayRateLimitBypassMetadata, "wrong-secret"))
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler); err != nil {
		t.Fatalf("first gRPC request returned error: %v", err)
	}
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.SystemService/GetStatus"}, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("wrong bypass token status = %s, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	limiter, err := newClientRateLimiter(rateLimitConfig{RequestsPerMinute: 0, Burst: 1})
	if err != nil {
		t.Fatalf("newClientRateLimiter returned error: %v", err)
	}
	if limiter != nil {
		t.Fatalf("disabled limiter = %#v, want nil", limiter)
	}
}

func TestRateLimiterRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	if _, err := newClientRateLimiter(rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		TrustedProxyCIDRs: []string{"10.0.0.5"},
	}); err == nil {
		t.Fatal("newClientRateLimiter accepted invalid trusted proxy CIDR")
	}
}

func TestRateLimiterTrustsXForwardedForOnlyFromTrustedProxy(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		TrustedProxyCIDRs: []string{"10.0.0.0/24"},
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if code := serveLimitedHTTPWithHeaders(handler, "10.0.0.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.10",
	}); code != http.StatusNoContent {
		t.Fatalf("first forwarded client status = %d, want 204", code)
	}
	if code := serveLimitedHTTPWithHeaders(handler, "10.0.0.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.11",
	}); code != http.StatusNoContent {
		t.Fatalf("second forwarded client status = %d, want 204", code)
	}
	if code := serveLimitedHTTPWithHeaders(handler, "10.0.0.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.10",
	}); code != http.StatusTooManyRequests {
		t.Fatalf("repeat forwarded client status = %d, want 429", code)
	}
}

func TestRateLimiterUsesRightmostUntrustedForwardedClient(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		TrustedProxyCIDRs: []string{"10.0.0.0/24"},
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if code := serveLimitedHTTPWithHeaders(handler, "10.0.0.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.250, 198.51.100.10",
	}); code != http.StatusNoContent {
		t.Fatalf("first forwarded chain status = %d, want 204", code)
	}
	if code := serveLimitedHTTPWithHeaders(handler, "10.0.0.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.251, 198.51.100.10",
	}); code != http.StatusTooManyRequests {
		t.Fatalf("spoof-prefix forwarded chain status = %d, want 429", code)
	}
}

func TestRateLimiterIgnoresXForwardedForFromUntrustedPeer(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	limiter := mustRateLimiter(t, rateLimitConfig{
		RequestsPerMinute: 60,
		Burst:             1,
		TrustedProxyCIDRs: []string{"10.0.0.0/24"},
		Now:               func() time.Time { return now },
	})
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if code := serveLimitedHTTPWithHeaders(handler, "203.0.113.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.10",
	}); code != http.StatusNoContent {
		t.Fatalf("first untrusted peer status = %d, want 204", code)
	}
	if code := serveLimitedHTTPWithHeaders(handler, "203.0.113.10:443", map[string]string{
		"X-Forwarded-For": "198.51.100.11",
	}); code != http.StatusTooManyRequests {
		t.Fatalf("second untrusted peer status = %d, want 429", code)
	}
}

func TestRateLimiterDisabledHTTPPassthrough(t *testing.T) {
	var limiter *clientRateLimiter
	handler := limiter.HTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	if code := serveLimitedHTTP(handler, "198.51.100.10:51515"); code != http.StatusNoContent {
		t.Fatalf("disabled limiter status = %d, want 204", code)
	}
}

func serveLimitedHTTP(handler http.Handler, remoteAddr string) int {
	return serveLimitedHTTPWithHeaders(handler, remoteAddr, nil)
}

func serveLimitedHTTPPath(handler http.Handler, remoteAddr, path string) int {
	return serveLimitedHTTPPathWithHeaders(handler, remoteAddr, path, nil)
}

func serveLimitedHTTPWithHeaders(handler http.Handler, remoteAddr string, headers map[string]string) int {
	return serveLimitedHTTPPathWithHeaders(handler, remoteAddr, "/v1/system/status", headers)
}

func serveLimitedHTTPPathWithHeaders(handler http.Handler, remoteAddr, path string, headers map[string]string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func mustRateLimiter(t *testing.T, cfg rateLimitConfig) *clientRateLimiter {
	t.Helper()
	limiter, err := newClientRateLimiter(cfg)
	if err != nil {
		t.Fatalf("newClientRateLimiter returned error: %v", err)
	}
	if limiter == nil {
		t.Fatal("newClientRateLimiter returned nil")
	}
	return limiter
}

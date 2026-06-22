package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/detailtech/oss-ngfw/internal/proxytrust"
)

const (
	gatewayRateLimitBypassMetadata = "x-openngfw-gateway-rate-limit-bypass"
	defaultRateLimitMaxClients     = 4096
)

type rateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
	MaxClients        int
	TrustedProxyCIDRs []string
	InternalBypass    string
	Now               func() time.Time
}

type clientRateLimiter struct {
	mu                sync.Mutex
	clients           map[string]*rateLimitBucket
	ratePerSecond     float64
	burst             float64
	maxClients        int
	trustedProxies    proxytrust.Set
	trustedProxyCIDRs []string
	internalBypass    string
	now               func() time.Time
	lastSweep         time.Time
}

type rateLimitBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

func newClientRateLimiter(cfg rateLimitConfig) (*clientRateLimiter, error) {
	trustedProxies, err := proxytrust.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	if cfg.RequestsPerMinute <= 0 {
		return nil, nil
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.RequestsPerMinute
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = defaultRateLimitMaxClients
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &clientRateLimiter{
		clients:           map[string]*rateLimitBucket{},
		ratePerSecond:     float64(cfg.RequestsPerMinute) / 60,
		burst:             float64(cfg.Burst),
		maxClients:        cfg.MaxClients,
		trustedProxies:    trustedProxies,
		trustedProxyCIDRs: trustedProxies.NormalizedCIDRs(),
		internalBypass:    cfg.InternalBypass,
		now:               now,
	}, nil
}

func (l *clientRateLimiter) allow(key string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweepLocked(now)
	b := l.clients[key]
	if b == nil {
		if len(l.clients) >= l.maxClients {
			l.evictOldestClientLocked()
		}
		l.clients[key] = &rateLimitBucket{tokens: l.burst - 1, last: now, lastSeen: now}
		return true, 0
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.ratePerSecond)
		b.last = now
	}
	b.lastSeen = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	needed := 1 - b.tokens
	return false, time.Duration(math.Ceil((needed / l.ratePerSecond) * float64(time.Second)))
}

func (l *clientRateLimiter) sweepLocked(now time.Time) {
	if l.lastSweep.IsZero() {
		l.lastSweep = now
		return
	}
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	for key, bucket := range l.clients {
		if now.Sub(bucket.lastSeen) > 10*time.Minute {
			delete(l.clients, key)
		}
	}
	l.enforceClientLimitLocked()
	l.lastSweep = now
}

func (l *clientRateLimiter) enforceClientLimitLocked() {
	for len(l.clients) > l.maxClients {
		l.evictOldestClientLocked()
	}
}

func (l *clientRateLimiter) evictOldestClientLocked() {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range l.clients {
		if oldestKey == "" || bucket.lastSeen.Before(oldest) || (bucket.lastSeen.Equal(oldest) && key < oldestKey) {
			oldestKey = key
			oldest = bucket.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.clients, oldestKey)
	}
}

func (l *clientRateLimiter) HTTP(next http.Handler) http.Handler {
	return l.HTTPWhen(next, nil)
}

func (l *clientRateLimiter) HTTPWhen(next http.Handler, shouldLimit func(*http.Request) bool) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldLimit != nil && !shouldLimit(r) {
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter := l.allow(l.httpClientKey(r))
		if !allowed {
			w.Header().Set("Retry-After", retryAfterHeader(retryAfter))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *clientRateLimiter) UnaryInterceptor() grpc.UnaryServerInterceptor {
	if l == nil {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if l.hasInternalBypass(ctx) {
			return handler(ctx, req)
		}
		allowed, retryAfter := l.allow(grpcClientKey(ctx))
		if !allowed {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded; retry after %s", retryAfterHeader(retryAfter))
		}
		return handler(ctx, req)
	}
}

func (l *clientRateLimiter) httpClientKey(r *http.Request) string {
	if l.trustedProxies.TrustsRemoteAddr(r.RemoteAddr) {
		if forwardedFor := l.trustedProxies.ForwardedClientIP(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
			return forwardedFor
		}
	}
	remoteHost := proxytrust.RemoteHost(r.RemoteAddr)
	if remoteHost != "" {
		return remoteHost
	}
	return r.RemoteAddr
}

func (l *clientRateLimiter) hasInternalBypass(ctx context.Context) bool {
	if l == nil || l.internalBypass == "" {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, got := range md.Get(gatewayRateLimitBypassMetadata) {
		if subtle.ConstantTimeCompare([]byte(got), []byte(l.internalBypass)) == 1 {
			return true
		}
	}
	return false
}

func grpcClientKey(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "grpc"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err == nil && host != "" {
		return host
	}
	return p.Addr.String()
}

func gatewayRateLimitBypassToken() (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", fmt.Errorf("generate gateway rate-limit bypass token: %w", err)
	}
	return token, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func retryAfterHeader(d time.Duration) string {
	seconds := int(math.Ceil(d.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

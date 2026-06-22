package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	defaultHTTPMaxBodyBytes    int64 = 10 << 20
	defaultGRPCMaxMessageBytes       = 16 << 20
)

func validateServerLimits(cfg config) error {
	if cfg.rateLimitRPM < 0 {
		return fmt.Errorf("--rate-limit-rpm must be >= 0")
	}
	if cfg.rateLimitBurst < 0 {
		return fmt.Errorf("--rate-limit-burst must be >= 0")
	}
	if cfg.rateLimitRPM > 0 && cfg.rateLimitMaxClients <= 0 {
		return fmt.Errorf("--rate-limit-max-clients must be > 0 when rate limiting is enabled")
	}

	checks := []struct {
		name  string
		value int64
	}{
		{name: "http-max-body-bytes", value: cfg.httpMaxBodyBytes},
		{name: "http-max-header-bytes", value: int64(cfg.httpMaxHeaderBytes)},
		{name: "grpc-max-recv-bytes", value: int64(cfg.grpcMaxRecvBytes)},
		{name: "grpc-max-send-bytes", value: int64(cfg.grpcMaxSendBytes)},
	}
	for _, check := range checks {
		if check.value < 0 {
			return fmt.Errorf("--%s must be >= 0", check.name)
		}
	}

	durations := []struct {
		name  string
		value time.Duration
	}{
		{name: "http-read-header-timeout", value: cfg.httpReadHeaderTimeout},
		{name: "http-read-timeout", value: cfg.httpReadTimeout},
		{name: "http-write-timeout", value: cfg.httpWriteTimeout},
		{name: "http-idle-timeout", value: cfg.httpIdleTimeout},
	}
	for _, check := range durations {
		if check.value < 0 {
			return fmt.Errorf("--%s must be >= 0", check.name)
		}
	}
	return nil
}

func appendGRPCSizeOptions(opts []grpc.ServerOption, cfg config) []grpc.ServerOption {
	if cfg.grpcMaxRecvBytes > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(cfg.grpcMaxRecvBytes))
	}
	if cfg.grpcMaxSendBytes > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(cfg.grpcMaxSendBytes))
	}
	return opts
}

func gatewayDialOptions(cfg config, rateLimitBypassToken string) []grpc.DialOption {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if rateLimitBypassToken != "" {
		dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(gatewayRateLimitBypassInterceptor(rateLimitBypassToken)))
	}
	var callOpts []grpc.CallOption
	if cfg.grpcMaxRecvBytes > 0 {
		callOpts = append(callOpts, grpc.MaxCallSendMsgSize(cfg.grpcMaxRecvBytes))
	}
	if cfg.grpcMaxSendBytes > 0 {
		callOpts = append(callOpts, grpc.MaxCallRecvMsgSize(cfg.grpcMaxSendBytes))
	}
	if len(callOpts) > 0 {
		dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(callOpts...))
	}
	return dialOpts
}

func gatewayRateLimitBypassInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, gatewayRateLimitBypassMetadata, token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func newHTTPServer(addr string, handler http.Handler, cfg config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.httpReadHeaderTimeout,
		ReadTimeout:       cfg.httpReadTimeout,
		WriteTimeout:      cfg.httpWriteTimeout,
		IdleTimeout:       cfg.httpIdleTimeout,
		MaxHeaderBytes:    cfg.httpMaxHeaderBytes,
	}
}

func limitRequestBody(next http.Handler, maxBodyBytes int64) http.Handler {
	if maxBodyBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			if r.ContentLength > maxBodyBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

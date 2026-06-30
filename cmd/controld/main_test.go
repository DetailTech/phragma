package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV("openid, profile,email,,")
	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCSV = %#v, want %#v", got, want)
	}
}

func TestReadSecretFileRejectsLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path); err == nil {
		t.Fatal("expected loose OIDC secret file to be rejected")
	}
}

func TestReadSecretFileTrimsSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret" {
		t.Fatalf("secret = %q, want trimmed value", got)
	}
}

func TestValidateManagementAuth(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "users file enables auth",
			cfg:  config{usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443"},
		},
		{
			name: "oidc enables auth",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "https://fw.example.com/v1/auth/oidc/callback",
				oidcScopes:      "openid,profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
		},
		{
			name: "oidc loopback http redirect allowed for local development",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "http://127.0.0.1:8080/v1/auth/oidc/callback",
				oidcScopes:      "openid,profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
		},
		{
			name: "oidc partial config rejected early",
			cfg: config{
				oidcIssuer: "https://idp.example.com",
				grpcListen: "127.0.0.1:9443",
			},
			wantErr: "--oidc-client-id is required",
		},
		{
			name: "oidc redirect path must match callback route",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "https://fw.example.com/callback",
				oidcScopes:      "openid,profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
			wantErr: "--oidc-redirect-url path must be /v1/auth/oidc/callback",
		},
		{
			name: "oidc non-loopback http redirect rejected",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "http://fw.example.com/v1/auth/oidc/callback",
				oidcScopes:      "openid,profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
			wantErr: "--oidc-redirect-url must use https unless the host is loopback",
		},
		{
			name: "oidc scopes must include openid",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "https://fw.example.com/v1/auth/oidc/callback",
				oidcScopes:      "profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
			wantErr: "--oidc-scopes must include openid",
		},
		{
			name: "oidc default role must be valid",
			cfg: config{
				oidcIssuer:      "https://idp.example.com",
				oidcClientID:    "openngfw",
				oidcRedirectURL: "https://fw.example.com/v1/auth/oidc/callback",
				oidcDefaultRole: "superuser",
				oidcScopes:      "openid,profile,email",
				grpcListen:      "127.0.0.1:9443",
			},
			wantErr: "--oidc-default-role",
		},
		{
			name:    "users file still rejects remote direct grpc",
			cfg:     config{usersFile: "/etc/openngfw/users.yaml", grpcListen: "0.0.0.0:9443"},
			wantErr: "direct gRPC management listener requires loopback",
		},
		{
			name:    "cleartext remote rest rejected",
			cfg:     config{usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080", tlsEnabled: false},
			wantErr: "--tls=false requires --http-listen",
		},
		{
			name: "public self signed opt in still requires tls",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: false, allowPublicSelfSignedTLS: true,
			},
			wantErr: "--allow-public-self-signed-tls requires --tls=true",
		},
		{
			name: "loopback self signed opt in still requires tls",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080",
				tlsEnabled: false, allowPublicSelfSignedTLS: true,
			},
			wantErr: "--allow-public-self-signed-tls requires --tls=true",
		},
		{
			name: "operator certificate requires tls",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080",
				tlsCert: "/etc/openngfw/tls/cert.pem", tlsKey: "/etc/openngfw/tls/key.pem",
			},
			wantErr: "--tls-cert and --tls-key require --tls=true",
		},
		{
			name: "tls remote rest with operator certificate allowed",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, tlsCert: "/etc/openngfw/tls/cert.pem", tlsKey: "/etc/openngfw/tls/key.pem",
			},
		},
		{
			name: "tls remote rest allows generated self signed certificate with explicit opt in",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, allowPublicSelfSignedTLS: true,
			},
		},
		{
			name: "public self signed opt in does not bypass authentication",
			cfg: config{
				grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, allowPublicSelfSignedTLS: true,
			},
			wantErr: "API authentication is required",
		},
		{
			name: "tls remote rest rejects generated self signed certificate",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080", tlsEnabled: true,
			},
			wantErr: "non-loopback --http-listen requires operator-provided --tls-cert and --tls-key",
		},
		{
			name: "tls remote rest rejects partial operator certificate",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, tlsCert: "/etc/openngfw/tls/cert.pem",
			},
			wantErr: "--tls-cert and --tls-key must be provided together",
		},
		{
			name: "tls remote rest opt in rejects certificate without key",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, tlsCert: "/etc/openngfw/tls/cert.pem", allowPublicSelfSignedTLS: true,
			},
			wantErr: "--tls-cert and --tls-key must be provided together",
		},
		{
			name: "tls remote rest opt in rejects key without certificate",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "0.0.0.0:8080",
				tlsEnabled: true, tlsKey: "/etc/openngfw/tls/key.pem", allowPublicSelfSignedTLS: true,
			},
			wantErr: "--tls-cert and --tls-key must be provided together",
		},
		{
			name: "tls loopback rest allows generated self signed certificate",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080", tlsEnabled: true,
			},
		},
		{
			name: "tls loopback rest tolerates redundant public self signed opt in",
			cfg: config{
				usersFile: "/etc/openngfw/users.yaml", grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080",
				tlsEnabled: true, allowPublicSelfSignedTLS: true,
			},
		},
		{
			name:    "missing auth rejected by default",
			cfg:     config{grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080", dryRun: true},
			wantErr: "API authentication is required",
		},
		{
			name: "explicit local dry run no-auth allowed",
			cfg: config{
				grpcListen: "127.0.0.1:9443", httpListen: "localhost:8080",
				dryRun: true, allowUnauthenticatedLocal: true,
			},
		},
		{
			name: "explicit local no-auth allows disabled http",
			cfg: config{
				grpcListen: "[::1]:9443", httpListen: "",
				dryRun: true, allowUnauthenticatedLocal: true,
			},
		},
		{
			name: "explicit no-auth requires dry run",
			cfg: config{
				grpcListen: "127.0.0.1:9443", httpListen: "127.0.0.1:8080",
				allowUnauthenticatedLocal: true,
			},
			wantErr: "requires --dry-run",
		},
		{
			name: "explicit no-auth rejects wildcard grpc",
			cfg: config{
				grpcListen: "0.0.0.0:9443", httpListen: "127.0.0.1:8080",
				dryRun: true, allowUnauthenticatedLocal: true,
			},
			wantErr: "direct gRPC management listener requires loopback",
		},
		{
			name: "explicit no-auth rejects wildcard http",
			cfg: config{
				grpcListen: "127.0.0.1:9443", httpListen: ":8080",
				dryRun: true, allowUnauthenticatedLocal: true,
			},
			wantErr: "--http-listen to be loopback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManagementAuth(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateManagementAuth() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateManagementAuth() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestUsesPublicSelfSignedTLS(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want bool
	}{
		{
			name: "explicit public generated certificate",
			cfg:  config{httpListen: "0.0.0.0:8080", tlsEnabled: true, allowPublicSelfSignedTLS: true},
			want: true,
		},
		{
			name: "public operator certificate",
			cfg: config{
				httpListen: "0.0.0.0:8080", tlsEnabled: true, allowPublicSelfSignedTLS: true,
				tlsCert: "/etc/openngfw/tls/cert.pem", tlsKey: "/etc/openngfw/tls/key.pem",
			},
		},
		{
			name: "loopback generated certificate",
			cfg:  config{httpListen: "127.0.0.1:8080", tlsEnabled: true, allowPublicSelfSignedTLS: true},
		},
		{
			name: "public tls disabled",
			cfg:  config{httpListen: "0.0.0.0:8080", allowPublicSelfSignedTLS: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := usesPublicSelfSignedTLS(test.cfg); got != test.want {
				t.Fatalf("usesPublicSelfSignedTLS() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLogManagementTLSPostureWarnsForExplicitPublicSelfSignedTLS(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	logManagementTLSPosture(config{
		httpListen: "0.0.0.0:8080", tlsEnabled: true, allowPublicSelfSignedTLS: true,
	}, "/var/lib/openngfw/tls/cert.pem", true)

	logBody := logs.String()
	for _, want := range []string{
		`"level":"WARN"`,
		"non-loopback WebUI/REST listener with generated self-signed TLS",
		"explicitly accepted for temporary lab use",
		`"listen":"0.0.0.0:8080"`,
		`"cert":"/var/lib/openngfw/tls/cert.pem"`,
		`"trust":"generated-self-signed"`,
		`"operator_acknowledged":true`,
		`"scope":"test-only"`,
	} {
		if !strings.Contains(logBody, want) {
			t.Fatalf("management TLS log = %s, want %q", logBody, want)
		}
	}
}

func TestValidateHAFlags(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{
			name: "empty accepted",
			cfg:  config{},
		},
		{
			name: "active passive peer url accepted",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
		},
		{
			name: "automatic policy replication accepted on passive peer",
			cfg: config{
				haMode:                      "active-passive",
				haRole:                      "passive",
				haPeerURL:                   "https://fw-a.example/v1/system/ha/status",
				haPeerTokenFile:             "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:          2 * time.Second,
				haHeartbeatStaleAfter:       30 * time.Second,
				haAutoPolicyReplication:     true,
				haPolicyReplicationInterval: time.Minute,
				haPolicyReplicationComment:  "automatic passive HA policy replication",
			},
		},
		{
			name: "local HA promotion accepted on passive node",
			cfg: config{
				haMode:                    "active-passive",
				haRole:                    "passive",
				haPromoteVIP:              "192.0.2.10/32",
				haPromoteInterface:        "eth0",
				haPromoteRouteDestination: "198.51.100.0/24",
				haPromoteRouteVia:         "192.0.2.1",
				haPromoteRouteMetric:      50,
			},
		},
		{
			name: "automatic policy replication requires passive role",
			cfg: config{
				haMode:                      "active-passive",
				haRole:                      "active",
				haPeerURL:                   "https://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:             "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:          2 * time.Second,
				haHeartbeatStaleAfter:       30 * time.Second,
				haAutoPolicyReplication:     true,
				haPolicyReplicationInterval: time.Minute,
				haPolicyReplicationComment:  "automatic passive HA policy replication",
			},
			wantErr: "--ha-auto-policy-replication requires --ha-role=passive",
		},
		{
			name: "automatic policy replication requires peer url",
			cfg: config{
				haMode:                      "active-passive",
				haRole:                      "passive",
				haAutoPolicyReplication:     true,
				haPolicyReplicationInterval: time.Minute,
				haPolicyReplicationComment:  "automatic passive HA policy replication",
			},
			wantErr: "--ha-auto-policy-replication requires --ha-peer-url",
		},
		{
			name: "automatic policy replication requires interval",
			cfg: config{
				haMode:                     "active-passive",
				haRole:                     "passive",
				haPeerURL:                  "https://fw-a.example/v1/system/ha/status",
				haPeerTokenFile:            "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:         2 * time.Second,
				haHeartbeatStaleAfter:      30 * time.Second,
				haAutoPolicyReplication:    true,
				haPolicyReplicationComment: "automatic passive HA policy replication",
			},
			wantErr: "--ha-policy-replication-interval must be greater than zero",
		},
		{
			name: "local HA promotion requires active passive mode",
			cfg: config{
				haMode:             "standalone",
				haRole:             "passive",
				haPromoteVIP:       "192.0.2.10/32",
				haPromoteInterface: "eth0",
			},
			wantErr: "--ha-promote-vip requires --ha-mode=active-passive",
		},
		{
			name: "local HA promotion requires passive role",
			cfg: config{
				haMode:             "active-passive",
				haRole:             "active",
				haPromoteVIP:       "192.0.2.10/32",
				haPromoteInterface: "eth0",
			},
			wantErr: "--ha-promote-vip requires --ha-role=passive",
		},
		{
			name: "local HA promotion requires VIP",
			cfg: config{
				haMode:             "active-passive",
				haRole:             "passive",
				haPromoteInterface: "eth0",
			},
			wantErr: "--ha-promote-vip is required when HA promotion flags are set",
		},
		{
			name: "local HA promotion requires interface",
			cfg: config{
				haMode:       "active-passive",
				haRole:       "passive",
				haPromoteVIP: "192.0.2.10/32",
			},
			wantErr: "--ha-promote-interface is required when --ha-promote-vip is set",
		},
		{
			name: "local HA promotion route via requires destination",
			cfg: config{
				haMode:             "active-passive",
				haRole:             "passive",
				haPromoteVIP:       "192.0.2.10/32",
				haPromoteInterface: "eth0",
				haPromoteRouteVia:  "192.0.2.1",
			},
			wantErr: "--ha-promote-route-via requires --ha-promote-route-destination",
		},
		{
			name: "token file requires url",
			cfg: config{
				haPeerTokenFile: "/etc/openngfw/ha-peer.token",
			},
			wantErr: "--ha-peer-token-file requires --ha-peer-url",
		},
		{
			name: "remote http rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "http://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url must use https",
		},
		{
			name: "peer url requires active passive",
			cfg: config{
				haMode:                "standalone",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url requires --ha-mode=active-passive",
		},
		{
			name: "wrong path rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url path must be /v1/system/ha/status",
		},
		{
			name: "url credentials rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://token@fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url must not include URL credentials",
		},
		{
			name: "fragment rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status#token",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url must not include a fragment",
		},
		{
			name: "query rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status?source=running",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-url must not include a query string",
		},
		{
			name: "missing token rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status",
				haHeartbeatTimeout:    2 * time.Second,
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-peer-token-file is required",
		},
		{
			name: "zero timeout rejected",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatStaleAfter: 30 * time.Second,
			},
			wantErr: "--ha-heartbeat-timeout must be greater than zero",
		},
		{
			name: "stale must exceed timeout",
			cfg: config{
				haMode:                "active-passive",
				haPeerURL:             "https://fw-b.example/v1/system/ha/status",
				haPeerTokenFile:       "/etc/openngfw/ha-peer.token",
				haHeartbeatTimeout:    5 * time.Second,
				haHeartbeatStaleAfter: 5 * time.Second,
			},
			wantErr: "--ha-heartbeat-stale-after must be greater than --ha-heartbeat-timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHAFlags(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateHAFlags() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateHAFlags() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestHAPeerSourcesRejectEmptyTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "ha-peer.token")
	if err := os.WriteFile(tokenPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		haPeerURL:          "https://fw-b.example/v1/system/ha/status",
		haPeerTokenFile:    tokenPath,
		haHeartbeatTimeout: time.Second,
	}
	if _, err := haPeerEvidenceSource(cfg); err == nil || !strings.Contains(err.Error(), "HA peer token file is empty") {
		t.Fatalf("haPeerEvidenceSource error = %v, want empty token error", err)
	}
	if _, err := haPeerPolicySource(cfg); err == nil || !strings.Contains(err.Error(), "HA peer token file is empty") {
		t.Fatalf("haPeerPolicySource error = %v, want empty token error", err)
	}
}

func TestReadBoundedResponseBodyRejectsOversize(t *testing.T) {
	_, err := readBoundedResponseBody(strings.NewReader(strings.Repeat("x", 6)), 5, "peer test")
	if err == nil || !strings.Contains(err.Error(), "peer test response exceeds 5 byte limit") {
		t.Fatalf("readBoundedResponseBody error = %v, want oversize error", err)
	}
	body, err := readBoundedResponseBody(strings.NewReader("12345"), 5, "peer test")
	if err != nil {
		t.Fatalf("readBoundedResponseBody exact limit: %v", err)
	}
	if string(body) != "12345" {
		t.Fatalf("body = %q, want 12345", string(body))
	}
}

func TestHAPeerSourcesUseExpectedHTTPSRequests(t *testing.T) {
	const token = "peer-token-0123456789"
	artifactHash := strings.Repeat("a", 64)
	generatedAt := time.Date(2026, 6, 19, 14, 30, 0, 0, time.UTC).Format(time.RFC3339)
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Method; got != http.MethodGet {
			t.Errorf("method = %q, want GET", got)
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
			http.Error(w, "bad accept", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want bearer token", got)
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.URL.RequestURI())
		switch r.URL.RequestURI() {
		case "/v1/system/ha/status":
			writeTestProtoJSON(t, w, &openngfwv1.GetHighAvailabilityStatusResponse{
				SchemaVersion: "phragma.ha.status.v1",
				GeneratedAt:   generatedAt,
				Status: &openngfwv1.HighAvailabilityStatus{
					NodeId:               "fw-a",
					Role:                 "active",
					RunningPolicyVersion: 12,
					Sync: &openngfwv1.HighAvailabilitySyncStatus{
						LocalArtifactSetSha256: artifactHash,
						Detail:                 "active peer heartbeat",
					},
				},
			})
		case "/v1/policy?source=POLICY_SOURCE_RUNNING":
			writeTestProtoJSON(t, w, &openngfwv1.GetPolicyResponse{
				Version: 12,
				Policy: &openngfwv1.Policy{
					Zones: []*openngfwv1.Zone{{Name: "peer-active"}},
				},
			})
		default:
			t.Errorf("unexpected peer request URI %q", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "ha-peer.token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(tempDir, "ha-peer-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		haPeerURL:          server.URL + "/v1/system/ha/status",
		haPeerTokenFile:    tokenPath,
		haPeerCAFile:       caPath,
		haHeartbeatTimeout: 2 * time.Second,
	}

	evidenceSource, err := haPeerEvidenceSource(cfg)
	if err != nil {
		t.Fatalf("haPeerEvidenceSource: %v", err)
	}
	evidence, err := evidenceSource(context.Background())
	if err != nil {
		t.Fatalf("peer evidence fetch: %v", err)
	}
	if evidence.NodeID != "fw-a" || evidence.Role != "active" || evidence.RunningPolicyVersion != 12 || evidence.ArtifactSetSHA256 != artifactHash {
		t.Fatalf("peer evidence = %#v, want active fw-a v12 with artifact hash", evidence)
	}
	if !evidence.LastHeartbeat.Equal(time.Date(2026, 6, 19, 14, 30, 0, 0, time.UTC)) {
		t.Fatalf("last heartbeat = %s, want generatedAt timestamp", evidence.LastHeartbeat)
	}

	policySource, err := haPeerPolicySource(cfg)
	if err != nil {
		t.Fatalf("haPeerPolicySource: %v", err)
	}
	policyResp, err := policySource(context.Background())
	if err != nil {
		t.Fatalf("peer policy fetch: %v", err)
	}
	if policyResp.GetVersion() != 12 || len(policyResp.GetPolicy().GetZones()) != 1 || policyResp.GetPolicy().GetZones()[0].GetName() != "peer-active" {
		t.Fatalf("peer policy response = %#v, want running peer policy v12", policyResp)
	}
	if !reflect.DeepEqual(seen, []string{"/v1/system/ha/status", "/v1/policy?source=POLICY_SOURCE_RUNNING"}) {
		t.Fatalf("peer request URIs = %#v, want status then running policy", seen)
	}
}

func TestHAPeerPolicyURLDerivesRunningPolicyEndpoint(t *testing.T) {
	got, err := haPeerPolicyURL("https://fw-b.example/v1/system/ha/status")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://fw-b.example/v1/policy?source=POLICY_SOURCE_RUNNING"; got != want {
		t.Fatalf("haPeerPolicyURL = %q, want %q", got, want)
	}
}

func writeTestProtoJSON(t *testing.T, w http.ResponseWriter, msg proto.Message) {
	t.Helper()
	body, err := (protojson.MarshalOptions{}).Marshal(msg)
	if err != nil {
		t.Errorf("marshal test proto JSON: %v", err)
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		t.Errorf("write test proto JSON: %v", err)
	}
}

func TestOIDCSessionCookieSecureUsesPublicRedirectURL(t *testing.T) {
	base := config{
		oidcIssuer:      "https://idp.example.com",
		oidcClientID:    "phragma",
		oidcRedirectURL: "https://fw.example.com/v1/auth/oidc/callback",
		tlsEnabled:      false,
	}
	if !oidcSessionCookieSecure(base) {
		t.Fatal("https public redirect should force Secure OIDC session cookie even when backend TLS terminates upstream")
	}
	base.oidcRedirectURL = "http://127.0.0.1:8080/v1/auth/oidc/callback"
	base.tlsEnabled = true
	if oidcSessionCookieSecure(base) {
		t.Fatal("http public redirect should not use Secure cookie even if backend TLS flag is true")
	}
	base.oidcRedirectURL = "://bad"
	base.tlsEnabled = true
	if !oidcSessionCookieSecure(base) {
		t.Fatal("unparseable redirect falls back to backend TLS posture")
	}
	if oidcSessionCookieSecure(config{tlsEnabled: true}) {
		t.Fatal("OIDC disabled should not report a Secure OIDC cookie")
	}
}

func TestIsLoopbackListenAddress(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:9443": true,
		"localhost:8080": true,
		"[::1]:9443":     true,
		"0.0.0.0:9443":   false,
		":9443":          false,
		"bad":            false,
	}
	for addr, want := range tests {
		if got := isLoopbackListenAddress(addr); got != want {
			t.Fatalf("isLoopbackListenAddress(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), true).ServeHTTP(rec, req)

	want := map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"Referrer-Policy":                   "no-referrer",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Permissions-Policy":                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
		"Strict-Transport-Security":         "max-age=31536000",
	}
	for key, value := range want {
		if got := rec.Header().Get(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("Content-Security-Policy = %q, missing %q", csp, directive)
		}
	}

	httpRec := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), false).ServeHTTP(httpRec, req)
	if got := httpRec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("cleartext Strict-Transport-Security = %q, want empty", got)
	}
}

func TestNoStoreAPIResponses(t *testing.T) {
	handler := noStoreAPIResponses(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, path := range []string{"/v1/system/status", "/api-spec.yaml", "/openapi.yaml", "/ui/api-spec.yaml"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control = %q, want no-store", path, got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Fatalf("%s Pragma = %q, want no-cache", path, got)
		}
	}

	uiReq := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	uiRec := httptest.NewRecorder()
	handler.ServeHTTP(uiRec, uiReq)
	if got := uiRec.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("UI Cache-Control = %q, want empty", got)
	}
}

func TestAPISpecRedirectHandler(t *testing.T) {
	for _, path := range []string{"/api-spec.yaml", "/openapi.yaml"} {
		rec := httptest.NewRecorder()
		apiSpecRedirectHandler(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("%s status = %d, want %d", path, rec.Code, http.StatusFound)
		}
		if got := rec.Header().Get("Location"); got != "/ui/api-spec.yaml" {
			t.Fatalf("%s Location = %q, want /ui/api-spec.yaml", path, got)
		}
	}

	rec := httptest.NewRecorder()
	apiSpecRedirectHandler(rec, httptest.NewRequest(http.MethodGet, "/bad.yaml", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown spec path status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGatewayErrorHandlerSuppressesInternalErrors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/system/status", nil)
	rec := httptest.NewRecorder()
	gatewayErrorHandler(context.Background(), nil, &gwruntime.JSONPb{}, rec, req, grpcstatus.Error(codes.Internal, "open /var/lib/openngfw/store.db: permission denied"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"message":"internal server error"`) {
		t.Fatalf("body = %s, want sanitized internal error", body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got := decoded["code"]; got != float64(codes.Internal) {
		t.Fatalf("code = %#v, want numeric grpc code %d", got, codes.Internal)
	}
	if _, ok := decoded["details"].([]any); !ok {
		t.Fatalf("details = %#v, want array", decoded["details"])
	}
	if strings.Contains(body, "/var/lib/openngfw") {
		t.Fatalf("body leaked internal path: %s", body)
	}
}

func TestGatewayErrorHandlerRedactsSuppressedInternalLog(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/system/status", nil)
	rec := httptest.NewRecorder()
	raw := "open /etc/openngfw/ha-peer.token: permission denied Authorization: Bearer raw-token token=raw-token Cookie: oidc_session=session-secret collector=https://user:pass@fw.example/status?api_key=raw-secret"
	gatewayErrorHandler(context.Background(), nil, &gwruntime.JSONPb{}, rec, req, grpcstatus.Error(codes.Internal, raw))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"message":"internal server error"`) {
		t.Fatalf("body = %s, want generic internal error", body)
	}
	logBody := logs.String()
	for _, leaked := range []string{"raw-token", "session-secret", "user:pass", "raw-secret", "/etc/openngfw/ha-peer.token"} {
		if strings.Contains(logBody, leaked) {
			t.Fatalf("gateway log leaked %q in %s", leaked, logBody)
		}
	}
	for _, want := range []string{"REST gateway sanitized error detail", "Bearer [redacted]", "token=[redacted]", "Cookie: [redacted]", "https://[redacted]@fw.example/status?api_key=[redacted]", "[redacted]"} {
		if !strings.Contains(logBody, want) {
			t.Fatalf("gateway log = %s, want %q", logBody, want)
		}
	}
}

func TestGatewayErrorHandlerPreservesClientErrors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/running", nil)
	rec := httptest.NewRecorder()
	gatewayErrorHandler(context.Background(), nil, &gwruntime.JSONPb{}, rec, req, grpcstatus.Error(codes.InvalidArgument, "policy is invalid"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"message":"policy is invalid"`) {
		t.Fatalf("body = %s, want public validation error", body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got := decoded["code"]; got != float64(codes.InvalidArgument) {
		t.Fatalf("code = %#v, want numeric grpc code %d", got, codes.InvalidArgument)
	}
}

func TestGatewayErrorHandlerRedactsSensitiveClientErrors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/running", nil)
	rec := httptest.NewRecorder()
	raw := "validation failed Authorization: Bearer raw-token token=raw-token cookie=session-value collector=https://user:pass@fw.example/status?api_key=raw-secret open /var/lib/openngfw/store.db"
	gatewayErrorHandler(context.Background(), nil, &gwruntime.JSONPb{}, rec, req, grpcstatus.Error(codes.InvalidArgument, raw))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	for _, leaked := range []string{"raw-token", "session-value", "user:pass", "raw-secret", "/var/lib/openngfw/store.db"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("body leaked %q: %s", leaked, body)
		}
	}
	for _, want := range []string{"Bearer [redacted]", "token=[redacted]", "cookie=[redacted]", "https://[redacted]@fw.example/status?api_key=[redacted]", "[redacted]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body = %s, want redacted marker %q", body, want)
		}
	}
}

func TestGatewayLogErrorMessageRedactsSensitiveDetails(t *testing.T) {
	raw := "Authorization: Bearer raw-token token=raw-token Cookie: oidc_session=session-secret collector=https://user:pass@fw.example/status?api_key=raw-secret oidc_client_secret_file=/etc/openngfw/oidc-client-secret open /var/lib/openngfw/store.db"
	got := gatewayLogErrorMessage(raw)
	for _, leaked := range []string{"raw-token", "session-secret", "user:pass", "raw-secret", "/etc/openngfw/oidc-client-secret", "/var/lib/openngfw/store.db"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("gatewayLogErrorMessage leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{"Authorization: Bearer [redacted]", "token=[redacted]", "Cookie: [redacted]", "https://[redacted]@fw.example/status?api_key=[redacted]", "oidc_client_secret_file=[redacted]", "[redacted]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("gatewayLogErrorMessage = %q, want %q", got, want)
		}
	}
}

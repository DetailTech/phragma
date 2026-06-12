package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const usersYAML = `users:
  - name: alice
    token: admin-token-0123456789
    role: admin
  - name: bob
    token: operator-token-012345678
    role: operator
  - name: carol
    token: viewer-token-0123456789
    role: viewer
`

func writeUsers(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsLooseModes(t *testing.T) {
	path := writeUsers(t, usersYAML, 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("world-readable users file must be rejected")
	}
}

func TestLoadRejectsBadUsers(t *testing.T) {
	for name, content := range map[string]string{
		"short token":  "users:\n  - {name: x, token: short, role: admin}\n",
		"bad role":     "users:\n  - {name: x, token: 0123456789abcdef, role: root}\n",
		"empty":        "users: []\n",
		"missing name": "users:\n  - {token: 0123456789abcdef, role: admin}\n",
	} {
		path := writeUsers(t, content, 0o600)
		if _, err := Load(path); err == nil {
			t.Errorf("%s: expected load error", name)
		}
	}
}

func call(t *testing.T, a *Authenticator, token, method string) (string, error) {
	t.Helper()
	ctx := context.Background()
	if token != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	}
	var actorSeen string
	_, err := a.UnaryInterceptor()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, _ any) (any, error) {
			actorSeen = Actor(ctx)
			return nil, nil
		})
	return actorSeen, err
}

func TestRBAC(t *testing.T) {
	a, err := Load(writeUsers(t, usersYAML, 0o600))
	if err != nil {
		t.Fatal(err)
	}

	const read = "/openngfw.v1.PolicyService/GetPolicy"
	const write = "/openngfw.v1.PolicyService/Commit"

	tests := []struct {
		name, token, method string
		wantCode            codes.Code
		wantActor           string
	}{
		{"viewer reads", "viewer-token-0123456789", read, codes.OK, "carol"},
		{"viewer cannot commit", "viewer-token-0123456789", write, codes.PermissionDenied, ""},
		{"operator commits", "operator-token-012345678", write, codes.OK, "bob"},
		{"admin commits", "admin-token-0123456789", write, codes.OK, "alice"},
		{"no token", "", read, codes.Unauthenticated, ""},
		{"bad token", "wrong-token-0123456789", read, codes.Unauthenticated, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actor, err := call(t, a, tt.token, tt.method)
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("code = %v, want %v (err=%v)", got, tt.wantCode, err)
			}
			if tt.wantCode == codes.OK && actor != tt.wantActor {
				t.Errorf("actor = %q, want %q", actor, tt.wantActor)
			}
		})
	}
}

func TestActorDefault(t *testing.T) {
	if got := Actor(context.Background()); got != "local" {
		t.Fatalf("Actor without auth = %q", got)
	}
}

func TestOIDCScaffoldRefuses(t *testing.T) {
	if _, err := NewOIDCAuthenticator(OIDCConfig{Issuer: "https://example.com"}); err == nil {
		t.Fatal("OIDC scaffold must refuse until security review")
	}
}

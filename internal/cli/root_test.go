package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestDialAllowsTokenToLoopbackInsecureTransport(t *testing.T) {
	restoreTokenTransportForTest(t, "local-token", false)

	for _, addr := range []string{
		"127.0.0.1:9443",
		"localhost:9443",
		"[::1]:9443",
		"dns:///127.0.0.1:9443",
	} {
		t.Run(addr, func(t *testing.T) {
			conn, rpcCtx, cancel, err := dial(context.Background(), addr)
			if err != nil {
				t.Fatalf("dial(%q) error = %v, want nil", addr, err)
			}
			defer func() {
				cancel()
				_ = conn.Close()
			}()
			requireBearerToken(t, rpcCtx, "local-token")
		})
	}
}

func TestDialRejectsTokenToRemoteInsecureTransport(t *testing.T) {
	restoreTokenTransportForTest(t, "remote-token", false)

	conn, rpcCtx, cancel, err := dial(context.Background(), "198.51.100.10:9443")
	if err == nil {
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dial remote token transport error = nil, want rejection")
	}
	if conn != nil || rpcCtx != nil || cancel != nil {
		t.Fatalf("dial returned conn=%v rpcCtx=%v cancel=%v on rejected transport", conn, rpcCtx, cancel)
	}
	if !strings.Contains(err.Error(), "refusing to send bearer token over insecure gRPC to non-loopback server") {
		t.Fatalf("error %q does not explain token transport rejection", err)
	}
	if strings.Contains(err.Error(), "remote-token") {
		t.Fatalf("error leaks bearer token: %q", err)
	}
}

func TestDialAllowsTokenToRemoteWithExplicitInsecureOptIn(t *testing.T) {
	restoreTokenTransportForTest(t, "remote-token", true)

	conn, rpcCtx, cancel, err := dial(context.Background(), "198.51.100.10:9443")
	if err != nil {
		t.Fatalf("dial remote with explicit opt-in error = %v, want nil", err)
	}
	defer func() {
		cancel()
		_ = conn.Close()
	}()
	requireBearerToken(t, rpcCtx, "remote-token")
}

func TestDialReadsTokenFile(t *testing.T) {
	restoreTokenTransportForTest(t, "", false)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiTokenFile = tokenFile

	conn, rpcCtx, cancel, err := dial(context.Background(), "127.0.0.1:9443")
	if err != nil {
		t.Fatalf("dial with token file error = %v, want nil", err)
	}
	defer func() {
		cancel()
		_ = conn.Close()
	}()
	requireBearerToken(t, rpcCtx, "file-token")
}

func TestDialReadsTokenFromStdin(t *testing.T) {
	restoreTokenTransportForTest(t, "", false)
	apiTokenStdin = true
	apiTokenStdinReader = strings.NewReader("stdin-token\n")

	conn, rpcCtx, cancel, err := dial(context.Background(), "127.0.0.1:9443")
	if err != nil {
		t.Fatalf("dial with token stdin error = %v, want nil", err)
	}
	defer func() {
		cancel()
		_ = conn.Close()
	}()
	requireBearerToken(t, rpcCtx, "stdin-token")
}

func TestDialRejectsConflictingTokenSources(t *testing.T) {
	restoreTokenTransportForTest(t, "secret-token", false)
	apiTokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(apiTokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	conn, rpcCtx, cancel, err := dial(context.Background(), "127.0.0.1:9443")
	if err == nil {
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dial with conflicting token sources error = nil, want rejection")
	}
	if conn != nil || rpcCtx != nil || cancel != nil {
		t.Fatalf("dial returned conn=%v rpcCtx=%v cancel=%v on rejected token source", conn, rpcCtx, cancel)
	}
	if !strings.Contains(err.Error(), "conflicting API token sources") {
		t.Fatalf("error %q does not explain token source conflict", err)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "file-token") {
		t.Fatalf("error leaks bearer token: %q", err)
	}
}

func TestDialRejectsEmptyTokenFile(t *testing.T) {
	restoreTokenTransportForTest(t, "", false)
	apiTokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(apiTokenFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	conn, rpcCtx, cancel, err := dial(context.Background(), "127.0.0.1:9443")
	if err == nil {
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("dial with empty token file error = nil, want rejection")
	}
	if conn != nil || rpcCtx != nil || cancel != nil {
		t.Fatalf("dial returned conn=%v rpcCtx=%v cancel=%v on empty token file", conn, rpcCtx, cancel)
	}
	if !strings.Contains(err.Error(), "API token file is empty") {
		t.Fatalf("error %q does not explain empty token file", err)
	}
}

func restoreTokenTransportForTest(t *testing.T, token string, allowInsecure bool) {
	t.Helper()
	oldToken := apiToken
	oldTokenFile := apiTokenFile
	oldTokenStdin := apiTokenStdin
	oldTokenStdinReader := apiTokenStdinReader
	oldAllowInsecure := allowInsecureTokenTransport
	apiToken = token
	apiTokenFile = ""
	apiTokenStdin = false
	apiTokenStdinReader = os.Stdin
	allowInsecureTokenTransport = allowInsecure
	t.Cleanup(func() {
		apiToken = oldToken
		apiTokenFile = oldTokenFile
		apiTokenStdin = oldTokenStdin
		apiTokenStdinReader = oldTokenStdinReader
		allowInsecureTokenTransport = oldAllowInsecure
	})
}

//nolint:revive // Test helper convention keeps *testing.T first.
func requireBearerToken(t *testing.T, ctx context.Context, token string) {
	t.Helper()
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("missing outgoing metadata")
	}
	got := md.Get("authorization")
	want := "Bearer " + token
	if len(got) != 1 || got[0] != want {
		t.Fatalf("authorization metadata = %v, want [%q]", got, want)
	}
}

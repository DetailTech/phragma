package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCRuntimeSmoke(t *testing.T) {
	clientID := "openngfw-smoke"
	provider := newOIDCSmokeProvider(t, clientID)
	defer provider.Close()

	grpcAddr := reserveLoopbackAddr(t)
	httpAddr := reserveLoopbackAddr(t)
	workDir := t.TempDir()
	dataDir := filepath.Join(workDir, "data")
	logDir := filepath.Join(workDir, "log")

	cmd, waitCh, logPath := startOIDCSmokeControld(t, provider.Issuer(), clientID, grpcAddr, httpAddr, dataDir, logDir)
	defer stopOIDCSmokeControld(t, cmd, waitCh, logPath)

	baseURL := "http://" + httpAddr
	waitForOIDCStatus(t, baseURL, waitCh, logPath)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	loginLocation := oidcSmokeRedirect(t, client, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings")
	callbackLocation := oidcSmokeRedirect(t, client, loginLocation)
	finalLocation := oidcSmokeRedirect(t, client, callbackLocation)
	if finalLocation != "/ui/#/settings" {
		t.Fatalf("OIDC callback final redirect = %q, want /ui/#/settings", finalLocation)
	}

	status := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	if status["authenticated"] != true || status["actor"] != "smoke-admin" || status["role"] != "admin" {
		t.Fatalf("OIDC status = %#v, want authenticated smoke-admin/admin", status)
	}
	csrf, ok := status["csrf_token"].(string)
	if !ok || csrf == "" {
		t.Fatalf("OIDC status missing csrf_token: %#v", status)
	}

	identity := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/system/identity", "", nil)
	if identity["actor"] != "smoke-admin" || identity["role"] != "admin" || identity["authSource"] != "oidc-session" {
		t.Fatalf("identity = %#v, want smoke-admin/admin/oidc-session", identity)
	}

	forbidden := oidcSmokeStatus(t, client, http.MethodPost, baseURL+"/v1/system/tune", "{}", map[string]string{
		"Content-Type": "application/json",
		"Origin":       baseURL,
	})
	if forbidden != http.StatusForbidden {
		t.Fatalf("OIDC cookie mutation without CSRF returned %d, want 403", forbidden)
	}

	tune := oidcSmokeJSON(t, client, http.MethodPost, baseURL+"/v1/system/tune", "{}", map[string]string{
		"Content-Type":    "application/json",
		"Origin":          baseURL,
		"X-Phragma-CSRF":  csrf,
		"X-Forwarded-For": "198.51.100.88",
	})
	if _, ok := tune["profile"]; !ok {
		t.Fatalf("admin tune preview response = %#v, want profile", tune)
	}

	logoutStatus := oidcSmokeStatus(t, client, http.MethodPost, baseURL+"/v1/auth/logout", "", map[string]string{
		"Origin":         baseURL,
		"X-Phragma-CSRF": csrf,
	})
	if logoutStatus != http.StatusNoContent {
		t.Fatalf("OIDC logout returned %d, want 204", logoutStatus)
	}
	afterLogout := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	if afterLogout["authenticated"] != false {
		t.Fatalf("OIDC status after logout = %#v, want unauthenticated", afterLogout)
	}

	replayClient := newOIDCSmokeClient(t)
	if got := oidcSmokeStatus(t, replayClient, http.MethodGet, callbackLocation, "", nil); got != http.StatusUnauthorized {
		t.Fatalf("reused OIDC callback returned %d, want 401", got)
	}
	assertOIDCSmokeUnauthenticated(t, replayClient, baseURL)

	missingStateClient := newOIDCSmokeClient(t)
	if got := oidcSmokeStatus(t, missingStateClient, http.MethodGet, baseURL+"/v1/auth/oidc/callback", "", nil); got != http.StatusUnauthorized {
		t.Fatalf("missing-state OIDC callback returned %d, want 401", got)
	}
	assertOIDCSmokeUnauthenticated(t, missingStateClient, baseURL)

	pkceClient := newOIDCSmokeClient(t)
	pkceLogin := oidcSmokeRedirect(t, pkceClient, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings")
	pkceCallback := oidcSmokeRedirect(t, pkceClient, pkceLogin)
	provider.BreakCodeChallenge(t, pkceCallback)
	if got := oidcSmokeStatus(t, pkceClient, http.MethodGet, pkceCallback, "", nil); got != http.StatusUnauthorized {
		t.Fatalf("PKCE-failed OIDC callback returned %d, want 401", got)
	}
	assertOIDCSmokeUnauthenticated(t, pkceClient, baseURL)

	provider.SetNextNonceMismatch()
	nonceClient := newOIDCSmokeClient(t)
	nonceLogin := oidcSmokeRedirect(t, nonceClient, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings")
	nonceCallback := oidcSmokeRedirect(t, nonceClient, nonceLogin)
	if got := oidcSmokeStatus(t, nonceClient, http.MethodGet, nonceCallback, "", nil); got != http.StatusUnauthorized {
		t.Fatalf("nonce-mismatch OIDC callback returned %d, want 401", got)
	}
	assertOIDCSmokeUnauthenticated(t, nonceClient, baseURL)

	provider.SetNextIdentity("smoke-viewer", "viewer")
	viewerClient := newOIDCSmokeClient(t)
	viewerLogin := oidcSmokeRedirect(t, viewerClient, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings")
	viewerCallback := oidcSmokeRedirect(t, viewerClient, viewerLogin)
	if final := oidcSmokeRedirect(t, viewerClient, viewerCallback); final != "/ui/#/settings" {
		t.Fatalf("viewer OIDC final redirect = %q, want /ui/#/settings", final)
	}
	viewerStatus := oidcSmokeJSON(t, viewerClient, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	viewerCSRF, ok := viewerStatus["csrf_token"].(string)
	if !ok || viewerCSRF == "" || viewerStatus["actor"] != "smoke-viewer" || viewerStatus["role"] != "viewer" {
		t.Fatalf("viewer OIDC status = %#v, want smoke-viewer/viewer with csrf", viewerStatus)
	}
	viewerDenied := oidcSmokeStatus(t, viewerClient, http.MethodPost, baseURL+"/v1/system/tune", "{}", map[string]string{
		"Content-Type":   "application/json",
		"Origin":         baseURL,
		"X-Phragma-CSRF": viewerCSRF,
	})
	if viewerDenied != http.StatusForbidden {
		t.Fatalf("viewer OIDC tune preview returned %d, want 403", viewerDenied)
	}

	t.Log("oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac")
	t.Log("oidc_runtime_negative_scope=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial")
	t.Log("oidc_runtime_provider=loopback-mock")
	t.Log("oidc_runtime_actor=smoke-admin")
	t.Log("status=passed")
}

func TestOIDCRuntimeSmokeProviderLifecycle(t *testing.T) {
	clientID := "openngfw-runtime-provider"
	provider := newOIDCSmokeProvider(t, clientID)
	defer provider.Close()

	grpcAddr := reserveLoopbackAddr(t)
	httpAddr := reserveLoopbackAddr(t)
	workDir := t.TempDir()
	dataDir := filepath.Join(workDir, "data")
	logDir := filepath.Join(workDir, "log")
	usersFile := filepath.Join(workDir, "users.yaml")
	adminToken := "admin-runtime-token-0123456789"
	if err := os.WriteFile(usersFile, []byte(`users:
  - name: runtime-admin
    token: `+adminToken+`
    role: admin
`), 0o600); err != nil {
		t.Fatalf("write runtime users file: %v", err)
	}

	cmd, waitCh, logPath := startOIDCSmokeControldWithArgs(t, grpcAddr, httpAddr, dataDir, logDir,
		"--users-file", usersFile,
	)
	defer stopOIDCSmokeControld(t, cmd, waitCh, logPath)

	baseURL := "http://" + httpAddr
	waitForOIDCStatusValue(t, baseURL, waitCh, logPath, false)

	client := newOIDCSmokeClient(t)
	if got := oidcSmokeStatus(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings", "", nil); got != http.StatusNotFound {
		t.Fatalf("disabled OIDC login returned %d, want 404 before runtime provider set", got)
	}

	providerConfig := map[string]any{
		"enabled":     true,
		"issuer":      provider.Issuer(),
		"clientId":    clientID,
		"redirectUrl": "http://" + httpAddr + "/v1/auth/oidc/callback",
		"roleClaim":   "role",
		"defaultRole": "viewer",
		"scopes":      []string{"openid", "profile", "email"},
	}
	authJSONHeaders := map[string]string{
		"Authorization": "Bearer " + adminToken,
		"Content-Type":  "application/json",
	}
	validateResp := oidcSmokeJSONBody(t, client, http.MethodPost, baseURL+"/v1/system/access-administration/oidc/config:validate", map[string]any{
		"config": providerConfig,
	}, authJSONHeaders)
	state, _ := validateResp["state"].(string)
	if state != "ready" && state != "review" {
		t.Fatalf("runtime OIDC validate response = %#v, want ready or review state", validateResp)
	}
	if validateResp["normalizedConfig"] == nil {
		t.Fatalf("runtime OIDC validate response = %#v, want normalizedConfig", validateResp)
	}

	setStepUpToken := oidcSmokeStepUpToken(t, client, baseURL, authJSONHeaders, "access-oidc-set", "runtime smoke configure OIDC provider")
	setBody := map[string]any{
		"config":        providerConfig,
		"ackOidcChange": true,
		"comment":       "runtime smoke configure OIDC provider",
		"stepUpToken":   setStepUpToken,
	}
	setResp := oidcSmokeJSONBody(t, client, http.MethodPut, baseURL+"/v1/system/access-administration/oidc/config", setBody, authJSONHeaders)
	if setResp["detail"] == "" {
		t.Fatalf("runtime OIDC set response = %#v, want detail", setResp)
	}
	if strings.Contains(fmt.Sprint(setResp), usersFile) || strings.Contains(fmt.Sprint(setResp), adminToken) {
		t.Fatalf("runtime OIDC set response leaked secret/path material: %#v", setResp)
	}
	waitForOIDCStatusValue(t, baseURL, waitCh, logPath, true)

	loginLocation := oidcSmokeRedirect(t, client, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings")
	callbackLocation := oidcSmokeRedirect(t, client, loginLocation)
	finalLocation := oidcSmokeRedirect(t, client, callbackLocation)
	if finalLocation != "/ui/#/settings" {
		t.Fatalf("runtime OIDC callback final redirect = %q, want /ui/#/settings", finalLocation)
	}
	status := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	if status["authenticated"] != true || status["actor"] != "smoke-admin" || status["role"] != "admin" {
		t.Fatalf("runtime OIDC status = %#v, want authenticated smoke-admin/admin", status)
	}

	disableStepUpToken := oidcSmokeStepUpToken(t, client, baseURL, authJSONHeaders, "access-oidc-disable", "runtime smoke disable OIDC provider")
	disableResp := oidcSmokeJSONBody(t, client, http.MethodPost, baseURL+"/v1/system/access-administration/oidc/config:disable", map[string]any{
		"ackDisableOidc": true,
		"comment":        "runtime smoke disable OIDC provider",
		"stepUpToken":    disableStepUpToken,
	}, authJSONHeaders)
	if disableResp["disabled"] != true {
		t.Fatalf("runtime OIDC disable response = %#v, want disabled true", disableResp)
	}
	waitForOIDCStatusValue(t, baseURL, waitCh, logPath, false)
	afterDisable := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	if afterDisable["authenticated"] == true {
		t.Fatalf("runtime OIDC status after disable = %#v, want no authenticated session", afterDisable)
	}
	if got := oidcSmokeStatus(t, client, http.MethodGet, baseURL+"/v1/system/identity", "", nil); got != http.StatusUnauthorized {
		t.Fatalf("old OIDC session identity after provider disable returned %d, want 401", got)
	}
	if got := oidcSmokeStatus(t, newOIDCSmokeClient(t), http.MethodGet, baseURL+"/v1/auth/oidc/login?return=/ui/%23/settings", "", nil); got != http.StatusNotFound {
		t.Fatalf("disabled OIDC login after provider disable returned %d, want 404", got)
	}

	t.Log("oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac,runtime-provider-lifecycle")
	t.Log("oidc_runtime_provider_lifecycle=api-validate,set,disable,runtime-authenticator-replacement,session-revocation")
}

type oidcSmokeProvider struct {
	clientID string
	issuer   string
	key      *rsa.PrivateKey
	server   *httptest.Server

	mu    sync.Mutex
	codes map[string]oidcSmokeCode

	nextActor        string
	nextRole         string
	nextNonceInvalid bool
}

type oidcSmokeCode struct {
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Actor               string
	Role                string
	NonceInvalid        bool
}

func newOIDCSmokeProvider(t *testing.T, clientID string) *oidcSmokeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC smoke key: %v", err)
	}
	p := &oidcSmokeProvider{
		clientID: clientID,
		key:      key,
		codes:    map[string]oidcSmokeCode{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/auth", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.server = httptest.NewUnstartedServer(mux)
	p.issuer = "http://" + p.server.Listener.Addr().String()
	p.server.Start()
	return p
}

func (p *oidcSmokeProvider) Issuer() string {
	return p.issuer
}

func (p *oidcSmokeProvider) Close() {
	p.server.Close()
}

func (p *oidcSmokeProvider) SetNextIdentity(actor, role string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextActor = actor
	p.nextRole = role
}

func (p *oidcSmokeProvider) SetNextNonceMismatch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextNonceInvalid = true
}

func (p *oidcSmokeProvider) BreakCodeChallenge(t *testing.T, callbackLocation string) {
	t.Helper()
	u, err := url.Parse(callbackLocation)
	if err != nil {
		t.Fatalf("parse callback location %q: %v", callbackLocation, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("callback location %q missing code", callbackLocation)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	stored, ok := p.codes[code]
	if !ok {
		t.Fatalf("callback code %q not present in smoke provider", code)
	}
	stored.CodeChallenge = "broken-pkce-challenge"
	p.codes[code] = stored
}

func (p *oidcSmokeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeOIDCSmokeJSON(w, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/auth",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *oidcSmokeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeOIDCSmokeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &p.key.PublicKey,
		KeyID:     "oidc-smoke-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}})
}

func (p *oidcSmokeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.clientID || q.Get("response_type") != "code" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		http.Error(w, "missing authorization parameter", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		http.Error(w, "unsupported code challenge method", http.StatusBadRequest)
		return
	}
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	p.mu.Lock()
	actor, role, nonceInvalid := p.consumeNextIdentityLocked()
	p.codes[code] = oidcSmokeCode{
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Actor:               actor,
		Role:                role,
		NonceInvalid:        nonceInvalid,
	}
	p.mu.Unlock()

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	out := u.Query()
	out.Set("code", code)
	out.Set("state", q.Get("state"))
	u.RawQuery = out.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *oidcSmokeProvider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad token form", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	code, ok := p.codes[r.Form.Get("code")]
	delete(p.codes, r.Form.Get("code"))
	p.mu.Unlock()
	if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" {
		http.Error(w, "bad token request", http.StatusBadRequest)
		return
	}
	if !oidcSmokePKCEMatches(code, r.Form.Get("code_verifier")) {
		http.Error(w, "bad token request", http.StatusBadRequest)
		return
	}
	raw, err := p.idToken(code)
	if err != nil {
		http.Error(w, "could not sign token", http.StatusInternalServerError)
		return
	}
	writeOIDCSmokeJSON(w, map[string]any{
		"access_token": "oidc-smoke-access",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     raw,
	})
}

func (p *oidcSmokeProvider) consumeNextIdentityLocked() (string, string, bool) {
	actor := p.nextActor
	role := p.nextRole
	nonceInvalid := p.nextNonceInvalid
	p.nextActor = ""
	p.nextRole = ""
	p.nextNonceInvalid = false
	if actor == "" {
		actor = "smoke-admin"
	}
	if role == "" {
		role = "admin"
	}
	return actor, role, nonceInvalid
}

func oidcSmokePKCEMatches(code oidcSmokeCode, verifier string) bool {
	if code.CodeChallengeMethod != "S256" || code.CodeChallenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == code.CodeChallenge
}

func (p *oidcSmokeProvider) idToken(code oidcSmokeCode) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "oidc-smoke-key"),
	)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := jwt.Claims{
		Issuer:   p.Issuer(),
		Subject:  "smoke-admin-subject",
		Audience: jwt.Audience{p.clientID},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}
	privateClaims := struct {
		Nonce             string `json:"nonce"`
		Role              string `json:"role"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}{
		Nonce:             code.Nonce,
		Role:              code.Role,
		PreferredUsername: code.Actor,
		Email:             code.Actor + "@example.invalid",
	}
	if code.NonceInvalid {
		privateClaims.Nonce = code.Nonce + "-mismatch"
	}
	return jwt.Signed(signer).Claims(claims).Claims(privateClaims).Serialize()
}

func writeOIDCSmokeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func startOIDCSmokeControld(t *testing.T, issuer, clientID, grpcAddr, httpAddr, dataDir, logDir string) (*exec.Cmd, <-chan error, string) {
	t.Helper()
	return startOIDCSmokeControldWithArgs(t, grpcAddr, httpAddr, dataDir, logDir,
		"--oidc-issuer", issuer,
		"--oidc-client-id", clientID,
		"--oidc-redirect-url", "http://"+httpAddr+"/v1/auth/oidc/callback",
		"--oidc-role-claim", "role",
		"--oidc-default-role", "viewer",
	)
}

func startOIDCSmokeControldWithArgs(t *testing.T, grpcAddr, httpAddr, dataDir, logDir string, extraArgs ...string) (*exec.Cmd, <-chan error, string) {
	t.Helper()
	root := repoRootForOIDCSmoke(t)
	binary := buildOIDCSmokeControld(t, root, filepath.Dir(dataDir))
	logPath := filepath.Join(filepath.Dir(dataDir), "controld.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create controld log: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })

	args := []string{
		"--dry-run",
		"--tls=false",
		"--listen", grpcAddr,
		"--http-listen", httpAddr,
		"--data-dir", dataDir,
		"--log-dir", logDir,
		"--rate-limit-rpm", "0",
	}
	args = append(args, extraArgs...)
	cmd := exec.Command(binary, args...)
	cmd.Dir = root
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start controld: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	return cmd, waitCh, logPath
}

func buildOIDCSmokeControld(t *testing.T, root, workDir string) string {
	t.Helper()
	binary := filepath.Join(workDir, "controld-oidc-smoke")
	cmd := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/controld")
	cmd.Dir = root
	if os.Getenv("GOCACHE") == "" {
		cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(workDir, "go-cache"))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build OIDC smoke controld: %v\n%s", err, out)
	}
	return binary
}

func stopOIDCSmokeControld(t *testing.T, cmd *exec.Cmd, waitCh <-chan error, logPath string) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-waitCh:
		if err != nil && !strings.Contains(err.Error(), "signal: interrupt") {
			t.Logf("controld exited after interrupt: %v\n%s", err, readOIDCSmokeLog(logPath))
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-waitCh
		t.Logf("killed controld after timeout\n%s", readOIDCSmokeLog(logPath))
	}
}

func waitForOIDCStatus(t *testing.T, baseURL string, waitCh <-chan error, logPath string) {
	t.Helper()
	waitForOIDCStatusValue(t, baseURL, waitCh, logPath, true)
}

func waitForOIDCStatusValue(t *testing.T, baseURL string, waitCh <-chan error, logPath string, enabled bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	want := []byte(fmt.Sprintf(`"enabled":%t`, enabled))
	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			t.Fatalf("controld exited before OIDC status was ready: %v\n%s", err, readOIDCSmokeLog(logPath))
		default:
		}
		resp, err := http.Get(baseURL + "/v1/auth/oidc/status")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && bytes.Contains(body, want) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for OIDC enabled=%t status\n%s", enabled, readOIDCSmokeLog(logPath))
}

func newOIDCSmokeClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
}

func assertOIDCSmokeUnauthenticated(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	status := oidcSmokeJSON(t, client, http.MethodGet, baseURL+"/v1/auth/oidc/status", "", nil)
	if status["authenticated"] != false {
		t.Fatalf("OIDC status = %#v, want unauthenticated", status)
	}
}

func oidcSmokeRedirect(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 302\n%s", target, resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("GET %s missing Location header", target)
	}
	return loc
}

func oidcSmokeJSON(t *testing.T, client *http.Client, method, target, body string, headers map[string]string) map[string]any {
	t.Helper()
	resp := oidcSmokeResponse(t, client, method, target, body, headers)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s status = %d, want 200\n%s", method, target, resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s %s JSON: %v", method, target, err)
	}
	return out
}

func oidcSmokeJSONBody(t *testing.T, client *http.Client, method, target string, body any, headers map[string]string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s %s body: %v", method, target, err)
	}
	return oidcSmokeJSON(t, client, method, target, string(raw), headers)
}

func oidcSmokeStepUpToken(t *testing.T, client *http.Client, baseURL string, headers map[string]string, action, comment string) string {
	t.Helper()
	resp := oidcSmokeJSONBody(t, client, http.MethodPost, baseURL+"/v1/system/access-administration/step-up", map[string]any{
		"action":    action,
		"comment":   comment,
		"ackStepUp": true,
	}, headers)
	token, ok := resp["token"].(string)
	if !ok || token == "" {
		t.Fatalf("step-up response for %s = %#v, want token", action, resp)
	}
	return token
}

func oidcSmokeStatus(t *testing.T, client *http.Client, method, target, body string, headers map[string]string) int {
	t.Helper()
	resp := oidcSmokeResponse(t, client, method, target, body, headers)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func oidcSmokeResponse(t *testing.T, client *http.Client, method, target, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, target, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func repoRootForOIDCSmoke(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}

func readOIDCSmokeLog(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("read %s: %v", path, err)
	}
	return string(raw)
}

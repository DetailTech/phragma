package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/detailtech/oss-ngfw/internal/proxytrust"
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

func tokenHashString(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestLoadRejectsLooseModes(t *testing.T) {
	path := writeUsers(t, usersYAML, 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("world-readable users file must be rejected")
	}
}

func TestLoadRejectsBadUsers(t *testing.T) {
	for name, content := range map[string]string{
		"short token":     "users:\n  - {name: x, token: short, role: admin}\n",
		"bad role":        "users:\n  - {name: x, token: 0123456789abcdef, role: root}\n",
		"empty":           "users: []\n",
		"missing name":    "users:\n  - {token: 0123456789abcdef, role: admin}\n",
		"missing token":   "users:\n  - {name: x, role: admin}\n",
		"token and hash":  "users:\n  - {name: x, token: 0123456789abcdef, token_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, role: admin}\n",
		"bad hash prefix": "users:\n  - {name: x, token_hash: md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, role: admin}\n",
		"short hash":      "users:\n  - {name: x, token_hash: sha256:abcd, role: admin}\n",
		"non-hex hash":    "users:\n  - {name: x, token_hash: sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz, role: admin}\n",
	} {
		path := writeUsers(t, content, 0o600)
		if _, err := Load(path); err == nil {
			t.Errorf("%s: expected load error", name)
		}
	}
}

func TestLoadAcceptsHashedToken(t *testing.T) {
	path := writeUsers(t, `users:
  - name: alice
    token_hash: `+tokenHashString("admin-token-0123456789")+`
    role: admin
`, 0o600)
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := call(t, a, "admin-token-0123456789", "/openngfw.v1.PolicyService/Commit")
	if err != nil {
		t.Fatalf("hashed token rejected: %v", err)
	}
	if actor != "alice" {
		t.Fatalf("actor = %q, want alice", actor)
	}
}

func TestLoadExposesSafeLocalUserInventory(t *testing.T) {
	hashedToken := tokenHashString("hashed-token-0123456789")
	path := writeUsers(t, `users:
  - name: bob
    token_hash: `+hashedToken+`
    role: operator
  - name: alice
    token: admin-token-0123456789
    role: admin
`, 0o600)
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	inventory := a.LocalUserInventory()
	if len(inventory) != 2 {
		t.Fatalf("inventory length = %d, want 2", len(inventory))
	}
	if inventory[0].Name != "alice" || inventory[0].Role != "admin" || inventory[0].AuthSource != AuthSourceLocalUsersFile {
		t.Fatalf("first inventory row = %#v, want alice/admin/local-users-file", inventory[0])
	}
	if inventory[0].TokenMaterial != "plaintext-token-redacted" || inventory[1].TokenMaterial != "prehashed-token-redacted" {
		t.Fatalf("token material = %#v, want redacted material classes", inventory)
	}
	for _, row := range inventory {
		if !row.Editable || !row.Enabled {
			t.Fatalf("local user row should be API-editable and enabled: %#v", row)
		}
		if !strings.HasPrefix(row.AuditHash, "inventory-sha256:") {
			t.Fatalf("audit hash = %q, want inventory fingerprint prefix", row.AuditHash)
		}
	}
	inventory[0].Name = "mutated"
	if got := a.LocalUserInventory()[0].Name; got != "alice" {
		t.Fatalf("LocalUserInventory returned mutable backing slice, got first name %q", got)
	}

	raw, err := json.Marshal(a.LocalUserInventory())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{
		"admin-token-0123456789",
		hashedToken,
		strings.TrimPrefix(hashedToken, "sha256:"),
		"token_hash",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("inventory JSON leaked secret material %q in %s", secret, body)
		}
	}
}

func TestLocalUserLifecycleMutatesPrivateUsersFileAndAuthenticator(t *testing.T) {
	path := writeUsers(t, `users:
  - name: alice
    token: admin-token-0123456789
    role: admin
`, 0o600)
	auth, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	next, bob, bobToken, err := CreateLocalUser(path, "bob", "operator")
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	auth.ReplaceLocalUsers(next)
	if bob.Name != "bob" || bob.Role != "operator" || !bob.Enabled || !bob.Editable || bobToken == "" {
		t.Fatalf("created user/token wrong: user=%#v token=%q", bob, bobToken)
	}
	if _, err := call(t, auth, bobToken, "/openngfw.v1.PolicyService/Commit"); err != nil {
		t.Fatalf("created operator token rejected: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if body := string(raw); strings.Contains(body, bobToken) || !strings.Contains(body, "token_hash: sha256:") {
		t.Fatalf("users file leaked generated token or missed hash:\n%s", body)
	}

	next, bob, rotatedToken, err := RotateLocalUserToken(path, "bob")
	if err != nil {
		t.Fatalf("RotateLocalUserToken: %v", err)
	}
	auth.ReplaceLocalUsers(next)
	if rotatedToken == "" || rotatedToken == bobToken || bob.TokenMaterial != "prehashed-token-redacted" {
		t.Fatalf("rotated token metadata wrong: user=%#v old=%q new=%q", bob, bobToken, rotatedToken)
	}
	if _, err := call(t, auth, bobToken, "/openngfw.v1.PolicyService/GetPolicy"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old token code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	if _, err := call(t, auth, rotatedToken, "/openngfw.v1.PolicyService/Commit"); err != nil {
		t.Fatalf("rotated token rejected: %v", err)
	}

	next, bob, err = UpdateLocalUserRole(path, "bob", "viewer")
	if err != nil {
		t.Fatalf("UpdateLocalUserRole: %v", err)
	}
	auth.ReplaceLocalUsers(next)
	if bob.Role != "viewer" {
		t.Fatalf("updated role = %q, want viewer", bob.Role)
	}
	if _, err := call(t, auth, rotatedToken, "/openngfw.v1.PolicyService/Commit"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer commit code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if _, err := call(t, auth, rotatedToken, "/openngfw.v1.PolicyService/GetPolicy"); err != nil {
		t.Fatalf("viewer read rejected: %v", err)
	}

	next, bob, err = DisableLocalUser(path, "bob")
	if err != nil {
		t.Fatalf("DisableLocalUser bob: %v", err)
	}
	auth.ReplaceLocalUsers(next)
	if bob.Enabled {
		t.Fatalf("disabled user still enabled: %#v", bob)
	}
	if _, err := call(t, auth, rotatedToken, "/openngfw.v1.PolicyService/GetPolicy"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("disabled token code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	if _, _, err := DisableLocalUser(path, "alice"); err == nil || !strings.Contains(err.Error(), "at least one enabled local admin") {
		t.Fatalf("DisableLocalUser last admin error = %v, want last-admin guard", err)
	}
}

func TestLoadRejectsDuplicateTokenDigests(t *testing.T) {
	duplicate := tokenHashString("admin-token-0123456789")
	for name, content := range map[string]string{
		"two hashes": `users:
  - name: alice
    token_hash: ` + duplicate + `
    role: admin
  - name: bob
    token_hash: ` + duplicate + `
    role: operator
`,
		"legacy and hash": `users:
  - name: alice
    token: admin-token-0123456789
    role: admin
  - name: bob
    token_hash: ` + duplicate + `
    role: operator
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeUsers(t, content, 0o600)
			if _, err := Load(path); err == nil {
				t.Fatal("expected duplicate token digest error")
			}
		})
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
	const listNat = "/openngfw.v1.PolicyService/ListNatRules"
	const upsertSourceNat = "/openngfw.v1.PolicyService/UpsertCandidateSourceNat"
	const renameObject = "/openngfw.v1.PolicyService/RenamePolicyObject"
	const listBackupSnapshots = "/openngfw.v1.PolicyService/ListBackupSnapshots"
	const createBackupSnapshot = "/openngfw.v1.PolicyService/CreateBackupSnapshot"
	const previewBackupRestore = "/openngfw.v1.PolicyService/PreviewBackupSnapshotRestore"
	const listApprovals = "/openngfw.v1.PolicyService/ListChangeApprovals"
	const createApproval = "/openngfw.v1.PolicyService/CreateChangeApproval"
	const threatList = "/openngfw.v1.ThreatTuningService/ListThreatExceptions"
	const threatStage = "/openngfw.v1.ThreatTuningService/StageThreatException"
	const threatUpdate = "/openngfw.v1.ThreatTuningService/UpdateThreatException"
	const threatState = "/openngfw.v1.ThreatTuningService/SetThreatExceptionState"
	const threatRemove = "/openngfw.v1.ThreatTuningService/RemoveThreatException"
	const appIDReplay = "/openngfw.v1.AppIdService/CompareAppIdReplay"
	const appIDStage = "/openngfw.v1.AppIdService/StageAppIdObservation"
	const appIDRegressionSample = "/openngfw.v1.AppIdService/StageAppIdRegressionSample"
	const hostTune = "/openngfw.v1.SystemService/TuneHost"
	const telemetryExportStatus = "/openngfw.v1.SystemService/GetTelemetryExportStatus"
	const telemetryExportVerify = "/openngfw.v1.SystemService/VerifyTelemetryExport"
	const systemLogs = "/openngfw.v1.SystemService/ListSystemLogs"
	const capture = "/openngfw.v1.SystemService/StartPacketCapture"
	const supportBundle = "/openngfw.v1.SystemService/GetSupportBundle"
	const pullHAPolicy = "/openngfw.v1.SystemService/PullHighAvailabilityPolicy"
	const runtimeReadiness = "/openngfw.v1.SystemService/CheckRuntimeReadiness"
	const activateHAFailover = "/openngfw.v1.SystemService/ActivateHighAvailabilityFailover"
	const accessAdministration = "/openngfw.v1.SystemService/GetAccessAdministration"
	const stepUpChallenge = "/openngfw.v1.SystemService/CreateStepUpChallenge"
	const oidcPreflight = "/openngfw.v1.SystemService/RunOIDCPreflight"
	const createLocalUser = "/openngfw.v1.SystemService/CreateLocalUser"
	const updateLocalUser = "/openngfw.v1.SystemService/UpdateLocalUser"
	const rotateLocalUser = "/openngfw.v1.SystemService/RotateLocalUserToken"
	const disableLocalUser = "/openngfw.v1.SystemService/DisableLocalUser"
	const captureList = "/openngfw.v1.SystemService/ListPacketCaptures"
	const captureDownload = "/openngfw.v1.SystemService/DownloadPacketCapture"
	const captureRetention = "/openngfw.v1.SystemService/SetPacketCaptureRetention"
	const contentEvidence = "/openngfw.v1.IntelService/GetContentEvidence"
	const contentCorpus = "/openngfw.v1.IntelService/GetContentCorpus"
	const contentPreview = "/openngfw.v1.IntelService/PreviewContentPackage"
	const contentCompare = "/openngfw.v1.IntelService/CompareContentPackage"
	const contentInstall = "/openngfw.v1.IntelService/InstallContentPackage"
	const contentRollback = "/openngfw.v1.IntelService/RollbackContentPackage"
	const threatReplay = "/openngfw.v1.ThreatTuningService/ReplayThreatEvidence"

	tests := []struct {
		name, token, method string
		wantCode            codes.Code
		wantActor           string
	}{
		{"viewer reads", "viewer-token-0123456789", read, codes.OK, "carol"},
		{"viewer lists nat", "viewer-token-0123456789", listNat, codes.OK, "carol"},
		{"viewer lists backup snapshots", "viewer-token-0123456789", listBackupSnapshots, codes.OK, "carol"},
		{"viewer checks runtime readiness", "viewer-token-0123456789", runtimeReadiness, codes.OK, "carol"},
		{"viewer replays threat evidence", "viewer-token-0123456789", threatReplay, codes.OK, "carol"},
		{"viewer lists change approvals", "viewer-token-0123456789", listApprovals, codes.OK, "carol"},
		{"viewer lists threat exceptions", "viewer-token-0123456789", threatList, codes.OK, "carol"},
		{"viewer reads telemetry export status", "viewer-token-0123456789", telemetryExportStatus, codes.OK, "carol"},
		{"viewer cannot verify telemetry export", "viewer-token-0123456789", telemetryExportVerify, codes.PermissionDenied, ""},
		{"viewer reads system logs", "viewer-token-0123456789", systemLogs, codes.OK, "carol"},
		{"viewer reads content evidence", "viewer-token-0123456789", contentEvidence, codes.OK, "carol"},
		{"viewer reads content corpus", "viewer-token-0123456789", contentCorpus, codes.OK, "carol"},
		{"viewer cannot export support bundle", "viewer-token-0123456789", supportBundle, codes.PermissionDenied, ""},
		{"viewer cannot preview content package", "viewer-token-0123456789", contentPreview, codes.PermissionDenied, ""},
		{"viewer cannot compare content package", "viewer-token-0123456789", contentCompare, codes.PermissionDenied, ""},
		{"viewer cannot pull ha policy", "viewer-token-0123456789", pullHAPolicy, codes.PermissionDenied, ""},
		{"viewer cannot activate ha failover", "viewer-token-0123456789", activateHAFailover, codes.PermissionDenied, ""},
		{"viewer cannot upsert source nat", "viewer-token-0123456789", upsertSourceNat, codes.PermissionDenied, ""},
		{"viewer cannot rename object", "viewer-token-0123456789", renameObject, codes.PermissionDenied, ""},
		{"viewer cannot create backup snapshot", "viewer-token-0123456789", createBackupSnapshot, codes.PermissionDenied, ""},
		{"viewer cannot preview backup restore", "viewer-token-0123456789", previewBackupRestore, codes.PermissionDenied, ""},
		{"viewer cannot read access administration", "viewer-token-0123456789", accessAdministration, codes.PermissionDenied, ""},
		{"viewer cannot create step-up challenge", "viewer-token-0123456789", stepUpChallenge, codes.PermissionDenied, ""},
		{"viewer cannot run oidc preflight", "viewer-token-0123456789", oidcPreflight, codes.PermissionDenied, ""},
		{"viewer cannot create local user", "viewer-token-0123456789", createLocalUser, codes.PermissionDenied, ""},
		{"viewer cannot commit", "viewer-token-0123456789", write, codes.PermissionDenied, ""},
		{"viewer cannot create change approval", "viewer-token-0123456789", createApproval, codes.PermissionDenied, ""},
		{"viewer cannot stage threat exception", "viewer-token-0123456789", threatStage, codes.PermissionDenied, ""},
		{"viewer cannot update threat exception", "viewer-token-0123456789", threatUpdate, codes.PermissionDenied, ""},
		{"viewer cannot set threat exception state", "viewer-token-0123456789", threatState, codes.PermissionDenied, ""},
		{"viewer cannot remove threat exception", "viewer-token-0123456789", threatRemove, codes.PermissionDenied, ""},
		{"viewer compares App-ID replay", "viewer-token-0123456789", appIDReplay, codes.OK, "carol"},
		{"viewer cannot stage App-ID observation", "viewer-token-0123456789", appIDStage, codes.PermissionDenied, ""},
		{"viewer cannot stage App-ID regression sample", "viewer-token-0123456789", appIDRegressionSample, codes.PermissionDenied, ""},
		{"viewer cannot set capture retention", "viewer-token-0123456789", captureRetention, codes.PermissionDenied, ""},
		{"operator exports support bundle", "operator-token-012345678", supportBundle, codes.OK, "bob"},
		{"operator pulls ha policy", "operator-token-012345678", pullHAPolicy, codes.OK, "bob"},
		{"operator checks runtime readiness", "operator-token-012345678", runtimeReadiness, codes.OK, "bob"},
		{"operator upserts source nat", "operator-token-012345678", upsertSourceNat, codes.OK, "bob"},
		{"operator renames object", "operator-token-012345678", renameObject, codes.OK, "bob"},
		{"operator creates backup snapshot", "operator-token-012345678", createBackupSnapshot, codes.OK, "bob"},
		{"operator previews backup restore", "operator-token-012345678", previewBackupRestore, codes.OK, "bob"},
		{"operator commits", "operator-token-012345678", write, codes.OK, "bob"},
		{"operator lists change approvals", "operator-token-012345678", listApprovals, codes.OK, "bob"},
		{"operator stages threat exception", "operator-token-012345678", threatStage, codes.OK, "bob"},
		{"operator updates threat exception", "operator-token-012345678", threatUpdate, codes.OK, "bob"},
		{"operator sets threat exception state", "operator-token-012345678", threatState, codes.OK, "bob"},
		{"operator removes threat exception", "operator-token-012345678", threatRemove, codes.OK, "bob"},
		{"operator stages App-ID observation", "operator-token-012345678", appIDStage, codes.OK, "bob"},
		{"operator stages App-ID regression sample", "operator-token-012345678", appIDRegressionSample, codes.OK, "bob"},
		{"operator cannot read access administration", "operator-token-012345678", accessAdministration, codes.PermissionDenied, ""},
		{"operator cannot create step-up challenge", "operator-token-012345678", stepUpChallenge, codes.PermissionDenied, ""},
		{"operator cannot run oidc preflight", "operator-token-012345678", oidcPreflight, codes.PermissionDenied, ""},
		{"operator cannot update local user", "operator-token-012345678", updateLocalUser, codes.PermissionDenied, ""},
		{"operator cannot rotate local user", "operator-token-012345678", rotateLocalUser, codes.PermissionDenied, ""},
		{"operator cannot disable local user", "operator-token-012345678", disableLocalUser, codes.PermissionDenied, ""},
		{"operator cannot tune host", "operator-token-012345678", hostTune, codes.PermissionDenied, ""},
		{"operator cannot verify telemetry export", "operator-token-012345678", telemetryExportVerify, codes.PermissionDenied, ""},
		{"operator cannot start capture", "operator-token-012345678", capture, codes.PermissionDenied, ""},
		{"operator cannot activate ha failover", "operator-token-012345678", activateHAFailover, codes.PermissionDenied, ""},
		{"operator cannot list captures", "operator-token-012345678", captureList, codes.PermissionDenied, ""},
		{"operator cannot download captures", "operator-token-012345678", captureDownload, codes.PermissionDenied, ""},
		{"operator cannot set capture retention", "operator-token-012345678", captureRetention, codes.PermissionDenied, ""},
		{"operator cannot create change approval", "operator-token-012345678", createApproval, codes.PermissionDenied, ""},
		{"operator cannot preview content package", "operator-token-012345678", contentPreview, codes.PermissionDenied, ""},
		{"operator cannot compare content package", "operator-token-012345678", contentCompare, codes.PermissionDenied, ""},
		{"operator cannot install content package", "operator-token-012345678", contentInstall, codes.PermissionDenied, ""},
		{"operator cannot rollback content package", "operator-token-012345678", contentRollback, codes.PermissionDenied, ""},
		{"admin commits", "admin-token-0123456789", write, codes.OK, "alice"},
		{"admin creates change approval", "admin-token-0123456789", createApproval, codes.OK, "alice"},
		{"admin reads access administration", "admin-token-0123456789", accessAdministration, codes.OK, "alice"},
		{"admin creates step-up challenge", "admin-token-0123456789", stepUpChallenge, codes.OK, "alice"},
		{"admin runs oidc preflight", "admin-token-0123456789", oidcPreflight, codes.OK, "alice"},
		{"admin creates local user", "admin-token-0123456789", createLocalUser, codes.OK, "alice"},
		{"admin updates local user", "admin-token-0123456789", updateLocalUser, codes.OK, "alice"},
		{"admin rotates local user", "admin-token-0123456789", rotateLocalUser, codes.OK, "alice"},
		{"admin disables local user", "admin-token-0123456789", disableLocalUser, codes.OK, "alice"},
		{"admin tunes host", "admin-token-0123456789", hostTune, codes.OK, "alice"},
		{"admin verifies telemetry export", "admin-token-0123456789", telemetryExportVerify, codes.OK, "alice"},
		{"admin starts capture", "admin-token-0123456789", capture, codes.OK, "alice"},
		{"admin lists captures", "admin-token-0123456789", captureList, codes.OK, "alice"},
		{"admin downloads captures", "admin-token-0123456789", captureDownload, codes.OK, "alice"},
		{"admin sets capture retention", "admin-token-0123456789", captureRetention, codes.OK, "alice"},
		{"admin previews content package", "admin-token-0123456789", contentPreview, codes.OK, "alice"},
		{"admin installs content package", "admin-token-0123456789", contentInstall, codes.OK, "alice"},
		{"admin rollbacks content package", "admin-token-0123456789", contentRollback, codes.OK, "alice"},
		{"admin activates ha failover", "admin-token-0123456789", activateHAFailover, codes.OK, "alice"},
		{"unknown method denied", "admin-token-0123456789", "/openngfw.v1.PolicyService/FutureMutation", codes.PermissionDenied, ""},
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

func TestRBACRoleTableCoversRegisteredRPCs(t *testing.T) {
	methods := registeredRPCMethods()
	for _, method := range methods {
		if _, ok := minRoles[method]; !ok {
			t.Fatalf("%s missing from RBAC role table", method)
		}
	}
	if got, want := len(minRoles), len(methods); got != want {
		t.Fatalf("RBAC role table has %d entries, want exactly %d registered RPCs", got, want)
	}
}

func registeredRPCMethods() []string {
	descs := []grpc.ServiceDesc{
		openngfwv1.SystemService_ServiceDesc,
		openngfwv1.PolicyService_ServiceDesc,
		openngfwv1.AlertService_ServiceDesc,
		openngfwv1.FlowService_ServiceDesc,
		openngfwv1.IntelService_ServiceDesc,
		openngfwv1.ComplianceService_ServiceDesc,
		openngfwv1.AppIdService_ServiceDesc,
		openngfwv1.ExplainService_ServiceDesc,
		openngfwv1.ThreatTuningService_ServiceDesc,
	}
	var methods []string
	for _, desc := range descs {
		for _, method := range desc.Methods {
			methods = append(methods, "/"+desc.ServiceName+"/"+method.MethodName)
		}
	}
	return methods
}

func TestStepUpChallengeIsActionScopedAndOneTime(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKey{}, Identity{
		Name:       "alice",
		Role:       RoleAdmin,
		AuthSource: AuthSourceLocalUsersFile,
	})
	challenge, err := CreateStepUpChallenge(ctx, "commit", "reviewed change")
	if err != nil {
		t.Fatalf("CreateStepUpChallenge: %v", err)
	}
	if challenge.Token == "" || challenge.Action != "commit" || challenge.Actor != "alice" {
		t.Fatalf("challenge = %#v, want actor-bound commit token", challenge)
	}
	if err := RequireStepUp(ctx, "rollback", challenge.Token); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("action mismatch code = %v, want FailedPrecondition err=%v", status.Code(err), err)
	}
	next, err := CreateStepUpChallenge(ctx, "commit", "")
	if err != nil {
		t.Fatalf("CreateStepUpChallenge second: %v", err)
	}
	if err := RequireStepUp(ctx, "commit", next.Token); err != nil {
		t.Fatalf("RequireStepUp matching token: %v", err)
	}
	if err := RequireStepUp(ctx, "commit", next.Token); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("reused token code = %v, want FailedPrecondition err=%v", status.Code(err), err)
	}
}

func TestStepUpChallengeRequiresAuthenticatedIdentity(t *testing.T) {
	if _, err := CreateStepUpChallenge(context.Background(), "commit", ""); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CreateStepUpChallenge code = %v, want FailedPrecondition err=%v", status.Code(err), err)
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, Identity{
		Name:       "local",
		Role:       RoleAdmin,
		AuthSource: AuthSourceDisabledLocal,
	})
	if err := RequireStepUp(ctx, "commit", ""); err != nil {
		t.Fatalf("disabled-local auth should preserve in-process compatibility: %v", err)
	}
}

func TestRequestIdentityIncludesRole(t *testing.T) {
	a, err := Load(writeUsers(t, usersYAML, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer operator-token-012345678"))
	var got Identity
	_, err = a.UnaryInterceptor()(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/openngfw.v1.PolicyService/Commit"},
		func(ctx context.Context, _ any) (any, error) {
			got = RequestIdentity(ctx, true)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if got.Name != "bob" || got.Role != RoleOperator || got.AuthSource != AuthSourceLocalUsersFile {
		t.Fatalf("identity = %#v, want bob/operator/local-users-file", got)
	}
}

func TestActorDefault(t *testing.T) {
	if got := Actor(context.Background()); got != "local" {
		t.Fatalf("Actor without auth = %q", got)
	}
}

func TestRequestIdentityWithoutAuthIsLocalAdmin(t *testing.T) {
	got := RequestIdentity(context.Background(), false)
	if got.Name != "local" || got.Role != RoleAdmin || got.AuthSource != AuthSourceDisabledLocal {
		t.Fatalf("identity = %#v, want local/admin/disabled-local", got)
	}
}

func TestRoleFromOIDCClaim(t *testing.T) {
	tests := []struct {
		name    string
		claim   any
		want    Role
		wantErr bool
	}{
		{"missing defaults", nil, RoleViewer, false},
		{"single role", "operator", RoleOperator, false},
		{"array uses highest role", []any{"viewer", "admin", "operator"}, RoleAdmin, false},
		{"bad role", "root", 0, true},
		{"bad type", 42, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := roleFromClaim(tt.claim, RoleViewer)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("role = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCSessionLookupExpires(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	o := &OIDCAuthenticator{
		sessions: map[string]session{
			"live": {
				Identity:  Identity{Name: "dana", Role: RoleOperator, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(time.Minute),
			},
			"expired": {
				Identity:  Identity{Name: "erin", Role: RoleViewer, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(-time.Second),
			},
		},
		now: func() time.Time { return now },
	}
	if id, ok := o.LookupSession("live"); !ok || id.Name != "dana" || id.Role != RoleOperator || id.AuthSource != AuthSourceOIDCSession {
		t.Fatalf("live session = %#v ok=%v", id, ok)
	}
	if _, ok := o.LookupSession("expired"); ok {
		t.Fatal("expired session should not validate")
	}
	if _, ok := o.sessions["expired"]; ok {
		t.Fatal("expired session should be removed")
	}
}

func TestOIDCLoginCapsPendingStates(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	o := &OIDCAuthenticator{
		cfg: OIDCConfig{StateTTL: time.Minute, MaxStates: 2},
		oauth: &oauth2.Config{
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/auth"},
		},
		states: map[string]loginState{
			"old":   {ExpiresAt: now.Add(10 * time.Second)},
			"newer": {ExpiresAt: now.Add(30 * time.Second)},
		},
		now: func() time.Time { return now },
	}
	req := httptest.NewRequest(http.MethodGet, "http://fw.example.com/v1/auth/oidc/login?return=/ui/", nil)
	rr := httptest.NewRecorder()

	o.handleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body=%q", rr.Code, rr.Body.String())
	}
	if len(o.states) != 2 {
		t.Fatalf("pending state count = %d, want 2", len(o.states))
	}
	if _, ok := o.states["old"]; ok {
		t.Fatal("oldest pending state was not evicted")
	}
	if _, ok := o.states["newer"]; !ok {
		t.Fatal("newer pending state should have been retained")
	}
}

func TestOIDCSessionStoreCapsOldest(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	o := &OIDCAuthenticator{
		cfg: OIDCConfig{MaxSessions: 2},
		sessions: map[string]session{
			"old":   {Identity: Identity{Name: "old"}, ExpiresAt: now.Add(time.Minute)},
			"newer": {Identity: Identity{Name: "newer"}, ExpiresAt: now.Add(2 * time.Minute)},
		},
		now: func() time.Time { return now },
	}

	o.storeSession("fresh", session{Identity: Identity{Name: "fresh"}, ExpiresAt: now.Add(3 * time.Minute)})

	if len(o.sessions) != 2 {
		t.Fatalf("session count = %d, want 2", len(o.sessions))
	}
	if _, ok := o.sessions["old"]; ok {
		t.Fatal("oldest session was not evicted")
	}
	for _, token := range []string{"newer", "fresh"} {
		if _, ok := o.sessions[token]; !ok {
			t.Fatalf("session %q missing after cap enforcement", token)
		}
	}
}

func TestOIDCInventoryAndSessionStatsAreAggregateOnly(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	o := &OIDCAuthenticator{
		cfg: OIDCConfig{
			Issuer:            "https://idp.example.com",
			ClientID:          "phragma",
			RoleClaim:         "groups",
			DefaultRole:       "viewer",
			CookieSecure:      true,
			Scopes:            []string{"openid", "profile"},
			TrustedProxyCIDRs: []string{"10.0.0.0/24"},
			SessionTTL:        2 * time.Hour,
			MaxSessions:       7,
		},
		sessions: map[string]session{
			"live-session-token": {
				Identity:  Identity{Name: "dana", Role: RoleOperator, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(time.Minute),
				CSRFToken: "csrf-token-0123456789",
			},
			"expired-session-token": {
				Identity:  Identity{Name: "erin", Role: RoleViewer, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(-time.Second),
				CSRFToken: "expired-csrf-token-0123456789",
			},
		},
		now: func() time.Time { return now },
	}

	inventory := o.Inventory()
	if !inventory.Enabled || inventory.Issuer != "https://idp.example.com" || inventory.ClientID != "phragma" {
		t.Fatalf("inventory = %#v, want enabled issuer/client ID", inventory)
	}
	if inventory.SessionTTLSeconds != uint64((2*time.Hour).Seconds()) || len(inventory.Scopes) != 2 || inventory.Scopes[0] != "openid" {
		t.Fatalf("inventory = %#v, want configured TTL/scopes", inventory)
	}
	stats := o.SessionInventory()
	if stats.ActiveSessions != 1 || stats.MaxSessions != 7 || !stats.SessionRevocationAvailable {
		t.Fatalf("session stats = %#v, want one active session and admin revocation", stats)
	}
	if len(stats.Sessions) != 1 {
		t.Fatalf("session records = %d, want 1", len(stats.Sessions))
	}
	if got := stats.Sessions[0]; !strings.HasPrefix(got.ID, "oidc-session-sha256:") || got.Actor != "dana" || got.Role != RoleOperator.String() || got.AuthSource != AuthSourceOIDCSession {
		t.Fatalf("session record = %#v, want non-secret dana/operator session", got)
	}
	if _, ok := o.sessions["expired-session-token"]; ok {
		t.Fatal("expired OIDC session should be reaped while counting aggregate stats")
	}
	raw, err := json.Marshal(map[string]any{"oidc": inventory, "sessions": stats})
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{
		"live-session-token",
		"expired-session-token",
		"csrf-token-0123456789",
		"expired-csrf-token-0123456789",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("OIDC aggregate inventory leaked secret material %q in %s", secret, body)
		}
	}
}

func TestOIDCSessionInventoryAndRevokeUseNonSecretSessionIDs(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	o := &OIDCAuthenticator{
		cfg: OIDCConfig{MaxSessions: 7},
		sessions: map[string]session{
			"session-token-0123456789": {
				Identity:  Identity{Name: "dana", Role: RoleAdmin, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(10 * time.Minute),
				CSRFToken: "csrf-token-0123456789",
			},
		},
		now: func() time.Time { return now },
	}

	records := o.ListSessions()
	if len(records) != 1 {
		t.Fatalf("session records = %d, want 1", len(records))
	}
	rec := records[0]
	if !strings.HasPrefix(rec.ID, "oidc-session-sha256:") || strings.Contains(rec.ID, "session-token") {
		t.Fatalf("session id = %q, want non-secret digest id", rec.ID)
	}
	if got, ok := o.SessionRecord(rec.ID); !ok || got.Actor != "dana" {
		t.Fatalf("SessionRecord = %#v ok=%v, want dana", got, ok)
	}
	if revoked, ok := o.RevokeSession(rec.ID); !ok || revoked.ID != rec.ID || revoked.Actor != "dana" {
		t.Fatalf("RevokeSession = %#v ok=%v, want revoked dana session", revoked, ok)
	}
	if _, ok := o.LookupSession("session-token-0123456789"); ok {
		t.Fatal("revoked session should not validate")
	}
	if _, ok := o.RevokeSession(rec.ID); ok {
		t.Fatal("second revoke should not find the session")
	}
}

func testOIDCSessionAuth(now time.Time) *OIDCAuthenticator {
	return &OIDCAuthenticator{
		cfg: OIDCConfig{CookieName: DefaultOIDCCookieName},
		sessions: map[string]session{
			"live": {
				Identity:  Identity{Name: "dana", Role: RoleOperator, AuthSource: AuthSourceOIDCSession},
				ExpiresAt: now.Add(time.Minute),
				CSRFToken: "csrf-token-0123456789",
			},
		},
		now: func() time.Time { return now },
	}
}

func mustProxyTrust(t *testing.T, cidrs ...string) proxytrust.Set {
	t.Helper()
	set, err := proxytrust.New(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestOIDCSessionCookieAuthReadAllowsCookieWithoutCSRF(t *testing.T) {
	o := testOIDCSessionAuth(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC))
	var gotAuth string
	handler := o.WithSessionCookieAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://fw.example.com/v1/system/status", nil)
	req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if gotAuth != "Bearer live" {
		t.Fatalf("Authorization = %q, want bearer session", gotAuth)
	}
}

func TestOIDCSessionCookieAuthMutationRequiresSameOriginAndCSRF(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		origin  string
		csrf    string
		want    int
		wantRun bool
	}{
		{"missing origin and csrf", "", "", http.StatusForbidden, false},
		{"same origin without csrf", "https://fw.example.com", "", http.StatusForbidden, false},
		{"cross origin with csrf", "https://evil.example", "csrf-token-0123456789", http.StatusForbidden, false},
		{"same host wrong port with csrf", "https://fw.example.com:444", "csrf-token-0123456789", http.StatusForbidden, false},
		{"same origin with csrf", "http://fw.example.com", "csrf-token-0123456789", http.StatusNoContent, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := testOIDCSessionAuth(now)
			called := false
			handler := o.WithSessionCookieAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if got := r.Header.Get("Authorization"); got != "Bearer live" {
					t.Fatalf("Authorization = %q, want bearer session", got)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, "http://fw.example.com/v1/commit", nil)
			req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.csrf != "" {
				req.Header.Set(OIDCCSRFHeader, tt.csrf)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%q", rr.Code, tt.want, rr.Body.String())
			}
			if called != tt.wantRun {
				t.Fatalf("handler called = %v, want %v", called, tt.wantRun)
			}
		})
	}
}

func TestOIDCSessionCookieAuthUsesForwardedProtoForSameOrigin(t *testing.T) {
	o := testOIDCSessionAuth(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC))
	o.proxies = mustProxyTrust(t, "10.0.0.0/24")
	called := false
	handler := o.WithSessionCookieAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://fw.example.com/v1/commit", nil)
	req.RemoteAddr = "10.0.0.10:443"
	req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://fw.example.com")
	req.Header.Set(OIDCCSRFHeader, "csrf-token-0123456789")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent || !called {
		t.Fatalf("status = %d called=%v, want 204 and called", rr.Code, called)
	}
}

func TestOIDCSessionCookieAuthIgnoresForwardedProtoFromUntrustedPeer(t *testing.T) {
	o := testOIDCSessionAuth(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC))
	o.proxies = mustProxyTrust(t, "10.0.0.0/24")
	called := false
	handler := o.WithSessionCookieAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://fw.example.com/v1/commit", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://fw.example.com")
	req.Header.Set(OIDCCSRFHeader, "csrf-token-0123456789")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden || called {
		t.Fatalf("status = %d called=%v, want 403 and not called", rr.Code, called)
	}
}

func TestOIDCSessionCookieAuthBearerBypassesCSRF(t *testing.T) {
	o := testOIDCSessionAuth(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC))
	var gotAuth string
	handler := o.WithSessionCookieAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://fw.example.com/v1/commit", nil)
	req.Header.Set("Authorization", "Bearer local-api-token")
	req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if gotAuth != "Bearer local-api-token" {
		t.Fatalf("Authorization = %q, want explicit bearer token", gotAuth)
	}
}

func TestOIDCStatusIncludesCSRFForActiveSession(t *testing.T) {
	o := testOIDCSessionAuth(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC))
	req := httptest.NewRequest(http.MethodGet, "http://fw.example.com/v1/auth/oidc/status", nil)
	req.AddCookie(&http.Cookie{Name: DefaultOIDCCookieName, Value: "live"})
	rr := httptest.NewRecorder()

	o.handleStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["authenticated"] != true || body["csrf_token"] != "csrf-token-0123456789" {
		t.Fatalf("status body = %#v, want authenticated session csrf", body)
	}
	if body["actor"] != "dana" || body["role"] != "operator" {
		t.Fatalf("status identity = actor:%v role:%v, want dana/operator", body["actor"], body["role"])
	}
}

func TestSafeReturnPath(t *testing.T) {
	tests := map[string]string{
		"":                         "/ui/",
		"/ui/#/settings":           "/ui/#/settings",
		"/ui/?x=1#/rules":          "/ui/?x=1#/rules",
		"https://evil.example/ui/": "/ui/",
		"//evil.example/ui/":       "/ui/",
		"/v1/system/status":        "/ui/",
	}
	for raw, want := range tests {
		if got := safeReturnPath(raw); got != want {
			t.Fatalf("safeReturnPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestValidateOIDCConfigRequiresAbsoluteRedirect(t *testing.T) {
	cfg := OIDCConfig{
		Issuer:      "https://idp.example.com",
		ClientID:    "openngfw",
		RedirectURL: "/v1/auth/oidc/callback",
		DefaultRole: "viewer",
		RoleClaim:   "role",
	}
	if err := validateOIDCConfig(cfg); err == nil {
		t.Fatal("expected relative redirect URL to be rejected")
	}
	cfg.RedirectURL = "https://fw.example.com/v1/auth/oidc/callback"
	if err := validateOIDCConfig(cfg); err != nil {
		t.Fatalf("absolute redirect URL rejected: %v", err)
	}
	cfg.RedirectURL = "http://fw.example.com/v1/auth/oidc/callback"
	if err := validateOIDCConfig(cfg); err == nil {
		t.Fatal("expected non-loopback http redirect URL to be rejected")
	}
	cfg.RedirectURL = "http://127.0.0.1:8080/v1/auth/oidc/callback"
	if err := validateOIDCConfig(cfg); err != nil {
		t.Fatalf("loopback http redirect URL rejected: %v", err)
	}
}

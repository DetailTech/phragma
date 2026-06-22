// Package authz implements local authentication and RBAC for the API
// (M5). Three roles gate the canonical API:
//
//	viewer   — read-only RPCs
//	operator — viewer + candidate/commit/rollback + intel refresh
//	admin    — everything (reserved headroom for user management)
//
// Authentication supports local API tokens from a root-owned file plus
// short-lived OIDC and SAML browser sessions.
package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/detailtech/oss-ngfw/internal/securefile"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/yaml"
)

// Role is an access level. Higher includes lower.
type Role int

// Roles in ascending privilege.
const (
	// RoleViewer grants read-only API access.
	RoleViewer Role = iota + 1
	// RoleOperator grants operational API access.
	RoleOperator
	// RoleAdmin grants full API access.
	RoleAdmin
)

const (
	// AuthSourceDisabledLocal identifies disabled local authentication.
	AuthSourceDisabledLocal = "disabled-local"
	// AuthSourceLocalUsersFile identifies users-file authentication.
	AuthSourceLocalUsersFile = "local-users-file"
	// AuthSourceOIDCSession identifies browser OIDC session authentication.
	AuthSourceOIDCSession = "oidc-session"
	// AuthSourceSAMLSession identifies browser SAML session authentication.
	AuthSourceSAMLSession = "saml-session"
)

// ParseRole maps the file representation to a Role.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(s) {
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	default:
		return 0, fmt.Errorf("unknown role %q (viewer|operator|admin)", s)
	}
}

// String returns the stable API/file representation for a role.
func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// User is one local API user.
type User struct {
	Name      string `json:"name"`
	Token     string `json:"token,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled,omitempty"`
}

// LocalUserInventory is the non-secret view of one loaded local users-file
// entry. It deliberately omits raw token material and token digests.
type LocalUserInventory struct {
	Name          string
	Role          string
	AuthSource    string
	TokenMaterial string
	Editable      bool
	AuditHash     string
	Enabled       bool
}

// usersFile is the on-disk format.
type usersFile struct {
	Users []User `json:"users"`
}

// SessionLookup validates an opaque server-side session token and returns the
// identity it represents.
type SessionLookup func(token string) (Identity, bool)

// Authenticator validates bearer tokens and enforces RBAC.
type Authenticator struct {
	mu            sync.RWMutex
	users         map[[32]byte]authedUser // keyed by local users-file token digest
	localUsers    []LocalUserInventory
	sessionLookup SessionLookup
}

type authedUser struct {
	name       string
	role       Role
	authSource string
}

// NewAuthenticator returns an empty authenticator. It is useful when browser
// sessions are the only enabled auth source.
func NewAuthenticator() *Authenticator {
	return &Authenticator{users: map[[32]byte]authedUser{}}
}

// SetSessionLookup installs the browser session validator used by the same
// interceptor as local tokens.
func (a *Authenticator) SetSessionLookup(lookup SessionLookup) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionLookup = lookup
}

// CompositeSessionLookup tries browser session validators in order.
func CompositeSessionLookup(lookups ...SessionLookup) SessionLookup {
	var active []SessionLookup
	for _, lookup := range lookups {
		if lookup != nil {
			active = append(active, lookup)
		}
	}
	if len(active) == 0 {
		return nil
	}
	return func(token string) (Identity, bool) {
		for _, lookup := range active {
			if id, ok := lookup(token); ok {
				return id, true
			}
		}
		return Identity{}, false
	}
}

// ReplaceLocalUsers swaps local users-file credentials in place so an
// installed interceptor sees user lifecycle changes without daemon restart.
// Browser session lookup is intentionally preserved.
func (a *Authenticator) ReplaceLocalUsers(next *Authenticator) {
	if a == nil || next == nil {
		return
	}
	if a == next {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next.mu.RLock()
	defer next.mu.RUnlock()
	a.users = make(map[[32]byte]authedUser, len(next.users))
	for digest, user := range next.users {
		a.users[digest] = user
	}
	a.localUsers = append([]LocalUserInventory(nil), next.localUsers...)
}

// Load reads a users file (YAML). The file must be private and owned by a
// trusted local principal because it controls API bearer-token access.
func Load(path string) (*Authenticator, error) {
	if err := securefile.ValidatePrivateFile(path, "users file"); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var usersDoc usersFile
	if err := yaml.Unmarshal(raw, &usersDoc); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	a := NewAuthenticator()
	for _, user := range usersDoc.Users {
		name := strings.TrimSpace(user.Name)
		if name == "" {
			return nil, fmt.Errorf("user %q: name required", user.Name)
		}
		tokenMaterial := localTokenMaterial(user)
		digest, err := userTokenDigest(user)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", user.Name, err)
		}
		role, err := ParseRole(user.Role)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", user.Name, err)
		}
		enabled := !user.Disabled
		if enabled {
			if _, dup := a.users[digest]; dup {
				return nil, fmt.Errorf("duplicate token in users file")
			}
			a.users[digest] = authedUser{name: name, role: role, authSource: AuthSourceLocalUsersFile}
		}
		a.localUsers = append(a.localUsers, LocalUserInventory{
			Name:          name,
			Role:          role.String(),
			AuthSource:    AuthSourceLocalUsersFile,
			TokenMaterial: tokenMaterial,
			Editable:      true,
			AuditHash:     localUserAuditHash(name, role.String(), tokenMaterial, enabled),
			Enabled:       enabled,
		})
	}
	if len(a.users) == 0 {
		return nil, fmt.Errorf("users file %s defines no users", path)
	}
	sort.Slice(a.localUsers, func(i, j int) bool {
		if a.localUsers[i].Name != a.localUsers[j].Name {
			return a.localUsers[i].Name < a.localUsers[j].Name
		}
		if a.localUsers[i].Role != a.localUsers[j].Role {
			return a.localUsers[i].Role < a.localUsers[j].Role
		}
		return a.localUsers[i].AuditHash < a.localUsers[j].AuditHash
	})
	return a, nil
}

// LocalUserInventory returns a defensive copy of the loaded local user
// inventory. It never consults files after Load and never exposes token
// material.
func (a *Authenticator) LocalUserInventory() []LocalUserInventory {
	if a != nil {
		a.mu.RLock()
		defer a.mu.RUnlock()
	}
	if a == nil || len(a.localUsers) == 0 {
		return nil
	}
	out := make([]LocalUserInventory, len(a.localUsers))
	copy(out, a.localUsers)
	return out
}

func localTokenMaterial(u User) string {
	switch {
	case strings.TrimSpace(u.Token) != "":
		return "plaintext-token-redacted"
	case strings.TrimSpace(u.TokenHash) != "":
		return "prehashed-token-redacted"
	default:
		return "missing-token-material"
	}
}

func localUserAuditHash(name, role, tokenMaterial string, enabled bool) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		"local-user-inventory-v1",
		AuthSourceLocalUsersFile,
		name,
		role,
		tokenMaterial,
		fmt.Sprintf("enabled=%t", enabled),
	}, "\x00")))
	return "inventory-sha256:" + hex.EncodeToString(digest[:])
}

// CreateLocalUser adds a users-file entry with a generated one-time token.
func CreateLocalUser(path, name, role string) (*Authenticator, LocalUserInventory, string, error) {
	var out LocalUserInventory
	var token string
	auth, err := mutateUsersFile(path, func(usersDoc *usersFile) error {
		normalizedName, err := normalizeLocalUserName(name)
		if err != nil {
			return err
		}
		if _, found := findUserIndex(usersDoc.Users, normalizedName); found {
			return fmt.Errorf("local user %q already exists", normalizedName)
		}
		parsedRole, err := ParseRole(role)
		if err != nil {
			return err
		}
		token, err = generateLocalUserToken()
		if err != nil {
			return err
		}
		usersDoc.Users = append(usersDoc.Users, User{
			Name:      normalizedName,
			TokenHash: localUserTokenHash(token),
			Role:      parsedRole.String(),
		})
		return nil
	})
	if err != nil {
		return nil, out, "", err
	}
	out, _ = findInventoryUser(auth.LocalUserInventory(), name)
	return auth, out, token, nil
}

// UpdateLocalUserRole changes an existing enabled or disabled local user's role.
func UpdateLocalUserRole(path, name, role string) (*Authenticator, LocalUserInventory, error) {
	var out LocalUserInventory
	auth, err := mutateUsersFile(path, func(usersDoc *usersFile) error {
		normalizedName, err := normalizeLocalUserName(name)
		if err != nil {
			return err
		}
		idx, found := findUserIndex(usersDoc.Users, normalizedName)
		if !found {
			return fmt.Errorf("local user %q not found", normalizedName)
		}
		parsedRole, err := ParseRole(role)
		if err != nil {
			return err
		}
		usersDoc.Users[idx].Role = parsedRole.String()
		return validateEnabledLocalAdmin(usersDoc.Users)
	})
	if err != nil {
		return nil, out, err
	}
	out, _ = findInventoryUser(auth.LocalUserInventory(), name)
	return auth, out, nil
}

// RotateLocalUserToken replaces an existing local user's token_hash and returns
// the generated token once.
func RotateLocalUserToken(path, name string) (*Authenticator, LocalUserInventory, string, error) {
	var out LocalUserInventory
	var token string
	auth, err := mutateUsersFile(path, func(usersDoc *usersFile) error {
		normalizedName, err := normalizeLocalUserName(name)
		if err != nil {
			return err
		}
		idx, found := findUserIndex(usersDoc.Users, normalizedName)
		if !found {
			return fmt.Errorf("local user %q not found", normalizedName)
		}
		token, err = generateLocalUserToken()
		if err != nil {
			return err
		}
		usersDoc.Users[idx].Token = ""
		usersDoc.Users[idx].TokenHash = localUserTokenHash(token)
		return nil
	})
	if err != nil {
		return nil, out, "", err
	}
	out, _ = findInventoryUser(auth.LocalUserInventory(), name)
	return auth, out, token, nil
}

// DisableLocalUser disables an existing local user and prevents it from
// authenticating on the returned Authenticator.
func DisableLocalUser(path, name string) (*Authenticator, LocalUserInventory, error) {
	var out LocalUserInventory
	auth, err := mutateUsersFile(path, func(usersDoc *usersFile) error {
		normalizedName, err := normalizeLocalUserName(name)
		if err != nil {
			return err
		}
		idx, found := findUserIndex(usersDoc.Users, normalizedName)
		if !found {
			return fmt.Errorf("local user %q not found", normalizedName)
		}
		usersDoc.Users[idx].Disabled = true
		return validateEnabledLocalAdmin(usersDoc.Users)
	})
	if err != nil {
		return nil, out, err
	}
	out, _ = findInventoryUser(auth.LocalUserInventory(), name)
	return auth, out, nil
}

func mutateUsersFile(path string, mutate func(*usersFile) error) (*Authenticator, error) {
	if err := securefile.ValidatePrivateFile(path, "users file"); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var usersDoc usersFile
	if err := yaml.Unmarshal(raw, &usersDoc); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	if err := mutate(&usersDoc); err != nil {
		return nil, err
	}
	if err := validateEnabledLocalAdmin(usersDoc.Users); err != nil {
		return nil, err
	}
	sort.SliceStable(usersDoc.Users, func(i, j int) bool {
		return strings.TrimSpace(usersDoc.Users[i].Name) < strings.TrimSpace(usersDoc.Users[j].Name)
	})
	encoded, err := yaml.Marshal(usersDoc)
	if err != nil {
		return nil, err
	}
	if err := writePrivateUsersFile(path, encoded); err != nil {
		return nil, err
	}
	return Load(path)
}

func writePrivateUsersFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".users-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func normalizeLocalUserName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", fmt.Errorf("local user name is required")
	case len(name) > 128:
		return "", fmt.Errorf("local user name must be at most 128 characters")
	case strings.ContainsAny(name, "/\x00\r\n\t"):
		return "", fmt.Errorf("local user name contains unsupported characters")
	default:
		return name, nil
	}
}

func findUserIndex(users []User, name string) (int, bool) {
	for i, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.Name), strings.TrimSpace(name)) {
			return i, true
		}
	}
	return -1, false
}

//nolint:unparam // The found flag is part of the lookup contract even when callers only need the value today.
func findInventoryUser(users []LocalUserInventory, name string) (LocalUserInventory, bool) {
	for _, user := range users {
		if strings.EqualFold(user.Name, strings.TrimSpace(name)) {
			return user, true
		}
	}
	return LocalUserInventory{}, false
}

func validateEnabledLocalAdmin(users []User) error {
	for _, user := range users {
		if user.Disabled {
			continue
		}
		role, err := ParseRole(user.Role)
		if err != nil {
			return fmt.Errorf("user %q: %w", user.Name, err)
		}
		if role == RoleAdmin {
			return nil
		}
	}
	return fmt.Errorf("at least one enabled local admin user is required")
}

func generateLocalUserToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "phr_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func localUserTokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func userTokenDigest(u User) ([32]byte, error) {
	token := strings.TrimSpace(u.Token)
	tokenHash := strings.TrimSpace(u.TokenHash)
	switch {
	case token != "" && tokenHash != "":
		return [32]byte{}, fmt.Errorf("set exactly one of token or token_hash")
	case token != "":
		if len(token) < 16 {
			return [32]byte{}, fmt.Errorf("token must be at least 16 characters")
		}
		return sha256.Sum256([]byte(token)), nil
	case tokenHash != "":
		return parseTokenHash(tokenHash)
	default:
		return [32]byte{}, fmt.Errorf("set exactly one of token or token_hash")
	}
}

func parseTokenHash(raw string) ([32]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(strings.ToLower(raw), prefix) {
		return [32]byte{}, fmt.Errorf("token_hash must use sha256:<hex>")
	}
	hexValue := raw[len(prefix):]
	if len(hexValue) != sha256.Size*2 {
		return [32]byte{}, fmt.Errorf("token_hash sha256 digest must be %d hex characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(hexValue)
	if err != nil {
		return [32]byte{}, fmt.Errorf("token_hash sha256 digest must be hex: %w", err)
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest, nil
}

// minRoles maps every registered RPC method to the minimum role. Unknown
// methods are denied by default so new mutating/admin RPCs cannot become
// accidentally callable as viewer operations.
var minRoles = map[string]Role{
	"/openngfw.v1.SystemService/GetVersion":                       RoleViewer,
	"/openngfw.v1.SystemService/GetStatus":                        RoleViewer,
	"/openngfw.v1.SystemService/ProveNetworkPath":                 RoleViewer,
	"/openngfw.v1.SystemService/GetTelemetryExportStatus":         RoleViewer,
	"/openngfw.v1.SystemService/VerifyTelemetryExport":            RoleAdmin,
	"/openngfw.v1.SystemService/ListSystemLogs":                   RoleViewer,
	"/openngfw.v1.SystemService/CheckRuntimeReadiness":            RoleViewer,
	"/openngfw.v1.SystemService/GetHighAvailabilityStatus":        RoleViewer,
	"/openngfw.v1.SystemService/PullHighAvailabilityPolicy":       RoleOperator,
	"/openngfw.v1.SystemService/ActivateHighAvailabilityFailover": RoleAdmin,
	"/openngfw.v1.SystemService/GetReleaseAcceptanceStatus":       RoleViewer,
	"/openngfw.v1.SystemService/GetSupportBundle":                 RoleOperator,
	"/openngfw.v1.SystemService/GetIdentity":                      RoleViewer,
	"/openngfw.v1.SystemService/CreateStepUpChallenge":            RoleAdmin,
	"/openngfw.v1.SystemService/GetAccessAdministration":          RoleAdmin,
	"/openngfw.v1.SystemService/RunOIDCPreflight":                 RoleAdmin,
	"/openngfw.v1.SystemService/GetOIDCProviderConfig":            RoleAdmin,
	"/openngfw.v1.SystemService/ValidateOIDCProviderConfig":       RoleAdmin,
	"/openngfw.v1.SystemService/SetOIDCProviderConfig":            RoleAdmin,
	"/openngfw.v1.SystemService/DisableOIDCProvider":              RoleAdmin,
	"/openngfw.v1.SystemService/GetSAMLProviderConfig":            RoleAdmin,
	"/openngfw.v1.SystemService/ValidateSAMLProviderConfig":       RoleAdmin,
	"/openngfw.v1.SystemService/SetSAMLProviderConfig":            RoleAdmin,
	"/openngfw.v1.SystemService/DisableSAMLProvider":              RoleAdmin,
	"/openngfw.v1.SystemService/CreateLocalUser":                  RoleAdmin,
	"/openngfw.v1.SystemService/UpdateLocalUser":                  RoleAdmin,
	"/openngfw.v1.SystemService/RotateLocalUserToken":             RoleAdmin,
	"/openngfw.v1.SystemService/DisableLocalUser":                 RoleAdmin,
	"/openngfw.v1.SystemService/RevokeAccessSession":              RoleAdmin,
	"/openngfw.v1.SystemService/PlanPacketCapture":                RoleViewer,
	"/openngfw.v1.SystemService/ListPacketCaptures":               RoleAdmin,
	"/openngfw.v1.SystemService/TuneHost":                         RoleAdmin,
	"/openngfw.v1.SystemService/StartPacketCapture":               RoleAdmin,
	"/openngfw.v1.SystemService/DownloadPacketCapture":            RoleAdmin,
	"/openngfw.v1.SystemService/SetPacketCaptureRetention":        RoleAdmin,
	"/openngfw.v1.PolicyService/GetPolicy":                        RoleViewer,
	"/openngfw.v1.PolicyService/GetCandidateStatus":               RoleViewer,
	"/openngfw.v1.PolicyService/ListNatRules":                     RoleViewer,
	"/openngfw.v1.PolicyService/ListObjectReferences":             RoleViewer,
	"/openngfw.v1.PolicyService/DiffPolicy":                       RoleViewer,
	"/openngfw.v1.PolicyService/ListChangeApprovals":              RoleViewer,
	"/openngfw.v1.PolicyService/ListBackupSnapshots":              RoleViewer,
	"/openngfw.v1.PolicyService/GetBackupSnapshot":                RoleViewer,
	"/openngfw.v1.PolicyService/ValidateBackupSnapshot":           RoleViewer,
	"/openngfw.v1.PolicyService/ListVersions":                     RoleViewer,
	"/openngfw.v1.PolicyService/ListAuditEntries":                 RoleViewer,
	"/openngfw.v1.PolicyService/VerifyAuditIntegrity":             RoleViewer,
	"/openngfw.v1.PolicyService/SetCandidate":                     RoleOperator,
	"/openngfw.v1.PolicyService/Validate":                         RoleOperator,
	"/openngfw.v1.PolicyService/UpsertCandidateSourceNat":         RoleOperator,
	"/openngfw.v1.PolicyService/DeleteCandidateSourceNat":         RoleOperator,
	"/openngfw.v1.PolicyService/UpsertCandidateDestinationNat":    RoleOperator,
	"/openngfw.v1.PolicyService/DeleteCandidateDestinationNat":    RoleOperator,
	"/openngfw.v1.PolicyService/RenamePolicyObject":               RoleOperator,
	"/openngfw.v1.PolicyService/CreateBackupSnapshot":             RoleOperator,
	"/openngfw.v1.PolicyService/PreviewBackupSnapshotRestore":     RoleOperator,
	"/openngfw.v1.PolicyService/Commit":                           RoleOperator,
	"/openngfw.v1.PolicyService/Rollback":                         RoleOperator,
	"/openngfw.v1.PolicyService/CreateChangeApproval":             RoleAdmin,
	"/openngfw.v1.AlertService/ListAlerts":                        RoleViewer,
	"/openngfw.v1.FlowService/ListFlows":                          RoleViewer,
	"/openngfw.v1.FlowService/ListSessions":                       RoleViewer,
	"/openngfw.v1.ComplianceService/ListComplianceReports":        RoleViewer,
	"/openngfw.v1.ComplianceService/GetComplianceReport":          RoleViewer,
	"/openngfw.v1.ComplianceService/ExportComplianceReport":       RoleViewer,
	"/openngfw.v1.ComplianceService/CreateComplianceReport":       RoleOperator,
	"/openngfw.v1.AppIdService/ListAppIdObservations":             RoleViewer,
	"/openngfw.v1.AppIdService/CompareAppIdReplay":                RoleViewer,
	"/openngfw.v1.AppIdService/StageAppIdObservation":             RoleOperator,
	"/openngfw.v1.AppIdService/StageAppIdRegressionSample":        RoleOperator,
	"/openngfw.v1.ExplainService/ExplainFlow":                     RoleViewer,
	"/openngfw.v1.IntelService/ListFeeds":                         RoleViewer,
	"/openngfw.v1.IntelService/ListContentPackages":               RoleViewer,
	"/openngfw.v1.IntelService/GetContentEvidence":                RoleViewer,
	"/openngfw.v1.IntelService/GetContentCorpus":                  RoleViewer,
	"/openngfw.v1.ThreatTuningService/ListThreatExceptions":       RoleViewer,
	"/openngfw.v1.ThreatTuningService/StageThreatException":       RoleOperator,
	"/openngfw.v1.ThreatTuningService/UpdateThreatException":      RoleOperator,
	"/openngfw.v1.ThreatTuningService/SetThreatExceptionState":    RoleOperator,
	"/openngfw.v1.ThreatTuningService/RemoveThreatException":      RoleOperator,
	"/openngfw.v1.ThreatTuningService/ReplayThreatEvidence":       RoleViewer,
	"/openngfw.v1.IntelService/PreviewContentPackage":             RoleAdmin,
	"/openngfw.v1.IntelService/CompareContentPackage":             RoleAdmin,
	"/openngfw.v1.IntelService/InstallContentPackage":             RoleAdmin,
	"/openngfw.v1.IntelService/RollbackContentPackage":            RoleAdmin,
	"/openngfw.v1.IntelService/RefreshFeeds":                      RoleOperator,
}

type ctxKey struct{}

// Identity is the authenticated API caller carried on the request context.
type Identity struct {
	Name       string
	Role       Role
	AuthSource string
}

// Actor returns the authenticated user name, or "local" when
// authentication is disabled.
func Actor(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return id.Name
	}
	return "local"
}

// RequestIdentity returns the current caller. When authentication is disabled
// local calls are treated as admin, matching the historical API behavior.
func RequestIdentity(ctx context.Context, authEnabled bool) Identity {
	if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
		if id.AuthSource == "" {
			id.AuthSource = "unknown"
		}
		return id
	}
	if authEnabled {
		return Identity{Name: "unknown", Role: 0, AuthSource: "unknown"}
	}
	return Identity{Name: "local", Role: RoleAdmin, AuthSource: AuthSourceDisabledLocal}
}

// IdentityFromContext returns the authenticated identity and whether it came
// from the auth interceptor.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// UnaryInterceptor authenticates every call and enforces RBAC.
func (a *Authenticator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		token := bearerToken(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		user, ok := a.lookup(token)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		required, ok := minRoles[info.FullMethod]
		if !ok {
			return nil, status.Errorf(codes.PermissionDenied, "method is not registered in RBAC policy: %s", info.FullMethod)
		}
		if user.role < required {
			return nil, status.Errorf(codes.PermissionDenied, "role does not permit %s", info.FullMethod)
		}
		return handler(context.WithValue(ctx, ctxKey{}, Identity{Name: user.name, Role: user.role, AuthSource: user.authSource}), req)
	}
}

// lookup hashes the presented bearer token before consulting the local user
// table, so raw users-file tokens are not retained after load.
func (a *Authenticator) lookup(token string) (authedUser, bool) {
	digest := sha256.Sum256([]byte(token))
	a.mu.RLock()
	defer a.mu.RUnlock()
	if user, ok := a.users[digest]; ok {
		return user, true
	}
	if a.sessionLookup != nil {
		if id, ok := a.sessionLookup(token); ok {
			return authedUser{name: id.Name, role: id.Role, authSource: id.AuthSource}, true
		}
	}
	return authedUser{}, false
}

// AuthenticateBearer validates a bearer token for HTTP handlers that are not
// served through the gRPC interceptor.
func (a *Authenticator) AuthenticateBearer(token string) (Identity, bool) {
	if a == nil {
		return Identity{}, false
	}
	user, ok := a.lookup(strings.TrimSpace(token))
	if !ok {
		return Identity{}, false
	}
	return Identity{Name: user.name, Role: user.role, AuthSource: user.authSource}, true
}

// bearerToken extracts the token from gRPC metadata. grpc-gateway
// forwards the HTTP Authorization header under both keys depending on
// version, so check both.
func bearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{"authorization", "grpcgateway-authorization"} {
		for _, v := range md.Get(key) {
			if t, ok := strings.CutPrefix(v, "Bearer "); ok {
				return t
			}
		}
	}
	return ""
}

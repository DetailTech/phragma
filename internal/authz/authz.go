// Package authz implements local authentication and RBAC for the API
// (M5). Three roles gate the canonical API:
//
//	viewer   — read-only RPCs
//	operator — viewer + candidate/commit/rollback + intel refresh
//	admin    — everything (reserved headroom for user management)
//
// Authentication is local API tokens from a root-owned file. OIDC/SAML
// is scaffolding only (see oidc.go) — implementing network-exposed SSO
// requires human security review per the project guardrails.
package authz

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

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
	RoleViewer Role = iota + 1
	RoleOperator
	RoleAdmin
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

// User is one local API user.
type User struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Role  string `json:"role"`
}

// usersFile is the on-disk format.
type usersFile struct {
	Users []User `json:"users"`
}

// Authenticator validates tokens and enforces RBAC.
type Authenticator struct {
	users map[string]authedUser // keyed by token
}

type authedUser struct {
	name string
	role Role
}

// Load reads a users file (YAML). The file must not be group/world
// readable — it contains bearer tokens.
func Load(path string) (*Authenticator, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("users file %s must not be group/world accessible (chmod 600)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var uf usersFile
	if err := yaml.Unmarshal(raw, &uf); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	a := &Authenticator{users: map[string]authedUser{}}
	for _, u := range uf.Users {
		if u.Name == "" || len(u.Token) < 16 {
			return nil, fmt.Errorf("user %q: name required and token must be at least 16 characters", u.Name)
		}
		role, err := ParseRole(u.Role)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		if _, dup := a.users[u.Token]; dup {
			return nil, fmt.Errorf("duplicate token in users file")
		}
		a.users[u.Token] = authedUser{name: u.Name, role: role}
	}
	if len(a.users) == 0 {
		return nil, fmt.Errorf("users file %s defines no users", path)
	}
	return a, nil
}

// minRoles maps full RPC method names to the minimum role. Methods not
// listed require RoleViewer (read-only by default — a new mutating RPC
// must be added here deliberately).
var minRoles = map[string]Role{
	"/openngfw.v1.PolicyService/SetCandidate": RoleOperator,
	"/openngfw.v1.PolicyService/Validate":     RoleOperator,
	"/openngfw.v1.PolicyService/Commit":       RoleOperator,
	"/openngfw.v1.PolicyService/Rollback":     RoleOperator,
	"/openngfw.v1.IntelService/RefreshFeeds":  RoleOperator,
}

type ctxKey struct{}

// Actor returns the authenticated user name, or "local" when
// authentication is disabled.
func Actor(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return "local"
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
		required := minRoles[info.FullMethod]
		if required == 0 {
			required = RoleViewer
		}
		if user.role < required {
			return nil, status.Errorf(codes.PermissionDenied, "role does not permit %s", info.FullMethod)
		}
		return handler(context.WithValue(ctx, ctxKey{}, user.name), req)
	}
}

// lookup is constant-time over the token value.
func (a *Authenticator) lookup(token string) (authedUser, bool) {
	for t, u := range a.users {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return u, true
		}
	}
	return authedUser{}, false
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

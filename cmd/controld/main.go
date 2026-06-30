// controld is the OpenNGFW control-plane daemon.
//
// It owns the policy store (candidate/commit/rollback), compiles policy
// to the IR, renders per-engine configs, and supervises the engines.
// The gRPC API is canonical; REST is served via grpc-gateway.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/intel"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/securefile"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/supportbundle"
	"github.com/detailtech/oss-ngfw/internal/tlsutil"
	"github.com/detailtech/oss-ngfw/internal/version"
	"github.com/detailtech/oss-ngfw/internal/webui"
)

const (
	maxHAPeerStatusBytes = 1 << 20
	maxHAPeerPolicyBytes = 16 << 20
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	grpcListen := flag.String("listen", "127.0.0.1:9443", "gRPC listen address")
	httpListen := flag.String("http-listen", "127.0.0.1:8080", "REST gateway listen address (empty disables)")
	dataDir := flag.String("data-dir", "/var/lib/openngfw", "state directory (store, rendered configs)")
	logDir := flag.String("log-dir", "/var/log/openngfw", "engine log directory (eve.json)")
	releaseAcceptanceManifest := flag.String("release-acceptance-manifest", "release/acceptance.json", "release acceptance manifest path exposed read-only through the WebUI")
	releaseEvidenceDir := flag.String("release-evidence-dir", "release/evidence", "release acceptance evidence directory exposed read-only through the WebUI")
	releaseNoPerformanceClaims := flag.Bool("release-no-performance-claims", false, "treat missing release-benchmark evidence as not applicable for releases that publish no performance claims")
	haMode := flag.String("ha-mode", "standalone", "high-availability mode reported by status: standalone | active-passive")
	haRole := flag.String("ha-role", "", "local high-availability role when --ha-mode=active-passive: active | passive")
	haNodeID := flag.String("ha-node-id", "", "local high-availability node identifier reported by status")
	haPeerID := flag.String("ha-peer-id", "", "peer high-availability node identifier reported by status")
	haPeerAddress := flag.String("ha-peer-address", "", "peer high-availability control address reported by status")
	haPeerURL := flag.String("ha-peer-url", "", "peer /v1/system/ha/status HTTPS URL used for read-only heartbeat evidence")
	haPeerTokenFile := flag.String("ha-peer-token-file", "", "file containing bearer token for peer HA status polling (chmod 600)")
	haPeerCAFile := flag.String("ha-peer-ca-file", "", "PEM CA bundle used to verify the peer HA status HTTPS endpoint")
	haHeartbeatTimeout := flag.Duration("ha-heartbeat-timeout", 2*time.Second, "timeout for read-only HA peer status polling")
	haHeartbeatStaleAfter := flag.Duration("ha-heartbeat-stale-after", 30*time.Second, "maximum accepted age for peer HA status heartbeat evidence")
	haAutoPolicyReplication := flag.Bool("ha-auto-policy-replication", false, "automatically pull newer active-peer policy on passive active/passive nodes")
	haPolicyReplicationInterval := flag.Duration("ha-policy-replication-interval", time.Minute, "interval for automatic passive HA policy replication checks")
	haPolicyReplicationComment := flag.String("ha-policy-replication-comment", "automatic passive HA policy replication", "audit comment used for automatic HA policy replication")
	haPromoteVIP := flag.String("ha-promote-vip", "", "CIDR VIP to promote locally during HA passive activation, for example 192.0.2.10/32")
	haPromoteInterface := flag.String("ha-promote-interface", "", "interface that receives --ha-promote-vip during HA passive activation")
	haPromoteRouteDestination := flag.String("ha-promote-route-destination", "", "optional route destination CIDR promoted with the HA VIP")
	haPromoteRouteVia := flag.String("ha-promote-route-via", "", "optional next-hop IP for --ha-promote-route-destination")
	haPromoteRouteMetric := flag.Uint("ha-promote-route-metric", 0, "optional metric for --ha-promote-route-destination")
	haPromoteAnnounce := flag.Bool("ha-promote-announce", true, "send gratuitous ARP after promoting an IPv4 HA VIP")
	ebpfPinRoot := flag.String("ebpf-pin-root", "/sys/fs/bpf/openngfw", "read-only eBPF pin root reported by status evidence")
	ebpfArtifactDir := flag.String("ebpf-artifact-dir", "", "directory containing read-only eBPF field evidence artifacts; defaults to <data-dir>/ebpf")
	ebpfAttachProbeInterfaces := flag.String("ebpf-attach-probe-interfaces", "", "comma-separated interfaces to inspect when --ebpf-runtime-probes is enabled")
	ebpfRuntimeProbes := flag.Bool("ebpf-runtime-probes", false, "collect read-only bpftool runtime attachment evidence in system status")
	dryRun := flag.Bool("dry-run", false, "render and validate but never touch engines (dev/demo)")
	usersFile := flag.String("users-file", "", "local API users file enabling token auth + RBAC (YAML; chmod 600)")
	accessConfigFile := flag.String("access-config-file", "", "node-local access config file for runtime browser SSO provider state; defaults to <data-dir>/access.json")
	allowUnauthenticatedLocal := flag.Bool("allow-unauthenticated-local", false, "allow no-auth loopback dry-run mode for isolated lab/debug use only")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL enabling browser SSO when set")
	oidcClientID := flag.String("oidc-client-id", "", "OIDC client ID for browser SSO")
	oidcClientSecretFile := flag.String("oidc-client-secret-file", "", "file containing the OIDC client secret (chmod 600; optional for public clients)")
	oidcRedirectURL := flag.String("oidc-redirect-url", "", "OIDC redirect URL, usually https://<host>/v1/auth/oidc/callback")
	oidcRoleClaim := flag.String("oidc-role-claim", "role", "OIDC claim containing viewer/operator/admin role")
	oidcDefaultRole := flag.String("oidc-default-role", "viewer", "OIDC role used when the role claim is absent")
	oidcScopes := flag.String("oidc-scopes", "openid,profile,email", "comma-separated OIDC scopes")
	tlsEnabled := flag.Bool("tls", true, "serve the REST gateway/WebUI over HTTPS (self-signed cert generated under <data-dir>/tls if no cert/key given)")
	tlsCert := flag.String("tls-cert", "", "PEM certificate for the REST gateway (enables operator-provided TLS instead of self-signed)")
	tlsKey := flag.String("tls-key", "", "PEM private key for the REST gateway")
	allowPublicSelfSignedTLS := flag.Bool("allow-public-self-signed-tls", false, "allow generated self-signed TLS on a non-loopback REST/WebUI listener (temporary lab use only)")
	rateLimitRPM := flag.Int("rate-limit-rpm", 600, "per-client request rate limit for REST API/OIDC and direct gRPC; embedded WebUI static assets are not counted; 0 disables")
	rateLimitBurst := flag.Int("rate-limit-burst", 120, "per-client burst allowed by --rate-limit-rpm")
	rateLimitMaxClients := flag.Int("rate-limit-max-clients", defaultRateLimitMaxClients, "maximum client identities tracked by the REST API/OIDC and direct gRPC rate limiter")
	trustedProxyCIDRs := flag.String("trusted-proxy-cidrs", "", "comma-separated proxy CIDRs whose X-Forwarded-For and X-Forwarded-Proto headers are trusted for REST/WebUI/OIDC")
	httpMaxBodyBytes := flag.Int64("http-max-body-bytes", defaultHTTPMaxBodyBytes, "maximum REST/WebUI request body size in bytes; 0 disables the explicit cap")
	httpMaxHeaderBytes := flag.Int("http-max-header-bytes", http.DefaultMaxHeaderBytes, "maximum REST/WebUI request header size in bytes; 0 uses Go's default")
	httpReadHeaderTimeout := flag.Duration("http-read-header-timeout", 10*time.Second, "maximum time to read REST/WebUI request headers")
	httpReadTimeout := flag.Duration("http-read-timeout", 15*time.Second, "maximum time to read a full REST/WebUI request")
	httpWriteTimeout := flag.Duration("http-write-timeout", 30*time.Second, "maximum time to write a REST/WebUI response")
	httpIdleTimeout := flag.Duration("http-idle-timeout", 2*time.Minute, "maximum idle keep-alive time for REST/WebUI clients")
	grpcMaxRecvBytes := flag.Int("grpc-max-recv-bytes", defaultGRPCMaxMessageBytes, "maximum inbound gRPC message size in bytes; 0 uses gRPC default")
	grpcMaxSendBytes := flag.Int("grpc-max-send-bytes", defaultGRPCMaxMessageBytes, "maximum outbound gRPC message size in bytes; 0 uses gRPC default")
	flag.Parse()

	if *showVersion {
		fmt.Println("controld " + version.String())
		return
	}

	cfg := config{
		grpcListen: *grpcListen, httpListen: *httpListen,
		dataDir: *dataDir, logDir: *logDir, usersFile: *usersFile, accessConfigFile: *accessConfigFile,
		releaseAcceptanceManifest: *releaseAcceptanceManifest, releaseEvidenceDir: *releaseEvidenceDir, releaseNoPerformanceClaims: *releaseNoPerformanceClaims,
		haMode: *haMode, haRole: *haRole, haNodeID: *haNodeID, haPeerID: *haPeerID, haPeerAddress: *haPeerAddress,
		haPeerURL: *haPeerURL, haPeerTokenFile: *haPeerTokenFile, haPeerCAFile: *haPeerCAFile,
		haHeartbeatTimeout: *haHeartbeatTimeout, haHeartbeatStaleAfter: *haHeartbeatStaleAfter,
		haAutoPolicyReplication: *haAutoPolicyReplication, haPolicyReplicationInterval: *haPolicyReplicationInterval, haPolicyReplicationComment: *haPolicyReplicationComment,
		haPromoteVIP: *haPromoteVIP, haPromoteInterface: *haPromoteInterface, haPromoteRouteDestination: *haPromoteRouteDestination,
		haPromoteRouteVia: *haPromoteRouteVia, haPromoteRouteMetric: uint32(*haPromoteRouteMetric), haPromoteAnnounce: *haPromoteAnnounce,
		ebpfPinRoot: *ebpfPinRoot, ebpfArtifactDir: *ebpfArtifactDir, ebpfAttachProbeInterfaces: *ebpfAttachProbeInterfaces, ebpfRuntimeProbes: *ebpfRuntimeProbes,
		oidcIssuer: *oidcIssuer, oidcClientID: *oidcClientID, oidcClientSecretFile: *oidcClientSecretFile,
		oidcRedirectURL: *oidcRedirectURL, oidcRoleClaim: *oidcRoleClaim, oidcDefaultRole: *oidcDefaultRole, oidcScopes: *oidcScopes,
		dryRun: *dryRun, allowUnauthenticatedLocal: *allowUnauthenticatedLocal,
		tlsEnabled: *tlsEnabled, tlsCert: *tlsCert, tlsKey: *tlsKey, allowPublicSelfSignedTLS: *allowPublicSelfSignedTLS,
		rateLimitRPM: *rateLimitRPM, rateLimitBurst: *rateLimitBurst, rateLimitMaxClients: *rateLimitMaxClients, trustedProxyCIDRs: *trustedProxyCIDRs,
		httpMaxBodyBytes: *httpMaxBodyBytes, httpMaxHeaderBytes: *httpMaxHeaderBytes,
		httpReadHeaderTimeout: *httpReadHeaderTimeout, httpReadTimeout: *httpReadTimeout,
		httpWriteTimeout: *httpWriteTimeout, httpIdleTimeout: *httpIdleTimeout,
		grpcMaxRecvBytes: *grpcMaxRecvBytes, grpcMaxSendBytes: *grpcMaxSendBytes,
	}
	if err := run(cfg); err != nil {
		slog.Error("controld exited", "error", err)
		os.Exit(1)
	}
}

// config holds the resolved daemon flags.
type config struct {
	grpcListen, httpListen      string
	dataDir, logDir             string
	releaseAcceptanceManifest   string
	releaseEvidenceDir          string
	releaseNoPerformanceClaims  bool
	haMode                      string
	haRole                      string
	haNodeID                    string
	haPeerID                    string
	haPeerAddress               string
	haPeerURL                   string
	haPeerTokenFile             string
	haPeerCAFile                string
	haHeartbeatTimeout          time.Duration
	haHeartbeatStaleAfter       time.Duration
	haAutoPolicyReplication     bool
	haPolicyReplicationInterval time.Duration
	haPolicyReplicationComment  string
	haPromoteVIP                string
	haPromoteInterface          string
	haPromoteRouteDestination   string
	haPromoteRouteVia           string
	haPromoteRouteMetric        uint32
	haPromoteAnnounce           bool
	ebpfPinRoot                 string
	ebpfArtifactDir             string
	ebpfAttachProbeInterfaces   string
	ebpfRuntimeProbes           bool
	usersFile                   string
	accessConfigFile            string
	oidcIssuer                  string
	oidcClientID                string
	oidcClientSecretFile        string
	oidcRedirectURL             string
	oidcRoleClaim               string
	oidcDefaultRole             string
	oidcScopes                  string
	dryRun                      bool
	allowUnauthenticatedLocal   bool
	tlsEnabled                  bool
	tlsCert, tlsKey             string
	allowPublicSelfSignedTLS    bool
	rateLimitRPM                int
	rateLimitBurst              int
	rateLimitMaxClients         int
	trustedProxyCIDRs           string
	httpMaxBodyBytes            int64
	httpMaxHeaderBytes          int
	httpReadHeaderTimeout       time.Duration
	httpReadTimeout             time.Duration
	httpWriteTimeout            time.Duration
	httpIdleTimeout             time.Duration
	grpcMaxRecvBytes            int
	grpcMaxSendBytes            int
}

func run(cfg config) error {
	if err := validateServerLimits(cfg); err != nil {
		return err
	}
	if err := validateHAFlags(cfg); err != nil {
		return err
	}
	if err := validateManagementAuth(cfg); err != nil {
		return err
	}
	startedAt := time.Now().UTC()
	grpcListen, httpListen := cfg.grpcListen, cfg.httpListen
	dataDir, logDir, usersFile, dryRun := cfg.dataDir, cfg.logDir, cfg.usersFile, cfg.dryRun
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	haPromoter, err := haPromoterFromConfig(dataDir, cfg)
	if err != nil {
		return err
	}
	accessConfigFile := strings.TrimSpace(cfg.accessConfigFile)
	if accessConfigFile == "" {
		accessConfigFile = filepath.Join(dataDir, "access.json")
	}
	contentDir := filepath.Join(dataDir, "content")
	contentImportDir := filepath.Join(dataDir, "content-import")
	ebpfArtifactDir := cfg.ebpfArtifactDir
	if ebpfArtifactDir == "" {
		ebpfArtifactDir = filepath.Join(dataDir, "ebpf")
	}
	if err := os.MkdirAll(contentImportDir, 0o750); err != nil {
		return fmt.Errorf("create content import dir: %w", err)
	}
	st, err := store.Open(filepath.Join(dataDir, "store.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	opts := renderers.DefaultOptions(dataDir, logDir)
	// Fan the inline IPS across the host's CPUs (one NFQUEUE + Suricata
	// worker each), capped so very large hosts don't create excessive
	// queues. Single-CPU hosts keep one queue.
	opts.InspectionWorkers = runtime.NumCPU()
	if opts.InspectionWorkers > 16 {
		opts.InspectionWorkers = 16
	}

	var sup *engines.Supervisor
	var suricata *engines.Suricata
	var vector *engines.Vector
	if dryRun {
		slog.Warn("running in dry-run mode: engine changes are NOT applied")
		sup = engines.NewSupervisor(
			&engines.DryRun{EngineName: engines.NftablesName},
			&engines.DryRun{EngineName: engines.RoutesName},
			&engines.DryRun{EngineName: engines.SuricataName},
			&engines.DryRun{EngineName: engines.VectorName},
			&engines.DryRun{EngineName: engines.FRRName},
			&engines.DryRun{EngineName: engines.StrongswanName},
			&engines.DryRun{EngineName: engines.WireguardName},
			&engines.DryRun{EngineName: engines.NetdevName},
		)
	} else {
		suricata = &engines.Suricata{StateDir: filepath.Join(dataDir, "suricata"), LogDir: logDir}
		vector = &engines.Vector{StateDir: filepath.Join(dataDir, "vector")}
		defer suricata.Stop()
		defer vector.Stop()
		sup = engines.NewSupervisor(
			&engines.Nftables{StateDir: dataDir},
			&engines.Routes{StateDir: dataDir},
			suricata,
			vector,
			&engines.FRR{StateDir: dataDir},
			&engines.Strongswan{},
			&engines.Wireguard{StateDir: dataDir},
			&engines.Netdev{},
		)
	}

	lis, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", grpcListen, err)
	}

	updater := &intel.Updater{RunningPolicy: func() (*openngfwv1.Policy, error) {
		p, _, err := st.GetRunning()
		return p, err
	}}
	intelTrigger := make(chan struct{}, 1)
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	go updater.Run(rootCtx, time.Hour, intelTrigger)

	trustedProxyCIDRs := splitCSV(cfg.trustedProxyCIDRs)
	oidcProvider, err := loadOIDCProviderConfig(cfg, accessConfigFile, trustedProxyCIDRs)
	if err != nil {
		return err
	}
	samlProvider, err := authz.LoadSAMLProviderConfig(accessConfigFile)
	if err != nil {
		return err
	}
	if samlProvider.Enabled && len(samlProvider.TrustedProxyCIDRs) == 0 {
		samlProvider.TrustedProxyCIDRs = append([]string(nil), trustedProxyCIDRs...)
	}
	authEnabled := usersFile != "" || oidcProvider.Enabled || samlProvider.Enabled
	var apiAuth *authz.Authenticator
	if usersFile != "" {
		apiAuth, err = authz.Load(usersFile)
		if err != nil {
			return fmt.Errorf("load users file: %w", err)
		}
		slog.Info("local API token authentication enabled", "users_file", usersFile)
	} else if oidcProvider.Enabled || samlProvider.Enabled {
		apiAuth = authz.NewAuthenticator()
	}

	var oidcAuth *authz.OIDCAuthenticator
	var samlAuth *authz.SAMLAuthenticator
	oidcCookieSecure := oidcProviderCookieSecure(oidcProvider)
	if oidcProvider.Enabled {
		secret, err := readSecretFile(oidcProvider.ClientSecretFile)
		if err != nil {
			return err
		}
		discoveryCtx, cancel := context.WithTimeout(rootCtx, 15*time.Second)
		oidcAuth, err = authz.NewOIDCAuthenticator(discoveryCtx, authz.OIDCProviderConfigToRuntime(oidcProvider, secret, oidcCookieSecure))
		cancel()
		if err != nil {
			return fmt.Errorf("configure OIDC: %w", err)
		}
		slog.Info("OIDC browser authentication enabled", "issuer", oidcProvider.Issuer, "client_id", oidcProvider.ClientID, "redirect_url", oidcProvider.RedirectURL)
		if !oidcCookieSecure {
			slog.Warn("OIDC is enabled with a non-HTTPS public redirect URL; secure session cookies will not be used", "redirect_url", oidcProvider.RedirectURL)
		}
	}
	samlCookieSecure := samlProviderCookieSecure(samlProvider)
	if samlProvider.Enabled {
		runtimeCtx, cancel := context.WithTimeout(rootCtx, 15*time.Second)
		samlAuth, err = authz.NewSAMLAuthenticator(runtimeCtx, authz.SAMLProviderConfigToRuntime(samlProvider, samlCookieSecure))
		cancel()
		if err != nil {
			return fmt.Errorf("configure SAML: %w", err)
		}
		slog.Info("SAML browser authentication enabled", "idp_entity_id", samlProvider.IDPEntityID, "sp_entity_id", samlProvider.SPEntityID, "acs_url", samlProvider.ACSURL)
		if !samlCookieSecure {
			slog.Warn("SAML is enabled with a non-HTTPS ACS URL; secure session cookies will not be used", "acs_url", samlProvider.ACSURL)
		}
	}
	if apiAuth != nil {
		var lookups []authz.SessionLookup
		if oidcAuth != nil {
			lookups = append(lookups, oidcAuth.LookupSession)
		}
		if samlAuth != nil {
			lookups = append(lookups, samlAuth.LookupSession)
		}
		apiAuth.SetSessionLookup(authz.CompositeSessionLookup(lookups...))
	}

	// Re-apply the running policy at startup: kernel rulesets and child
	// engines do not survive reboots/daemon restarts, the store does.
	if p, ver, err := st.GetRunning(); err != nil {
		return fmt.Errorf("read running policy: %w", err)
	} else if ver > 0 && !dryRun {
		artifacts, err := renderers.RenderAll(p, opts)
		if err != nil {
			return fmt.Errorf("render running policy v%d: %w", ver, err)
		}
		if err := sup.Apply(rootCtx, artifacts, nil); err != nil {
			return fmt.Errorf("re-apply running policy v%d: %w", ver, err)
		}
		slog.Info("running policy re-applied at startup", "version", ver)
		select {
		case intelTrigger <- struct{}{}:
		default:
		}
	}

	var gatewayBypassToken string
	if cfg.rateLimitRPM > 0 {
		gatewayBypassToken, err = gatewayRateLimitBypassToken()
		if err != nil {
			return err
		}
	}
	httpLimiter, err := newClientRateLimiter(rateLimitConfig{
		RequestsPerMinute: cfg.rateLimitRPM,
		Burst:             cfg.rateLimitBurst,
		MaxClients:        cfg.rateLimitMaxClients,
		TrustedProxyCIDRs: trustedProxyCIDRs,
	})
	if err != nil {
		return fmt.Errorf("configure HTTP rate limiter: %w", err)
	}
	grpcLimiter, err := newClientRateLimiter(rateLimitConfig{
		RequestsPerMinute: cfg.rateLimitRPM,
		Burst:             cfg.rateLimitBurst,
		MaxClients:        cfg.rateLimitMaxClients,
		InternalBypass:    gatewayBypassToken,
	})
	if err != nil {
		return fmt.Errorf("configure gRPC rate limiter: %w", err)
	}
	var unaryInterceptors []grpc.UnaryServerInterceptor
	if grpcLimiter != nil {
		unaryInterceptors = append(unaryInterceptors, grpcLimiter.UnaryInterceptor())
		slog.Info("per-client API rate limiting enabled", "requests_per_minute", cfg.rateLimitRPM, "burst", cfg.rateLimitBurst, "max_clients", cfg.rateLimitMaxClients, "trusted_proxy_cidrs", httpLimiter.trustedProxyCIDRs)
	}
	if apiAuth != nil {
		unaryInterceptors = append(unaryInterceptors, apiAuth.UnaryInterceptor())
		slog.Info("API authentication enabled")
	} else {
		slog.Warn("API authentication is DISABLED by explicit --allow-unauthenticated-local; loopback dry-run lab/debug mode only")
	}
	var serverOpts []grpc.ServerOption
	if len(unaryInterceptors) > 0 {
		serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(unaryInterceptors...))
	}
	serverOpts = appendGRPCSizeOptions(serverOpts, cfg)

	statusEngines := []apiserver.SystemEngine{
		{Name: engines.NftablesName, Role: "stateful L3/L4 firewall and NAT renderer", Dependencies: []string{"nft"}},
		{Name: engines.RoutesName, Role: "static route programming", Dependencies: []string{"ip"}},
		{Name: engines.SuricataName, Role: "IDS/IPS matching engine", Dependencies: []string{"suricata"}},
		{Name: engines.VectorName, Role: "telemetry shipping", Dependencies: []string{"vector"}},
		{Name: engines.FRRName, Role: "dynamic routing", Dependencies: []string{"vtysh"}},
		{Name: engines.StrongswanName, Role: "IPsec VPN", Dependencies: []string{"swanctl"}},
		{Name: engines.WireguardName, Role: "WireGuard VPN", Dependencies: []string{"ip", "wg"}},
		{Name: engines.NetdevName, Role: "interface MTU and offload tuning", Dependencies: []string{"ip", "ethtool"}},
	}
	if suricata != nil {
		statusEngines[2].Runtime = processRuntime(suricata.Status)
	}
	if vector != nil {
		statusEngines[3].Runtime = processRuntime(vector.Status)
	}
	haPeerEvidence, err := haPeerEvidenceSource(cfg)
	if err != nil {
		return err
	}
	haPeerPolicy, err := haPeerPolicySource(cfg)
	if err != nil {
		return err
	}

	systemService := &apiserver.SystemService{
		Store:              st,
		Auth:               apiAuth,
		OIDC:               oidcAuth,
		SAML:               samlAuth,
		LocalUsersFile:     usersFile,
		AccessConfigFile:   accessConfigFile,
		OIDCProviderConfig: oidcProvider,
		SAMLProviderConfig: samlProvider,
		Status: apiserver.SystemStatusConfig{
			StartedAt:                           startedAt,
			GRPCListen:                          grpcListen,
			HTTPListen:                          httpListen,
			TLSEnabled:                          cfg.tlsEnabled,
			PublicSelfSignedTLS:                 usesPublicSelfSignedTLS(cfg),
			AuthEnabled:                         authEnabled,
			OIDCEnabled:                         oidcAuth != nil,
			OIDCCookieSecure:                    oidcCookieSecure,
			DryRun:                              dryRun,
			DataDir:                             dataDir,
			LogDir:                              logDir,
			ContentDir:                          contentDir,
			ReleaseAcceptanceManifestPath:       cfg.releaseAcceptanceManifest,
			ReleaseEvidenceDir:                  cfg.releaseEvidenceDir,
			ReleaseNoPerformanceClaims:          cfg.releaseNoPerformanceClaims,
			HighAvailabilityMode:                cfg.haMode,
			HighAvailabilityRole:                cfg.haRole,
			HighAvailabilityNodeID:              cfg.haNodeID,
			HighAvailabilityPeerID:              cfg.haPeerID,
			HighAvailabilityPeerAddress:         cfg.haPeerAddress,
			HighAvailabilityHeartbeatStaleAfter: cfg.haHeartbeatStaleAfter,
			HighAvailabilityAutoReplicate:       cfg.haAutoPolicyReplication,
			HighAvailabilityReplicationInterval: cfg.haPolicyReplicationInterval,
			HighAvailabilityReplicationComment:  cfg.haPolicyReplicationComment,
			HighAvailabilityPeerEvidence:        haPeerEvidence,
			HighAvailabilityPeerPolicy:          haPeerPolicy,
			HighAvailabilityPromoter:            haPromoter,
			EbpfPinRoot:                         cfg.ebpfPinRoot,
			EbpfArtifactDir:                     ebpfArtifactDir,
			EbpfAttachProbeInterfaces:           splitCSV(cfg.ebpfAttachProbeInterfaces),
			EbpfRuntimeProbes:                   cfg.ebpfRuntimeProbes,
			InspectionWorkers:                   uint32(opts.InspectionWorkers),
			HostCPUs:                            uint32(runtime.NumCPU()),
			ActiveDataplane:                     "nftables/conntrack",
			RateLimitRPM:                        cfg.rateLimitRPM,
			RateLimitBurst:                      cfg.rateLimitBurst,
			TrustedProxyCIDRs:                   trustedProxyCIDRs,
			HTTPMaxBodyBytes:                    cfg.httpMaxBodyBytes,
			HTTPMaxHeaderBytes:                  cfg.httpMaxHeaderBytes,
			HTTPReadHeaderTimeout:               cfg.httpReadHeaderTimeout,
			HTTPReadTimeout:                     cfg.httpReadTimeout,
			HTTPWriteTimeout:                    cfg.httpWriteTimeout,
			HTTPIdleTimeout:                     cfg.httpIdleTimeout,
			GRPCMaxRecvBytes:                    cfg.grpcMaxRecvBytes,
			GRPCMaxSendBytes:                    cfg.grpcMaxSendBytes,
			Engines:                             statusEngines,
			CommandRun: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return exec.CommandContext(ctx, name, args...).CombinedOutput()
			},
		},
	}
	policyServer := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
	policyServer.RuntimeReadiness = systemService.RuntimeReadinessWarnings
	policyServer.OnCommit = func() {
		select {
		case intelTrigger <- struct{}{}:
		default:
		}
	}
	alertServer := &apiserver.AlertServer{EvePath: opts.EvePath(), Store: st, ContentDir: contentDir}
	policyServer.ThreatReplayAlerts = alertServer
	policyServer.ThreatReplayStatus = systemService
	intelServer := &apiserver.IntelServer{
		Store:            st,
		Updater:          updater,
		ContentDir:       contentDir,
		ContentImportDir: contentImportDir,
	}
	flowServer := &apiserver.FlowServer{EvePath: opts.EvePath(), Store: st, ContentDir: contentDir}
	systemService.Policy = policyServer
	systemService.Alerts = alertServer
	systemService.Flows = flowServer
	systemService.Intel = intelServer
	go systemService.StartHighAvailabilityReplication(rootCtx, slog.Info)

	srv := grpc.NewServer(serverOpts...)
	openngfwv1.RegisterSystemServiceServer(srv, systemService)
	openngfwv1.RegisterComplianceServiceServer(srv, systemService)
	openngfwv1.RegisterPolicyServiceServer(srv, policyServer)
	openngfwv1.RegisterThreatTuningServiceServer(srv, policyServer)
	openngfwv1.RegisterAlertServiceServer(srv, alertServer)
	openngfwv1.RegisterIntelServiceServer(srv, intelServer)
	openngfwv1.RegisterFlowServiceServer(srv, flowServer)
	openngfwv1.RegisterAppIdServiceServer(srv, &apiserver.AppIDServer{EvePath: opts.EvePath(), Store: st, ContentDir: contentDir, Policy: policyServer})
	openngfwv1.RegisterExplainServiceServer(srv, &apiserver.ExplainServer{
		Store:      st,
		EvePath:    opts.EvePath(),
		CaptureDir: filepath.Join(logDir, "pcap"),
	})

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Serve(lis) }()
	slog.Info("controld started", "version", version.Version, "grpc", grpcListen, "dry_run", dryRun)

	var httpSrv *http.Server
	if httpListen != "" {
		mux := gwruntime.NewServeMux(gwruntime.WithErrorHandler(gatewayErrorHandler))
		dialOpts := gatewayDialOptions(cfg, gatewayBypassToken)
		ctx := context.Background()
		if err := openngfwv1.RegisterSystemServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register system gateway: %w", err)
		}
		if err := openngfwv1.RegisterComplianceServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register compliance gateway: %w", err)
		}
		if err := openngfwv1.RegisterPolicyServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register policy gateway: %w", err)
		}
		if err := openngfwv1.RegisterThreatTuningServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register threat tuning gateway: %w", err)
		}
		if err := openngfwv1.RegisterAlertServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register alert gateway: %w", err)
		}
		if err := openngfwv1.RegisterIntelServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register intel gateway: %w", err)
		}
		if err := openngfwv1.RegisterFlowServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register flow gateway: %w", err)
		}
		if err := openngfwv1.RegisterAppIdServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register app-id gateway: %w", err)
		}
		if err := openngfwv1.RegisterExplainServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register explain gateway: %w", err)
		}
		root := http.NewServeMux()
		root.Handle(authz.OIDCLoginPath, dynamicOIDCHandler(systemService, false))
		root.Handle(authz.OIDCCallbackPath, dynamicOIDCHandler(systemService, false))
		root.Handle(authz.OIDCLogoutPath, dynamicBrowserLogoutHandler(systemService))
		root.Handle(authz.OIDCStatusPath, dynamicOIDCHandler(systemService, true))
		root.Handle(authz.SAMLLoginPath, dynamicSAMLHandler(systemService, false))
		root.Handle(authz.SAMLACSPath, dynamicSAMLHandler(systemService, false))
		root.Handle(authz.SAMLStatusPath, dynamicSAMLHandler(systemService, true))
		root.HandleFunc("/api-spec.yaml", apiSpecRedirectHandler)
		root.HandleFunc("/openapi.yaml", apiSpecRedirectHandler)
		root.Handle("/v1/fleet/nodes", systemService.FleetHandler())
		root.Handle("/v1/fleet/template-results", systemService.FleetHandler())
		root.Handle("/v1/fleet/templates", systemService.FleetHandler())
		root.Handle("/v1/fleet/templates/", systemService.FleetHandler())
		root.Handle("/v1/investigation/cases", systemService.InvestigationCaseHandler())
		root.Handle("/v1/investigation/cases/", systemService.InvestigationCaseHandler())
		root.Handle("/v1/compliance/reports", systemService.ComplianceReportHandler())
		root.Handle("/v1/compliance/reports/", systemService.ComplianceReportHandler())
		root.Handle("/v1/system/automation/replay:validate", systemService.AutomationReplayValidationHandler())
		root.Handle("/ui/", webui.Handler())
		root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/ui/", http.StatusFound)
				return
			}
			mux.ServeHTTP(w, r)
		}))
		var handler http.Handler = root
		handler = dynamicBrowserSessionCookieAuth(systemService, handler)
		handler = noStoreAPIResponses(handler)
		handler = limitRequestBody(handler, cfg.httpMaxBodyBytes)
		if httpLimiter != nil {
			handler = httpLimiter.HTTPWhen(handler, shouldRateLimitManagementHTTP)
		}
		handler = securityHeaders(handler, cfg.tlsEnabled)
		httpSrv = newHTTPServer(httpListen, handler, cfg)

		var certFile, keyFile string
		if cfg.tlsEnabled {
			var selfSigned bool
			certFile, keyFile, selfSigned, err = tlsutil.LoadOrCreate(dataDir, cfg.tlsCert, cfg.tlsKey)
			if err != nil {
				return fmt.Errorf("tls material: %w", err)
			}
			if selfSigned && usesPublicSelfSignedTLS(cfg) {
				slog.Warn("serving a non-loopback WebUI/REST listener with generated self-signed TLS; explicitly accepted for temporary lab use", "listen", httpListen, "cert", certFile)
			} else if selfSigned {
				slog.Info("serving WebUI/REST over HTTPS with a self-signed certificate (browsers will warn until you supply --tls-cert/--tls-key)", "cert", certFile)
			} else {
				slog.Info("serving WebUI/REST over HTTPS with operator-provided certificate", "cert", certFile)
			}
		} else {
			slog.Warn("TLS is DISABLED (--tls=false): WebUI/REST is served as cleartext HTTP — do not expose off-host")
		}

		go func() {
			var serveErr error
			if cfg.tlsEnabled {
				serveErr = httpSrv.ListenAndServeTLS(certFile, keyFile)
			} else {
				serveErr = httpSrv.ListenAndServe()
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http gateway: %w", serveErr)
			}
		}()
		scheme := "https"
		if !cfg.tlsEnabled {
			scheme = "http"
		}
		slog.Info("REST gateway started", "url", scheme+"://"+httpListen+"/ui/")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig.String())
		if httpSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutCtx)
		}
		srv.GracefulStop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	}
}

func oidcConfigured(cfg config) bool {
	return cfg.oidcIssuer != "" || cfg.oidcClientID != "" || cfg.oidcRedirectURL != "" || cfg.oidcClientSecretFile != ""
}

func loadOIDCProviderConfig(cfg config, accessConfigFile string, trustedProxyCIDRs []string) (authz.OIDCProviderConfig, error) {
	if oidcConfigured(cfg) {
		out := authz.NormalizeOIDCProviderConfig(authz.OIDCProviderConfig{
			Enabled:           true,
			Issuer:            cfg.oidcIssuer,
			ClientID:          cfg.oidcClientID,
			ClientSecretFile:  cfg.oidcClientSecretFile,
			RedirectURL:       cfg.oidcRedirectURL,
			RoleClaim:         cfg.oidcRoleClaim,
			DefaultRole:       cfg.oidcDefaultRole,
			Scopes:            splitCSV(cfg.oidcScopes),
			TrustedProxyCIDRs: trustedProxyCIDRs,
		})
		return out, nil
	}
	out, err := authz.LoadOIDCProviderConfig(accessConfigFile)
	if err != nil {
		return authz.OIDCProviderConfig{}, err
	}
	if out.Enabled {
		if len(out.TrustedProxyCIDRs) == 0 {
			out.TrustedProxyCIDRs = append([]string(nil), trustedProxyCIDRs...)
		}
		return authz.NormalizeOIDCProviderConfig(out), nil
	}
	return out, nil
}

func oidcProviderCookieSecure(cfg authz.OIDCProviderConfig) bool {
	if !cfg.Enabled {
		return false
	}
	redirect, err := url.Parse(strings.TrimSpace(cfg.RedirectURL))
	if err == nil {
		switch strings.ToLower(redirect.Scheme) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	return false
}

func samlProviderCookieSecure(cfg authz.SAMLProviderConfig) bool {
	if !cfg.Enabled {
		return false
	}
	acs, err := url.Parse(strings.TrimSpace(cfg.ACSURL))
	if err == nil {
		switch strings.ToLower(acs.Scheme) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	return false
}

func oidcSessionCookieSecure(cfg config) bool {
	if !oidcConfigured(cfg) {
		return false
	}
	redirect, err := url.Parse(strings.TrimSpace(cfg.oidcRedirectURL))
	if err == nil {
		switch strings.ToLower(redirect.Scheme) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	return cfg.tlsEnabled
}

func dynamicOIDCHandler(systemService *apiserver.SystemService, statusHandler bool) http.Handler {
	disabled := authz.DisabledOIDCStatusHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oidc := systemService.CurrentOIDC()
		if oidc == nil {
			if statusHandler {
				disabled.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		oidc.ServeHTTP(w, r)
	})
}

func dynamicSAMLHandler(systemService *apiserver.SystemService, statusHandler bool) http.Handler {
	disabled := authz.DisabledSAMLStatusHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saml := systemService.CurrentSAML()
		if saml == nil {
			if statusHandler {
				disabled.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		saml.ServeHTTP(w, r)
	})
}

func dynamicBrowserLogoutHandler(systemService *apiserver.SystemService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if c, err := r.Cookie(authz.DefaultOIDCCookieName); err == nil {
			systemService.RevokeBrowserSessionToken(c.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     authz.DefaultOIDCCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	})
}

func dynamicBrowserSessionCookieAuth(systemService *apiserver.SystemService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := next
		if oidc := systemService.CurrentOIDC(); oidc != nil {
			handler = oidc.WithSessionCookieAuth(handler)
		}
		if saml := systemService.CurrentSAML(); saml != nil {
			handler = saml.WithSessionCookieAuth(handler)
		}
		handler.ServeHTTP(w, r)
	})
}

func validateManagementAuth(cfg config) error {
	if !isLoopbackListenAddress(cfg.grpcListen) {
		return fmt.Errorf("direct gRPC management listener requires loopback until gRPC TLS/mTLS is configured, got --listen %q", cfg.grpcListen)
	}
	hasTLSCert := strings.TrimSpace(cfg.tlsCert) != ""
	hasTLSKey := strings.TrimSpace(cfg.tlsKey) != ""
	if hasTLSCert != hasTLSKey {
		return errors.New("--tls-cert and --tls-key must be provided together")
	}
	if !cfg.tlsEnabled {
		if cfg.allowPublicSelfSignedTLS {
			return errors.New("--allow-public-self-signed-tls requires --tls=true")
		}
		if hasTLSCert {
			return errors.New("--tls-cert and --tls-key require --tls=true")
		}
	}
	if cfg.httpListen != "" && !isLoopbackListenAddress(cfg.httpListen) {
		if !cfg.tlsEnabled {
			return fmt.Errorf("--tls=false requires --http-listen to be loopback or empty, got %q", cfg.httpListen)
		}
		if !hasTLSCert && !cfg.allowPublicSelfSignedTLS {
			return fmt.Errorf("non-loopback --http-listen requires operator-provided --tls-cert and --tls-key unless --allow-public-self-signed-tls is explicitly set for temporary lab use")
		}
	}
	if oidcConfigured(cfg) {
		if err := validateOIDCFlags(cfg); err != nil {
			return err
		}
	}
	if cfg.usersFile != "" || oidcConfigured(cfg) {
		return nil
	}
	if !cfg.allowUnauthenticatedLocal {
		return errors.New("API authentication is required: configure --users-file/OIDC or pass --allow-unauthenticated-local for isolated loopback dry-run lab use")
	}
	if !cfg.dryRun {
		return errors.New("--allow-unauthenticated-local requires --dry-run")
	}
	if cfg.httpListen != "" && !isLoopbackListenAddress(cfg.httpListen) {
		return fmt.Errorf("--allow-unauthenticated-local requires --http-listen to be loopback or empty, got %q", cfg.httpListen)
	}
	return nil
}

func usesPublicSelfSignedTLS(cfg config) bool {
	return cfg.tlsEnabled && cfg.httpListen != "" && !isLoopbackListenAddress(cfg.httpListen) &&
		strings.TrimSpace(cfg.tlsCert) == "" && strings.TrimSpace(cfg.tlsKey) == "" && cfg.allowPublicSelfSignedTLS
}

func validateOIDCFlags(cfg config) error {
	if strings.TrimSpace(cfg.oidcIssuer) == "" {
		return errors.New("--oidc-issuer is required when OIDC is configured")
	}
	if strings.TrimSpace(cfg.oidcClientID) == "" {
		return errors.New("--oidc-client-id is required when OIDC is configured")
	}
	if strings.TrimSpace(cfg.oidcRedirectURL) == "" {
		return errors.New("--oidc-redirect-url is required when OIDC is configured")
	}
	if strings.TrimSpace(cfg.oidcDefaultRole) != "" {
		if _, err := authz.ParseRole(cfg.oidcDefaultRole); err != nil {
			return fmt.Errorf("--oidc-default-role: %w", err)
		}
	}
	if err := validatePublicHTTPURL("--oidc-issuer", cfg.oidcIssuer, true); err != nil {
		return err
	}
	redirect, err := url.Parse(strings.TrimSpace(cfg.oidcRedirectURL))
	if err != nil {
		return fmt.Errorf("--oidc-redirect-url: %w", err)
	}
	if err := validatePublicHTTPURL("--oidc-redirect-url", cfg.oidcRedirectURL, true); err != nil {
		return err
	}
	if redirect.EscapedPath() != authz.OIDCCallbackPath {
		return fmt.Errorf("--oidc-redirect-url path must be %s", authz.OIDCCallbackPath)
	}
	if !csvContains(splitCSV(cfg.oidcScopes), "openid") {
		return errors.New("--oidc-scopes must include openid")
	}
	return nil
}

func validateHAFlags(cfg config) error {
	if cfg.haAutoPolicyReplication {
		if !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active-passive") && !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active_passive") {
			return errors.New("--ha-auto-policy-replication requires --ha-mode=active-passive")
		}
		if !strings.EqualFold(strings.TrimSpace(cfg.haRole), "passive") {
			return errors.New("--ha-auto-policy-replication requires --ha-role=passive")
		}
		if strings.TrimSpace(cfg.haPeerURL) == "" {
			return errors.New("--ha-auto-policy-replication requires --ha-peer-url")
		}
		if cfg.haPolicyReplicationInterval <= 0 {
			return errors.New("--ha-policy-replication-interval must be greater than zero")
		}
		if strings.TrimSpace(cfg.haPolicyReplicationComment) == "" {
			return errors.New("--ha-policy-replication-comment is required when automatic HA policy replication is enabled")
		}
	}
	if err := validateHAPromotionFlags(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.haPeerURL) == "" {
		if strings.TrimSpace(cfg.haPeerTokenFile) != "" {
			return errors.New("--ha-peer-token-file requires --ha-peer-url")
		}
		if strings.TrimSpace(cfg.haPeerCAFile) != "" {
			return errors.New("--ha-peer-ca-file requires --ha-peer-url")
		}
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active-passive") && !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active_passive") {
		return errors.New("--ha-peer-url requires --ha-mode=active-passive")
	}
	if err := validatePublicHTTPURL("--ha-peer-url", cfg.haPeerURL, false); err != nil {
		return err
	}
	peerURL, _ := url.Parse(strings.TrimSpace(cfg.haPeerURL))
	if peerURL.User != nil {
		return errors.New("--ha-peer-url must not include URL credentials")
	}
	if peerURL.Fragment != "" {
		return errors.New("--ha-peer-url must not include a fragment")
	}
	if peerURL.RawQuery != "" || peerURL.ForceQuery {
		return errors.New("--ha-peer-url must not include a query string")
	}
	if peerURL.EscapedPath() != "/v1/system/ha/status" {
		return errors.New("--ha-peer-url path must be /v1/system/ha/status")
	}
	if strings.TrimSpace(cfg.haPeerTokenFile) == "" {
		return errors.New("--ha-peer-token-file is required when --ha-peer-url is configured")
	}
	if cfg.haHeartbeatTimeout <= 0 {
		return errors.New("--ha-heartbeat-timeout must be greater than zero")
	}
	if cfg.haHeartbeatStaleAfter <= 0 {
		return errors.New("--ha-heartbeat-stale-after must be greater than zero")
	}
	if cfg.haHeartbeatStaleAfter <= cfg.haHeartbeatTimeout {
		return errors.New("--ha-heartbeat-stale-after must be greater than --ha-heartbeat-timeout")
	}
	return nil
}

func validateHAPromotionFlags(cfg config) error {
	enabled := strings.TrimSpace(cfg.haPromoteVIP) != "" ||
		strings.TrimSpace(cfg.haPromoteInterface) != "" ||
		strings.TrimSpace(cfg.haPromoteRouteDestination) != "" ||
		strings.TrimSpace(cfg.haPromoteRouteVia) != "" ||
		cfg.haPromoteRouteMetric != 0
	if !enabled {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active-passive") && !strings.EqualFold(strings.TrimSpace(cfg.haMode), "active_passive") {
		return errors.New("--ha-promote-vip requires --ha-mode=active-passive")
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.haRole), "passive") {
		return errors.New("--ha-promote-vip requires --ha-role=passive")
	}
	if strings.TrimSpace(cfg.haPromoteVIP) == "" {
		return errors.New("--ha-promote-vip is required when HA promotion flags are set")
	}
	if strings.TrimSpace(cfg.haPromoteInterface) == "" {
		return errors.New("--ha-promote-interface is required when --ha-promote-vip is set")
	}
	if _, err := netip.ParsePrefix(strings.TrimSpace(cfg.haPromoteVIP)); err != nil {
		return fmt.Errorf("--ha-promote-vip: %w", err)
	}
	if strings.TrimSpace(cfg.haPromoteRouteVia) != "" && strings.TrimSpace(cfg.haPromoteRouteDestination) == "" {
		return errors.New("--ha-promote-route-via requires --ha-promote-route-destination")
	}
	if cfg.haPromoteRouteMetric != 0 && strings.TrimSpace(cfg.haPromoteRouteDestination) == "" {
		return errors.New("--ha-promote-route-metric requires --ha-promote-route-destination")
	}
	if strings.TrimSpace(cfg.haPromoteRouteDestination) != "" {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cfg.haPromoteRouteDestination)); err != nil {
			return fmt.Errorf("--ha-promote-route-destination: %w", err)
		}
		if strings.TrimSpace(cfg.haPromoteRouteVia) != "" {
			if _, err := netip.ParseAddr(strings.TrimSpace(cfg.haPromoteRouteVia)); err != nil {
				return fmt.Errorf("--ha-promote-route-via: %w", err)
			}
		}
	}
	return nil
}

func haPromoterFromConfig(dataDir string, cfg config) (*engines.HAPromotion, error) {
	if strings.TrimSpace(cfg.haPromoteVIP) == "" && strings.TrimSpace(cfg.haPromoteInterface) == "" {
		return nil, nil
	}
	vip, err := netip.ParsePrefix(strings.TrimSpace(cfg.haPromoteVIP))
	if err != nil {
		return nil, fmt.Errorf("--ha-promote-vip: %w", err)
	}
	promoter := &engines.HAPromotion{
		StateDir:   filepath.Join(dataDir, "ha"),
		Interface:  strings.TrimSpace(cfg.haPromoteInterface),
		VIP:        vip,
		AnnounceIP: cfg.haPromoteAnnounce,
	}
	if strings.TrimSpace(cfg.haPromoteRouteDestination) != "" {
		dest, err := netip.ParsePrefix(strings.TrimSpace(cfg.haPromoteRouteDestination))
		if err != nil {
			return nil, fmt.Errorf("--ha-promote-route-destination: %w", err)
		}
		route := engines.HAPromotionRoute{
			Destination: dest,
			Interface:   strings.TrimSpace(cfg.haPromoteInterface),
			Metric:      cfg.haPromoteRouteMetric,
		}
		if strings.TrimSpace(cfg.haPromoteRouteVia) != "" {
			via, err := netip.ParseAddr(strings.TrimSpace(cfg.haPromoteRouteVia))
			if err != nil {
				return nil, fmt.Errorf("--ha-promote-route-via: %w", err)
			}
			route.Via = via
		}
		promoter.Routes = append(promoter.Routes, route)
	}
	if err := promoter.Validate(context.Background()); err != nil {
		return nil, err
	}
	return promoter, nil
}

func haPeerEvidenceSource(cfg config) (func(context.Context) (*apiserver.HighAvailabilityPeerEvidence, error), error) {
	if strings.TrimSpace(cfg.haPeerURL) == "" {
		return nil, nil
	}
	token, err := readHAPeerToken(cfg)
	if err != nil {
		return nil, err
	}
	client, err := haPeerHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	peerURL := strings.TrimSpace(cfg.haPeerURL)
	timeout := cfg.haHeartbeatTimeout
	return func(ctx context.Context) (*apiserver.HighAvailabilityPeerEvidence, error) {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, peerURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()
		body, err := readBoundedResponseBody(res.Body, maxHAPeerStatusBytes, "peer HA status")
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("peer status HTTP %d", res.StatusCode)
		}
		var peerResp openngfwv1.GetHighAvailabilityStatusResponse
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &peerResp); err != nil {
			return nil, fmt.Errorf("decode peer HA status: %w", err)
		}
		status := peerResp.GetStatus()
		if status == nil {
			return nil, errors.New("peer HA status response missing status")
		}
		generatedAt, _ := time.Parse(time.RFC3339, peerResp.GetGeneratedAt())
		artifactHash := status.GetSync().GetLocalArtifactSetSha256()
		if artifactHash == "" {
			artifactHash = status.GetLastKnownGoodArtifactSetSha256()
		}
		detail := status.GetSync().GetDetail()
		if detail == "" {
			detail = status.GetDetail()
		}
		return &apiserver.HighAvailabilityPeerEvidence{
			NodeID:               status.GetNodeId(),
			Role:                 status.GetRole(),
			RunningPolicyVersion: status.GetRunningPolicyVersion(),
			ArtifactSetSHA256:    artifactHash,
			LastHeartbeat:        generatedAt,
			Detail:               detail,
		}, nil
	}, nil
}

func haPeerPolicySource(cfg config) (func(context.Context) (*openngfwv1.GetPolicyResponse, error), error) {
	if strings.TrimSpace(cfg.haPeerURL) == "" {
		return nil, nil
	}
	token, err := readHAPeerToken(cfg)
	if err != nil {
		return nil, err
	}
	client, err := haPeerHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	policyURL, err := haPeerPolicyURL(cfg.haPeerURL)
	if err != nil {
		return nil, err
	}
	timeout := cfg.haHeartbeatTimeout
	return func(ctx context.Context) (*openngfwv1.GetPolicyResponse, error) {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, policyURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()
		body, err := readBoundedResponseBody(res.Body, maxHAPeerPolicyBytes, "peer running policy")
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("peer policy HTTP %d", res.StatusCode)
		}
		var peerResp openngfwv1.GetPolicyResponse
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &peerResp); err != nil {
			return nil, fmt.Errorf("decode peer running policy: %w", err)
		}
		return &peerResp, nil
	}, nil
}

func haPeerPolicyURL(raw string) (string, error) {
	peerURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	peerURL.Path = "/v1/policy"
	peerURL.RawPath = ""
	peerURL.RawQuery = "source=POLICY_SOURCE_RUNNING"
	peerURL.Fragment = ""
	return peerURL.String(), nil
}

func haPeerHTTPClient(cfg config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(cfg.haPeerCAFile) != "" {
		pemBytes, err := os.ReadFile(cfg.haPeerCAFile)
		if err != nil {
			return nil, fmt.Errorf("read HA peer CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("--ha-peer-ca-file did not contain any PEM certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: transport, Timeout: cfg.haHeartbeatTimeout}, nil
}

func readHAPeerToken(cfg config) (string, error) {
	token, err := readPrivateTextFile(cfg.haPeerTokenFile, "HA peer token file")
	if err != nil {
		return "", fmt.Errorf("load HA peer token: %w", err)
	}
	if token == "" {
		return "", errors.New("load HA peer token: HA peer token file is empty")
	}
	return token, nil
}

func readBoundedResponseBody(body io.Reader, maxBytes int64, label string) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%s response size limit must be greater than zero", label)
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%s response exceeds %d byte limit", label, maxBytes)
	}
	return raw, nil
}

func validatePublicHTTPURL(flagName, raw string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", flagName, err)
	}
	if !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%s must be an absolute http(s) URL", flagName)
	}
	if u.Scheme == "http" && (!allowLoopbackHTTP || !isLoopbackURLHost(u.Hostname())) {
		return fmt.Errorf("%s must use https unless the host is loopback", flagName)
	}
	return nil
}

func isLoopbackURLHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func csvContains(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func isLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readSecretFile(path string) (string, error) {
	return readPrivateTextFile(path, "OIDC client secret file")
}

func readPrivateTextFile(path, label string) (string, error) {
	if path == "" {
		return "", nil
	}
	if err := securefile.ValidatePrivateFile(path, label); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func securityHeaders(next http.Handler, tlsEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-src 'none'; media-src 'none'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if tlsEnabled {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func noStoreAPIResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || apiSpecPath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func shouldRateLimitManagementHTTP(r *http.Request) bool {
	path := r.URL.Path
	return path == "/v1" || strings.HasPrefix(path, "/v1/")
}

func apiSpecRedirectHandler(w http.ResponseWriter, r *http.Request) {
	if !apiSpecPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/api-spec.yaml", http.StatusFound)
}

func apiSpecPath(path string) bool {
	switch path {
	case "/api-spec.yaml", "/openapi.yaml", "/ui/api-spec.yaml":
		return true
	default:
		return false
	}
}

func gatewayErrorHandler(ctx context.Context, _ *gwruntime.ServeMux, _ gwruntime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	statusCode := 0
	if httpErr, ok := err.(*gwruntime.HTTPStatusError); ok {
		statusCode = httpErr.HTTPStatus
		err = httpErr.Err
	}
	st := grpcstatus.Convert(err)
	code := st.Code()
	if statusCode == 0 {
		statusCode = gwruntime.HTTPStatusFromCode(code)
	}
	rawMessage := st.Message()
	message := publicGatewayErrorMessage(code, rawMessage)
	if message != strings.TrimSpace(rawMessage) {
		slog.WarnContext(ctx, "REST gateway sanitized error detail", "path", r.URL.Path, "code", code.String(), "error", gatewayLogErrorMessage(rawMessage))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    int32(code),
		"message": message,
		"details": []any{},
	})
}

func publicGatewayErrorMessage(code codes.Code, message string) string {
	switch code {
	case codes.Internal, codes.Unknown, codes.DataLoss:
		return "internal server error"
	case codes.Unavailable:
		return "service unavailable"
	}
	message = supportbundle.RedactString(strings.TrimSpace(message))
	if message == "" {
		return strings.ToLower(code.String())
	}
	return message
}

func gatewayLogErrorMessage(message string) string {
	return supportbundle.RedactString(strings.TrimSpace(message))
}

func processRuntime(status func() engines.ProcessStatus) func() apiserver.EngineRuntime {
	return func() apiserver.EngineRuntime {
		st := status()
		return apiserver.EngineRuntime{
			State:        st.State,
			PID:          st.PID,
			Restarts:     st.Restarts,
			MaxRestarts:  st.MaxRestarts,
			StartedAt:    st.StartedAt,
			LastExitAt:   st.LastExitAt,
			LastExitErr:  st.LastExitErr,
			LastUptime:   st.LastUptime,
			RestartDelay: st.RestartDelay,
			StartupGrace: st.StartupGrace,
		}
	}
}

// Package releaseacceptance contains release gate status logic shared by the
// CLI and the runtime API.
package releaseacceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/perfreport"
)

const acceptanceSchemaVersion = "phragma.release.acceptance.v1"
const acceptanceStatusSchemaVersion = "phragma.release.status.v1"
const acceptanceTemplateSchemaVersion = acceptanceSchemaVersion + ".template"
const evidenceSchemaVersion = "phragma.release.evidence.v1"
const defaultNoPerformanceDetail = "This tag publishes no throughput, latency, connection-rate, or comparison claims."
const contentPackageCheckName = "content-package-verification"
const contentProductionReadinessCheckName = "content-production-readiness"
const webUIEnterpriseSmokeCheckName = "webui-enterprise-smoke"
const oidcFieldEvidenceCheckName = "m5-oidc-field-evidence"
const samlFieldEvidenceCheckName = "m5-saml-field-evidence"
const haReadinessRecoveryCheckName = "ha-readiness-recovery"
const contentPackageDemoScope = "demo-only"
const contentProductionReadinessScope = "production"
const contentPackageSmokeSentinel = "content-package-smoke: scope=demo-only production_content=false mechanics_verified=true production_ready=false"
const contentPackageDemoRecordDetail = "demo-only signed content package mechanics; does not certify production App-ID, Threat-ID, or intel-feed content"
const hardeningDeferredStatus = "hardening_deferred"

const (
	// AcceptanceSchemaVersion identifies release acceptance manifest files.
	AcceptanceSchemaVersion = acceptanceSchemaVersion
	// AcceptanceTemplateSchemaVersion identifies release acceptance templates.
	AcceptanceTemplateSchemaVersion = acceptanceTemplateSchemaVersion
	// AcceptanceStatusSchemaVersion identifies generated acceptance status reports.
	AcceptanceStatusSchemaVersion = acceptanceStatusSchemaVersion
	// EvidenceSchemaVersion identifies release evidence record files.
	EvidenceSchemaVersion = evidenceSchemaVersion
	// DefaultNoPerformanceDetail documents tags with no performance claims.
	DefaultNoPerformanceDetail = defaultNoPerformanceDetail
	// ContentPackageCheckName is the release check for signed package mechanics.
	ContentPackageCheckName = contentPackageCheckName
	// ContentProductionReadinessCheckName is the release check for production content evidence.
	ContentProductionReadinessCheckName = contentProductionReadinessCheckName
	// WebUIEnterpriseSmokeCheckName is the release check for the broad WebUI browser sweep.
	WebUIEnterpriseSmokeCheckName = webUIEnterpriseSmokeCheckName
	// OIDCFieldEvidenceCheckName is the release check for real OIDC provider evidence.
	OIDCFieldEvidenceCheckName = oidcFieldEvidenceCheckName
	// SAMLFieldEvidenceCheckName is the release check for real SAML provider evidence.
	SAMLFieldEvidenceCheckName = samlFieldEvidenceCheckName
	// ContentPackageDemoScope marks demo-only content package mechanics evidence.
	ContentPackageDemoScope = contentPackageDemoScope
	// ContentProductionReadinessScope marks production content readiness evidence.
	ContentProductionReadinessScope = contentProductionReadinessScope
	// ContentPackageSmokeSentinel is the required smoke-test stdout marker.
	ContentPackageSmokeSentinel = contentPackageSmokeSentinel
	// ContentPackageDemoRecordDetail is the required detail for demo package evidence.
	ContentPackageDemoRecordDetail = contentPackageDemoRecordDetail
	// ContentPackageProductionReadinessSummary summarizes production readiness evidence.
	ContentPackageProductionReadinessSummary = "production App-ID, Threat-ID, and intel-feed content readiness evidence"
)

var requiredReleaseChecks = []string{
	"proto-verify",
	"privileged-integration",
	"deploy-hardening",
	"policy-restore-drill",
	haReadinessRecoveryCheckName,
	"e2e-install",
	contentPackageCheckName,
	contentProductionReadinessCheckName,
	"release-benchmark",
	"m3-live-networking",
	"m3-field-evidence",
	"ebpf-ol9-field-evidence",
	"m5-oidc-provider",
	oidcFieldEvidenceCheckName,
	samlFieldEvidenceCheckName,
	"m5-auth-ui",
	webUIEnterpriseSmokeCheckName,
}

var hardeningDeferredChecks = map[string]string{
	contentProductionReadinessCheckName: "hardening-deferred: signed production App-ID, Threat-ID, and intel-feed certification remains required before full production certification",
	"m3-field-evidence":                 "hardening-deferred: external BGP, IPsec, and WireGuard field certification remains required before full production certification",
	oidcFieldEvidenceCheckName:          "hardening-deferred: real-provider OIDC browser SSO field certification remains required before full production certification",
	samlFieldEvidenceCheckName:          "hardening-deferred: real-provider SAML browser SSO field certification remains required before full production certification",
}

var evidenceCommandPrefixes = map[string][][]string{
	"proto-verify": {
		{"make", "proto-verify"},
	},
	"privileged-integration": {
		{"make", "privileged-integration-evidence-check"},
		{"bash", "release/privileged-integration-no-skip.sh"},
		{"sudo", "/tmp/openngfw-itest", "-test.v", "-test.timeout", "300s"},
	},
	"deploy-hardening": {
		{"bash", "release/deploy-hardening-check.sh", "--check"},
		{"./release/deploy-hardening-check.sh", "--check"},
		{"make", "deploy-hardening-check"},
	},
	"policy-restore-drill": {
		{"make", "policy-restore-drill-check"},
		{"bash", "release/policy-restore-drill.sh", "--check"},
	},
	haReadinessRecoveryCheckName: {
		{"make", "ha-readiness-recovery-check"},
		{"bash", "release/ha-readiness-recovery.sh", "--check"},
	},
	"e2e-install": {
		{"bash", "e2e/install-smoke.sh", "--run"},
		{"make", "e2e-install"},
		{"sudo", "make", "e2e-install"},
		{"sudo", "-E", "make", "e2e-install"},
	},
	contentPackageCheckName: {
		{"make", "content-package-smoke"},
		{"bash", "e2e/content-package-smoke.sh", "--check"},
	},
	contentProductionReadinessCheckName: {
		{"make", "content-production-readiness-check"},
		{"bash", "release/content-production-readiness.sh", "--evidence-dir"},
		{"./release/content-production-readiness.sh", "--evidence-dir"},
	},
	"release-benchmark": {
		{"make", "benchmark-verify-release"},
		{"go", "run", "./cmd/ngfwperf", "verify", "--strict", "--publishable"},
	},
	"m3-live-networking": {
		{"bash", "release/m3-live-networking.sh", "--run"},
		{"./release/m3-live-networking.sh", "--run"},
		{"make", "m3-live-networking"},
	},
	"m3-field-evidence": {
		{"bash", "release/m3-field-evidence.sh", "--evidence-dir"},
		{"./release/m3-field-evidence.sh", "--evidence-dir"},
		{"make", "m3-field-evidence-check"},
	},
	"ebpf-ol9-field-evidence": {
		{"make", "ebpf-ol9-field-evidence-check"},
		{"bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir"},
	},
	"m5-oidc-provider": {
		{"make", "e2e-oidc-runtime-smoke"},
		{"go", "test", "-count=1", "-run", "TestOIDCRuntimeSmoke", "-v", "./cmd/controld"},
	},
	oidcFieldEvidenceCheckName: {
		{"make", "m5-oidc-field-evidence-check"},
		{"bash", "release/oidc-field-evidence.sh", "--evidence-dir"},
		{"./release/oidc-field-evidence.sh", "--evidence-dir"},
	},
	samlFieldEvidenceCheckName: {
		{"make", "m5-saml-field-evidence-check"},
		{"bash", "release/saml-field-evidence.sh", "--evidence-dir"},
		{"./release/saml-field-evidence.sh", "--evidence-dir"},
	},
	"m5-auth-ui": {
		{"make", "e2e-auth-runtime-smoke"},
	},
	webUIEnterpriseSmokeCheckName: {
		{"make", "webui-enterprise-smoke"},
	},
}

var recommendedEvidenceCommands = map[string][]string{
	"proto-verify":                      {"make", "proto-verify"},
	"privileged-integration":            {"make", "privileged-integration-evidence-check"},
	"deploy-hardening":                  {"make", "deploy-hardening-check"},
	"policy-restore-drill":              {"make", "policy-restore-drill-check"},
	haReadinessRecoveryCheckName:        {"make", "ha-readiness-recovery-check"},
	"e2e-install":                       {"sudo", "-E", "make", "e2e-install"},
	contentPackageCheckName:             {"make", "content-package-smoke"},
	contentProductionReadinessCheckName: {"make", "content-production-readiness-check"},
	"release-benchmark":                 {"make", "benchmark-verify-release"},
	"m3-live-networking":                {"./release/m3-live-networking.sh", "--run"},
	"m3-field-evidence":                 {"make", "m3-field-evidence-check"},
	"ebpf-ol9-field-evidence":           {"make", "ebpf-ol9-field-evidence-check"},
	"m5-oidc-provider":                  {"make", "e2e-oidc-runtime-smoke"},
	oidcFieldEvidenceCheckName:          {"make", "m5-oidc-field-evidence-check"},
	samlFieldEvidenceCheckName:          {"make", "m5-saml-field-evidence-check"},
	"m5-auth-ui":                        {"make", "e2e-auth-runtime-smoke"},
	webUIEnterpriseSmokeCheckName:       {"make", "webui-enterprise-smoke"},
}

var evidenceStdoutRequiredFragments = map[string][]string{
	"proto-verify": {
		"buf lint",
		"buf generate",
		"cmd/ngfwopenapi",
	},
	"privileged-integration": {
		"check=privileged-integration",
		"mode=run",
		"privileged_integration_scope=nftables,network-namespaces,packet-capture,live-integration",
		"privileged_integration_skip_policy=no-skipped-tests",
		"run_requires=linux-root,nftables,iproute2,netcat,tcpdump",
		"=== RUN",
		"PASS",
		"skipped_tests=0",
		"status=passed",
	},
	"e2e-install": {
		"check=e2e-install",
		"mode=run",
		"install_smoke_scope=installed-service-policy-enforcement",
		"run_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding",
		"install smoke passed: installed service committed allow and deny policies and filtered namespace traffic",
		"status=passed",
	},
	contentPackageCheckName: {
		contentPackageSmokeSentinel,
	},
	contentProductionReadinessCheckName: {
		"check=content-production-readiness",
		"mode=check",
		"content_production_scope=app-id,threat-id,intel-feeds",
		"required_content_kinds=app-id,threat-id,intel-feeds",
		"required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill",
		"required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill",
		"required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill",
		"content_readiness=production_content=true,production_ready=true",
		"status=passed",
	},
	"deploy-hardening": {
		"required_service_posture=loopback-listeners,authenticated-by-default,no-dev-bypass,no-public-self-signed,systemd-sandbox,capability-bounds",
		"required_installer_posture=root-only,0700-state-log-config,hashed-admin-token,0600-secret-files,unsafe-remote-install-opt-in",
		"status=passed",
	},
	"policy-restore-drill": {
		"check=policy-restore-drill",
		"mode=check",
		"restore_drill_scope=policy-version-rollback,validation,impact-ack,runtime-ack,audit-comment,audit-log,running-pointer,last-known-good,engine-apply",
		"automated_tests=TestPolicyRollbackRecordsIntentAuditAndAppliesEngines,TestPolicyRollbackRequiresAckRiskForHighRiskImpact,TestPolicyRollbackRequiresAckRuntimeForRuntimeWarnings,TestPolicyRollbackUsesOperatorComment",
		"restore_surface=PolicyService.Rollback,ngfwctl-rollback-preflight,store-version-history,audit-chain",
		"run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine",
		"status=passed",
	},
	haReadinessRecoveryCheckName: {
		"check=ha-readiness-recovery",
		"mode=check",
		"ha_recovery_scope=status,passive-policy-pull,automatic-replication,manual-activation,optional-linux-local-vip-route-promotion,cli-parity,daemon-peer-config,support-bundle",
		"automated_tests=TestSystemHighAvailabilityStatusReportsPeerHeartbeatSync,TestSystemHighAvailabilityStatusDegradesStaleOrSameRolePeer,TestSystemPullHighAvailabilityPolicyAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationRecordsBlockedAttempt,TestSystemActivateHighAvailabilityFailoverPersistsActiveRole,TestSystemActivateHighAvailabilityFailoverPromotesVIPBeforePersistingActiveRole,TestSystemActivateHighAvailabilityFailoverDoesNotPersistActiveRoleWhenPromotionFails,TestHAPromotionPromoteAppliesDesiredStateAndRemovesManagedStaleEntries,TestSystemSupportBundleCollectsServerBundle,TestPrintStatusShowsHighAvailabilityReadiness,TestSystemHAStatusPrintsCutoverPlan,TestSystemHAPullPolicyCallsAPIAndPrintsSummary,TestSystemHAActivatePassiveCallsAPIAndPrintsSummary,TestValidateHAFlags,TestHAPeerSourcesUseExpectedHTTPSRequests,TestSupportBundleCollectorShape",
		"ha_claim_boundary=does_not_certify_privileged_vip_route_field_evidence,peer_fencing,connection_state_sync,live_linux_failover",
		"ha_surface=SystemService.GetHighAvailabilityStatus,PullHighAvailabilityPolicy,RunHighAvailabilityReplicationOnce,ActivateHighAvailabilityFailover,HAPromotion,ngfwctl-status,ngfwctl-system-ha,controld-ha-peer-source,controld-ha-promotion-flags,support-bundle-highAvailabilityStatus",
		"deferred_field_controls=peer-mtls,peer-token-rotation,privileged-vip-route-field-evidence,peer-fencing,split-brain-policy,conntrack-sync,live-linux-failover",
		"run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine,loopback-httptest-peer",
		"status=passed",
	},
	"m3-live-networking": {
		"automated_scope=static-route-live-forwarding,bgp-frr-netns-route-programming,wireguard-handshake-peer-traffic",
		"automated_tests=TestM3StaticRouteProgramsLiveForwarding,TestM3BGPProgramsKernelRouteFromFRRPeer,TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic",
		"manual_field_tests=bgp-external-peer,ipsec-strongswan-sa-traffic,wireguard-external-client",
		"manual_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping",
		"manual_ipsec_template=docs/testing-plan.md:T3.3,docs/examples/policy-routing-vpn.yaml",
		"run_requires_commands=ip,nft,nc,wg,vtysh,zebra,bgpd",
		"status=passed",
	},
	"m3-field-evidence": {
		"field_evidence_scope=bgp,ipsec,wireguard",
		"required_bgp_evidence=show-bgp-summary,ip-route-remote-prefix,frr-running-config",
		"required_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping",
		"required_wireguard_evidence=wg-show,client-config-redacted,external-client-ping",
		"m3_field_redaction=wireguard-private-key-redacted,preshared-key-redacted,bearer-tokens-redacted,api-keys-redacted,url-credentials-redacted",
		"redaction_scan=private-key,psk,bearer,api-key,token,url-userinfo",
		"status=passed",
	},
	"ebpf-ol9-field-evidence": {
		"check=ebpf-ol9-field-evidence",
		"mode=check",
		"field_evidence_scope=ol9-oci-host,ebpf-host-prereqs,xdp-attach-probe,tc-attach-probe,status-api,renderer-scaffold,cleanup",
		"required_host_evidence=os-release,uname,oci-instance",
		"required_ebpf_prereqs=bpftool,clang,tc,ip,kernel-btf,bpffs,cgroup-v2,link-inventory",
		"required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup",
		"required_status_evidence=ngfwctl-status,system-status-ebpf-json",
		"required_renderer_evidence=ebpf-render-plan",
		"required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records",
		"active_dataplane=nftables/conntrack",
		"ebpf_renderer_state=planned",
		"supported_hooks=xdp,tc",
		"xdp_attach_result=passed",
		"tc_attach_result=passed",
		"cleanup_result=passed",
		"ebpf_field_redaction=oci-ocids-redacted,public-ips-redacted,tokens-redacted",
		"redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip",
		"status=passed",
	},
	"m5-oidc-provider": {
		"oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac,runtime-provider-lifecycle",
		"oidc_runtime_negative_scope=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial",
		"oidc_runtime_provider_lifecycle=api-validate,set,disable,runtime-authenticator-replacement,session-revocation",
		"oidc_runtime_provider=loopback-mock",
		"oidc_runtime_actor=smoke-admin",
		"status=passed",
	},
	oidcFieldEvidenceCheckName: {
		"field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
		"oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac",
		"oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial",
		"oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted",
		"required_provider_evidence=issuer-client-discovery,id-token-validation",
		"required_deployment_evidence=public-https-callback,client-secret-file-permissions",
		"required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
		"required_rbac_evidence=viewer,operator,admin",
		"required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
		"redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf",
		"status=passed",
	},
	samlFieldEvidenceCheckName: {
		"field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
		"saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac",
		"saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial",
		"saml_field_redaction=idp-entity-redacted,sp-entity-redacted,subject-redacted,email-redacted,assertions-redacted,cookies-redacted",
		"required_provider_evidence=idp-metadata,sp-metadata",
		"required_deployment_evidence=public-https-acs,secure-cookie-posture",
		"required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
		"required_rbac_evidence=viewer,operator,admin",
		"required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
		"redaction_scan=saml-response,relaystate,assertion,x509,private-key,cookie,csrf",
		"status=passed",
	},
	"m5-auth-ui": {
		"auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit,unsafe-noauth-startup-guard",
		"auth_runtime_startup_guard=missing-auth-rejected,unauthenticated-local-requires-dry-run",
		"status=passed",
	},
	webUIEnterpriseSmokeCheckName: {
		"webui_js_checks=passed",
		"javascript_checks=required",
		"release_smoke_mode=desktop-enterprise",
		"browser_required=1",
		"[webui-smoke] browser_required=true",
		"[webui-smoke] browser_coverage=chromium",
		"viewport_coverage=desktop",
		"evidence policy: mode=broad",
		"route_coverage=19/19",
		"[webui-smoke] summary: result=passed mode=broad",
		"route_coverage=",
		"checks=",
		"screenshots=",
		"[webui-smoke] evidence manifest:",
		"[webui-smoke] release note: Broad route sweep evidence may support production release only after source-control acceptance and repo-local release evidence recording.",
	},
	"release-benchmark": {
		"verified ",
		"publication gate: 0 failure(s)",
	},
}

// StatusOptions controls how release acceptance status is read.
type StatusOptions struct {
	ManifestPath             string
	EvidenceDir              string
	ExpectedCommit           string
	ExpectedVersion          string
	AllowNoPerformanceClaims bool
	AllowHardeningDeferred   bool
	IncludeRecordability     bool
	JSON                     bool
	Strict                   bool
}

// StatusReport is the machine-readable release acceptance status.
type StatusReport struct {
	SchemaVersion   string               `json:"schema_version"`
	GeneratedAt     string               `json:"generated_at"`
	ManifestPath    string               `json:"manifest_path"`
	EvidenceDir     string               `json:"evidence_dir"`
	Provenance      string               `json:"provenance"`
	Disclosures     []string             `json:"disclosures,omitempty"`
	ManifestPresent bool                 `json:"manifest_present"`
	Ready           bool                 `json:"ready"`
	State           string               `json:"state"`
	Summary         StatusSummary        `json:"summary"`
	Problems        []string             `json:"problems,omitempty"`
	Checks          []CheckStatus        `json:"checks"`
	Recordability   *RecordabilityStatus `json:"recordability,omitempty"`
}

// StatusSummary counts release checks by state.
type StatusSummary struct {
	Passed            int `json:"passed"`
	Recorded          int `json:"recorded"`
	Missing           int `json:"missing"`
	Invalid           int `json:"invalid"`
	ReviewNeeded      int `json:"review_needed"`
	NotApplicable     int `json:"not_applicable"`
	HardeningDeferred int `json:"hardening_deferred"`
	Todo              int `json:"todo"`
}

// CheckStatus reports one release check's current evidence state.
type CheckStatus struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	Artifact         string   `json:"artifact,omitempty"`
	EvidencePath     string   `json:"evidence_path,omitempty"`
	BenchmarkSummary string   `json:"benchmark_summary,omitempty"`
	RanAt            string   `json:"ran_at,omitempty"`
	Detail           string   `json:"detail,omitempty"`
	Command          []string `json:"command,omitempty"`
	Problems         []string `json:"problems,omitempty"`
	ReviewNeeded     bool     `json:"review_needed,omitempty"`
	NextAction       string   `json:"next_action,omitempty"`
	NextCommand      []string `json:"next_command,omitempty"`
}

type acceptanceManifest struct {
	SchemaVersion       string            `json:"schema_version"`
	ReleaseVersion      string            `json:"release_version"`
	Commit              string            `json:"commit"`
	GeneratedAt         string            `json:"generated_at"`
	Operator            string            `json:"operator"`
	NoPerformanceClaims bool              `json:"no_performance_claims"`
	Checks              []acceptanceCheck `json:"checks"`
}

type acceptanceCheck struct {
	Name             string `json:"name"`
	Status           string `json:"status"`
	Artifact         string `json:"artifact"`
	ArtifactSHA256   string `json:"artifact_sha256,omitempty"`
	BenchmarkSummary string `json:"benchmark_summary,omitempty"`
	RanAt            string `json:"ran_at"`
	Detail           string `json:"detail,omitempty"`
}

type verifyOptions struct {
	ManifestPath             string
	ExpectedCommit           string
	ExpectedVersion          string
	AllowNoPerformanceClaims bool
	AllowHardeningDeferred   bool
}

type evidenceRecord struct {
	SchemaVersion    string                    `json:"schema_version"`
	Check            string                    `json:"check"`
	Commit           string                    `json:"commit"`
	RanAt            string                    `json:"ran_at"`
	DurationMS       int64                     `json:"duration_ms"`
	CWD              string                    `json:"cwd"`
	Command          []string                  `json:"command"`
	Detail           string                    `json:"detail,omitempty"`
	ExitCode         int                       `json:"exit_code"`
	Stdout           string                    `json:"stdout"`
	Stderr           string                    `json:"stderr"`
	ContentReadiness *contentReadinessEvidence `json:"content_readiness,omitempty"`
}

type contentReadinessEvidence struct {
	Scope                      string   `json:"scope"`
	ProductionContent          bool     `json:"production_content"`
	ProductionReady            bool     `json:"production_ready"`
	MechanicsVerified          bool     `json:"mechanics_verified"`
	RequiredProductionEvidence []string `json:"required_production_evidence,omitempty"`
}

// Manifest is the public alias for a release acceptance manifest.
type Manifest = acceptanceManifest

// Check is the public alias for a manifest release check entry.
type Check = acceptanceCheck

// VerifyOptions is the public alias for manifest verification options.
type VerifyOptions = verifyOptions

// EvidenceRecord is the public alias for a release evidence record.
type EvidenceRecord = evidenceRecord

// ContentReadinessEvidence is the public alias for content readiness evidence.
type ContentReadinessEvidence = contentReadinessEvidence

// RequiredChecks returns the release checks that must be represented.
func RequiredChecks() []string {
	return append([]string(nil), requiredReleaseChecks...)
}

// IsRequiredCheck reports whether name is a required release check.
func IsRequiredCheck(name string) bool {
	for _, required := range requiredReleaseChecks {
		if name == required {
			return true
		}
	}
	return false
}

// HardeningDeferredAllowed reports whether name can be deferred in functional release mode.
func HardeningDeferredAllowed(name string) bool {
	_, ok := hardeningDeferredChecks[name]
	return ok
}

// HardeningDeferredDetail returns the required detail for a functional-mode deferred check.
func HardeningDeferredDetail(name string) string {
	return hardeningDeferredChecks[name]
}

// ApprovedEvidenceCommandPrefixes returns accepted command prefixes for a check.
func ApprovedEvidenceCommandPrefixes(name string) [][]string {
	return cloneCommandPrefixes(evidenceCommandPrefixes[name])
}

// AllApprovedEvidenceCommandPrefixes returns accepted command prefixes for every check.
func AllApprovedEvidenceCommandPrefixes() map[string][][]string {
	out := make(map[string][][]string, len(evidenceCommandPrefixes))
	for name, prefixes := range evidenceCommandPrefixes {
		out[name] = cloneCommandPrefixes(prefixes)
	}
	return out
}

// RequiredStdoutFragments returns stdout fragments required for recorded evidence.
func RequiredStdoutFragments(name string) []string {
	return append([]string(nil), evidenceStdoutRequiredFragments[name]...)
}

// ValidateEvidenceStdout returns problems found in recorded evidence stdout.
func ValidateEvidenceStdout(name, stdout string) []string {
	return validateEvidenceStdout(name, stdout)
}

// RecommendedEvidenceCommand returns the preferred evidence command for a check.
func RecommendedEvidenceCommand(name string) []string {
	return recommendedEvidenceCommand(name)
}

// AllowedEvidenceCommand reports whether command is approved for the check.
func AllowedEvidenceCommand(name string, command []string) bool {
	return allowedEvidenceCommand(name, command)
}

// DecodeManifest decodes a release acceptance manifest from JSON.
func DecodeManifest(raw []byte, m *Manifest) error {
	return decodeAcceptanceManifest(raw, m)
}

// ValidateManifest returns validation problems for a release acceptance manifest.
func ValidateManifest(m Manifest, baseDir string, opts VerifyOptions) []string {
	return validateAcceptanceManifest(m, baseDir, opts)
}

// ReadEvidenceRecordFile decodes a release evidence record from path.
func ReadEvidenceRecordFile(path string) (EvidenceRecord, error) {
	return readEvidenceRecordFile(path)
}

// ValidateEvidenceRecord returns a validated evidence record and its problems.
func ValidateEvidenceRecord(path, name, manifestCommit string) (*EvidenceRecord, []string) {
	return validateEvidenceRecord(path, name, manifestCommit)
}

// ContentReadinessForRecordedEvidence extracts readiness evidence from a record.
func ContentReadinessForRecordedEvidence(rec EvidenceRecord) (*ContentReadinessEvidence, error) {
	if rec.Check != contentPackageCheckName && rec.Check != contentProductionReadinessCheckName {
		return nil, nil
	}
	if rec.Check == contentProductionReadinessCheckName {
		if !allowedEvidenceCommand(rec.Check, rec.Command) {
			return nil, fmt.Errorf("command %q is not an approved content-production readiness command", strings.Join(rec.Command, " "))
		}
		if problems := validateEvidenceStdout(rec.Check, rec.Stdout); len(problems) > 0 {
			return nil, errors.New(strings.Join(problems, "; "))
		}
		readiness := ProductionContentReadiness()
		return &readiness, nil
	}
	if !isContentPackageSmokeCommand(rec.Command) {
		return nil, fmt.Errorf("command %q is not an approved rootless content-package smoke command", strings.Join(rec.Command, " "))
	}
	if err := requireContentPackageDemoDetail(rec.Detail); err != nil {
		return nil, err
	}
	if !strings.Contains(rec.Stdout, contentPackageSmokeSentinel) {
		return nil, fmt.Errorf("stdout must include %q from e2e/content-package-smoke.sh", contentPackageSmokeSentinel)
	}
	readiness := DemoContentReadiness()
	return &readiness, nil
}

// ContentPackageAcceptanceDetail formats content package acceptance detail.
func ContentPackageAcceptanceDetail(readiness ContentReadinessEvidence) string {
	return ContentReadinessAcceptanceDetail(contentPackageCheckName, readiness)
}

// ContentReadinessAcceptanceDetail formats readiness detail for a release check.
func ContentReadinessAcceptanceDetail(name string, readiness ContentReadinessEvidence) string {
	if name == contentPackageCheckName && !readiness.ProductionContent && strings.TrimSpace(readiness.Scope) == contentPackageDemoScope {
		return "demo-only content-package mechanics evidence; does not certify production App-ID, Threat-ID, or intel-feed content"
	}
	if name == contentProductionReadinessCheckName && readiness.ProductionContent && readiness.ProductionReady {
		return ContentPackageProductionReadinessSummary
	}
	if readiness.ProductionContent {
		return "production content package readiness evidence"
	}
	return "content package readiness evidence"
}

// DemoContentReadiness returns demo-only package mechanics readiness evidence.
func DemoContentReadiness() ContentReadinessEvidence {
	return contentReadinessEvidence{
		Scope:             contentPackageDemoScope,
		ProductionContent: false,
		ProductionReady:   false,
		MechanicsVerified: true,
		RequiredProductionEvidence: []string{
			"signed production App-ID package status from <data-dir>/content/app-id",
			"signed production Threat-ID package status from <data-dir>/content/threat-id",
			"signed production intel-feed package status from <data-dir>/content/intel-feeds",
			"production corpus, license, rollout, and rollback evidence for each package",
		},
	}
}

// ProductionContentReadiness returns production content readiness evidence.
func ProductionContentReadiness() ContentReadinessEvidence {
	return contentReadinessEvidence{
		Scope:             contentProductionReadinessScope,
		ProductionContent: true,
		ProductionReady:   true,
		MechanicsVerified: true,
		RequiredProductionEvidence: []string{
			"app-id:app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill",
			"threat-id:threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill",
			"intel-feeds:feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill",
		},
	}
}

func cloneCommandPrefixes(prefixes [][]string) [][]string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([][]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, append([]string(nil), prefix...))
	}
	return out
}

// ReportStatus writes release acceptance status in text or JSON form.
func ReportStatus(stdout io.Writer, opts StatusOptions) error {
	report := BuildStatusReport(opts)
	var writeErr error
	if opts.JSON {
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal release acceptance status: %w", err)
		}
		_, writeErr = stdout.Write(append(raw, '\n'))
	} else {
		writeErr = WriteStatusText(stdout, report)
	}
	if writeErr != nil {
		return fmt.Errorf("write release acceptance status: %w", writeErr)
	}
	if opts.Strict && !report.Ready {
		return fmt.Errorf("release acceptance status is %s: %d problem(s)", report.State, len(report.Problems))
	}
	return nil
}

// BuildStatusReport reads the manifest and release evidence directory.
func BuildStatusReport(opts StatusOptions) StatusReport {
	manifestPath := strings.TrimSpace(opts.ManifestPath)
	if manifestPath == "" {
		manifestPath = "release/acceptance.json"
	}
	evidenceDir := strings.TrimSpace(opts.EvidenceDir)
	if evidenceDir == "" {
		evidenceDir = "release/evidence"
	}
	report := StatusReport{
		SchemaVersion: acceptanceStatusSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ManifestPath:  manifestPath,
		EvidenceDir:   evidenceDir,
		Provenance:    "durable release evidence is limited to ngfwrelease-recorded artifacts bound to the accepted release acceptance manifest",
		Disclosures: []string{
			"remote continuation evidence, copied worktree notes, and smoke-run paths are continuation context only and do not satisfy release gates until rerun through repo-local release tooling",
			"stale evidence, digest mismatches, manifest/evidence commit mismatches, or artifact/readiness mismatches require operator review and evidence regeneration before acceptance",
			"skip-proof gates cannot be satisfied by skipped tests; privileged integration evidence must prove skipped_tests=0 and contain no Go test SKIP records",
		},
		Checks: make([]CheckStatus, 0, len(requiredReleaseChecks)),
	}
	if opts.IncludeRecordability {
		recordability := EvaluateRecordability(evidenceDir, opts.ExpectedCommit)
		report.Recordability = &recordability
	}

	raw, err := os.ReadFile(manifestPath)
	if err == nil {
		report.ManifestPresent = true
		var m acceptanceManifest
		if err := decodeAcceptanceManifest(raw, &m); err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("parse release acceptance manifest: %v", err))
			report.Checks = evidenceDirCheckStatuses(evidenceDir, normalizeCommit(opts.ExpectedCommit), opts.AllowNoPerformanceClaims, opts.AllowHardeningDeferred)
			applyCheckRemediation(report.Checks, evidenceDir, opts.ExpectedCommit)
			finalizeStatusReport(&report)
			return report
		}
		report.Problems = append(report.Problems, validateAcceptanceManifest(m, filepath.Dir(manifestPath), verifyOptions{
			ManifestPath:             manifestPath,
			ExpectedCommit:           opts.ExpectedCommit,
			ExpectedVersion:          opts.ExpectedVersion,
			AllowNoPerformanceClaims: opts.AllowNoPerformanceClaims,
			AllowHardeningDeferred:   opts.AllowHardeningDeferred,
		})...)
		report.Checks = manifestCheckStatuses(m, filepath.Dir(manifestPath), opts)
		applyCheckRemediation(report.Checks, evidenceDir, opts.ExpectedCommit)
		finalizeStatusReport(&report)
		return report
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		report.Problems = append(report.Problems, fmt.Sprintf("read release acceptance manifest %s: %v", manifestPath, err))
	}
	report.Checks = evidenceDirCheckStatuses(evidenceDir, normalizeCommit(opts.ExpectedCommit), opts.AllowNoPerformanceClaims, opts.AllowHardeningDeferred)
	applyCheckRemediation(report.Checks, evidenceDir, opts.ExpectedCommit)
	for _, check := range report.Checks {
		for _, problem := range check.Problems {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: %s", check.Name, problem))
		}
		if check.State == "missing" {
			report.Problems = append(report.Problems, fmt.Sprintf("%s evidence artifact is missing", check.Name))
		}
	}
	if !report.ManifestPresent {
		report.Problems = append(report.Problems, fmt.Sprintf("release acceptance manifest %s is missing", manifestPath))
	}
	finalizeStatusReport(&report)
	return report
}

func manifestCheckStatuses(m acceptanceManifest, baseDir string, opts StatusOptions) []CheckStatus {
	seen := map[string]acceptanceCheck{}
	for _, check := range m.Checks {
		name := strings.TrimSpace(check.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = check
		}
	}
	seenArtifacts := map[string]string{}
	statuses := make([]CheckStatus, 0, len(requiredReleaseChecks))
	for _, name := range requiredReleaseChecks {
		check, ok := seen[name]
		if !ok {
			statuses = append(statuses, CheckStatus{Name: name, State: "missing", Problems: []string{fmt.Sprintf("missing required check %q", name)}})
			continue
		}
		st := CheckStatus{
			Name:             name,
			State:            "passed",
			Artifact:         strings.TrimSpace(check.Artifact),
			BenchmarkSummary: strings.TrimSpace(check.BenchmarkSummary),
			RanAt:            strings.TrimSpace(check.RanAt),
			Detail:           strings.TrimSpace(check.Detail),
		}
		if st.Artifact != "" && !filepath.IsAbs(st.Artifact) {
			st.EvidencePath = filepath.Join(baseDir, filepath.FromSlash(st.Artifact))
		}
		problems := validateCheck(baseDir, name, check, normalizeCommit(m.Commit), m.NoPerformanceClaims, opts.AllowNoPerformanceClaims, opts.AllowHardeningDeferred, seenArtifacts)
		if len(problems) > 0 {
			st.State = "invalid"
			st.Problems = problems
			st.ReviewNeeded = checkProblemsNeedReview(problems)
		} else if strings.EqualFold(strings.TrimSpace(check.Status), hardeningDeferredStatus) {
			st.State = hardeningDeferredStatus
		} else if name == "release-benchmark" && m.NoPerformanceClaims {
			st.State = "not_applicable"
		}
		if rec, err := evidenceRecordFromCheck(baseDir, check); err == nil {
			st.Command = rec.Command
			if st.Detail == "" {
				st.Detail = strings.TrimSpace(rec.Detail)
			}
			if st.RanAt == "" {
				st.RanAt = strings.TrimSpace(rec.RanAt)
			}
		}
		statuses = append(statuses, st)
	}
	return statuses
}

func applyCheckRemediation(checks []CheckStatus, evidenceDir, expectedCommit string) {
	for i := range checks {
		checks[i].NextAction, checks[i].NextCommand = remediationForCheck(checks[i], evidenceDir, expectedCommit)
	}
}

func remediationForCheck(check CheckStatus, evidenceDir, expectedCommit string) (string, []string) {
	switch check.State {
	case "missing":
		return "Record real evidence for " + check.Name + " with ngfwrelease record; do not edit the manifest by hand.",
			recordCommandForCheck(check.Name, evidenceDir, expectedCommit, false)
	case "invalid":
		if check.ReviewNeeded {
			return "Review stale or mismatched release evidence for " + check.Name + "; do not treat remote continuation notes or edited manifests as durable evidence. Re-record real evidence from a clean checkout before acceptance.",
				recordCommandForCheck(check.Name, evidenceDir, expectedCommit, true)
		}
		if hasStdoutFragmentProblem(check) {
			return "Evidence artifact is stale or incomplete for " + check.Name + "; re-record real evidence from a clean checkout so stdout includes the required release sentinels.",
				recordCommandForCheck(check.Name, evidenceDir, expectedCommit, true)
		}
		return "Fix the listed problem(s), then re-record real evidence for " + check.Name + " before assembling or verifying the manifest.",
			recordCommandForCheck(check.Name, evidenceDir, expectedCommit, true)
	case "recorded":
		return "Evidence is recorded but is not accepted until the release acceptance manifest is assembled and verified.", nil
	case "not_applicable":
		return "No evidence artifact is required for this check in the current release acceptance context.", nil
	case hardeningDeferredStatus:
		return "Deferred to the hardening pass for full production certification; functional acceptance must still keep all non-deferred release gates recorded.", nil
	default:
		return "", nil
	}
}

func checkProblemsNeedReview(problems []string) bool {
	for _, problem := range problems {
		lower := strings.ToLower(problem)
		if strings.Contains(lower, "does not match manifest") ||
			strings.Contains(lower, "digest") ||
			strings.Contains(lower, "sha256") ||
			strings.Contains(lower, "reuses evidence artifact") ||
			strings.Contains(lower, "must stay under evidence/") ||
			strings.Contains(lower, "stale") ||
			strings.Contains(lower, "skipped test") ||
			strings.Contains(lower, "skip records") {
			return true
		}
	}
	return false
}

func hasStdoutFragmentProblem(check CheckStatus) bool {
	for _, problem := range check.Problems {
		if strings.Contains(problem, "evidence stdout must include") {
			return true
		}
	}
	return false
}

func recordCommandForCheck(name, evidenceDir, expectedCommit string, overwrite bool) []string {
	evidenceCommand := recommendedEvidenceCommand(name)
	if len(evidenceCommand) == 0 {
		return nil
	}
	commit := normalizeCommit(expectedCommit)
	if !isFullCommitHex(commit) {
		commit = "FULL_RELEASE_COMMIT_SHA"
	}
	command := []string{
		"go", "run", "./cmd/ngfwrelease", "record",
		"--evidence-dir", evidenceDir,
		"--check", name,
		"--commit", commit,
		"--detail", "EVIDENCE_DETAIL",
	}
	if overwrite {
		command = append(command, "--overwrite")
	}
	command = append(command, "--")
	evidenceCommand = appendPinnedMakeBuildVars(evidenceCommand, commit)
	command = append(command, evidenceCommand...)
	return command
}

func appendPinnedMakeBuildVars(command []string, commit string) []string {
	if len(command) == 0 || !approvedMakeSpec(command) || !isFullCommitHex(commit) {
		return command
	}
	out := append([]string(nil), command...)
	out = append(out, "VERSION="+commit[:7], "COMMIT="+commit)
	return out
}

func recommendedEvidenceCommand(name string) []string {
	command := recommendedEvidenceCommands[name]
	if len(command) == 0 {
		return nil
	}
	return append([]string(nil), command...)
}

func evidenceDirCheckStatuses(evidenceDir, expectedCommit string, allowNoPerformanceClaims, allowHardeningDeferred bool) []CheckStatus {
	statuses := make([]CheckStatus, 0, len(requiredReleaseChecks))
	for _, name := range requiredReleaseChecks {
		path := filepath.Join(evidenceDir, name+".txt")
		st := CheckStatus{
			Name:         name,
			State:        "recorded",
			Artifact:     filepath.ToSlash(filepath.Join("evidence", name+".txt")),
			EvidencePath: path,
		}
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if name == "release-benchmark" && allowNoPerformanceClaims {
					st.State = "not_applicable"
					st.Artifact = ""
					st.EvidencePath = ""
					st.Detail = defaultNoPerformanceDetail
					statuses = append(statuses, st)
					continue
				}
				if allowHardeningDeferred && HardeningDeferredAllowed(name) {
					st.State = hardeningDeferredStatus
					st.Artifact = ""
					st.EvidencePath = ""
					st.Detail = HardeningDeferredDetail(name)
					statuses = append(statuses, st)
					continue
				}
				st.State = "missing"
				statuses = append(statuses, st)
				continue
			}
			st.State = "invalid"
			st.Problems = []string{fmt.Sprintf("stat evidence artifact: %v", err)}
			statuses = append(statuses, st)
			continue
		}
		if info.IsDir() {
			st.State = "invalid"
			st.Problems = []string{"evidence artifact must be a file"}
			statuses = append(statuses, st)
			continue
		}
		rec, problems := validateEvidenceRecord(path, name, expectedCommit)
		if rec != nil {
			st.Command = rec.Command
			st.RanAt = strings.TrimSpace(rec.RanAt)
			st.Detail = strings.TrimSpace(rec.Detail)
		}
		if len(problems) > 0 {
			st.State = "invalid"
			st.Problems = problems
			st.ReviewNeeded = checkProblemsNeedReview(problems)
		}
		statuses = append(statuses, st)
	}
	return statuses
}

func evidenceRecordFromCheck(baseDir string, check acceptanceCheck) (*evidenceRecord, error) {
	artifact := strings.TrimSpace(check.Artifact)
	if artifact == "" || filepath.IsAbs(artifact) {
		return nil, errors.New("artifact is empty or absolute")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(artifact)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, errors.New("artifact escapes manifest directory")
	}
	rec, err := readEvidenceRecordFile(filepath.Join(baseDir, filepath.FromSlash(clean)))
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func finalizeStatusReport(report *StatusReport) {
	report.Summary = StatusSummary{}
	for _, check := range report.Checks {
		switch check.State {
		case "passed":
			report.Summary.Passed++
		case "recorded":
			report.Summary.Recorded++
		case "missing":
			report.Summary.Missing++
		case "invalid":
			report.Summary.Invalid++
			if check.ReviewNeeded {
				report.Summary.ReviewNeeded++
			}
		case "not_applicable":
			report.Summary.NotApplicable++
		case hardeningDeferredStatus:
			report.Summary.HardeningDeferred++
		default:
			report.Summary.Todo++
		}
	}
	report.Ready = report.ManifestPresent && len(report.Problems) == 0 && report.Summary.Invalid == 0 && report.Summary.Missing == 0 && report.Summary.Todo == 0
	switch {
	case report.Ready:
		report.State = "ready"
	case !report.ManifestPresent && report.Summary.Missing == 0 && report.Summary.Invalid == 0:
		report.State = "evidence-pending-manifest"
	default:
		report.State = "blocked"
	}
}

// WriteStatusText writes the human-readable status report used by ngfwrelease.
func WriteStatusText(stdout io.Writer, report StatusReport) error {
	if _, err := fmt.Fprintf(stdout, "release acceptance status: %s\n", report.State); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "manifest: %s (%s)\n", report.ManifestPath, presentLabel(report.ManifestPresent)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "evidence_dir: %s\n", report.EvidenceDir); err != nil {
		return err
	}
	if report.Provenance != "" {
		if _, err := fmt.Fprintf(stdout, "provenance: %s\n", report.Provenance); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "checks: passed=%d recorded=%d missing=%d invalid=%d review_needed=%d not_applicable=%d hardening_deferred=%d todo=%d\n",
		report.Summary.Passed, report.Summary.Recorded, report.Summary.Missing, report.Summary.Invalid, report.Summary.ReviewNeeded, report.Summary.NotApplicable, report.Summary.HardeningDeferred, report.Summary.Todo); err != nil {
		return err
	}
	if report.Summary.ReviewNeeded > 0 {
		if _, err := fmt.Fprintf(stdout, "review_needed_checks: %s\n", strings.Join(reviewNeededCheckNames(report.Checks), ", ")); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout, "review_needed_next: regenerate the listed evidence with ngfwrelease record after source-control acceptance; do not certify copied remote continuation evidence as durable release evidence"); err != nil {
			return err
		}
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(stdout, "- %s: %s", check.Name, check.State); err != nil {
			return err
		}
		if check.EvidencePath != "" {
			if _, err := fmt.Fprintf(stdout, " (%s)", check.EvidencePath); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
		for _, problem := range check.Problems {
			if _, err := fmt.Fprintf(stdout, "  problem: %s\n", problem); err != nil {
				return err
			}
		}
		if check.ReviewNeeded {
			if _, err := fmt.Fprintln(stdout, "  review_needed: true"); err != nil {
				return err
			}
		}
		if check.NextAction != "" {
			if _, err := fmt.Fprintf(stdout, "  next: %s\n", check.NextAction); err != nil {
				return err
			}
		}
		if len(check.NextCommand) > 0 {
			if _, err := fmt.Fprintf(stdout, "  next_command: %s\n", shellJoin(check.NextCommand)); err != nil {
				return err
			}
		}
	}
	if len(report.Problems) > 0 {
		if _, err := fmt.Fprintln(stdout, "problems:"); err != nil {
			return err
		}
		for _, problem := range report.Problems {
			if _, err := fmt.Fprintf(stdout, "- %s\n", problem); err != nil {
				return err
			}
		}
	}
	if len(report.Disclosures) > 0 {
		if _, err := fmt.Fprintln(stdout, "disclosures:"); err != nil {
			return err
		}
		for _, disclosure := range report.Disclosures {
			if _, err := fmt.Fprintf(stdout, "- %s\n", disclosure); err != nil {
				return err
			}
		}
	}
	return nil
}

func reviewNeededCheckNames(checks []CheckStatus) []string {
	names := make([]string, 0)
	for _, check := range checks {
		if check.ReviewNeeded {
			names = append(names, check.Name)
		}
	}
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
}

func shellJoin(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if !strings.ContainsAny(arg, " \t\r\n'\"\\$`!&|;<>(){}[]*?~") {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}

func presentLabel(ok bool) string {
	if ok {
		return "present"
	}
	return "missing"
}

func validateAcceptanceManifest(m acceptanceManifest, baseDir string, opts verifyOptions) []string {
	var problems []string
	if m.SchemaVersion != acceptanceSchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version must be %q", acceptanceSchemaVersion))
	}
	if strings.TrimSpace(m.ReleaseVersion) == "" {
		problems = append(problems, "release_version is required")
	} else if opts.ExpectedVersion != "" && opts.ExpectedVersion != "dev" && m.ReleaseVersion != opts.ExpectedVersion {
		problems = append(problems, fmt.Sprintf("release_version %q does not match expected %q", m.ReleaseVersion, opts.ExpectedVersion))
	}
	m.Commit = normalizeCommit(m.Commit)
	expectedCommit := normalizeCommit(opts.ExpectedCommit)
	if m.Commit == "" {
		problems = append(problems, "commit is required")
	} else if !isFullCommitHex(m.Commit) {
		problems = append(problems, "commit must be a full 40-character hex git commit")
	} else if expectedCommit != "" && expectedCommit != "unknown" {
		if !isFullCommitHex(expectedCommit) {
			problems = append(problems, "expected commit must be a full 40-character hex git commit")
		} else if m.Commit != expectedCommit {
			problems = append(problems, fmt.Sprintf("commit %q does not match expected %q", m.Commit, expectedCommit))
		}
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(m.GeneratedAt)); err != nil {
		problems = append(problems, "generated_at must be RFC3339")
	}
	if strings.TrimSpace(m.Operator) == "" {
		problems = append(problems, "operator is required")
	}
	seen := map[string]acceptanceCheck{}
	for i, check := range m.Checks {
		check.Name = strings.TrimSpace(check.Name)
		if check.Name == "" {
			problems = append(problems, fmt.Sprintf("checks[%d].name is required", i))
			continue
		}
		if _, ok := seen[check.Name]; ok {
			problems = append(problems, fmt.Sprintf("duplicate check %q", check.Name))
			continue
		}
		seen[check.Name] = check
	}
	seenArtifacts := map[string]string{}
	for _, name := range requiredReleaseChecks {
		check, ok := seen[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("missing required check %q", name))
			continue
		}
		if m.NoPerformanceClaims {
			problems = append(problems, validateNoPerformanceClaimsDetail(name, check.Detail)...)
		}
		problems = append(problems, validateCheck(baseDir, name, check, m.Commit, m.NoPerformanceClaims, opts.AllowNoPerformanceClaims, opts.AllowHardeningDeferred, seenArtifacts)...)
	}
	return problems
}

func validateNoPerformanceClaimsDetail(name, detail string) []string {
	findings := perfreport.PerformanceClaimFindings(detail)
	if len(findings) == 0 {
		return nil
	}
	problems := make([]string, 0, len(findings))
	for _, finding := range findings {
		problems = append(problems, fmt.Sprintf("%s detail must not contain performance claim language when no_performance_claims is true: %s", name, finding.String()))
	}
	return problems
}

func validateCheck(baseDir, name string, check acceptanceCheck, manifestCommit string, noPerformanceClaims, allowNoPerformanceClaims, allowHardeningDeferred bool, seenArtifacts map[string]string) []string {
	var problems []string
	status := strings.ToLower(strings.TrimSpace(check.Status))
	if status == hardeningDeferredStatus {
		if !allowHardeningDeferred {
			return []string{fmt.Sprintf("%s is hardening_deferred, but functional hardening-deferred mode was not enabled", name)}
		}
		if !HardeningDeferredAllowed(name) {
			problems = append(problems, fmt.Sprintf("%s is not allowed to be hardening_deferred", name))
		}
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(check.RanAt)); err != nil {
			problems = append(problems, fmt.Sprintf("%s hardening_deferred ran_at must be RFC3339", name))
		}
		if strings.TrimSpace(check.Detail) == "" {
			problems = append(problems, fmt.Sprintf("%s hardening_deferred requires detail tracking the production certification work", name))
		}
		if strings.TrimSpace(check.Artifact) != "" || strings.TrimSpace(check.ArtifactSHA256) != "" || strings.TrimSpace(check.BenchmarkSummary) != "" {
			problems = append(problems, fmt.Sprintf("%s hardening_deferred must not reference an artifact, artifact digest, or benchmark summary", name))
		}
		return problems
	}
	if name == "release-benchmark" && noPerformanceClaims {
		if !allowNoPerformanceClaims {
			return []string{"release-benchmark is not_applicable, but --allow-no-performance-claims was not set"}
		}
		if status != "not_applicable" {
			problems = append(problems, "release-benchmark must be not_applicable when no_performance_claims is true")
		}
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(check.RanAt)); err != nil {
			problems = append(problems, "release-benchmark ran_at must be RFC3339")
		}
		if strings.TrimSpace(check.Detail) == "" {
			problems = append(problems, "release-benchmark not_applicable requires detail explaining that no performance claims are published")
		}
		if strings.TrimSpace(check.Artifact) != "" || strings.TrimSpace(check.ArtifactSHA256) != "" || strings.TrimSpace(check.BenchmarkSummary) != "" {
			problems = append(problems, "release-benchmark not_applicable must not reference an artifact or benchmark summary")
		}
		return problems
	}
	if status != "passed" {
		problems = append(problems, fmt.Sprintf("%s status must be passed", name))
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(check.RanAt)); err != nil {
		problems = append(problems, fmt.Sprintf("%s ran_at must be RFC3339", name))
	}
	artifact := strings.TrimSpace(check.Artifact)
	if artifact == "" {
		problems = append(problems, fmt.Sprintf("%s artifact is required", name))
		return problems
	}
	if filepath.IsAbs(artifact) {
		problems = append(problems, fmt.Sprintf("%s artifact must be relative to the manifest", name))
		return problems
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(artifact)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		problems = append(problems, fmt.Sprintf("%s artifact path escapes the manifest directory", name))
		return problems
	}
	if clean == "evidence" || !strings.HasPrefix(clean, "evidence/") {
		problems = append(problems, fmt.Sprintf("%s artifact must be under evidence/", name))
		return problems
	}
	path := filepath.Join(baseDir, filepath.FromSlash(clean))
	if info, err := os.Stat(path); err != nil {
		problems = append(problems, fmt.Sprintf("%s artifact %q is not readable: %v", name, artifact, err))
	} else if info.IsDir() {
		problems = append(problems, fmt.Sprintf("%s artifact %q must be a file", name, artifact))
	} else if info.Size() == 0 {
		problems = append(problems, fmt.Sprintf("%s artifact %q must not be empty", name, artifact))
	} else if err := validateArtifactDigest(path, name, check.ArtifactSHA256); err != nil {
		problems = append(problems, err.Error())
	} else if realPath, err := resolvedPathUnder(filepath.Join(baseDir, "evidence"), path); err != nil {
		problems = append(problems, fmt.Sprintf("%s artifact %q must stay under evidence/: %v", name, artifact, err))
	} else if previous, ok := seenArtifacts[realPath]; ok {
		problems = append(problems, fmt.Sprintf("%s artifact %q reuses evidence artifact already used by %s", name, artifact, previous))
	} else {
		seenArtifacts[realPath] = name
	}
	rec, evidenceProblems := validateEvidenceRecord(path, name, manifestCommit)
	problems = append(problems, evidenceProblems...)
	if name == contentPackageCheckName {
		problems = append(problems, validateContentPackageManifestDetail(check.Detail, rec)...)
	}
	if name == "release-benchmark" {
		problems = append(problems, validateBenchmarkSummary(baseDir, check.BenchmarkSummary)...)
	}
	return problems
}

func validateEvidenceRecord(path, name, manifestCommit string) (*evidenceRecord, []string) {
	rec, err := readEvidenceRecordFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s artifact must be JSON produced by ngfwrelease record: %v", name, err)}
	}
	var problems []string
	if rec.SchemaVersion != evidenceSchemaVersion {
		problems = append(problems, fmt.Sprintf("%s evidence schema_version must be %s", name, evidenceSchemaVersion))
	}
	if rec.Check != name {
		problems = append(problems, fmt.Sprintf("%s evidence check %q does not match manifest check", name, rec.Check))
	}
	rec.Commit = normalizeCommit(rec.Commit)
	if !isFullCommitHex(rec.Commit) {
		problems = append(problems, fmt.Sprintf("%s evidence commit must be a full 40-character hex git commit", name))
	} else if manifestCommit != "" && rec.Commit != normalizeCommit(manifestCommit) {
		problems = append(problems, fmt.Sprintf("%s evidence commit %q does not match manifest commit %q", name, rec.Commit, normalizeCommit(manifestCommit)))
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(rec.RanAt)); err != nil {
		problems = append(problems, fmt.Sprintf("%s evidence ran_at must be RFC3339", name))
	}
	if rec.ExitCode != 0 {
		problems = append(problems, fmt.Sprintf("%s evidence exit_code must be 0", name))
	}
	if strings.TrimSpace(rec.Detail) == "" {
		problems = append(problems, fmt.Sprintf("%s evidence detail is required", name))
	}
	problems = append(problems, ValidateEvidenceMetadataRedaction(name, "detail", rec.Detail)...)
	if len(rec.Command) == 0 {
		problems = append(problems, fmt.Sprintf("%s evidence command is required", name))
	} else if !allowedEvidenceCommand(name, rec.Command) {
		problems = append(problems, fmt.Sprintf("%s evidence command %q is not an approved release evidence command for this check", name, strings.Join(rec.Command, " ")))
	}
	problems = append(problems, validateEvidenceStdout(name, rec.Stdout)...)
	problems = append(problems, ValidateEvidenceOutputRedaction(name, rec.Stdout, rec.Stderr)...)
	problems = append(problems, validateContentReadiness(rec)...)
	return &rec, problems
}

func readEvidenceRecordFile(path string) (evidenceRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return evidenceRecord{}, fmt.Errorf("read evidence record %q: %w", path, err)
	}
	var rec evidenceRecord
	if err := decodeStrictJSON(raw, &rec); err != nil {
		return evidenceRecord{}, err
	}
	return rec, nil
}

func decodeAcceptanceManifest(raw []byte, m *acceptanceManifest) error {
	return decodeStrictJSON(raw, m)
}

func decodeStrictJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateContentReadiness(rec evidenceRecord) []string {
	switch rec.Check {
	case contentPackageCheckName:
		return validateContentPackageReadiness(rec)
	case contentProductionReadinessCheckName:
		return validateContentProductionReadiness(rec)
	default:
		return nil
	}
}

func validateContentPackageReadiness(rec evidenceRecord) []string {
	if rec.Check != contentPackageCheckName {
		return nil
	}
	if rec.ContentReadiness == nil {
		return []string{"content-package-verification evidence content_readiness is required"}
	}
	readiness := *rec.ContentReadiness
	var problems []string
	if isContentPackageSmokeCommand(rec.Command) {
		if strings.TrimSpace(readiness.Scope) != contentPackageDemoScope {
			problems = append(problems, fmt.Sprintf("content-package-verification demo smoke content_readiness.scope must be %q", contentPackageDemoScope))
		}
		if readiness.ProductionContent {
			problems = append(problems, "content-package-verification demo smoke evidence must not claim production content")
		}
		if readiness.ProductionReady {
			problems = append(problems, "content-package-verification demo smoke evidence must not claim production readiness")
		}
		if !readiness.MechanicsVerified {
			problems = append(problems, "content-package-verification demo smoke evidence must set mechanics_verified true")
		}
		if err := requireContentPackageDemoDetail(rec.Detail); err != nil {
			problems = append(problems, "content-package-verification evidence detail "+err.Error())
		}
	}
	return problems
}

func validateContentProductionReadiness(rec evidenceRecord) []string {
	if rec.ContentReadiness == nil {
		return []string{"content-production-readiness evidence content_readiness is required"}
	}
	readiness := *rec.ContentReadiness
	var problems []string
	if strings.TrimSpace(readiness.Scope) != contentProductionReadinessScope {
		problems = append(problems, fmt.Sprintf("content-production-readiness content_readiness.scope must be %q", contentProductionReadinessScope))
	}
	if !readiness.ProductionContent {
		problems = append(problems, "content-production-readiness evidence content_readiness.production_content must be true")
	}
	if !readiness.ProductionReady {
		problems = append(problems, "content-production-readiness evidence content_readiness.production_ready must be true")
	}
	for _, set := range []string{"app-id", "threat-id", "intel-feeds"} {
		if !hasRequiredProductionEvidenceSet(readiness.RequiredProductionEvidence, set) {
			problems = append(problems, fmt.Sprintf("content-production-readiness required_production_evidence must include %s evidence set", set))
		}
	}
	return problems
}

func hasRequiredProductionEvidenceSet(entries []string, set string) bool {
	set = strings.ToLower(strings.TrimSpace(set))
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry), set) {
			return true
		}
	}
	return false
}

func validateContentPackageManifestDetail(detail string, rec *evidenceRecord) []string {
	if rec == nil || rec.ContentReadiness == nil || rec.ContentReadiness.ProductionContent {
		return nil
	}
	var problems []string
	normalized := strings.ToLower(strings.TrimSpace(detail))
	if !strings.Contains(normalized, "demo-only") || !strings.Contains(normalized, "does not certify production") {
		problems = append(problems, "content-package-verification manifest detail must state demo-only scope and that it does not certify production content")
	}
	if containsProductionContentReadyClaim(normalized) {
		problems = append(problems, "content-package-verification manifest detail must not claim production content readiness for demo-only evidence")
	}
	return problems
}

func requireContentPackageDemoDetail(detail string) error {
	normalized := strings.ToLower(strings.TrimSpace(detail))
	if !strings.Contains(normalized, "demo-only") || !strings.Contains(normalized, "does not certify production") {
		return errors.New("detail must state demo-only scope and that it does not certify production content")
	}
	if containsProductionContentReadyClaim(normalized) {
		return errors.New("detail must not claim production content readiness for demo-only evidence")
	}
	return nil
}

func containsProductionContentReadyClaim(detail string) bool {
	for _, phrase := range []string{
		"production-ready",
		"production ready",
		"production content ready",
		"production content is ready",
		"certifies production content",
	} {
		if strings.Contains(detail, phrase) {
			return true
		}
	}
	return false
}

func isContentPackageSmokeCommand(command []string) bool {
	return allowedEvidenceCommand(contentPackageCheckName, command)
}

func validateEvidenceStdout(name, stdout string) []string {
	required := evidenceStdoutRequiredFragments[name]
	var problems []string
	for _, fragment := range required {
		if !strings.Contains(stdout, fragment) {
			problems = append(problems, fmt.Sprintf("%s evidence stdout must include %q", name, fragment))
		}
	}
	if name == "privileged-integration" && hasGoTestSkipRecord(stdout) {
		problems = append(problems, "privileged-integration evidence stdout contains skipped test records; skip-proof gates cannot be satisfied by skipped tests")
	}
	return problems
}

func hasGoTestSkipRecord(stdout string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--- SKIP:") || strings.HasPrefix(trimmed, "=== SKIP") {
			return true
		}
	}
	return false
}

func allowedEvidenceCommand(name string, command []string) bool {
	allowed := evidenceCommandPrefixes[name]
	if len(allowed) == 0 {
		return false
	}
	for _, spec := range allowed {
		if commandMatchesApprovedSpec(name, command, spec) {
			return true
		}
	}
	return false
}

func commandMatchesApprovedSpec(name string, command, spec []string) bool {
	if !hasCommandPrefix(command, spec) {
		return false
	}
	if len(command) == len(spec) {
		_, needsPath := evidencePathRootForSpec(name, spec)
		return !needsPath
	}
	root, needsPath := evidencePathRootForSpec(name, spec)
	if !needsPath && approvedMakeEvidenceVars(command, spec) {
		return true
	}
	if !needsPath || len(command) != len(spec)+1 {
		return false
	}
	return validEvidenceCommandPath(command[len(spec)], root)
}

func approvedMakeEvidenceVars(command, spec []string) bool {
	if len(spec) == 0 || !approvedMakeSpec(spec) || len(command) <= len(spec) {
		return false
	}
	for _, arg := range command[len(spec):] {
		if !approvedMakeEvidenceVar(arg) {
			return false
		}
	}
	return true
}

func approvedMakeSpec(spec []string) bool {
	return spec[0] == "make" ||
		(len(spec) >= 2 && spec[0] == "sudo" && spec[1] == "make") ||
		(len(spec) >= 3 && spec[0] == "sudo" && spec[1] == "-E" && spec[2] == "make")
}

func approvedMakeEvidenceVar(arg string) bool {
	name, value, ok := strings.Cut(arg, "=")
	if !ok || name == "" || value == "" || strings.ContainsAny(name, "/\\") {
		return false
	}
	switch name {
	case "VERSION", "COMMIT", "BUILD_DATE":
		return true
	default:
		return false
	}
}

func evidencePathRootForSpec(name string, spec []string) (string, bool) {
	if name == "release-benchmark" && commandsEqual(spec, []string{"go", "run", "./cmd/ngfwperf", "verify", "--strict", "--publishable"}) {
		return "perf/release-results", true
	}
	if len(spec) == 0 || spec[len(spec)-1] != "--evidence-dir" {
		return "", false
	}
	switch name {
	case contentProductionReadinessCheckName:
		return "release/field-evidence/content-production", true
	case "m3-field-evidence":
		return "release/field-evidence/m3", true
	case "ebpf-ol9-field-evidence":
		return "release/field-evidence/ebpf-ol9", true
	case oidcFieldEvidenceCheckName:
		return "release/field-evidence/oidc", true
	case samlFieldEvidenceCheckName:
		return "release/field-evidence/saml", true
	default:
		return "", false
	}
}

func validEvidenceCommandPath(raw, root string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") || filepath.IsAbs(raw) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(raw))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	root = filepath.ToSlash(filepath.Clean(root))
	return clean == root || strings.HasPrefix(clean, root+"/")
}

func hasCommandPrefix(command, prefix []string) bool {
	if len(command) < len(prefix) {
		return false
	}
	for i := range prefix {
		if command[i] != prefix[i] {
			return false
		}
	}
	return true
}

func commandsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateArtifactDigest(path, name, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if expected == "" {
		return fmt.Errorf("%s artifact_sha256 is required", name)
	}
	if len(expected) != sha256.Size*2 {
		return fmt.Errorf("%s artifact_sha256 must be %d hex characters", name, sha256.Size*2)
	}
	for _, r := range expected {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("%s artifact_sha256 must be hex", name)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s artifact digest could not be computed: %v", name, err)
	}
	digest := sha256.Sum256(raw)
	got := fmt.Sprintf("%x", digest[:])
	if got != expected {
		return fmt.Errorf("%s artifact_sha256 %q does not match artifact digest %q", name, expected, got)
	}
	return nil
}

func resolvedPathUnder(root, path string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("evidence root %s must not be a symlink", root)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(realRoot) {
		realRoot, err = filepath.Abs(realRoot)
		if err != nil {
			return "", err
		}
	}
	realRoot = filepath.Clean(realRoot)
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(realPath) {
		realPath, err = filepath.Abs(realPath)
		if err != nil {
			return "", err
		}
	}
	realPath = filepath.Clean(realPath)
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("resolved path %s escapes %s", realPath, realRoot)
	}
	return realPath, nil
}

func validateBenchmarkSummary(baseDir, raw string) []string {
	var problems []string
	summary := strings.TrimSpace(raw)
	if summary == "" {
		return []string{"release-benchmark benchmark_summary is required"}
	}
	if filepath.IsAbs(summary) {
		return []string{"release-benchmark benchmark_summary must be relative to the repository root"}
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(summary)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return []string{"release-benchmark benchmark_summary must not escape the repository root"}
	}
	parts := strings.Split(clean, "/")
	if len(parts) != 4 || parts[0] != "perf" || parts[1] != "release-results" || parts[2] == "" || parts[3] != "summary.json" {
		return []string{"release-benchmark benchmark_summary must point to perf/release-results/<run>/summary.json"}
	}
	repoRoot := releaseRepoRoot(baseDir)
	path := filepath.Join(repoRoot, filepath.FromSlash(clean))
	result, err := perfreport.ValidateSummaryFile(path)
	if err != nil {
		return []string{fmt.Sprintf("release-benchmark benchmark_summary %q is not readable: %v", clean, err)}
	}
	if len(result.Errors) > 0 {
		problems = append(problems, fmt.Sprintf("release-benchmark benchmark_summary %q has %d validation error(s): %s", clean, len(result.Errors), strings.Join(result.Errors, "; ")))
	}
	gate := perfreport.EvaluatePublicationGate(result, true)
	if !gate.Publishable() {
		problems = append(problems, fmt.Sprintf("release-benchmark benchmark_summary %q is not publishable: %s", clean, gate.Title))
	}
	return problems
}

func releaseRepoRoot(baseDir string) string {
	if filepath.Base(baseDir) == "release" {
		return filepath.Dir(baseDir)
	}
	return baseDir
}

func normalizeCommit(commit string) string {
	return strings.ToLower(strings.TrimSpace(commit))
}

func isFullCommitHex(commit string) bool {
	commit = normalizeCommit(commit)
	if len(commit) != 40 {
		return false
	}
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

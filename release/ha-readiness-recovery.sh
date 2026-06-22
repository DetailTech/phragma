#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: release/ha-readiness-recovery.sh [--check]

Runs the rootless HA readiness and recovery gate used by release acceptance.
The gate exercises active/passive HA status, passive policy pull, automatic
replication bookkeeping, guarded manual activation, optional Linux-local
VIP/route promotion control flow, CLI parity, daemon peer configuration, and
support-bundle collection without claiming privileged field certification,
peer fencing, or connection-state synchronization.
USAGE
}

mode="check"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check)
      mode="check"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

run_go_tests() {
  go test -count=1 -v ./internal/apiserver \
    -run '^(TestSystemHighAvailabilityStatusReportsStandaloneLKG|TestSystemStatusEmbedsDegradedActivePassiveHA|TestSystemHighAvailabilityStatusReportsPeerHeartbeatSync|TestSystemHighAvailabilityStatusRequiresLKGForReadiness|TestSystemHighAvailabilityStatusDegradesStaleOrSameRolePeer|TestSystemHighAvailabilityStatusDegradesUnreachablePeer|TestSystemPullHighAvailabilityPolicyAppliesActivePeerPolicy|TestSystemAutomaticHighAvailabilityReplicationAppliesActivePeerPolicy|TestSystemAutomaticHighAvailabilityReplicationRecordsBlockedAttempt|TestSystemActivateHighAvailabilityFailoverPersistsActiveRole|TestSystemActivateHighAvailabilityFailoverPromotesVIPBeforePersistingActiveRole|TestSystemActivateHighAvailabilityFailoverDoesNotPersistActiveRoleWhenPromotionFails|TestSystemActivateHighAvailabilityFailoverRejectsMissingAcks|TestSystemPullHighAvailabilityPolicyRejectsDirtyCandidateBeforePeerFetch|TestSystemPullHighAvailabilityPolicyRejectsCandidateStagedDuringPeerFetch|TestSystemSupportBundleCollectsServerBundle)$'
  go test -count=1 -v ./internal/cli \
    -run '^(TestPrintStatusShowsHighAvailabilityReadiness|TestSystemHAStatusPrintsCutoverPlan|TestSystemHAStatusPrintsBlockedCutoverPlan|TestSystemHAPullPolicyRequiresMessageAndAck|TestSystemHAPullPolicyCallsAPIAndPrintsSummary|TestSystemHAActivatePassiveRequiresMessageAndAcks|TestSystemHAActivatePassiveCallsAPIAndPrintsSummary|TestSupportBundleCollectorShape|TestCollectSupportBundleUsesServerRPCWhenAvailable|TestCollectSupportBundleFallsBackToLegacyAggregationForUnimplemented)$'
  go test -count=1 -v ./internal/engines \
    -run '^(TestHAPromotionValidateRejectsUnsafeConfig|TestHAPromotionPromoteAppliesDesiredStateAndRemovesManagedStaleEntries|TestHAPromotionAnnouncementWarningDoesNotFailPromotion)$'
  go test -count=1 -v ./cmd/controld \
    -run '^(TestValidateHAFlags|TestHAPeerSourcesRejectEmptyTokenFile|TestHAPeerSourcesUseExpectedHTTPSRequests|TestHAPeerPolicyURLDerivesRunningPolicyEndpoint)$'
}

run_go_tests

cat <<EOF
check=ha-readiness-recovery
mode=${mode}
ha_recovery_scope=status,passive-policy-pull,automatic-replication,manual-activation,optional-linux-local-vip-route-promotion,cli-parity,daemon-peer-config,support-bundle
automated_tests=TestSystemHighAvailabilityStatusReportsPeerHeartbeatSync,TestSystemHighAvailabilityStatusDegradesStaleOrSameRolePeer,TestSystemPullHighAvailabilityPolicyAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationRecordsBlockedAttempt,TestSystemActivateHighAvailabilityFailoverPersistsActiveRole,TestSystemActivateHighAvailabilityFailoverPromotesVIPBeforePersistingActiveRole,TestSystemActivateHighAvailabilityFailoverDoesNotPersistActiveRoleWhenPromotionFails,TestHAPromotionPromoteAppliesDesiredStateAndRemovesManagedStaleEntries,TestSystemSupportBundleCollectsServerBundle,TestPrintStatusShowsHighAvailabilityReadiness,TestSystemHAStatusPrintsCutoverPlan,TestSystemHAPullPolicyCallsAPIAndPrintsSummary,TestSystemHAActivatePassiveCallsAPIAndPrintsSummary,TestValidateHAFlags,TestHAPeerSourcesUseExpectedHTTPSRequests,TestSupportBundleCollectorShape
ha_claim_boundary=does_not_certify_privileged_vip_route_field_evidence,peer_fencing,connection_state_sync,live_linux_failover
ha_surface=SystemService.GetHighAvailabilityStatus,PullHighAvailabilityPolicy,RunHighAvailabilityReplicationOnce,ActivateHighAvailabilityFailover,HAPromotion,ngfwctl-status,ngfwctl-system-ha,controld-ha-peer-source,controld-ha-promotion-flags,support-bundle-highAvailabilityStatus
deferred_field_controls=peer-mtls,peer-token-rotation,privileged-vip-route-field-evidence,peer-fencing,split-brain-policy,conntrack-sync,live-linux-failover
run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine,loopback-httptest-peer
status=passed
EOF

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: release/policy-restore-drill.sh [--check]

Runs the rootless emergency policy restore drill used by release acceptance.
The drill exercises rollback validation, acknowledgements, audit comments,
audit log writes, running-pointer recovery metadata, last-known-good metadata,
and engine apply behavior through the canonical in-process PolicyService tests.
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
  go test -count=1 -v ./internal/apiserver ./internal/cli \
    -run 'TestPolicyRollback(RecordsIntentAuditAndAppliesEngines|RequiresAckRiskForHighRiskImpact|RequiresAckRuntimeForRuntimeWarnings|UsesOperatorComment)|TestHandleRollbackPreflight(RequiresAckForHighRisk|RejectsInvalidTarget|RequiresAckForRuntimeUnavailable)|TestRollbackCommandRequiresAuditCommentBeforeDial'
}

run_go_tests

cat <<EOF
check=policy-restore-drill
mode=${mode}
restore_drill_scope=policy-version-rollback,validation,impact-ack,runtime-ack,audit-comment,audit-log,running-pointer,last-known-good,engine-apply
automated_tests=TestPolicyRollbackRecordsIntentAuditAndAppliesEngines,TestPolicyRollbackRequiresAckRiskForHighRiskImpact,TestPolicyRollbackRequiresAckRuntimeForRuntimeWarnings,TestPolicyRollbackUsesOperatorComment
restore_surface=PolicyService.Rollback,ngfwctl-rollback-preflight,store-version-history,audit-chain
run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine
status=passed
EOF

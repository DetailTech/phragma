import assert from "node:assert/strict";

import { SUPPORT_BUNDLE_REDACTED, SUPPORT_BUNDLE_SCHEMA, buildSupportBundle, redactSensitive, supportBundleFilename, supportBundlePreviewModel, supportBundlePreviewReport } from "./support_bundle.js";

const collectedAt = "2026-06-17T12:30:05.123Z";

{
  const bundle = buildSupportBundle({
    collectedAt,
    browser: {},
    results: {
      status: { status: "fulfilled", value: {
        runtime: {
          version: "dev",
          dataDir: "/var/lib/openngfw",
          logDir: "/var/log/openngfw",
        },
        dataplane: {
          activeDataplane: "nftables",
          kernelTuning: { sysctlConfigPath: "/etc/openngfw/sysctl.d/dataplane.conf" },
        },
      } },
      highAvailabilityStatus: { status: "fulfilled", value: {
        schemaVersion: "phragma.ha.status.v1",
        status: {
          state: "degraded",
          mode: "active-passive",
          role: "active",
          sync: { state: "degraded" },
          failover: { state: "planned", eligible: false },
        },
      } },
      telemetryExportStatus: { status: "fulfilled", value: {
        schemaVersion: "phragma.telemetry.export.status.v1",
        state: "configured",
        telemetryEnabled: true,
        runningPolicyVersion: "7",
        vector: { state: "active", detail: "process running" },
        clickhouse: { configured: true, endpoint: "https://clickhouse.example:8443", database: "openngfw", evidenceState: "configured-unverified" },
        exports: [
          { name: "local-json", configured: true, type: "TELEMETRY_EXPORT_TYPE_JSON_FILE", target: "/var/log/openngfw/exports/eve.json", protocol: "file", evidenceState: "receiving" },
          { name: "siem-json", configured: true, type: "TELEMETRY_EXPORT_TYPE_JSON_TCP", target: "siem.example:5514", protocol: "tcp", evidenceState: "configured-unverified" },
        ],
        warnings: [{ message: "receiver proof required" }],
      } },
      runningPolicy: { status: "fulfilled", value: {} },
      candidateStatus: { status: "fulfilled", value: {
        hasCandidate: true,
        dirty: true,
        runningVersion: 7,
        changeCount: 3,
        changes: [{ section: "rules", added: 1, modified: 1, removed: 1 }],
      } },
      candidateValidation: { status: "fulfilled", value: {} },
      runtimeReadinessPreflight: { status: "fulfilled", value: {
        schemaVersion: "phragma.runtime-readiness.v1",
        operation: "commit",
        label: "Runtime warnings need acknowledgement",
        requiresAck: true,
        detail: "Runtime posture has warnings from /opt/phragma/runtime/status.json that require operator acknowledgement.",
        items: [{
          id: "runtime-warning",
          severity: "warning",
          message: "inspection engine degraded token=runtime-secret evidence_path=/data/openngfw/runtime-preflight.json",
          command: ["ngfwctl", "system", "runtime-readiness", "--token", "runtime-command-secret", "--output=/opt/phragma/runtime-preflight.json"],
        }],
      } },
      auditIntegrity: { status: "fulfilled", value: { ok: true, entryCount: 4, latestEntryHash: "abcd1234" } },
      contentPackages: { status: "fulfilled", value: {
        packages: [
          {
            kind: "app-id",
            state: "verified",
            blockers: [],
            manifestPath: "/var/lib/openngfw/content/app-id/manifest.json",
            rollbackPath: "/var/lib/openngfw/content/app-id/.rollback/app-id-1.0.0",
            restoredRollbackPath: "/var/lib/openngfw/content/app-id/.rollback/app-id-0.9.0",
            sourcePath: "/tmp/content-import/app-id-1.0.0",
          },
          { kind: "threat-id", state: "local-only", blockers: ["signed manifest", "package rollback"] },
        ],
      } },
      releaseAcceptanceStatus: { status: "fulfilled", value: {
        state: "blocked",
        ready: false,
        manifestPresent: false,
        manifestPath: "/Users/alice/openngfw/release/acceptance.json",
        evidenceDir: "/opt/phragma/release/evidence",
        summary: {
          missing: 6,
          invalid: 1,
          notApplicable: 1,
          todo: 0,
        },
        problems: ["release acceptance manifest release/acceptance.json is missing"],
        recordability: {
          ready: false,
          gitHead: "abc1234",
          recordCommit: "def5678",
          allowedDirtyPaths: ["release/evidence"],
          dirtySourcePaths: [" M internal/source.go", "?? /Users/alice/openngfw/internal/generated.go"],
          truncatedDirtySourceCount: 4,
          problems: ["dirty source tree has uncommitted source changes"],
          nextAction: "Commit or stash source changes before recording release evidence.",
        },
        checks: [
          {
            name: "release-benchmark",
            state: "not_applicable",
            nextAction: "No evidence artifact is required for this check in the current release acceptance context; checked /opt/phragma/release/manifest.json.",
          },
          {
            name: "privileged-integration",
            state: "missing",
            evidencePath: "release/evidence/privileged-integration.txt",
            next_action: "Record real evidence for privileged-integration from /home/opc/field-evidence and token=release-secret.",
            next_command: ["go", "run", "./cmd/ngfwrelease", "record", "privileged-integration", "--token", "release-command-secret", "--evidence-dir=/opt/phragma/release/evidence", "--", "make", "integration-test"],
          },
        ],
      } },
      audit: { status: "fulfilled", value: {
        entries: [{
          detail: "kind=app-id source='/tmp/content-import/app-id-1.0.0' rollback_path='/var/lib/openngfw/content/app-id/.rollback/app-id-1.0.0' restored_rollback_path='/var/lib/openngfw/content/app-id/.rollback/app-id-0.9.0' cfg=/etc/openngfw/policy.yaml user=/Users/alice/openngfw/state.db home=/home/opc/.config/openngfw/config.yaml log=/var/log/openngfw/controld.log",
        }],
      } },
    },
  });

  assert.equal(bundle.schemaVersion, SUPPORT_BUNDLE_SCHEMA);
  assert.deepEqual(bundle.collector, { type: "browser", name: "webui", version: "" });
  assert.equal(bundle.summary.runtimeVersion, "dev");
  assert.equal(bundle.summary.activeDataplane, "nftables");
  assert.equal(bundle.summary.runningPolicyVersion, "none");
  assert.equal(bundle.summary.candidateHasCandidate, true);
  assert.equal(bundle.summary.candidateDirty, true);
  assert.equal(bundle.summary.candidateRunningVersion, 7);
  assert.equal(bundle.summary.candidateChangeCount, 3);
  assert.equal(bundle.summary.candidateValidation, "not-set");
  assert.equal(bundle.summary.contentPackageCount, 2);
  assert.equal(bundle.summary.verifiedContentPackages, 1);
  assert.equal(bundle.summary.contentPackageBlockers, 2);
  assert.equal(bundle.summary.telemetryExportState, "configured");
  assert.equal(bundle.summary.telemetryExportEnabled, true);
  assert.equal(bundle.summary.telemetryExportVectorState, "active");
  assert.equal(bundle.summary.telemetryExportSinkCount, 2);
  assert.equal(bundle.summary.telemetryExportObservedSinkCount, 1);
  assert.equal(bundle.summary.telemetryExportClickHouseEvidence, "configured-unverified");
  assert.equal(bundle.summary.telemetryExportWarnings, 1);
  assert.equal(bundle.summary.releaseAcceptanceState, "blocked");
  assert.equal(bundle.summary.releaseAcceptanceReady, false);
  assert.equal(bundle.summary.releaseAcceptanceManifestPresent, false);
  assert.equal(bundle.summary.releaseAcceptanceMissing, 6);
  assert.equal(bundle.summary.releaseAcceptanceInvalid, 1);
  assert.equal(bundle.summary.releaseAcceptanceNotApplicable, 1);
  assert.equal(bundle.summary.releaseAcceptanceTodo, 0);
  assert.equal(bundle.summary.releaseAcceptanceProblems, 1);
  assert.equal(bundle.summary.releaseAcceptanceNextActions, 2);
  assert.equal(bundle.summary.releaseAcceptanceNextCommands, 1);
  assert.equal(bundle.summary.releaseAcceptanceRecordabilityReady, false);
  assert.equal(bundle.summary.releaseAcceptanceRecordabilityProblems, 1);
  assert.equal(bundle.summary.releaseAcceptanceDirtySourcePaths, 2);
  assert.equal(bundle.summary.releaseAcceptanceTruncatedDirtySourceCount, 4);
  assert.equal(bundle.summary.auditIntegrity, "verified");
  assert.equal(bundle.summary.auditEntryCount, 4);
  assert.equal(bundle.summary.latestAuditHash, "abcd1234");
  assert.deepEqual(bundle.summary.failedEndpoints, []);
  assert.equal(bundle.endpoints.status.data.runtime.dataDir, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.status.data.runtime.logDir, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.status.data.dataplane.kernelTuning.sysctlConfigPath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.contentPackages.data.packages[0].manifestPath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.contentPackages.data.packages[0].rollbackPath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.contentPackages.data.packages[0].restoredRollbackPath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.contentPackages.data.packages[0].sourcePath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.manifestPath, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.evidenceDir, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.recordability.allowedDirtyPaths[0], SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.recordability.dirtySourcePaths[0], SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.recordability.dirtySourcePaths[1], SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.checks[1].next_command[0], "go");
  assert.equal(bundle.endpoints.runtimeReadinessPreflight.data.items[0].message.includes("runtime-secret"), false);
  assert.equal(bundle.endpoints.runtimeReadinessPreflight.data.items[0].message.includes("/data/openngfw"), false);
  assert.deepEqual(
    bundle.endpoints.runtimeReadinessPreflight.data.items[0].command,
    ["ngfwctl", "system", "runtime-readiness", "--token", SUPPORT_BUNDLE_REDACTED, `--output=${SUPPORT_BUNDLE_REDACTED}`],
  );
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.checks[0].nextAction.includes("/opt/phragma"), false);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.checks[1].next_action.includes("/home/opc"), false);
  assert.equal(bundle.endpoints.releaseAcceptanceStatus.data.checks[1].next_action.includes("release-secret"), false);
  assert.deepEqual(
    bundle.endpoints.releaseAcceptanceStatus.data.checks[1].next_command,
    ["go", "run", "./cmd/ngfwrelease", "record", "privileged-integration", "--token", SUPPORT_BUNDLE_REDACTED, `--evidence-dir=${SUPPORT_BUNDLE_REDACTED}`, "--", "make", "integration-test"],
  );
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/tmp/"), false);
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/var/lib/"), false);
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/etc/openngfw/"), false);
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/Users/"), false);
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/home/"), false);
  assert.equal(bundle.endpoints.audit.data.entries[0].detail.includes("/var/log/"), false);
  assert.match(bundle.endpoints.audit.data.entries[0].detail, /source='\[redacted\]'/);
  assert.match(bundle.endpoints.audit.data.entries[0].detail, /rollback_path='\[redacted\]'/);
  assert.match(bundle.endpoints.audit.data.entries[0].detail, /restored_rollback_path='\[redacted\]'/);

  const preview = supportBundlePreviewModel(bundle);
  assert.equal(preview.totals.sections, 11);
  assert.equal(preview.totals.failed, 0);
  assert.equal(preview.totals.contentPackageBlockers, 2);
  assert.ok(preview.totals.redactions >= 7);
  assert.equal(preview.failures.length, 0);
  assert.equal(preview.sections.find((section) => section.name === "highAvailabilityStatus").detail, "degraded · active-passive · active · sync degraded · failover planned");
  assert.equal(preview.sections.find((section) => section.name === "telemetryExportStatus").detail, "configured · vector active · sinks 2 · observed 1 · ClickHouse configured-unverified");
  assert.equal(preview.sections.find((section) => section.name === "contentPackages").detail, "2 packages");
  assert.equal(preview.sections.find((section) => section.name === "candidateStatus").detail, "dirty candidate · 3 changes · running v7");
  assert.equal(preview.sections.find((section) => section.name === "runtimeReadinessPreflight").detail, "Runtime warnings need acknowledgement · ack required · 1 item");
  assert.equal(preview.sections.find((section) => section.name === "releaseAcceptanceStatus").detail, "blocked · missing 6 · invalid 1 · not_applicable 1 · next actions 2 · next commands 1 · recordability blocked (6 dirty source paths)");
  assert.match(preview.redaction.title, /redaction marker/);

  const report = supportBundlePreviewReport(bundle);
  assert.match(report, /^OpenNGFW support bundle preview\n/);
  assert.match(report, /sections=included:11 failed:0 total:11/);
  assert.match(report, /runtime_readiness=operation:commit label:Runtime warnings need acknowledgement requires_ack:true items:1/);
  assert.match(report, /- Active\/passive HA status: included - degraded .* sync degraded .* failover planned/);
  assert.match(report, /- Runtime readiness preflight: included - Runtime warnings need acknowledgement .* ack required .* 1 item/);
  assert.match(report, /telemetry_export=state:configured enabled:true vector:active sinks:2 observed:1 clickhouse:configured-unverified warnings:1/);
  assert.match(report, /- Telemetry export status: included - configured .* vector active .* observed 1 .* ClickHouse configured-unverified/);
  assert.match(report, /release_acceptance=state:blocked ready:false manifest:missing missing:6 invalid:1 not_applicable:1 next_actions:2 next_commands:1/);
  assert.match(report, /recordability=ready:false problems:1 dirty_source_paths:6/);
  assert.match(report, /- Release acceptance: included - blocked .* recordability blocked \(6 dirty source paths\)/);
  assert.match(report, /Preview export does not create evidence/);
  for (const leaked of ["/Users/alice", "/opt/phragma", "/data/openngfw", "/tmp/content-import", "/var/lib/openngfw", "/etc/openngfw", "runtime-secret", "runtime-command-secret", "release-secret", "release-command-secret"]) {
    assert.equal(report.includes(leaked), false, `support bundle preview report leaked ${leaked}`);
  }
}

{
  const bundle = buildSupportBundle({
    collectedAt,
    browser: {},
    results: {
      runningPolicy: { status: "rejected", reason: { status: 403, message: "permission denied" } },
      identity: { status: "rejected", reason: { status: 401, message: "unauthenticated" } },
    },
  });

  assert.equal(bundle.summary.runningPolicyVersion, "unavailable");
  assert.equal(bundle.summary.candidateHasCandidate, false);
  assert.equal(bundle.summary.candidateDirty, false);
  assert.equal(bundle.summary.candidateChangeCount, 0);
  assert.deepEqual(bundle.summary.failedEndpoints, ["identity", "runningPolicy"]);

  const preview = supportBundlePreviewModel(bundle);
  assert.equal(preview.totals.sections, 2);
  assert.equal(preview.totals.failed, 2);
  assert.deepEqual(preview.failures.map((section) => section.name), ["runningPolicy", "identity"]);
  assert.match(preview.failure.detail, /Running policy: permission denied/);

  const report = supportBundlePreviewReport(bundle);
  assert.match(report, /sections=included:0 failed:2 total:2/);
  assert.match(report, /failed_endpoints=identity, runningPolicy/);
  assert.match(report, /- Running policy: failed - permission denied/);
}

{
  const name = supportBundleFilename(new Date(collectedAt));
  assert.match(name, /^phragma-support-2026-06-17T12-30-05-123Z\.json$/);
}

{
  const bundle = buildSupportBundle({
    collectedAt,
    browser: {},
    results: {
      status: { status: "fulfilled", value: {
        runtime: { version: "dev" },
        management: {
          oidcCookieSecure: true,
          authorization: "Bearer browser-token",
          oidcClientSecretFile: "/etc/openngfw/oidc-client-secret",
        },
      } },
      candidatePolicy: { status: "fulfilled", value: {
        policy: {
          vpn: {
            ipsecTunnels: [{ name: "site-a", pskFile: "/etc/openngfw/secrets/site-a.conf" }],
            wireguardInterfaces: [{ name: "wg0", privateKeyFile: "/etc/openngfw/keys/wg0.key", publicKey: "safe-public-key" }],
          },
        },
      } },
      identity: { status: "rejected", reason: { message: "Authorization: Bearer rejected-token token=also-secret" } },
    },
  });

  assert.equal(bundle.endpoints.status.data.runtime.version, "dev");
  assert.equal(bundle.endpoints.status.data.management.oidcCookieSecure, true);
  assert.equal(bundle.endpoints.status.data.management.authorization, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.status.data.management.oidcClientSecretFile, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.candidatePolicy.data.policy.vpn.ipsecTunnels[0].pskFile, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.candidatePolicy.data.policy.vpn.wireguardInterfaces[0].privateKeyFile, SUPPORT_BUNDLE_REDACTED);
  assert.equal(bundle.endpoints.candidatePolicy.data.policy.vpn.wireguardInterfaces[0].publicKey, "safe-public-key");
  assert.equal(bundle.endpoints.identity.error, `Authorization: Bearer ${SUPPORT_BUNDLE_REDACTED} token=${SUPPORT_BUNDLE_REDACTED}`);
}

{
  const redacted = redactSensitive({
    nested: [{ api_key: "secret-api-key" }],
    message: "Bearer inline-token password=hunter2 open /Users/alice/openngfw/state.db and /home/opc/.config/openngfw/config.yaml and /etc/openngfw/policy.yaml and /var/log/openngfw/controld.log",
    latestEntryHash: "abcd1234",
  });
  assert.equal(redacted.nested[0].api_key, SUPPORT_BUNDLE_REDACTED);
  assert.match(redacted.message, new RegExp(`Bearer ${escapeRegExp(SUPPORT_BUNDLE_REDACTED)} password=${escapeRegExp(SUPPORT_BUNDLE_REDACTED)}`));
  for (const leaked of ["inline-token", "hunter2", "/Users/", "/home/", "/etc/openngfw/", "/var/log/"]) {
    assert.equal(redacted.message.includes(leaked), false, `message leaked ${leaked}`);
  }
  assert.equal(redacted.latestEntryHash, "abcd1234");
}

{
  const redacted = redactSensitive({
    clickhouseUrl: "https://writer:hunter2@clickhouse.example:8443?access_token=secret-token&cluster=prod;key=other&public_key=safe",
    message: "failed to reach https://writer:hunter2@clickhouse.example:8443?cluster=prod;api_key=secret access_token=inline monkey=banana",
  });
  assert.equal(
    redacted.clickhouseUrl,
    `https://${SUPPORT_BUNDLE_REDACTED}@clickhouse.example:8443?access_token=${SUPPORT_BUNDLE_REDACTED}&cluster=prod;key=${SUPPORT_BUNDLE_REDACTED}&public_key=safe`,
  );
  assert.match(redacted.message, new RegExp(`https://${escapeRegExp(SUPPORT_BUNDLE_REDACTED)}@clickhouse\\.example:8443\\?cluster=prod;api_key=${escapeRegExp(SUPPORT_BUNDLE_REDACTED)}`));
  assert.match(redacted.message, new RegExp(`access_token=${escapeRegExp(SUPPORT_BUNDLE_REDACTED)}`));
  assert.match(redacted.message, /monkey=banana/);
  for (const leaked of ["writer", "hunter2", "secret-token", "api_key=secret", "access_token=inline"]) {
    assert.equal(redacted.message.includes(leaked), false, `message leaked ${leaked}`);
  }
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

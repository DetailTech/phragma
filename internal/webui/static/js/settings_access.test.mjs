import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  accessAdministrationModel,
  accessAdministrationUnavailable,
  accessAdminReadiness,
  accessAuditHash,
  accessGovernanceModel,
  accessGovernanceRows,
  accessGovernanceWorkflows,
  accessLifecycleReviewModel,
  accessLifecycleReviewText,
  accessRoleWorkflowMatrix,
  accessWorkflowAuditLinks,
  oidcPreflightEvidenceText,
  oidcPreflightModel,
  oidcRolloutInitialValues,
  oidcRolloutPlan,
  oidcRolloutPlanText,
  roleImpactPreview,
  samlRolloutPlan,
  samlRolloutPlanText,
  summarizeCapabilities,
} from "./access_governance.js";

const settingsViewSource = readFileSync(new URL("./views/settings.js", import.meta.url), "utf8");
const appCSS = readFileSync(new URL("../css/app.css", import.meta.url), "utf8");
const apiSource = readFileSync(new URL("./api.js", import.meta.url), "utf8");
assert.match(settingsViewSource, /class: "note settings-access-browser-sso-note"/);
assert.match(appCSS, /\.card > \.note\.settings-access-browser-sso-note \{[\s\S]*?overflow: visible;[\s\S]*?-webkit-line-clamp: unset;/);
const {
  accessFieldEvidenceArtifactStatus,
  accessFieldEvidenceCertificationModel,
  accessFieldEvidenceCertificationPacket,
  accessFieldEvidenceCertificationText,
  accessFieldEvidenceParseImport,
} = settingsAccessFieldEvidenceHelpers(settingsViewSource);

function settingsAccessFieldEvidenceHelpers(source) {
  const start = source.indexOf("function accessActiveBrowserSessionCount");
  const end = source.indexOf("function exportAccessFieldEvidenceCertification");
  assert.ok(start > 0 && end > start, "field-evidence helper source block should be loadable");
  const helperSource = source.slice(start, end).replaceAll("export function", "function");
  return Function("redactedAccessPacket", "settingsPanelHash", "sanitizeDrawerText", `${helperSource}
return { accessFieldEvidenceArtifactStatus, accessFieldEvidenceCertificationModel, accessFieldEvidenceCertificationPacket, accessFieldEvidenceCertificationText, accessFieldEvidenceParseImport };`)(
    (packet) => packet,
    () => "#/settings?panel=access",
    (value) => String(value || "").replace(/\b(bearer|token|secret|cookie|samlresponse|relaystate)\b/gi, "[redacted]"),
  );
}
assert.match(settingsViewSource, /function oidcPreflightInvestigationHandoffPacket/);
assert.match(settingsViewSource, /function pinOIDCPreflightEvidence/);
assert.match(settingsViewSource, /oidcPreflightEvidencePacket/);
assert.match(settingsViewSource, /settingsPanelHash\("access"\)/);
assert.match(settingsViewSource, /data-access-action": "configure-oidc"/);
assert.match(settingsViewSource, /data-access-action": "prepare-saml"/);
assert.match(settingsViewSource, /data-access-action": "access-lifecycle-review"/);
assert.match(settingsViewSource, /type: "button", title: "Open access lifecycle review"/);
assert.match(settingsViewSource, /data-access-action": "field-evidence-certification"/);
assert.match(settingsViewSource, /type: "button", title: "Open OIDC\/SAML field evidence handoff"/);
assert.match(settingsViewSource, /function openAccessFieldEvidenceCertification/);
assert.match(settingsViewSource, /function accessFieldEvidenceCertificationModel/);
assert.match(settingsViewSource, /function accessOIDCFieldEvidenceProtocol/);
assert.match(settingsViewSource, /function accessSAMLFieldEvidenceProtocol/);
assert.match(settingsViewSource, /function accessFieldEvidenceCertificationBody/);
assert.match(settingsViewSource, /function accessFieldEvidenceCertificationText/);
assert.match(settingsViewSource, /function accessFieldEvidenceImportPanel/);
assert.match(settingsViewSource, /function accessFieldEvidenceParseImport/);
assert.match(settingsViewSource, /function accessFieldEvidenceProtocolWithInventory/);
assert.match(settingsViewSource, /function accessFieldEvidenceArtifactInventory/);
assert.match(settingsViewSource, /function accessFieldEvidenceArtifactStatus/);
assert.match(settingsViewSource, /function accessFieldEvidenceHasUnsafeMaterial/);
assert.match(settingsViewSource, /function accessFieldEvidenceObservedFields/);
assert.match(settingsViewSource, /function accessFieldEvidenceProtocolFacts/);
assert.match(settingsViewSource, /function accessFieldEvidenceFactsTable/);
assert.match(settingsViewSource, /function accessFieldEvidenceStatusValue/);
assert.match(settingsViewSource, /function accessFieldEvidenceBucketStatus/);
assert.match(settingsViewSource, /function copyAccessFieldEvidenceCertification/);
assert.match(settingsViewSource, /function exportAccessFieldEvidenceCertification/);
assert.match(settingsViewSource, /function pinAccessFieldEvidenceCertification/);
assert.match(settingsViewSource, /openngfw\.access\.field-evidence-certification\.v1/);
assert.match(settingsViewSource, /operator-evidence-required/);
assert.match(settingsViewSource, /field-run-evidence-complete/);
assert.match(settingsViewSource, /fieldRunEvidenceComplete/);
assert.match(settingsViewSource, /fieldRunCertification: fieldRunEvidenceComplete \? "certified-by-evidence" : "not-certified"/);
assert.match(settingsViewSource, /externalCertification: "not-certified"/);
assert.match(settingsViewSource, /certified-by-evidence means the required redacted field-run artifact packet parsed cleanly/);
assert.match(settingsViewSource, /not certified/);
assert.match(settingsViewSource, /No real IdP run is certified by this browser-generated packet/);
assert.match(settingsViewSource, /does not claim that an OIDC or SAML provider run has happened/);
assert.match(settingsViewSource, /docs\/testing-plan\.md M5 OIDC\/SAML provider field evidence/);
assert.match(settingsViewSource, /fieldEvidenceArtifacts/);
assert.match(settingsViewSource, /data-access-field-evidence-importer/);
assert.match(settingsViewSource, /data-access-field-evidence-import": "oidc"/);
assert.match(settingsViewSource, /data-access-field-evidence-import": "saml"/);
assert.match(settingsViewSource, /data-access-field-evidence-action": "review-import"/);
assert.match(settingsViewSource, /type: "button", title: "Review imported OIDC\/SAML field evidence packet"/);
assert.match(settingsViewSource, /Raw pasted text stays in this browser pass and is not copied, exported, or pinned/);
assert.match(settingsViewSource, /requiredSentinel: "status=passed"/);
assert.match(settingsViewSource, /status=passed sentinel present/);
assert.match(settingsViewSource, /missing artifact; status=passed sentinel not observed/);
assert.match(settingsViewSource, /stale-artifacts/);
assert.match(settingsViewSource, /unsafe-artifacts/);
assert.match(settingsViewSource, /data-access-field-evidence-artifact-state/);
assert.match(settingsViewSource, /data-access-field-evidence-status-parser/);
assert.match(settingsViewSource, /data-access-field-evidence-facts/);
assert.match(settingsViewSource, /data-access-field-evidence-fact/);
assert.match(settingsViewSource, /data-access-field-evidence-action": "copy"/);
assert.match(settingsViewSource, /data-access-field-evidence-action": "export"/);
assert.match(settingsViewSource, /data-access-field-evidence-action": "pin"/);
assert.match(settingsViewSource, /type: "button", title: "Copy OIDC\/SAML field evidence checklist"/);
assert.match(settingsViewSource, /type: "button", title: "Export OIDC\/SAML field evidence JSON"/);
assert.match(settingsViewSource, /type: "button", title: "Pin OIDC\/SAML field evidence handoff to investigation case"/);
assert.match(settingsViewSource, /release\/field-evidence\/oidc/);
assert.match(settingsViewSource, /release\/field-evidence\/saml/);
assert.match(settingsViewSource, /make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release\/field-evidence\/oidc/);
assert.match(settingsViewSource, /make release-evidence-m5-oidc-field-evidence OIDC_FIELD_EVIDENCE_DIR=release\/field-evidence\/oidc/);
assert.match(settingsViewSource, /make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release\/field-evidence\/saml/);
assert.match(settingsViewSource, /make release-evidence-m5-saml-field-evidence SAML_FIELD_EVIDENCE_DIR=release\/field-evidence\/saml/);
assert.match(settingsViewSource, /provider\/issuer-client-discovery\.txt/);
assert.match(settingsViewSource, /provider\/id-token-validation\.txt/);
assert.match(settingsViewSource, /deployment\/public-callback\.txt/);
assert.match(settingsViewSource, /deployment\/client-secret-file-permissions\.txt/);
assert.match(settingsViewSource, /browser\/missing-state-rejection\.txt/);
assert.match(settingsViewSource, /browser\/session-cookie\.txt/);
assert.match(settingsViewSource, /browser\/step-up-proof\.txt/);
assert.match(settingsViewSource, /lifecycle\/disable-rollback-proof\.txt/);
assert.match(settingsViewSource, /browser\/reused-state-rejection\.txt/);
assert.match(settingsViewSource, /browser\/nonce-mismatch-rejection\.txt/);
assert.match(settingsViewSource, /browser\/pkce-exchange-failure\.txt/);
assert.match(settingsViewSource, /browser\/operator-mutation-with-csrf\.txt/);
assert.match(settingsViewSource, /browser\/missing-csrf-rejection\.txt/);
assert.match(settingsViewSource, /browser\/cross-origin-rejection\.txt/);
assert.match(settingsViewSource, /browser\/viewer-mutation-denial\.txt/);
assert.match(settingsViewSource, /browser\/logout-invalidation\.txt/);
assert.match(settingsViewSource, /provider\/idp-metadata\.txt/);
assert.match(settingsViewSource, /provider\/sp-metadata\.txt/);
assert.match(settingsViewSource, /deployment\/public-acs\.txt/);
assert.match(settingsViewSource, /browser\/login-redirect\.txt/);
assert.match(settingsViewSource, /browser\/assertion-session-cookie\.txt/);
assert.match(settingsViewSource, /ACS URL/);
assert.match(settingsViewSource, /Provider URL \/ issuer/);
assert.match(settingsViewSource, /Provider URL \/ IdP entity/);
assert.match(settingsViewSource, /Role claim \/ group mapping/);
assert.match(settingsViewSource, /Session proof/);
assert.match(settingsViewSource, /Step-up proof/);
assert.match(settingsViewSource, /Disable \/ rollback proof/);
assert.match(settingsViewSource, /browser\/invalid-signature-rejection\.txt/);
assert.match(settingsViewSource, /browser\/replayed-assertion-rejection\.txt/);
assert.match(settingsViewSource, /browser\/missing-relaystate-rejection\.txt/);
assert.match(settingsViewSource, /rbac\/role-mapping\.txt/);
assert.match(settingsViewSource, /redaction\/identity-redacted\.txt/);
assert.match(settingsViewSource, /redaction\/audit-log-redacted\.txt/);
assert.match(settingsViewSource, /redaction\/support-bundle-redacted\.txt/);
assert.match(settingsViewSource, /field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction/);
assert.match(settingsViewSource, /"status=passed"/);
assert.match(settingsViewSource, /oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac/);
assert.match(settingsViewSource, /oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial/);
assert.match(settingsViewSource, /required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation/);
assert.match(settingsViewSource, /required_step_up_evidence=browser-step-up-proof/);
assert.match(settingsViewSource, /required_disable_rollback_evidence=provider-disable,session-invalidation,break-glass-fallback/);
assert.match(settingsViewSource, /redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf/);
assert.match(settingsViewSource, /field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction/);
assert.match(settingsViewSource, /saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac/);
assert.match(settingsViewSource, /saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial/);
assert.match(settingsViewSource, /required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation/);
assert.match(settingsViewSource, /redaction_scan=saml-response,relaystate,assertion,x509,private-key,cookie,csrf/);
assert.match(settingsViewSource, /redactionChecklist: \["cookies", "authorization codes", "provider tokens", "ID tokens", "refresh tokens", "client secrets"/);
assert.match(settingsViewSource, /redactionChecklist: \["SAMLResponse", "RelayState", "assertions", "X\.509 certificate bodies", "X\.509 private keys", "session cookies", "CSRF tokens"/);
assert.match(settingsViewSource, /Real-provider field-evidence handoff; not certified/);
assert.match(settingsViewSource, /Redacted OIDC\/SAML field-evidence checklist copied as plain text; this is not certification/);
assert.match(settingsViewSource, /kind: "access-field-evidence-certification"/);
assert.match(settingsViewSource, /claim: model\.fieldRunCertification \|\| "not-certified"/);
assert.match(settingsViewSource, /externalCertification: model\.externalCertification \|\| "not-certified"/);
assert.match(settingsViewSource, /type: "button", title: "Create local user"/);
assert.match(settingsViewSource, /type: "button", title: `Change role for \$\{user\.name\}`/);
assert.match(settingsViewSource, /type: "button", title: `Rotate token for \$\{user\.name\}`/);
assert.match(settingsViewSource, /type: "button", title: `Disable local user \$\{user\.name\}`/);
assert.match(settingsViewSource, /type: "button", title: `Revoke browser SSO session for \$\{session\.actor\}`/);
assert.match(settingsViewSource, /"data-access-session": session\.sessionFingerprint \|\| session\.sessionId/);
assert.match(settingsViewSource, /const ruleLabel = rule\.name \|\| `rule \$\{idx \+ 1\}`/);
assert.match(settingsViewSource, /type: "button", title: "Edit host-input rule", "aria-label": `Edit host-input rule \$\{ruleLabel\}`/);
assert.match(settingsViewSource, /type: "button", title: "Delete host-input rule", "aria-label": `Delete host-input rule \$\{ruleLabel\}`/);
assert.match(settingsViewSource, /data-access-lifecycle-action": "copy"/);
assert.match(settingsViewSource, /data-access-lifecycle-action": "copy-route"/);
assert.match(settingsViewSource, /data-access-lifecycle-action": "export"/);
assert.match(settingsViewSource, /data-access-lifecycle-action": "pin"/);
assert.match(settingsViewSource, /data-access-lifecycle-action": "close"/);
assert.match(settingsViewSource, /type: "button", title: "Copy access lifecycle review"/);
assert.match(settingsViewSource, /type: "button", title: "Copy Access settings route"/);
assert.match(settingsViewSource, /type: "button", title: "Export access lifecycle review JSON"/);
assert.match(settingsViewSource, /type: "button", title: "Pin access lifecycle review to investigation case"/);
assert.match(settingsViewSource, /function accessLifecycleHandoffPanel/);
assert.match(settingsViewSource, /function accessLifecycleHandoffs/);
assert.match(settingsViewSource, /data-access-lifecycle-handoffs": "true"/);
assert.match(settingsViewSource, /data-access-lifecycle-handoff": item\.id/);
assert.match(settingsViewSource, /function accessLifecycleReviewCopyText/);
assert.match(settingsViewSource, /function copyAccessLifecycleRoute/);
assert.match(settingsViewSource, /settingsPanelURL\("access", "\/settings", globalThis\.location\)/);
assert.match(settingsViewSource, /source: \{ interface: "webui", route: settingsPanelHash\("access"\) \}/);
assert.match(settingsViewSource, /handoffs: accessLifecycleHandoffs\(review\)/);
assert.match(settingsViewSource, /evidence: accessLifecycleReviewCopyText\(review\)\.split\("\\n"\)/);
assert.match(settingsViewSource, /Operator handoffs:/);
assert.match(settingsViewSource, /Step-up authentication and production identity custody are hardening items/);
assert.match(settingsViewSource, /Credential inventory custody and secret-manager proof remain hardening/);
assert.match(settingsViewSource, /phragma\.access\.lifecycle-review\.v1/);
assert.match(settingsViewSource, /data-access-field": "saml-metadata-url"/);
assert.match(settingsViewSource, /openngfw\.saml-rollout\.v1/);
assert.match(settingsViewSource, /function copySAMLRolloutPlan/);
assert.match(settingsViewSource, /function exportSAMLRolloutPlan/);
assert.match(settingsViewSource, /function pinSAMLRolloutPlan/);
assert.match(settingsViewSource, /Browser SSO session/);
assert.match(settingsViewSource, /Revoke browser SSO session\?/);
assert.doesNotMatch(settingsViewSource, /Activation remains blocked until the SAML browser login\/session runtime exists/);
assert.doesNotMatch(settingsViewSource, /Revoke OIDC session\?/);
assert.match(settingsViewSource, /data-access-submit": "validate-saml"/);
assert.match(settingsViewSource, /data-access-action": "close-saml-rollout"/);
assert.match(settingsViewSource, /type: "button", title: "Validate SAML metadata packet"/);
assert.match(settingsViewSource, /data-access-field": "saml-audit-comment"/);
assert.match(settingsViewSource, /data-access-submit": "save-saml-provider"/);
assert.match(settingsViewSource, /type: "button", title: "Save SAML provider"/);
assert.match(settingsViewSource, /data-access-action": "disable-saml-provider"/);
assert.match(settingsViewSource, /type: "button", title: "Disable SAML provider"/);
assert.match(settingsViewSource, /title: "Copy SAML rollout packet"/);
assert.match(settingsViewSource, /title: "Export SAML rollout packet JSON"/);
assert.match(settingsViewSource, /title: "Pin SAML rollout packet to investigation case"/);
assert.match(settingsViewSource, /data-access-action": "test-saml-login-unavailable"/);
assert.match(settingsViewSource, /api\.setSAMLProviderConfig/);
assert.match(settingsViewSource, /api\.disableSAMLProvider/);
assert.match(settingsViewSource, /SAML provider saved/);
assert.match(settingsViewSource, /Disable SAML provider\?/);
assert.match(settingsViewSource, /data-access-field": "oidc-issuer"/);
assert.match(settingsViewSource, /data-access-field": "oidc-audit-comment"/);
assert.match(settingsViewSource, /data-access-submit": "validate-oidc"/);
assert.match(settingsViewSource, /data-access-action": "close-oidc-rollout"/);
assert.match(settingsViewSource, /type: "button", title: "Validate OIDC rollout plan"/);
assert.match(settingsViewSource, /data-access-submit": "save-oidc-provider"/);
assert.match(settingsViewSource, /type: "button", title: "Save OIDC provider"/);
assert.match(settingsViewSource, /data-access-action": "disable-oidc-provider"/);
assert.match(settingsViewSource, /type: "button", title: "Disable OIDC provider"/);
assert.match(settingsViewSource, /title: "Copy OIDC rollout plan"/);
assert.match(settingsViewSource, /title: "Export OIDC rollout plan JSON"/);
assert.match(settingsViewSource, /title: "Pin OIDC rollout plan to investigation case"/);
assert.match(settingsViewSource, /title: "Run OIDC browser preflight"/);
assert.match(settingsViewSource, /data-access-action": "pin-oidc-preflight"/);
assert.match(settingsViewSource, /data-access-action": "copy-oidc-preflight"/);
assert.match(settingsViewSource, /data-access-action": "export-oidc-preflight"/);
assert.match(settingsViewSource, /data-access-action": "sign-in-oidc-preflight"/);
assert.match(settingsViewSource, /data-access-action": "close-oidc-preflight"/);
assert.match(settingsViewSource, /accessBreakglassPanel/);
assert.match(settingsViewSource, /data-access-action": "rotate-breakglass"/);
assert.match(settingsViewSource, /function openBreakGlassRotation/);
assert.match(settingsViewSource, /function openCreateBreakGlassAdmin/);
assert.match(settingsViewSource, /type: "button", title: "Create break-glass admin"/);
assert.match(settingsViewSource, /type: "button", title: `Update role for \$\{user\.name\}`/);
assert.match(settingsViewSource, /type: "button", title: `Rotate break-glass credential for \$\{user\.name\}`/);
assert.match(settingsViewSource, /openngfw\.breakglass-token\.v1/);
assert.match(settingsViewSource, /tokenStoredInInventory: false/);
assert.match(settingsViewSource, /data-access-action": "copy-breakglass-evidence"/);
assert.match(settingsViewSource, /data-access-action": "export-breakglass-evidence"/);
assert.match(settingsViewSource, /data-access-action": "pin-breakglass-evidence"/);
assert.match(settingsViewSource, /data-access-action": "copy-one-time-token"/);
assert.match(settingsViewSource, /data-access-action": "close-token-result"/);
assert.match(settingsViewSource, /type: "button", title: "Copy break-glass evidence"/);
assert.match(settingsViewSource, /type: "button", title: "Export break-glass evidence JSON"/);
assert.match(settingsViewSource, /type: "button", title: "Pin break-glass evidence to investigation case"/);
assert.match(settingsViewSource, /function oidcRolloutPacket/);
assert.match(settingsViewSource, /function redactedAccessPacket/);
assert.match(settingsViewSource, /function oidcProviderConfigFromRolloutValues\(values = \{\}, existing = \{\}\)/);
assert.match(settingsViewSource, /oidcProviderConfigFromRolloutValues\(currentValues\(\), oidc\)/);
assert.match(settingsViewSource, /if \(!config\.clientSecretFile && existing\?\.clientSecretFileConfigured\) delete config\.clientSecretFile/);
assert.match(settingsViewSource, /return redactedAccessPacket\(\{/);
assert.match(settingsViewSource, /const packet = redactedAccessPacket\(evidence\);\n  const blob = new Blob\(\[JSON\.stringify\(packet, null, 2\)\]/);
assert.match(settingsViewSource, /await refreshAccessAdministration\(opts\);\n    toast\("Session revoked"/);
assert.match(settingsViewSource, /width: "min\(860px, 96vw\)"/);
assert.match(settingsViewSource, /class: "btn ghost", type: "button", disabled: true, "aria-disabled": "true", title: "SAML browser login\/session runtime is not active\."/);
assert.match(settingsViewSource, /function oidcProviderConfigFromRolloutValues/);
assert.match(settingsViewSource, /function normalizeOIDCConfiguredSecretPlan/);
assert.match(settingsViewSource, /clientSecretFile: "\[configured\]"/);
assert.match(settingsViewSource, /No client secret file is set/);
assert.match(settingsViewSource, /function accessAdministrationWithOIDCConfig/);
assert.match(settingsViewSource, /api\.oidcProviderConfig\(\)/);
assert.match(apiSource, /oidcProviderConfig/);
assert.match(apiSource, /validateOIDCProviderConfig/);
assert.match(apiSource, /setOIDCProviderConfig/);
assert.match(apiSource, /disableOIDCProvider/);
assert.match(apiSource, /samlProviderConfig/);
assert.match(apiSource, /validateSAMLProviderConfig/);
assert.match(apiSource, /setSAMLProviderConfig/);
assert.match(apiSource, /disableSAMLProvider/);

{
  const rows = accessGovernanceRows("viewer");
  assert.equal(rows.find((row) => row.id === "read").allowed, true);
  assert.equal(rows.find((row) => row.id === "stage").allowed, false);
  assert.equal(rows.find((row) => row.id === "packet-capture").allowed, false);
  assert.equal(rows.find((row) => row.id === "content-install").allowed, false);
  assert.equal(rows.find((row) => row.id === "access-admin").allowed, false);
}

{
  const rows = accessGovernanceRows("operator");
  assert.equal(rows.find((row) => row.id === "read").allowed, true);
  assert.equal(rows.find((row) => row.id === "commit").allowed, true);
  assert.equal(rows.find((row) => row.id === "rollback").allowed, true);
  assert.equal(rows.find((row) => row.id === "host-tune").allowed, false);
  assert.equal(rows.find((row) => row.id === "content-rollback").allowed, false);
  assert.equal(rows.find((row) => row.id === "access-admin").allowed, false);
}

{
  const rows = accessGovernanceRows("admin");
  assert.equal(rows.every((row) => row.allowed), true);
}

{
  const model = oidcPreflightModel({
    schemaVersion: "openngfw.oidc-preflight.v1",
    generatedAt: "2026-06-19T12:00:00Z",
    state: "blocked",
    label: "1 blocker",
    detail: "OIDC browser SSO preflight has blockers before production rollout.",
    oidc: {
      enabled: true,
      issuer: "https://idp.example.com",
      clientId: "openngfw-web",
      roleClaim: "groups",
      defaultRole: "viewer",
      cookieSecure: false,
      scopes: ["openid", "profile", "email"],
      trustedProxyCidrs: ["10.0.0.0/8"],
      sessionTtlSeconds: 3600,
    },
    checks: [
      {
        id: "session-cookie",
        label: "Session cookie",
        state: "blocked",
        class: "bad",
        detail: "OIDC browser sessions are not using Secure cookies.",
        evidence: "cookie=super-secret; id_token=eyJaaa.bbb.ccc",
        nextAction: "Enable Secure cookies before exposing browser SSO.",
      },
      {
        id: "provider-discovery",
        label: "Provider discovery",
        state: "ready",
        class: "ok",
        detail: "Provider discovery and signing-key metadata loaded successfully.",
        evidence: "OpenID Connect discovery document loaded.",
        nextAction: "Keep issuer DNS and TLS reachable from the firewall.",
      },
    ],
    blockers: ["session_id=oidc-session-sha256:abcdef0123456789"],
    warnings: [],
    evidence: ["client_secret=topsecret", "Provider advertised and served JWKS metadata."],
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.cls, "bad");
  assert.equal(model.oidc.cookieSecure, false);
  assert.equal(model.checks.find((check) => check.id === "session-cookie").evidence, "cookie=[redacted]; id_token=[redacted]");
  assert.equal(model.blockers[0].label, "session_id=[redacted]");
  assert.equal(model.evidence[0], "client_secret=[redacted]");
  const text = oidcPreflightEvidenceText(model);
  assert.match(text, /OIDC preflight: blocked/);
  assert.doesNotMatch(text, /topsecret|super-secret|oidc-session-sha256:abcdef|eyJaaa/);
}

{
  const model = oidcPreflightModel({
    state: "blocked",
    checks: [
      {
        id: "callback",
        label: "Callback",
        state: "blocked",
        class: "bad",
        detail: "Redirect included code%3Dabc123 and session_id%3Doidc-session-sha256:abcdef0123456789abcdef0123456789",
        evidence: "https://fw.example.com/v1/auth/oidc/callback?code%3Dsecret-code&session_id%3Doidc-session-sha256:abcdef0123456789abcdef0123456789",
        nextAction: "Clear cookie%3Dsession-cookie before retry.",
      },
    ],
    blockers: ["session_id%3Doidc-session-sha256:abcdef0123456789abcdef0123456789"],
    evidence: ["access_token%3Dtopsecret", "id_token=eyJaaa.bbb.ccc"],
  });
  const text = oidcPreflightEvidenceText(model);
  assert.doesNotMatch(text, /secret-code|topsecret|session-cookie|oidc-session-sha256:abcdef|eyJaaa/);
  assert.match(text, /code=\[redacted\]/);
  assert.match(text, /session_id=\[redacted\]/);
  assert.match(text, /access_token=\[redacted\]/);
}

{
  const preview = roleImpactPreview("viewer", "operator");
  assert.equal(preview.direction, "escalation");
  assert.equal(preview.cls, "ok");
  assert.deepEqual(preview.gained.map((row) => row.id), ["stage", "commit", "rollback"]);
  assert.equal(preview.lost.length, 0);
  assert.equal(preview.allowed.some((row) => row.id === "read"), true);
}

{
  const enabled = oidcRolloutInitialValues({
    enabled: true,
    issuer: "https://idp.example.com",
    clientId: "phragma-web-tablet",
    redirectUrl: "https://fw.example.com/v1/auth/oidc/callback",
    roleClaim: "groups",
    defaultRole: "operator",
    scopes: ["openid", "profile", "email"],
    trustedProxyCidrs: ["10.0.0.0/8"],
    clientSecretFileConfigured: true,
  });
  assert.equal(enabled.issuer, "https://idp.example.com");
  assert.equal(enabled.clientId, "phragma-web-tablet");
  assert.equal(enabled.redirectUrl, "https://fw.example.com/v1/auth/oidc/callback");
  assert.equal(enabled.roleClaim, "groups");
  assert.equal(enabled.defaultRole, "operator");
  assert.equal(enabled.scopes, "openid,profile,email");
  assert.equal(enabled.trustedProxyCidrs, "10.0.0.0/8");
  assert.equal(enabled.clientSecretFile, "");
  assert.match(enabled.clientSecretFilePlaceholder, /configured/);

  const disabled = oidcRolloutInitialValues({
    enabled: false,
    issuer: "https://idp.example.com",
    clientId: "phragma-web-tablet",
    redirectUrl: "https://fw.example.com/v1/auth/oidc/callback",
    roleClaim: "groups",
    defaultRole: "operator",
    scopes: ["openid", "profile", "email"],
    trustedProxyCidrs: ["10.0.0.0/8"],
    clientSecretFileConfigured: true,
  });
  assert.equal(disabled.issuer, "");
  assert.equal(disabled.clientId, "");
  assert.equal(disabled.redirectUrl, "");
  assert.equal(disabled.roleClaim, "role");
  assert.equal(disabled.defaultRole, "viewer");
  assert.equal(disabled.scopes, "openid,profile,email");
  assert.equal(disabled.trustedProxyCidrs, "");
  assert.equal(disabled.clientSecretFile, "");
  assert.doesNotMatch(disabled.clientSecretFilePlaceholder, /configured/);
}

{
  const administration = accessAdministrationModel(
    { authEnabled: true },
    { enabled: false },
    {
      authEnabled: true,
      localUsers: [],
      oidc: {
        enabled: true,
        issuer: "https://idp.example.com",
        clientId: "phragma-web",
        redirectUrl: "https://fw.example.com/v1/auth/oidc/callback",
        roleClaim: "groups",
        defaultRole: "viewer",
        scopes: ["openid", "profile"],
        trustedProxyCidrs: ["10.0.0.0/8"],
        clientSecretFileConfigured: true,
      },
      sessions: {},
      breakGlass: { state: "ready" },
      blockers: [],
    },
  );
  assert.equal(administration.oidc.enabled, true);
  assert.equal(administration.oidc.redirectUrl, "https://fw.example.com/v1/auth/oidc/callback");
  assert.equal(administration.oidc.clientSecretFileConfigured, true);
  assert.equal(administration.oidc.rows.some((row) => row.label === "Client secret file" && row.value === "configured"), true);
}

{
  const administration = accessAdministrationModel(
    { authEnabled: true },
    { enabled: false },
    {
      authEnabled: true,
      localUsers: [{ name: "breakglass", role: "admin", authSource: "local", tokenMaterial: "hashed", editable: true, enabled: true }],
      oidc: { enabled: false },
      sessions: { sessionRevocationAvailable: false },
      breakGlass: { state: "ready", detail: "Local admin available.", nextAction: "Rotate quarterly." },
      blockers: [],
    },
  );
  const plan = oidcRolloutPlan({
    issuer: "https://idp.example.com/",
    clientId: "phragma-web",
    redirectUrl: "https://fw.example.com/v1/auth/oidc/callback",
    roleClaim: "groups",
    defaultRole: "viewer",
    scopes: "openid,profile,email",
    trustedProxyCidrs: "10.0.0.0/8, 192.0.2.0/24",
    clientSecretFile: "/etc/openngfw/oidc-client-secret",
  }, administration, { enabled: false });
  assert.equal(plan.state, "ready");
  assert.equal(plan.cls, "ok");
  assert.equal(plan.breakGlassReady, true);
  assert.equal(plan.localAdminCount, 1);
  assert.equal(plan.values.issuer, "https://idp.example.com");
  assert.deepEqual(plan.values.scopes, ["openid", "profile", "email"]);
  assert.match(plan.command, /--oidc-issuer https:\/\/idp\.example\.com/);
  assert.match(plan.command, /\[server-local path redacted\]/);
  assert.match(plan.systemdDropIn, /PHRAGMA_OIDC_ARGS/);
  const text = oidcRolloutPlanText(plan);
  assert.match(text, /OIDC rollout plan: ready/);
  assert.match(text, /break_glass_local_admins=1/);
  assert.doesNotMatch(text, /\/etc\/openngfw|client_secret=.*secret/i);

  const loopbackPlan = oidcRolloutPlan({
    issuer: "http://127.0.0.1:4180/",
    clientId: "phragma-web",
    redirectUrl: "http://127.0.0.1/v1/auth/oidc/callback",
    roleClaim: "groups",
    defaultRole: "viewer",
    scopes: "openid,profile,email",
    trustedProxyCidrs: "10.0.0.0/8",
    clientSecretFile: "/tmp/openngfw-oidc-client-secret",
  }, administration, { enabled: false });
  assert.equal(loopbackPlan.state, "review");
  assert.equal(loopbackPlan.breakGlassReady, true);
  assert.deepEqual(loopbackPlan.blockers, []);
  assert.match(loopbackPlan.warnings.join("\n"), /Loopback HTTP issuer/);
}

{
  const administration = accessAdministrationModel(
    { authEnabled: true },
    { enabled: true },
    {
      authEnabled: true,
      localUsers: [{ name: "breakglass", role: "admin", authSource: "local", tokenMaterial: "hashed", editable: true, enabled: true }],
      oidc: { enabled: true, issuer: "https://idp.example.com", defaultRole: "viewer" },
      sessions: { sessionRevocationAvailable: true },
      breakGlass: { state: "ready", detail: "Local admin available.", nextAction: "Rotate quarterly." },
      blockers: [],
    },
  );
  assert.equal(administration.saml.label, "not configured");
  assert.equal(administration.saml.cls, "warn");
  const readiness = accessAdminReadiness({ authEnabled: true }, { role: "admin" }, { enabled: true }, administration);
  assert.equal(readiness.items.some((item) => item.id === "saml-lifecycle" && item.status === "not configured"), true);
  const plan = samlRolloutPlan({
    idpEntityId: "https://idp.example.com/saml",
    metadataUrl: "https://idp.example.com/metadata?client_secret=topsecret",
    ssoUrl: "https://idp.example.com/sso?access_token=topsecret",
    spEntityId: "https://fw.example.com/ui",
    acsUrl: "https://fw.example.com/v1/auth/saml/acs",
    roleAttribute: "groups",
    defaultRole: "viewer",
    certificateFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  }, administration);
  assert.equal(plan.state, "ready");
  assert.equal(plan.breakGlassReady, true);
  assert.equal(plan.blockers.length, 0);
  assert.match(plan.command, /ngfwctl access saml provider validate/);
  const text = samlRolloutPlanText(plan);
  assert.match(text, /SAML rollout plan: ready/);
  assert.match(text, /acs_url=https:\/\/fw\.example\.com\/v1\/auth\/saml\/acs/);
  assert.doesNotMatch(text, /\/etc\/|topsecret|0123456789abcdef/i);
}

{
  const plan = oidcRolloutPlan({
    issuer: "http://idp.example.com",
    clientId: "",
    redirectUrl: "http://fw.example.com/wrong",
    defaultRole: "admin",
    scopes: "profile,email",
    clientSecretFile: "/etc/openngfw/oidc-client-secret client_secret=topsecret",
  }, accessAdministrationModel(
    { authEnabled: true },
    { enabled: false },
    { authEnabled: true, localUsers: [], oidc: { enabled: false }, sessions: {}, breakGlass: { state: "missing" }, blockers: [] },
  ), {});
  assert.equal(plan.state, "blocked");
  assert.equal(plan.cls, "bad");
  assert.equal(plan.breakGlassReady, false);
  assert.ok(plan.blockers.some((item) => /break-glass/.test(item)));
  assert.ok(plan.blockers.some((item) => /Client ID/.test(item)));
  assert.ok(plan.blockers.some((item) => /openid/.test(item)));
  assert.ok(plan.warnings.some((item) => /Default admin role/.test(item)));
  const text = oidcRolloutPlanText(plan);
  assert.doesNotMatch(text, /topsecret/);
  assert.match(text, /client_secret=\[redacted\]/);
  assert.doesNotMatch(text, /\/etc\/openngfw/);
}

{
  const preview = roleImpactPreview("operator", "admin");
  assert.equal(preview.direction, "escalation");
  assert.deepEqual(preview.gained.map((row) => row.id), ["host-tune", "packet-capture", "content-install", "content-rollback", "access-admin"]);
  assert.equal(preview.lost.length, 0);
  assert.equal(preview.restricted.length, 0);
}

{
  const preview = roleImpactPreview("admin", "viewer");
  assert.equal(preview.direction, "demotion");
  assert.equal(preview.cls, "bad");
  assert.equal(preview.gained.length, 0);
  assert.deepEqual(preview.lost.map((row) => row.id), ["stage", "commit", "rollback", "host-tune", "packet-capture", "content-install", "content-rollback", "access-admin"]);
  assert.deepEqual(preview.allowed.map((row) => row.id), ["read"]);
}

{
  const preview = roleImpactPreview("admin", "root");
  assert.equal(preview.direction, "invalid");
  assert.equal(preview.targetKnown, false);
  assert.equal(preview.allowed.length, 0);
  assert.equal(preview.restricted.length, accessGovernanceWorkflows().length);
  assert.match(preview.detail, /Unknown roles are treated as restricted/);
}

{
  const model = accessGovernanceModel(
    { authEnabled: true },
    { actor: "alice@example.com", role: "operator", authSource: "oidc-session", capabilities: ["read", "write", "read"] },
    { enabled: true, authenticated: true, csrf_token: "csrf" },
  );
  assert.equal(model.actor, "alice@example.com");
  assert.equal(model.role, "operator");
  assert.equal(model.capabilitiesLabel, "read, write");
  assert.equal(model.sessionLabel, "OIDC active");
  assert.equal(model.csrfLabel, "CSRF ready");
  assert.equal(model.capabilitySummary.canRead, true);
  assert.equal(model.capabilitySummary.canWrite, true);
  assert.equal(model.capabilitySummary.canAdmin, false);
  assert.equal(model.adminReadiness.cls, "warn");
  assert.equal(model.adminReadiness.adminVerified, false);
  assert.equal(model.adminReadiness.items.find((item) => item.id === "users-roles").status, "not loaded");
  assert.equal(model.adminReadiness.items.find((item) => item.id === "sessions").status, "not loaded");
  assert.equal(model.adminReadiness.items.find((item) => item.id === "idp-lifecycle").status, "status only");
  assert.doesNotMatch(model.adminReadiness.items.map((item) => `${item.status} ${item.detail} ${item.nextAction}`).join("\n"), /missing management API|cannot list or revoke|Add session inventory|OIDC session inventory/);
  assert.equal(model.actorAuditHash, "#/changes?tab=audit&actor=alice%40example.com&limit=300");
  assert.equal(model.authSourceAuditHash, "#/changes?tab=audit&query=oidc-session&limit=300");
}

{
  const administration = {
    authEnabled: true,
    localUsers: [
      {
        name: "local-admin",
        role: "admin",
        authSource: "local",
        tokenMaterial: "hashed",
        editable: true,
        enabled: true,
        auditHash: "inventory-sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      },
      {
        name: "breakglass",
        role: "operator",
        authSource: "local",
        tokenMaterial: "sealed",
        editable: false,
        enabled: false,
        auditHash: "inventory-sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      },
    ],
    oidc: {
      enabled: true,
      issuer: "https://idp.example.com",
      clientId: "openngfw-web",
      roleClaim: "groups",
      defaultRole: "viewer",
      cookieSecure: true,
      scopes: ["openid", "profile", "email"],
      trustedProxyCidrs: ["10.0.0.0/8"],
      sessionTtlSeconds: 3600,
    },
    sessions: {
      oidcActiveSessions: 3,
      oidcMaxSessions: 20,
      sessionRevocationAvailable: true,
      detail: "Admins can revoke browser SSO sessions.",
      activeSessions: [
        {
          sessionId: "oidc-session-sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          actor: "admin@example.com",
          role: "admin",
          authSource: "oidc-session",
          expiresAt: "2026-06-18T12:00:00Z",
          secondsUntilExpiry: 3600,
        },
      ],
    },
    breakGlass: {
      state: "ready",
      detail: "Emergency account sealed.",
      nextAction: "Rotate quarterly.",
    },
    blockers: ["Rotate default local token"],
  };
  const model = accessGovernanceModel(
    { authEnabled: true },
    { actor: "admin@example.com", role: "admin", authSource: "oidc-session", capabilities: ["read", "write", "admin"] },
    { enabled: true, authenticated: true, csrfToken: "csrf" },
    administration,
  );
  assert.equal(model.administration.available, true);
  assert.equal(model.administration.label, "1 blocker");
  assert.equal(model.administration.localUsers.length, 2);
  assert.equal(model.administration.localUsers[0].editableLabel, "editable");
  assert.equal(model.administration.localUsers[0].enabledLabel, "enabled");
  assert.equal(model.administration.localUsers[0].enabledCls, "ok");
  assert.equal(model.administration.localUsers[0].auditHash, "inventory-sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
  assert.equal(model.administration.localUsers[0].auditFingerprint, "inventory-sha256:abcdef012345...23456789");
  assert.equal(model.administration.localUsers[0].actorAuditHash, "#/changes?tab=audit&query=user%3Dlocal-admin&limit=300");
  assert.equal(model.administration.localUsers[1].editableCls, "neutral");
  assert.equal(model.administration.localUsers[1].enabledLabel, "disabled");
  assert.equal(model.administration.localUsers[1].enabledCls, "bad");
  assert.equal(model.administration.oidc.issuer, "https://idp.example.com");
  assert.equal(model.administration.oidc.rows.find((row) => row.label === "Session TTL").value, "1h");
  assert.equal(model.administration.sessions.label, "3/20 active");
  assert.equal(model.administration.sessions.cls, "ok");
  assert.equal(model.administration.sessions.rows.find((row) => row.label === "Browser SSO active").value, "3");
  assert.equal(model.administration.sessions.detail, "Admins can revoke browser SSO sessions.");
  assert.equal(model.administration.sessions.activeSessions.length, 1);
  assert.equal(model.administration.sessions.activeSessions[0].sessionFingerprint, "oidc-session-sha256:abcdef012345...23456789");
  assert.equal(model.administration.sessions.activeSessions[0].expiryLabel, "1h");
  assert.equal(model.administration.sessions.activeSessions[0].auditHash, "#/changes?tab=audit&action=access-session-revoke&query=session_id%3Doidc-session-sha256%3Aabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789&limit=300");
  assert.equal(model.administration.breakGlass.cls, "ok");
  assert.equal(model.adminReadiness.cls, "bad");
  assert.equal(model.adminReadiness.items[0].id, "backend-blocker-1");
  assert.equal(model.adminReadiness.items.find((item) => item.id === "sessions").status, "revocation available");
  assert.equal(model.adminReadiness.items.find((item) => item.id === "users-roles").status, "editable workflow");

  const review = accessLifecycleReviewModel(
    { authEnabled: true },
    { actor: "admin@example.com", role: "admin", authSource: "oidc-session", capabilities: ["read", "write", "admin"] },
    { enabled: true, authenticated: true, csrfToken: "csrf" },
    model.administration,
  );
  assert.equal(review.schemaVersion, "phragma.access.lifecycle-review.v1");
  assert.equal(review.state, "blocked");
  assert.equal(review.label, "1 blocker");
  assert.equal(review.localAdminCount, 1);
  assert.equal(review.activeSessionCount, 1);
  assert.equal(review.lifecycleRows.find((row) => row.id === "backend-blocker-1").cls, "bad");
  assert.equal(review.lifecycleRows.find((row) => row.id === "sessions").state, "3/20 active");
  assert.equal(review.lifecycleRows.find((row) => row.id === "break-glass").cls, "ok");
  assert.ok(review.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration"));
  assert.ok(review.cli.some((item) => /ngfwctl access users rotate-token local-admin/.test(item)));
  assert.ok(review.auditLinks.some((link) => link.href.includes("access-session-revoke")));
  const text = accessLifecycleReviewText(review);
  assert.match(text, /Access lifecycle review: blocked/);
  assert.match(text, /break_glass_local_admins=1/);
  assert.match(text, /active_browser_sso_sessions=1/);
  assert.doesNotMatch(text, /abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789/);
}

{
  const review = accessLifecycleReviewModel(
    { authEnabled: true },
    { actor: "secops@example.com", role: "admin", authSource: "api-token" },
    { enabled: false },
    accessAdministrationModel(
      { authEnabled: true },
      { enabled: false },
      {
        authEnabled: true,
        localUsers: [],
        oidc: { enabled: true, issuer: "https://idp.example.com", cookieSecure: false },
        saml: { enabled: true, entityId: "https://idp.example.com/saml", runtimeAvailable: false },
        sessions: { oidcActiveSessions: 0, oidcMaxSessions: 20, sessionRevocationAvailable: true, activeSessions: [] },
        breakGlass: { state: "missing", detail: "No local admin available.", nextAction: "Create break-glass admin." },
        blockers: [],
      },
    ),
  );
  assert.equal(review.state, "blocked");
  assert.equal(review.lifecycleRows.find((row) => row.id === "break-glass").cls, "bad");
  assert.equal(review.lifecycleRows.find((row) => row.id === "saml").state, "runtime pending");
  assert.equal(review.lifecycleRows.find((row) => row.id === "oidc").cls, "warn");
  assert.match(accessLifecycleReviewText(review), /Create break-glass admin/);
}

{
  const model = accessGovernanceModel(
    { authEnabled: true },
    { actor: "viewer@example.com", role: "viewer", authSource: "api-token", capabilities: ["read"] },
    { enabled: true },
    accessAdministrationUnavailable({ status: 403, message: "permission denied" }),
  );
  assert.equal(model.administration.available, false);
  assert.equal(model.administration.label, "endpoint unavailable");
  assert.match(model.administration.detail, /HTTP 403: permission denied/);
  assert.equal(model.adminReadiness.cls, "warn");
  assert.equal(model.adminReadiness.adminVerified, false);
  assert.equal(model.adminReadiness.items.find((item) => item.id === "users-roles").status, "endpoint unavailable");
  assert.equal(model.adminReadiness.items.find((item) => item.id === "break-glass").status, "not loaded");
  assert.equal(model.rows.find((row) => row.id === "read").allowed, true);
  assert.equal(model.rows.find((row) => row.id === "commit").allowed, false);
}

{
  const readiness = accessAdminReadiness(
    { authEnabled: true },
    { actor: "viewer@example.com", role: "viewer", authSource: "api-token", capabilities: ["read"] },
    { enabled: true },
  );
  assert.match(readiness.items.find((item) => item.id === "idp-lifecycle").detail, /load access administration to review SAML runtime posture/);
}

{
  const normalized = accessAdministrationModel(
    { authEnabled: false },
    { enabled: false },
    {
      authEnabled: false,
      localUsers: [{ name: "ops", role: "operator", authSource: "local", tokenMaterial: "present" }],
      oidc: { enabled: false },
      sessions: { sessionRevocationAvailable: false },
      breakGlass: { state: "auth disabled", detail: "Auth disabled for lab.", nextAction: "Enable auth." },
      blockers: [],
    },
  );
  assert.equal(normalized.authEnabled, false);
  assert.equal(normalized.localUsers[0].editableLabel, "unknown");
  assert.equal(normalized.localUsers[0].enabledLabel, "enabled");
  assert.equal(normalized.localUsers[0].auditHash, "");
  assert.equal(normalized.localUsers[0].auditFingerprint, "not reported");
  assert.equal(normalized.localUsers[0].actorAuditHash, "#/changes?tab=audit&query=user%3Dops&limit=300");
  assert.equal(normalized.oidc.label, "disabled");
  assert.equal(normalized.sessions.cls, "warn");
  assert.equal(normalized.breakGlass.cls, "bad");
}

{
  const model = accessGovernanceModel({ authEnabled: false }, null, { enabled: false });
  assert.equal(model.actor, "local admin mode");
  assert.equal(model.role, "admin");
  assert.equal(model.authSource, "auth-disabled");
  assert.equal(model.capabilitiesLabel, "read, write, admin");
  assert.equal(model.capabilitySummary.canAdmin, true);
  assert.equal(model.adminReadiness.cls, "bad");
  assert.equal(model.adminReadiness.adminVerified, true);
  assert.equal(model.adminReadiness.items.find((item) => item.id === "break-glass").status, "auth disabled");
  assert.equal(model.rows.every((row) => row.allowed), true);
}

{
  const readiness = accessAdminReadiness(
    { authEnabled: true },
    { actor: "admin@example.com", role: "admin", authSource: "api-token", capabilities: ["read", "write", "admin"] },
    { enabled: false },
  );
  assert.equal(readiness.cls, "warn");
  assert.equal(readiness.label, "4 review items");
  assert.equal(readiness.adminVerified, true);
  assert.deepEqual(
    readiness.items.filter((item) => item.cls === "bad").map((item) => item.id),
    [],
  );
  assert.equal(readiness.items.find((item) => item.id === "users-roles").status, "not loaded");
  assert.equal(readiness.items.find((item) => item.id === "sessions").status, "not loaded");
  assert.equal(readiness.items.find((item) => item.id === "idp-lifecycle").status, "not configured");
  assert.equal(readiness.items.find((item) => item.id === "break-glass").status, "not exposed");
  assert.match(readiness.detail, /review items/);
  assert.doesNotMatch(readiness.items.map((item) => `${item.status} ${item.detail} ${item.nextAction}`).join("\n"), /missing management API|cannot list or revoke|Add user and role CRUD/);
}

{
  assert.equal(
    accessAuditHash({ actor: "Dana User", query: "local users", limit: 500 }),
    "#/changes?tab=audit&actor=Dana+User&query=local+users&limit=500",
  );
}

{
  const workflows = accessGovernanceWorkflows();
  assert.ok(workflows.some((workflow) => workflow.id === "content-install"));
  assert.deepEqual(
    workflows.find((workflow) => workflow.id === "host-tune").auditLinks.map((link) => link.href),
    ["#/changes?tab=audit&action=system-tune&limit=300"],
  );
  assert.deepEqual(
    workflows.find((workflow) => workflow.id === "packet-capture").auditLinks.map((link) => link.action),
    ["packet-capture"],
  );
}

{
  const matrix = accessRoleWorkflowMatrix();
  const commit = matrix.find((row) => row.id === "commit");
  assert.deepEqual(commit.roles, { viewer: false, operator: true, admin: true });
  const contentRollback = matrix.find((row) => row.id === "content-rollback");
  assert.deepEqual(contentRollback.roles, { viewer: false, operator: false, admin: true });
  const accessAdmin = matrix.find((row) => row.id === "access-admin");
  assert.deepEqual(accessAdmin.roles, { viewer: false, operator: false, admin: true });
  assert.deepEqual(
    accessGovernanceWorkflows().find((workflow) => workflow.id === "access-admin").auditLinks.map((link) => link.action),
    [
      "access-local-user-create",
      "access-local-user-update",
      "access-local-user-rotate-token",
      "access-local-user-disable",
      "access-oidc-provider-set",
      "access-oidc-provider-disable",
      "access-saml-provider-set",
      "access-saml-provider-disable",
      "access-session-revoke",
    ],
  );
}

{
  const links = accessWorkflowAuditLinks({ auditActions: ["commit", "commit-intent"] });
  assert.deepEqual(links, [
    { action: "commit", label: "Commit", href: "#/changes?tab=audit&action=commit&limit=300" },
    { action: "commit-intent", label: "Commit Intent", href: "#/changes?tab=audit&action=commit-intent&limit=300" },
  ]);
}

{
  assert.deepEqual(summarizeCapabilities(["write", "read", "write"]), {
    values: ["write", "read"],
    label: "write, read",
    canRead: true,
    canWrite: true,
    canAdmin: false,
  });
  assert.deepEqual(summarizeCapabilities(null), {
    values: [],
    label: "none",
    canRead: false,
    canWrite: false,
    canAdmin: false,
  });
}

function completeAccessFieldEvidenceArtifacts() {
  const seed = accessFieldEvidenceCertificationModel({}, {});
  const collectedAt = new Date().toISOString();
  const artifacts = {};
  for (const protocol of seed.protocols) {
    artifacts[protocol.id] = {};
    for (const item of protocol.artifactInventory) {
      const provider = protocol.id === "saml"
        ? "idp_entity_id=https://idp.example.com/saml\nmetadata_url=https://idp.example.com/metadata"
        : "issuer=https://idp.example.com\nissuer_url=https://idp.example.com";
      const callback = protocol.id === "saml"
        ? "acs_url=https://firewall.example.com/v1/auth/saml/acs"
        : "callback_url=https://firewall.example.com/v1/auth/oidc/callback";
      artifacts[protocol.id][item.path] = [
        "status=passed",
        `collected_at=${collectedAt}`,
        provider,
        callback,
        "role_claim=groups",
        "session_cookie=present",
        "step_up_proof=present",
        "disable_rollback_proof=present",
      ].join("\n");
    }
  }
  return artifacts;
}

{
  const model = accessFieldEvidenceCertificationModel({
    oidc: { enabled: true },
    saml: { enabled: true },
    breakGlass: { state: "ready" },
    sessions: { activeSessions: [{ actor: "operator@example.com" }] },
  }, { fieldEvidenceArtifacts: completeAccessFieldEvidenceArtifacts() });
  assert.equal(model.state, "field-run-evidence-complete");
  assert.equal(model.fieldRunCertification, "certified-by-evidence");
  assert.equal(model.externalCertification, "not-certified");
  assert.equal(model.externalCertificationLabel, "Field-run evidence complete; external IdP certification deferred");
  assert.match(model.certificationBoundary, /not vendor certification/);
  const handoffText = accessFieldEvidenceCertificationText(model);
  assert.match(handoffText, /field_run_certification=certified-by-evidence/);
  assert.match(handoffText, /external_certification=not-certified/);
  assert.match(handoffText, /No real IdP run is certified by this browser-generated packet/);
  const handoffPacket = accessFieldEvidenceCertificationPacket(model);
  assert.equal(handoffPacket.fieldRunCertification, "certified-by-evidence");
  assert.equal(handoffPacket.externalCertification, "not-certified");
  assert.ok(model.protocols.every((protocol) => protocol.fieldFacts.complete));
  assert.ok(model.protocols.every((protocol) => protocol.artifactInventory.every((item) => item.state === "passed")));
}

{
  const artifacts = completeAccessFieldEvidenceArtifacts();
  delete artifacts.oidc["provider/issuer-client-discovery.txt"];
  const model = accessFieldEvidenceCertificationModel({}, { fieldEvidenceArtifacts: artifacts });
  assert.equal(model.state, "missing-artifacts");
  assert.equal(model.fieldRunCertification, "not-certified");
  const providerRow = model.protocols.find((protocol) => protocol.id === "oidc").fieldFacts.rows.find((row) => row.id === "provider");
  assert.equal(providerRow.state, "missing");
}

{
  const stale = accessFieldEvidenceArtifactStatus("status=passed\ncollected_at=2020-01-01T00:00:00Z\nissuer=https://idp.example.com");
  assert.equal(stale.state, "stale");
  const artifacts = completeAccessFieldEvidenceArtifacts();
  artifacts.saml["provider/idp-metadata.txt"] = "status=passed\ncollected_at=2020-01-01T00:00:00Z\nidp_entity_id=https://idp.example.com/saml";
  const model = accessFieldEvidenceCertificationModel({}, { fieldEvidenceArtifacts: artifacts });
  assert.equal(model.state, "stale-artifacts");
}

{
  const unsafe = accessFieldEvidenceArtifactStatus("status=passed\naccess_token=super-secret-token\nissuer=https://idp.example.com");
  assert.equal(unsafe.state, "unsafe");
  const artifacts = completeAccessFieldEvidenceArtifacts();
  artifacts.oidc["browser/session-cookie.txt"] = "status=passed\nset-cookie=sessionid=super-secret-cookie";
  const model = accessFieldEvidenceCertificationModel({}, { fieldEvidenceArtifacts: artifacts });
  assert.equal(model.state, "unsafe-artifacts");
  const serialized = JSON.stringify(model);
  assert.doesNotMatch(serialized, /super-secret-token|super-secret-cookie|sessionid=/);
}

{
  assert.deepEqual(accessFieldEvidenceParseImport(""), {});
  assert.deepEqual(accessFieldEvidenceParseImport("{\"provider/issuer-client-discovery.txt\":\"status=passed\"}"), {
    "provider/issuer-client-discovery.txt": "status=passed",
  });
  assert.throws(() => accessFieldEvidenceParseImport("[\"not\", \"a\", \"map\"]"), /JSON object keyed by artifact path/);
  const current = accessFieldEvidenceCertificationModel({}, { fieldEvidenceArtifacts: completeAccessFieldEvidenceArtifacts() });
  try {
    accessFieldEvidenceParseImport("[1]");
  } catch {
    // Import review catches parse failures before constructing a replacement model.
  }
  const afterFailedImport = accessFieldEvidenceCertificationModel({}, { fieldEvidenceArtifacts: completeAccessFieldEvidenceArtifacts() });
  assert.equal(current.state, afterFailedImport.state);
  assert.equal(afterFailedImport.fieldRunCertification, "certified-by-evidence");
}

import { h } from "./core.js";
import { pill } from "./ui.js";

export function validationErrors(validation, fallback = "Validation failed without a detailed error.") {
  if (Array.isArray(validation?.errors) && validation.errors.length) return validation.errors;
  const errors = validationFindings(validation, { severity: "error", includeImpact: true }).map(findingText).filter(Boolean);
  return errors.length ? errors : [fallback];
}

export function renderValidationEvidence(validation, {
  validText = "Candidate validated successfully. Engine syntax checks passed.",
  invalidLead = "Fix these before committing:",
  emptyError = "Validation failed without a detailed error.",
} = {}) {
  const valid = Boolean(validation?.valid);
  const findings = validationFindings(validation);
  return h("div", { class: "validation-evidence" },
    valid
      ? h("div", { class: "alert-box ok" }, validText)
      : h("div", { class: "alert-box bad" },
        h("strong", {}, "Validation failed. "),
        invalidLead,
        h("ul", { class: "compact-list" }, validationErrors(validation, emptyError).map((e) => h("li", {}, e)))),
    findings.length ? h("div", { class: "impact-section-head" },
      h("strong", {}, "Validation findings"),
      h("span", {}, `${findings.length} item${findings.length === 1 ? "" : "s"}`)) : null,
    findings.length ? h("div", { class: "impact-list impact-list-scroll" }, findings.map((finding) =>
      h("div", { class: "impact-row " + findingClass(finding) },
        h("div", {}, pill(findingLabel(finding), findingPillClass(finding))),
        h("div", {}, h("strong", {}, finding.message || finding.code || "Validation finding"),
          finding.detail ? h("span", {}, finding.detail) : null,
          finding.fieldPath ? h("small", {}, finding.fieldPath) : null)))) : null,
    renderPlan(validation?.renderPlan));
}

function renderPlan(plan) {
  const artifacts = Array.isArray(plan?.artifacts) ? plan.artifacts : [];
  if (!artifacts.length) return null;
  return h("details", { class: "diff-details" },
    h("summary", {}, `Render plan: ${Number(plan.artifactCount) || artifacts.length} artifacts, ${Number(plan.totalBytes) || 0} bytes`),
    h("div", { class: "impact-list impact-list-scroll" }, artifacts.map((artifact) =>
      h("div", { class: "impact-row low" },
        h("div", {}, pill("plan", "neutral")),
        h("div", {}, h("strong", {}, artifact.name || artifact.engine || "artifact"),
          h("span", {}, `${Number(artifact.sizeBytes) || 0} bytes`))))));
}

function validationFindings(validation, { severity = "", includeImpact = false } = {}) {
  return (validation?.findings || []).filter((finding) => {
    if (!includeImpact && findingStage(finding) === "impact") return false;
    if (severity && findingSeverity(finding) !== severity) return false;
    return true;
  });
}

function findingText(finding) {
  const pieces = [finding?.message || finding?.code || ""];
  if (finding?.fieldPath) pieces.push(`(${finding.fieldPath})`);
  if (finding?.detail) pieces.push(finding.detail);
  return pieces.filter(Boolean).join(": ");
}

function findingSeverity(finding) {
  const raw = finding?.severity;
  if (raw === 1 || raw === "VALIDATION_SEVERITY_ERROR") return "error";
  if (raw === 2 || raw === "VALIDATION_SEVERITY_WARNING") return "warning";
  if (raw === 3 || raw === "VALIDATION_SEVERITY_INFO") return "info";
  return "info";
}

function findingStage(finding) {
  const raw = finding?.stage;
  if (raw === 4 || raw === "VALIDATION_STAGE_IMPACT") return "impact";
  if (raw === 3 || raw === "VALIDATION_STAGE_ENGINE_VALIDATE") return "engine";
  if (raw === 2 || raw === "VALIDATION_STAGE_RENDER") return "render";
  if (raw === 1 || raw === "VALIDATION_STAGE_POLICY_MODEL") return "policy";
  return "validation";
}

function findingLabel(finding) {
  const stage = findingStage(finding);
  const severity = findingSeverity(finding);
  return stage === "validation" ? severity : `${severity}/${stage}`;
}

function findingClass(finding) {
  const severity = findingSeverity(finding);
  if (severity === "error") return "high";
  if (severity === "warning") return "medium";
  return "low";
}

function findingPillClass(finding) {
  const severity = findingSeverity(finding);
  if (severity === "error") return "bad";
  if (severity === "warning") return "warn";
  return "neutral";
}

#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createServer } from "node:net";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { readFileSync } from "node:fs";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

const allViewports = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "tablet", width: 1024, height: 900 },
  { name: "mobile", width: 390, height: 900 },
];
const viewports = selectedViewports();

const screens = [
  { name: "Dashboard", path: "/" },
  { name: "Guided setup", path: "/setup" },
  { name: "Rules", path: "/rules", navTitle: "Security rules" },
  { name: "Objects", path: "/objects" },
  { name: "NAT", path: "/nat" },
  { name: "Inspection", path: "/inspection", view: "ids" },
  { name: "Threats", path: "/threats" },
  { name: "Traffic", path: "/traffic" },
  { name: "System logs", path: "/logs", navTitle: "System logs" },
  { name: "Troubleshoot", path: "/troubleshoot" },
  { name: "Performance", path: "/performance" },
  { name: "Investigation", path: "/investigation" },
  { name: "Fleet & templates", path: "/fleet", navTitle: "Fleet & templates" },
  { name: "Threat intel", path: "/intel" },
  { name: "Routing & VPN", path: "/netvpn" },
  { name: "Proxy / WAF", path: "/proxy" },
  { name: "Compliance", path: "/compliance" },
  { name: "Changes", path: "/changes" },
  { name: "Settings", path: "/settings" },
];

const started = {
  process: null,
  detached: false,
  workDir: "",
  logDir: "",
};

let seededInvestigationTelemetry = false;
let smokeAdminToken = "";
let oidcSmokeIssuer = "";
let oidcSmokeSecretFile = "";
let oidcSmokeProvider = null;
const requireChangesUIApply = envFlag("WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY");
const requireEbpfRuntimeEvidence = envFlag("WEBUI_SMOKE_EBPF_RUNTIME_EVIDENCE");
const screenTimeoutMs = positiveIntEnv("WEBUI_SMOKE_SCREEN_TIMEOUT_MS", 120000);
const totalTimeoutMs = positiveIntEnv("WEBUI_SMOKE_TOTAL_TIMEOUT_MS", 20 * 60 * 1000);
let smokeStage = "starting";
const smokeProgress = {
  completed: 0,
  total: 0,
  currentStartedAt: 0,
  currentLabel: "",
  planned: [],
  completedLabels: [],
  checkpoints: [],
};
const smokeRun = {
  startedAt: new Date().toISOString(),
  endedAt: "",
  baseURL: "",
  artifactDir: "",
  mode: "",
  routeCoverage: "",
  routeSource: "",
  requestedRoutes: [],
  routeOrder: [],
  selectedRoutes: [],
  missingBroadRoutes: [],
  screenshotFiles: [],
  routeResults: [],
  failureRecords: [],
  manifestPath: "",
};

function setSmokeStage(stage) {
  smokeStage = String(stage || "running");
  console.log(`[webui-smoke] ${smokeStage}`);
}

function beginSmokeCheckpoint(label, total) {
  smokeProgress.currentLabel = label;
  smokeProgress.currentStartedAt = Date.now();
  const prefix = total > 0 ? `${smokeProgress.completed + 1}/${total}` : String(smokeProgress.completed + 1);
  setSmokeStage(`${prefix} ${label} start`);
}

function completeSmokeCheckpoint(label, total, status = "passed") {
  const elapsedMs = smokeProgress.currentStartedAt ? Date.now() - smokeProgress.currentStartedAt : 0;
  smokeProgress.completed += 1;
  smokeProgress.completedLabels.push(label);
  smokeProgress.checkpoints.push({ label, elapsedMs, status });
  if (smokeProgress.checkpoints.length > 12) smokeProgress.checkpoints.shift();
  const prefix = total > 0 ? `${smokeProgress.completed}/${total}` : String(smokeProgress.completed);
  setSmokeStage(`${prefix} ${label} ${status} in ${formatDuration(elapsedMs)}`);
}

function smokeProgressSummary() {
  const completedLabels = new Set(smokeProgress.completedLabels);
  const remaining = smokeProgress.planned.filter((label) => !completedLabels.has(label));
  const recent = smokeProgress.checkpoints
    .map((item) => `${item.label} ${item.status || "finished"} ${formatDuration(item.elapsedMs)}`)
    .join("; ");
  const activeElapsed = smokeProgress.currentStartedAt ? formatDuration(Date.now() - smokeProgress.currentStartedAt) : "0ms";
  return [
    `completed=${smokeProgress.completed}/${smokeProgress.total || "unknown"}`,
    `active=${smokeProgress.currentLabel || smokeStage}`,
    `active_elapsed=${activeElapsed}`,
    remaining.length ? `remaining=${remaining.slice(0, 10).join("; ")}${remaining.length > 10 ? `; +${remaining.length - 10} more` : ""}` : "",
    recent ? `recent=${recent}` : "",
  ].filter(Boolean).join(" | ");
}

const investigationSeed = {
  flowId: "eve-flow-visual-001",
  alertKey: "flow:eve-flow-visual-001",
  srcIp: "10.100.1.10",
  srcPort: 40000,
  destIp: "10.100.2.20",
  destPort: 443,
  protocol: "TCP",
  appProto: "tls",
  signatureId: 9000001,
  signature: "ET EXPLOIT Visual Smoke Test Attack",
  operatorReason: "validated visual smoke false positive workflow",
  customAppId: "visual-admin-app",
  customAppSignal: "visual-admin-app",
  customAppDescription: "Visual smoke reviewed App-ID drop rule.",
};

const captureArtifactSeed = {
  id: "phragma-visual-lifecycle",
  filename: "phragma-visual-lifecycle.pcap",
  completedAt: "2026-06-18T12:00:04Z",
};

const appIdQueueSeed = {
  queueId: "2bae9369b539d05a",
  flowId: "eve-flow-appid-queue-001",
  srcIp: "10.100.3.30",
  srcPort: 41111,
  destIp: "10.100.4.40",
  destPort: 9443,
  protocol: "TCP",
  appProto: "weird-proto",
  customAppId: "visual-queue-app",
  customAppSignal: "weird-proto",
  customAppDescription: "Visual smoke promoted App-ID queue observation.",
};

function investigationCaseSeedEnvelope() {
	const tuple = {
		srcIp: investigationSeed.srcIp,
		srcPort: investigationSeed.srcPort,
		destIp: investigationSeed.destIp,
		destPort: investigationSeed.destPort,
		protocol: investigationSeed.protocol,
		appId: investigationSeed.appProto,
	};
	const appIdQueueTuple = {
		srcIp: appIdQueueSeed.srcIp,
		srcPort: appIdQueueSeed.srcPort,
		destIp: appIdQueueSeed.destIp,
		destPort: appIdQueueSeed.destPort,
		protocol: appIdQueueSeed.protocol,
		appId: "unknown",
	};
  const collectedAt = "2026-06-18T12:10:00.000Z";
  const packet = ({ kind, title, subject, route, summary = {}, evidence = [], artifacts = {} }) => ({
    schemaVersion: "phragma.investigation.handoff.v1",
    kind,
    title,
    collectedAt,
    generatedBy: "openngfw-webui",
    source: { interface: "webui", route },
    subject,
    summary,
    evidence,
    artifacts,
  });
  const packets = [
    packet({
      kind: "flow",
      title: "Flow investigation handoff",
      subject: { id: investigationSeed.flowId, label: `${investigationSeed.srcIp}:${investigationSeed.srcPort} -> ${investigationSeed.destIp}:${investigationSeed.destPort}`, tuple },
      route: `#/traffic?flowId=${encodeURIComponent(investigationSeed.flowId)}`,
      summary: {
        appId: investigationSeed.appProto,
        appName: "TLS",
        action: "allowed",
        eventPolicy: "v8",
        fromZone: "trust",
        toZone: "dmz",
        currentInspectionPosture: "flow telemetry",
      },
      evidence: ["flow observed in visual smoke EVE telemetry", "application fallback: tls"],
      artifacts: { flow: { flowId: investigationSeed.flowId, ...tuple, appId: investigationSeed.appProto, policyVersionKnown: true, policyVersion: 8, rule: "allow-outbound-tls" } },
    }),
    packet({
      kind: "alert",
      title: "Threat alert investigation handoff",
      subject: { id: investigationSeed.flowId, label: investigationSeed.signature, tuple },
      route: `#/threats?alert=${encodeURIComponent(investigationSeed.alertKey)}`,
      summary: {
        threatId: `suricata-sid-${investigationSeed.signatureId}`,
        threatName: investigationSeed.signature,
        signatureId: investigationSeed.signatureId,
        flowId: investigationSeed.flowId,
        action: "blocked",
        eventPolicy: "v8",
        fromZone: "trust",
        toZone: "dmz",
      },
      evidence: [`SID ${investigationSeed.signatureId}`, "alert correlated with seeded flow"],
      artifacts: { alert: { flowId: investigationSeed.flowId, signatureId: investigationSeed.signatureId, signature: investigationSeed.signature, action: "blocked", ...tuple, policyVersionKnown: true, policyVersion: 8 } },
    }),
    packet({
      kind: "capture",
      title: "Packet capture investigation handoff",
      subject: { id: investigationSeed.flowId, label: `${investigationSeed.srcIp}:${investigationSeed.srcPort} -> ${investigationSeed.destIp}:${investigationSeed.destPort}`, tuple },
      route: "#/troubleshoot?intent=capture&flowId=eve-flow-visual-001&token=Bearer-secret&password=secret&path=/etc/passwd&file=file:/tmp/pcap",
      summary: {
        flowId: investigationSeed.flowId,
        captureState: "completed",
        outputPath: "/var/log/openngfw/pcap/phragma-case-flow.pcap",
        sha256: "b".repeat(64),
        detail: "capture stored at /var/log/openngfw/pcap/phragma-case-flow.pcap",
      },
      evidence: ["bounded packet capture completed", "artifact sha256: " + "b".repeat(12)],
      artifacts: {
        query: { flowId: investigationSeed.flowId, ...tuple },
        capturePlan: { flowId: investigationSeed.flowId, ...tuple, outputPath: "/var/log/openngfw/pcap/phragma-case-flow.pcap" },
        captureJob: { id: "pcap-visual-001", state: "completed", sha256: "b".repeat(64), bytesWritten: 4096, plan: { flowId: investigationSeed.flowId, ...tuple, outputPath: "/var/log/openngfw/pcap/phragma-case-flow.pcap" } },
      },
    }),
	    packet({
	      kind: "app-id-observation",
	      title: "App-ID observation handoff",
	      subject: { id: appIdQueueSeed.flowId, label: "weird-proto App-ID review", tuple: appIdQueueTuple },
	      route: `#/traffic?mode=app-id&queueId=${encodeURIComponent(appIdQueueSeed.queueId)}&engineSignal=${encodeURIComponent(appIdQueueSeed.appProto)}&protocol=${encodeURIComponent(appIdQueueSeed.protocol)}&port=${encodeURIComponent(String(appIdQueueSeed.destPort))}`,
	      summary: {
	        reason: "unknown application",
	        queueId: appIdQueueSeed.queueId,
	        appId: "unknown",
	        appName: "unknown",
	        engineSignal: appIdQueueSeed.appProto,
	        protocol: appIdQueueSeed.protocol,
	        destPort: appIdQueueSeed.destPort,
	        sampleFlowId: appIdQueueSeed.flowId,
	      },
	      evidence: [`engine signal: eve=${appIdQueueSeed.appProto}`, "sample flow is pinned for App-ID review"],
	      artifacts: { observation: { queueId: appIdQueueSeed.queueId, sampleFlowId: appIdQueueSeed.flowId, sampleSrcIp: appIdQueueSeed.srcIp, sampleSrcPort: appIdQueueSeed.srcPort, sampleDestIp: appIdQueueSeed.destIp, destPort: appIdQueueSeed.destPort, protocol: appIdQueueSeed.protocol, engineSignal: appIdQueueSeed.appProto, appId: "unknown" } },
	    }),
    packet({
      kind: "nat-path",
      title: "NAT path preview handoff",
      subject: { id: "nat-preview-visual-001", label: "Candidate DNAT preview", tuple },
      route: "#/nat?fromZone=trust&toZone=dmz&protocol=PROTOCOL_TCP&srcIp=10.100.1.10&srcPort=40000&destIp=10.100.2.20&destPort=443&run=1",
      summary: {
        runningVerdict: "default drop",
        candidateVerdict: "allowed",
        candidateMatchedRule: "allow-public-web",
        fromZone: "trust",
        toZone: "dmz",
      },
      evidence: ["candidate NAT changes path behavior", "running/candidate preview retained"],
      artifacts: { flow: { ...tuple, fromZone: "trust", toZone: "dmz" }, running: { verdict: "default drop" }, candidate: { verdict: "allowed", matchedRule: "allow-public-web" } },
    }),
    packet({
      kind: "audit-entry",
      title: "Audit entry handoff",
      subject: { id: "audit-visual-001", label: "policy.prepare" },
      route: "#/changes?tab=audit",
      summary: {
        action: "policy.prepare",
        actor: "visual-smoke",
        detail: "prepared from /etc/openngfw/private-state with access_token=writer-secret",
        entryHash: "c".repeat(32),
      },
      evidence: ["audit entry linked to candidate policy review"],
      artifacts: { auditEntry: { id: 42, action: "policy.prepare", detail: "prepared from /etc/openngfw/private-state with access_token=writer-secret", entryHash: "c".repeat(32) } },
    }),
    packet({
      kind: "content-package-lifecycle",
      title: "Content package lifecycle handoff",
      subject: { id: "app-id", label: "App-ID package readiness" },
      route: "#/intel?surface=app-id&drawer=review",
      summary: {
        status: "review",
        version: "visual-smoke",
        source: "/var/lib/openngfw/content/app-id/source",
        blockerCount: 1,
      },
      evidence: ["signature verified", "regression evidence required"],
      artifacts: { contentPackage: { kind: "app-id", version: "visual-smoke", source: "/var/lib/openngfw/content/app-id/source" } },
    }),
  ];
  return {
    schemaVersion: "phragma.investigation.case.v1",
    updatedAt: "2026-06-18T12:10:07.000Z",
    items: packets.map((p, index) => ({
      key: `${p.kind}:visual-${index}`,
      pinnedAt: `2026-06-18T12:10:0${index}.000Z`,
      kind: p.kind,
      title: p.title,
      subject: p.subject,
      source: p.source,
      summary: p.summary,
      packet: p,
    })),
  };
}

process.on("SIGINT", () => {
  cleanup().finally(() => process.exit(130));
});
process.on("SIGTERM", () => {
  cleanup().finally(() => process.exit(143));
});

async function main() {
  if (envFlag("WEBUI_SMOKE_SELF_CHECK")) {
    await runSmokeRunnerSelfCheck();
    return;
  }

  const requireBrowser = envFlag("WEBUI_SMOKE_REQUIRE_BROWSER");
  const suppliedURL = process.env.WEBUI_SMOKE_URL || "";
  const playwright = await loadPlaywright();

  if (!playwright && requireBrowser) {
    throw browserRequiredError("Playwright is not installed or not resolvable from this checkout");
  }

  const baseURL = suppliedURL ? normalizeUIURL(suppliedURL) : await startControld();
  try {
    if (playwright) {
      const mode = await runPlaywrightSmoke(playwright, baseURL, { requireBrowser });
      if (mode === "fallback") return;
      console.log(`webui visual smoke passed via Playwright at ${baseURL}`);
      return;
    }

    await runHTTPFallback(baseURL);
    console.log(`webui visual smoke fallback passed at ${baseURL}`);
    console.log("Playwright was not available, so browser console and layout overflow checks were not executed.");
    console.log("Set WEBUI_SMOKE_REQUIRE_BROWSER=1 to make missing browser coverage a hard failure.");
  } finally {
    await cleanup();
  }
}

async function runSmokeStep(label, fn) {
  try {
    return await fn();
  } catch (err) {
    throw new Error(`${label}: ${err.message || err}`);
  }
}

async function withSmokeTimeout(label, promise, timeoutMs = screenTimeoutMs) {
  let timer = null;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function positiveIntEnv(name, fallback) {
  const value = Number.parseInt(String(process.env[name] || ""), 10);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function selectedViewports() {
  const requested = String(process.env.WEBUI_SMOKE_VIEWPORTS || "").trim();
  if (!requested) return allViewports;
  const wanted = requested.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  const selected = allViewports.filter((viewport) => wanted.includes(viewport.name));
  if (!selected.length || selected.length !== new Set(wanted).size) {
    const valid = allViewports.map((viewport) => viewport.name).join(",");
    throw new Error(`WEBUI_SMOKE_VIEWPORTS must contain known viewport names (${valid}); received ${requested}`);
  }
  return selected;
}

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch (err) {
    if (err && (err.code === "ERR_MODULE_NOT_FOUND" || err.code === "MODULE_NOT_FOUND")) {
      return null;
    }
    throw err;
  }
}

async function runPlaywrightSmoke(playwright, baseURL, opts = {}) {
  await assertAPISpecServed(baseURL);
  setSmokeStage("launching Chromium");
  smokeRun.baseURL = baseURL;
  const launch = await launchBrowser(playwright);
  const browser = launch.browser;
  if (!browser) {
    if (opts.requireBrowser) {
      throw browserRequiredError("Playwright is installed, but Chromium could not be launched", launch.error);
    }
    await runHTTPFallback(baseURL);
    console.log(`webui visual smoke fallback passed at ${baseURL}`);
    console.log("Playwright module is installed, but no browser was launchable; used HTTP/static fallback.");
    console.log("Set WEBUI_SMOKE_REQUIRE_BROWSER=1 to make this a hard failure in CI.");
    return "fallback";
  }

  const artifactDir = await prepareArtifactDir();
  const selectedScreens = filteredSmokeScreens();
  const policy = evidencePolicy(selectedScreens);
  Object.assign(smokeRun, {
    artifactDir,
    mode: policy.mode,
    routeCoverage: policy.routeCoverage,
    routeSource: policy.source,
    requestedRoutes: policy.requestedRoutes,
    routeOrder: selectedScreens.map((screen) => screen.path),
    selectedRoutes: selectedScreens.map((screen) => ({ name: screen.name, path: screen.path })),
    missingBroadRoutes: policy.missingBroadRoutes,
  });
  smokeProgress.total = selectedScreens.length * viewports.length;
  smokeProgress.planned = plannedSmokeLabels(selectedScreens);
  console.log(`[webui-smoke] selected ${selectedScreens.length} routes across ${viewports.length} viewports (${smokeProgress.total} route checks)`);
  console.log(`[webui-smoke] route order: ${selectedScreens.map((screen) => screen.path).join(",")}`);
  console.log(`[webui-smoke] browser_required=${opts.requireBrowser ? "true" : "false"}`);
  console.log(`[webui-smoke] browser_coverage=chromium`);
  console.log(`[webui-smoke] viewport_coverage=${viewports.map((viewport) => viewport.name).join(",")}`);
  for (const line of evidencePolicyLines(selectedScreens, policy)) {
    console.log(`[webui-smoke] ${line}`);
  }
  const failures = [];
  try {
    for (const viewport of viewports) {
      setSmokeStage(`creating browser context for ${viewport.name}`);
      const context = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
        ignoreHTTPSErrors: true,
        acceptDownloads: true,
      });
      if (smokeAdminToken) {
        await context.addInitScript((token) => {
          globalThis.sessionStorage?.setItem("phragma.token", token);
          globalThis.localStorage?.removeItem("phragma.token");
          globalThis.localStorage?.removeItem("openngfw.token");
          const nativeFetch = globalThis.fetch?.bind(globalThis);
          if (nativeFetch && !globalThis.__openngfwSmokeFetchAuth) {
            globalThis.__openngfwSmokeFetchAuth = true;
            globalThis.fetch = (input, init = {}) => {
              const url = typeof input === "string" ? input : input?.url || "";
              let parsed = null;
              try { parsed = new URL(url, globalThis.location?.href || "http://127.0.0.1/"); } catch {}
              const sameOriginAPI = parsed && parsed.origin === globalThis.location.origin && parsed.pathname.startsWith("/v1/");
              const headers = new Headers(init?.headers || (typeof input !== "string" ? input?.headers : undefined) || {});
              if (sameOriginAPI && !headers.has("Authorization")) {
                headers.set("Authorization", `Bearer ${token}`);
              }
              return nativeFetch(input, { ...init, headers });
            };
          }
        }, smokeAdminToken);
      }
      try {
        for (const screen of selectedScreens) {
          const page = await context.newPage();
          const consoleErrors = [];
          const assetFailures = [];
          const httpFailures = [];
          const screenLabel = `${viewport.name} ${screen.name} ${screen.path}`;
          const routeResult = beginRouteResult(screen, viewport);
          page.on("console", (msg) => {
            if (msg.type() === "error") consoleErrors.push(msg.text());
          });
          page.on("pageerror", (err) => consoleErrors.push(err.message));
          page.on("requestfailed", (req) => {
            if (criticalResourceType(req.resourceType())) {
              const failure = req.failure()?.errorText || "request failed";
              assetFailures.push(`${req.resourceType()} ${req.url()}: ${failure}`);
            }
          });
          page.on("response", (res) => {
            const req = res.request();
            if (res.status() >= 400) {
              httpFailures.push(`${req.resourceType()} ${res.status()} ${res.url()}`);
            }
            if (res.status() >= 400 && criticalResourceType(req.resourceType())) {
              assetFailures.push(`${req.resourceType()} ${res.status()} ${res.url()}`);
            }
          });

          try {
            const routeFailureStart = failures.length;
            beginSmokeCheckpoint(screenLabel, smokeProgress.total);
            await withSmokeTimeout(screenLabel, (async () => {
            if (screen.path === "/investigation") {
              await page.addInitScript((envelope) => {
                globalThis.localStorage?.setItem("phragma.investigation.case.v1", JSON.stringify(envelope));
              }, investigationCaseSeedEnvelope());
            }
            if (seededInvestigationTelemetry && seededTelemetryRoute(screen.path)) {
              await ensureSeededInvestigationTelemetry();
            }
            await page.goto(routeURL(baseURL, screen.path), { waitUntil: "networkidle", timeout: 30000 });
            await page.waitForSelector("#content", { timeout: 10000 });
            await page.waitForFunction(() => !document.querySelector("#content > .loading"), null, { timeout: 10000 });
            await page.waitForTimeout(150);
            const screenshotFile = await captureRouteScreenshot(page, artifactDir, screen, viewport);
            if (screenshotFile) {
              smokeRun.screenshotFiles.push(screenshotFile);
              routeResult.screenshot = screenshotFile;
            }

            const state = await page.evaluate(() => {
              const content = document.querySelector("#content");
              const doc = document.documentElement;
              const body = document.body;
              const scrolling = document.scrollingElement || doc;
              const overflow = Math.max(
                doc.scrollWidth - window.innerWidth,
                body.scrollWidth - window.innerWidth,
                scrolling.scrollWidth - window.innerWidth,
              );
              const badView = content?.textContent?.includes("Could not load this view.") || false;
              const offenders = [...document.querySelectorAll("body *")]
                .map((node) => {
                  const rect = node.getBoundingClientRect?.();
                  if (!rect) return null;
                  const right = Math.ceil(rect.right - window.innerWidth);
                  const internal = Math.ceil((node.scrollWidth || 0) - (node.clientWidth || 0));
                  const overflow = Math.max(0, right, Math.ceil(0 - rect.left), internal);
                  if (overflow <= 2) return null;
                  const label = [
                    node.tagName?.toLowerCase() || "node",
                    node.id ? `#${node.id}` : "",
                    node.className && typeof node.className === "string" ? `.${node.className.trim().replace(/\s+/g, ".")}` : "",
                    node.dataset ? Object.entries(node.dataset).slice(0, 2).map(([key, value]) => `[data-${key}="${value}"]`).join("") : "",
                  ].filter(Boolean).join("");
                  return { label, overflow, right, internal, width: Math.ceil(rect.width), left: Math.floor(rect.left) };
                })
                .filter(Boolean)
                .sort((a, b) => b.overflow - a.overflow)
                .slice(0, 4);
              return {
                activeNavPath: document.querySelector("#nav a.active")?.dataset?.path || "",
                contentLength: content?.textContent?.trim().length || 0,
                badView,
                loading: Boolean(content?.querySelector(":scope > .loading")),
                notFound: Boolean(content?.querySelector(".not-found-view")),
                overflow,
                scrollWidth: scrolling.scrollWidth,
                viewportWidth: window.innerWidth,
                offenders,
              };
            });

            const actionableConsoleErrors = consoleErrors.filter((item) =>
              !isGenericResourceConsoleError(item) || !httpFailures.length || !httpFailures.every(isHandledHTTPFailure));
            if (actionableConsoleErrors.length > 0) {
              addRouteFailure(failures, routeResult, screen, viewport, `console errors: ${actionableConsoleErrors.join(" | ")}${httpFailures.length ? `; http failures: ${httpFailures.join(" | ")}` : ""}`);
            }
            if (assetFailures.length > 0) {
              addRouteFailure(failures, routeResult, screen, viewport, `critical resource failures: ${assetFailures.join(" | ")}`);
            }
            if (state.activeNavPath !== screen.path) {
              addRouteFailure(failures, routeResult, screen, viewport, `active nav path "${state.activeNavPath || "<none>"}" did not match "${screen.path}"`);
            }
            if (state.loading) {
              addRouteFailure(failures, routeResult, screen, viewport, "route was still showing the loading state");
            }
            if (state.badView) {
              addRouteFailure(failures, routeResult, screen, viewport, "route rendered the generic load failure");
            }
            if (state.notFound) {
              addRouteFailure(failures, routeResult, screen, viewport, "route rendered the not-found view");
            }
            if (state.contentLength === 0) {
              addRouteFailure(failures, routeResult, screen, viewport, "route rendered empty #content");
            }
            if (state.overflow > 2) {
              const detail = state.offenders?.length ? ` offenders=${JSON.stringify(state.offenders)}` : "";
              addRouteFailure(failures, routeResult, screen, viewport, `horizontal overflow ${state.overflow}px (scrollWidth=${state.scrollWidth}, viewport=${state.viewportWidth})${detail}`);
            }
            routeResult.diagnostics = {
              activeNavPath: state.activeNavPath,
              contentLength: state.contentLength,
              overflow: state.overflow,
              scrollWidth: state.scrollWidth,
              viewportWidth: state.viewportWidth,
              offenders: state.offenders || [],
              consoleErrorCount: actionableConsoleErrors.length,
              httpFailureCount: httpFailures.length,
              criticalResourceFailureCount: assetFailures.length,
            };
            await assertAccessibleOperatorChrome(page, viewport);
            if (screen.path === "/setup") {
              await assertGuidedSetupBaselineWorkflow(page, viewport);
            }
            if (screen.path === "/intel") {
              await assertIntelContentLifecycleWorkbench(page, viewport);
              await assertIntelFeedGovernanceCandidateWorkflow(page, viewport);
            }
            if (screen.path === "/changes") {
              await assertChangesImportPreviewGuardrail(page, viewport);
              await assertChangesCommitRollbackLifecycle(page, viewport);
              await assertChangesAuditWorkbench(page, viewport);
            }
            if (seededInvestigationTelemetry && screen.path === "/") {
              await assertDashboardEvidenceConsole(page, viewport);
            }
            if (screen.path === "/") {
              await assertGlobalKeyboardFocusWorkflow(page, viewport);
              await assertDashboardAutomationContext(page, viewport);
              await assertAutomationRecorderMultiRouteRunbook(page, viewport);
              await assertGlobalDiagnosticConsoleWorkflow(page, viewport);
            }
            if (seededInvestigationTelemetry && screen.path === "/traffic") {
              await assertTrafficInvestigationWorkbench(page, viewport);
              await assertAppIdObservationQueuePromotion(page, viewport);
            }
            if (seededInvestigationTelemetry && screen.path === "/threats") {
              await assertThreatInvestigationWorkbench(page, viewport);
            }
            if (seededInvestigationTelemetry && screen.path === "/logs") {
              await assertSystemLogsWorkbench(page, viewport);
            }
            if (screen.path === "/investigation") {
              await assertInvestigationCaseWorkbench(page, viewport);
            }
            if (screen.path === "/troubleshoot") {
              await assertTroubleshootCompareSimulator(page, viewport);
            }
            if (screen.path === "/performance") {
              await assertPerformanceBenchmarkEvidenceVerifier(page, viewport);
            }
            if (screen.path === "/fleet") {
              await assertFleetTemplatesWorkspace(page, viewport);
            }
            if (screen.path === "/rules") {
              await assertRulesBulkDensityControls(page, viewport);
            }
            if (screen.path === "/nat") {
              await assertObjectNatDependencyWorkflow(page, viewport);
            }
            if (screen.path === "/objects") {
              await assertObjectsZoneInterfaceWorkflow(page, viewport);
              await assertObjectsGenericLifecycleParity(page, viewport);
              await assertSecurityProfileImpactWorkbench(page, viewport);
              await assertObjectsAppIdPortHintHygiene(page, viewport);
              await assertObjectsMissingRouteReview(page, viewport);
            }
            if (screen.path === "/inspection") {
              await assertInspectionWorkspace(page, viewport);
            }
            if (screen.path === "/proxy") {
              await assertProxyPlanProofWorkflow(page, viewport);
            }
            if (screen.path === "/netvpn") {
              await runSmokeStep("netvpn dynamic routing editors", () => assertNetvpnDynamicRoutingEditors(page, viewport));
              await runSmokeStep("netvpn invalid editor preflight", () => assertNetvpnVpnEditorInvalidPreflight(page, viewport));
              await runSmokeStep("netvpn static route IPsec lifecycle", () => assertNetvpnStaticRouteIpsecLifecycle(page, viewport));
              await runSmokeStep("netvpn WireGuard rollout workflow", () => assertNetvpnWireguardRolloutWorkflow(page, viewport));
              await runSmokeStep("netvpn tunnel workbench", () => assertNetvpnTunnelWorkbench(page, viewport));
            }
            if (screen.path === "/settings") {
              await runSmokeStep("settings telemetry export workflow", () => assertSettingsTelemetryExportWorkflow(page, viewport));
              await runSmokeStep("settings network and host-input workflow", () => assertSettingsNetworkHostInputWorkflow(page, viewport));
              await runSmokeStep("settings access posture", () => assertSettingsAccessPosture(page, viewport));
              await runSmokeStep("settings access lifecycle", () => assertSettingsAccessLifecycle(page, viewport));
            }
            await assertVisibleTextAndControlFit(page, viewport);
            if (viewport.name === "mobile" && screen.path === "/") {
              await assertMobileMenuRouteCollapse(page);
            }
            })());
            const status = failures.length > routeFailureStart ? "failed" : "passed";
            completeRouteResult(routeResult, status);
            completeSmokeCheckpoint(screenLabel, smokeProgress.total, status);
          } catch (err) {
            addRouteFailure(failures, routeResult, screen, viewport, err.message);
            completeRouteResult(routeResult, "failed");
            completeSmokeCheckpoint(screenLabel, smokeProgress.total, "failed");
          } finally {
            await page.close().catch(() => {});
          }
        }
      } finally {
        await context.close().catch(() => {});
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }

  await writeSmokeEvidenceManifest(artifactDir, failures);

  if (failures.length > 0) {
    throw new Error(webuiSmokeFailureMessage(failures));
  }
}

async function prepareArtifactDir() {
  const value = process.env.WEBUI_SMOKE_ARTIFACT_DIR || "";
  if (!value.trim()) return "";
  const artifactDir = resolve(value);
  await mkdir(artifactDir, { recursive: true });
  console.log(`webui visual smoke will write route screenshots to ${artifactDir}`);
  return artifactDir;
}

async function captureRouteScreenshot(page, artifactDir, screen, viewport) {
  if (!artifactDir) return;
  const route = screen.path === "/" ? "dashboard" : screen.path.replace(/^\/+/, "");
  const filename = `${viewport.name}-${safeArtifactName(route || screen.name)}.png`;
  await page.screenshot({ path: join(artifactDir, filename), fullPage: true });
  return filename;
}

function safeArtifactName(value) {
  return String(value || "route")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "route";
}

function filteredSmokeScreens() {
  const explicitPaths = String(process.env.WEBUI_SMOKE_PATHS || "").trim();
  const replayManifest = String(process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST || "").trim();
  const raw = explicitPaths || failedRoutePathsFromManifest(replayManifest).join(",");
  if (!raw) return screens;
  const byKey = new Map();
  for (const screen of screens) {
    const keys = [
      screen.path,
      screen.name,
      screen.name.toLowerCase(),
      screen.navTitle,
      screen.navTitle?.toLowerCase(),
    ].filter(Boolean);
    for (const key of keys) byKey.set(String(key), screen);
  }
  byKey.set("/dashboard", screens.find((screen) => screen.path === "/"));
  byKey.set("dashboard", screens.find((screen) => screen.path === "/"));

  const selected = [];
  const seen = new Set();
  const unknown = [];
  for (const item of raw.split(",").map((value) => value.trim()).filter(Boolean)) {
    const screen = byKey.get(item) || byKey.get(item.toLowerCase());
    if (!screen) {
      unknown.push(item);
      continue;
    }
    if (seen.has(screen.path)) continue;
    selected.push(screen);
    seen.add(screen.path);
  }
  if (unknown.length) {
    throw new Error(`WEBUI_SMOKE_PATHS included unknown route(s): ${unknown.join(", ")}`);
  }
  if (!selected.length) {
    throw new Error("WEBUI_SMOKE_PATHS did not select any known WebUI routes");
  }
  return selected;
}

function failedRoutePathsFromManifest(manifestPath) {
  if (!manifestPath) return [];
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(resolve(manifestPath), "utf8"));
  } catch (err) {
    throw new Error(`WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST could not be read: ${err.message || err}`);
  }
  return canonicalFailedRoutesFromManifest(parsed);
}

function canonicalFailedRoutesFromManifest(manifest) {
  const failed = new Set();
  for (const record of manifest?.failureRecords || []) {
    const route = record?.route || record?.path;
    if (route) failed.add(String(route));
  }
  for (const result of manifest?.routeResults || []) {
    if (result?.status === "failed" && result?.path) failed.add(String(result.path));
  }
  return screens
    .map((screen) => screen.path)
    .filter((path) => failed.has(path));
}

function plannedSmokeLabels(selectedScreens) {
  const labels = [];
  for (const viewport of viewports) {
    for (const screen of selectedScreens) {
      labels.push(`${viewport.name} ${screen.name} ${screen.path}`);
    }
  }
  return labels;
}

function beginRouteResult(screen, viewport) {
  const result = {
    name: screen.name,
    path: screen.path,
    viewport: { name: viewport.name, width: viewport.width, height: viewport.height },
    status: "running",
    startedAt: new Date().toISOString(),
    endedAt: "",
    elapsedMs: 0,
    screenshot: "",
    diagnostics: {},
    failures: [],
  };
  smokeRun.routeResults.push(result);
  return result;
}

function completeRouteResult(result, status) {
  if (!result || result.status !== "running") return;
  result.status = status;
  result.endedAt = new Date().toISOString();
  result.elapsedMs = Date.parse(result.endedAt) - Date.parse(result.startedAt);
}

function addRouteFailure(failures, routeResult, screen, viewport, detail) {
  const message = formatFailure(screen, viewport, detail);
  failures.push(message);
  const record = {
    route: screen.path,
    routeName: screen.name,
    viewport: viewport.name,
    width: viewport.width,
    detail: String(detail || ""),
    message,
    stage: smokeStage,
    active: smokeProgress.currentLabel,
    artifact: routeResult?.screenshot || "",
  };
  smokeRun.failureRecords.push(record);
  routeResult?.failures?.push(record);
}

function evidencePolicy(selectedScreens) {
  const selectedPaths = new Set(selectedScreens.map((screen) => screen.path));
  const fullRouteCount = screens.length;
  const routeCoverage = `${selectedPaths.size}/${fullRouteCount}`;
  const coversBroadRoutes = screens.every((screen) => selectedPaths.has(screen.path));
  const source = String(process.env.WEBUI_SMOKE_PATHS || "").trim()
    ? "WEBUI_SMOKE_PATHS"
    : String(process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST || "").trim()
      ? "WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST"
      : "default";
  const requestedRoutes = requestedSmokeRoutes();
  const missing = screens
    .filter((screen) => !selectedPaths.has(screen.path))
    .map((screen) => screen.path);
  return {
    mode: coversBroadRoutes ? "broad" : "targeted",
    routeCoverage,
    source,
    requestedRoutes,
    missingBroadRoutes: missing,
  };
}

function evidencePolicyLines(selectedScreens, policy = evidencePolicy(selectedScreens)) {
  if (policy.mode === "broad") {
    return [
      `evidence policy: mode=broad route_coverage=${policy.routeCoverage} source=${policy.source} budget=${formatDuration(totalTimeoutMs)} screen_timeout=${formatDuration(screenTimeoutMs)}`,
      "evidence policy detail: this is the broad route sweep; if it passes, targeted reruns may supplement repaired routes without weakening any route assertions.",
      "release evidence message: broad visual-smoke evidence is production-release evidence only after it is recorded through the repo-local release evidence tooling for the accepted source snapshot.",
    ];
  }

  return [
    `evidence policy: mode=targeted route_coverage=${policy.routeCoverage} source=${policy.source} budget=${formatDuration(totalTimeoutMs)} screen_timeout=${formatDuration(screenTimeoutMs)}`,
    `evidence policy detail: targeted route evidence must be paired with a successful broad sweep for the same source snapshot before it is treated as broad-plus-targeted evidence; missing_broad_routes=${policy.missingBroadRoutes.join(",")}`,
    "release evidence message: targeted visual-smoke evidence is repair diagnostics only unless paired with a same-snapshot successful broad run and recorded through release tooling.",
  ];
}

async function writeSmokeEvidenceManifest(artifactDir, failures) {
  if (!artifactDir) return;
  smokeRun.endedAt = new Date().toISOString();
  const routeDurationSummary = buildRouteDurationSummary(smokeRun.routeResults);
  const failureDiagnostics = buildFailureDiagnostics(failures);
  const operatorSummary = buildOperatorSummary(failures, routeDurationSummary, failureDiagnostics);
  const manifest = {
    schemaVersion: "phragma.webui.smoke.evidence.v1",
    result: failures.length ? "failed" : "passed",
    generatedBy: "openngfw-webui-visual-smoke",
    runner: {
      path: "e2e/webui-visual-smoke.mjs",
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
    },
    startedAt: smokeRun.startedAt,
    endedAt: smokeRun.endedAt,
    elapsedMs: Date.parse(smokeRun.endedAt) - Date.parse(smokeRun.startedAt),
    baseURL: smokeRun.baseURL,
    artifactDir,
    operatorSummary,
    evidencePolicy: {
      mode: smokeRun.mode,
      routeCoverage: smokeRun.routeCoverage,
      source: smokeRun.routeSource,
      broadRouteCount: screens.length,
      requestedRouteCount: smokeRun.requestedRoutes.length,
      requestedRoutes: smokeRun.requestedRoutes,
      selectedRouteCount: smokeRun.selectedRoutes.length,
      missingBroadRoutes: smokeRun.missingBroadRoutes,
      browserCoverage: "chromium",
      viewportCoverage: viewports.map((viewport) => viewport.name),
      releaseEvidenceMessage: releaseEvidenceMessage(smokeRun.mode),
      totalTimeoutMs,
      screenTimeoutMs,
      requireBrowser: envFlag("WEBUI_SMOKE_REQUIRE_BROWSER"),
      requireChangesUIApply,
      requireEbpfRuntimeEvidence,
    },
    viewports: viewports.map(({ name, width, height }) => ({ name, width, height })),
    routeOrder: smokeRun.routeOrder,
    selectedRoutes: smokeRun.selectedRoutes,
    progress: {
      plannedChecks: smokeProgress.total,
      completedChecks: smokeProgress.completed,
      completedLabels: smokeProgress.completedLabels,
      checkpoints: smokeProgress.checkpoints,
      remainingLabels: smokeProgress.planned.filter((label) => !new Set(smokeProgress.completedLabels).has(label)),
    },
    screenshots: smokeRun.screenshotFiles,
    routeDurationSummary,
    routeResults: smokeRun.routeResults,
    failureDiagnostics,
    failureRecords: smokeRun.failureRecords,
    failures,
  };
  const filename = "webui-smoke-evidence.json";
  smokeRun.manifestPath = join(artifactDir, filename);
  await writeFile(smokeRun.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`[webui-smoke] evidence manifest: ${smokeRun.manifestPath}`);
  printOperatorSummary(operatorSummary, routeDurationSummary, failureDiagnostics);
}

function releaseEvidenceMessage(mode) {
  if (mode === "broad") {
    return "Broad route sweep evidence may support production release only after source-control acceptance and repo-local release evidence recording.";
  }
  return "Targeted route evidence is diagnostic repair evidence and must be paired with a same-snapshot successful broad sweep before broad-plus-targeted release claims.";
}

function webuiSmokeFailureMessage(failures) {
  const routeDurationSummary = buildRouteDurationSummary(smokeRun.routeResults);
  const failureDiagnostics = buildFailureDiagnostics(failures);
  const failedRoutes = smokeRun.routeResults
    .filter((result) => result.status === "failed")
    .map((result) => `${result.viewport.name}:${result.path}`)
    .join(", ");
  const slowRoutes = routeDurationSummary.slowestRoutes
    .slice(0, 5)
    .map((route) => `${route.path} max=${route.maxElapsed} avg=${route.avgElapsed}`)
    .join("; ");
  const lines = [
    "WebUI visual smoke failed.",
    `evidence policy: mode=${smokeRun.mode || "unknown"} route_coverage=${smokeRun.routeCoverage || "unknown"} source=${smokeRun.routeSource || "unknown"}`,
    `route checks: passed=${failureDiagnostics.passedChecks} failed=${failureDiagnostics.failedChecks} incomplete=${failureDiagnostics.incompleteChecks}`,
    `route order: ${(smokeRun.routeOrder || []).join(",") || "<not selected>"}`,
    smokeRun.missingBroadRoutes?.length ? `missing broad routes: ${smokeRun.missingBroadRoutes.join(",")}` : "missing broad routes: none",
    failedRoutes ? `failed route checks: ${failedRoutes}` : "",
    slowRoutes ? `slow route summary: ${slowRoutes}` : "",
    smokeRun.manifestPath ? `evidence manifest: ${smokeRun.manifestPath}` : "",
    `progress: ${smokeProgressSummary()}`,
    releaseEvidenceMessage(smokeRun.mode),
    ...failures,
  ];
  return lines.filter(Boolean).join("\n");
}

function requestedSmokeRoutes() {
  const raw = String(process.env.WEBUI_SMOKE_PATHS || "").trim();
  if (!raw) {
    const replayRoutes = failedRoutePathsFromManifest(String(process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST || "").trim());
    return replayRoutes.length ? replayRoutes : screens.map((screen) => screen.path);
  }
  return raw.split(",").map((value) => value.trim()).filter(Boolean);
}

function buildRouteDurationSummary(routeResults = []) {
  const groups = new Map();
  for (const result of routeResults) {
    const path = result.path || "<unknown>";
    const current = groups.get(path) || {
      name: result.name || path,
      path,
      checks: 0,
      passed: 0,
      failed: 0,
      running: 0,
      totalElapsedMs: 0,
      maxElapsedMs: 0,
      minElapsedMs: Number.POSITIVE_INFINITY,
      slowestViewport: "",
      screenshots: [],
      diagnostics: {
        consoleErrors: 0,
        httpFailures: 0,
        criticalResourceFailures: 0,
        maxOverflow: 0,
      },
    };
    const elapsedMs = Math.max(0, Number(result.elapsedMs) || 0);
    current.checks += 1;
    current.totalElapsedMs += elapsedMs;
    if (result.status === "passed") current.passed += 1;
    else if (result.status === "failed") current.failed += 1;
    else current.running += 1;
    if (elapsedMs > current.maxElapsedMs) {
      current.maxElapsedMs = elapsedMs;
      current.slowestViewport = result.viewport?.name || "";
    }
    current.minElapsedMs = Math.min(current.minElapsedMs, elapsedMs);
    if (result.screenshot) current.screenshots.push({ viewport: result.viewport?.name || "", file: result.screenshot });
    current.diagnostics.consoleErrors += Number(result.diagnostics?.consoleErrorCount) || 0;
    current.diagnostics.httpFailures += Number(result.diagnostics?.httpFailureCount) || 0;
    current.diagnostics.criticalResourceFailures += Number(result.diagnostics?.criticalResourceFailureCount) || 0;
    current.diagnostics.maxOverflow = Math.max(current.diagnostics.maxOverflow, Number(result.diagnostics?.overflow) || 0);
    groups.set(path, current);
  }
  const perRoute = [...groups.values()].map((item) => {
    const avgElapsedMs = item.checks ? Math.round(item.totalElapsedMs / item.checks) : 0;
    const minElapsedMs = Number.isFinite(item.minElapsedMs) ? item.minElapsedMs : 0;
    return {
      name: item.name,
      path: item.path,
      checks: item.checks,
      passed: item.passed,
      failed: item.failed,
      running: item.running,
      totalElapsedMs: item.totalElapsedMs,
      totalElapsed: formatDuration(item.totalElapsedMs),
      avgElapsedMs,
      avgElapsed: formatDuration(avgElapsedMs),
      minElapsedMs,
      minElapsed: formatDuration(minElapsedMs),
      maxElapsedMs: item.maxElapsedMs,
      maxElapsed: formatDuration(item.maxElapsedMs),
      slowestViewport: item.slowestViewport,
      screenshots: item.screenshots,
      diagnostics: item.diagnostics,
    };
  }).sort((a, b) => screens.findIndex((screen) => screen.path === a.path) - screens.findIndex((screen) => screen.path === b.path));
  const slowestRoutes = [...perRoute]
    .sort((a, b) => b.maxElapsedMs - a.maxElapsedMs || b.avgElapsedMs - a.avgElapsedMs || a.path.localeCompare(b.path))
    .slice(0, 8);
  const totalElapsedMs = perRoute.reduce((sum, item) => sum + item.totalElapsedMs, 0);
  return {
    totalRouteElapsedMs: totalElapsedMs,
    totalRouteElapsed: formatDuration(totalElapsedMs),
    routeCount: perRoute.length,
    viewportCount: viewports.length,
    slowRouteThresholdMs: Math.max(screenTimeoutMs * 0.75, 1),
    slowestRoutes,
    perRoute,
  };
}

function buildFailureDiagnostics(failures = []) {
  const completedLabels = new Set(smokeProgress.completedLabels);
  const failedChecks = smokeRun.routeResults.filter((result) => result.status === "failed");
  const passedChecks = smokeRun.routeResults.filter((result) => result.status === "passed");
  const runningChecks = smokeRun.routeResults.filter((result) => result.status === "running");
  const remainingLabels = smokeProgress.planned.filter((label) => !completedLabels.has(label));
  const failedRouteChecks = failedChecks.map((result) => ({
    route: result.path,
    routeName: result.name,
    viewport: result.viewport?.name || "",
    elapsedMs: result.elapsedMs,
    elapsed: formatDuration(result.elapsedMs),
    screenshot: result.screenshot || "",
    failureMessages: (result.failures || []).map((failure) => failure.detail || failure.message).filter(Boolean),
    diagnostics: result.diagnostics || {},
  }));
  return {
    failed: failures.length > 0,
    failureCount: failures.length,
    passedChecks: passedChecks.length,
    failedChecks: failedChecks.length,
    runningChecks: runningChecks.length,
    incompleteChecks: remainingLabels.length,
    failedRoutes: [...new Set(failedChecks.map((result) => result.path))],
    failedRouteChecks,
    firstFailure: smokeRun.failureRecords[0] || null,
    remainingLabels,
    recentProgress: smokeProgress.checkpoints,
    progressSummary: smokeProgressSummary(),
  };
}

function buildOperatorSummary(failures, routeDurationSummary, failureDiagnostics) {
  const elapsedMs = smokeRun.endedAt ? Date.parse(smokeRun.endedAt) - Date.parse(smokeRun.startedAt) : 0;
  const result = failures.length ? "failed" : "passed";
  const slowestRoutes = routeDurationSummary.slowestRoutes.slice(0, 5).map((route) => ({
    path: route.path,
    name: route.name,
    maxElapsedMs: route.maxElapsedMs,
    maxElapsed: route.maxElapsed,
    avgElapsedMs: route.avgElapsedMs,
    avgElapsed: route.avgElapsed,
    slowestViewport: route.slowestViewport,
  }));
  return {
    result,
    conclusion: operatorConclusion(result, failureDiagnostics),
    mode: smokeRun.mode || "unknown",
    routeCoverage: smokeRun.routeCoverage || "unknown",
    selectedRouteCount: smokeRun.selectedRoutes.length,
    requestedRouteCount: smokeRun.requestedRoutes.length,
    broadRouteCount: screens.length,
    viewportCount: viewports.length,
    plannedChecks: smokeProgress.total,
    completedChecks: smokeProgress.completed,
    passedChecks: failureDiagnostics.passedChecks,
    failedChecks: failureDiagnostics.failedChecks,
    incompleteChecks: failureDiagnostics.incompleteChecks,
    screenshotCount: smokeRun.screenshotFiles.length,
    elapsedMs,
    elapsed: formatDuration(elapsedMs),
    slowestRoutes,
    releaseEvidenceMessage: releaseEvidenceMessage(smokeRun.mode),
  };
}

function operatorConclusion(result, failureDiagnostics) {
  if (result !== "passed") {
    return "Not release-adjacent: investigate failed route checks before using this run as continuation evidence.";
  }
  if (smokeRun.mode !== "broad") {
    return "Targeted repair evidence only: pair with a same-snapshot successful broad route sweep before release-adjacent use.";
  }
  if (failureDiagnostics.incompleteChecks > 0) {
    return "Not complete: broad route selection did not finish every planned viewport check.";
  }
  return "Broad route sweep passed every selected viewport check; treat as continuation evidence until repo-local release evidence recording accepts the source snapshot.";
}

function printOperatorSummary(operatorSummary, routeDurationSummary, failureDiagnostics) {
  console.log(`[webui-smoke] summary: result=${operatorSummary.result} mode=${operatorSummary.mode} route_coverage=${operatorSummary.routeCoverage} checks=${operatorSummary.passedChecks}/${operatorSummary.plannedChecks} elapsed=${operatorSummary.elapsed}`);
  console.log(`[webui-smoke] summary: requested_routes=${operatorSummary.requestedRouteCount} canonical_routes=${operatorSummary.selectedRouteCount} screenshots=${operatorSummary.screenshotCount}`);
  const slowRoutes = routeDurationSummary.slowestRoutes
    .slice(0, 5)
    .map((route) => `${route.path} max=${route.maxElapsed} avg=${route.avgElapsed} viewport=${route.slowestViewport || "unknown"}`)
    .join("; ");
  console.log(`[webui-smoke] slow routes: ${slowRoutes || "none"}`);
  if (failureDiagnostics.failedRouteChecks.length) {
    const failed = failureDiagnostics.failedRouteChecks
      .slice(0, 8)
      .map((item) => `${item.viewport}:${item.route} ${item.elapsed}`)
      .join("; ");
    console.log(`[webui-smoke] failed route checks: ${failed}`);
  }
  console.log(`[webui-smoke] release note: ${operatorSummary.releaseEvidenceMessage}`);
}

async function runSmokeRunnerSelfCheck() {
  const originalPaths = process.env.WEBUI_SMOKE_PATHS;
  const originalReplayManifest = process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST;
  try {
    delete process.env.WEBUI_SMOKE_PATHS;
    delete process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST;
    const broad = filteredSmokeScreens();
    const broadPolicy = evidencePolicy(broad);
    assertSelfCheck(broadPolicy.mode === "broad", "default smoke route selection should be broad");
    assertSelfCheck(broad.length === screens.length, "default smoke route selection should include every declared route");
    assertSelfCheck(broad.length === 19, "desktop enterprise smoke should cover the 19 canonical navigation routes");
    assertSelfCheck(plannedSmokeLabels(broad).length === screens.length * viewports.length, "planned labels should cover route x viewport checks");
    const appNavPaths = appNavRoutePaths();
    const smokePaths = screens.map((screen) => screen.path);
    assertSelfCheck(!smokePaths.includes("/readiness"), "standalone Readiness should not be a canonical smoke route");
    assertSelfCheck(appNavPaths.join(",") === smokePaths.join(","), `smoke route list should match app NAV; app=${appNavPaths.join(",")} smoke=${smokePaths.join(",")}`);

    process.env.WEBUI_SMOKE_PATHS = "/settings,/rules,/settings,dashboard";
    const targeted = filteredSmokeScreens();
    const targetedPolicy = evidencePolicy(targeted);
    assertSelfCheck(targeted.map((screen) => screen.path).join(",") === "/settings,/rules,/", "targeted route order and de-duplication should follow WEBUI_SMOKE_PATHS");
    assertSelfCheck(targetedPolicy.mode === "targeted", "partial route selection should be targeted");
    assertSelfCheck(targetedPolicy.requestedRoutes.join(",") === "/settings,/rules,/settings,dashboard", "policy should preserve requested route entries before canonical de-duplication");
    assertSelfCheck(targetedPolicy.missingBroadRoutes.includes("/traffic"), "targeted policy should list missing broad routes");
    assertSelfCheck(evidencePolicyLines(targeted, targetedPolicy).some((line) => line.includes("targeted visual-smoke evidence is repair diagnostics")), "targeted policy should print release evidence warning");

    process.env.WEBUI_SMOKE_PATHS = "/,/dashboard,/setup,/rules,/objects,/nat,/inspection,/threats,/traffic,/logs,/troubleshoot,/performance,/investigation,/fleet,/intel,/netvpn,/proxy,/compliance,/changes,/settings";
    const enterpriseAliasBroad = filteredSmokeScreens();
    const enterpriseAliasPolicy = evidencePolicy(enterpriseAliasBroad);
    assertSelfCheck(enterpriseAliasBroad.length === screens.length, "enterprise path list should de-duplicate dashboard alias into the full broad route set");
    assertSelfCheck(enterpriseAliasPolicy.mode === "broad", "enterprise path list with dashboard alias should remain broad evidence");
    assertSelfCheck(enterpriseAliasPolicy.routeCoverage === `${screens.length}/${screens.length}`, "enterprise path list should report complete route coverage");
    assertSelfCheck(enterpriseAliasPolicy.missingBroadRoutes.length === 0, "enterprise path list should have no missing broad routes");

    const routeDurationSummary = buildRouteDurationSummary([
      { name: "Settings", path: "/settings", viewport: { name: "desktop" }, status: "passed", elapsedMs: 1200, screenshot: "desktop-settings.png", diagnostics: { overflow: 0 } },
      { name: "Settings", path: "/settings", viewport: { name: "mobile" }, status: "passed", elapsedMs: 2400, screenshot: "mobile-settings.png", diagnostics: { overflow: 1 } },
      { name: "Rules", path: "/rules", viewport: { name: "desktop" }, status: "failed", elapsedMs: 800, screenshot: "desktop-rules.png", diagnostics: { consoleErrorCount: 1 } },
    ]);
    const settingsSummary = routeDurationSummary.perRoute.find((route) => route.path === "/settings");
    assertSelfCheck(settingsSummary?.checks === 2 && settingsSummary.avgElapsedMs === 1800, "route duration summary should aggregate route checks across viewports");
    assertSelfCheck(routeDurationSummary.slowestRoutes[0]?.path === "/settings", "slow route summary should rank routes by max elapsed time");

    delete process.env.WEBUI_SMOKE_PATHS;
    const replayManifest = join(tmpdir(), `webui-smoke-replay-self-check-${process.pid}.json`);
    await writeFile(replayManifest, JSON.stringify({
      failureRecords: [
        { route: "/settings" },
        { route: "/rules" },
        { route: "/settings" },
      ],
      routeResults: [
        { path: "/traffic", status: "failed" },
        { path: "/nat", status: "passed" },
      ],
    }), "utf8");
    process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST = replayManifest;
    const replay = filteredSmokeScreens();
    const replayPolicy = evidencePolicy(replay);
    assertSelfCheck(replay.map((screen) => screen.path).join(",") === "/rules,/traffic,/settings", "replay manifest route selection should follow canonical route order and de-duplicate failed paths");
    assertSelfCheck(replayPolicy.source === "WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST", "replay manifest should identify evidence source");
    assertSelfCheck(replayPolicy.requestedRoutes.join(",") === "/rules,/traffic,/settings", "replay manifest should drive requested route accounting");
    await rm(replayManifest, { force: true });
    delete process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST;

	    process.env.WEBUI_SMOKE_PATHS = "/settings,/not-a-route";
	    let unknownFailed = false;
	    try {
	      filteredSmokeScreens();
	    } catch (err) {
	      unknownFailed = /unknown route/.test(String(err?.message || err));
	    }
	    assertSelfCheck(unknownFailed, "unknown WEBUI_SMOKE_PATHS entries should fail fast");
	    assertSelfCheck(isGenericOperatorActionLabel("Copy"), "generic action predicate should catch exact labels");
	    assertSelfCheck(isGenericOperatorActionLabel("Copy summary"), "generic action predicate should catch verb-led labels");
	    assertSelfCheck(isGenericOperatorActionLabel("System evidence"), "generic action predicate should catch operational noun-action labels");
	    assertSelfCheck(getOperatorActionViolations([
	      { label: "Copy", title: "", ariaLabel: "", hasStableHook: true },
	    ]).length === 1, "generic action guard should reject missing title and aria intent");
	    assertSelfCheck(getOperatorActionViolations([
	      { label: "Copy", title: "Copy summary", ariaLabel: "Copy summary", hasStableHook: false },
	    ]).length === 1, "generic action guard should reject missing stable hook");
	    assertSelfCheck(getOperatorActionViolations([
	      { label: "Copy", title: "Copy summary", ariaLabel: "Copy summary", hasStableHook: true },
	    ]).length === 0, "generic action guard should accept stable hook plus title and aria intent");
	    assertSelfCheck(!dashboardTelemetryDisclosureIssue(false, "", ""), "complete Dashboard telemetry may omit the paging disclosure");
	    assertSelfCheck(!dashboardTelemetryDisclosureIssue(true, "limited", "Some telemetry is paged. 2/12 alerts and 1/1 flows shown."), "paged Dashboard telemetry should accept the production disclosure");
	    assertSelfCheck(Boolean(dashboardTelemetryDisclosureIssue(true, "", "")), "paged Dashboard telemetry should reject a missing disclosure");
	    assertSelfCheck(Boolean(dashboardTelemetryDisclosureIssue(false, "complete", "Telemetry summaries are current.")), "Dashboard should not render the paging disclosure for complete telemetry");
	    console.log("[webui-smoke] self-check passed: route selection, ordering, policy messaging, duration summaries, action-accessibility guard, and unknown-route diagnostics");
	  } finally {
    if (originalPaths == null) {
      delete process.env.WEBUI_SMOKE_PATHS;
    } else {
      process.env.WEBUI_SMOKE_PATHS = originalPaths;
    }
    if (originalReplayManifest == null) {
      delete process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST;
    } else {
      process.env.WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST = originalReplayManifest;
    }
  }
}

function assertSelfCheck(condition, message) {
  if (!condition) throw new Error(`self-check failed: ${message}`);
}

function appNavRoutePaths() {
  const appSource = readFileSync(join(repoRoot, "internal/webui/static/js/app.js"), "utf8");
  const navStart = appSource.indexOf("const NAV = [");
  const navEnd = appSource.indexOf("];", navStart);
  if (navStart < 0 || navEnd <= navStart) {
    throw new Error("could not locate NAV route list in internal/webui/static/js/app.js");
  }
  return [...appSource.slice(navStart, navEnd).matchAll(/\{\s*path:\s*"([^"]+)"/g)].map((match) => match[1]);
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "0ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m${String(remainder).padStart(2, "0")}s`;
}

async function assertAccessibleOperatorChrome(page, viewport) {
  const chrome = await page.evaluate((viewportName) => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    const unlabeledIconButtons = [...document.querySelectorAll(".icon-btn")]
      .filter(visible)
      .filter((el) => !(el.getAttribute("aria-label") || el.getAttribute("title") || el.textContent || "").trim())
      .map((el) => el.id || el.className || el.outerHTML.slice(0, 80));
    const operatorControls = [...document.querySelectorAll([
      "button.btn",
      "a.btn",
      "button.linklike",
      "a.linklike",
      ".linklike[role='button']",
      ".profile-option",
      ".rule-hygiene-chip",
      ".seg button",
      ".chip button",
      "[role='button']",
    ].join(","))]
      .filter(visible)
      .map((el) => {
        const label = (el.textContent || "").replace(/\s+/g, " ").trim();
        const hasStableHook = Boolean(el.id || Object.keys(el.dataset || {}).length);
        const hasAccessibleIntent = Boolean((el.getAttribute("title") || "").trim() && (el.getAttribute("aria-label") || "").trim());
        return { label, title: el.getAttribute("title") || "", ariaLabel: el.getAttribute("aria-label") || "", hasStableHook, hasAccessibleIntent, html: el.outerHTML.slice(0, 120) };
      })
    const mobileTargets = viewportName === "mobile"
      ? ["#menu-toggle", "#open-palette", "#open-diagnostics", "#open-automation", "#theme-toggle"].map((selector) => {
          const el = document.querySelector(selector);
          const rect = el?.getBoundingClientRect();
          return { selector, width: rect?.width || 0, height: rect?.height || 0, visible: visible(el) };
        })
      : [];
    return { unlabeledIconButtons, operatorControls, mobileTargets };
  }, viewport.name);

  if (chrome.unlabeledIconButtons.length) {
    throw new Error(`visible icon controls were missing accessible names: ${chrome.unlabeledIconButtons.join(", ")}`);
  }
  const operatorActionViolations = getOperatorActionViolations(chrome.operatorControls);
  if (operatorActionViolations.length) {
    throw new Error(`visible generic operator actions need stable hooks plus title/aria intent: ${operatorActionViolations.join("; ")}`);
  }
  const smallTargets = chrome.mobileTargets.filter((target) => target.visible && (target.width < 36 || target.height < 36));
  if (smallTargets.length) {
    throw new Error(`mobile chrome tap targets below 36px: ${smallTargets.map((target) => `${target.selector} ${Math.round(target.width)}x${Math.round(target.height)}`).join(", ")}`);
  }
}

function getOperatorActionViolations(items = []) {
  return items
    .filter((item) => {
      const hasAccessibleIntent = Boolean(item.hasAccessibleIntent || (String(item.title || "").trim() && String(item.ariaLabel || "").trim()));
      return isGenericOperatorActionLabel(item.label) && (!item.hasStableHook || !hasAccessibleIntent);
    })
    .map((item) => `${item.label || "<empty>"} title=${item.title || "<missing>"} aria=${item.ariaLabel || "<missing>"} stable=${Boolean(item.hasStableHook)}`);
}

function isGenericOperatorActionLabel(label = "") {
  const normalized = String(label || "").replace(/\s+/g, " ").trim().toLowerCase();
  if (!normalized) return false;
  const exact = new Set([
    "open",
    "copy",
    "apply",
    "clear",
    "pin",
    "download",
    "review",
    "stage",
    "validate",
    "refresh",
    "retry",
    "close",
    "reset",
    "candidate",
    "system evidence",
    "preview support bundle",
  ]);
  if (exact.has(normalized)) return true;
  return /^(open|copy|apply|clear|pin|download|export|review|stage|validate|refresh|retry|close|reset|preview)\b/.test(normalized);
}

async function assertDashboardEvidenceConsole(page, viewport) {
  await ensureSeededInvestigationTelemetry();
  const report = await page.evaluate((seed) => {
    const content = document.querySelector("#content");
    const text = content?.textContent || "";
    const tableState = (selector, rowSelector) => {
      const table = document.querySelector(selector);
      const row = table?.querySelector(rowSelector || "tbody tr");
      const labels = [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
      const mobileLabelsRendered = window.innerWidth > 820 || [...(row?.querySelectorAll("td") || [])].every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      });
      return {
        present: Boolean(table),
        className: table?.className || "",
        labels,
        rowKey: row ? Object.entries(row.dataset || {}).map(([key, value]) => `${key}:${value}`).join("|") : "",
        mobileLabelsRendered,
        overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      };
    };
    const severityLayout = document.querySelector(".dashboard-severity-layout");
    const severityRect = severityLayout?.getBoundingClientRect?.();
    const telemetryScope = document.querySelector("[data-dashboard-telemetry-scope]");
    const metricFoot = (label) => {
      const card = [...document.querySelectorAll(".phr-metric-card")]
        .find((candidate) => candidate.querySelector(".stat-label")?.textContent?.trim() === label);
      return (card?.querySelector(".stat-foot")?.textContent || "").replace(/\s+/g, " ").trim();
    };
    const alertFoot = metricFoot("Threats (recent)");
    const flowFoot = metricFoot("Traffic (recent)");
    const telemetryPaged = [alertFoot, flowFoot].some((foot) => /^\d+\/(?:\d+|many) shown$/i.test(foot));
    const severityLegend = [...document.querySelectorAll("[data-dashboard-severity-legend]")].map((el) => {
      const swatch = el.querySelector(".dashboard-severity-swatch");
      const rect = el.getBoundingClientRect();
      return {
        severity: el.dataset.dashboardSeverityLegend || "",
        className: el.className || "",
        swatchClassName: swatch?.className || "",
        href: el.getAttribute("href") || "",
        text: (el.textContent || "").replace(/\s+/g, " ").trim(),
        width: rect.width,
        height: rect.height,
      };
    });
    return {
      hasTopApplications: text.includes("Top applications"),
      hasTLSFallback: /\bTLS\b/.test(text),
      hasRecentThreats: text.includes("Recent threats"),
      hasSignature: text.includes(seed.signature),
      hasSignatureId: text.includes(String(seed.signatureId)) || text.includes(`SID ${seed.signatureId}`),
      hasRecentChangesEmptyState: text.includes("No versions yet"),
      telemetryPaged,
      telemetryAlertFoot: alertFoot,
      telemetryFlowFoot: flowFoot,
      telemetryScope: telemetryScope?.dataset?.dashboardTelemetryScope || "",
      telemetryScopeText: (telemetryScope?.textContent || "").replace(/\s+/g, " ").trim(),
      engineTable: tableState(".dashboard-engine-table", "[data-dashboard-engine]"),
      threatTable: tableState(".dashboard-threat-table", "[data-dashboard-threat]"),
      versionTable: tableState(".dashboard-version-table", "[data-dashboard-version]"),
      severityLegend,
      severityLayoutClass: severityLayout?.className || "",
      severityOverflow: severityLayout && severityRect ? Math.max(0, Math.ceil(severityRect.right - window.innerWidth), Math.ceil(0 - severityRect.left), Math.ceil(severityLayout.scrollWidth - severityLayout.clientWidth)) : 0,
    };
  }, investigationSeed);
  if (!report.hasTopApplications || !report.hasTLSFallback) {
    throw new Error(`Dashboard did not render seeded application fallback evidence at ${viewport.name}: ${JSON.stringify(report)}`);
  }
  if (!report.hasRecentThreats || (!report.hasSignature && !report.hasSignatureId)) {
    throw new Error(`Dashboard did not render seeded threat evidence at ${viewport.name}: ${JSON.stringify(report)}`);
  }
  const telemetryDisclosureIssue = dashboardTelemetryDisclosureIssue(report.telemetryPaged, report.telemetryScope, report.telemetryScopeText);
  if (telemetryDisclosureIssue) {
    throw new Error(`Dashboard telemetry paging disclosure was invalid at ${viewport.name}: ${telemetryDisclosureIssue}; ${JSON.stringify(report)}`);
  }
  if (!report.severityLayoutClass.includes("dashboard-severity-layout") || report.severityOverflow > 2) {
    throw new Error(`Dashboard severity chart layout overflowed or missed design classes at ${viewport.name}: ${JSON.stringify(report)}`);
  }
  const expectedSeverityLegend = ["1", "2", "3", "4"];
  const missingSeverityLegend = expectedSeverityLegend.filter((severity) => !report.severityLegend.some((item) =>
    item.severity === severity &&
    item.swatchClassName.includes("dashboard-severity-swatch") &&
    item.swatchClassName.includes(`severity-${severity}`) &&
    item.href.includes(`/threats?sev=${severity}`)));
  if (missingSeverityLegend.length) {
    throw new Error(`Dashboard severity legend missed classed link(s) at ${viewport.name}: ${missingSeverityLegend.join(", ")} ${JSON.stringify(report.severityLegend)}`);
  }
  if (viewport.name === "mobile") {
    const cramped = report.severityLegend.filter((item) => item.width < 42 || item.height < 24);
    if (cramped.length) {
      throw new Error(`Dashboard severity legend mobile target(s) too small at ${viewport.name}: ${JSON.stringify(cramped)}`);
    }
  }
  assertDashboardTable(report.engineTable, viewport, "capability coverage", ["Capability", "State", "Detail"], "dashboardEngine");
  assertDashboardTable(report.threatTable, viewport, "recent threats", ["Severity", "Threat", "Source", "Time"], "dashboardThreat");
  if (report.versionTable.present) {
    assertDashboardTable(report.versionTable, viewport, "recent changes", ["Version", "Comment", "Actor", "Time"], "dashboardVersion");
  } else if (!report.hasRecentChangesEmptyState) {
    throw new Error(`Dashboard recent changes rendered neither table nor empty state at ${viewport.name}: ${JSON.stringify(report)}`);
  }
  await assertDashboardNetvpnRuntimeReviewRoute(page, viewport);
}

function dashboardTelemetryDisclosureIssue(paged = false, scope = "", text = "") {
  if (!paged && !scope) return "";
  if (!paged) return `complete telemetry unexpectedly rendered disclosure state ${JSON.stringify(scope)}`;
  if (scope !== "limited") return `paged telemetry rendered disclosure state ${JSON.stringify(scope || "missing")}`;
  if (!/Some telemetry is paged\./.test(String(text || ""))) return "limited telemetry omitted the paging explanation";
  return "";
}

async function assertDashboardNetvpnRuntimeReviewRoute(page, viewport) {
  const link = page.locator('[data-dashboard-engine-action="netvpn"]').first();
  const count = await link.count();
  if (!count) {
    throw new Error(`Dashboard did not expose a Routing/VPN runtime-review owner link at ${viewport.name}`);
  }
  const href = await link.getAttribute("href");
  if (!href || !href.startsWith("#/netvpn?") || !href.includes("drawer=runtime-review")) {
    throw new Error(`Dashboard Routing/VPN owner link did not target runtime-review at ${viewport.name}: ${href || "<none>"}`);
  }
  await link.click();
  await waitForRouteReady(page, "/netvpn");
  await page.waitForSelector('[data-netvpn-runtime-review="true"]', { timeout: 10000 });
  const state = await collectRouteBackedDrawerState(page, '[data-netvpn-runtime-review="true"]');
  if (!/Routing & VPN runtime review/.test(state.title) || !state.text.includes("protected-subnet traffic")) {
    throw new Error(`Dashboard Routing/VPN runtime-review route did not restore drawer at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  await page.click('#drawer:not([hidden]) [data-netvpn-action="close-runtime-review"]');
  await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])") && (location.hash === "#/netvpn" || location.hash === ""), null, { timeout: 5000 });
  await page.evaluate(() => { location.hash = "#/"; });
  await waitForRouteReady(page, "/");
}

function assertDashboardTable(state, viewport, label, expectedLabels, rowDatasetKey) {
  if (!state.present) {
    throw new Error(`Dashboard ${label} table missing at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.className.includes("responsive-evidence")) {
    throw new Error(`Dashboard ${label} table missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`Dashboard ${label} table overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const missingLabels = expectedLabels.filter((item) => !state.labels.includes(item));
  if (missingLabels.length) {
    throw new Error(`Dashboard ${label} table missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (!state.rowKey.includes(rowDatasetKey)) {
    throw new Error(`Dashboard ${label} table missing row hook at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`Dashboard ${label} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertDashboardAutomationContext(page, viewport) {
  const copied = await assertAutomationContextDrawer(page, viewport, "dashboard automation context", [
    "/v1/system/status",
    "/v1/system/identity",
    "/v1/candidate/status",
    "/v1/policy?source=POLICY_SOURCE_RUNNING",
    "/v1/alerts?limit=500",
    "/v1/flows?limit=500",
    "/v1/versions?limit=8",
    "/v1/intel/feeds",
    "ngfwctl status",
    "ngfwctl whoami",
    "ngfwctl status # routing-vpn",
    "ngfwctl policy status --json",
    "ngfwctl alerts --limit 50",
    "ngfwctl flows --limit 50",
    "ngfwctl versions --limit 8",
  ]);
  for (const required of [
    "GET /v1/system/status",
    "GET /v1/system/identity",
    "GET /v1/candidate/status",
    "GET /v1/policy?source=POLICY_SOURCE_RUNNING",
    "GET /v1/alerts?limit=500",
    "GET /v1/flows?limit=500",
    "GET /v1/versions?limit=8",
    "GET /v1/intel/feeds",
  ]) {
    if (!copied.includes(required)) {
      throw new Error(`Dashboard automation copied context missing ${required} at ${viewport.name}`);
    }
  }
  const leaked = /release\/evidence|manifestPath|evidenceDir|dirtySourcePaths|next_command|make release-|go run \.\/cmd\/ngfwrelease\//i.test(copied);
  if (leaked) {
    throw new Error(`Dashboard automation context leaked detailed release evidence at ${viewport.name}`);
  }
}

async function assertFleetTemplatesWorkspace(page, viewport) {
  await page.waitForFunction(() => {
    const root = document.querySelector("[data-fleet-workspace='true']");
    const text = root?.textContent || "";
    return Boolean(root) &&
      text.includes("Fleet operations") &&
      text.includes("Managed appliances") &&
      text.includes("Template and drift") &&
      text.includes("Evidence sources");
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const root = document.querySelector("[data-fleet-workspace='true']");
    const tableState = (selector) => {
      const table = root?.querySelector(selector);
      const firstRow = table?.querySelector("tbody tr");
      return {
        exists: Boolean(table),
        className: table?.className || "",
        rowCount: table?.querySelectorAll("tbody tr").length || 0,
        labels: [...(firstRow?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || ""),
        mobileLabelsRendered: window.innerWidth > 820 || [...(firstRow?.querySelectorAll("td") || [])].every((cell) => {
          const before = getComputedStyle(cell, "::before").content || "";
          return before !== "none" && before !== "\"\"" && before.length > 2;
        }),
      };
    };
    return {
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      nodeCount: root?.querySelectorAll("[data-fleet-node]").length || 0,
      templateCount: root?.querySelectorAll("[data-fleet-template]").length || 0,
      evidenceCount: root?.querySelectorAll("[data-fleet-evidence]").length || 0,
      apiCli: Boolean(root?.querySelector("[data-fleet-action='api-cli']")),
      nodeTable: tableState(".fleet-node-table"),
      templateTable: tableState(".fleet-template-table"),
      evidenceTable: tableState(".fleet-evidence-table"),
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
  if (state.overflow > 2) {
    throw new Error(`Fleet workspace introduced horizontal overflow at ${viewport.name}: ${state.overflow}px`);
  }
  for (const [label, table, expected] of [
    ["node", state.nodeTable, ["Appliance", "Role", "Policy", "HA sync", "Runtime"]],
    ["template", state.templateTable, ["Template", "State", "Scope", "Action"]],
    ["evidence", state.evidenceTable, ["Evidence", "Source", "State"]],
  ]) {
    if (!table.exists || !table.className.includes("responsive-evidence") || table.rowCount < 1) {
      throw new Error(`Fleet ${label} table missing responsive structure at ${viewport.name}: ${JSON.stringify(table)}`);
    }
    const missing = expected.filter((item) => !table.labels.includes(item));
    if (missing.length) {
      throw new Error(`Fleet ${label} table missing labels ${missing.join(", ")} at ${viewport.name}: ${JSON.stringify(table)}`);
    }
    if (!table.mobileLabelsRendered) {
      throw new Error(`Fleet ${label} table mobile labels did not render at ${viewport.name}: ${JSON.stringify(table)}`);
    }
  }
  if (state.nodeCount < 1 || state.templateCount < 4 || state.evidenceCount < 4 || !state.apiCli) {
    throw new Error(`Fleet workspace missing expected hooks at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const required of ["Managed nodes", "Policy drift", "Content posture", "Fleet apply result custody", "local control plane"]) {
    if (!state.text.includes(required)) {
      throw new Error(`Fleet workspace missing ${required} at ${viewport.name}: ${state.text}`);
    }
  }
  await page.click("[data-fleet-action='api-cli']");
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "fleet API / CLI context", [
    "Fleet & templates",
    "/v1/system/status",
    "/v1/system/ha/status",
    "/v1/candidate/status",
    "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE",
    "/v1/system/support-bundle?versionLimit=100&auditLimit=300&eventLimit=500",
    "ngfwctl status",
    "ngfwctl policy status --json",
    "ngfwctl support-bundle --output-dir .",
    "multi-node discovery",
  ], ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `fleet API / CLI drawer ${viewport.name}`);
  await closeActiveDrawer(page);
  await assertFleetTemplatePreviewRoute(page, viewport);
  await assertFleetLifecycleDrillThrough(page, viewport);
}

async function assertFleetTemplatePreviewRoute(page, viewport) {
  await page.evaluate(() => { location.hash = "#/fleet?drawer=template-preview&template=ha"; });
  await waitForRouteReady(page, "/fleet");
  await page.waitForSelector('[data-fleet-template-preview="ha"]', { timeout: 10000 });
  let state = await collectRouteBackedDrawerState(page, '[data-fleet-template-preview="ha"]');
  if (!/preview/.test(state.title) || !state.text.includes("Opened from route state") || !state.text.includes("Local preview only")) {
    throw new Error(`Fleet template preview route did not restore HA drawer at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const apiHref = await page.locator('#drawer:not([hidden]) [data-fleet-template-action="api-cli"]').evaluate((button) => {
    const handlerRoute = button?.getAttribute("data-fleet-template-action") || "";
    return { handlerRoute, text: button?.textContent || "" };
  });
  if (apiHref.handlerRoute !== "api-cli" || !apiHref.text.includes("API / CLI")) {
    throw new Error(`Fleet template preview API/CLI control missing at ${viewport.name}: ${JSON.stringify(apiHref)}`);
  }
  await page.click('#drawer:not([hidden]) [data-fleet-template-action="close-preview"]');
  await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])") && (location.hash === "#/fleet" || location.hash === ""), null, { timeout: 5000 });

  await page.click('[data-fleet-template="edge-policy"] [data-fleet-template-action="preview"]');
  await page.waitForSelector('[data-fleet-template-preview="edge-policy"]', { timeout: 10000 });
  state = await collectRouteBackedDrawerState(page, '[data-fleet-template-preview="edge-policy"]');
  const hash = await page.evaluate(() => location.hash);
  const ownerHref = await page.locator('#drawer:not([hidden]) [data-fleet-template-action="open-changes"]').getAttribute("href");
  if (!/Edge policy template preview/.test(state.title) || !hash.includes("drawer=template-preview") || !hash.includes("template=edge-policy") || ownerHref !== "#/changes?tab=candidate") {
    throw new Error(`Fleet template preview click did not set shareable route at ${viewport.name}: ${JSON.stringify({ state, hash })}`);
  }
  await page.click('#drawer:not([hidden]) [data-fleet-template-action="open-changes"]');
  await waitForRouteReady(page, "/changes");
  await page.waitForSelector('[data-changes-tab="candidate"]', { timeout: 10000 });
  const ownerHash = await page.evaluate(() => location.hash);
  if (ownerHash !== "#/changes?tab=candidate") {
    throw new Error(`Fleet edge-policy preview owner route mismatch at ${viewport.name}: ${ownerHash || "<empty>"}`);
  }
}

async function assertFleetLifecycleDrillThrough(page, viewport) {
  await page.evaluate(() => { location.hash = "#/fleet"; });
  await waitForRouteReady(page, "/fleet");
  const expectedOwners = [
    { template: "edge-policy", href: "#/changes?tab=candidate", path: "/changes", hook: '[data-changes-tab="candidate"]' },
    { template: "content", href: "#/intel", path: "/intel", hook: "#content h1" },
    { template: "routing-vpn", href: "#/netvpn", path: "/netvpn", hook: '[data-netvpn-action="add-route"]' },
    { template: "ha", href: "#/fleet", path: "/fleet", hook: '[data-fleet-workspace="true"]' },
  ];
  const links = await page.evaluate(() => [...document.querySelectorAll('[data-fleet-template] [data-fleet-template-action="open"]')]
    .map((link) => ({
      template: link.closest("[data-fleet-template]")?.getAttribute("data-fleet-template") || "",
      href: link.getAttribute("href") || "",
      text: (link.textContent || "").replace(/\s+/g, " ").trim(),
    })));
  for (const owner of expectedOwners) {
    const link = links.find((item) => item.template === owner.template);
    if (link?.href !== owner.href) {
      throw new Error(`Fleet ${owner.template} owner route mismatch at ${viewport.name}: ${JSON.stringify({ expected: owner.href, link, links })}`);
    }
    await page.click(`[data-fleet-template="${owner.template}"] [data-fleet-template-action="open"]`);
    await waitForRouteReady(page, owner.path);
    await page.waitForSelector(owner.hook, { timeout: 30000 });
    const hash = await page.evaluate(() => location.hash);
    if (hash !== owner.href) {
      throw new Error(`Fleet ${owner.template} drill-through opened ${hash || "<empty>"} instead of ${owner.href} at ${viewport.name}`);
    }
    if (owner.path !== "/fleet") {
      await page.evaluate(() => { location.hash = "#/fleet"; });
      await waitForRouteReady(page, "/fleet");
      await page.waitForSelector('[data-fleet-workspace="true"]', { timeout: 10000 });
    }
  }
}

async function assertGlobalKeyboardFocusWorkflow(page, viewport) {
  await page.focus("#open-palette");
  await page.keyboard.press(process.platform === "darwin" ? "Meta+K" : "Control+K");
  await page.waitForSelector("#palette-scrim:not([hidden]) #palette-input", { timeout: 5000 });
  let state = await page.evaluate(() => ({
    activeId: document.activeElement?.id || "",
    expanded: document.querySelector("#palette-input")?.getAttribute("aria-expanded") || "",
    activeDescendant: document.querySelector("#palette-input")?.getAttribute("aria-activedescendant") || "",
    resultCount: document.querySelectorAll("#palette-results [role='option']").length,
  }));
  if (state.activeId !== "palette-input" || state.expanded !== "true" || state.activeDescendant !== "palette-option-0" || state.resultCount < 2) {
    throw new Error(`global palette focus state mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }

  await page.keyboard.press("ArrowDown");
  state = await page.evaluate(() => ({
    activeId: document.activeElement?.id || "",
    activeDescendant: document.querySelector("#palette-input")?.getAttribute("aria-activedescendant") || "",
  }));
  if (state.activeId !== "palette-input" || state.activeDescendant !== "palette-option-1") {
    throw new Error(`global palette arrow navigation mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }

  await page.keyboard.press("Tab");
  const paletteTabContained = await page.evaluate(() => {
    const scrim = document.querySelector("#palette-scrim");
    return Boolean(scrim && !scrim.hidden && scrim.contains(document.activeElement));
  });
  if (!paletteTabContained) {
    throw new Error(`global palette Tab escaped the dialog at ${viewport.name}`);
  }

  await page.keyboard.press("Escape");
  await page.waitForFunction(() => document.querySelector("#palette-scrim")?.hidden, null, { timeout: 5000 });
  state = await page.evaluate(() => ({
    activeId: document.activeElement?.id || "",
    expanded: document.querySelector("#palette-input")?.getAttribute("aria-expanded") || "",
    activeDescendant: document.querySelector("#palette-input")?.getAttribute("aria-activedescendant") || "",
  }));
  if (state.activeId !== "open-palette" || state.expanded !== "false" || state.activeDescendant) {
    throw new Error(`global palette close/focus-return mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }

  await page.click("#open-automation");
  await page.waitForSelector("#drawer:not([hidden])", { timeout: 5000 });
  state = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const focusables = [...(drawer?.querySelectorAll("a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex='-1'])") || [])];
    focusables.at(-1)?.focus();
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      role: drawer?.getAttribute("role") || "",
      modal: drawer?.getAttribute("aria-modal") || "",
      labelledby: drawer?.getAttribute("aria-labelledby") || "",
      activeInside: Boolean(drawer?.contains(document.activeElement)),
      focusableCount: focusables.length,
    };
  });
  if (state.role !== "dialog" || state.modal !== "true" || state.labelledby !== "drawer-title" || !state.activeInside || state.focusableCount < 2) {
    throw new Error(`global drawer accessibility state mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }

  await page.keyboard.press("Tab");
  const drawerTabContained = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return Boolean(drawer && drawer.contains(document.activeElement));
  });
  if (!drawerTabContained) {
    throw new Error(`global drawer Tab escaped the dialog at ${viewport.name}`);
  }

  await page.keyboard.press("Escape");
  await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])"), null, { timeout: 5000 });
  const drawerFocusReturned = await page.evaluate(() => document.activeElement?.id === "open-automation");
  if (!drawerFocusReturned) {
    throw new Error(`global drawer did not restore opener focus at ${viewport.name}`);
  }
}

async function assertGlobalDiagnosticConsoleWorkflow(page, viewport) {
  await closeDiagnosticConsoleIfOpen(page);
  await page.evaluate(() => {
    globalThis.__diagnosticSnapshotCopiedText = "";
    const writeText = async (text) => {
      globalThis.__diagnosticSnapshotCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });

  await page.click("#open-diagnostics");
  await waitForDiagnosticConsole(page);
  let state = await collectDiagnosticConsoleState(page);
  assertDiagnosticConsoleState(state, viewport, "toolbar");

  await clickDiagnosticConsoleButton(page, "Copy");
  await page.waitForFunction(() => Boolean(globalThis.__diagnosticSnapshotCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__diagnosticSnapshotCopiedText || "");
  assertDiagnosticSnapshot(copied, viewport, "toolbar copy");

  await page.evaluate(() => { globalThis.__diagnosticSnapshotCopiedText = ""; });
  await clickDiagnosticConsoleButton(page, "Refresh");
  await page.waitForFunction(() => {
    const text = document.querySelector("#diagnostic-console-scrim .diag-body")?.textContent || "";
    return text.includes("ngfwctl status") && !text.includes("Collecting API evidence");
  }, null, { timeout: 5000 });
  state = await collectDiagnosticConsoleState(page);
  assertDiagnosticConsoleState(state, viewport, "refresh");

  await page.keyboard.press("Escape");
  await page.waitForFunction(() => !document.querySelector("#diagnostic-console-scrim"), null, { timeout: 5000 });
  const focusReturned = await page.evaluate(() => document.activeElement?.id === "open-diagnostics");
  if (!focusReturned) {
    throw new Error(`diagnostic console did not restore toolbar focus at ${viewport.name}`);
  }

  await page.click("#open-palette");
  await page.fill("#palette-input", "diagnostic");
  await page.keyboard.press("Enter");
  await waitForDiagnosticConsole(page);
  state = await collectDiagnosticConsoleState(page);
  assertDiagnosticConsoleState(state, viewport, "command palette");
  await closeDiagnosticConsoleIfOpen(page);
}

async function waitForDiagnosticConsole(page) {
  await page.waitForSelector("#diagnostic-console-scrim .diag-console", { state: "visible", timeout: 5000 });
  await page.waitForFunction(() => {
    const text = document.querySelector("#diagnostic-console-scrim .diag-body")?.textContent || "";
    return text.includes("ngfwctl status") && text.includes("ngfwctl whoami");
  }, null, { timeout: 5000 });
}

async function clickDiagnosticConsoleButton(page, label) {
  const clicked = await page.evaluate((buttonLabel) => {
    const buttons = [...document.querySelectorAll("#diagnostic-console-scrim button")];
    const button = buttons.find((item) => (item.textContent || "").includes(buttonLabel));
    if (!button) return false;
    button.click();
    return true;
  }, label);
  if (!clicked) {
    throw new Error(`diagnostic console button not found: ${label}`);
  }
}

async function collectDiagnosticConsoleState(page) {
  return page.evaluate(() => {
    const scrim = document.querySelector("#diagnostic-console-scrim");
    const panel = scrim?.querySelector(".diag-console");
    const body = scrim?.querySelector(".diag-body");
    const rect = panel?.getBoundingClientRect();
    const text = scrim?.textContent || "";
    return {
      open: Boolean(scrim && panel),
      title: scrim?.querySelector("#diagnostic-console-title")?.textContent?.trim() || "",
      text,
      snapshot: body?.dataset?.snapshot || "",
      overflow: panel ? Math.max(0, Math.ceil(panel.scrollWidth - panel.clientWidth)) : 0,
      width: rect?.width || 0,
      height: rect?.height || 0,
      refreshFocused: document.activeElement?.dataset?.action === "refresh",
    };
  });
}

function assertDiagnosticConsoleState(state, viewport, source) {
  if (!state.open || state.title !== "API Diagnostic Console") {
    throw new Error(`diagnostic console did not open from ${source} at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const required of [
    "read-only",
    "ngfwctl status",
    "ngfwctl whoami",
    "ngfwctl status # engines",
    "ngfwctl status # routing-vpn",
    "ngfwctl policy status --json",
    "ngfwctl sessions --limit 8",
    "ngfwctl audit --limit 8",
    "ngfwctl status # warnings",
    "Refresh",
    "Copy",
    "Sessions",
  ]) {
    if (!state.text.includes(required)) {
      throw new Error(`diagnostic console from ${source} missing ${required} at ${viewport.name}`);
    }
  }
  if (!state.snapshot.includes("# Phragma diagnostic snapshot") || !state.snapshot.includes("$ ngfwctl status")) {
    throw new Error(`diagnostic console from ${source} did not retain copyable snapshot at ${viewport.name}`);
  }
  if (state.overflow > 2) {
    throw new Error(`diagnostic console from ${source} overflowed by ${state.overflow}px at ${viewport.name}`);
  }
  assertAutomationContextRedaction(state.text, `diagnostic console ${source} text`);
  assertDiagnosticSnapshot(state.snapshot, viewport, `${source} snapshot`);
}

function assertDiagnosticSnapshot(text, viewport, label) {
  for (const required of [
    "# Phragma diagnostic snapshot",
    "$ ngfwctl status",
    "$ ngfwctl whoami",
    "$ ngfwctl status # engines",
    "$ ngfwctl status # routing-vpn",
    "$ ngfwctl policy status --json",
    "$ ngfwctl sessions --limit 8",
    "$ ngfwctl audit --limit 8",
    "$ ngfwctl status # warnings",
  ]) {
    if (!text.includes(required)) {
      throw new Error(`diagnostic ${label} missing ${required} at ${viewport.name}`);
    }
  }
  if (/\$ phragma\b|curl\s+|\/v1\/system\/release-acceptance|release\/evidence|manifestPath|evidenceDir|dirtySourcePaths/i.test(text)) {
    throw new Error(`diagnostic ${label} included non-diagnostic or release evidence detail at ${viewport.name}`);
  }
  assertAutomationContextRedaction(text, `diagnostic ${label}`);
}

async function closeDiagnosticConsoleIfOpen(page) {
  const open = await page.evaluate(() => Boolean(document.querySelector("#diagnostic-console-scrim")));
  if (!open) return;
  await page.keyboard.press("Escape");
  await page.waitForFunction(() => !document.querySelector("#diagnostic-console-scrim"), null, { timeout: 5000 });
}

async function assertVisibleTextAndControlFit(page, viewport) {
  const report = await page.evaluate(() => {
    const tolerance = 2;
    const maxIssues = 12;
    const controlSelector = [
      "button",
      "a",
      "[role='button']",
      "summary",
      ".btn",
      ".ghost-btn",
      ".search-btn",
      ".seg button",
      ".profile-option",
      ".rule-hygiene-chip",
      ".linklike",
    ].join(",");
    const textSelector = [
      "h1",
      "h2",
      "h3",
      "h4",
      "p",
      "li",
      "dt",
      "dd",
      "th",
      "td",
      "small",
      "strong",
      "span",
      "label.field > span",
      ".badge",
      ".pill",
      ".note",
    ].join(",");
    const horizontalScrollSelectors = [
      ".table-wrap",
      ".rules-table-wrap",
      ".release-evidence-report",
      ".setup-host-command",
      ".warning-actions",
      ".diff",
      ".diag-body",
      "pre",
      "code",
      "textarea",
    ].join(",");
    const verticalScrollSelectors = [
      ".impact-list-scroll",
      ".palette-results",
      ".drawer-body",
      ".diag-body",
      ".diff",
      ".release-evidence-report",
      "pre",
      "textarea",
    ].join(",");

    const unique = (items) => [...new Set(items)];
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const visible = (el) => {
      if (!el || el.hidden || el.closest("[hidden],[aria-hidden='true']")) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) return false;
      if (rect.width <= 0 || rect.height <= 0) return false;
      const docWidth = Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0, window.innerWidth);
      const docHeight = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0, window.innerHeight);
      if (rect.right <= 1 && rect.left < 0) return false;
      if (rect.bottom <= 1 && rect.top < 0) return false;
      if (rect.left >= docWidth - 1 || rect.top >= docHeight - 1) return false;
      return true;
    };
    const styleAllowsScroll = (style, axis) => {
      const value = axis === "x" ? style.overflowX : style.overflowY;
      return /^(auto|scroll)$/i.test(value);
    };
    const axisAllowedByAncestor = (el, axis) => {
      const explicit = axis === "x" ? horizontalScrollSelectors : verticalScrollSelectors;
      if (el.closest(explicit)) return true;
      for (let node = el.parentElement; node && node !== document.body && node !== document.documentElement; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (axis === "x" && styleAllowsScroll(style, "x") && node.scrollWidth > node.clientWidth + tolerance) return true;
        if (axis === "y" && styleAllowsScroll(style, "y") && node.scrollHeight > node.clientHeight + tolerance) return true;
      }
      return false;
    };
    const intentionalEllipsis = (el, style) => {
      if (el.matches(controlSelector)) return false;
      return style.textOverflow === "ellipsis" && /^(hidden|clip)$/i.test(style.overflowX) && style.whiteSpace === "nowrap";
    };
    const hasOnlyInlineTextChildren = (el) => {
      const children = [...el.children].filter((child) => {
        if (["SVG", "PATH", "USE"].includes(child.tagName)) return false;
        return visible(child);
      });
      if (children.length === 0) return true;
      return children.every((child) => {
        const display = getComputedStyle(child).display;
        return display === "inline" || display === "contents";
      });
    };
    const describe = (el) => {
      const tag = el.tagName.toLowerCase();
      const id = el.id ? `#${el.id}` : "";
      const classes = [...el.classList].slice(0, 3).map((name) => `.${name}`).join("");
      const data = el.dataset?.path ? `[data-path="${el.dataset.path}"]` : "";
      const label = textOf(el) || el.getAttribute("aria-label") || el.getAttribute("title") || "";
      const snippet = label ? ` "${label.slice(0, 72)}${label.length > 72 ? "..." : ""}"` : "";
      return `${tag}${id}${classes}${data}${snippet}`;
    };
    const measure = (el) => {
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return {
        style,
        rect,
        dx: Math.ceil(el.scrollWidth - el.clientWidth),
        dy: Math.ceil(el.scrollHeight - el.clientHeight),
        scrollWidth: el.scrollWidth,
        clientWidth: el.clientWidth,
        scrollHeight: el.scrollHeight,
        clientHeight: el.clientHeight,
      };
    };
    const addFitIssues = (issues, el, kind) => {
      if (!visible(el) || !textOf(el)) return;
      if (axisAllowedByAncestor(el, "x") && axisAllowedByAncestor(el, "y")) return;
      const measured = measure(el);
      if (measured.clientWidth <= 0 || measured.clientHeight <= 0) return;
      if (kind === "text" && !hasOnlyInlineTextChildren(el)) return;
      if (kind === "text" && intentionalEllipsis(el, measured.style)) return;
      const clipsVerticalText = kind === "control label" || /^(hidden|clip)$/i.test(measured.style.overflowY);
      if (measured.dx > tolerance && !axisAllowedByAncestor(el, "x")) {
        issues.push(`${kind} horizontal overflow ${measured.dx}px in ${describe(el)} (${Math.round(measured.rect.width)}x${Math.round(measured.rect.height)}, scroll ${measured.scrollWidth}x${measured.scrollHeight}, client ${measured.clientWidth}x${measured.clientHeight})`);
      }
      if (measured.dy > tolerance && clipsVerticalText && !axisAllowedByAncestor(el, "y")) {
        issues.push(`${kind} vertical clipping ${measured.dy}px in ${describe(el)} (${Math.round(measured.rect.width)}x${Math.round(measured.rect.height)}, scroll ${measured.scrollWidth}x${measured.scrollHeight}, client ${measured.clientWidth}x${measured.clientHeight})`);
      }
    };

    const issues = [];
    const controls = unique([...document.querySelectorAll(controlSelector)]);
    const textNodes = unique([...document.querySelectorAll(textSelector)]);
    for (const el of controls) {
      addFitIssues(issues, el, "control label");
      if (issues.length >= maxIssues) break;
    }
    if (issues.length < maxIssues) {
      for (const el of textNodes) {
        if (el.closest(controlSelector)) continue;
        addFitIssues(issues, el, "text");
        if (issues.length >= maxIssues) break;
      }
    }
    return {
      issues,
      checkedControls: controls.filter((el) => visible(el) && textOf(el)).length,
      checkedText: textNodes.filter((el) => visible(el) && textOf(el) && !el.closest(controlSelector)).length,
    };
  });

  if (report.issues.length) {
    throw new Error(`visible text/control fit failed at ${viewport.name}: ${report.issues.join(" | ")}`);
  }
  if (report.checkedControls === 0 || report.checkedText === 0) {
    throw new Error(`visible text/control fit check did not inspect enough UI (controls=${report.checkedControls}, text=${report.checkedText})`);
  }
}

async function assertMobileMenuRouteCollapse(page) {
  const initial = await page.evaluate(() => ({
    expanded: document.querySelector("#menu-toggle")?.getAttribute("aria-expanded") || "",
    controls: document.querySelector("#menu-toggle")?.getAttribute("aria-controls") || "",
    menuOpen: Boolean(document.querySelector("#app")?.classList.contains("menu-open")),
  }));
  if (initial.controls !== "sidebar") {
    throw new Error(`mobile menu toggle aria-controls was "${initial.controls || "<none>"}"`);
  }
  if (initial.expanded !== "false" || initial.menuOpen) {
    throw new Error(`mobile menu did not start closed (expanded=${initial.expanded || "<none>"}, menuOpen=${initial.menuOpen})`);
  }

  await page.click("#menu-toggle");
  const opened = await page.evaluate(() => ({
    expanded: document.querySelector("#menu-toggle")?.getAttribute("aria-expanded") || "",
    menuOpen: Boolean(document.querySelector("#app")?.classList.contains("menu-open")),
  }));
  if (opened.expanded !== "true" || !opened.menuOpen) {
    throw new Error(`mobile menu did not open accessibly (expanded=${opened.expanded || "<none>"}, menuOpen=${opened.menuOpen})`);
  }

  await page.click('#nav a[data-path="/rules"]');
  await page.waitForFunction(() => (
    location.hash === "#/rules" &&
    !document.querySelector("#content > .loading") &&
    document.querySelector("#nav a.active")?.dataset?.path === "/rules" &&
    document.querySelector("#menu-toggle")?.getAttribute("aria-expanded") === "false" &&
    !document.querySelector("#app")?.classList.contains("menu-open")
  ), null, { timeout: 10000 });
  const closed = await page.evaluate(() => ({
    activeNavPath: document.querySelector("#nav a.active")?.dataset?.path || "",
    expanded: document.querySelector("#menu-toggle")?.getAttribute("aria-expanded") || "",
    menuOpen: Boolean(document.querySelector("#app")?.classList.contains("menu-open")),
  }));
  if (closed.activeNavPath !== "/rules") {
    throw new Error(`mobile nav click did not activate /rules (active=${closed.activeNavPath || "<none>"})`);
  }
  if (closed.expanded !== "false" || closed.menuOpen) {
    throw new Error(`mobile menu did not collapse after route activation (expanded=${closed.expanded || "<none>"}, menuOpen=${closed.menuOpen})`);
  }
}

async function assertGuidedSetupBaselineWorkflow(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const plan = {
    insideZone: `lan-${marker}`,
    outsideZone: `wan-${marker}`,
    insideInterfaces: `eth-setup-${marker}-in`,
    outsideInterfaces: `eth-setup-${marker}-out`,
    insideCidr: marker === "mobile" ? "10.31.0.0/24" : marker === "tablet" ? "10.32.0.0/24" : "10.33.0.0/24",
    webuiPort: marker === "mobile" ? "8445" : marker === "tablet" ? "8444" : "8443",
  };
  try {
    await page.waitForSelector('[data-setup-action="stage"]', { timeout: 10000 });
    const before = await collectGuidedSetupState(page);
    await assertGuidedSetupActionButtons(page, viewport);
    await assertPageResponsiveTable(page, viewport, ".setup-checklist-table", ["Check", "Status", "Proof"], "guided setup checklist");
    const requiredChecks = ["interfaces", "admin-access", "host-input", "content-updates", "topology-proof", "outbound", "inspection", "host-tuning", "candidate-review"];
    const missing = requiredChecks.filter((id) => !before.checks.includes(id));
    if (missing.length) {
      throw new Error(`guided setup missing checklist item(s): ${missing.join(", ")}`);
    }
    if (!before.profiles.includes("throughput") || !before.profiles.includes("ids-detect") || !before.profiles.includes("ips-prevent")) {
      throw new Error(`guided setup profile options incomplete: ${JSON.stringify(before.profiles)}`);
    }
    const requiredScenarios = ["cloud-edge", "east-west", "vpn-edge", "ids-tap", "lab"];
    const missingScenarios = requiredScenarios.filter((scenario) => !before.scenarios.includes(scenario));
    if (missingScenarios.length) {
      throw new Error(`guided setup scenario options incomplete: ${JSON.stringify({ missingScenarios, scenarios: before.scenarios })}`);
    }
    if (before.stageDisabled) {
      throw new Error(`guided setup stage action unexpectedly disabled before field update: ${JSON.stringify(before)}`);
    }
    if (!before.topologyRows.includes("interfaces") || !before.topologyRows.includes("host-input")) {
      throw new Error(`guided setup missing topology proof row(s): ${JSON.stringify(before.topologyRows)}`);
    }
    await assertGuidedSetupScenarioPresets(page, viewport);

    await setGuidedSetupField(page, "insideZone", plan.insideZone);
    await setGuidedSetupField(page, "outsideZone", plan.outsideZone);
    await setGuidedSetupField(page, "insideInterfaces", plan.insideInterfaces);
    await setGuidedSetupField(page, "outsideInterfaces", plan.outsideInterfaces);
    await setGuidedSetupField(page, "insideCidr", plan.insideCidr);
    await setGuidedSetupField(page, "webuiPort", plan.webuiPort);
    await page.click('[data-setup-action="stage"]');
    await page.waitForSelector('[data-setup-action="review-changes"]', { timeout: 10000 });
    await page.waitForFunction(async (expected) => {
      const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
      if (!response.ok) return false;
      const policy = (await response.json())?.policy || {};
      return (policy.zones || []).some((zone) => zone?.name === expected.insideZone);
    }, plan, { timeout: 10000 });

    const state = await page.evaluate(async (expected) => {
      const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
        fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
        fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
        fetch("/v1/candidate/status"),
      ]);
      if (!candidateResponse.ok) throw new Error(`read guided setup candidate failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
      if (!runningResponse.ok) throw new Error(`read guided setup running failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
      const candidate = (await candidateResponse.json())?.policy || {};
      const running = (await runningResponse.json())?.policy || {};
      const status = statusResponse.ok ? await statusResponse.json() : {};
      const zone = (policy, name) => (policy.zones || []).find((item) => item?.name === name) || null;
      const addressName = `${expected.insideZone}-net`;
      const ruleName = `allow-${expected.insideZone}-to-${expected.outsideZone}`;
      const natName = `${expected.insideZone}-masq`;
      const hostRuleName = `allow-${expected.insideZone}-management`;
      const service = (candidate.services || []).find((item) => item?.name === "webui") || {};
      const hasWebUIPort = (service.ports || []).some((port) => String(port.start || "") === String(expected.webuiPort));
      const runningText = JSON.stringify(running);
      return {
        candidate: {
          insideZone: zone(candidate, expected.insideZone),
          outsideZone: zone(candidate, expected.outsideZone),
          address: (candidate.addresses || []).find((item) => item?.name === addressName && item?.cidr === expected.insideCidr) || null,
          webuiService: hasWebUIPort,
          rule: (candidate.rules || []).find((item) => item?.name === ruleName && item?.action === "ACTION_ALLOW" && item?.log === true) || null,
          nat: (candidate.nat?.source || []).find((item) => item?.name === natName && item?.masquerade === true) || null,
          hostRule: (candidate.hostInput?.rules || []).find((item) => item?.name === hostRuleName && item?.action === "ACTION_ALLOW") || null,
          hostDefaultDeny: candidate.hostInput?.defaultAction === "ACTION_DENY",
          flowOffload: candidate.network?.enableFlowOffload === true,
          clampMss: candidate.network?.clampMssToPmtu === true,
          idsDisabled: candidate.ids?.enabled === false,
        },
        runningContainsMarker: runningText.includes(expected.insideZone) || runningText.includes(expected.outsideZone),
        statusDirty: Boolean(status.dirty || status.hasCandidate || status.has_candidate),
        reviewHref: document.querySelector('[data-setup-action="review-changes"]')?.getAttribute("href") || "",
        text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
      };
    }, plan);
    const missingCandidate = Object.entries(state.candidate)
      .filter(([, value]) => value === null || value === false)
      .map(([key]) => key);
    if (missingCandidate.length) {
      throw new Error(`guided setup candidate missing expected baseline output at ${viewport.name}: ${missingCandidate.join(", ")} state=${JSON.stringify(state.candidate)}`);
    }
    if (state.runningContainsMarker) {
      throw new Error(`guided setup baseline leaked into running policy before commit at ${viewport.name}`);
    }
    if (!state.statusDirty || state.reviewHref !== "#/changes") {
      throw new Error(`guided setup did not expose candidate review after staging at ${viewport.name}: ${JSON.stringify({ dirty: state.statusDirty, href: state.reviewHref })}`);
    }
    if (!/Setup staged|Review changes|First-run checklist/.test(state.text)) {
      throw new Error(`guided setup staged view missing review/readiness copy at ${viewport.name}`);
    }
    await assertAutomationContextDrawer(page, viewport, "guided setup automation context", [
      "setup",
      "policy baseline",
      "policy validate",
      "policy diff",
    ]);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/setup"; });
    await waitForRouteReady(page, "/setup");
  }
}

async function collectGuidedSetupState(page) {
  return await page.evaluate(() => ({
    scenarios: [...document.querySelectorAll("[data-setup-scenario]")].map((button) => button.getAttribute("data-setup-scenario") || ""),
    profiles: [...document.querySelectorAll("[data-setup-profile]")].map((button) => button.getAttribute("data-setup-profile") || ""),
    checks: [...document.querySelectorAll("[data-setup-check]")].map((row) => row.getAttribute("data-setup-check") || ""),
    topologyRows: [...document.querySelectorAll("[data-setup-topology-proof-row]")].map((row) => row.getAttribute("data-setup-topology-proof-row") || ""),
    stageDisabled: Boolean(document.querySelector('[data-setup-action="stage"]')?.disabled),
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
  }));
}

async function assertGuidedSetupActionButtons(page, viewport, opts = {}) {
  const state = await page.evaluate(() => {
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = window.getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const setupSelector = (node) => {
      if (node.hasAttribute("data-setup-action")) return `data-setup-action=${node.getAttribute("data-setup-action")}`;
      if (node.hasAttribute("data-setup-profile")) return `data-setup-profile=${node.getAttribute("data-setup-profile")}`;
      if (node.hasAttribute("data-setup-scenario")) return `data-setup-scenario=${node.getAttribute("data-setup-scenario")}`;
      if (node.hasAttribute("data-setup-host-action")) return `data-setup-host-action=${node.getAttribute("data-setup-host-action")}`;
      if (node.hasAttribute("data-setup-interface-action")) return `data-setup-interface-action=${node.getAttribute("data-setup-interface-action")}`;
      if (node.hasAttribute("data-setup-segment")) return `data-setup-segment=${node.getAttribute("data-setup-segment")}`;
      return "";
    };
    const buttons = [...document.querySelectorAll([
      "button[data-setup-action]",
      "button[data-setup-profile]",
      "button[data-setup-scenario]",
      "button[data-setup-host-action]",
      "button[data-setup-interface-action]",
      "button[data-setup-segment]",
    ].join(","))]
      .filter(visible)
      .map((button) => ({
        selector: setupSelector(button),
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.getAttribute("data-setup-action") || "",
        profile: button.getAttribute("data-setup-profile") || "",
        scenario: button.getAttribute("data-setup-scenario") || "",
        hostAction: button.getAttribute("data-setup-host-action") || "",
        interfaceAction: button.getAttribute("data-setup-interface-action") || "",
        setupInterface: button.getAttribute("data-setup-interface") || "",
        segment: button.getAttribute("data-setup-segment") || "",
      }));
    const proofLinks = [...document.querySelectorAll("a[data-setup-check-action]")]
      .filter(visible)
      .map((link) => ({
        selector: `data-setup-check-action=${link.getAttribute("data-setup-check-action") || ""}`,
        href: link.getAttribute("href") || "",
        title: link.getAttribute("title") || "",
        ariaLabel: link.getAttribute("aria-label") || "",
        text: (link.textContent || "").replace(/\s+/g, " ").trim(),
      }));
    return {
      buttons,
      proofLinks,
      invalidButtons: buttons.filter((button) => (
        button.type !== "button" ||
        !button.title.trim() ||
        !button.ariaLabel.trim() ||
        !button.selector ||
        (button.interfaceAction && (!button.setupInterface || !button.ariaLabel.includes(button.setupInterface)))
      )),
      invalidProofLinks: proofLinks.filter((link) => !link.href || !link.title.trim() || !link.ariaLabel.trim() || !link.selector),
      actions: buttons.map((button) => button.action).filter(Boolean),
      profiles: buttons.map((button) => button.profile).filter(Boolean),
      scenarios: buttons.map((button) => button.scenario).filter(Boolean),
      hostActions: buttons.map((button) => button.hostAction).filter(Boolean),
      interfaceActions: buttons.map((button) => button.interfaceAction).filter(Boolean),
      segments: buttons.map((button) => button.segment).filter(Boolean),
    };
  });
  if (state.invalidButtons.length || state.invalidProofLinks.length) {
    throw new Error(`guided setup controls missing action semantics at ${viewport.name}: ${JSON.stringify({ invalidButtons: state.invalidButtons, invalidProofLinks: state.invalidProofLinks })}`);
  }
  for (const action of ["stage", "api-cli"]) {
    if (!state.actions.includes(action)) {
      throw new Error(`guided setup missing ${action} action button at ${viewport.name}: ${JSON.stringify(state.actions)}`);
    }
  }
  for (const profile of ["throughput", "ids-detect", "ips-prevent"]) {
    if (!state.profiles.includes(profile)) {
      throw new Error(`guided setup missing ${profile} profile button at ${viewport.name}: ${JSON.stringify(state.profiles)}`);
    }
  }
  for (const scenario of ["cloud-edge", "east-west", "vpn-edge", "ids-tap", "lab"]) {
    if (!state.scenarios.includes(scenario)) {
      throw new Error(`guided setup missing ${scenario} scenario button at ${viewport.name}: ${JSON.stringify(state.scenarios)}`);
    }
  }
  if (state.hostActions.length < 2) {
    throw new Error(`guided setup host tuning actions incomplete at ${viewport.name}: ${JSON.stringify(state.hostActions)}`);
  }
  if (opts.requireSegment && !state.segments.includes("failureBehavior")) {
    throw new Error(`guided setup missing IPS failure behavior segment at ${viewport.name}: ${JSON.stringify(state.segments)}`);
  }
}

async function assertGuidedSetupScenarioPresets(page, viewport) {
  await page.click('[data-setup-profile="ips-prevent"]');
  await page.waitForSelector('[data-setup-segment="failureBehavior"]', { timeout: 5000 });
  await assertGuidedSetupActionButtons(page, viewport, { requireSegment: true });

  await page.click('[data-setup-scenario="ids-tap"]');
  await page.waitForFunction(() => document.querySelector('[data-setup-field="insideZone"]')?.value === "tap", null, { timeout: 5000 });
  let state = await page.evaluate(() => ({
    activeScenario: document.querySelector('[data-setup-scenario="ids-tap"]')?.classList.contains("active"),
    insideZone: document.querySelector('[data-setup-field="insideZone"]')?.value || "",
    outsideZone: document.querySelector('[data-setup-field="outsideZone"]')?.value || "",
    insideCidr: document.querySelector('[data-setup-field="insideCidr"]')?.value || "",
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (!state.activeScenario || state.insideZone !== "tap" || state.outsideZone !== "monitor" || state.insideCidr !== "10.30.0.0/24") {
    throw new Error(`guided setup IDS tap scenario did not populate expected fields at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const expected of ["IDS tap", "Passive monitoring deployment", "Outbound allow and source NAT are not staged", "No default outbound allow path", "IDS detect mode is staged"]) {
    if (!state.text.includes(expected)) {
      throw new Error(`guided setup IDS tap scenario missing ${expected} at ${viewport.name}: ${JSON.stringify(state)}`);
    }
  }
  if (state.overflow > 2) {
    throw new Error(`guided setup scenario presets overflow at ${viewport.name}: ${state.overflow}px`);
  }

  await page.click('[data-setup-action="api-cli"]');
  await waitForDrawerTitle(page, "API / CLI context");
  let drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "guided setup IDS tap API / CLI context", [
    "ids-tap",
    "--profile ids-detect",
    "--inside-zone tap",
    "--outside-zone monitor",
    "--inside-cidr 10.30.0.0/24",
    "--allow-outbound=false",
    "--masquerade=false",
    "no outbound allow path and no source NAT",
  ], ["Copy session JSON", "Copy context"]);
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);

  await page.click('[data-setup-scenario="east-west"]');
  await page.waitForFunction(() => document.querySelector('[data-setup-field="insideZone"]')?.value === "app", null, { timeout: 5000 });
  state = await page.evaluate(() => ({
    activeScenario: document.querySelector('[data-setup-scenario="east-west"]')?.classList.contains("active"),
    insideZone: document.querySelector('[data-setup-field="insideZone"]')?.value || "",
    outsideZone: document.querySelector('[data-setup-field="outsideZone"]')?.value || "",
    insideCidr: document.querySelector('[data-setup-field="insideCidr"]')?.value || "",
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (!state.activeScenario || state.insideZone !== "app" || state.outsideZone !== "db" || state.insideCidr !== "10.10.0.0/24") {
    throw new Error(`guided setup east-west scenario did not populate expected fields at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const expected of ["Internal segmentation point", "upstream routing", "Source NAT, internet-edge assumptions, and inline prevention are not staged"]) {
    if (!state.text.includes(expected)) {
      throw new Error(`guided setup east-west scenario missing ${expected} at ${viewport.name}: ${JSON.stringify(state)}`);
    }
  }
  if (state.overflow > 2) {
    throw new Error(`guided setup east-west scenario overflow at ${viewport.name}: ${state.overflow}px`);
  }

  await page.click('[data-setup-scenario="vpn-edge"]');
  await page.waitForFunction(() => document.querySelector('[data-setup-field="insideZone"]')?.value === "branch", null, { timeout: 5000 });
  state = await page.evaluate(() => ({
    activeScenario: document.querySelector('[data-setup-scenario="vpn-edge"]')?.classList.contains("active"),
    insideZone: document.querySelector('[data-setup-field="insideZone"]')?.value || "",
    outsideZone: document.querySelector('[data-setup-field="outsideZone"]')?.value || "",
    insideCidr: document.querySelector('[data-setup-field="insideCidr"]')?.value || "",
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (!state.activeScenario || state.insideZone !== "branch" || state.outsideZone !== "vpn" || state.insideCidr !== "10.20.0.0/24") {
    throw new Error(`guided setup VPN edge scenario did not populate expected fields at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const expected of ["Branch or remote-network edge", "Tunnel peers, private keys, PSKs", "Create the WireGuard or IPsec tunnel"]) {
    if (!state.text.includes(expected)) {
      throw new Error(`guided setup VPN edge scenario missing ${expected} at ${viewport.name}: ${JSON.stringify(state)}`);
    }
  }
  if (state.overflow > 2) {
    throw new Error(`guided setup VPN edge scenario overflow at ${viewport.name}: ${state.overflow}px`);
  }

  await page.click('[data-setup-scenario="cloud-edge"]');
  await page.waitForFunction(() => document.querySelector('[data-setup-field="insideZone"]')?.value === "lan", null, { timeout: 5000 });
  state = await page.evaluate(() => ({
    activeScenario: document.querySelector('[data-setup-scenario="cloud-edge"]')?.classList.contains("active"),
    insideZone: document.querySelector('[data-setup-field="insideZone"]')?.value || "",
    outsideZone: document.querySelector('[data-setup-field="outsideZone"]')?.value || "",
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
  }));
  if (!state.activeScenario || state.insideZone !== "lan" || state.outsideZone !== "wan" || !state.text.includes("Cloud edge")) {
    throw new Error(`guided setup cloud edge scenario did not reset expected fields at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function setGuidedSetupField(page, key, value) {
  await page.evaluate(({ fieldKey, fieldValue }) => {
    const input = document.querySelector(`[data-setup-field="${fieldKey}"]`);
    if (!input) throw new Error(`guided setup field ${fieldKey} was not found`);
    input.value = String(fieldValue);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, { fieldKey: key, fieldValue: value });
}

async function assertTrafficInvestigationWorkbench(page, viewport) {
	await runSmokeStep("traffic saved filter lifecycle", () => assertSavedFilterLifecycle(page, viewport, {
		label: "traffic saved filter",
		routeHash: "#/traffic?mode=flows",
		routePath: "/traffic",
		scope: "traffic",
    filterRoot: ".telemetry-filters",
    fields: [
      { label: "Search", value: "tls" },
      { label: "IP", value: investigationSeed.srcIp },
      { label: "Protocol", value: investigationSeed.protocol },
      { label: "Port", value: String(investigationSeed.destPort) },
    ],
		expectedParams: { q: "tls", ip: investigationSeed.srcIp, protocol: investigationSeed.protocol, port: String(investigationSeed.destPort) },
		forbiddenStateKeys: ["flowId", "queueId", "sessionKey"],
	}));
	await runSmokeStep("traffic automation context parity", () => assertTrafficAutomationContextParity(page, viewport));

	await runSmokeStep("traffic seeded flow drawer", () => openSeededFlowDrawer(page));
	let drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "traffic flow detail", [
    "Flow detail",
    "Flow ID",
    investigationSeed.flowId,
    "Source",
    `${investigationSeed.srcIp}:${investigationSeed.srcPort}`,
    "Destination",
    `${investigationSeed.destIp}:${investigationSeed.destPort}`,
    "Protocol",
    "App-ID",
    "App-ID evidence",
    "Packet capture evidence",
    "Event policy",
  ], ["Close", "Explain", "Capture", "App-ID", "Allow", "Drop"]);
  await assertTrafficDrawerActions(page, viewport, "flow detail", "trafficAction", [
    "close-flow",
    "related-threats",
    "explain-flow-drawer",
    "capture-flow-drawer",
    "capture-audit",
    "custom-app-flow-drawer",
    "allow-flow-drawer",
    "drop-flow-drawer",
  ]);
  await assertTrafficDrawerActions(page, viewport, "flow handoff", "trafficHandoffAction", ["pin", "copy", "export"]);

  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/traffic", ["flowId", "queueId"]);

	await runSmokeStep("traffic explain handoff drawer", () => openSeededFlowDrawer(page));
	let initialHash = await clickDrawerFooterButton(page, "Explain");
  assertInvestigationActionHash(initialHash, "explain");
  await assertTroubleshootInvestigation(page, viewport, "explain");

	await runSmokeStep("traffic capture handoff drawer", () => openSeededFlowDrawer(page));
	initialHash = await clickDrawerFooterButton(page, "Capture");
  assertInvestigationActionHash(initialHash, "capture");
  await assertTroubleshootInvestigation(page, viewport, "capture", { skipCaptureLifecycle: true });

	await runSmokeStep("traffic allow rule drawer", () => openSeededFlowDrawer(page));
	await clickDrawerFooterButton(page, "Allow");
  await waitForSelectionCleared(page, "/traffic", ["flowId", "queueId"]);
  await waitForDrawerTitle(page, "New rule");
  await assertRuleEditorCandidateOnly(page, viewport, "ACTION_ALLOW", { namePrefix: "allow-flow-", expectLog: false });
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);

	await runSmokeStep("traffic drop rule drawer", () => openSeededFlowDrawer(page));
	await clickDrawerFooterButton(page, "Drop");
  await waitForSelectionCleared(page, "/traffic", ["flowId", "queueId"]);
  await waitForDrawerTitle(page, "New rule");
  await assertRuleEditorCandidateOnly(page, viewport, "ACTION_DENY", { namePrefix: "drop-flow-", expectLog: true });
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);

	const previousPolicy = await snapshotCandidatePolicy(page);
	try {
		await runSmokeStep("traffic custom app-id drawer", () => openSeededFlowDrawer(page));
    await clickDrawerFooterButton(page, "App-ID");
    await waitForSelectionCleared(page, "/traffic", ["flowId", "queueId"]);
    await waitForDrawerTitle(page, "Custom App-ID");
    await fillCustomAppIdReviewDrawer(page);
    await assertCustomAppIdReviewDrawer(page, viewport);
    await assertTrafficDrawerActions(page, viewport, "custom App-ID", "appidAction", [
      "cancel-custom-app",
      "save-view",
      "review-drop",
      "save-drop",
      "save",
    ]);
    await clickDrawerFooterButton(page, "Review drop rule");
    await waitForDrawerTitle(page, "New rule");
    await assertAppIdRuleReviewEditor(page, viewport);
    await clickDrawerFooterButton(page, "Add rule");
    await waitForDrawerClosed(page);
    await assertReviewedAppIdDropCandidate(page);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertTrafficDrawerActions(page, viewport, label, datasetKey, expectedActions) {
  const actions = await page.evaluate((key) => {
    const selector = key.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
    return [...document.querySelectorAll(`#drawer:not([hidden]) [data-${selector}]`)].map((node) => ({
      action: node.dataset[key] || "",
      tag: node.tagName,
      type: node.getAttribute("type") || "",
      title: node.getAttribute("title") || "",
      ariaLabel: node.getAttribute("aria-label") || "",
      text: (node.textContent || "").replace(/\s+/g, " ").trim(),
      width: node.getBoundingClientRect().width,
      height: node.getBoundingClientRect().height,
    }));
  }, datasetKey);
  const missing = expectedActions.filter((action) => !actions.some((item) => item.action === action));
  if (missing.length) {
    throw new Error(`traffic ${label} missing drawer actions at ${viewport.name}: ${missing.join(", ")} state=${JSON.stringify(actions)}`);
  }
  const invalid = actions.filter((item) => expectedActions.includes(item.action) && (
    (item.tag === "BUTTON" && item.type !== "button") ||
    !item.title ||
    !item.ariaLabel ||
    item.width < 34 ||
    item.height < 30
  ));
  if (invalid.length) {
    throw new Error(`traffic ${label} drawer actions were not accessible at ${viewport.name}: ${JSON.stringify(invalid)}`);
  }
}

async function assertTrafficAutomationContextParity(page, viewport) {
  await page.evaluate((seed) => {
    location.hash = `#/traffic?mode=flows&ip=${encodeURIComponent(seed.srcIp)}&protocol=${encodeURIComponent(seed.protocol)}&port=${encodeURIComponent(String(seed.destPort))}&flowId=${encodeURIComponent(seed.flowId)}&limit=100`;
  }, investigationSeed);
  await waitForRouteReady(page, "/traffic");
  await assertTrafficResponsiveTable(page, viewport, ".traffic-flow-table", ["App-ID", "Policy", "Proto", "Source", "Destination", "To server", "To client", "Packets", "Actions"]);
  await assertTrafficRowActions(page, viewport, ".traffic-flow-table", "trafficAction", [
    { action: "view-flow", label: "Details" },
    { action: "explain-flow", label: "Explain" },
    { action: "custom-app-flow", label: "App-ID" },
    { action: "allow-flow", label: "Allow" },
    { action: "drop-flow", label: "Drop" },
  ]);
  await assertAutomationContextDrawer(page, viewport, "traffic flows automation context", [
    "/v1/flows?limit=100",
    `ip=${investigationSeed.srcIp}`,
    `protocol=${investigationSeed.protocol}`,
    `port=${investigationSeed.destPort}`,
    "ngfwctl flows --limit 100",
    `--ip ${investigationSeed.srcIp}`,
    `--protocol ${investigationSeed.protocol}`,
    `--port ${investigationSeed.destPort}`,
  ]);

  await page.evaluate((seed) => {
    location.hash = `#/traffic?mode=sessions&ip=${encodeURIComponent(seed.srcIp)}&protocol=${encodeURIComponent(seed.protocol)}&sessionState=ESTABLISHED&port=${encodeURIComponent(String(seed.destPort))}&limit=100&sessionSort=packets`;
  }, investigationSeed);
  await waitForRouteReady(page, "/traffic");
  await assertTrafficResponsiveTable(page, viewport, ".traffic-session-table", ["Proto", "State", "Original", "Reply", "Packets", "Bytes", "Timeout", "Flags", "Actions"], { allowAbsent: true });
  await assertTrafficRowActions(page, viewport, ".traffic-session-table", "trafficAction", [
    { action: "explain-session", label: "Explain" },
    { action: "custom-app-session", label: "App-ID" },
    { action: "allow-session", label: "Allow" },
    { action: "drop-session", label: "Drop" },
  ], { allowAbsent: true });
  await assertAutomationContextDrawer(page, viewport, "traffic sessions automation context", [
    "sessionSort=packets",
    `/v1/sessions?limit=100&ip=${investigationSeed.srcIp}&protocol=${investigationSeed.protocol}&port=${investigationSeed.destPort}&state=ESTABLISHED`,
    `ngfwctl sessions --limit 100 --ip ${investigationSeed.srcIp} --protocol ${investigationSeed.protocol} --port ${investigationSeed.destPort} --state ESTABLISHED`,
  ]);

  await page.evaluate((seed) => {
    location.hash = `#/traffic?mode=app-id&q=${encodeURIComponent(seed.appProto)}&observationKind=APP_ID_OBSERVATION_KIND_UNKNOWN&engineSignal=${encodeURIComponent(seed.appProto)}&protocol=${encodeURIComponent(seed.protocol)}&port=${encodeURIComponent(String(seed.destPort))}&confidenceThreshold=70&flowLimit=1000&limit=50`;
  }, appIdQueueSeed);
  await waitForRouteReady(page, "/traffic");
  await assertTrafficResponsiveTable(page, viewport, ".appid-observation-table", ["Review", "Evidence", "Suggested App-ID", "Context", "Volume", "Next action", "Actions"]);
  await assertTrafficRowActions(page, viewport, ".appid-observation-table", "appidObservationAction", [
    { action: "define", label: "Define" },
    { action: "review", label: "Review" },
    { action: "capture", label: "Capture" },
    { action: "flows", label: "Flows" },
  ]);
  await assertAutomationContextDrawer(page, viewport, "traffic app-id automation context", [
    "/v1/app-id/observations?limit=50&flowLimit=1000&confidenceThreshold=70",
    "kind=APP_ID_OBSERVATION_KIND_UNKNOWN",
    `engineSignal=${appIdQueueSeed.appProto}`,
    "ngfwctl app-id observations --limit 50 --flow-limit 1000 --confidence-threshold 70",
    "--kind unknown",
    `--engine-signal ${appIdQueueSeed.appProto}`,
  ]);

	const observation = await findAppIdQueueObservation(page);
	const queueId = observation.queueId;
	await page.evaluate(({ obs, seed }) => {
		location.hash = `#/traffic?mode=app-id&q=${encodeURIComponent(obs.engineSignal || seed.appProto)}&queueId=${encodeURIComponent(obs.queueId)}&confidenceThreshold=70&flowLimit=1000&limit=100`;
	}, { obs: observation, seed: appIdQueueSeed });
  await waitForRouteReady(page, "/traffic");
  await assertTrafficResponsiveTable(page, viewport, ".appid-observation-table", ["Review", "Evidence", "Suggested App-ID", "Context", "Volume", "Next action", "Actions"]);
  await assertTrafficRowActions(page, viewport, ".appid-observation-table", "appidObservationAction", [
    { action: "define", label: "Define" },
    { action: "review", label: "Review" },
    { action: "capture", label: "Capture" },
    { action: "flows", label: "Flows" },
  ]);
  await assertAutomationContextDrawer(page, viewport, "traffic selected App-ID queue automation context", [
    "/v1/app-id/observations?limit=100&flowLimit=1000&confidenceThreshold=70",
    `/v1/app-id/observations/${queueId}:stage`,
    `/v1/app-id/observations/${queueId}:stage-regression-sample`,
    `Selected App-ID queue item: ${queueId}`,
    `ngfwctl app-id promote ${queueId} --reason "reviewed App-ID observation" --flow-limit 1000 --confidence-threshold 70`,
    `ngfwctl app-id promote ${queueId} --drop --confirm-drop --reason "block repeated unknown app" --flow-limit 1000 --confidence-threshold 70`,
    `ngfwctl app-id corpus add ${queueId} --pcap-sha256`,
  ], { keepActiveDrawer: true, drawerButtonLabel: "API / CLI" });
}

async function assertTrafficResponsiveTable(page, viewport, selector, expectedLabels, opts = {}) {
  const state = await page.evaluate(({ selector }) => {
    const table = document.querySelector(selector);
    const row = table?.querySelector("tbody tr");
    const cells = [...(row?.querySelectorAll("td") || [])];
    return {
      tableClass: table?.className || "",
      labels: cells.map((cell) => cell.getAttribute("data-label") || ""),
      rowClass: row?.className || "",
      rowRole: row?.getAttribute("role") || "",
      rowTabindex: row?.getAttribute("tabindex") || "",
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      mobileLabelsRendered: window.innerWidth > 820 || cells.filter((cell) => (cell.getAttribute("data-label") || "") !== "Actions").every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
    };
  }, { selector });
  if (opts.allowAbsent && !state.tableClass && !state.labels.length) {
    return;
  }
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes(selector.replace(".", ""))) {
    throw new Error(`traffic table ${selector} missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.labels.length) {
    throw new Error(`traffic table ${selector} rendered no data row at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = expectedLabels.filter((label) => !state.labels.includes(label));
  if (missingLabels.length) {
    throw new Error(`traffic table ${selector} missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (!state.rowClass.includes("clickable") || state.rowRole !== "button" || state.rowTabindex !== "0") {
    throw new Error(`traffic table ${selector} row accessibility mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`traffic table ${selector} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`traffic table ${selector} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertTrafficRowActions(page, viewport, selector, datasetKey, expectedActions, opts = {}) {
  const state = await page.evaluate(({ selector, datasetKey }) => {
    const table = document.querySelector(selector);
    const row = table?.querySelector("tbody tr");
    const buttons = [...(row?.querySelectorAll(".row-actions button") || [])];
    return {
      tablePresent: Boolean(table),
      rowPresent: Boolean(row),
      actions: buttons.map((button) => {
        const rect = button.getBoundingClientRect();
        return {
          action: button.dataset[datasetKey] || "",
          label: (button.textContent || "").replace(/\s+/g, " ").trim(),
          type: button.getAttribute("type") || "",
          title: button.getAttribute("title") || "",
          ariaLabel: button.getAttribute("aria-label") || "",
          width: Math.round(rect.width),
          height: Math.round(rect.height),
        };
      }),
    };
  }, { selector, datasetKey });
  if (opts.allowAbsent && (!state.tablePresent || !state.rowPresent)) {
    return;
  }
  const missing = expectedActions.filter((expected) => !state.actions.some((actual) => actual.action === expected.action && actual.label.includes(expected.label)));
  if (missing.length) {
    throw new Error(`traffic actions ${selector} missing expected controls at ${viewport.name}: ${JSON.stringify({ missing, state })}`);
  }
  const invalid = state.actions.filter((action) =>
    !action.action ||
    action.type !== "button" ||
    !action.title ||
    !action.ariaLabel ||
    action.width < 44 ||
    action.height < 32);
  if (invalid.length) {
    throw new Error(`traffic actions ${selector} accessibility mismatch at ${viewport.name}: ${JSON.stringify({ invalid, state })}`);
  }
}

async function assertSystemLogsWorkbench(page, viewport) {
  await ensureSeededInvestigationTelemetry();
  const filteredHash = "#/logs?source=engine&engine=suricata&severity=warn&q=degraded&limit=100";
  await page.evaluate((hash) => { location.hash = hash; }, filteredHash);
  await waitForRouteReady(page, "/logs");
  await page.waitForFunction(() => Boolean(document.querySelector('[data-logs-workbench="true"] [data-system-log-row]')), null, { timeout: 10000 });
  const state = await page.evaluate(async () => {
    const response = await fetch("/v1/system/logs?limit=100&source=engine&engine=suricata&severity=warn&query=degraded");
    if (!response.ok) return { ok: false, status: response.status, text: await response.text() };
    const data = await response.json();
    const entry = data.entries?.[0] || null;
    return {
      ok: true,
      entry,
      filters: [...document.querySelectorAll("[data-logs-filter]")].map((node) => node.getAttribute("data-logs-filter")),
      logActions: [...document.querySelectorAll("button[data-logs-action]")].map((node) => ({
        action: node.getAttribute("data-logs-action") || "",
        type: node.getAttribute("type") || "",
        title: node.getAttribute("title") || "",
        ariaLabel: node.getAttribute("aria-label") || "",
      })),
      evidenceActions: [...document.querySelectorAll('[data-evidence-surface="system-logs"] [data-evidence-action]')].map((node) => ({
        action: node.getAttribute("data-evidence-action") || "",
        type: node.getAttribute("type") || "",
        title: node.getAttribute("title") || "",
        ariaLabel: node.getAttribute("aria-label") || "",
      })),
      rowCount: document.querySelectorAll("[data-system-log-row]").length,
      tableClass: document.querySelector(".system-log-table")?.className || "",
      rowLabels: [...(document.querySelector("[data-system-log-row]")?.querySelectorAll("td") || [])].map((node) => node.getAttribute("data-label") || ""),
      hasMessageCell: Boolean(document.querySelector(".system-log-table .system-log-message-cell")),
      hasFileCell: Boolean(document.querySelector(".system-log-table .system-log-file-cell")),
      mobileLabelsRendered: window.innerWidth <= 820
        ? [...(document.querySelector("[data-system-log-row]")?.querySelectorAll("td") || [])].every((node) => {
            const before = getComputedStyle(node, "::before").content || "";
            return before !== "none" && before !== "\"\"" && before.length > 2;
          })
        : true,
      contentFits: [...document.querySelectorAll(".system-log-message-cell code, .system-log-file-cell .mono")].every((node) => {
        const box = node.getBoundingClientRect();
        const parent = node.closest("td")?.getBoundingClientRect();
        return !parent || box.right <= parent.right + 2;
      }),
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
      content: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
      hash: location.hash,
    };
  });
  if (!state.ok) {
    throw new Error(`system logs API failed at ${viewport.name}: ${state.status} ${state.text || ""}`);
  }
  if (!state.entry?.id || state.entry.source !== "engine" || state.entry.engine !== "suricata" || state.entry.severity !== "warn") {
    throw new Error(`system logs seeded entry missing or misclassified at ${viewport.name}: ${JSON.stringify(state.entry)}`);
  }
  for (const filter of ["query", "source", "engine", "severity", "limit"]) {
    if (!state.filters.includes(filter)) throw new Error(`system logs filter hook missing ${filter} at ${viewport.name}`);
  }
  for (const action of ["api-cli", "refresh", "clear"]) {
    const button = state.logActions.find((item) => item.action === action);
    if (!button) throw new Error(`system logs page action missing ${action} at ${viewport.name}: ${JSON.stringify(state.logActions)}`);
    if (button.type !== "button" || !button.title || !button.ariaLabel) {
      throw new Error(`system logs page action ${action} was not accessible at ${viewport.name}: ${JSON.stringify(button)}`);
    }
  }
  for (const action of ["copy-link", "copy-api", "copy-cli", "export-json", "export-csv"]) {
    const button = state.evidenceActions.find((item) => item.action === action);
    if (!button) throw new Error(`system logs evidence action missing ${action} at ${viewport.name}: ${JSON.stringify(state.evidenceActions)}`);
    if (button.type !== "button" || !button.title || !button.ariaLabel) {
      throw new Error(`system logs evidence action ${action} was not accessible at ${viewport.name}: ${JSON.stringify(button)}`);
    }
  }
  const expectedLabels = ["Time", "Source", "Engine", "Severity", "Message", "File"];
  if (JSON.stringify(state.rowLabels) !== JSON.stringify(expectedLabels)) {
    throw new Error(`system logs responsive row labels mismatch at ${viewport.name}: ${JSON.stringify(state.rowLabels)}`);
  }
  if (!state.tableClass.includes("responsive-evidence")) throw new Error(`system logs table missing responsive-evidence at ${viewport.name}: ${state.tableClass}`);
  if (!state.hasMessageCell || !state.hasFileCell) throw new Error(`system logs table primitive cell hooks missing at ${viewport.name}: ${JSON.stringify(state)}`);
  if (!state.mobileLabelsRendered) throw new Error(`system logs mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  if (!state.contentFits) throw new Error(`system logs table content overflowed cells at ${viewport.name}: ${JSON.stringify(state)}`);
  if (state.overflow > 2) throw new Error(`system logs route overflow at ${viewport.name}: ${state.overflow}px`);
  if (!state.content.includes("System logs") || !state.content.includes("suricata") || !state.content.includes("Bearer [redacted]") || !state.content.includes("access_token=[redacted]")) {
    throw new Error(`system logs filtered content missing expected redacted evidence at ${viewport.name}: ${state.content}`);
  }
  assertNoInvestigationLeak(state.content, `system logs filtered content ${viewport.name}`);

  await assertAutomationContextDrawer(page, viewport, "system logs automation context", [
    "/v1/system/logs?limit=100&source=engine&engine=suricata&severity=warn&query=degraded",
    "ngfwctl system logs --limit 100 --source engine --engine suricata --severity warn --query degraded",
  ]);

  await page.evaluate((entryId) => {
    const row = document.querySelector(`[data-log-entry-id="${entryId}"]`);
    if (!row) throw new Error(`system log row ${entryId} was not found`);
    row.click();
  }, state.entry.id);
  await waitForDrawerTitle(page, "WARN log event");
  let drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "system log drawer", [
    "WARN log event",
    "Source",
    "engine",
    "Engine",
    "suricata",
    "Severity",
    "warn",
    "Message",
    "suricata engine degraded",
    "Bearer [redacted]",
    "access_token=[redacted]",
    "Derived context",
    `${investigationSeed.srcIp}:${investigationSeed.srcPort}`,
    `${investigationSeed.destIp}:${investigationSeed.destPort}`,
    String(investigationSeed.signatureId),
    "Threats",
    "Traffic",
    "Troubleshoot",
    "Investigation",
  ], ["Copy packet", "Export JSON", "Pin to case", "Close"]);
  assertNoInvestigationLeak(drawer.text, `system log drawer ${viewport.name}`);
  const drawerActions = await page.evaluate(() =>
    [...document.querySelectorAll("#drawer:not([hidden]) button[data-log-action]")].map((node) => ({
      action: node.getAttribute("data-log-action") || "",
      type: node.getAttribute("type") || "",
      title: node.getAttribute("title") || "",
      ariaLabel: node.getAttribute("aria-label") || "",
      text: (node.textContent || "").replace(/\s+/g, " ").trim(),
    })));
  for (const action of ["copy-packet", "export-json", "pin-case", "close"]) {
    const button = drawerActions.find((item) => item.action === action);
    if (!button) throw new Error(`system log drawer action missing ${action} at ${viewport.name}: ${JSON.stringify(drawerActions)}`);
    if (button.type !== "button" || !button.title || !button.ariaLabel) {
      throw new Error(`system log drawer action ${action} was not accessible at ${viewport.name}: ${JSON.stringify(button)}`);
    }
  }
  const pivotState = await page.evaluate(() => {
    const href = (name) => document.querySelector(`[data-system-log-drawer="true"] [data-log-pivot="${name}"]`)?.getAttribute("href") || "";
    return {
      traffic: href("traffic"),
      threats: href("threats"),
      troubleshoot: href("troubleshoot"),
      derived: (document.querySelector('[data-system-log-drawer="true"] [data-log-derived-context="true"]')?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  });
  const expectedTraffic = `#/traffic?mode=flows&ip=${encodeURIComponent(investigationSeed.srcIp)}&protocol=${investigationSeed.protocol}&port=${investigationSeed.destPort}&app=${investigationSeed.appProto}&flowId=${investigationSeed.flowId}&limit=100`;
  const expectedThreats = `#/threats?signatureId=${investigationSeed.signatureId}&ip=${encodeURIComponent(investigationSeed.srcIp)}&protocol=${investigationSeed.protocol}&port=${investigationSeed.destPort}&flowId=${investigationSeed.flowId}&limit=100`;
  const expectedTroubleshoot = `#/troubleshoot?source=POLICY_SOURCE_RUNNING&src=${encodeURIComponent(investigationSeed.srcIp)}&sport=${investigationSeed.srcPort}&dst=${encodeURIComponent(investigationSeed.destIp)}&dport=${investigationSeed.destPort}&protocol=PROTOCOL_${investigationSeed.protocol}&app=${investigationSeed.appProto}&flowId=${investigationSeed.flowId}&runtime=1`;
  if (pivotState.traffic !== expectedTraffic || pivotState.threats !== expectedThreats || pivotState.troubleshoot !== expectedTroubleshoot) {
    throw new Error(`system log derived pivot href mismatch at ${viewport.name}: ${JSON.stringify({ pivotState, expectedTraffic, expectedThreats, expectedTroubleshoot })}`);
  }
  if (!pivotState.derived.includes(investigationSeed.appProto) || !pivotState.derived.includes(String(investigationSeed.signatureId))) {
    throw new Error(`system log derived context missing tuple evidence at ${viewport.name}: ${JSON.stringify(pivotState)}`);
  }
  await page.waitForFunction((entryId) => new URLSearchParams((location.hash.split("?")[1] || "")).get("entry") === entryId, state.entry.id, { timeout: 5000 });

  await page.evaluate(() => {
    globalThis.__systemLogCopiedText = "";
    const writeText = async (text) => {
      globalThis.__systemLogCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try { navigator.clipboard.writeText = writeText; } catch {}
    }
  });
  await clickDrawerFooterButton(page, "Copy packet");
  await page.waitForFunction(() => Boolean(globalThis.__systemLogCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__systemLogCopiedText || "");
  if (!copied.includes("kind=system-log") || !copied.includes("source=engine") || !copied.includes("severity=warn")) {
    throw new Error(`system log copied packet missing expected evidence at ${viewport.name}: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `system log copied packet ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickDrawerFooterButton(page, "Export JSON");
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^phragma-investigation-system-log-.*\.json$/.test(filename)) {
    throw new Error(`system log export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) throw new Error(`system log export did not produce a readable file at ${viewport.name}`);
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `system log export ${viewport.name}`);
  const packet = JSON.parse(text);
  if (packet?.schemaVersion !== "phragma.investigation.handoff.v1" ||
      packet?.kind !== "system-log" ||
      packet?.artifacts?.log?.engine !== "suricata" ||
      packet?.summary?.flowId !== investigationSeed.flowId ||
      packet?.summary?.srcIp !== investigationSeed.srcIp ||
      packet?.summary?.destIp !== investigationSeed.destIp ||
      String(packet?.summary?.destPort || "") !== String(investigationSeed.destPort) ||
      packet?.summary?.appId !== investigationSeed.appProto ||
      String(packet?.summary?.signatureId || "") !== String(investigationSeed.signatureId) ||
      packet?.artifacts?.flow?.flowId !== investigationSeed.flowId ||
      String(packet?.artifacts?.alert?.signatureId || "") !== String(investigationSeed.signatureId) ||
      !String(packet?.artifacts?.logContext?.troubleshootHash || "").includes("#/troubleshoot?")) {
    throw new Error(`system log export had unexpected packet identity/context at ${viewport.name}: ${JSON.stringify({ schemaVersion: packet?.schemaVersion, kind: packet?.kind, engine: packet?.artifacts?.log?.engine, summary: packet?.summary, flow: packet?.artifacts?.flow, alert: packet?.artifacts?.alert, context: packet?.artifacts?.logContext })}`);
  }

  await clickDrawerFooterButton(page, "Pin to case");
  const pinned = await page.evaluate((entryId) => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    const data = JSON.parse(raw);
    const item = (data.items || []).find((candidate) => candidate.packet?.kind === "system-log" && candidate.packet?.subject?.id === entryId);
    return {
      hasPacket: Boolean(item),
      flowId: item?.packet?.summary?.flowId || "",
      srcIp: item?.packet?.summary?.srcIp || "",
      destIp: item?.packet?.summary?.destIp || "",
      signatureId: String(item?.packet?.summary?.signatureId || ""),
      hasFlowArtifact: Boolean(item?.packet?.artifacts?.flow?.flowId),
      raw,
    };
  }, state.entry.id);
  if (!pinned.hasPacket) throw new Error(`system log pin did not add investigation case item at ${viewport.name}: ${pinned.raw}`);
  if (pinned.flowId !== investigationSeed.flowId || pinned.srcIp !== investigationSeed.srcIp || pinned.destIp !== investigationSeed.destIp || pinned.signatureId !== String(investigationSeed.signatureId) || !pinned.hasFlowArtifact) {
    throw new Error(`system log pinned packet lost derived context at ${viewport.name}: ${JSON.stringify(pinned)}`);
  }
  assertNoInvestigationLeak(pinned.raw, `system log pinned packet ${viewport.name}`);

  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await page.waitForFunction(() => !new URLSearchParams((location.hash.split("?")[1] || "")).has("entry"), null, { timeout: 5000 });

  await runSmokeStep("system logs saved filters", () => assertSystemLogsSavedFilterLifecycle(page, viewport, filteredHash, state.entry.id));
  await runSmokeStep("system logs routed entry reload", () => assertSystemLogsRoutedEntryReload(page, viewport, filteredHash, state.entry.id));
  await runSmokeStep("system logs empty state", () => assertSystemLogsEmptyState(page, viewport, filteredHash));
}

async function assertSystemLogsSavedFilterLifecycle(page, viewport, routeHash, entryId) {
  const scope = "system-logs";
  const name = `system logs ${viewport.name}`;
  await page.evaluate(({ hash, filterScope }) => {
    localStorage.removeItem(`openngfw.savedFilters.${filterScope}`);
    location.hash = hash;
  }, { hash: routeHash + `&entry=${entryId}`, filterScope: scope });
  await waitForRouteReady(page, "/logs");
  await waitForDrawerTitle(page, "WARN log event");
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await page.waitForSelector(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="name"]`, { timeout: 10000 });
  await page.fill('[data-logs-filter="query"]', "degraded");
  await page.selectOption('[data-logs-filter="source"]', "engine");
  await page.selectOption('[data-logs-filter="engine"]', "suricata");
  await page.selectOption('[data-logs-filter="severity"]', "warn");
  await page.selectOption('[data-logs-filter="limit"]', "100");
  await waitForHashParams(page, { q: "degraded", source: "engine", engine: "suricata", severity: "warn", limit: "100" });
  await page.fill(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="name"]`, name);
  await clickSavedFilterAction(page, scope, "save");
  await page.waitForFunction(({ filterScope, filterName }) => {
    const select = document.querySelector(`[data-saved-filter-scope="${filterScope}"][data-saved-filter-control="select"]`);
    return [...(select?.options || [])].some((option) => option.value === filterName);
  }, { filterScope: scope, filterName: name }, { timeout: 5000 });
  const saved = await savedFilterStorageState(page, scope);
  const entry = saved.entries.find((item) => item.name === name);
  if (!entry) {
    throw new Error(`system logs saved filter was not persisted at ${viewport.name}: ${JSON.stringify(saved)}`);
  }
  if (Object.prototype.hasOwnProperty.call(entry.state || {}, "entry")) {
    throw new Error(`system logs saved filter persisted transient entry key at ${viewport.name}: ${JSON.stringify(entry)}`);
  }
  await page.evaluate(() => { location.hash = "#/logs"; });
  await waitForRouteReady(page, "/logs");
  await page.selectOption(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="select"]`, name);
  await clickSavedFilterAction(page, scope, "apply");
  await waitForHashParams(page, { q: "degraded", source: "engine", engine: "suricata", severity: "warn", limit: "100" });
  await page.selectOption(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="select"]`, name);
  await clickSavedFilterAction(page, scope, "delete");
  await page.waitForFunction(({ filterScope, filterName }) => {
    const raw = localStorage.getItem(`openngfw.savedFilters.${filterScope}`) || "[]";
    let entries = [];
    try { entries = JSON.parse(raw); } catch {}
    const select = document.querySelector(`[data-saved-filter-scope="${filterScope}"][data-saved-filter-control="select"]`);
    return !entries.some((item) => item?.name === filterName) &&
      ![...(select?.options || [])].some((option) => option.value === filterName);
  }, { filterScope: scope, filterName: name }, { timeout: 5000 });
}

async function assertSystemLogsRoutedEntryReload(page, viewport, routeHash, entryId) {
  await page.evaluate(({ hash, id }) => { location.hash = `${hash}&entry=${id}`; }, { hash: routeHash, id: entryId });
  await waitForRouteReady(page, "/logs");
  await waitForDrawerTitle(page, "WARN log event");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "system log routed drawer", ["WARN log event", "suricata engine degraded", "Threats", "Traffic", "Troubleshoot", "Investigation"], ["Copy packet", "Export JSON", "Pin to case", "Close"]);
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
}

async function assertSystemLogsEmptyState(page, viewport, restoreHash) {
  await page.evaluate(() => { location.hash = "#/logs?source=audit&q=no-such-visual-smoke-log&limit=100"; });
  await waitForRouteReady(page, "/logs");
  await page.waitForSelector('[data-logs-empty-state="true"]', { timeout: 10000 });
  const state = await page.evaluate(() => {
    const root = document.querySelector('[data-logs-empty-state="true"]');
    const rect = root?.getBoundingClientRect?.();
    return {
      text: root?.textContent || "",
      hasRetiredReadinessAction: Boolean(root?.querySelector('a[href^="#/readiness"]')),
      overflow: root ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(root.scrollWidth - root.clientWidth)) : 999,
    };
  });
  if (!state.text.includes("No matching log events") || state.hasRetiredReadinessAction) {
    throw new Error(`system logs empty state was missing its text or exposed the retired readiness route at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`system logs empty state overflow at ${viewport.name}: ${state.overflow}px`);
  }
  await page.evaluate((hash) => { location.hash = hash; }, restoreHash);
  await waitForRouteReady(page, "/logs");
  await page.waitForSelector("[data-system-log-row]", { timeout: 10000 });
}

async function assertAppIdObservationQueuePromotion(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  try {
    const observation = await findAppIdQueueObservation(page);
    await page.evaluate((obs) => {
      const params = new URLSearchParams();
      params.set("mode", "app-id");
      params.set("q", "weird-proto");
      params.set("port", String(obs.destPort || 9443));
      params.set("queueId", obs.queueId);
      location.hash = "#/traffic?" + params.toString();
    }, observation);
    await waitForRouteReady(page, "/traffic");
    await waitForDrawerTitle(page, "App-ID observation");
    const drawer = await collectDrawerState(page);
    assertDrawerContains(drawer, viewport, "App-ID observation queue drawer", [
      "App-ID observation",
      "Queue ID",
      observation.queueId,
      "Engine signal",
      appIdQueueSeed.appProto,
      "Suggested object",
      "Candidate path",
    ], ["Close", "Matching flows", "Capture sample", "API / CLI", "Promote App-ID"]);
    await assertTrafficDrawerActions(page, viewport, "App-ID observation", "appidObservationAction", [
      "close",
      "matching-flows",
      "capture-sample",
      "api-cli",
      "promote-app-id",
    ]);
    await assertTrafficDrawerActions(page, viewport, "App-ID observation handoff", "trafficHandoffAction", ["pin", "copy", "export"]);

    await clickDrawerFooterButton(page, "API / CLI");
    await waitForDrawerTitle(page, "API / CLI context");
    const contextDrawer = await collectDrawerState(page);
    assertDrawerContains(contextDrawer, viewport, "App-ID observation selected API / CLI drawer action", [
      `/v1/app-id/observations/${observation.queueId}:stage`,
      `/v1/app-id/observations/${observation.queueId}:stage-regression-sample`,
      `Selected App-ID queue item: ${observation.queueId}`,
      `ngfwctl app-id promote ${observation.queueId} --reason "reviewed App-ID observation"`,
      `ngfwctl app-id promote ${observation.queueId} --drop --confirm-drop`,
      `ngfwctl app-id corpus add ${observation.queueId} --pcap-sha256`,
    ], ["Copy session JSON", "Copy context"]);
    assertAutomationContextRedaction(contextDrawer.text, `App-ID observation selected API / CLI drawer action ${viewport.name}`);
    await clickDrawerFooterButton(page, "Cancel");
    await waitForDrawerClosed(page);
    await page.evaluate(() => { location.hash = "#/traffic"; });
    await waitForRouteReady(page, "/traffic");
    await page.evaluate((obs) => {
      const params = new URLSearchParams();
      params.set("mode", "app-id");
      params.set("q", "weird-proto");
      params.set("port", String(obs.destPort || 9443));
      params.set("queueId", obs.queueId);
      location.hash = "#/traffic?" + params.toString();
    }, observation);
    await waitForRouteReady(page, "/traffic");
    await waitForDrawerTitle(page, "App-ID observation");

    await runSmokeStep("App-ID regression sample drawer", async () => {
      const hasPanel = await page.locator("#drawer:not([hidden]) [data-appid-regression-sample-panel='true']").count();
      if (!hasPanel) throw new Error("App-ID observation drawer missing regression sample panel");
      await page.click("#drawer:not([hidden]) [data-appid-action='stage-regression-sample']");
      await waitForDrawerTitle(page, "App-ID regression sample");
      await page.waitForSelector("#drawer:not([hidden]) [data-appid-regression-sample-drawer='true']", { timeout: 5000 });
      await assertTrafficDrawerActions(page, viewport, "App-ID regression sample", "appidRegressionAction", ["close", "stage-sample"]);
      await clickDrawerFooterButton(page, "Stage sample");
      await page.waitForTimeout(200);
      const emptyState = await page.evaluate(() => {
        const root = document.querySelector("#drawer:not([hidden]) [data-appid-regression-sample-drawer='true']");
        const status = root?.querySelector("[data-appid-regression-status]")?.textContent || "";
        return {
          stillOpen: Boolean(root),
          status,
          staged: root?.querySelector("[data-appid-regression-status='staged']")?.textContent || "",
        };
      });
      if (!emptyState.stillOpen || emptyState.staged) {
        throw new Error(`App-ID regression sample accepted missing SHA unexpectedly: ${JSON.stringify(emptyState)}`);
      }
      const sha = "b".repeat(64);
      await page.fill("#drawer:not([hidden]) [data-appid-regression-field='pcap-sha256']", sha);
      await page.fill("#drawer:not([hidden]) [data-appid-regression-field='expected-app']", appIdQueueSeed.customAppId);
      await page.fill("#drawer:not([hidden]) [data-appid-regression-field='observed-app']", appIdQueueSeed.appProto);
      await page.fill("#drawer:not([hidden]) [data-appid-regression-field='reason']", `visual smoke reviewed App-ID observation ${observation.queueId}`);
      await clickDrawerFooterButton(page, "Stage sample");
      await page.waitForFunction(() => {
        const status = document.querySelector("#drawer:not([hidden]) [data-appid-regression-status='staged']");
        return /Staged .*samples?\)/.test(status?.textContent || "");
      }, null, { timeout: 10000 });
      const staged = await collectDrawerState(page);
      assertDrawerContains(staged, viewport, "App-ID regression sample staged drawer", [
        "App-ID regression sample",
        "Staged",
        "samples",
      ], ["Close", "Stage sample"]);
      await clickDrawerFooterButton(page, "Close");
      await waitForDrawerClosed(page);
    });

    await page.evaluate(() => { location.hash = "#/traffic"; });
    await waitForRouteReady(page, "/traffic");
    await page.evaluate((obs) => {
      const params = new URLSearchParams();
      params.set("mode", "app-id");
      params.set("q", "weird-proto");
      params.set("port", String(obs.destPort || 9443));
      params.set("queueId", obs.queueId);
      location.hash = "#/traffic?" + params.toString();
    }, observation);
    await waitForRouteReady(page, "/traffic");
    await waitForDrawerTitle(page, "App-ID observation");

    await clickDrawerFooterButton(page, "Promote App-ID");
    await waitForDrawerTitle(page, "Custom App-ID");
    await fillCustomAppIdReviewDrawer(page, appIdQueueSeed);
    await assertCustomAppIdReviewDrawer(page, viewport, appIdQueueSeed);
    await assertTrafficDrawerActions(page, viewport, "queued custom App-ID", "appidAction", [
      "cancel-custom-app",
      "save-view",
      "review-drop",
      "save-drop",
      "save",
    ]);
    await clickDrawerFooterButton(page, "Save & drop");
    await waitForDrawerClosed(page);
    await page.waitForFunction(async (seed) => {
      const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
      if (!response.ok) return false;
      const policy = (await response.json())?.policy || {};
      return (policy.applications || []).some((app) => app?.name === seed.customAppId) &&
        (policy.rules || []).some((rule) => (rule?.name || "").startsWith(`drop-app-${seed.customAppId}-`));
    }, appIdQueueSeed, { timeout: 10000 });
    await assertReviewedAppIdDropCandidate(page, appIdQueueSeed);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/traffic"; });
    await waitForRouteReady(page, "/traffic");
  }
}

async function findAppIdQueueObservation(page) {
  return await page.evaluate(async (seed) => {
    const params = new URLSearchParams({
      query: seed.appProto,
      port: String(seed.destPort),
      limit: "50",
      flowLimit: "1000",
      confidenceThreshold: "70",
    });
    const response = await fetch("/v1/app-id/observations?" + params.toString());
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch (err) {
      throw new Error(`App-ID observation response was not JSON: ${err.message}; body=${text.slice(0, 200)}`);
    }
    if (!response.ok) {
      throw new Error(`App-ID observation lookup failed with HTTP ${response.status}: ${body.message || body.error || text}`);
    }
    const observations = Array.isArray(body.observations) ? body.observations : [];
    const match = observations.find((obs) =>
      String(obs.engineSignal || "").toLowerCase() === seed.appProto &&
      Number(obs.destPort || 0) === Number(seed.destPort));
    if (!match) {
      throw new Error(`App-ID queue observation for ${seed.appProto}/${seed.destPort} was not found: ${JSON.stringify(observations)}`);
    }
    if (!match.queueId) {
      throw new Error(`App-ID queue observation did not include queueId: ${JSON.stringify(match)}`);
    }
    return match;
  }, appIdQueueSeed);
}

async function assertThreatInvestigationWorkbench(page, viewport) {
  await ensureSeededInvestigationTelemetry();
  await assertSavedFilterLifecycle(page, viewport, {
    label: "threat saved filter",
    routeHash: "#/threats",
    routePath: "/threats",
    scope: "threats",
    filterRoot: ".telemetry-filters",
    fields: [
      { label: "Search", value: "Visual Smoke" },
      { label: "IP", value: investigationSeed.srcIp },
      { label: "Protocol", value: investigationSeed.protocol },
      { label: "Signature ID", value: String(investigationSeed.signatureId) },
      { label: "Port", value: String(investigationSeed.destPort) },
    ],
    expectedParams: { q: "Visual Smoke", ip: investigationSeed.srcIp, protocol: investigationSeed.protocol, signatureId: String(investigationSeed.signatureId), port: String(investigationSeed.destPort) },
    forbiddenStateKeys: ["alert", "flowId", "view", "exception"],
  });
  await assertThreatAutomationContextParity(page, viewport);
  await assertThreatFacetTableShape(page, viewport);

  await openSeededThreatDrawer(page);
  let drawer = await collectDrawerState(page);
  await assertThreatDrawerActionControls(page, viewport, "threat detail", {
    buttons: ["explain", "capture", "stage-fp", "drop-source"],
    links: ["Related flow", "Capture audit"],
    handoff: ["pin-case", "copy-handoff", "export-json"],
  });
  assertDrawerContains(drawer, viewport, "threat detail", [
    "Threat detail",
    "Threat-ID",
    "suricata-sid-9000001",
    "Signature",
    investigationSeed.signature,
    "Flow ID",
    investigationSeed.flowId,
    "Source",
    `${investigationSeed.srcIp}:${investigationSeed.srcPort}`,
    "Destination",
    `${investigationSeed.destIp}:${investigationSeed.destPort}`,
    "Evidence",
    "Packet capture evidence",
    "Respond to this detection:",
  ], ["Close", "Explain", "Capture", "Stage FP exception", "Drop this source"]);

  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/threats", ["alert"]);

  await openSeededThreatDrawer(page);
  let initialHash = await clickDrawerFooterButton(page, "Explain");
  assertInvestigationActionHash(initialHash, "explain");
  await assertTroubleshootInvestigation(page, viewport, "explain");

  await openSeededThreatDrawer(page);
  initialHash = await clickDrawerFooterButton(page, "Capture");
  assertInvestigationActionHash(initialHash, "capture");
  await assertTroubleshootInvestigation(page, viewport, "capture", { skipCaptureLifecycle: true });

  await openSeededThreatDrawer(page);
  await clickDrawerFooterButton(page, "Stage FP exception");
  await waitForSelectionCleared(page, "/threats", ["alert"]);
  await waitForDrawerTitle(page, "Stage false-positive exception");
  await assertThreatFalsePositiveDrawer(page, viewport);
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);

  await openSeededThreatDrawer(page);
  await clickDrawerFooterButton(page, "Drop this source");
  await waitForSelectionCleared(page, "/threats", ["alert"]);
  await waitForDrawerTitle(page, "New rule");
  await assertRuleEditorCandidateOnly(page, viewport, "ACTION_DENY", { namePrefix: "drop-", expectLog: true });
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function assertThreatFacetTableShape(page, viewport) {
  await page.evaluate((seed) => {
    location.hash = `#/threats?ip=${encodeURIComponent(seed.srcIp)}&protocol=${encodeURIComponent(seed.protocol)}&signatureId=${encodeURIComponent(String(seed.signatureId))}&port=${encodeURIComponent(String(seed.destPort))}&limit=100`;
  }, investigationSeed);
  await waitForRouteReady(page, "/threats");
  await page.waitForFunction(() => Boolean(document.querySelector(".threats-table [data-threat-alert-row]")), null, { timeout: 10000 });
  const initial = await page.evaluate(() => ({
    facetCount: document.querySelectorAll("[data-threat-facet]").length,
    facetStates: [...document.querySelectorAll("[data-threat-facet]")].map((node) => ({
      value: node.getAttribute("data-threat-facet") || "",
      pressed: node.getAttribute("aria-pressed") || "",
      selected: node.classList.contains("is-selected"),
    })),
    tableClass: document.querySelector(".threats-table")?.className || "",
    labels: [...(document.querySelector(".threats-table [data-threat-alert-row]")?.querySelectorAll("td") || [])].map((node) => node.getAttribute("data-label") || ""),
    hasThreatIdCell: Boolean(document.querySelector(".threats-table .threat-id-cell")),
    hasTimeCell: Boolean(document.querySelector(".threats-table .cell-time")),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (initial.facetCount !== 4) throw new Error(`Threats facet count mismatch at ${viewport.name}: ${initial.facetCount}`);
  for (const value of ["1", "2", "3", "4"]) {
    const facet = initial.facetStates.find((item) => item.value === value);
    if (!facet || !["true", "false"].includes(facet.pressed)) throw new Error(`Threats facet ${value} missing aria state at ${viewport.name}: ${JSON.stringify(initial.facetStates)}`);
  }
  if (!initial.tableClass.includes("responsive-evidence")) throw new Error(`Threats table missing responsive-evidence at ${viewport.name}: ${initial.tableClass}`);
  for (const label of ["Severity", "Policy", "Threat-ID", "Source", "Destination", "Outcome", "Time"]) {
    if (!initial.labels.includes(label)) throw new Error(`Threats table label missing ${label} at ${viewport.name}: ${JSON.stringify(initial.labels)}`);
  }
  if (!initial.hasThreatIdCell || !initial.hasTimeCell) throw new Error(`Threats table class hooks missing at ${viewport.name}: ${JSON.stringify(initial)}`);
  if (initial.overflow > 2) throw new Error(`Threats table route overflow at ${viewport.name}: ${initial.overflow}px`);
}

async function assertThreatAutomationContextParity(page, viewport) {
  await page.evaluate((seed) => {
    location.hash = `#/threats?threatSeverity=high&ip=${encodeURIComponent(seed.srcIp)}&protocol=${encodeURIComponent(seed.protocol)}&signatureId=${encodeURIComponent(String(seed.signatureId))}&port=${encodeURIComponent(String(seed.destPort))}&flowId=${encodeURIComponent(seed.flowId)}&limit=100`;
  }, investigationSeed);
  await waitForRouteReady(page, "/threats");
  await assertAutomationContextDrawer(page, viewport, "threats filtered automation context", [
    "#/threats?threatSeverity=high",
    `/v1/alerts?limit=100&ip=${investigationSeed.srcIp}&protocol=${investigationSeed.protocol}&threatSeverity=high&signatureId=${investigationSeed.signatureId}&port=${investigationSeed.destPort}&flowId=${investigationSeed.flowId}`,
    `ngfwctl alerts --limit 100 --ip ${investigationSeed.srcIp} --protocol ${investigationSeed.protocol} --threat-severity high --signature-id ${investigationSeed.signatureId} --port ${investigationSeed.destPort} --flow-id ${investigationSeed.flowId}`,
  ]);
}

async function assertInvestigationCaseWorkbench(page, viewport) {
  await page.waitForSelector("[data-investigation-cockpit='true']", { timeout: 10000 });
  await page.waitForSelector("[data-investigation-posture='true']", { timeout: 10000 });
  const state = await page.evaluate((seed) => {
    const content = document.querySelector("#content");
    const text = (content?.textContent || "").replace(/\s+/g, " ").trim();
    const plannerActions = [...(content?.querySelectorAll("[data-remediation-action]") || [])].map((el) => ({
      id: el.dataset.remediationAction || "",
      href: el.getAttribute("href") || "",
      disabled: Boolean(el.disabled) || el.classList.contains("disabled"),
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const caseActions = [...(content?.querySelectorAll("[data-case-action]") || [])].map((el) => ({
      id: el.dataset.caseAction || "",
      href: el.getAttribute("href") || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const remediationPlan = content?.querySelector("[data-remediation-plan='true']");
    const planSteps = [...(content?.querySelectorAll("[data-remediation-step]") || [])].map((el) => ({
      id: el.dataset.remediationStep || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
      href: el.querySelector("a")?.getAttribute("href") || "",
      status: el.querySelector(".investigation-step-status")?.textContent?.trim() || "",
    }));
    const evidenceChips = [...(content?.querySelectorAll("[data-evidence-id]") || [])].map((el) => ({
      id: el.dataset.evidenceId || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
      ready: el.classList.contains("ready"),
    }));
    const compare = content?.querySelector(".investigation-compare");
    const compareRow = compare?.querySelector("tbody tr");
    const compareCells = [...(compareRow?.querySelectorAll("td") || [])];
    const rows = [...(compare?.querySelectorAll("tbody tr") || [])].map((row) => (row.textContent || "").replace(/\s+/g, " ").trim());
    const routeLabels = [...(content?.querySelectorAll(".investigation-kv dd") || [])].map((el) => (el.textContent || "").replace(/\s+/g, " ").trim());
    const buttons = [...(content?.querySelectorAll("button") || [])].map((button) => ({
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      investigationAction: button.dataset.investigationAction || "",
      caseAction: button.dataset.investigationCaseAction || "",
      caseKey: button.dataset.investigationCaseKey || "",
      className: button.className || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
      type: button.getAttribute("type") || "",
      disabled: button.disabled,
      width: button.getBoundingClientRect().width,
      height: button.getBoundingClientRect().height,
    }));
    return {
      text,
      plannerActions,
      caseActions,
      remediationPlan: remediationPlan ? {
        status: remediationPlan.dataset.remediationPlanStatus || "",
        primaryAction: remediationPlan.dataset.remediationPrimaryAction || "",
        text: (remediationPlan.textContent || "").replace(/\s+/g, " ").trim(),
      } : null,
      planSteps,
      evidenceChips,
      rows,
      compareTable: {
        tableClass: compare?.className || "",
        labels: compareCells.map((cell) => cell.getAttribute("data-label") || ""),
        overflow: compare ? Math.max(0, Math.ceil(compare.scrollWidth - compare.clientWidth)) : 0,
        mobileLabelsRendered: window.innerWidth > 820 || compareCells.every((cell) => {
          const before = getComputedStyle(cell, "::before").content || "";
          return before !== "none" && before !== "\"\"" && before.length > 2;
        }),
      },
      routeLabels,
      buttons,
      hasCapturePanel: Boolean(content?.querySelector(".capture-evidence")),
      seed,
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  }, investigationSeed);

  if (state.overflow > 2) {
    throw new Error(`investigation case route overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const removeButtons = state.buttons.filter((button) => button.caseAction === "remove");
  if (removeButtons.length < 7 || removeButtons.some((button) =>
    button.type !== "button" ||
    button.title !== "Remove from case" ||
    !/^Remove .+ from investigation case$/.test(button.ariaLabel) ||
    !button.caseKey ||
    !button.className.includes("icon-btn") ||
    button.width < 34 ||
    button.height < 34)) {
    throw new Error(`investigation case remove buttons were not accessible at ${viewport.name}: ${JSON.stringify(removeButtons)}`);
  }
  const requiredText = [
    "7 pinned evidence items",
    "Case cockpit",
    "Evidence custody",
    "redaction active",
    "Remediation planner",
    "Multi-evidence fix plan",
    "Threat-to-policy remediation ready",
    "Candidate decision differs from running policy",
    investigationSeed.flowId,
    investigationSeed.signature,
    "Flow investigation handoff",
    "Threat alert investigation handoff",
    "Packet capture investigation handoff",
    "NAT path preview handoff",
    "Audit entry handoff",
    "Content package lifecycle handoff",
    "redacted unsafe route",
    "[server-local path redacted]",
  ];
  const missingText = requiredText.filter((needle) => !state.text.includes(needle));
  if (missingText.length) {
    throw new Error(`investigation case missing text at ${viewport.name}: ${missingText.join(", ")}`);
  }
  if (state.rows.length < 7) {
    throw new Error(`investigation compare table rendered too few rows at ${viewport.name}: ${state.rows.length}`);
  }
  if (!state.compareTable.tableClass.includes("responsive-evidence") || !state.compareTable.tableClass.includes("investigation-compare")) {
    throw new Error(`investigation compare table missing responsive class at ${viewport.name}: ${JSON.stringify(state.compareTable)}`);
  }
  const expectedCompareLabels = ["Evidence", "Tuple", "App", "Verdict", "Rule", "Policy", "Capture"];
  const missingCompareLabels = expectedCompareLabels.filter((label) => !state.compareTable.labels.includes(label));
  if (missingCompareLabels.length) {
    throw new Error(`investigation compare table missing labels at ${viewport.name}: ${JSON.stringify({ missingCompareLabels, table: state.compareTable })}`);
  }
  if (state.compareTable.overflow > 2) {
    throw new Error(`investigation compare table overflow at ${viewport.name}: ${state.compareTable.overflow}px`);
  }
  if (!state.compareTable.mobileLabelsRendered) {
    throw new Error(`investigation compare table mobile labels did not render at ${viewport.name}: ${JSON.stringify(state.compareTable)}`);
  }
  if (!state.hasCapturePanel) {
    throw new Error("investigation case did not expose packet-capture evidence panel");
  }
  const apiCliButton = state.buttons.find((button) => button.investigationAction === "api-cli");
  if (!apiCliButton || apiCliButton.disabled || apiCliButton.type !== "button" || !apiCliButton.title || !apiCliButton.ariaLabel) {
    throw new Error(`investigation case did not expose an enabled API / CLI action at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
  }
  const requiredInvestigationActions = ["api-cli", "copy-case", "export-case", "clear-case"];
  const missingInvestigationActions = requiredInvestigationActions.filter((action) => !state.buttons.some((button) =>
    button.investigationAction === action &&
    button.type === "button" &&
    button.title &&
    button.ariaLabel));
  if (missingInvestigationActions.length) {
    throw new Error(`investigation case action controls missing explicit semantics at ${viewport.name}: ${missingInvestigationActions.join(", ")} state=${JSON.stringify(state.buttons)}`);
  }
  if (!state.remediationPlan) {
    throw new Error("investigation case did not expose multi-evidence remediation plan");
  }
  if (state.remediationPlan.status !== "ready" || state.remediationPlan.primaryAction !== "threat-exception") {
    throw new Error(`investigation remediation plan not ready for threat owner workflow: ${JSON.stringify(state.remediationPlan)}`);
  }
  const requiredEvidence = ["traffic", "threat", "capture", "policy", "app-id", "nat"];
  const missingEvidence = requiredEvidence.filter((id) => !state.evidenceChips.some((chip) => chip.id === id && chip.ready));
  if (missingEvidence.length) {
    throw new Error(`investigation remediation plan missing ready evidence: ${missingEvidence.join(", ")}`);
  }
  const requiredSteps = ["correlate", "packet-proof", "candidate-compare", "owner-workspace"];
  const missingSteps = requiredSteps.filter((id) => !state.planSteps.some((step) => step.id === id));
  if (missingSteps.length) {
    throw new Error(`investigation remediation plan missing step(s): ${missingSteps.join(", ")}`);
  }
  const incompleteSteps = state.planSteps.filter((step) => requiredSteps.includes(step.id) && !/complete|ready/i.test(step.status));
  if (incompleteSteps.length) {
    throw new Error(`investigation remediation plan step(s) not ready: ${incompleteSteps.map((step) => `${step.id}:${step.status}`).join(", ")}`);
  }
  const requiredPlanner = ["explain", "capture", "candidate-rule", "threat-exception", "app-id", "nat-route"];
  const missingPlanner = requiredPlanner.filter((id) => !state.plannerActions.some((action) => action.id === id));
  if (missingPlanner.length) {
    throw new Error(`investigation planner missing action(s): ${missingPlanner.join(", ")}`);
  }
  const disabledPlanner = state.plannerActions.filter((action) => requiredPlanner.includes(action.id) && action.disabled);
  if (disabledPlanner.length) {
    throw new Error(`investigation planner unexpectedly disabled action(s): ${disabledPlanner.map((action) => action.id).join(", ")}`);
  }
  const hrefs = [...state.plannerActions.map((action) => action.href), ...state.caseActions.map((action) => action.href)].filter(Boolean).join("\n");
  for (const expectedHref of ["#/troubleshoot?", "intent=capture", "#/rules?", "#/threats?", "#/traffic?", "#/nat?"]) {
    if (!hrefs.includes(expectedHref)) {
      throw new Error(`investigation planner/action hrefs missing ${expectedHref}: ${hrefs}`);
    }
  }
  for (const expectedCustody of ["caseKey=", "caseAction=candidate-rule", "caseAction=threat-exception", "caseAction=app-id", "caseAction=nat-route"]) {
    if (!hrefs.includes(expectedCustody)) {
      throw new Error(`investigation planner/action hrefs missing custody marker ${expectedCustody}: ${hrefs}`);
    }
  }
  assertNoInvestigationLeak(`${state.text}\n${hrefs}`, `investigation case route ${viewport.name}`);
  await assertInvestigationRouteFocus(page, viewport);
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => button.text && !button.disabled && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`investigation mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }

  await assertInvestigationCopy(page, viewport);
  await assertInvestigationExport(page, viewport);
  await assertInvestigationServerCustody(page, viewport);
  await assertInvestigationAutomationContext(page, viewport);
  if (viewport.name === "desktop") {
    await assertInvestigationRulesCustodyHandoff(page);
    await assertInvestigationNonRulesCustodyHandoffs(page);
  }
}

async function assertInvestigationServerCustody(page, viewport) {
  await page.click("[data-investigation-action='server-save']");
  await page.waitForFunction(() => {
    const panel = document.querySelector("[data-investigation-server-custody='true']");
    const row = document.querySelector("[data-server-case-id]");
    return panel?.textContent?.includes("linked") && row?.dataset.serverCaseId;
  }, { timeout: 10000 });
  const before = await page.evaluate(() => {
    const row = document.querySelector("[data-server-case-id]");
    const match = row?.textContent?.match(/(\d+) evidence items? retained on server/);
    return {
      id: row?.dataset.serverCaseId || "",
      count: match ? Number(match[1]) : 0,
      text: row?.textContent || "",
    };
  });
  if (!before.id || before.count < 7) {
    throw new Error(`investigation server custody save did not retain seeded evidence at ${viewport.name}: ${JSON.stringify(before)}`);
  }
  await page.click(`[data-server-case-id="${before.id}"] button[aria-label="Append current browser evidence to this server case"]`);
  await page.waitForFunction(({ id, count }) => {
    const row = document.querySelector(`[data-server-case-id="${CSS.escape(id)}"]`);
    const match = row?.textContent?.match(/(\d+) evidence items? retained on server/);
    return match && Number(match[1]) > count;
  }, before, { timeout: 10000 });
  const after = await page.evaluate((id) => {
    const row = document.querySelector(`[data-server-case-id="${CSS.escape(id)}"]`);
    const match = row?.textContent?.match(/(\d+) evidence items? retained on server/);
    return {
      id: row?.dataset.serverCaseId || "",
      count: match ? Number(match[1]) : 0,
      text: row?.textContent || "",
      linked: document.querySelector("[data-investigation-server-custody='true']")?.textContent?.includes("linked") || false,
    };
  }, before.id);
  if (after.id !== before.id || after.count <= before.count || !after.linked) {
    throw new Error(`investigation server custody append did not update linked case at ${viewport.name}: before=${JSON.stringify(before)} after=${JSON.stringify(after)}`);
  }
}

async function assertInvestigationRouteFocus(page, viewport) {
  const target = await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    const parsed = JSON.parse(raw);
    const item = (parsed.items || []).find((entry) => entry.kind === "flow") || (parsed.items || [])[0] || null;
    if (!item?.key) return null;
    const q = new URLSearchParams();
    q.set("caseKey", item.key);
    q.set("caseAction", "candidate-rule");
    q.set("caseKind", item.kind || "flow");
    location.hash = "#/investigation?" + q.toString();
    return { key: item.key, kind: item.kind || "flow", route: item.source?.route || "" };
  });
  if (!target?.key) throw new Error(`investigation focus target not found at ${viewport.name}`);
  await waitForRouteReady(page, "/investigation");
  await page.waitForFunction((key) => {
    const row = document.querySelector(`[data-case-key="${CSS.escape(key)}"]`);
    return row?.dataset.caseFocused === "true" && document.querySelector("[data-case-focus-banner='true']");
  }, target.key, { timeout: 5000 });
  const focused = await page.evaluate((expected) => {
    const row = document.querySelector(`[data-case-key="${CSS.escape(expected.key)}"]`);
    const banner = document.querySelector("[data-case-focus-banner='true']");
    return {
      hash: location.hash,
      rowFocused: row?.dataset.caseFocused || "",
      rowAction: row?.dataset.caseAction || "",
      rowKind: row?.dataset.caseKind || "",
      rowClass: row?.className || "",
      bannerFocused: banner?.dataset.caseFocused || "",
      bannerAction: banner?.dataset.caseAction || "",
      bannerKind: banner?.dataset.caseKind || "",
      bannerText: (banner?.textContent || "").replace(/\s+/g, " ").trim(),
      sourceHref: banner?.querySelector("a")?.getAttribute("href") || "",
      text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  }, target);
  if (focused.rowFocused !== "true" ||
      focused.rowAction !== "candidate-rule" ||
      focused.rowKind !== target.kind ||
      !focused.rowClass.includes("is-focused") ||
      focused.bannerFocused !== "true" ||
      focused.bannerAction !== "candidate-rule" ||
      focused.bannerKind !== target.kind ||
      !focused.bannerText.includes("Focused case action: Candidate Rule") ||
      !focused.sourceHref.includes("#/traffic?")) {
    throw new Error(`investigation route focus did not render expected focused state at ${viewport.name}: ${JSON.stringify(focused)}`);
  }
  assertNoInvestigationLeak(`${focused.hash}\n${focused.bannerText}\n${focused.sourceHref}\n${focused.text}`, `investigation focused route ${viewport.name}`);
}

async function assertInvestigationAutomationContext(page, viewport) {
  await closeActiveDrawer(page);
  await page.evaluate(() => {
    localStorage.removeItem("phragma.webui.automation-recorder.v1");
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  await page.click('[data-investigation-action="api-cli"]');
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  const drawerRequiredText = [
    "API / CLI context",
    "Investigation",
    "Current view",
    "/investigation",
    "/v1/explain/flow",
    "/v1/system/packet-captures/plan",
    "/v1/flows?limit=200",
    "/v1/alerts?limit=200",
    "/v1/audit?limit=200",
    "ngfwctl explain --source running",
    "ngfwctl system capture --interface any",
    "ngfwctl flows --limit 100",
    "ngfwctl alerts --limit 100",
    "ngfwctl audit --limit 200",
    "browser storage",
    "does not mutate policy directly",
  ];
  const copiedRequiredText = [
    "# Phragma API/CLI context: Investigation",
    "Current view:",
    "#/investigation",
    "POST /v1/explain/flow",
    "POST /v1/system/packet-captures/plan",
    "GET /v1/flows?limit=200",
    "GET /v1/alerts?limit=200",
    "GET /v1/audit?limit=200",
    "ngfwctl explain --source running",
    "ngfwctl system capture --interface any",
    "ngfwctl flows --limit 100",
    "ngfwctl alerts --limit 100",
    "ngfwctl audit --limit 200",
    "browser storage",
    "does not mutate policy directly",
  ];
  assertDrawerContains(drawer, viewport, "investigation cockpit API / CLI context", drawerRequiredText, ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `investigation cockpit API / CLI drawer ${viewport.name}`);
  assertNoInvestigationAutomationLeak(drawer.text, `investigation cockpit API / CLI drawer ${viewport.name}`);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `investigation cockpit workflow session JSON ${viewport.name}`);
  assertNoInvestigationAutomationLeak(sessionJson, `investigation cockpit workflow session JSON ${viewport.name}`);
  let sessionPacket = null;
  try {
    sessionPacket = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`investigation cockpit workflow session JSON was not parseable at ${viewport.name}: ${err.message}`);
  }
  if (sessionPacket.schemaVersion !== "phragma.webui.workflow-session.v1" ||
      sessionPacket.routeState?.path !== "/investigation" ||
      sessionPacket.custody?.serverStored !== false ||
      !sessionPacket.endpoints?.some((endpoint) => endpoint.path === "/v1/explain/flow") ||
      !sessionPacket.cli?.some((item) => String(item.command || "").includes("ngfwctl system capture"))) {
    throw new Error(`investigation cockpit workflow session JSON had unexpected shape at ${viewport.name}: ${JSON.stringify(sessionPacket)}`);
  }
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  for (const required of copiedRequiredText) {
    if (!copied.includes(required)) {
      throw new Error(`investigation cockpit copied API / CLI context missing ${required} at ${viewport.name}`);
    }
  }
  assertAutomationContextRedaction(copied, `investigation cockpit copied API / CLI context ${viewport.name}`);
  assertNoInvestigationAutomationLeak(copied, `investigation cockpit copied API / CLI context ${viewport.name}`);
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function assertInvestigationRulesCustodyHandoff(page) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  try {
    const route = await page.evaluate(() => {
      const action = document.querySelector("[data-remediation-action='candidate-rule']");
      return action?.getAttribute("href") || "";
    });
    if (!route || !route.includes("caseKey=") || !route.includes("caseAction=candidate-rule")) {
      throw new Error(`investigation candidate-rule route missing case custody: ${route}`);
    }
    await page.evaluate((hash) => { location.hash = hash; }, route);
    await waitForRouteReady(page, "/rules");
    await page.waitForSelector("[data-case-custody='true']", { timeout: 10000 });
    await page.waitForFunction(() => /Allow|Deny|Reject|Default/i.test(document.querySelector(".sim-result")?.textContent || ""), null, { timeout: 10000 });
    const before = await page.evaluate(() => {
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed.items) ? parsed.items.length : 0;
      } catch {
        return 0;
      }
    });
    await page.evaluate(() => {
      const button = [...document.querySelectorAll(".sim-result button")]
        .find((candidate) => /Stage drop rule/.test(candidate.textContent || ""));
      if (!button) throw new Error("Rules case-custody stage drop button was not found");
      button.click();
    });
    await page.waitForFunction((previousCount) => {
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
      let parsed = {};
      try { parsed = JSON.parse(raw); } catch {}
      const items = Array.isArray(parsed.items) ? parsed.items : [];
      return items.length > previousCount && items.some((item) =>
        item.kind === "candidate-remediation" &&
        item.summary?.caseAction === "candidate-rule" &&
        item.summary?.changesRoute === "#/changes?tab=candidate" &&
        item.packet?.artifacts?.candidateStatus?.dirty === true);
    }, before, { timeout: 10000 });
    const state = await page.evaluate(async () => {
      const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
        fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
        fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
        fetch("/v1/candidate/status"),
      ]);
      const candidate = (await candidateResponse.json())?.policy || {};
      const running = (await runningResponse.json())?.policy || {};
      const status = statusResponse.ok ? await statusResponse.json() : {};
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
      const parsed = JSON.parse(raw);
      const packet = (parsed.items || []).find((item) => item.kind === "candidate-remediation") || {};
      return {
        hasCustodyBanner: Boolean(document.querySelector("[data-case-custody='true']")),
        candidateRuleName: packet.summary?.ruleName || "",
        candidateHasRule: (candidate.rules || []).some((rule) => rule?.name === packet.summary?.ruleName),
        runningHasRule: (running.rules || []).some((rule) => rule?.name === packet.summary?.ruleName),
        dirty: Boolean(status.dirty || status.hasCandidate || status.has_candidate),
        packetText: JSON.stringify(packet),
      };
    });
    if (!state.hasCustodyBanner || !state.candidateRuleName || !state.candidateHasRule || state.runningHasRule || !state.dirty) {
      throw new Error(`rules case-custody staging failed: ${JSON.stringify(state)}`);
    }
    assertNoInvestigationLeak(state.packetText, "rules case-custody staged packet");
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/investigation"; });
    await waitForRouteReady(page, "/investigation");
  }
}

async function assertInvestigationNonRulesCustodyHandoffs(page) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  try {
    const routes = await page.evaluate(() => {
      const routeFor = (id) => document.querySelector(`[data-remediation-action='${id}']`)?.getAttribute("href") || "";
      return {
        threat: routeFor("threat-exception"),
        appId: routeFor("app-id"),
      };
    });
    if (!routes.threat || !routes.threat.includes("caseKey=") || !routes.threat.includes("caseAction=threat-exception")) {
      throw new Error(`investigation threat-exception route missing case custody: ${routes.threat}`);
    }
    if (!routes.appId || !routes.appId.includes("caseKey=") || !routes.appId.includes("caseAction=app-id")) {
      throw new Error(`investigation app-id route missing case custody: ${routes.appId}`);
    }

    await runSmokeStep("investigation threat custody route", async () => {
      await page.evaluate((hash) => { location.hash = hash; }, routes.threat);
      await waitForRouteReady(page, "/threats");
      await page.waitForSelector("[data-threat-alert-row]", { timeout: 10000 });
    });
    const threatDrawerOpen = await page.evaluate(() => document.querySelector("#drawer:not([hidden]) h2")?.textContent?.trim() === "Threat detail");
    if (!threatDrawerOpen) {
      await page.click("[data-threat-alert-row]");
      await waitForDrawerTitle(page, "Threat detail");
    }
    await clickDrawerFooterButton(page, "Stage FP exception");
    await waitForDrawerTitle(page, "Stage false-positive exception");
    await page.fill('#drawer:not([hidden]) textarea[placeholder="Required: why this alert is safe to suppress"]', investigationSeed.operatorReason);
    await runSmokeStep("investigation threat custody stage enabled", () => page.waitForFunction(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const stageButton = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
        .find((button) => /^Stage (source|destination|global) exception$/.test((button.textContent || "").replace(/\s+/g, " ").trim()));
      return Boolean(stageButton && !stageButton.disabled);
    }, null, { timeout: 5000 }));
    const beforeThreat = await removeCandidateRemediationPackets(page, { caseAction: "threat-exception" });
    await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const stageButton = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
        .find((button) => /^Stage (source|destination|global) exception$/.test((button.textContent || "").replace(/\s+/g, " ").trim()));
      if (!stageButton) throw new Error("threat case-custody stage exception button was not found");
      stageButton.click();
    });
    await waitForDrawerTitle(page, "False-positive exception staged");
    const threatPacket = await runSmokeStep("investigation threat custody packet pinned", () => waitForCandidateRemediationPacket(page, beforeThreat, {
      caseAction: "threat-exception",
      changesRoute: "#/changes?tab=candidate",
      requireStageResult: true,
    }));
    assertNoInvestigationLeak(JSON.stringify(threatPacket), "threat case-custody staged packet");

    await runSmokeStep("investigation app-id custody route", async () => {
      const observation = await findAppIdQueueObservation(page);
      await page.evaluate(({ obs, seed, caseRoute }) => {
        const query = caseRoute.includes("?") ? caseRoute.slice(caseRoute.indexOf("?") + 1) : "";
        const params = new URLSearchParams(query);
        params.set("mode", "app-id");
        params.set("queueId", obs.queueId);
        params.set("engineSignal", obs.engineSignal || seed.appProto);
        params.set("protocol", seed.protocol);
        params.set("port", String(seed.destPort));
        params.set("confidenceThreshold", "70");
        params.set("flowLimit", "1000");
        params.set("limit", "100");
        location.hash = "#/traffic?" + params.toString();
      }, { obs: observation, seed: appIdQueueSeed, caseRoute: routes.appId });
      await waitForRouteReady(page, "/traffic");
      const drawerOpen = await page.evaluate(() => document.querySelector("#drawer:not([hidden]) h2")?.textContent?.trim() === "App-ID observation");
      if (!drawerOpen) {
        const rowSelector = `.appid-observation-table tbody tr[data-appid-observation-id="${observation.queueId}"]`;
        await page.waitForSelector(rowSelector, { timeout: 10000 });
        await page.click(rowSelector);
      }
      await waitForDrawerTitle(page, "App-ID observation");
    });
    await clickDrawerFooterButton(page, "Promote App-ID");
    await waitForDrawerTitle(page, "Custom App-ID");
    await fillCustomAppIdReviewDrawer(page, appIdQueueSeed);
    await clickDrawerFooterButton(page, "Review drop rule");
    await waitForDrawerTitle(page, "New rule");
    await assertAppIdRuleReviewEditor(page, { name: "desktop" }, appIdQueueSeed);
    const beforeAppId = await removeCandidateRemediationPackets(page, { caseAction: "app-id", mode: "define-and-drop" });
    await clickDrawerFooterButton(page, "Add rule");
    await waitForDrawerClosed(page);
    await assertReviewedAppIdDropCandidate(page, appIdQueueSeed);
    const appIdPacket = await runSmokeStep("investigation app-id custody packet pinned", () => waitForCandidateRemediationPacket(page, beforeAppId, {
      caseAction: "app-id",
      mode: "define-and-drop",
      changesRoute: "#/changes?tab=candidate",
      requireApplication: true,
    }));
    assertNoInvestigationLeak(JSON.stringify(appIdPacket), "app-id case-custody staged packet");
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/investigation"; });
    await waitForRouteReady(page, "/investigation");
  }
}

async function investigationCaseItemCount(page) {
  return await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed.items) ? parsed.items.length : 0;
    } catch {
      return 0;
    }
  });
}

async function removeCandidateRemediationPackets(page, expected = {}) {
  return await page.evaluate((expected) => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    let parsed = {};
    try { parsed = JSON.parse(raw); } catch {}
    const items = Array.isArray(parsed.items) ? parsed.items : [];
    const keep = items.filter((item) => {
      if (item.kind !== "candidate-remediation") return true;
      if (expected.caseAction && item.summary?.caseAction !== expected.caseAction) return true;
      if (expected.mode && item.summary?.mode !== expected.mode) return true;
      return false;
    });
    if (keep.length !== items.length) {
      localStorage.setItem("phragma.investigation.case.v1", JSON.stringify({
        ...parsed,
        updatedAt: new Date().toISOString(),
        items: keep,
      }));
    }
    return keep.length;
  }, expected);
}

async function waitForCandidateRemediationPacket(page, previousCount, expected = {}) {
  try {
    await page.waitForFunction(({ count, expected }) => {
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
      let parsed = {};
      try { parsed = JSON.parse(raw); } catch {}
      const items = Array.isArray(parsed.items) ? parsed.items : [];
      return items.length >= count && [...items].reverse().some((item) => {
        if (item.kind !== "candidate-remediation") return false;
        if (expected.caseAction && item.summary?.caseAction !== expected.caseAction) return false;
        if (expected.mode && item.summary?.mode !== expected.mode) return false;
        if (expected.changesRoute && item.summary?.changesRoute !== expected.changesRoute) return false;
        if (item.summary?.candidateDirty !== true && item.packet?.artifacts?.candidateStatus?.dirty !== true) return false;
        if (expected.requireStageResult && !item.packet?.artifacts?.stageResult) return false;
        if (expected.requireApplication && !item.packet?.artifacts?.pendingApplications?.length && !item.packet?.artifacts?.application) return false;
        return true;
      });
    }, { count: previousCount, expected }, { timeout: 10000 });
  } catch (err) {
    const state = await page.evaluate(({ count, expected }) => {
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
      let parsed = {};
      try { parsed = JSON.parse(raw); } catch {}
      const items = Array.isArray(parsed.items) ? parsed.items : [];
      return {
        previousCount: count,
        itemCount: items.length,
        expected,
        recent: [...items].slice(-8).map((item) => ({
          kind: item.kind || "",
          title: item.title || "",
          summary: item.summary || {},
          artifactKeys: Object.keys(item.packet?.artifacts || {}),
          pendingApplications: item.packet?.artifacts?.pendingApplications || [],
          application: item.packet?.artifacts?.application || null,
          candidateStatus: item.packet?.artifacts?.candidateStatus || null,
        })),
      };
    }, { count: previousCount, expected });
    throw new Error(`candidate remediation packet did not match: ${JSON.stringify(state)}`);
  }
  return await page.evaluate((expected) => {
    const parsed = JSON.parse(localStorage.getItem("phragma.investigation.case.v1") || "{}");
    const items = Array.isArray(parsed.items) ? parsed.items : [];
    return [...items].reverse().find((item) => {
      if (item.kind !== "candidate-remediation") return false;
      if (expected.caseAction && item.summary?.caseAction !== expected.caseAction) return false;
      if (expected.mode && item.summary?.mode !== expected.mode) return false;
      return true;
    }) || {};
  }, expected);
}

async function assertInvestigationCopy(page, viewport) {
  await page.evaluate(() => {
    globalThis.__investigationCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__investigationCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.evaluate(() => {
    const button = [...document.querySelectorAll("#content button")]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Copy case");
    if (!button) throw new Error("investigation copy case button was not found");
    button.click();
  });
  await page.waitForFunction(() => Boolean(globalThis.__investigationCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__investigationCopiedText || "");
  if (!copied.includes("Phragma investigation case") || !copied.includes("route=redacted unsafe route") || !copied.includes("Packet capture investigation handoff")) {
    throw new Error(`investigation copied case missing expected content at ${viewport.name}`);
  }
  assertNoInvestigationLeak(copied, `investigation copied case ${viewport.name}`);
}

async function assertInvestigationExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.evaluate(() => {
    const button = [...document.querySelectorAll("#content button")]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Export JSON");
    if (!button) throw new Error("investigation export case button was not found");
    button.click();
  });
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^phragma-investigation-case-.+\.json$/.test(filename)) {
    throw new Error(`investigation export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`investigation export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `investigation export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`investigation export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.schemaVersion !== "phragma.investigation.case.v1" || packet?.summary?.itemCount !== 7) {
    throw new Error(`investigation export had unexpected identity at ${viewport.name}: ${JSON.stringify({ schemaVersion: packet?.schemaVersion, itemCount: packet?.summary?.itemCount })}`);
  }
  if (packet.summary.redactedRouteCount < 1 || !packet.items?.some((item) => item.source?.routeRedacted || item.packet?.source?.routeRedacted)) {
    throw new Error(`investigation export missing redacted route custody marker at ${viewport.name}`);
  }
}

function assertNoInvestigationLeak(text, label) {
  const leaked = [
    /Bearer-secret/i,
    /writer-secret/i,
    /\/etc\/passwd/i,
    /\/etc\/openngfw/i,
    /\/tmp\/pcap/i,
    /file:\/tmp/i,
    /\/var\/log\/openngfw/i,
    /\/var\/lib\/openngfw/i,
    /phragma-case-flow\.pcap/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked sensitive material: ${leaked}`);
  }
}

function assertNoInvestigationAutomationLeak(text, label) {
  const leaked = [
    /Bearer-secret/i,
    /writer-secret/i,
    /\/etc\/passwd/i,
    /\/tmp\/pcap/i,
    /file:\/tmp/i,
    /\/var\/log\/openngfw/i,
    /\/var\/lib\/openngfw/i,
    /phragma-case-flow\.pcap/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
    /https?:\/\/[^/\s"']+:[^@\s"']+@/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked sensitive investigation context: ${leaked}`);
  }
}

async function openSeededFlowDrawer(page) {
	await ensureSeededInvestigationTelemetry();
	await page.evaluate(() => { location.hash = "#/"; });
	await waitForRouteReady(page, "/");
	await page.evaluate((seed) => {
		const params = new URLSearchParams();
		params.set("mode", "flows");
		params.set("flowId", seed.flowId);
		params.set("ip", seed.srcIp);
		params.set("protocol", seed.protocol);
		params.set("port", String(seed.destPort));
		params.set("limit", "100");
		location.hash = "#/traffic?" + params.toString();
	}, investigationSeed);
	await waitForRouteReady(page, "/traffic");
	try {
		await waitForDrawerTitle(page, "Flow detail", 2500);
		return;
	} catch {
		await page.waitForSelector(".traffic-flow-table tbody tr", { timeout: 10000 });
		const clickState = await page.evaluate((seed) => {
			const rows = Array.from(document.querySelectorAll(".traffic-flow-table tbody tr"));
			const exactRow = rows.find((row) => row.dataset.trafficFlowId === seed.flowId);
			const tupleRow = rows.find((row) => {
				const text = (row.textContent || "").replace(/\s+/g, " ");
				return text.includes(seed.srcIp) && text.includes(seed.destIp) && text.includes(String(seed.destPort));
			});
			const row = exactRow || tupleRow || rows[0] || null;
			const action = row?.querySelector("[data-traffic-action='view-flow']") || null;
			const target = action || row;
			if (target) target.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
			return {
				clicked: Boolean(target),
				action: action?.dataset?.trafficAction || "",
				rowFlowId: row?.dataset?.trafficFlowId || "",
				rowText: (row?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
				hash: location.hash,
			};
		}, investigationSeed);
		await page.waitForTimeout(250);
		const opened = await page.evaluate(() => document.querySelector("#drawer:not([hidden]) h2")?.textContent?.trim() === "Flow detail");
		if (!opened) {
			const state = await page.evaluate((clickState) => ({
				clickState,
				drawerTitle: document.querySelector("#drawer:not([hidden]) h2")?.textContent?.trim() || "",
				drawerText: (document.querySelector("#drawer:not([hidden])")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
				hash: location.hash,
				rows: Array.from(document.querySelectorAll(".traffic-flow-table tbody tr")).slice(0, 4).map((row) => ({
					flowId: row.dataset.trafficFlowId || "",
					text: (row.textContent || "").replace(/\s+/g, " ").trim().slice(0, 220),
					actions: Array.from(row.querySelectorAll("[data-traffic-action]")).map((node) => ({
						action: node.dataset.trafficAction || "",
						flowId: node.dataset.trafficFlowId || "",
						text: (node.textContent || "").replace(/\s+/g, " ").trim(),
					})),
				})),
			}), clickState);
			throw new Error(`seeded flow detail did not open after Details click: ${JSON.stringify(state)}`);
		}
	}
	await waitForDrawerTitle(page, "Flow detail");
}

async function openSeededThreatDrawer(page) {
  await ensureSeededInvestigationTelemetry();
  await page.evaluate((alertKey) => {
    location.hash = "#/threats?alert=" + encodeURIComponent(alertKey);
  }, investigationSeed.alertKey);
  await waitForRouteReady(page, "/threats");
  await waitForDrawerTitle(page, "Threat detail");
}

async function waitForRouteReady(page, path) {
  await page.waitForFunction((expectedPath) => (
    document.querySelector("#nav a.active")?.dataset?.path === expectedPath &&
    !document.querySelector("#content > .loading") &&
    !document.querySelector("#content .not-found-view")
  ), path, { timeout: 10000 });
  await page.waitForTimeout(120);
}

async function forceRouteReload(page, path) {
  const hash = `#${path}`;
  const navigatedAway = await page.evaluate((targetHash) => {
    if (location.hash === targetHash) {
      location.hash = "#/";
      return true;
    }
    return false;
  }, hash);
  if (navigatedAway && path !== "/") await waitForRouteReady(page, "/");
  await page.evaluate((targetHash) => {
    location.hash = targetHash;
  }, hash);
  await waitForRouteReady(page, path);
}

async function waitForDrawerTitle(page, title, timeout = 10000) {
  await page.waitForFunction((expectedTitle) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return Boolean(drawer && drawer.querySelector("h2")?.textContent?.trim() === expectedTitle);
  }, title, { timeout });
  await page.waitForTimeout(260);
}

async function waitForDrawerTitleStep(page, title, step, timeout = 10000) {
  try {
    await waitForDrawerTitle(page, title, timeout);
  } catch (err) {
    throw new Error(`${step}: drawer title "${title}" was not reached (${err.message})`);
  }
}

async function waitForDrawerOpen(page, timeout = 10000) {
  await page.waitForFunction(() => Boolean(document.querySelector("#drawer:not([hidden])")), null, { timeout });
  await page.waitForTimeout(260);
}

async function waitForDrawerClosed(page, timeout = 5000) {
  await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])"), null, { timeout });
}

async function waitForDrawerClosedStep(page, step) {
  try {
    await waitForDrawerClosed(page);
  } catch (err) {
    const state = await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      return {
        title: drawer?.querySelector("h2")?.textContent?.trim() || "",
        drawerText: (drawer?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 700),
        toastText: (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
      };
    });
    throw new Error(`${step}: drawer did not close (${err.message}); state=${JSON.stringify(state)}`);
  }
}

async function closeDrawerIfOpen(page) {
  const isOpen = await page.locator("#drawer:not([hidden])").count().then(Boolean).catch(() => false);
  if (!isOpen) return;
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function waitForSelectionCleared(page, path, keys) {
  await page.waitForFunction(({ expectedPath, names }) => {
    const hash = location.hash || "";
    if (!hash.startsWith("#" + expectedPath)) return false;
    const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
    const params = new URLSearchParams(query);
    return names.every((name) => !params.has(name));
  }, { expectedPath: path, names: keys }, { timeout: 5000 });
}

async function assertSavedFilterLifecycle(page, viewport, config = {}) {
  const name = `${config.label || config.scope || "saved filter"} ${viewport.name}`;
  await page.evaluate(({ routeHash, scope }) => {
    localStorage.removeItem(`openngfw.savedFilters.${scope}`);
    location.hash = routeHash;
  }, { routeHash: config.routeHash, scope: config.scope });
  await waitForRouteReady(page, config.routePath);
  await page.waitForSelector(`[data-saved-filter-scope="${config.scope}"][data-saved-filter-control="name"]`, { timeout: 10000 });
  await setFilterControls(page, config.filterRoot, config.fields || []);
  await clickFilterRootButton(page, config.filterRoot, "Apply");
  await waitForHashParams(page, config.expectedParams || {});

  await page.fill(`[data-saved-filter-scope="${config.scope}"][data-saved-filter-control="name"]`, name);
  await clickSavedFilterAction(page, config.scope, "save");
  await page.waitForFunction(({ scope, name }) => {
    const select = document.querySelector(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="select"]`);
    return [...(select?.options || [])].some((option) => option.value === name);
  }, { scope: config.scope, name }, { timeout: 5000 });
  const saved = await savedFilterStorageState(page, config.scope);
  if (!saved.entries.some((entry) => entry.name === name)) {
    throw new Error(`${config.label} did not persist saved filter ${name}: ${JSON.stringify(saved)}`);
  }
  const forbidden = (config.forbiddenStateKeys || []).filter((key) =>
    saved.entries.some((entry) => Object.prototype.hasOwnProperty.call(entry.state || {}, key)));
  if (forbidden.length) {
    throw new Error(`${config.label} persisted transient route keys: ${forbidden.join(", ")}`);
  }

  await page.evaluate((routeHash) => { location.hash = routeHash; }, config.routeHash);
  await waitForRouteReady(page, config.routePath);
  await page.selectOption(`[data-saved-filter-scope="${config.scope}"][data-saved-filter-control="select"]`, name);
  await clickSavedFilterAction(page, config.scope, "apply");
  await waitForHashParams(page, config.expectedParams || {});

  await page.selectOption(`[data-saved-filter-scope="${config.scope}"][data-saved-filter-control="select"]`, name);
  await clickSavedFilterAction(page, config.scope, "delete");
  await page.waitForFunction(({ scope, name }) => {
    const raw = localStorage.getItem(`openngfw.savedFilters.${scope}`) || "[]";
    let entries = [];
    try { entries = JSON.parse(raw); } catch {}
    const select = document.querySelector(`[data-saved-filter-scope="${scope}"][data-saved-filter-control="select"]`);
    return !entries.some((entry) => entry?.name === name) &&
      ![...(select?.options || [])].some((option) => option.value === name);
  }, { scope: config.scope, name }, { timeout: 5000 });
  await page.evaluate((routeHash) => { location.hash = routeHash; }, config.routeHash);
  await waitForRouteReady(page, config.routePath);
}

async function setFilterControls(page, filterRoot, fields = []) {
  await page.evaluate(({ rootSelector, fieldSpecs }) => {
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const root = document.querySelector(rootSelector);
    if (!root) throw new Error(`filter root ${rootSelector} was not found`);
    for (const field of fieldSpecs) {
      const label = [...root.querySelectorAll("label.field")]
        .find((candidate) => textOf(candidate.querySelector("span")) === field.label);
      if (!label) throw new Error(`filter field ${field.label} was not found`);
      const control = label.querySelector("input,select,textarea");
      if (!control) throw new Error(`filter field ${field.label} has no control`);
      control.value = String(field.value ?? "");
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }, { rootSelector: filterRoot, fieldSpecs: fields });
}

async function clickFilterRootButton(page, filterRoot, label) {
  await page.evaluate(({ rootSelector, buttonLabel }) => {
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const root = document.querySelector(rootSelector);
    if (!root) throw new Error(`filter root ${rootSelector} was not found`);
    const wanted = String(buttonLabel || "").trim().toLowerCase();
    const button = [...root.querySelectorAll("button")].find((candidate) => {
      const action = Object.values(candidate.dataset || {}).join(" ").toLowerCase();
      const text = textOf(candidate).toLowerCase();
      if (wanted === "apply" && /\bapply[-_\s]?(filters|appid)?\b/.test(action)) return true;
      if (wanted === "clear" && /\b(clear|reset)[-_\s]?filters\b/.test(action)) return true;
      return text === wanted || text === `${wanted} filters`;
    });
    if (!button) throw new Error(`filter button ${buttonLabel} was not found`);
    button.click();
  }, { rootSelector: filterRoot, buttonLabel: label });
}

async function clickSavedFilterAction(page, scope, action) {
  await page.click(`[data-saved-filter-scope="${scope}"][data-saved-filter-action="${action}"]`);
}

async function waitForHashParams(page, expected = {}) {
  await page.waitForFunction((params) => {
    const hash = location.hash || "";
    const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
    const current = new URLSearchParams(query);
    return Object.entries(params).every(([key, value]) => current.get(key) === String(value));
  }, expected, { timeout: 5000 });
}

async function savedFilterStorageState(page, scope) {
  return await page.evaluate((filterScope) => {
    const key = `openngfw.savedFilters.${filterScope}`;
    const raw = localStorage.getItem(key) || "[]";
    let entries = [];
    try { entries = JSON.parse(raw); } catch {}
    return { key, raw, entries: Array.isArray(entries) ? entries : [] };
  }, scope);
}

async function collectDrawerState(page) {
  return await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const footerButtons = [...(drawer?.querySelectorAll(".drawer-foot button") || [])].map((button) => ({
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      disabled: button.disabled,
      width: button.getBoundingClientRect().width,
      height: button.getBoundingClientRect().height,
    }));
    const overflow = drawer ? Math.max(
      0,
      Math.ceil(rect.right - window.innerWidth),
      Math.ceil(0 - rect.left),
      Math.ceil(drawer.scrollWidth - drawer.clientWidth),
    ) : 0;
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      footerButtons,
      overflow,
    };
  });
}

function assertDrawerContains(drawer, viewport, label, requiredText, requiredButtons) {
  if (drawer.overflow > 2) {
    throw new Error(`${label} drawer overflow at ${viewport.name}: ${drawer.overflow}px`);
  }
  const missingText = requiredText.filter((needle) => !drawer.text.includes(needle));
  if (missingText.length) {
    throw new Error(`${label} drawer missing text: ${missingText.join(", ")}`);
  }
  const missingButtons = requiredButtons.filter((needle) => !drawer.footerButtons.some((button) => button.text === needle));
  if (missingButtons.length) {
    throw new Error(`${label} drawer missing footer action(s): ${missingButtons.join(", ")}`);
  }
  if (viewport.name === "mobile") {
    const cramped = drawer.footerButtons.filter((button) => button.width < 56 || button.height < 36);
    if (cramped.length) {
      throw new Error(`${label} mobile footer action(s) too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
}

async function clickDrawerFooterButton(page, label) {
  return await page.evaluate((buttonLabel) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
	const buttons = [...(drawer?.querySelectorAll(".drawer-foot button") || [])];
	const target = buttons.find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === buttonLabel);
	if (!target) throw new Error(`drawer footer button "${buttonLabel}" was not found`);
	if (target.disabled) throw new Error(`drawer footer button "${buttonLabel}" was disabled`);
	target.click();
	return location.hash || "";
  }, label);
}

async function clickDrawerButton(page, label) {
  return await page.evaluate((buttonLabel) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const buttons = [...(drawer?.querySelectorAll("button") || [])];
    const target = buttons.find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === buttonLabel);
    if (!target) throw new Error(`drawer button "${buttonLabel}" was not found`);
    target.click();
    return location.hash || "";
  }, label);
}

async function waitForDrawerButtonEnabled(page, label) {
  await page.waitForFunction((buttonLabel) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const buttons = [...(drawer?.querySelectorAll("button") || [])];
    const target = buttons.find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === buttonLabel);
    return Boolean(target && !target.disabled);
  }, label, { timeout: 5000 });
}

function assertInvestigationActionHash(hash, intent) {
  if (!hash.startsWith("#/troubleshoot?")) {
    throw new Error(`investigation ${intent} action did not route to Troubleshoot immediately (hash=${hash || "<empty>"})`);
  }
  const params = new URLSearchParams(hash.slice(hash.indexOf("?") + 1));
  const expected = {
    src: investigationSeed.srcIp,
    sport: String(investigationSeed.srcPort),
    dst: investigationSeed.destIp,
    dport: String(investigationSeed.destPort),
    protocol: "PROTOCOL_TCP",
    flowId: investigationSeed.flowId,
    runtime: "1",
    run: "1",
    intent,
  };
  const wrong = Object.entries(expected)
    .filter(([key, value]) => params.get(key) !== value)
    .map(([key, value]) => `${key}=${params.get(key) || "<none>"} want ${value}`);
  if (wrong.length) {
    throw new Error(`investigation ${intent} route missing tuple/run state: ${wrong.join(", ")}`);
  }
}

function escapeRegExp(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function assertTroubleshootInvestigation(page, viewport, intent, opts = {}) {
  await waitForRouteReady(page, "/troubleshoot");
  const routeState = await page.evaluate(() => {
    const labelControl = (labelText) => {
      const label = [...document.querySelectorAll("#content label.field")]
        .find((candidate) => (candidate.querySelector("span")?.textContent || "").trim() === labelText);
      const control = label?.querySelector("input, select, textarea");
      return {
        value: control?.type === "checkbox" ? Boolean(control.checked) : (control?.value || ""),
        present: Boolean(control),
      };
    };
    const content = document.querySelector("#content");
    const captureRow = content?.querySelector(".capture-command-row");
    return {
      hash: location.hash || "",
      text: (content?.textContent || "").replace(/\s+/g, " ").trim(),
      flowId: labelControl("Flow ID"),
      src: labelControl("Source IP"),
      sport: labelControl("Source port"),
      dst: labelControl("Destination IP"),
      dport: labelControl("Destination port"),
      protocol: labelControl("Protocol"),
      runtime: labelControl("Include live runtime evidence"),
      captureVisible: Boolean(captureRow),
      captureCommand: captureRow?.textContent || "",
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
  if (routeState.overflow > 2) {
    throw new Error(`troubleshoot investigation route overflow at ${viewport.name}: ${routeState.overflow}px`);
  }
  if (!routeState.text.includes("Flow query") || !routeState.text.includes("Explain flow")) {
    throw new Error("troubleshoot investigation route did not show the flow query form");
  }
  const expectedFields = [
    ["Flow ID", routeState.flowId, investigationSeed.flowId],
    ["Source IP", routeState.src, investigationSeed.srcIp],
    ["Source port", routeState.sport, String(investigationSeed.srcPort)],
    ["Destination IP", routeState.dst, investigationSeed.destIp],
    ["Destination port", routeState.dport, String(investigationSeed.destPort)],
    ["Protocol", routeState.protocol, "PROTOCOL_TCP"],
  ];
  const wrongFields = expectedFields
    .filter(([, field, expected]) => !field.present || String(field.value) !== expected)
    .map(([labelText, field, expected]) => `${labelText}=${field.present ? field.value : "<missing>"} want ${expected}`);
  if (wrongFields.length) {
    throw new Error(`troubleshoot investigation fields not prefilled: ${wrongFields.join(", ")}`);
  }
  if (!routeState.runtime.present || routeState.runtime.value !== true) {
    throw new Error("troubleshoot investigation did not enable runtime evidence");
  }
  if (intent === "capture") {
    await page.waitForFunction(() => new URLSearchParams((location.hash.split("?")[1] || "")).get("intent") === "capture", null, { timeout: 5000 });
    await page.waitForFunction(() => {
      const text = document.querySelector("#content")?.textContent || "";
      return text.includes("Packet capture") && text.includes("Server plan") && text.includes("Start capture") && Boolean(document.querySelector(".capture-command-row"));
    }, null, { timeout: 10000 });
    await assertCaptureCorrelationEvidence(page);
    if (!opts.skipCaptureLifecycle) {
      await assertPacketCaptureArtifactLifecycle(page, viewport);
    }
    const copiedContext = await assertAutomationContextDrawer(page, viewport, "troubleshoot capture automation context", [
      "/v1/system/packet-captures/plan",
      "/v1/system/packet-captures",
    ]);
    const expectedPatterns = [
      [/"policySource"\s*:\s*"POLICY_SOURCE_CANDIDATE"/, "flat ExplainFlow policySource"],
      [new RegExp(`"srcIp"\\s*:\\s*"${escapeRegExp(investigationSeed.srcIp)}"`), "flat ExplainFlow srcIp"],
      [new RegExp(`"destIp"\\s*:\\s*"${escapeRegExp(investigationSeed.destIp)}"`), "flat ExplainFlow destIp"],
      [/\"flow\"\s*:/, "legacy nested flow body", true],
      [/\"source\"\s*:/, "legacy source field body", true],
      [/"interface"\s*:\s*"any"/, "capture interface any"],
      [/"durationSeconds"\s*:\s*20/, "capture duration 20"],
      [/"packetCount"\s*:\s*500/, "capture packet count 500"],
      [/"snaplenBytes"\s*:\s*256/, "capture snaplen 256"],
      [new RegExp(`ngfwctl system capture --interface any --protocol tcp --src ${escapeRegExp(investigationSeed.srcIp)} --sport ${investigationSeed.srcPort} --dst ${escapeRegExp(investigationSeed.destIp)} --dport ${investigationSeed.destPort} --duration 20 --packets 500 --snaplen 256 --flow-id ${escapeRegExp(investigationSeed.flowId)}`), "capture plan CLI"],
      [new RegExp(`ngfwctl system capture --start --ack-capture --interface any --protocol tcp --src ${escapeRegExp(investigationSeed.srcIp)} --sport ${investigationSeed.srcPort} --dst ${escapeRegExp(investigationSeed.destIp)} --dport ${investigationSeed.destPort} --duration 20 --packets 500 --snaplen 256 --flow-id ${escapeRegExp(investigationSeed.flowId)}`), "capture start CLI"],
    ];
    for (const [pattern, label, mustBeAbsent] of expectedPatterns) {
      const matched = pattern.test(copiedContext);
      if (mustBeAbsent ? matched : !matched) {
        throw new Error(`troubleshoot capture copied automation context missing ${label}`);
      }
    }
  }
}

async function assertTroubleshootCompareSimulator(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  let plan = null;
  try {
    plan = await seedTroubleshootCompareCandidate(page, viewport.name);
    await page.evaluate((nextHash) => { location.hash = nextHash; }, plan.hash);
    await waitForRouteReady(page, "/troubleshoot");
    await page.waitForFunction((ruleName) => {
      const content = document.querySelector("#content");
      const text = (content?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("Running vs candidate") &&
        text.includes("Running") &&
        text.includes("Candidate") &&
        text.includes("Verdict") &&
        text.includes("Matched rule") &&
        text.includes(ruleName) &&
        !text.includes("Comparing running and candidate policy");
    }, plan.ruleName, { timeout: 10000 });
    const state = await page.evaluate((expected) => {
      const content = document.querySelector("#content");
      const labelControl = (labelText) => {
        const label = [...document.querySelectorAll("#content label.field")]
          .find((candidate) => (candidate.querySelector("span")?.textContent || "").trim() === labelText);
        const control = label?.querySelector("input, select, textarea");
        return {
          value: control?.type === "checkbox" ? Boolean(control.checked) : (control?.value || ""),
          present: Boolean(control),
        };
      };
      const text = (content?.textContent || "").replace(/\s+/g, " ").trim();
      const deltas = [...(content?.querySelectorAll(".compare-delta") || [])].map((node) => (node.textContent || "").replace(/\s+/g, " ").trim());
      const sides = [...(content?.querySelectorAll(".compare-side") || [])].map((node) => (node.textContent || "").replace(/\s+/g, " ").trim());
      const overflow = Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth));
      const fields = {
        src: labelControl("Source IP"),
        sport: labelControl("Source port"),
        dst: labelControl("Destination IP"),
        dport: labelControl("Destination port"),
        protocol: labelControl("Protocol"),
      };
      return {
        hash: location.hash || "",
        text,
        deltas,
        sides,
        hasCompareGrid: Boolean(content?.querySelector(".compare-grid")),
        overflow,
        fields,
        routeFieldsPresent: fields.src.value === expected.src &&
          fields.sport.value === "51515" &&
          fields.dst.value === expected.dst &&
          fields.dport.value === expected.dport &&
          fields.protocol.value === expected.protocol,
      };
    }, plan);
    if (state.overflow > 2) {
      throw new Error(`troubleshoot compare route overflow at ${viewport.name}: ${state.overflow}px`);
    }
    if (!state.hash.includes("intent=compare") || !state.hash.includes("run=1")) {
      throw new Error(`troubleshoot compare route did not preserve compare autorun state: ${state.hash || "<empty>"}`);
    }
    if (!state.hasCompareGrid || !state.routeFieldsPresent) {
      throw new Error(`troubleshoot compare route did not render the expected compare grid/fields: ${JSON.stringify(state)}`);
    }
    if (!state.deltas.some((delta) => /Verdict/i.test(delta)) || !state.deltas.some((delta) => /Matched rule/i.test(delta))) {
      throw new Error(`troubleshoot compare did not show verdict and matched-rule deltas: ${JSON.stringify(state.deltas)}`);
    }
    if (!state.text.includes(plan.ruleName) || !state.text.includes(plan.expectedCandidateLabel)) {
      throw new Error(`troubleshoot compare did not show candidate verdict/rule: ${JSON.stringify({ expected: plan, state })}`);
    }
    await assertTroubleshootCompareCandidateOnly(page, plan);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/troubleshoot"; });
    await waitForRouteReady(page, "/troubleshoot");
  }
}

async function seedTroubleshootCompareCandidate(page, viewportName) {
  return await page.evaluate(async ({ viewportName }) => {
    const runningResponse = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!runningResponse.ok) {
      throw new Error(`read running policy before troubleshoot compare failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    }
    const runningBody = await runningResponse.json();
    const runningPolicy = runningBody?.policy || {};
    const zones = (runningPolicy.zones || []).map((zone) => zone?.name).filter(Boolean);
    const fromZone = zones.find((name) => !/wan|outside|untrust/i.test(name)) || zones[0] || "";
    const toZone = zones.find((name) => name !== fromZone && /wan|outside|untrust/i.test(name)) || zones.find((name) => name !== fromZone) || "";
    const suffix = String(viewportName || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
    const src = "198.51.100.10";
    const dst = "203.0.113.88";
    const dport = "9443";
    const protocol = "PROTOCOL_TCP";
    const query = {
      policySource: "POLICY_SOURCE_RUNNING",
      version: "0",
      fromZone,
      toZone,
      srcIp: src,
      srcPort: 51515,
      destIp: dst,
      destPort: Number(dport),
      protocol,
      appId: "",
      includeRuntime: false,
      flowId: "",
    };
    const runningExplain = await fetch("/v1/explain/flow", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(query),
    });
    const runningExplainText = await runningExplain.text();
    let runningExplainBody = {};
    try {
      runningExplainBody = runningExplainText ? JSON.parse(runningExplainText) : {};
    } catch (err) {
      throw new Error(`running explain before troubleshoot compare was not JSON: ${err.message}`);
    }
    if (!runningExplain.ok) {
      throw new Error(`running explain before troubleshoot compare failed with HTTP ${runningExplain.status}: ${(runningExplainBody.message || runningExplainBody.error || runningExplainText)}`);
    }
    const runningVerdict = String(runningExplainBody.verdict || "");
    const action = runningVerdict === "EXPLAIN_VERDICT_ALLOWED" ? "ACTION_DENY" : "ACTION_ALLOW";
    const expectedCandidateLabel = action === "ACTION_ALLOW" ? "allowed" : "denied";
    const ruleName = `visual-compare-${suffix}`;
    const srcName = `${ruleName}-src`;
    const dstName = `${ruleName}-dst`;
    const svcName = `${ruleName}-tcp-9443`;
    const nextPolicy = structuredClone(runningPolicy);
    nextPolicy.addresses = (nextPolicy.addresses || []).filter((item) => ![srcName, dstName].includes(item?.name));
    nextPolicy.services = (nextPolicy.services || []).filter((item) => item?.name !== svcName);
    nextPolicy.rules = (nextPolicy.rules || []).filter((item) => item?.name !== ruleName);
    nextPolicy.addresses.push({ name: srcName, cidr: `${src}/32`, description: "Visual smoke compare source." });
    nextPolicy.addresses.push({ name: dstName, cidr: `${dst}/32`, description: "Visual smoke compare destination." });
    nextPolicy.services.push({ name: svcName, protocol, ports: [{ start: Number(dport) }] });
    nextPolicy.rules.unshift({
      name: ruleName,
      fromZones: fromZone ? [fromZone] : ["any"],
      toZones: toZone ? [toZone] : ["any"],
      sourceAddresses: [srcName],
      destinationAddresses: [dstName],
      services: [svcName],
      applications: [],
      action,
      log: true,
      disabled: false,
      tags: ["visual-smoke", "path-compare"],
      description: "Visual smoke candidate-only path simulator verdict change.",
    });
    const candidate = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy: nextPolicy }),
    });
    if (!candidate.ok) {
      throw new Error(`seed troubleshoot compare candidate failed with HTTP ${candidate.status}: ${await candidate.text()}`);
    }
    const q = new URLSearchParams();
    if (fromZone) q.set("fromZone", fromZone);
    if (toZone) q.set("toZone", toZone);
    q.set("src", src);
    q.set("sport", "51515");
    q.set("dst", dst);
    q.set("dport", dport);
    q.set("protocol", protocol);
    q.set("run", "1");
    q.set("intent", "compare");
    return {
      hash: "#/troubleshoot?" + q.toString(),
      ruleName,
      action,
      expectedCandidateLabel,
      runningVerdict,
      fromZone,
      toZone,
      src,
      dst,
      dport,
      protocol,
    };
  }, { viewportName });
}

async function assertTroubleshootCompareCandidateOnly(page, plan) {
  const state = await page.evaluate(async (expected) => {
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read compare candidate failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read compare running failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    if (!statusResponse.ok) throw new Error(`read compare candidate status failed with HTTP ${statusResponse.status}: ${await statusResponse.text()}`);
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const status = await statusResponse.json();
    return {
      candidateRule: (candidate.rules || []).find((rule) => rule.name === expected.ruleName) || null,
      runningRule: (running.rules || []).find((rule) => rule.name === expected.ruleName) || null,
      dirty: Boolean(status.dirty),
      changeCount: Number(status.changeCount || status.change_count || 0),
      changesText: JSON.stringify(status.changes || []),
    };
  }, plan);
  if (!state.candidateRule || state.candidateRule.action !== plan.action) {
    throw new Error(`troubleshoot compare candidate rule was not staged correctly: ${JSON.stringify(state)}`);
  }
  if (state.runningRule) {
    throw new Error(`troubleshoot compare mutated running policy before commit: ${JSON.stringify(state.runningRule)}`);
  }
  if (!state.dirty || state.changeCount < 1 || !state.changesText.includes("rules")) {
    throw new Error(`troubleshoot compare did not preserve candidate-only status: ${JSON.stringify(state)}`);
  }
}

async function assertCaptureCorrelationEvidence(page) {
  const state = await page.evaluate((seed) => {
    const content = document.querySelector("#content");
    const runtime = content?.querySelector("[data-explain-profile=\"runtime\"]");
    const eveTableWrap = content?.querySelector("[data-correlated-eve-table]");
    const eveTable = eveTableWrap?.querySelector("table");
    const command = content?.querySelector("[data-capture-command]");
    const detail = content?.querySelector("[data-capture-detail]");
    const warnings = content?.querySelector("[data-capture-warnings]");
    return {
      runtimeText: (runtime?.textContent || "").replace(/\s+/g, " ").trim(),
      eveTableClass: eveTable?.className || "",
      eveFlowRows: content?.querySelectorAll("[data-correlated-eve-row='flow']").length || 0,
      eveAlertRows: content?.querySelectorAll("[data-correlated-eve-row='alert']").length || 0,
      eveFlowIds: [...(content?.querySelectorAll("[data-correlated-eve-flow-id]") || [])].map((node) => node.getAttribute("data-correlated-eve-flow-id") || ""),
      trafficPivot: eveTableWrap?.querySelector(`a[href*="#/traffic?"][href*="${seed.flowId}"]`)?.getAttribute("href") || "",
      threatPivot: eveTableWrap?.querySelector(`a[href*="#/threats?"][href*="${seed.flowId}"]`)?.getAttribute("href") || "",
      commandText: (command?.textContent || "").replace(/\s+/g, " ").trim(),
      detailText: (detail?.textContent || "").replace(/\s+/g, " ").trim(),
      warningText: (warnings?.textContent || "").replace(/\s+/g, " ").trim(),
      seed,
    };
  }, investigationSeed);
  const requiredRuntime = [
    "Correlated EVE flows",
    "Correlated EVE alerts",
    `flow_id=${investigationSeed.flowId}`,
    `SID ${investigationSeed.signatureId}`,
  ];
  const missingRuntime = requiredRuntime.filter((part) => !state.runtimeText.includes(part));
  if (missingRuntime.length) {
    throw new Error(`capture runtime evidence missing: ${missingRuntime.join(", ")} in ${state.runtimeText || "<empty>"}`);
  }
  if (!state.eveTableClass.includes("responsive-evidence") || !state.eveTableClass.includes("troubleshoot-correlated-eve-table")) {
    throw new Error(`capture runtime correlated EVE table did not use responsive evidence at ${state.seed.flowId}: ${state.eveTableClass || "<missing>"}`);
  }
  if (state.eveFlowRows < 1 || state.eveAlertRows < 1 || !state.eveFlowIds.includes(investigationSeed.flowId) ||
      !state.trafficPivot.includes("#/traffic?") || !state.threatPivot.includes("#/threats?")) {
    throw new Error(`capture runtime correlated EVE rows/pivots missing: ${JSON.stringify(state)}`);
  }
  const captureText = `${state.commandText} ${state.detailText} ${state.warningText}`;
  const requiredCapture = [
    "tcp",
    investigationSeed.srcIp,
    String(investigationSeed.srcPort),
    investigationSeed.destIp,
    String(investigationSeed.destPort),
    `src host ${investigationSeed.srcIp}`,
    `src host ${investigationSeed.destIp}`,
  ];
  const missingCapture = requiredCapture.filter((part) => !captureText.includes(part));
  if (missingCapture.length) {
    throw new Error(`capture tuple evidence missing: ${missingCapture.join(", ")} in ${captureText || "<empty>"}`);
  }
}

async function assertPacketCaptureArtifactLifecycle(page, viewport) {
  const rowSelector = `[data-capture-workbench="troubleshoot"] [data-capture-artifact-row="${captureArtifactSeed.id}"]`;
  await page.waitForSelector(rowSelector, { timeout: 10000 });
  const initial = await packetCaptureArtifactState(page, rowSelector);
  const requiredSelectors = [
    "[data-capture-field=\"interface\"]",
    "[data-capture-field=\"duration\"]",
    "[data-capture-field=\"packets\"]",
    "[data-capture-field=\"snaplen\"]",
    "[data-capture-command]",
    "[data-capture-detail]",
    "[data-capture-warnings]",
    "[data-capture-history]",
    "[data-capture-action=\"server-plan\"]",
    "[data-capture-action=\"start\"]",
    "[data-capture-action=\"pin\"]",
    "[data-capture-action=\"copy-handoff\"]",
    "[data-capture-action=\"export-json\"]",
    "[data-capture-action=\"copy-command\"]",
    "[data-capture-action=\"refresh-history\"]",
  ];
  const missing = requiredSelectors.filter((selector) => !initial.selectorMatches.includes(selector));
  if (missing.length) {
    throw new Error(`packet-capture workbench missing stable selector(s) at ${viewport.name}: ${missing.join(", ")}`);
  }
  if (initial.copyCommandAction.type !== "button" || initial.copyCommandAction.ariaLabel !== "Copy capture command") {
    throw new Error(`packet-capture copy command action was not accessible at ${viewport.name}: ${JSON.stringify(initial.copyCommandAction)}`);
  }
  if (initial.overflow > 2) {
    throw new Error(`packet-capture lifecycle row overflow at ${viewport.name}: ${initial.overflow}px`);
  }
  if (!initial.text.includes(captureArtifactSeed.filename) || !initial.text.includes(investigationSeed.flowId) || !initial.text.includes("SHA-256")) {
    throw new Error(`packet-capture lifecycle row missing seeded artifact evidence at ${viewport.name}: ${initial.text || "<empty>"}`);
  }
  if (!initial.actions.includes("retain") || !initial.actions.includes("download") || !initial.actions.includes("audit")) {
    throw new Error(`packet-capture lifecycle row missing initial actions at ${viewport.name}: ${JSON.stringify(initial.actions)}`);
  }

  await page.locator(`${rowSelector} [data-capture-action="retain"]`).click();
  await page.waitForSelector("[data-capture-retention-form]", { timeout: 5000 });
  await clickDrawerFooterButton(page, "Retain");
  await page.waitForFunction(() => (document.body.textContent || "").includes("Retention reason required"), null, { timeout: 5000 });
  const afterRejectedRetain = await packetCaptureArtifactState(page, rowSelector);
  if (afterRejectedRetain.retentionState === "retained" || afterRejectedRetain.text.includes("visual smoke case hold")) {
    throw new Error(`packet-capture retain without reason updated metadata at ${viewport.name}: ${JSON.stringify(afterRejectedRetain)}`);
  }

  await page.locator(`${rowSelector} [data-capture-action="retain"]`).click();
  await page.waitForSelector("[data-capture-retention-form]", { timeout: 5000 });
  await page.fill("[data-capture-retention-field=\"reason\"]", "visual smoke case hold");
  await page.fill("[data-capture-retention-field=\"case-id\"]", "VS-2026-CAPTURE");
  await page.fill("[data-capture-retention-field=\"retain-until\"]", "2026-07-20T00:00:00Z");
  await clickDrawerFooterButton(page, "Retain");
  await page.waitForFunction((selector) => {
    const row = document.querySelector(selector);
    return row?.dataset?.captureRetentionState === "retained" &&
      (row.textContent || "").includes("visual smoke case hold") &&
      (row.textContent || "").includes("VS-2026-CAPTURE");
  }, rowSelector, { timeout: 10000 });
  const retained = await packetCaptureArtifactState(page, rowSelector);
  if (!retained.actions.includes("release") || retained.actions.includes("retain")) {
    throw new Error(`packet-capture retained row exposed wrong actions at ${viewport.name}: ${JSON.stringify(retained.actions)}`);
  }

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.locator(`${rowSelector} [data-capture-action="download"]`).click();
  const download = await downloadPromise;
  if (download.suggestedFilename() !== captureArtifactSeed.filename) {
    throw new Error(`packet-capture download filename mismatch at ${viewport.name}: ${download.suggestedFilename() || "<none>"}`);
  }
  const downloadPath = await download.path();
  if (!downloadPath) {
    throw new Error(`packet-capture download missing readable file at ${viewport.name}`);
  }
  const downloaded = await readFile(downloadPath);
  if (!downloaded.includes(Buffer.from("visual smoke packet capture"))) {
    throw new Error(`packet-capture download body did not match seeded artifact at ${viewport.name}`);
  }

  await page.locator(`${rowSelector} [data-capture-action="release"]`).click();
  await page.waitForSelector("[data-capture-retention-form]", { timeout: 5000 });
  await page.fill("[data-capture-retention-field=\"reason\"]", "visual smoke release complete");
  await page.fill("[data-capture-retention-field=\"case-id\"]", "VS-2026-CAPTURE");
  await clickDrawerFooterButton(page, "Release");
  await page.waitForFunction((selector) => {
    const row = document.querySelector(selector);
    return row?.dataset?.captureRetentionState === "released" &&
      (row.textContent || "").includes("visual smoke release complete");
  }, rowSelector, { timeout: 10000 });

  await page.locator(`${rowSelector} [data-capture-action="audit"]`).click();
  await waitForRouteReady(page, "/changes");
  const auditState = await page.evaluate(() => ({
    hash: location.hash || "",
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (!auditState.hash.includes("tab=audit") || !auditState.hash.includes("action=packet-capture") || !auditState.hash.includes("query=")) {
    throw new Error(`packet-capture audit action did not route to audit search at ${viewport.name}: ${auditState.hash || "<empty>"}`);
  }
  if (auditState.overflow > 2) {
    throw new Error(`packet-capture audit route overflow at ${viewport.name}: ${auditState.overflow}px`);
  }
  if (!auditState.text.includes("Audit log")) {
    throw new Error(`packet-capture audit route did not render audit log at ${viewport.name}: ${auditState.text || "<empty>"}`);
  }

  const restoreHash = `#/troubleshoot?fromZone=trust&toZone=dmz&src=${encodeURIComponent(investigationSeed.srcIp)}&sport=${investigationSeed.srcPort}&dst=${encodeURIComponent(investigationSeed.destIp)}&dport=${investigationSeed.destPort}&protocol=PROTOCOL_TCP&flowId=${encodeURIComponent(investigationSeed.flowId)}&runtime=1&run=1&intent=capture`;
  await page.evaluate((hash) => { location.hash = hash; }, restoreHash);
  await waitForRouteReady(page, "/troubleshoot");
  await page.waitForSelector(rowSelector, { timeout: 10000 });
}

async function packetCaptureArtifactState(page, rowSelector) {
  return await page.evaluate((selector) => {
    const row = document.querySelector(selector);
    const content = document.querySelector("#content");
    const selectors = [
      "[data-capture-field=\"interface\"]",
      "[data-capture-field=\"duration\"]",
      "[data-capture-field=\"packets\"]",
      "[data-capture-field=\"snaplen\"]",
      "[data-capture-command]",
      "[data-capture-detail]",
      "[data-capture-warnings]",
      "[data-capture-history]",
      "[data-capture-action=\"server-plan\"]",
      "[data-capture-action=\"start\"]",
      "[data-capture-action=\"pin\"]",
      "[data-capture-action=\"copy-handoff\"]",
      "[data-capture-action=\"export-json\"]",
      "[data-capture-action=\"copy-command\"]",
      "[data-capture-action=\"refresh-history\"]",
    ];
    const copyCommand = content?.querySelector('[data-capture-action="copy-command"]');
    return {
      present: Boolean(row),
      text: (row?.textContent || "").replace(/\s+/g, " ").trim(),
      actions: [...(row?.querySelectorAll("[data-capture-action]") || [])].map((node) => node.dataset.captureAction),
      retentionState: row?.dataset?.captureRetentionState || "",
      selectorMatches: selectors.filter((candidate) => Boolean(content?.querySelector(candidate))),
      copyCommandAction: {
        type: copyCommand?.getAttribute("type") || "",
        ariaLabel: copyCommand?.getAttribute("aria-label") || "",
        title: copyCommand?.getAttribute("title") || "",
      },
      overflow: row ? Math.max(0, Math.ceil(row.scrollWidth - row.clientWidth)) : 0,
    };
  }, rowSelector);
}

async function assertRuleEditorCandidateOnly(page, viewport, expectedAction, opts = {}) {
  const state = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const labelControl = (labelText) => {
      const label = [...(drawer?.querySelectorAll("label.field") || [])]
        .find((candidate) => (candidate.querySelector("span")?.textContent || "").trim().startsWith(labelText));
      const control = label?.querySelector("input, select, textarea");
      return {
        value: control?.type === "checkbox" ? Boolean(control.checked) : (control?.value || ""),
        present: Boolean(control),
      };
    };
    const rect = drawer?.getBoundingClientRect?.();
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      name: labelControl("Name"),
      action: labelControl("Action"),
      log: labelControl("Log matches"),
      footerButtons: [...(drawer?.querySelectorAll(".drawer-foot button") || [])].map((button) => (button.textContent || "").replace(/\s+/g, " ").trim()),
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
  if (state.title !== "New rule") {
    throw new Error(`rule pivot opened "${state.title || "<none>"}" instead of New rule`);
  }
  if (!state.text.includes("Changes stage to the candidate")) {
    throw new Error("rule pivot did not expose candidate-only staging language");
  }
  if (!state.footerButtons.includes("Cancel") || !state.footerButtons.includes("Add rule")) {
    throw new Error(`rule pivot footer missing Cancel/Add rule actions: ${state.footerButtons.join(", ")}`);
  }
  if (!state.action.present || state.action.value !== expectedAction) {
    throw new Error(`rule pivot action=${state.action.present ? state.action.value : "<missing>"} want ${expectedAction}`);
  }
  if (opts.namePrefix && (!state.name.present || !String(state.name.value).startsWith(opts.namePrefix))) {
    throw new Error(`rule pivot name=${state.name.present ? state.name.value : "<missing>"} does not start with ${opts.namePrefix}`);
  }
  if (opts.expectLog != null && (!state.log.present || state.log.value !== opts.expectLog)) {
    throw new Error(`rule pivot log=${state.log.present ? state.log.value : "<missing>"} want ${opts.expectLog}`);
  }
  if (state.overflow > 2) {
    throw new Error(`rule pivot drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
}

async function snapshotCandidatePolicy(page) {
  return await page.evaluate(async () => {
    const candidate = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (candidate.ok) return (await candidate.json())?.policy || {};
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read policy snapshot failed with HTTP ${running.status}: ${await running.text()}`);
    }
    return (await running.json())?.policy || {};
  });
}

async function fillCustomAppIdReviewDrawer(page, seed = investigationSeed) {
  await page.evaluate((seed) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("custom App-ID drawer was not open");
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const fieldControl = (label) => {
      const field = [...drawer.querySelectorAll("label.field")]
        .find((candidate) => textOf(candidate.querySelector("span")).startsWith(label));
      const control = field?.querySelector("input, select, textarea");
      if (!control) throw new Error(`custom App-ID field ${label} was not found`);
      return control;
    };
    const setInput = (control, value) => {
      control.value = value;
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setInput(fieldControl("App-ID"), seed.customAppId);
    setInput(fieldControl("Display name"), "Visual Admin App");
    setInput(fieldControl("Category"), "business-app");
    setInput(fieldControl("Engine signals"), seed.customAppSignal);
    setInput(fieldControl("TCP ports"), String(seed.destPort));
    setInput(fieldControl("UDP ports"), "");
    setInput(fieldControl("Description"), seed.customAppDescription);
  }, seed);
}

async function assertCustomAppIdReviewDrawer(page, viewport, seed = investigationSeed) {
  const drawer = await page.evaluate(() => {
    const el = document.querySelector("#drawer:not([hidden])");
    const rect = el?.getBoundingClientRect?.();
    const textOf = (node) => (node?.textContent || "").replace(/\s+/g, " ").trim();
    const labelControl = (labelText) => {
      const label = [...(el?.querySelectorAll("label.field") || [])]
        .find((candidate) => textOf(candidate.querySelector("span")).startsWith(labelText));
      const control = label?.querySelector("input, select, textarea");
      return control?.value || "";
    };
    return {
      title: el?.querySelector("h2")?.textContent?.trim() || "",
      text: textOf(el),
      appId: labelControl("App-ID"),
      tcpPorts: labelControl("TCP ports"),
      footerButtons: [...(el?.querySelectorAll(".drawer-foot button") || [])].map((button) => ({
        text: textOf(button),
        width: button.getBoundingClientRect().width,
        height: button.getBoundingClientRect().height,
      })),
      overflow: el ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(el.scrollWidth - el.clientWidth),
      ) : 0,
    };
  });
  assertDrawerContains(drawer, viewport, "custom App-ID drawer", [
    "Custom App-ID",
    "fallback hint only",
    "Review drop rule",
  ], ["Cancel", "Save & view", "Review drop rule", "Save & drop", "Save"]);
  if (drawer.appId !== seed.customAppId || drawer.tcpPorts !== String(seed.destPort)) {
    throw new Error(`custom App-ID drawer fields not populated: appId=${drawer.appId || "<empty>"} tcp=${drawer.tcpPorts || "<empty>"}`);
  }
}

async function assertAppIdRuleReviewEditor(page, viewport, seed = investigationSeed) {
  const state = await page.evaluate((seed) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const labelControl = (labelText) => {
      const label = [...(drawer?.querySelectorAll("label.field") || [])]
        .find((candidate) => (candidate.querySelector("span")?.textContent || "").trim().startsWith(labelText));
      const control = label?.querySelector("input, select, textarea");
      return {
        value: control?.type === "checkbox" ? Boolean(control.checked) : (control?.value || ""),
        present: Boolean(control),
        text: (label?.textContent || "").replace(/\s+/g, " ").trim(),
        chips: [...(label?.querySelectorAll(".chip") || [])].map((chip) => (chip.textContent || "").replace(/\s+/g, " ").trim()).filter(Boolean),
      };
    };
    const rect = drawer?.getBoundingClientRect?.();
    const addRule = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
      .find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === "Add rule");
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      name: labelControl("Name"),
      services: labelControl("Services"),
      applications: labelControl("Applications"),
      action: labelControl("Action"),
      log: labelControl("Log matches"),
      addDisabled: Boolean(addRule?.disabled),
      seed,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  }, seed);
  if (state.title !== "New rule") {
    throw new Error(`App-ID review opened "${state.title || "<none>"}" instead of New rule`);
  }
  if (!state.name.present || !String(state.name.value).startsWith(`drop-app-${seed.customAppId}-`)) {
    throw new Error(`App-ID review rule name=${state.name.present ? state.name.value : "<missing>"}`);
  }
  if (!state.text.includes(seed.customAppId) || !state.text.includes("Current App-ID enforcement path")) {
    throw new Error("App-ID review rule did not disclose the current enforcement path");
  }
  if (!state.text.includes("Engine-signal-only App-ID enforcement is a future L7 dataplane milestone")) {
    throw new Error("App-ID review rule did not disclose the L7 dataplane limitation");
  }
  if (!state.applications.chips.includes(seed.customAppId)) {
    throw new Error(`App-ID review rule applications field missing ${seed.customAppId}: ${JSON.stringify(state.applications.chips)}`);
  }
  if (state.services.chips.length) {
    throw new Error(`App-ID review rule unexpectedly retained explicit services: ${JSON.stringify(state.services.chips)}`);
  }
  if (!state.action.present || state.action.value !== "ACTION_DENY") {
    throw new Error(`App-ID review rule action=${state.action.present ? state.action.value : "<missing>"} want ACTION_DENY`);
  }
  if (!state.log.present || state.log.value !== true) {
    throw new Error(`App-ID review rule log=${state.log.present ? state.log.value : "<missing>"} want true`);
  }
  if (state.addDisabled) {
    throw new Error("App-ID review Add rule button was disabled");
  }
  if (state.overflow > 2) {
    throw new Error(`App-ID review rule drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
}

async function assertReviewedAppIdDropCandidate(page, seed = investigationSeed) {
  const state = await page.evaluate(async (seed) => {
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    const candidateBody = await candidateResponse.json();
    const runningBody = await runningResponse.json();
    const candidatePolicy = candidateBody?.policy || {};
    const runningText = JSON.stringify(runningBody?.policy || {});
    const app = (candidatePolicy.applications || []).find((item) => item.name === seed.customAppId);
    const rule = (candidatePolicy.rules || []).find((item) => (item.name || "").startsWith(`drop-app-${seed.customAppId}-`));
    return {
      candidateStatus: candidateResponse.status,
      runningStatus: runningResponse.status,
      app,
      rule,
      runningLeakedNames: [seed.customAppId, `drop-app-${seed.customAppId}`].filter((name) => runningText.includes(name)),
    };
  }, seed);
  if (state.candidateStatus !== 200) {
    throw new Error(`candidate policy fetch failed with HTTP ${state.candidateStatus}`);
  }
  if (state.runningStatus !== 200) {
    throw new Error(`running policy fetch failed with HTTP ${state.runningStatus}`);
  }
  if (!state.app || !state.app.engineSignals?.includes(seed.customAppSignal)) {
    throw new Error(`candidate App-ID object missing or incomplete: ${JSON.stringify(state.app)}`);
  }
  if (!state.app.ports?.some((hint) => hint.protocol === "PROTOCOL_TCP" && hint.ports?.some((port) => Number(port.start) === seed.destPort))) {
    throw new Error(`candidate App-ID object missing TCP/${seed.destPort}: ${JSON.stringify(state.app)}`);
  }
  if (!state.rule || state.rule.action !== "ACTION_DENY" || state.rule.log !== true) {
    throw new Error(`candidate App-ID drop rule missing or incomplete: ${JSON.stringify(state.rule)}`);
  }
  if ((state.rule.services || []).length !== 0 || !state.rule.applications?.includes(seed.customAppId)) {
    throw new Error(`candidate App-ID drop rule retained wrong match fields: ${JSON.stringify(state.rule)}`);
  }
  if (state.runningLeakedNames.length) {
    throw new Error(`App-ID review workflow mutated running policy: ${state.runningLeakedNames.join(", ")}`);
  }
}

async function assertThreatFalsePositiveDrawer(page, viewport) {
  const initial = await collectFalsePositiveDrawer(page);
  if (initial.overflow > 2) {
    throw new Error(`false-positive exception drawer overflow at ${viewport.name}: ${initial.overflow}px`);
  }
  if (!initial.reasonPlaceholder.includes("Required: why this alert is safe to suppress")) {
    throw new Error("false-positive exception drawer did not require an operator reason");
  }
  if (!initial.text.includes("Candidate-only") || !initial.text.includes("operator reason is required")) {
    throw new Error("false-positive exception drawer did not show candidate-only incomplete preview");
  }
  if (!/^Stage (source|destination|global) exception$/.test(initial.stageLabel) || !initial.stageDisabled) {
    throw new Error(`false-positive exception stage button was not disabled until reason (label=${initial.stageLabel || "<none>"}, disabled=${initial.stageDisabled})`);
  }
  if (initial.stageType !== "button" || !initial.stageTitle || !initial.stageAriaLabel) {
    throw new Error(`false-positive exception stage button missing semantics at ${viewport.name}: ${JSON.stringify(initial)}`);
  }

  await page.fill('#drawer:not([hidden]) textarea[placeholder="Required: why this alert is safe to suppress"]', investigationSeed.operatorReason);
  await page.waitForFunction((reason) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const stageButton = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
      .find((button) => /^Stage (source|destination|global) exception$/.test((button.textContent || "").replace(/\s+/g, " ").trim()));
    const text = drawer?.textContent || "";
    return Boolean(stageButton && !stageButton.disabled && text.includes("staged after click") && text.includes(reason));
  }, investigationSeed.operatorReason, { timeout: 5000 });

  const ready = await collectFalsePositiveDrawer(page);
  if (ready.stageDisabled || !ready.text.includes("staged after click") || !ready.text.includes(investigationSeed.operatorReason)) {
    throw new Error("false-positive exception drawer did not enable staging after operator reason");
  }
  if (ready.stageType !== "button" || !ready.stageTitle || !ready.stageAriaLabel) {
    throw new Error(`false-positive exception ready stage button missing semantics at ${viewport.name}: ${JSON.stringify(ready)}`);
  }
  await clickDrawerFooterButton(page, ready.stageLabel);
  await waitForDrawerTitle(page, "False-positive exception staged");
  const staged = await collectDrawerState(page);
  assertDrawerContains(staged, viewport, "false-positive staged result", [
    "False-positive exception staged",
    "Candidate only",
    "Exception",
    "Signature ID",
    String(investigationSeed.signatureId),
    "Scope",
    investigationSeed.operatorReason,
    "openngfw-threshold.config",
    "Candidate status",
    "Diff:",
    "Open candidate",
    "Review & commit",
  ], ["Close"]);
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await assertThreatExceptionWorkbench(page, viewport);
  await page.click('[data-threat-action="ids-settings"]');
  await waitForDrawerTitle(page, "IDS / IPS configuration");
  await assertIdsActionControls(page, viewport, "IDS editor from Threats", [
    "data-ids-action=stage-settings",
    "data-ids-exception-action=remove",
  ]);
  const idsEditor = await collectIDSEditorState(page);
  if (!idsEditor.visible) {
    throw new Error("IDS editor did not expose the stable editor marker after staging a false-positive exception");
  }
  const stagedException = idsEditor.exceptions.find((item) => item.name.includes("fp-9000001-source") || item.text.includes("SID 9000001"));
  if (!stagedException) {
    throw new Error(`IDS editor did not list the staged false-positive exception: ${JSON.stringify(idsEditor.exceptions)}`);
  }
  if (!stagedException.text.includes(investigationSeed.operatorReason) || !/candidate/i.test(stagedException.text)) {
    throw new Error(`IDS editor staged exception row did not preserve reason and candidate state: ${JSON.stringify(stagedException)}`);
  }
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
  await assertIdsProfileSettingsLifecycle(page, viewport);
  await assertThreatExceptionLifecycle(page, viewport, stagedException.name);
}

async function assertIdsProfileSettingsLifecycle(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const baselineRunningIds = await snapshotRunningIds(page);
  try {
    await assertInvalidIdsProfilePreflight(page, viewport);
    const cases = [
      {
        label: "detect",
        form: {
          enabled: true,
          mode: "detect",
          monitorInterfaces: "eth-threat-detect",
          homeNetworks: "10.91.0.0/24",
          ruleFiles: "visual-smoke-detect.rules",
          queueNum: "7",
          failureBehavior: "fail-open",
        },
        expected: {
          enabled: true,
          mode: "IDS_MODE_DETECT",
          monitorInterfaces: ["eth-threat-detect"],
          homeNetworks: ["10.91.0.0/24"],
          ruleFiles: ["visual-smoke-detect.rules"],
          queueNum: undefined,
          failureBehavior: "",
        },
      },
      {
        label: "prevent fail-open",
        form: {
          enabled: true,
          mode: "prevent",
          monitorInterfaces: "eth-threat-prevent-open",
          homeNetworks: "10.92.0.0/24",
          ruleFiles: "visual-smoke-prevent.rules",
          queueNum: "11",
          failureBehavior: "fail-open",
        },
        expected: {
          enabled: true,
          mode: "IDS_MODE_PREVENT",
          monitorInterfaces: ["eth-threat-prevent-open"],
          homeNetworks: ["10.92.0.0/24"],
          ruleFiles: ["visual-smoke-prevent.rules"],
          queueNum: 11,
          failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
        },
      },
      {
        label: "prevent fail-closed",
        form: {
          enabled: true,
          mode: "prevent",
          monitorInterfaces: "eth-threat-prevent-closed",
          homeNetworks: "10.93.0.0/24",
          ruleFiles: "visual-smoke-prevent.rules",
          queueNum: "12",
          failureBehavior: "fail-closed",
        },
        expected: {
          enabled: true,
          mode: "IDS_MODE_PREVENT",
          monitorInterfaces: ["eth-threat-prevent-closed"],
          homeNetworks: ["10.93.0.0/24"],
          ruleFiles: ["visual-smoke-prevent.rules"],
          queueNum: 12,
          failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
        },
      },
      {
        label: "disable",
        form: {
          enabled: false,
          mode: "detect",
          monitorInterfaces: "eth-threat-disabled",
          homeNetworks: "10.94.0.0/24",
          ruleFiles: "visual-smoke-disabled.rules",
          queueNum: "13",
          failureBehavior: "fail-open",
        },
        expected: {
          enabled: false,
          mode: "",
          monitorInterfaces: ["eth-threat-disabled"],
          homeNetworks: ["10.94.0.0/24"],
          ruleFiles: ["visual-smoke-disabled.rules"],
          queueNum: undefined,
          failureBehavior: "",
        },
      },
    ];

    for (const testCase of cases) {
      await openIdsSettingsEditor(page);
      await stageIdsProfileSettings(page, testCase.form);
      await assertIdsProfilePolicyState(page, testCase.expected, baselineRunningIds, testCase.label);
      await openIdsSettingsEditor(page);
      const editor = await collectIDSEditorState(page);
      assertIdsEditorProfileState(editor, testCase.expected, testCase.label, viewport);
      await clickDrawerFooterButton(page, "Cancel");
      await waitForDrawerClosed(page);
    }
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertInvalidIdsProfilePreflight(page, viewport) {
  const beforePolicy = await snapshotCandidatePolicy(page);
  await openIdsSettingsEditor(page);
  await assertIdsActionControls(page, viewport, "IDS invalid preflight editor", ["data-ids-action=stage-settings"]);
  await page.evaluate(() => {
    const root = document.querySelector("[data-ids-editor='true']");
    if (!root) throw new Error("IDS editor was not open for invalid preflight");
    const enabled = root.querySelector("input[data-ids-field='enabled']");
    if (!enabled) throw new Error("IDS enabled control was not found");
    if (!enabled.checked) enabled.click();
    root.querySelector("[data-ids-mode='prevent']")?.click();
    root.querySelector("[data-ids-failure-behavior='fail-open']")?.click();
    const setInput = (field, value) => {
      const input = root.querySelector(`input[data-ids-field='${field}']`);
      if (!input) throw new Error(`IDS input ${field} was not found`);
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setInput("monitor-interfaces", "eth-invalid-preflight");
    setInput("home-networks", "10.91.0.0/99");
    setInput("rule-files", "../bad.rules");
    setInput("queue-num", "70000");
    const stage = document.querySelector("#drawer:not([hidden]) [data-ids-action='stage-settings']");
    if (!stage || stage.disabled) throw new Error("IDS stage settings action was not available");
    stage.click();
  });
  await page.waitForFunction(() => {
    const root = document.querySelector("[data-ids-editor='true']");
    const validation = root?.querySelector("[data-ids-validation-state='failed']");
    const text = (validation?.textContent || root?.textContent || "").replace(/\s+/g, " ").trim();
    return Boolean(root && validation) &&
      /invalid home network CIDR|rule file|queue_num/.test(text);
  }, null, { timeout: 10000 });
  const state = await collectIDSEditorState(page);
  if (!state.visible || !/invalid home network CIDR|rule file|queue_num/.test(state.text)) {
    throw new Error(`IDS invalid preflight did not keep validation evidence visible at ${viewport.name}: ${state.text}`);
  }
  if (state.overflow > 2) {
    throw new Error(`IDS invalid preflight drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const afterPolicy = await snapshotCandidatePolicy(page);
  if (JSON.stringify(afterPolicy) !== JSON.stringify(beforePolicy)) {
    throw new Error("IDS invalid preflight mutated the candidate before a valid stage action");
  }
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
}

async function assertInspectionWorkspace(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const baselineRunningIds = await snapshotRunningIds(page);
  try {
    await page.evaluate(() => {
      location.hash = "#/inspection";
    });
    await waitForRouteReady(page, "/inspection");
    await page.waitForSelector("[data-inspection-workspace='true']", { timeout: 10000 });
    await assertIdsActionControls(page, viewport, "inspection workspace", [
      "data-inspection-action=edit-profile",
      "data-inspection-action=stage-profile",
      "data-ids-profile-action=detect",
      "data-ids-profile-action=disable",
    ]);
    const initial = await collectInspectionWorkspaceState(page);
    for (const required of ["Inspection profile", "Runtime posture", "Inspection coverage map", "Threat rollout actions", "Threat-ID package", "False-positive exceptions"]) {
      if (!initial.text.includes(required)) {
        throw new Error(`inspection workspace missing ${required} at ${viewport.name}: ${initial.text}`);
      }
    }
    if (!initial.coverageText.includes("candidate rules") || !initial.coverageText.includes("active allow paths")) {
      throw new Error(`inspection coverage map missing rule counters at ${viewport.name}: ${initial.coverageText}`);
    }
    if (!initial.coverageBuckets.length && !initial.coverageText.includes("No rules to map")) {
      throw new Error(`inspection coverage map missing bucket rows or empty state at ${viewport.name}: ${initial.coverageText}`);
    }
    if (initial.coverageBuckets.length) {
      await assertPageResponsiveTable(page, viewport, ".inspection-coverage-table", ["Coverage", "Rules", "Examples", "Operator action"], "inspection coverage map");
    }
    if (!initial.actions.includes("detect") || !initial.actions.includes("disable")) {
      throw new Error(`inspection workspace missing direct rollout actions at ${viewport.name}: ${JSON.stringify(initial.actions)}`);
    }
    if (initial.overflow > 2) {
      throw new Error(`inspection workspace overflow at ${viewport.name}: ${initial.overflow}px`);
    }

    await page.click('[data-ids-profile-action="detect"][data-inspection-action="stage-profile"]');
    await waitForInspectionProfileState(page, "detect", (state) => (
      state.candidate.enabled === true &&
      state.candidate.mode === "IDS_MODE_DETECT" &&
      state.runningFingerprint === state.baselineRunningFingerprint
    ), baselineRunningIds);
    await page.waitForFunction(() => {
      const text = (document.querySelector("[data-inspection-workspace='true']")?.textContent || "").replace(/\s+/g, " ").trim();
      return /candidate-only|Candidate delta/.test(text);
    }, null, { timeout: 10000 });
    const detectView = await collectInspectionWorkspaceState(page);
    if (!/candidate-only|Candidate delta/.test(detectView.text)) {
      throw new Error(`inspection workspace did not show candidate-only detect state at ${viewport.name}: ${detectView.text}`);
    }
    if (!detectView.coverageText.includes("Inspection coverage map")) {
      throw new Error(`inspection coverage map disappeared after detect staging at ${viewport.name}: ${detectView.text}`);
    }

    await page.click('[data-ids-profile-action="disable"][data-inspection-action="stage-profile"]');
    await waitForInspectionProfileState(page, "disable", (state) => (
      state.candidate.enabled === false &&
      state.runningFingerprint === state.baselineRunningFingerprint
    ), baselineRunningIds);

    await assertAutomationContextDrawer(page, viewport, "inspection automation context", [
      "#/inspection",
      "/v1/system/status",
      "/v1/intel/content/packages",
      "/v1/alerts?limit=200",
      "ngfwctl status",
      "ngfwctl intel content",
      "ngfwctl alerts --limit 100",
      "IDS/IPS engine detect/prevent runtime changes after validation and commit",
    ]);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function collectInspectionWorkspaceState(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-inspection-workspace='true']");
    const rect = root?.getBoundingClientRect?.();
    return {
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      actions: [...(root?.querySelectorAll("[data-ids-profile-action]") || [])].map((button) => button.dataset.idsProfileAction || ""),
      coverageText: (root?.querySelector("[data-inspection-coverage-map='true']")?.textContent || "").replace(/\s+/g, " ").trim(),
      coverageBuckets: [...(root?.querySelectorAll("[data-inspection-coverage-bucket]") || [])].map((row) => ({
        state: row.dataset.inspectionCoverageBucket || "",
        text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      })),
      overflow: root ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(root.scrollWidth - root.clientWidth),
      ) : 0,
    };
  });
}

async function waitForInspectionProfileState(page, label, predicate, baselineRunningIds) {
  const deadline = Date.now() + 10000;
  let state = null;
  while (Date.now() < deadline) {
    state = await page.evaluate(async ({ label: stateLabel, baseline }) => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok) return { matched: false, http: [candidateResponse.status, runningResponse.status] };
    const candidate = (await candidateResponse.json())?.policy?.ids || {};
    const running = (await runningResponse.json())?.policy?.ids || {};
    const state = {
      label: stateLabel,
      candidate,
      running,
      runningFingerprint: stable(running),
      baselineRunningFingerprint: stable(baseline || {}),
    };
    globalThis.__inspectionWorkspaceLastState = state;
    if (stateLabel === "detect") {
      return { ...state, matched: candidate.enabled === true && candidate.mode === "IDS_MODE_DETECT" && state.runningFingerprint === state.baselineRunningFingerprint };
    }
    if (stateLabel === "disable") {
      return { ...state, matched: candidate.enabled === false && state.runningFingerprint === state.baselineRunningFingerprint };
    }
    return { ...state, matched: false };
    }, { label, baseline: baselineRunningIds || {} });
    if (state?.matched && predicate(state)) return;
    await page.waitForTimeout(200);
  }
  const diagnostic = await page.evaluate(() => ({
    lastState: globalThis.__inspectionWorkspaceLastState || null,
    lastError: globalThis.__inspectionWorkspaceLastError || "",
    toast: (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim(),
    pageText: (document.querySelector("[data-inspection-workspace='true']")?.textContent || "").replace(/\s+/g, " ").trim(),
  }));
  if (!state || !state.candidate || !predicate(state)) {
    throw new Error(`inspection workspace ${label} candidate state mismatch: ${JSON.stringify({ state, diagnostic })}`);
  }
}

async function snapshotRunningIds(page) {
  return await page.evaluate(async () => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!response.ok) {
      throw new Error(`read running IDS snapshot failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json())?.policy?.ids || {};
  });
}

async function openIdsSettingsEditor(page) {
  await page.evaluate(() => {
    location.hash = "#/threats?view=exceptions";
  });
  await waitForRouteReady(page, "/threats");
  await page.click('[data-threat-action="ids-settings"]');
  await waitForDrawerTitle(page, "IDS / IPS configuration");
  await page.waitForSelector("[data-ids-editor='true']", { timeout: 10000 });
}

async function assertIdsActionControls(page, viewport, label, expected = []) {
  const state = await page.evaluate((expected) => {
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const watched = ["data-inspection-action", "data-ids-profile-action", "data-ids-action", "data-ids-exception-action"];
    const buttons = [...document.querySelectorAll(watched.map((attr) => `button[${attr}]`).join(","))]
      .filter(visible)
      .map((button) => {
        const attrs = Object.fromEntries(watched.map((attr) => [attr, button.getAttribute(attr) || ""]));
        return {
          attrs,
          keys: Object.entries(attrs).filter(([, value]) => value).map(([attr, value]) => `${attr}=${value}`),
          type: button.getAttribute("type") || "",
          title: button.getAttribute("title") || "",
          ariaLabel: button.getAttribute("aria-label") || "",
          text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        };
      });
    return {
      buttons,
      invalid: buttons.filter((button) => (
        button.keys.some((key) => expected.includes(key)) &&
        (button.type !== "button" || !button.title.trim() || !button.ariaLabel.trim())
      )),
    };
  }, expected);
  if (state.invalid.length) {
    throw new Error(`${label} IDS/Inspection action controls missing semantics at ${viewport.name}: ${JSON.stringify(state.invalid)}`);
  }
  for (const key of expected) {
    if (!state.buttons.some((button) => button.keys.includes(key))) {
      throw new Error(`${label} missing IDS/Inspection action ${key} at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
}

async function stageIdsProfileSettings(page, form) {
  await page.evaluate((next) => {
    const root = document.querySelector("[data-ids-editor='true']");
    if (!root) throw new Error("IDS editor was not open");
    const enabled = root.querySelector("input[data-ids-field='enabled']");
    if (!enabled) throw new Error("IDS enabled control was not found");
    if (Boolean(enabled.checked) !== Boolean(next.enabled)) enabled.click();
    const mode = root.querySelector(`[data-ids-mode='${next.mode}']`);
    if (!mode) throw new Error(`IDS mode control ${next.mode} was not found`);
    mode.click();
    const failure = root.querySelector(`[data-ids-failure-behavior='${next.failureBehavior}']`);
    if (!failure) throw new Error(`IDS failure behavior control ${next.failureBehavior} was not found`);
    failure.click();
    const setInput = (field, value) => {
      const input = root.querySelector(`input[data-ids-field='${field}']`);
      if (!input) throw new Error(`IDS input ${field} was not found`);
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setInput("monitor-interfaces", next.monitorInterfaces);
    setInput("home-networks", next.homeNetworks);
    setInput("rule-files", next.ruleFiles);
    setInput("queue-num", next.queueNum);
    const stage = document.querySelector("#drawer:not([hidden]) [data-ids-action='stage-settings']");
    if (!stage || stage.disabled) throw new Error("IDS stage settings action was not available");
    stage.click();
  }, form);
  await waitForDrawerClosed(page);
}

async function assertIdsProfilePolicyState(page, expected, baselineRunningIds, label) {
  const state = await page.evaluate(async () => {
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read IDS candidate policy failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read IDS running policy failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    return {
      candidate: (await candidateResponse.json())?.policy?.ids || {},
      running: (await runningResponse.json())?.policy?.ids || {},
    };
  });
  assertIdsProfileMatches(state.candidate, expected, `candidate ${label}`);
  if (JSON.stringify(state.running) !== JSON.stringify(baselineRunningIds || {})) {
    throw new Error(`IDS ${label} mutated running policy before commit: got ${JSON.stringify(state.running)}, want baseline ${JSON.stringify(baselineRunningIds || {})}`);
  }
}

function assertIdsEditorProfileState(editor, expected, label, viewport) {
  if (!editor.visible) {
    throw new Error(`IDS editor was not visible after staging ${label}`);
  }
  if (editor.overflow > 2) {
    throw new Error(`IDS editor overflow after staging ${label} at ${viewport.name}: ${editor.overflow}px`);
  }
  assertIdsProfileMatches(editor.profile, expected, `editor ${label}`);
  if (!editor.actions.includes("stage-settings")) {
    throw new Error(`IDS editor did not expose stable stage action after ${label}: ${JSON.stringify(editor.actions)}`);
  }
}

function assertIdsProfileMatches(actual = {}, expected = {}, label = "IDS profile") {
  const enabled = Boolean(actual.enabled);
  const mode = enabled ? (actual.mode || "") : "";
  const prevent = enabled && mode === "IDS_MODE_PREVENT";
  const normalized = {
    enabled,
    mode,
    monitorInterfaces: actual.monitorInterfaces || [],
    homeNetworks: actual.homeNetworks || [],
    ruleFiles: actual.ruleFiles || [],
    queueNum: prevent ? actual.queueNum : undefined,
    failureBehavior: prevent && actual.failureBehavior !== "IDS_FAILURE_BEHAVIOR_UNSPECIFIED" ? actual.failureBehavior || "" : "",
  };
  const fields = ["enabled", "mode", "monitorInterfaces", "homeNetworks", "ruleFiles", "failureBehavior"];
  for (const field of fields) {
    if (JSON.stringify(normalized[field]) !== JSON.stringify(expected[field])) {
      throw new Error(`${label} ${field} mismatch: got ${JSON.stringify(normalized[field])}, want ${JSON.stringify(expected[field])}; profile=${JSON.stringify(normalized)}`);
    }
  }
  if (expected.queueNum !== undefined && Number(normalized.queueNum) !== Number(expected.queueNum)) {
    throw new Error(`${label} queueNum mismatch: got ${JSON.stringify(normalized.queueNum)}, want ${expected.queueNum}; profile=${JSON.stringify(normalized)}`);
  }
  if (expected.queueNum === undefined && normalized.queueNum !== undefined) {
    throw new Error(`${label} queueNum should be absent: ${JSON.stringify(normalized)}`);
  }
}

async function assertThreatExceptionWorkbench(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/threats?view=exceptions";
  });
  await waitForRouteReady(page, "/threats");
  await page.waitForSelector("[data-threat-exception-workbench='true'] [data-threat-exception-row]", { timeout: 10000 });
  const state = await collectThreatExceptionWorkbench(page);
  if (!state.visible) {
    throw new Error("Threat exception workbench did not render");
  }
  if (state.overflow > 2) {
    throw new Error(`threat exception workbench overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.table.tableClass.includes("responsive-evidence") || !state.table.tableClass.includes("threat-exception-table")) {
    throw new Error(`Threat exception table missing responsive class at ${viewport.name}: ${JSON.stringify(state.table)}`);
  }
  const expectedLabels = ["Threat-ID", "Scope", "Reason", "Review", "Policy state", "Actions"];
  const missingLabels = expectedLabels.filter((label) => !state.table.labels.includes(label));
  if (missingLabels.length) {
    throw new Error(`Threat exception table missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, table: state.table })}`);
  }
  if (state.table.overflow > 2) {
    throw new Error(`Threat exception table overflow at ${viewport.name}: ${state.table.overflow}px`);
  }
  if (!state.table.mobileLabelsRendered) {
    throw new Error(`Threat exception table mobile labels did not render at ${viewport.name}: ${JSON.stringify(state.table)}`);
  }
  const staged = state.rows.find((row) => row.name.includes("fp-9000001-source") || row.text.includes("SID 9000001"));
  if (!staged) {
    throw new Error(`Threat exception workbench did not list staged exception: ${JSON.stringify(state.rows)}`);
  }
  for (const action of ["edit", "disable", "remove"]) {
    if (!staged.actions.some((button) => button.action === action)) {
      throw new Error(`Threat exception row missing ${action} action: ${JSON.stringify(staged)}`);
    }
  }
  if (!staged.text.includes(investigationSeed.operatorReason) || !/candidate/i.test(staged.text)) {
    throw new Error(`Threat exception row did not preserve reason and candidate state: ${JSON.stringify(staged)}`);
  }
  await page.click(`[data-threat-exception-row="${staged.name}"]`);
  await waitForDrawerTitle(page, "Threat exception");
  await assertThreatDrawerActionControls(page, viewport, "threat exception detail", {
    buttons: ["api-cli", "edit", "disable", "remove"],
    links: ["Review & commit"],
  });
  const detail = await collectDrawerState(page);
  assertDrawerContains(detail, viewport, "threat exception detail", [
    "Threat exception",
    staged.name,
    "Candidate lifecycle",
    "Signature ID",
    "Scope",
    "Post-commit artifact",
    "openngfw-threshold.config",
    "Edit",
    "Disable",
    "Remove",
    "API / CLI",
    "Review & commit",
  ], ["Close"]);
  await assertThreatExceptionDetailAutomationContext(page, viewport, staged.name);
}

async function assertThreatExceptionDetailAutomationContext(page, viewport, exceptionName) {
  await page.evaluate(() => {
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try { navigator.clipboard.writeText = writeText; } catch {}
    }
  });
  await page.click('#drawer:not([hidden]) [data-threat-exception-action="api-cli"]');
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "threat exception detail API / CLI context", [
    "API / CLI context",
    `#/threats?view=exceptions&exception=${exceptionName}`,
    `/v1/threat-exceptions/${exceptionName}:set-state`,
    `/v1/threat-exceptions/${exceptionName}:remove`,
    "ngfwctl threat-exceptions update",
    "ngfwctl threat-exceptions disable",
    "ngfwctl threat-exceptions enable",
    "ngfwctl threat-exceptions remove",
    "Copy session JSON",
    "Copy context",
  ], ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `threat exception detail API / CLI drawer ${viewport.name}`);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `threat exception detail workflow session JSON ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`threat exception workflow session JSON was not parseable at ${viewport.name}: ${err.message}`);
  }
  if (packet.schemaVersion !== "phragma.webui.workflow-session.v1" ||
      packet.source !== "browser-local" ||
      packet.routeState?.hash !== `#/threats?view=exceptions&exception=${exceptionName}` ||
      packet.custody?.serverStored !== false ||
      packet.custody?.signed !== false ||
      !packet.endpoints?.some((endpoint) => endpoint.path === `/v1/threat-exceptions/${exceptionName}:remove`) ||
      !packet.cli?.some((item) => String(item.command || "").includes(`threat-exceptions remove ${exceptionName}`))) {
    throw new Error(`threat exception workflow session JSON had unexpected shape at ${viewport.name}: ${JSON.stringify(packet)}`);
  }
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
}

async function assertThreatExceptionLifecycle(page, viewport, exceptionName) {
  await page.evaluate(() => {
    location.hash = "#/threats?view=exceptions";
  });
  await waitForRouteReady(page, "/threats");
  let state = await collectThreatExceptionWorkbench(page);
  assertThreatExceptionWorkbenchActions(state, viewport);
  let row = state.rows.find((item) => item.name === exceptionName);
  if (!row) {
    throw new Error(`Threat exception lifecycle could not find ${exceptionName}: ${JSON.stringify(state.rows)}`);
  }

  await clickThreatExceptionRowAction(page, exceptionName, "edit");
  await waitForDrawerTitle(page, "Edit threat exception");
  await assertThreatDrawerActionControls(page, viewport, "threat exception edit", { buttons: ["save-edit"] });
  await page.fill('#drawer:not([hidden]) textarea[placeholder="Exception reason stored in policy"]', "edited visual smoke false-positive exception");
  await page.fill('#drawer:not([hidden]) textarea[placeholder="Required audit reason for this lifecycle change"]', "visual smoke edit exception lifecycle");
  await waitForDrawerButtonEnabled(page, "Stage edit");
  await clickDrawerButton(page, "Stage edit");
  await waitForDrawerTitle(page, "Threat exception edit staged");
  let result = await collectDrawerState(page);
  assertDrawerContains(result, viewport, "threat exception edit result", [
    "Threat exception edit staged",
    "Candidate only",
    "Action",
    "update",
    "Candidate status",
    "Diff:",
    "Review & commit",
  ], ["Close"]);
  await assertThreatExceptionPolicyState(page, exceptionName, {
    exists: true,
    disabled: false,
    reasonIncludes: "edited visual smoke false-positive exception",
  });
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);

  state = await collectThreatExceptionWorkbench(page);
  assertThreatExceptionWorkbenchActions(state, viewport);
  row = state.rows.find((item) => item.name === exceptionName);
  if (!row?.text.includes("edited visual smoke false-positive exception")) {
    throw new Error(`Threat exception lifecycle edit did not refresh row text: ${JSON.stringify(row)}`);
  }

  await clickThreatExceptionRowAction(page, exceptionName, "disable");
  await waitForDrawerTitle(page, "Disable threat exception");
  await assertThreatDrawerActionControls(page, viewport, "threat exception disable", { buttons: ["disable"] });
  await page.fill('#drawer:not([hidden]) textarea[placeholder="Required: why this exception should be disabled"]', "visual smoke disable exception lifecycle");
  await waitForDrawerButtonEnabled(page, "Stage disable");
  await clickDrawerButton(page, "Stage disable");
  await waitForDrawerTitle(page, "Threat exception disabled");
  result = await collectDrawerState(page);
  assertDrawerContains(result, viewport, "threat exception disable result", [
    "Threat exception disabled",
    "Candidate only",
    "Action",
    "disable",
    "Candidate status",
    "Diff:",
  ], ["Close"]);
  await assertThreatExceptionPolicyState(page, exceptionName, {
    exists: true,
    disabled: true,
    reasonIncludes: "edited visual smoke false-positive exception",
  });
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);

  state = await collectThreatExceptionWorkbench(page);
  assertThreatExceptionWorkbenchActions(state, viewport);
  row = state.rows.find((item) => item.name === exceptionName);
  if (!row || !row.actions.some((button) => button.action === "enable") || !row.text.includes("disabled")) {
    throw new Error(`Threat exception lifecycle disable did not show enable action: ${JSON.stringify(row)}`);
  }

  await clickThreatExceptionRowAction(page, exceptionName, "enable");
  await waitForDrawerTitle(page, "Enable threat exception");
  await assertThreatDrawerActionControls(page, viewport, "threat exception enable", { buttons: ["enable"] });
  await page.fill('#drawer:not([hidden]) textarea[placeholder="Required: why this exception should be re-enabled"]', "visual smoke re-enable exception lifecycle");
  await waitForDrawerButtonEnabled(page, "Stage enable");
  await clickDrawerButton(page, "Stage enable");
  await waitForDrawerTitle(page, "Threat exception enabled");
  result = await collectDrawerState(page);
  assertDrawerContains(result, viewport, "threat exception enable result", [
    "Threat exception enabled",
    "Candidate only",
    "Action",
    "enable",
    "Candidate status",
    "Diff:",
  ], ["Close"]);
  await assertThreatExceptionPolicyState(page, exceptionName, {
    exists: true,
    disabled: false,
    reasonIncludes: "edited visual smoke false-positive exception",
  });
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);

  await clickThreatExceptionRowAction(page, exceptionName, "remove");
  await waitForDrawerTitle(page, "Remove threat exception");
  await assertThreatDrawerActionControls(page, viewport, "threat exception remove", { buttons: ["remove"] });
  await page.fill('#drawer:not([hidden]) textarea[placeholder="Required: why this exception can be removed"]', "visual smoke remove exception lifecycle");
  await waitForDrawerButtonEnabled(page, "Stage removal");
  await clickDrawerButton(page, "Stage removal");
  await waitForDrawerTitle(page, "Threat exception removal staged");
  result = await collectDrawerState(page);
  assertDrawerContains(result, viewport, "threat exception remove result", [
    "Threat exception removal staged",
    "Candidate only",
    "Action",
    "remove",
    "Exception",
    "removed",
    "Candidate status",
    "Diff:",
  ], ["Close"]);
  await assertThreatExceptionPolicyState(page, exceptionName, { exists: false });
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);

  state = await collectThreatExceptionWorkbench(page);
  assertThreatExceptionWorkbenchActions(state, viewport);
  if (state.rows.some((item) => item.name === exceptionName)) {
    throw new Error(`Threat exception lifecycle removal left row visible: ${JSON.stringify(state.rows)}`);
  }
  await assertAutomationContextDrawer(page, viewport, "threat exception automation context", [
    "#/threats?view=exceptions",
    "view = exceptions",
    "/v1/threat-exceptions:stage",
    "/v1/alerts",
    "ngfwctl alerts",
    "candidate-safe exceptions",
  ]);
}

async function clickThreatExceptionRowAction(page, exceptionName, action) {
  await page.evaluate(({ name, actionName }) => {
    const rows = [...document.querySelectorAll("[data-threat-exception-row]")];
    const row = rows.find((candidate) => candidate.dataset.threatExceptionRow === name);
    if (!row) throw new Error(`threat exception row ${name} was not found`);
    const button = [...row.querySelectorAll("[data-threat-exception-action]")]
      .find((candidate) => candidate.dataset.threatExceptionAction === actionName);
    if (!button) throw new Error(`threat exception action ${actionName} was not found on ${name}`);
    button.click();
  }, { name: exceptionName, actionName: action });
}

async function assertThreatDrawerActionControls(page, viewport, label, expected = {}) {
  const state = await page.evaluate((expected) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const buttons = [...(drawer?.querySelectorAll("button[data-threat-alert-action], button[data-threat-exception-action], button[data-threat-handoff-action], button[data-threat-fp-stage]") || [])]
      .filter(visible)
      .map((button) => ({
        action: button.getAttribute("data-threat-alert-action") ||
          button.getAttribute("data-threat-exception-action") ||
          button.getAttribute("data-threat-handoff-action") ||
          button.getAttribute("data-threat-fp-stage") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      }));
    const links = [...(drawer?.querySelectorAll("a.btn") || [])]
      .filter(visible)
      .map((link) => ({
        text: (link.textContent || "").replace(/\s+/g, " ").trim(),
        href: link.getAttribute("href") || "",
        title: link.getAttribute("title") || "",
        ariaLabel: link.getAttribute("aria-label") || "",
      }));
    return {
      buttons,
      links,
      invalidButtons: buttons.filter((button) => (
        button.type !== "button" ||
        !button.title.trim() ||
        !button.ariaLabel.trim() ||
        !button.action
      )),
      invalidLinks: links.filter((link) => (
        expected.links?.includes(link.text) &&
        (!link.href || !link.title.trim() || !link.ariaLabel.trim())
      )),
    };
  }, expected);
  if (state.invalidButtons.length || state.invalidLinks.length) {
    throw new Error(`${label} threat action controls missing semantics at ${viewport.name}: ${JSON.stringify({ invalidButtons: state.invalidButtons, invalidLinks: state.invalidLinks })}`);
  }
  for (const action of [...(expected.buttons || []), ...(expected.handoff || [])]) {
    if (!state.buttons.some((button) => button.action === action)) {
      throw new Error(`${label} missing threat action ${action} at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
  for (const text of expected.links || []) {
    if (!state.links.some((link) => link.text === text)) {
      throw new Error(`${label} missing threat link ${text} at ${viewport.name}: ${JSON.stringify(state.links)}`);
    }
  }
}

async function assertThreatExceptionPolicyState(page, exceptionName, expected = {}) {
  const state = await page.evaluate(async (name) => {
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read candidate for threat exception lifecycle failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read running for threat exception lifecycle failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const find = (policy) => (policy.ids?.exceptions || []).find((item) => item.name === name) || null;
    return {
      candidate: find(candidate),
      running: find(running),
    };
  }, exceptionName);
  if (state.running) {
    throw new Error(`Threat exception lifecycle mutated running policy before commit: ${JSON.stringify(state.running)}`);
  }
  if (expected.exists === false) {
    if (state.candidate) {
      throw new Error(`Threat exception lifecycle expected ${exceptionName} removed from candidate: ${JSON.stringify(state.candidate)}`);
    }
    return;
  }
  if (!state.candidate) {
    throw new Error(`Threat exception lifecycle expected ${exceptionName} in candidate`);
  }
  if (typeof expected.disabled === "boolean" && Boolean(state.candidate.disabled) !== expected.disabled) {
    throw new Error(`Threat exception lifecycle disabled state mismatch: ${JSON.stringify(state.candidate)}`);
  }
  if (expected.reasonIncludes && !String(state.candidate.description || "").includes(expected.reasonIncludes)) {
    throw new Error(`Threat exception lifecycle reason mismatch: ${JSON.stringify(state.candidate)}`);
  }
}

async function collectThreatExceptionWorkbench(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-threat-exception-workbench='true']");
    const rect = root?.getBoundingClientRect?.();
    const table = root?.querySelector(".threat-exception-table");
    const firstRow = table?.querySelector("tbody tr");
    const firstRowCells = [...(firstRow?.querySelectorAll("td") || [])];
    const rows = [...(root?.querySelectorAll("[data-threat-exception-row]") || [])].map((row) => ({
      name: row.dataset.threatExceptionRow || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      actions: [...row.querySelectorAll("[data-threat-exception-action]")].map((button) => ({
        action: button.dataset.threatExceptionAction || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      })),
    }));
    return {
      visible: Boolean(root),
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      rows,
      table: {
        tableClass: table?.className || "",
        labels: firstRowCells.map((cell) => cell.getAttribute("data-label") || ""),
        overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
        mobileLabelsRendered: window.innerWidth > 820 || firstRowCells
          .filter((cell) => cell.getAttribute("data-label") !== "Actions")
          .every((cell) => {
          const before = getComputedStyle(cell, "::before").content || "";
          return before !== "none" && before !== "\"\"" && before.length > 2;
        }),
      },
      overflow: root ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(root.scrollWidth - root.clientWidth),
      ) : 0,
    };
  });
}

function assertThreatExceptionWorkbenchActions(state, viewport) {
  const invalid = state.rows.flatMap((row) => row.actions
    .filter((button) => button.type !== "button" || !button.title || !button.ariaLabel || !button.action)
    .map((button) => ({ row: row.name, ...button })));
  if (invalid.length) {
    throw new Error(`threat exception workbench action controls missing semantics at ${viewport.name}: ${JSON.stringify(invalid)}`);
  }
}

async function collectFalsePositiveDrawer(page) {
  return await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const reason = drawer?.querySelector('textarea[placeholder="Required: why this alert is safe to suppress"]');
    const stageButton = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
      .find((button) => /^Stage (source|destination|global) exception$/.test((button.textContent || "").replace(/\s+/g, " ").trim()));
    return {
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      reasonPlaceholder: reason?.getAttribute("placeholder") || "",
      stageLabel: (stageButton?.textContent || "").replace(/\s+/g, " ").trim(),
      stageDisabled: Boolean(stageButton?.disabled),
      stageType: stageButton?.getAttribute("type") || "",
      stageTitle: stageButton?.getAttribute("title") || "",
      stageAriaLabel: stageButton?.getAttribute("aria-label") || "",
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

async function collectIDSEditorState(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-ids-editor='true']");
    const rect = root?.getBoundingClientRect?.();
    const activeDatasetValue = (selector, key) => {
      const active = root?.querySelector(`${selector}.active`);
      return active?.dataset?.[key] || "";
    };
    const inputValue = (field) => root?.querySelector(`input[data-ids-field='${field}']`)?.value || "";
    const csv = (value) => String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
    const rows = [...(root?.querySelectorAll("[data-ids-exception-row]") || [])].map((row) => ({
      name: row.dataset.idsExceptionRow || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      removeActions: row.querySelectorAll("[data-ids-exception-action='remove']").length,
    }));
    const enabled = root?.querySelector("input[data-ids-field='enabled']");
    const isEnabled = Boolean(enabled?.checked);
    const rawMode = activeDatasetValue("[data-ids-mode]", "idsMode");
    const rawFailureBehavior = activeDatasetValue("[data-ids-failure-behavior]", "idsFailureBehavior");
    const mode = isEnabled ? rawMode : "";
    const failureBehavior = isEnabled && rawMode === "prevent" ? rawFailureBehavior : "";
    const queueValue = inputValue("queue-num");
    return {
      visible: Boolean(root),
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      actions: [...(document.querySelectorAll("#drawer:not([hidden]) [data-ids-action]") || [])].map((button) => button.dataset.idsAction || ""),
      profile: {
        enabled: isEnabled,
        mode: mode === "prevent" ? "IDS_MODE_PREVENT" : mode === "detect" ? "IDS_MODE_DETECT" : "",
        monitorInterfaces: csv(inputValue("monitor-interfaces")),
        homeNetworks: csv(inputValue("home-networks")),
        ruleFiles: csv(inputValue("rule-files")),
        queueNum: isEnabled && rawMode === "prevent" && queueValue !== "" ? Number(queueValue) : undefined,
        failureBehavior: failureBehavior === "fail-closed"
          ? "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
          : failureBehavior === "fail-open"
            ? "IDS_FAILURE_BEHAVIOR_FAIL_OPEN"
            : "",
      },
      exceptions: rows,
      overflow: root ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(root.scrollWidth - root.clientWidth),
      ) : 0,
    };
  });
}

async function assertIntelContentLifecycleWorkbench(page, viewport) {
  setSmokeStage(`${viewport.name} intel content review drawer`);
  await openIntelContentDrawer(page, "app-id", "review");
  let state = await collectIntelContentDrawer(page);
  assertIntelLifecycleDrawer(state, viewport, "review", [
    "App-ID",
    "rollout review",
    "signature",
    "hash",
    "regression",
    "rollout",
    "Rollback",
    "Production evidence",
  ], ["API / CLI", "Copy handoff", "Export JSON", "Done"]);
  await assertIntelLifecycleExport(page, viewport);
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/intel", ["surface", "drawer"]);

  setSmokeStage(`${viewport.name} intel content quality drawer`);
  await openIntelContentDrawer(page, "app-id", "quality");
  state = await collectIntelContentDrawer(page);
  assertIntelLifecycleDrawer(state, viewport, "quality", [
    "App-ID",
    "quality gates",
    "Evidence inventory",
    "App Regression Corpus attached",
    "Gate score",
    "Required evidence",
    "Package gate",
    "Required evidence",
    "Production evidence",
  ], ["API / CLI", "Pin to case", "Copy handoff", "Export JSON", "Done"]);
  if (!state.evidenceInventory || state.evidenceInventory.attached < 1 || state.evidenceInventory.required < 6) {
    throw new Error(`intel quality drawer did not expose required evidence inventory at ${viewport.name}: ${JSON.stringify(state.evidenceInventory)}`);
  }
  await assertIntelLifecycleAutomationContext(page, viewport, "app-id quality API/CLI context", [
    "#/intel?surface=app-id&drawer=quality",
    "Current Intel drawer: quality",
    "/v1/intel/content/packages/app-id/evidence/app-regression-corpus",
    "/v1/intel/content/packages/app-id/corpus?evidence_type=app-regression-corpus&limit=100",
    "/v1/intel/content/packages/app-id/compare",
    "ngfwctl intel content corpus app-id --evidence-type app-regression-corpus --limit 100",
    "ngfwctl intel content compare app-id --source app-id --evidence-type app-regression-corpus",
    "Compare preview is non-mutating",
  ], [
    "#/intel?surface=app-id&drawer=quality",
    "Current Intel drawer: quality",
    "GET /v1/intel/content/packages/app-id/evidence/app-regression-corpus",
    "GET /v1/intel/content/packages/app-id/corpus?evidence_type=app-regression-corpus&limit=100",
    "POST /v1/intel/content/packages/app-id/compare",
    "ngfwctl intel content corpus app-id --evidence-type app-regression-corpus --limit 100",
    "ngfwctl intel content compare app-id --source app-id --evidence-type app-regression-corpus",
    "Compare preview is non-mutating",
  ]);
  setSmokeStage(`${viewport.name} intel content evidence artifact`);
  await openIntelContentDrawer(page, "app-id", "quality");
  await openIntelEvidenceArtifact(page, "app-regression-corpus");
  const evidenceState = await collectIntelEvidenceArtifact(page);
  if (evidenceState.overflow > 2) {
    throw new Error(`intel evidence artifact drawer overflow at ${viewport.name}: ${evidenceState.overflow}px`);
  }
  for (const required of ["Evidence artifact summary", "App Regression Corpus", "Sample count", "corp-admin", "sha256:"]) {
    if (!evidenceState.text.includes(required)) {
      throw new Error(`intel evidence artifact drawer missing "${required}" at ${viewport.name}: ${evidenceState.text}`);
    }
  }
  assertIntelContentSampleTable(evidenceState, viewport, "evidence artifact", ["Expected", "Observed", "PCAP hash", "Verdict"], "content-evidence-samples", "corp-admin");
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
  setSmokeStage(`${viewport.name} intel content corpus browser`);
  await openIntelContentDrawer(page, "app-id", "quality");
  await openIntelCorpusBrowser(page, "app-regression-corpus");
  const corpusState = await collectIntelCorpusBrowser(page);
  if (corpusState.overflow > 2) {
    throw new Error(`intel corpus browser overflow at ${viewport.name}: ${corpusState.overflow}px`);
  }
  for (const required of ["Persisted regression corpus", "corp-admin-login", "corp-admin-api", "Sample", "Expected", "Observed", "Failed samples"]) {
    if (!corpusState.text.includes(required)) {
      throw new Error(`intel corpus browser missing "${required}" at ${viewport.name}: ${corpusState.text}`);
    }
  }
  if (corpusState.rows.length < 2 || corpusState.failedSamples !== "0") {
    throw new Error(`intel corpus browser did not expose expected sample rows at ${viewport.name}: ${JSON.stringify(corpusState)}`);
  }
  assertIntelContentSampleTable(corpusState, viewport, "corpus browser", ["Sample", "Expected", "Observed", "PCAP hash", "Verdict"], "content-corpus-samples", "corp-admin-login");
  await page.fill('#drawer:not([hidden]) [data-intel-corpus-filter="query"]', "api");
  const filteredCorpusState = await collectIntelCorpusBrowser(page);
  if (filteredCorpusState.rows.length !== 1 || !filteredCorpusState.rows[0].includes("corp-admin-api") || filteredCorpusState.rows[0].includes("corp-admin-login")) {
    throw new Error(`intel corpus browser search filter failed at ${viewport.name}: ${JSON.stringify(filteredCorpusState.rows)}`);
  }
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
  await openIntelContentDrawer(page, "app-id", "quality");
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/intel", ["surface", "drawer"]);

  setSmokeStage(`${viewport.name} intel content install drawer`);
  await openIntelContentDrawer(page, "app-id", "install");
  state = await collectIntelContentDrawer(page);
  assertIntelLifecycleDrawer(state, viewport, "install", [
    "Install App-ID",
    "server-local",
    "source",
    "audited",
    "not a browser upload",
    "candidate source verification",
  ], ["API / CLI", "Copy handoff", "Export JSON", "Cancel", "Install"]);
  if (!state.installInput || state.installInput.value) {
    throw new Error(`intel install drawer source input was not empty at ${viewport.name}: ${JSON.stringify(state.installInput)}`);
  }
  if (!/content-import\/app-id/.test(state.installInput.placeholder || "")) {
    throw new Error(`intel install drawer placeholder did not point at content import root: ${state.installInput.placeholder || "<missing>"}`);
  }
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/intel", ["surface", "drawer"]);

  setSmokeStage(`${viewport.name} intel content rollback drawer`);
  await openIntelContentDrawer(page, "threat-id", "rollback");
  state = await collectIntelContentDrawer(page);
  assertIntelLifecycleDrawer(state, viewport, "rollback", [
    "Rollback Threat-ID",
    "Acknowledgement",
    "latest verified backup",
    "audits the content lifecycle action",
  ], ["API / CLI", "Copy handoff", "Export JSON", "Cancel", "Rollback"]);
  const rollbackButton = state.buttons.find((button) => button.text === "Rollback");
  if (!rollbackButton || !rollbackButton.disabled) {
    throw new Error(`intel rollback destructive action was enabled before acknowledgement at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
  }
  if (state.text.includes("Rollback unavailable") && state.rollbackAck && !state.rollbackAck.disabled) {
    throw new Error(`intel rollback acknowledgement was enabled without a verified backup at ${viewport.name}`);
  }
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/intel", ["surface", "drawer"]);
}

async function assertIntelFeedGovernanceCandidateWorkflow(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const feedName = `visual-feed-${marker}`;
  const feedUrl = `https://feeds.example.test/${marker}.txt`;
  const editedFeedUrl = `https://feeds.example.test/${marker}-edited.txt`;
  const refreshInterval = marker === "mobile" ? 35 : marker === "tablet" ? 45 : 55;
  const seed = await intelFeedGovernanceState(page);
  const builtInFeed = seed.feeds.find((feed) => !feed.custom && feed.allowsCommercialUse !== false) || seed.feeds.find((feed) => !feed.custom);
  if (!builtInFeed) {
    throw new Error(`intel feed governance smoke could not find a built-in feed at ${viewport.name}`);
  }
  try {
    await page.evaluate(() => {
      location.hash = "#/intel";
    });
    await waitForRouteReady(page, "/intel");
    setSmokeStage(`${viewport.name} intel feed governance loaded`);
    await page.waitForSelector('[data-intel-field="commercial-use"]', { state: "attached", timeout: 10000 });

    setSmokeStage(`${viewport.name} intel feed governance commercial-use`);
    await page.evaluate(() => {
      const input = document.querySelector('[data-intel-field="commercial-use"]');
      if (!input) throw new Error("intel commercial-use switch was not found");
      if (!input.checked) {
        input.checked = true;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    await waitForIntelFeedGovernanceState(page, "commercial use", (state) => (
      state.candidate.commercialUse === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    await page.fill('[data-intel-field="refresh-interval"]', String(refreshInterval));
    await page.click('[data-intel-action="stage-refresh-interval"]');
    await waitForIntelFeedGovernanceState(page, "refresh interval", (state) => (
      state.candidate.refreshIntervalMinutes === refreshInterval &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    setSmokeStage(`${viewport.name} intel feed governance custom feed`);
    await page.click('[data-intel-action="add-custom-feed"]');
    await waitForDrawerTitleStep(page, "Add custom feed", "intel add custom feed drawer");
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="name"]', feedName);
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="url"]', "http://169.254.169.254/opc/v2/instance/");
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="description"]', `Visual smoke ${marker} rejected feed`);
    await page.click('#drawer:not([hidden]) [data-intel-action="save-custom-feed"]');
    await page.waitForFunction(() => (
      Boolean(document.querySelector("#drawer:not([hidden]) [data-intel-custom-field='url']")) &&
      (document.body.textContent || "").includes("URL must not target loopback, private, link-local, local, or metadata destinations")
    ), null, { timeout: 5000 });
    await waitForIntelFeedGovernanceState(page, "custom feed unsafe URL rejected", (state) => (
      !state.candidate.customFeeds.some((feed) => feed.name === feedName) &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="name"]', feedName);
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="url"]', feedUrl);
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="description"]', `Visual smoke ${marker} candidate feed`);
    await page.click('#drawer:not([hidden]) [data-intel-action="save-custom-feed"]');
    await waitForDrawerClosed(page);
    await waitForIntelFeedGovernanceState(page, "custom feed add", (state) => (
      Boolean(state.candidate.customFeeds.find((feed) => feed.name === feedName && feed.url === feedUrl)) &&
      !state.runningText.includes(feedName) &&
      state.status.dirty === true &&
      state.status.intelChanged === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    const tableState = await collectIntelFeedTableState(page, feedName, builtInFeed.name);
    assertIntelFeedTables(tableState, viewport, feedName, builtInFeed.name);

    await page.click(`[data-intel-custom-feed="${feedName}"] [data-intel-action="edit-custom-feed"]`);
    await waitForDrawerTitleStep(page, "Edit custom feed", "intel edit custom feed drawer");
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="url"]', editedFeedUrl);
    await page.fill('#drawer:not([hidden]) [data-intel-custom-field="description"]', `Visual smoke ${marker} edited candidate feed`);
    await page.click('#drawer:not([hidden]) [data-intel-action="save-custom-feed"]');
    await waitForDrawerClosed(page);
    await waitForIntelFeedGovernanceState(page, "custom feed edit", (state) => (
      Boolean(state.candidate.customFeeds.find((feed) => feed.name === feedName && feed.url === editedFeedUrl && /edited/.test(feed.description || ""))) &&
      !state.runningText.includes(editedFeedUrl) &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    await page.evaluate((feedName) => {
      const button = document.querySelector(`[data-intel-custom-feed="${feedName}"] [data-intel-action="delete-custom-feed"]`);
      if (!button) throw new Error(`intel custom feed delete action was not found for ${feedName}`);
      button.click();
    }, feedName);
    await waitForDrawerTitleStep(page, "Delete custom feed?", "intel delete custom feed confirmation");
    await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const button = [...(drawer?.querySelectorAll("button") || [])]
        .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Delete");
      if (!button) throw new Error("intel delete confirmation button was not found");
      button.click();
    });
    await waitForIntelFeedGovernanceState(page, "custom feed delete", (state) => (
      !state.candidate.customFeeds.some((feed) => feed.name === feedName) &&
      !state.runningText.includes(feedName) &&
      state.status.intelChanged === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    await page.keyboard.press("Escape");

    await page.evaluate((feedName) => {
      const input = document.querySelector(`[data-intel-feed-row="${feedName}"] [data-intel-feed-toggle="${feedName}"]`);
      if (!input) throw new Error(`intel built-in feed toggle was not found for ${feedName}`);
      if (input.disabled) throw new Error(`intel built-in feed toggle was disabled for ${feedName}`);
      input.checked = !input.checked;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }, builtInFeed.name);
    await waitForIntelFeedGovernanceState(page, "built-in feed toggle", (state) => {
      const staged = state.candidate.feeds.find((feed) => feed.name === builtInFeed.name);
      return Boolean(staged) &&
        staged.enabled === !builtInFeed.effectiveEnabled &&
        state.status.intelChanged === true &&
        state.runningFingerprint === seed.runningFingerprint;
    });

    setSmokeStage(`${viewport.name} intel feed governance changes review`);
    await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
    await waitForRouteReady(page, "/changes");
    await page.waitForFunction(() => {
      const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("Current candidate") &&
        text.includes("Threat intel changed") &&
        text.includes("Feed or content settings changed");
    }, null, { timeout: 10000 });
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => {
      location.hash = "#/intel";
    });
    await waitForRouteReady(page, "/intel");
  }
}

async function waitForIntelFeedGovernanceState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await intelFeedGovernanceState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`intel feed governance ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function intelFeedGovernanceState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse, feedsResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
      fetch("/v1/intel/feeds"),
    ]);
    if (!runningResponse.ok) throw new Error(`read intel running failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    const runningPolicy = (await runningResponse.json())?.policy || {};
    const candidatePolicy = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : runningPolicy;
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const feedBody = feedsResponse.ok ? await feedsResponse.json() : {};
    const intel = candidatePolicy.intel || {};
    const runningText = JSON.stringify(runningPolicy);
    const changes = Array.isArray(status.changes) ? status.changes : [];
    const intelChange = changes.find((change) => change?.section === "intel") || null;
    const stagedFeeds = new Map((intel.feeds || []).map((feed) => [feed.name, feed]));
    const feeds = (feedBody.feeds || []).map((feed) => ({
      ...feed,
      effectiveEnabled: stagedFeeds.has(feed.name) ? stagedFeeds.get(feed.name).enabled : feed.enabled,
    }));
    return {
      candidate: {
        commercialUse: Boolean(intel.commercialUse),
        refreshIntervalMinutes: intel.refreshIntervalMinutes,
        customFeeds: Array.isArray(intel.customFeeds) ? intel.customFeeds : [],
        feeds: Array.isArray(intel.feeds) ? intel.feeds : [],
      },
      feeds,
      runningText,
      runningFingerprint: stable(runningPolicy),
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        intelChanged: Boolean(intelChange && Number(intelChange.added || 0) + Number(intelChange.modified || 0) + Number(intelChange.removed || 0) > 0),
        changes,
      },
    };
  });
}

async function collectIntelFeedTableState(page, customFeedName, builtInFeedName) {
  return await page.evaluate(({ customFeedName, builtInFeedName }) => {
    const labelsFor = (row) => [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
    const mobileLabelsRendered = (row) => window.innerWidth > 820 || [...(row?.querySelectorAll("td") || [])].every((cell) => {
      if (cell.getAttribute("data-label") === "Actions") return true;
      const before = getComputedStyle(cell, "::before").content || "";
      return before !== "none" && before !== "\"\"" && before.length > 2;
    });
    const customTable = document.querySelector(".intel-custom-feed-table");
    const customRow = document.querySelector(`[data-intel-custom-feed="${customFeedName}"]`);
    const customActionCell = customRow?.querySelector('td.cell-actions[data-label="Actions"]');
    const registryWrap = document.querySelector(".intel-feed-registry-wrap");
    const registryTable = document.querySelector(".intel-feed-registry-table");
    const registryRow = document.querySelector(`[data-intel-feed-row="${builtInFeedName}"]`);
    const registryToggle = registryRow?.querySelector(`[data-intel-feed-toggle="${builtInFeedName}"]`);
    return {
      customTableClass: customTable?.className || "",
      customLabels: labelsFor(customRow),
      customRowKey: customRow?.getAttribute("data-intel-custom-feed") || "",
      customActions: [...(customActionCell?.querySelectorAll("[data-intel-action]") || [])].map((button) => button.getAttribute("data-intel-action")),
      customMobileLabelsRendered: mobileLabelsRendered(customRow),
      registryWrapClass: registryWrap?.className || "",
      registryTableClass: registryTable?.className || "",
      registryLabels: labelsFor(registryRow),
      registryRowKey: registryRow?.getAttribute("data-intel-feed-row") || "",
      registryToggle: registryToggle?.getAttribute("data-intel-feed-toggle") || "",
      registryMobileLabelsRendered: mobileLabelsRendered(registryRow),
    };
  }, { customFeedName, builtInFeedName });
}

function assertIntelFeedTables(state, viewport, customFeedName, builtInFeedName) {
  if (!state.customTableClass.includes("responsive-evidence") || !state.customTableClass.includes("intel-custom-feed-table")) {
    throw new Error(`intel custom feed table missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.registryWrapClass.includes("intel-feed-registry-wrap") || !state.registryTableClass.includes("responsive-evidence") || !state.registryTableClass.includes("intel-feed-registry-table")) {
    throw new Error(`intel feed registry table missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingCustom = ["Name", "URL", "Description", "Actions"].filter((label) => !state.customLabels.includes(label));
  const missingRegistry = ["On", "Feed", "License", "Commercial", "Kind", "Status"].filter((label) => !state.registryLabels.includes(label));
  if (missingCustom.length || missingRegistry.length) {
    throw new Error(`intel feed tables missing labels at ${viewport.name}: ${JSON.stringify({ missingCustom, missingRegistry, state })}`);
  }
  if (state.customRowKey !== customFeedName || state.registryRowKey !== builtInFeedName || state.registryToggle !== builtInFeedName) {
    throw new Error(`intel feed table row hooks mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const action of ["edit-custom-feed", "delete-custom-feed"]) {
    if (!state.customActions.includes(action)) {
      throw new Error(`intel custom feed table missing ${action} action at ${viewport.name}: ${JSON.stringify(state)}`);
    }
  }
  if (!state.customMobileLabelsRendered || !state.registryMobileLabelsRendered) {
    throw new Error(`intel feed table mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function openIntelContentDrawer(page, surface, drawer) {
  await page.evaluate(({ surface, drawer }) => {
    location.hash = `#/intel?surface=${encodeURIComponent(surface)}&drawer=${encodeURIComponent(drawer)}`;
  }, { surface, drawer });
  await waitForRouteReady(page, "/intel");
  await page.waitForFunction(({ surface, drawer }) => {
    const root = document.querySelector(`[data-intel-content-drawer="${drawer}"][data-intel-content-surface="${surface}"]`);
    const containingDrawer = root?.closest?.("#drawer:not([hidden])");
    return Boolean(root && containingDrawer);
  }, { surface, drawer }, { timeout: 10000 });
  await page.waitForTimeout(120);
}

async function assertIntelLifecycleAutomationContext(page, viewport, label, requiredText = [], copiedRequiredText = requiredText) {
  await page.evaluate(() => {
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  await page.click('#drawer:not([hidden]) [data-intel-content-action="api-cli"]');
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, label, [
    "API / CLI context",
    "Current view",
    "REST endpoints",
    "CLI equivalents",
    "Copy session JSON",
    "Copy context",
    ...requiredText,
  ], ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `${label} drawer`);
  await assertAutomationContextActionButtons(page, viewport, label);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `${label} workflow session JSON`);
  let sessionPacket = null;
  try {
    sessionPacket = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`${label} workflow session JSON was not parseable: ${err.message}`);
  }
  if (sessionPacket.routeState?.hash !== "#/intel?surface=app-id&drawer=quality") {
    throw new Error(`${label} workflow session route mismatch: ${JSON.stringify(sessionPacket.routeState)}`);
  }
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  for (const required of copiedRequiredText) {
    if (!copied.includes(required)) {
      throw new Error(`${label} copied context missing ${required}`);
    }
  }
  assertAutomationContextRedaction(copied, `${label} copied context`);
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
  await waitForRouteReady(page, "/intel");
}

async function collectIntelContentDrawer(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-intel-content-drawer]");
    const drawer = root?.closest("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const buttons = [...(drawer?.querySelectorAll("button") || [])].map((button) => {
      const b = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.getAttribute("data-netvpn-action") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        width: b.width,
        height: b.height,
        disabled: button.disabled,
      };
    });
    const installInput = drawer?.querySelector("[data-intel-install-source]");
    const rollbackAck = drawer?.querySelector("[data-intel-rollback-ack]");
    const inventory = drawer?.querySelector("[data-content-quality-inventory]");
    return {
      hash: location.hash || "",
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      drawer: root?.getAttribute("data-intel-content-drawer") || "",
      surface: root?.getAttribute("data-intel-content-surface") || "",
      buttons,
      evidenceInventory: inventory ? {
        surface: inventory.getAttribute("data-content-quality-inventory") || "",
        required: inventory.querySelectorAll("[data-content-quality-evidence]").length,
        attached: inventory.querySelectorAll(".system-evidence-row.ok[data-content-quality-evidence]").length,
        missing: inventory.querySelectorAll(".system-evidence-row.bad[data-content-quality-evidence]").length,
      } : null,
      installInput: installInput ? {
        value: installInput.value || "",
        placeholder: installInput.getAttribute("placeholder") || "",
      } : null,
      rollbackAck: rollbackAck ? {
        checked: rollbackAck.checked,
        disabled: rollbackAck.disabled,
      } : null,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

async function openIntelEvidenceArtifact(page, evidenceType) {
  await page.evaluate((type) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const button = drawer?.querySelector(`[data-intel-content-action="inspect-evidence"][data-evidence-type="${type}"]`);
    if (!button) throw new Error(`content evidence inspect action ${type} was not found`);
    button.click();
  }, evidenceType);
  await page.waitForSelector("#drawer:not([hidden]) .content-evidence-packet", { timeout: 10000 });
  await page.waitForFunction(() => {
    const text = document.querySelector("#drawer:not([hidden]) .content-evidence-packet")?.textContent || "";
    return text.includes("Package-local JSON evidence") && text.includes("Evidence artifact summary");
  }, null, { timeout: 10000 });
}

async function collectIntelEvidenceArtifact(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("#drawer:not([hidden]) .content-evidence-packet");
    const drawer = root?.closest("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const table = root?.querySelector(".content-evidence-samples");
    const row = table?.querySelector("[data-intel-evidence-sample]");
    return {
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      tableClass: table?.className || "",
      labels: [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || ""),
      sampleKey: row?.getAttribute("data-intel-evidence-sample") || "",
      mobileLabelsRendered: window.innerWidth <= 820
        ? [...(row?.querySelectorAll("td") || [])].every((cell) => {
            const before = getComputedStyle(cell, "::before").content || "";
            return before !== "none" && before !== "\"\"" && before.length > 2;
          })
        : true,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

async function openIntelCorpusBrowser(page, evidenceType) {
  await page.evaluate((type) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const button = drawer?.querySelector(`[data-intel-content-action="browse-corpus"][data-evidence-type="${type}"]`);
    if (!button) throw new Error(`content corpus browse action ${type} was not found`);
    button.click();
  }, evidenceType);
  await page.waitForSelector("#drawer:not([hidden]) .content-corpus-browser", { timeout: 10000 });
  await page.waitForFunction(() => {
    const text = document.querySelector("#drawer:not([hidden]) .content-corpus-browser")?.textContent || "";
    return text.includes("Persisted regression corpus") && text.includes("corp-admin-login");
  }, null, { timeout: 10000 });
}

async function collectIntelCorpusBrowser(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("#drawer:not([hidden]) .content-corpus-browser");
    const drawer = root?.closest("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const metrics = [...(root?.querySelectorAll(".posture-metric") || [])].map((node) => ({
      label: node.querySelector("span")?.textContent?.trim() || "",
      value: node.querySelector("strong")?.textContent?.trim() || "",
    }));
    const table = root?.querySelector(".content-corpus-samples");
    const row = table?.querySelector("[data-intel-corpus-sample]");
    return {
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      tableClass: table?.className || "",
      labels: [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || ""),
      sampleKey: row?.getAttribute("data-intel-corpus-sample") || "",
      rows: [...(root?.querySelectorAll(".content-corpus-samples tbody tr") || [])].map((row) => (row.textContent || "").replace(/\s+/g, " ").trim()),
      failedSamples: metrics.find((item) => item.label === "Failed samples")?.value || "",
      mobileLabelsRendered: window.innerWidth <= 820
        ? [...(row?.querySelectorAll("td") || [])].every((cell) => {
            const before = getComputedStyle(cell, "::before").content || "";
            return before !== "none" && before !== "\"\"" && before.length > 2;
          })
        : true,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

function assertIntelContentSampleTable(state, viewport, label, expectedLabels, expectedClass, expectedKey) {
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes(expectedClass)) {
    throw new Error(`intel ${label} table missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = expectedLabels.filter((item) => !state.labels.includes(item));
  if (missingLabels.length) {
    throw new Error(`intel ${label} table missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (!state.sampleKey.includes(expectedKey)) {
    throw new Error(`intel ${label} row hook mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`intel ${label} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

function assertIntelLifecycleDrawer(state, viewport, label, requiredText, requiredButtons) {
  if (state.overflow > 2) {
    throw new Error(`intel ${label} drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const body = `${state.title} ${state.text}`.toLowerCase();
  const missingText = requiredText.filter((needle) => !body.includes(String(needle).toLowerCase()));
  if (missingText.length) {
    throw new Error(`intel ${label} drawer missing text: ${missingText.join(", ")}`);
  }
  const missingButtons = requiredButtons.filter((needle) => !state.buttons.some((button) => button.text === needle));
  if (missingButtons.length) {
    throw new Error(`intel ${label} drawer missing action(s): ${missingButtons.join(", ")}`);
  }
  const leaked = [
    /\/var\/lib\/[^\s"',;}]+/i,
    /\/tmp\/[^\s"',;}]+/i,
    /\/Users\/[^\s"',;}]+/i,
    /\b(?:sourcePath|manifestPath|rollbackPath|restoredRollbackPath)\b\s*[:=]/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /writer:secret/i,
  ].find((pattern) => pattern.test(state.text));
  if (leaked) {
    throw new Error(`intel ${label} drawer leaked sensitive material at ${viewport.name}: ${leaked}`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => !button.disabled && button.text && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`intel ${label} mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
}

async function assertIntelLifecycleExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const button = [...(drawer?.querySelectorAll("button") || [])]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Export JSON");
    if (!button) throw new Error("intel lifecycle export button was not found");
    button.click();
  });
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^phragma-investigation-content-package-lifecycle-app-id-.+\.json$/.test(filename)) {
    throw new Error(`intel lifecycle export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`intel lifecycle export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  const leaked = [
    /\/var\/lib\/[^\s"',;}]+/i,
    /\/tmp\/[^\s"',;}]+/i,
    /\/Users\/[^\s"',;}]+/i,
    /\b(?:sourcePath|manifestPath|rollbackPath|restoredRollbackPath)\b\s*[:=]/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /writer:secret/i,
  ].find((pattern) => pattern.test(text));
  if (leaked) {
    throw new Error(`intel lifecycle export leaked sensitive material at ${viewport.name}: ${leaked}`);
  }
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`intel lifecycle export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.kind !== "content-package-lifecycle" || packet?.subject?.id !== "app-id") {
    throw new Error(`intel lifecycle export had unexpected packet identity at ${viewport.name}: ${JSON.stringify({ kind: packet?.kind, subject: packet?.subject })}`);
  }
}

async function assertReadinessEngineTable(page, viewport) {
  const state = await page.evaluate(() => {
    const table = document.querySelector(".readiness-engine-table");
    const rows = [...(table?.querySelectorAll("[data-readiness-engine-row]") || [])].map((row) => ({
      id: row.dataset.readinessEngineRow || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      labels: [...row.querySelectorAll("td[data-label]")].map((cell) => cell.getAttribute("data-label") || ""),
      rect: (() => {
        const rect = row.getBoundingClientRect();
        return { width: rect.width, height: rect.height };
      })(),
    }));
    const headers = [...(table?.querySelectorAll("thead th") || [])].map((cell) => (cell.textContent || "").trim());
    const pseudoLabels = [...(table?.querySelectorAll("tbody td[data-label]") || [])].slice(0, 5).map((cell) => getComputedStyle(cell, "::before").content || "");
    const rect = table?.getBoundingClientRect?.();
    return {
      visible: Boolean(table && rect && rect.width > 0 && rect.height > 0 && getComputedStyle(table).display !== "none"),
      className: table?.className || "",
      headers,
      rows,
      pseudoLabels,
      overflow: table ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
    };
  });
  if (!state.visible) {
    throw new Error(`readiness engine table was not visible at ${viewport.name}`);
  }
  if (!state.className.includes("responsive-evidence")) {
    throw new Error(`readiness engine table did not use responsive-evidence at ${viewport.name}: ${state.className}`);
  }
  const expectedHeaders = ["Engine", "State", "Mode", "Role", "Detail"];
  const missingHeaders = expectedHeaders.filter((label) => !state.headers.includes(label));
  if (missingHeaders.length) {
    throw new Error(`readiness engine table missing header(s) at ${viewport.name}: ${missingHeaders.join(", ")}`);
  }
  if (!state.rows.length) {
    throw new Error(`readiness engine table did not render any engine rows at ${viewport.name}`);
  }
  const badRows = state.rows.filter((row) => expectedHeaders.some((label) => !row.labels.includes(label)));
  if (badRows.length) {
    throw new Error(`readiness engine row(s) missing responsive labels at ${viewport.name}: ${JSON.stringify(badRows.slice(0, 2))}`);
  }
  if (state.overflow > 2) {
    throw new Error(`readiness engine table overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (viewport.name === "mobile") {
    if (!state.pseudoLabels.some((label) => label.includes("Engine")) || !state.pseudoLabels.some((label) => label.includes("State"))) {
      throw new Error(`readiness engine table mobile labels were not visible at ${viewport.name}: ${JSON.stringify(state.pseudoLabels)}`);
    }
    const cramped = state.rows.filter((row) => row.rect.width < 280 || row.rect.height < 44);
    if (cramped.length) {
      throw new Error(`readiness engine table mobile rows too small at ${viewport.name}: ${JSON.stringify(cramped)}`);
    }
  }
}

async function assertReadinessEbpfTables(page, viewport) {
  const state = await page.evaluate(() => {
    const probeTable = document.querySelector(".readiness-ebpf-probe-table");
    const probeWrap = document.querySelector("[data-readiness-ebpf-table='probes']");
    const attachmentTable = document.querySelector(".readiness-ebpf-attachment-table");
    const attachmentWrap = document.querySelector("[data-readiness-ebpf-table='attachments']");
    const artifactTable = document.querySelector(".readiness-ebpf-artifact-table");
    const artifactWrap = document.querySelector("[data-readiness-ebpf-table='artifacts']");
    const actions = [...document.querySelectorAll("[data-readiness-ebpf-evidence-action]")].map((el) => ({
      action: el.dataset.readinessEbpfEvidenceAction || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const rows = [...(probeTable?.querySelectorAll("[data-readiness-ebpf-probe]") || [])].map((row) => ({
      probe: row.dataset.readinessEbpfProbe || "",
      scope: row.dataset.readinessEbpfScope || "",
      labels: [...row.querySelectorAll("td[data-label]")].map((cell) => cell.getAttribute("data-label") || ""),
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      rect: (() => {
        const rect = row.getBoundingClientRect();
        return { width: rect.width, height: rect.height };
      })(),
    }));
    const headers = [...(probeTable?.querySelectorAll("thead th") || [])].map((cell) => (cell.textContent || "").trim());
    const attachmentRows = [...(attachmentTable?.querySelectorAll("[data-readiness-ebpf-attachment]") || [])].map((row) => ({
      key: row.dataset.readinessEbpfAttachment || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      labels: [...row.querySelectorAll("td[data-label]")].map((cell) => cell.getAttribute("data-label") || ""),
    }));
    const artifactRows = [...(artifactTable?.querySelectorAll("[data-readiness-ebpf-artifact]") || [])].map((row) => ({
      key: row.dataset.readinessEbpfArtifact || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
      labels: [...row.querySelectorAll("td[data-label]")].map((cell) => cell.getAttribute("data-label") || ""),
    }));
    const pseudoLabels = [...(probeTable?.querySelectorAll("tbody td[data-label]") || [])].slice(0, 5).map((cell) => getComputedStyle(cell, "::before").content || "");
    const rect = probeWrap?.getBoundingClientRect?.();
    return {
      visible: Boolean(probeTable && probeWrap && rect && rect.width > 0 && rect.height > 0 && getComputedStyle(probeTable).display !== "none"),
      className: probeTable?.className || "",
      wrapClass: probeWrap?.className || "",
      headers,
      rows,
      pseudoLabels,
      hasAttachmentTable: Boolean(attachmentTable),
      hasArtifactTable: Boolean(artifactTable),
      attachmentClassName: attachmentTable?.className || "",
      artifactClassName: artifactTable?.className || "",
      attachmentRows,
      artifactRows,
      actions,
      overflow: Math.max(
        0,
        probeWrap && rect ? Math.ceil(rect.right - window.innerWidth) : 0,
        probeWrap && rect ? Math.ceil(0 - rect.left) : 0,
        probeWrap ? Math.ceil(probeWrap.scrollWidth - probeWrap.clientWidth) : 0,
        attachmentWrap ? Math.ceil(attachmentWrap.scrollWidth - attachmentWrap.clientWidth) : 0,
        artifactWrap ? Math.ceil(artifactWrap.scrollWidth - artifactWrap.clientWidth) : 0,
      ),
    };
  });
  if (!state.visible) {
    throw new Error(`readiness eBPF probe table was not visible at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.className.includes("responsive-evidence") || !state.className.includes("readiness-ebpf-probe-table")) {
    throw new Error(`readiness eBPF probe table missing responsive classes at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const expectedHeaders = ["Scope", "Probe", "Key", "State", "Detail"];
  const missingHeaders = expectedHeaders.filter((label) => !state.headers.includes(label));
  if (missingHeaders.length) {
    throw new Error(`readiness eBPF probe table missing header(s) at ${viewport.name}: ${missingHeaders.join(", ")}`);
  }
  if (!state.rows.length) {
    throw new Error(`readiness eBPF probe table rendered no probe rows at ${viewport.name}`);
  }
  const badRows = state.rows.filter((row) => expectedHeaders.some((label) => !row.labels.includes(label)));
  if (badRows.length) {
    throw new Error(`readiness eBPF probe row(s) missing responsive labels at ${viewport.name}: ${JSON.stringify(badRows.slice(0, 2))}`);
  }
  const unexpectedScopes = state.rows.filter((row) => row.scope && !["host", "attach"].includes(row.scope));
  if (unexpectedScopes.length) {
    throw new Error(`readiness eBPF probe table rendered unexpected scope(s) at ${viewport.name}: ${JSON.stringify(unexpectedScopes)}`);
  }
  for (const action of ["drill-handoff", "field-evidence", "copy-drill"]) {
    if (!state.actions.some((item) => item.action === action)) {
      throw new Error(`readiness eBPF action ${action} was missing at ${viewport.name}: ${JSON.stringify(state.actions)}`);
    }
  }
  if (state.overflow > 2) {
    throw new Error(`readiness eBPF probe table overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (requireEbpfRuntimeEvidence) {
    if (!state.hasAttachmentTable || state.attachmentRows.length < 2) {
      throw new Error(`readiness eBPF runtime attachment table missing seeded rows at ${viewport.name}: ${JSON.stringify(state)}`);
    }
    if (!state.attachmentClassName.includes("responsive-evidence") || !state.attachmentClassName.includes("readiness-ebpf-attachment-table")) {
      throw new Error(`readiness eBPF runtime attachment table missing responsive classes at ${viewport.name}: ${JSON.stringify(state)}`);
    }
    const expectedAttachmentLabels = ["Interface / hook", "Program", "State", "Detail"];
    const badAttachmentRows = state.attachmentRows.filter((row) => expectedAttachmentLabels.some((label) => !row.labels.includes(label)));
    if (badAttachmentRows.length) {
      throw new Error(`readiness eBPF runtime attachment row(s) missing responsive labels at ${viewport.name}: ${JSON.stringify(badAttachmentRows.slice(0, 2))}`);
    }
    if (!state.attachmentRows.some((row) => /openngfw-ebpf0.*xdp.*xdp_probe/i.test(row.text)) ||
        !state.attachmentRows.some((row) => /openngfw-ebpf0.*tc.*tc_ingress/i.test(row.text))) {
      throw new Error(`readiness eBPF runtime attachment rows missed seeded XDP/tc evidence at ${viewport.name}: ${JSON.stringify(state.attachmentRows)}`);
    }
    if (!state.hasArtifactTable || state.artifactRows.length < 2) {
      throw new Error(`readiness eBPF artifact table missing seeded rows at ${viewport.name}: ${JSON.stringify(state)}`);
    }
    if (!state.artifactClassName.includes("responsive-evidence") || !state.artifactClassName.includes("readiness-ebpf-artifact-table")) {
      throw new Error(`readiness eBPF artifact table missing responsive classes at ${viewport.name}: ${JSON.stringify(state)}`);
    }
    const expectedArtifactLabels = ["Artifact", "Path", "State", "Digest"];
    const badArtifactRows = state.artifactRows.filter((row) => expectedArtifactLabels.some((label) => !row.labels.includes(label)));
    if (badArtifactRows.length) {
      throw new Error(`readiness eBPF artifact row(s) missing responsive labels at ${viewport.name}: ${JSON.stringify(badArtifactRows.slice(0, 2))}`);
    }
    if (!state.artifactRows.some((row) => /manifest\.txt/i.test(row.text)) ||
        !state.artifactRows.some((row) => /ebpf-plan\.txt/i.test(row.text))) {
      throw new Error(`readiness eBPF artifact rows missed seeded manifest/plan evidence at ${viewport.name}: ${JSON.stringify(state.artifactRows)}`);
    }
    const apiState = await page.evaluate(async () => {
      const response = await fetch("/v1/system/status");
      if (!response.ok) return { ok: false, status: response.status, text: await response.text() };
      const status = await response.json();
      const dataplane = status.dataplane || {};
      const ebpf = dataplane.ebpf || {};
      const attachments = Array.isArray(ebpf.attachments) ? ebpf.attachments : [];
      const artifacts = Array.isArray(ebpf.artifacts) ? ebpf.artifacts : [];
      return {
        ok: true,
        activeDataplane: dataplane.activeDataplane || dataplane.active_dataplane || "",
        evidenceScope: ebpf.evidenceScope || ebpf.evidence_scope || "",
        attachState: ebpf.attachState || ebpf.attach_state || "",
        attachments: attachments.map((item) => ({
          interface: item.interface || item.interface_ || "",
          hook: item.hook || "",
          state: item.state || "",
          programName: item.programName || item.program_name || "",
          programId: item.programId || item.program_id || "",
        })),
        artifacts: artifacts.map((item) => ({ name: item.name || "", state: item.state || "", sha256: item.sha256 || "" })),
      };
    });
    if (!apiState.ok) {
      throw new Error(`readiness eBPF status API failed at ${viewport.name}: ${apiState.status} ${apiState.text || ""}`);
    }
    if (apiState.activeDataplane !== "nftables/conntrack" || !/runtime-probes/.test(apiState.evidenceScope || "")) {
      throw new Error(`readiness eBPF status API missed active dataplane/runtime scope at ${viewport.name}: ${JSON.stringify(apiState)}`);
    }
    if (!apiState.attachments.some((item) => item.interface === "openngfw-ebpf0" && item.hook === "xdp" && item.state === "attached" && item.programName === "xdp_probe") ||
        !apiState.attachments.some((item) => item.interface === "openngfw-ebpf0" && item.hook === "tc" && item.state === "attached" && item.programName === "tc_ingress")) {
      throw new Error(`readiness eBPF status API missed seeded runtime attachments at ${viewport.name}: ${JSON.stringify(apiState)}`);
    }
    if (!apiState.artifacts.some((item) => item.name === "manifest.txt" && item.state === "ready" && /^[a-f0-9]{64}$/i.test(item.sha256)) ||
        !apiState.artifacts.some((item) => item.name === "ebpf-plan.txt" && item.state === "ready" && /^[a-f0-9]{64}$/i.test(item.sha256))) {
      throw new Error(`readiness eBPF status API missed hashed artifacts at ${viewport.name}: ${JSON.stringify(apiState)}`);
    }
  }
  if (viewport.name === "mobile") {
    if (!state.pseudoLabels.some((label) => label.includes("Scope")) || !state.pseudoLabels.some((label) => label.includes("State"))) {
      throw new Error(`readiness eBPF table mobile labels were not visible at ${viewport.name}: ${JSON.stringify(state.pseudoLabels)}`);
    }
    const cramped = state.rows.filter((row) => row.rect.width < 280 || row.rect.height < 44);
    if (cramped.length) {
      throw new Error(`readiness eBPF table mobile rows too small at ${viewport.name}: ${JSON.stringify(cramped)}`);
    }
  }
  await page.click("[data-readiness-ebpf-evidence-action='drill-handoff']");
  const drawerState = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const report = drawer?.querySelector("[data-readiness-ebpf-drill-evidence-report='true']");
    const text = report?.value || drawer?.textContent || "";
    return {
      visible: Boolean(drawer),
      hasRoot: Boolean(drawer?.querySelector("[data-readiness-ebpf-drill-evidence='true']")),
      text,
      actions: [...(drawer?.querySelectorAll("[data-readiness-ebpf-drill-action]") || [])].map((el) => el.dataset.readinessEbpfDrillAction || ""),
    };
  });
  if (!drawerState.visible || !drawerState.hasRoot) {
    throw new Error(`readiness eBPF drill drawer did not open at ${viewport.name}: ${JSON.stringify(drawerState)}`);
  }
  for (const action of ["copy", "export", "pin"]) {
    if (!drawerState.actions.includes(action)) {
      throw new Error(`readiness eBPF drill drawer action ${action} missing at ${viewport.name}: ${JSON.stringify(drawerState.actions)}`);
    }
  }
  if (!/phragma\.ebpf\.drill-evidence\.v1/.test(drawerState.text) ||
      !/active_dataplane=nftables\/conntrack/.test(drawerState.text) ||
      !/does not certify active eBPF dataplane cutover/.test(drawerState.text)) {
    throw new Error(`readiness eBPF drill drawer missed expected evidence at ${viewport.name}: ${drawerState.text.slice(0, 400)}`);
  }
  if (/\/etc\/phragma|Authorization: Bearer|access_token|refresh_token/i.test(drawerState.text)) {
    throw new Error(`readiness eBPF drill drawer leaked sensitive-looking text at ${viewport.name}: ${drawerState.text.slice(0, 400)}`);
  }
  await closeActiveDrawer(page);
}

async function assertReadinessReleaseEvidence(page, viewport) {
  const releaseEvidence = await page.evaluate(() => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    const supportedHashRoutes = [...new Set([...document.querySelectorAll("#nav a[data-path]")]
      .map((el) => el.dataset?.path || "")
      .filter(Boolean))];
    const navLinks = [...document.querySelectorAll("#nav a[data-path]")].map((el) => ({
      path: el.dataset?.path || "",
      href: el.getAttribute("href") || "",
    }));
    const isHashAppHref = (href) => {
      try {
        const resolved = new URL(href || "", location.href);
        return (href || "").startsWith("#/") || resolved.hash.startsWith("#/");
      } catch {
        return false;
      }
    };
    const appSupportsNonHashRoutes = navLinks.some((item) => {
      if (!item.href || !item.path || isHashAppHref(item.href)) return false;
      try {
        return new URL(item.href, location.href).origin === location.origin;
      } catch {
        return false;
      }
    });
    const items = [...document.querySelectorAll(".release-evidence-item")].filter(visible).map((el) => {
      const rect = el.getBoundingClientRect();
      const link = el.matches("a[href]")
        ? el
        : el.querySelector("a[data-release-evidence-action='open-route'][href], a[href]");
      const href = link?.getAttribute("href") || "";
      let resolvedHash = "";
      let sameOrigin = false;
      try {
        const resolved = new URL(href || "", location.href);
        resolvedHash = resolved.hash || "";
        sameOrigin = resolved.origin === location.origin;
      } catch {}
      return {
        id: el.dataset.releaseEvidence || "",
        href,
        resolvedHash,
        sameOrigin,
        text: el.textContent || "",
        width: rect.width,
        height: rect.height,
      };
    });
    const headerBadge = document.querySelector(".release-evidence-card-head .phr-badge");
    return { appSupportsNonHashRoutes, items, supportedHashRoutes, headerText: headerBadge?.textContent || "" };
  });
  const evidence = releaseEvidence.items;
  const ids = new Set(evidence.map((item) => item.id));
  const externalGateIds = ["content-production-readiness", "privileged-integration", "m3-field-evidence", "ebpf-ol9-field-evidence", "m5-oidc-field-evidence"];
  const required = ["runtime", "content", ...externalGateIds, "host", "dataplane", "inspection", "performance", "support"];
  const missing = required.filter((id) => !ids.has(id));
  if (missing.length) {
    throw new Error(`release evidence strip missing item(s): ${missing.join(", ")}`);
  }
  const statusTextPattern = /blocked|review|field required|required|requires|must|missing\s*evidence|missing|todo|production content blocker|not enough|before release|do not close|cannot close|make [a-z0-9-]+-check/i;
  const missingStatusText = externalGateIds.filter((id) => {
    const item = evidence.find((candidate) => candidate.id === id);
    return !statusTextPattern.test(item?.text || "");
  });
  if (missingStatusText.length) {
    const snippets = missingStatusText.map((id) => {
      const item = evidence.find((candidate) => candidate.id === id);
      const text = (item?.text || "").replace(/\s+/g, " ").trim();
      return `${id}="${text.slice(0, 220)}${text.length > 220 ? "..." : ""}"`;
    });
    throw new Error(`external release evidence gate(s) missing blocking/review text: ${snippets.join("; ")}`);
  }
  const supportedHashRoutes = new Set(releaseEvidence.supportedHashRoutes);
  const badLinks = evidence.flatMap((item) => {
    const href = String(item.href || "").trim();
    if (!href) return [];
    if (item.resolvedHash.startsWith("#/")) {
      const route = item.resolvedHash.slice(1).split(/[?#]/, 1)[0] || "/";
      if (supportedHashRoutes.has(route)) return [];
      return [`${item.id || "<unknown>"} href "${href}" targets unsupported hash route "${route}"`];
    }
    if (item.sameOrigin && !releaseEvidence.appSupportsNonHashRoutes) {
      return [`${item.id || "<unknown>"} href "${href}" is a non-hash same-origin route, but this WebUI nav only advertises hash routes`];
    }
    return [];
  });
  if (badLinks.length) {
    throw new Error(`release evidence strip has dead app route link(s): ${badLinks.join("; ")}`);
  }
  const performance = evidence.find((item) => item.id === "performance");
  if (performance?.href !== "#/performance") {
    throw new Error(`release evidence performance item href was "${performance?.href || "<none>"}"`);
  }
  const performanceText = (performance?.text || "").replace(/\s+/g, " ").trim();
  if (/no claims/i.test(performanceText)) {
    if (!/release-benchmark not_applicable/i.test(performanceText) || /missing evidence|publishable benchmark artifact|local artifact|browser-only review/i.test(performanceText)) {
      throw new Error(`release evidence performance no-claims row overclaimed or leaked fallback text: "${performanceText}"`);
    }
  } else if (/missing evidence/i.test(performanceText)) {
    if (!/publishable benchmark artifact/i.test(performanceText) || /no claims|local artifact|browser-only review/i.test(performanceText)) {
      throw new Error(`release evidence performance missing-benchmark row was not explicit: "${performanceText}"`);
    }
  } else {
    throw new Error(`release evidence performance item did not reflect backend release status: "${performanceText}"`);
  }
  if (!/\d+\s+blocked/i.test(releaseEvidence.headerText || "")) {
    throw new Error(`release evidence aggregate did not remain blocked: "${releaseEvidence.headerText || "<none>"}"`);
  }
  const content = evidence.find((item) => item.id === "content");
  if (content?.href !== "#/intel") {
    throw new Error(`release evidence content item href was "${content?.href || "<none>"}"`);
  }
  if (!evidence.some((item) => /Support bundle evidence/.test(item.text))) {
    throw new Error("release evidence strip did not include support bundle evidence text");
  }
  const copyAction = await page.evaluate(() => {
    const el = document.querySelector("[data-release-evidence-action='copy-summary']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!copyAction?.visible || !/Copy summary/.test(copyAction.text)) {
    throw new Error("release evidence copy summary action was not visible");
  }
  await assertReadinessSystemEvidencePacket(page, viewport);
  await assertReadinessHAEvidencePacket(page, viewport);
  await assertReadinessReleaseAcceptanceStatus(page, viewport);
  await assertReadinessSupportBundlePreview(page, viewport);
  await assertReadinessExternalGateDetails(page, viewport, externalGateIds, releaseEvidence);
  await assertReadinessHostTuningPreviewTable(page, viewport);
  await assertReadinessRouteBackedDrawers(page, viewport);
  if (viewport.name === "mobile") {
    const cramped = evidence.filter((item) => item.width < 320 || item.height < 44);
    if (cramped.length) {
      throw new Error(`mobile release evidence rows too small: ${cramped.map((item) => `${item.id} ${Math.round(item.width)}x${Math.round(item.height)}`).join(", ")}`);
    }
    if (copyAction.width < 122 || copyAction.height < 38) {
      throw new Error(`mobile release evidence copy action too small: ${Math.round(copyAction.width)}x${Math.round(copyAction.height)}`);
    }
  }
}

async function assertReadinessRoutingVpnPosture(page, viewport) {
  const state = await page.evaluate(() => {
    const root = document.querySelector("[data-readiness-routing-vpn-posture='true']")?.closest(".card") ||
      document.querySelector("[data-readiness-routing-vpn-posture='true']");
    const rect = root?.getBoundingClientRect?.();
    const links = [...(root?.querySelectorAll("[data-readiness-routing-vpn-action]") || [])].map((el) => ({
      action: el.dataset.readinessRoutingVpnAction || "",
      href: el.getAttribute("href") || "",
      text: el.textContent || "",
    }));
    const rows = [...(root?.querySelectorAll("[data-readiness-routing-vpn-item]") || [])].map((el) => ({
      item: el.dataset.readinessRoutingVpnItem || "",
      state: el.dataset.readinessRoutingVpnState || "",
      text: el.textContent || "",
    }));
    return {
      visible: Boolean(root && rect && rect.width > 0 && rect.height > 0 && getComputedStyle(root).display !== "none" && getComputedStyle(root).visibility !== "hidden"),
      text: root?.textContent || "",
      links,
      rows,
      overflow: root ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(root.scrollWidth - root.clientWidth)) : 0,
    };
  });
  if (!state.visible) {
    throw new Error("readiness Routing & VPN posture panel was not visible");
  }
  if (state.overflow > 2) {
    throw new Error(`readiness Routing & VPN posture panel overflow at ${viewport.name}: ${state.overflow}px`);
  }
  for (const term of ["Routing & VPN posture", "BGP", "OSPF", "FRR", "IPsec", "WireGuard"]) {
    if (!state.text.includes(term)) {
      throw new Error(`readiness Routing & VPN posture panel missing term "${term}" at ${viewport.name}`);
    }
  }
  const netvpnLink = state.links.find((link) => link.action === "open-netvpn");
  if (netvpnLink?.href !== "#/netvpn") {
    throw new Error(`readiness Routing & VPN posture NetVPN link was "${netvpnLink?.href || "<none>"}" at ${viewport.name}`);
  }
  const requiredRows = ["routing-vpn-bgp", "routing-vpn-ospf", "routing-vpn-ipsec", "routing-vpn-wireguard"];
  const missingRows = requiredRows.filter((id) => !state.rows.some((row) => row.item === id));
  if (missingRows.length) {
    throw new Error(`readiness Routing & VPN posture missing row(s) at ${viewport.name}: ${missingRows.join(", ")}`);
  }
}

async function assertProxyPlanProofWorkflow(page, viewport) {
  await page.waitForSelector("[data-proxy-workspace='true']", { timeout: 10000 });
  await runSmokeStep("proxy stage WAF plan", async () => {
    await page.locator("[data-proxy-action='add-waf']").first().click();
    await waitForDrawerTitle(page, "Add WAF policy");
    await page.locator("#drawer:not([hidden]) [data-proxy-action='stage-waf']").first().click();
    await waitForDrawerClosed(page, 10000);
  });
  await runSmokeStep("proxy stage service plan", async () => {
    await page.locator("[data-proxy-action='add-service']").first().click();
    await waitForDrawerTitle(page, "Add virtual service");
    await page.locator("#drawer:not([hidden]) [data-proxy-action='stage-service']").first().click();
    await waitForDrawerClosed(page, 10000);
  });
  await runSmokeStep("proxy validate route-backed plan", async () => {
    await page.locator("[data-proxy-action='validate-plan']").first().click();
    await page.waitForFunction(() => location.hash.startsWith("#/proxy") && location.hash.includes("drawer=plan"), null, { timeout: 10000 });
    await waitForDrawerTitle(page, "Proxy / WAF plan proof", 15000);
    await page.waitForSelector("[data-proxy-plan-proof='ready']", { timeout: 30000 });
  });
  const state = await page.evaluate(() => {
    const root = document.querySelector("[data-proxy-plan-proof='ready']");
    const drawer = document.querySelector("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const rows = [...(root?.querySelectorAll("[data-proxy-plan-artifact]") || [])].map((row) => ({
      key: row.dataset.proxyPlanArtifact || "",
      text: row.textContent || "",
    }));
    const links = [...(root?.querySelectorAll("[data-proxy-plan-proof-link]") || [])].map((link) => ({
      key: link.dataset.proxyPlanProofLink || "",
      href: link.getAttribute("href") || "",
      text: link.textContent || "",
    }));
    return {
      visible: Boolean(root && drawer && rect && rect.width > 0 && rect.height > 0),
      hash: location.hash,
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      artifactPresent: root?.dataset.proxyArtifactPresent || "",
      rows,
      links,
      overflow: drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0,
    };
  });
  if (!state.visible) {
    throw new Error(`proxy plan proof drawer was not visible at ${viewport.name}`);
  }
  if (state.overflow > 2) {
    throw new Error(`proxy plan proof drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (state.artifactPresent !== "true" || !state.rows.some((row) => row.key === "proxy" && /yes/i.test(row.text))) {
    throw new Error(`proxy plan proof did not show proxy artifact presence at ${viewport.name}: ${JSON.stringify(state.rows)}`);
  }
  for (const term of ["Artifact exposure", "Hardening notes", "Active proxy/WAF traffic rollout"]) {
    if (!state.text.includes(term)) {
      throw new Error(`proxy plan proof missing "${term}" at ${viewport.name}`);
    }
  }
  if (!/metadata only|bounded review snippets/i.test(state.text)) {
    throw new Error(`proxy plan proof missing artifact exposure mode at ${viewport.name}`);
  }
  if (state.links.length !== 1 || !state.links.some((link) => link.key === "changes" && link.href === "#/changes?tab=candidate")) {
    throw new Error(`proxy plan proof owner link was wrong at ${viewport.name}: ${JSON.stringify(state.links)}`);
  }
  await page.locator("#drawer:not([hidden]) [data-proxy-action='close-plan-proof']").first().click();
  await waitForDrawerClosed(page, 10000);
  const hashAfterClose = await page.evaluate(() => location.hash);
  if (/drawer=plan/.test(hashAfterClose)) {
    throw new Error(`proxy plan proof route state was not cleared after close: ${hashAfterClose}`);
  }
}

async function assertReadinessHostTuningPreviewTable(page, viewport) {
  await resetReadinessDrawerState(page);
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-readiness-action='review-host-baseline']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    return {
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
      visible: rect.width > 0 && rect.height > 0 && getComputedStyle(el).display !== "none",
      disabled: Boolean(el.disabled),
    };
  });
  if (!action?.visible || action.disabled) {
    throw new Error(`readiness host tuning baseline review action unavailable at ${viewport.name}: ${JSON.stringify(action)}`);
  }
  await page.evaluate(() => document.querySelector("[data-readiness-action='review-host-baseline']")?.click());
  await waitForDrawerTitle(page, "Host tuning preview");
  const state = await page.evaluate(() => {
    const table = document.querySelector(".readiness-tune-result-table");
    const row = table?.querySelector("[data-readiness-tune-result]");
    const labels = [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
    const drawer = document.querySelector("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const commandButtons = [...(drawer?.querySelectorAll("[data-readiness-tuning-command-copy]") || [])].map((button) => ({
      key: button.getAttribute("data-readiness-tuning-command-copy") || "",
      type: button.getAttribute("type") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      tableClass: table?.className || "",
      rowKey: row?.getAttribute("data-readiness-tune-result") || "",
      labels,
      commandButtons,
      hasMonoKey: Boolean(row?.querySelector('td.mono[data-label="Key"]')),
      hasMonoValue: Boolean(row?.querySelector('td.mono[data-label="Value"]')),
      mobileLabelsRendered: window.innerWidth <= 820
        ? [...(row?.querySelectorAll("td") || [])].every((cell) => {
            const before = getComputedStyle(cell, "::before").content || "";
            return before !== "none" && before !== "\"\"" && before.length > 2;
          })
        : true,
      overflow: drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0,
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  });
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes("readiness-tune-result-table")) {
    throw new Error(`readiness host tuning table missing responsive classes at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const expectedLabels = ["Key", "Value", "State", "Detail"];
  const missingLabels = expectedLabels.filter((label) => !state.labels.includes(label));
  if (missingLabels.length || !state.hasMonoKey || !state.hasMonoValue) {
    throw new Error(`readiness host tuning table labels mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`readiness host tuning mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.commandButtons.some((button) => button.type !== "button" || !/^Copy .+ host tuning command$/.test(button.ariaLabel))) {
    throw new Error(`readiness host tuning command copy buttons were not accessible at ${viewport.name}: ${JSON.stringify(state.commandButtons)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`readiness host tuning drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function assertReadinessReleaseAcceptanceStatus(page, viewport) {
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-release-evidence-action='open-acceptance-status']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!action?.visible || !/Acceptance status/.test(action.text)) {
    throw new Error("release acceptance status action was not visible");
  }
  if (viewport.name === "mobile" && (action.width < 126 || action.height < 34)) {
    throw new Error(`mobile release acceptance status action too small: ${Math.round(action.width)}x${Math.round(action.height)}`);
  }

  await page.evaluate(() => document.querySelector("[data-release-evidence-action='open-acceptance-status']")?.click());
  await waitForReadinessDrawer(page, "[data-readiness-release-acceptance='true']");
  const state = await page.evaluate(() => {
    const root = document.querySelector("[data-readiness-release-acceptance='true']");
    const drawer = root?.closest?.(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const checks = [...(root?.querySelectorAll("[data-release-acceptance-check]") || [])].map((row) => ({
      id: row.dataset.releaseAcceptanceCheck || "",
      text: row.textContent || "",
	      commands: [...row.querySelectorAll("[data-release-acceptance-command]")].map((el) => ({
	        check: el.dataset.releaseAcceptanceCommand || "",
	        role: el.dataset.releaseAcceptanceCommandRole || "",
	        text: el.textContent || "",
	      })),
	      commandCopyButtons: [...row.querySelectorAll("[data-release-acceptance-command-copy]")].map((button) => ({
	        check: button.getAttribute("data-release-acceptance-command-copy") || "",
	        role: button.getAttribute("data-release-acceptance-command-role") || "",
	        type: button.getAttribute("type") || "",
	        ariaLabel: button.getAttribute("aria-label") || "",
	      })),
	      width: row.getBoundingClientRect().width,
      height: row.getBoundingClientRect().height,
    }));
    const report = root?.querySelector("[data-release-acceptance-report]")?.value || "";
    const copy = root?.closest(".drawer")?.querySelector("[data-release-acceptance-action='copy-report']");
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      visible: Boolean(root),
      text: root?.textContent || "",
      report,
      checks,
      copyText: copy?.textContent || "",
      overflow,
    };
  });
  if (!state.visible) {
    throw new Error("release acceptance status drawer did not open");
  }
  if (state.overflow > 2) {
    throw new Error(`release acceptance status drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  for (const id of ["release-benchmark", "privileged-integration", "ha-readiness-recovery", "m3-field-evidence", "ebpf-ol9-field-evidence", "m5-oidc-field-evidence"]) {
    if (!state.checks.some((check) => check.id === id)) {
      throw new Error(`release acceptance status drawer missing check ${id}`);
    }
  }
  if (!/state=blocked/.test(state.report) || !/release-benchmark/.test(state.report) || !/privileged-integration/.test(state.report)) {
    throw new Error("release acceptance status report missing blocked state or key checks");
  }
	  const protoVerify = state.checks.find((check) => check.id === "proto-verify");
	  if (!protoVerify?.commands.some((command) => /ngfwrelease record/.test(command.text) && /make proto-verify/.test(command.text))) {
	    throw new Error("release acceptance proto-verify row did not expose the validation command");
	  }
	  if (!protoVerify?.commandCopyButtons.some((button) => button.type === "button" && button.ariaLabel === "Copy record command for proto-verify")) {
	    throw new Error(`release acceptance proto-verify command copy button was not accessible: ${JSON.stringify(protoVerify?.commandCopyButtons || [])}`);
	  }
	  const privilegedIntegration = state.checks.find((check) => check.id === "privileged-integration");
	  if (!privilegedIntegration?.commands.some((command) => /make privileged-integration-evidence-check/.test(command.text))) {
	    throw new Error("release acceptance privileged-integration row did not expose the validation command");
	  }
	  if (!privilegedIntegration?.commands.some((command) =>
	    /release-evidence-privileged-integration/.test(command.text) ||
	    (/ngfwrelease record/.test(command.text) &&
	      /--check privileged-integration/.test(command.text) &&
	      /(sudo \/tmp\/openngfw-itest|make privileged-integration-evidence-check|bash release\/privileged-integration-no-skip\.sh)/.test(command.text)))) {
	    throw new Error("release acceptance privileged-integration row did not expose the record command");
	  }
	  if (!privilegedIntegration?.commandCopyButtons.some((button) => button.type === "button" && /Copy .+ command for privileged-integration/.test(button.ariaLabel))) {
	    throw new Error(`release acceptance privileged-integration command copy button was not accessible: ${JSON.stringify(privilegedIntegration?.commandCopyButtons || [])}`);
	  }
  const haRecovery = state.checks.find((check) => check.id === "ha-readiness-recovery");
  if (!haRecovery?.commands.some((command) => /make ha-readiness-recovery-check/.test(command.text))) {
    throw new Error("release acceptance ha-readiness-recovery row did not expose the validation command");
  }
  if (!haRecovery?.commands.some((command) => /release-evidence-ha-readiness-recovery/.test(command.text))) {
    throw new Error("release acceptance ha-readiness-recovery row did not expose the record command");
  }
  const m3Field = state.checks.find((check) => check.id === "m3-field-evidence");
  if (!m3Field?.commands.some((command) => /ngfwrelease record/.test(command.text) && /m3-field-evidence-check/.test(command.text))) {
    throw new Error("release acceptance m3-field-evidence row did not expose the record command");
  }
  const ebpfOL9Field = state.checks.find((check) => check.id === "ebpf-ol9-field-evidence");
  if (!ebpfOL9Field?.commands.some((command) => /ngfwrelease record/.test(command.text) && /ebpf-ol9-field-evidence-check/.test(command.text))) {
    throw new Error("release acceptance ebpf-ol9-field-evidence row did not expose the record command");
  }
  if (!/command \(Next\): go run \.\/cmd\/ngfwrelease record/.test(state.report) || !/m5-oidc-field-evidence-check/.test(state.report) || !/ha-readiness-recovery/.test(state.report) || !/make ha-readiness-recovery-check/.test(state.report)) {
    throw new Error("release acceptance status report missing next commands");
  }
  if (/Release acceptance evidence is ready/i.test(state.text)) {
    throw new Error("release acceptance status drawer overclaimed readiness");
  }
  if (!/Copy status/.test(state.copyText)) {
    throw new Error("release acceptance status copy action missing");
  }
  await page.keyboard.press("Escape");
  await page.waitForTimeout(80);
}

async function assertReadinessSupportBundlePreview(page, viewport) {
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-readiness-action='preview-support-bundle']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!action?.visible || !/Preview support bundle/.test(action.text)) {
    throw new Error("support bundle preview action was not visible");
  }
  if (viewport.name === "mobile" && (action.width < 142 || action.height < 34)) {
    throw new Error(`mobile support bundle preview action too small: ${Math.round(action.width)}x${Math.round(action.height)}`);
  }

  await page.evaluate(() => document.querySelector("[data-readiness-action='preview-support-bundle']")?.click());
  await waitForReadinessDrawer(page, ".drawer .support-bundle-preview");
  const state = await page.evaluate(() => {
    const root = document.querySelector(".drawer .support-bundle-preview");
    const drawer = root?.closest?.(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const rows = [...(root?.querySelectorAll(".support-section-row") || [])].map((row) => row.textContent || "");
    const download = drawer?.querySelector(".btn.primary");
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      visible: Boolean(root),
      text: root?.textContent || "",
      rows,
      downloadText: download?.textContent || "",
      overflow,
    };
  });
  if (!state.visible) {
    throw new Error("support bundle preview drawer did not open");
  }
  if (state.overflow > 2) {
    throw new Error(`support bundle preview drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  for (const label of ["Runtime status", "Runtime readiness preflight", "Release acceptance", "Audit integrity", "Traffic flows", "Content packages"]) {
    if (!state.rows.some((row) => row.includes(label))) {
      throw new Error(`support bundle preview missing section ${label}`);
    }
  }
  if (!/Sections/.test(state.text) || !/Failures/.test(state.text) || !/Redactions/.test(state.text) || !/Package blockers/.test(state.text)) {
    throw new Error("support bundle preview missing summary counters");
  }
  if (!/redaction/i.test(state.text)) {
    throw new Error("support bundle preview missing redaction notice");
  }
  if (!/Download JSON/.test(state.downloadText)) {
    throw new Error("support bundle preview download action missing");
  }
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const download = [...(drawer?.querySelectorAll("button") || [])]
      .find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === "Download JSON");
    if (!download) throw new Error("support bundle download button was not found");
    download.click();
  });
  await assertSupportBundleDownload(await downloadPromise, viewport);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(80);
}

async function assertSupportBundleDownload(download, viewport) {
  const filename = download.suggestedFilename();
  if (!/^phragma-support-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z\.json$/.test(filename)) {
    throw new Error(`support bundle download filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`support bundle download did not produce a readable local file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  let bundle = null;
  try {
    bundle = JSON.parse(text);
  } catch (err) {
    throw new Error(`support bundle download was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (bundle?.schemaVersion !== "phragma.support.bundle.v1") {
    throw new Error(`support bundle schemaVersion=${bundle?.schemaVersion || "<missing>"} at ${viewport.name}`);
  }
  if (!bundle.collectedAt || Number.isNaN(Date.parse(bundle.collectedAt))) {
    throw new Error(`support bundle collectedAt was not an ISO timestamp at ${viewport.name}`);
  }
  const endpoints = bundle.endpoints || {};
  const requiredEndpoints = [
    "status",
    "highAvailabilityStatus",
    "identity",
    "runningPolicy",
    "candidatePolicy",
    "candidateValidation",
    "runtimeReadinessPreflight",
    "versions",
    "audit",
    "auditIntegrity",
    "alerts",
    "flows",
    "sessions",
    "feeds",
    "contentPackages",
    "releaseAcceptanceStatus",
  ];
  const missingEndpoints = requiredEndpoints.filter((name) => !Object.prototype.hasOwnProperty.call(endpoints, name));
  if (missingEndpoints.length) {
    throw new Error(`support bundle download missing endpoint section(s) at ${viewport.name}: ${missingEndpoints.join(", ")}`);
  }
  const summary = bundle.summary || {};
  const numericSummaryFields = [
    "contentPackageCount",
    "contentPackageBlockers",
    "releaseAcceptanceMissing",
    "releaseAcceptanceInvalid",
    "releaseAcceptanceNotApplicable",
    "releaseAcceptanceTodo",
    "releaseAcceptanceProblems",
    "releaseAcceptanceNextActions",
    "releaseAcceptanceNextCommands",
    "auditEntryCount",
    "flowCount",
    "alertCount",
    "sessionCount",
  ];
  const badSummaryFields = numericSummaryFields.filter((name) => typeof summary[name] !== "number" || Number.isNaN(summary[name]));
  if (badSummaryFields.length) {
    throw new Error(`support bundle summary field(s) were not numeric at ${viewport.name}: ${badSummaryFields.join(", ")}`);
  }
  if (typeof summary.releaseAcceptanceReady !== "boolean") {
    throw new Error(`support bundle releaseAcceptanceReady was not boolean at ${viewport.name}`);
  }
  if (!Array.isArray(summary.failedEndpoints)) {
    throw new Error(`support bundle failedEndpoints was not an array at ${viewport.name}`);
  }
  if (endpoints.status?.data && endpoints.status.ok !== true) {
    throw new Error(`support bundle status section had data but was not marked ok at ${viewport.name}`);
  }
  if (endpoints.highAvailabilityStatus?.data && endpoints.highAvailabilityStatus.ok !== true) {
    throw new Error(`support bundle HA status section had data but was not marked ok at ${viewport.name}`);
  }
  if (endpoints.releaseAcceptanceStatus?.data && endpoints.releaseAcceptanceStatus.ok !== true) {
    throw new Error(`support bundle release acceptance section had data but was not marked ok at ${viewport.name}`);
  }
  const releaseAcceptanceChecks = Array.isArray(endpoints.releaseAcceptanceStatus?.data?.checks)
    ? endpoints.releaseAcceptanceStatus.data.checks
    : [];
  const releaseAcceptanceNextSteps = countReleaseAcceptanceNextSteps(releaseAcceptanceChecks);
  if (summary.releaseAcceptanceNextActions !== releaseAcceptanceNextSteps.actions) {
    throw new Error(`support bundle releaseAcceptanceNextActions=${summary.releaseAcceptanceNextActions} did not match endpoint checks=${releaseAcceptanceNextSteps.actions} at ${viewport.name}`);
  }
  if (summary.releaseAcceptanceNextCommands !== releaseAcceptanceNextSteps.commands) {
    throw new Error(`support bundle releaseAcceptanceNextCommands=${summary.releaseAcceptanceNextCommands} did not match endpoint checks=${releaseAcceptanceNextSteps.commands} at ${viewport.name}`);
  }
  const blockedReleaseAcceptanceChecks = releaseAcceptanceChecks.filter((check) => {
    const state = String(check?.state || check?.status || "").trim().toLowerCase().replace(/-/g, "_");
    return state === "missing" || state === "invalid" || (Array.isArray(check?.problems) && check.problems.length > 0);
  });
  if (blockedReleaseAcceptanceChecks.length && releaseAcceptanceNextSteps.actions === 0) {
    throw new Error(`support bundle release acceptance checks did not preserve next_action guidance at ${viewport.name}`);
  }
  if (blockedReleaseAcceptanceChecks.length && releaseAcceptanceNextSteps.commands === 0) {
    throw new Error(`support bundle release acceptance checks did not preserve next_command guidance at ${viewport.name}`);
  }
  const leaked = [
    /Authorization:\s*Bearer\s+(?!\[redacted\])/i,
    /\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/=-]+/i,
    /access[_-]?token=(?!\[redacted\])[^&\s"',;]+/i,
    /api[_-]?key=(?!\[redacted\])[^&\s"',;]+/i,
    /password=(?!\[redacted\])[^&\s"',;]+/i,
    /\/Users\/[^"',\s}]+/i,
    /\/home\/[^"',\s}]+/i,
    /\/etc\/openngfw\/[^"',\s}]+/i,
    /\/var\/log(?:\/openngfw)?\/[^"',\s}]+/i,
    /\/var\/lib\/[^"',\s}]+/i,
  ].find((pattern) => pattern.test(text));
  if (leaked) {
    throw new Error(`support bundle download leaked sensitive material at ${viewport.name}: ${leaked}`);
  }
}

function countReleaseAcceptanceNextSteps(checks = []) {
  return checks.reduce((out, check) => {
    if (releaseAcceptanceHasText(check?.nextAction ?? check?.next_action)) out.actions += 1;
    if (releaseAcceptanceHasCommand(check?.nextCommand ?? check?.next_command)) out.commands += 1;
    return out;
  }, { actions: 0, commands: 0 });
}

function releaseAcceptanceHasCommand(value) {
  if (Array.isArray(value)) return value.some(releaseAcceptanceHasText);
  return releaseAcceptanceHasText(value);
}

function releaseAcceptanceHasText(value) {
  return String(value ?? "").trim().length > 0;
}

async function assertReadinessSystemEvidencePacket(page, viewport) {
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-readiness-action='open-system-evidence']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!action?.visible || !/System evidence/.test(action.text)) {
    throw new Error("readiness system evidence action was not visible");
  }
  if (viewport.name === "mobile" && (action.width < 138 || action.height < 38)) {
    throw new Error(`mobile system evidence action too small: ${Math.round(action.width)}x${Math.round(action.height)}`);
  }

  await page.evaluate(() => document.querySelector("[data-readiness-action='open-system-evidence']")?.click());
  await page.waitForTimeout(120);
  const packet = await page.evaluate(() => {
    const root = document.querySelector("[data-readiness-system-evidence='true']");
    const drawer = root?.closest?.(".drawer");
    const report = root?.querySelector("[data-readiness-system-evidence-report]")?.value || "";
    const rows = [...(root?.querySelectorAll("[data-system-evidence-row]") || [])].map((row) => ({
      id: row.dataset.systemEvidenceRow || "",
      text: row.textContent || "",
      width: row.getBoundingClientRect().width,
      height: row.getBoundingClientRect().height,
    }));
    const rect = drawer?.getBoundingClientRect?.();
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      visible: Boolean(root),
      text: root?.textContent || "",
      report,
      rows,
      overflow,
    };
  });
  if (!packet.visible) {
    throw new Error("system evidence drawer did not open");
  }
  if (packet.overflow > 2) {
    throw new Error(`system evidence drawer overflow at ${viewport.name}: ${packet.overflow}px`);
  }
  const requiredRows = ["production-posture", "management-plane", "dataplane-proof", "external-release-gates"];
  const missingRows = requiredRows.filter((id) => !packet.rows.some((row) => row.id === id));
  if (missingRows.length) {
    throw new Error(`system evidence packet missing row(s): ${missingRows.join(", ")}`);
  }
  if (!/OpenNGFW system evidence packet/.test(packet.report) || !/unresolved_external_gates=/.test(packet.report)) {
    throw new Error("system evidence report missing packet header or unresolved external gate line");
  }
  if (!/Local system evidence does not close external field gates/.test(packet.report)) {
    throw new Error("system evidence report overclaims external field evidence closure");
  }
  await page.keyboard.press("Escape");
  await page.waitForTimeout(80);
}

async function assertReadinessHAEvidencePacket(page, viewport) {
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-readiness-action='open-ha-evidence']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!action?.visible || !/HA evidence/.test(action.text)) {
    throw new Error("readiness HA evidence action was not visible");
  }
  if (viewport.name === "mobile" && (action.width < 112 || action.height < 34)) {
    throw new Error(`mobile HA evidence action too small: ${Math.round(action.width)}x${Math.round(action.height)}`);
  }

  await page.evaluate(() => document.querySelector("[data-readiness-action='open-ha-evidence']")?.click());
  await waitForReadinessDrawer(page, "[data-readiness-ha-evidence='true']");
  const packet = await page.evaluate(() => {
    const root = document.querySelector("[data-readiness-ha-evidence='true']");
    const drawer = root?.closest?.(".drawer");
    const report = root?.querySelector("[data-readiness-ha-evidence-report]")?.value || "";
    const rows = [...(root?.querySelectorAll("[data-system-evidence-row]") || [])].map((row) => ({
      id: row.dataset.systemEvidenceRow || "",
      text: row.textContent || "",
    }));
    const rect = drawer?.getBoundingClientRect?.();
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      visible: Boolean(root),
      text: root?.textContent || "",
      report,
      rows,
      overflow,
    };
  });
  if (!packet.visible) {
    throw new Error("HA evidence drawer did not open");
  }
  if (packet.overflow > 2) {
    throw new Error(`HA evidence drawer overflow at ${viewport.name}: ${packet.overflow}px`);
  }
  const requiredRows = ["ha-state", "ha-policy-recovery", "ha-peer-sync", "ha-auto-replication", "ha-failover", "ha-blockers"];
  const missingRows = requiredRows.filter((id) => !packet.rows.some((row) => row.id === id));
  if (missingRows.length) {
    throw new Error(`HA evidence packet missing row(s): ${missingRows.join(", ")}`);
  }
  if (!/OpenNGFW high availability evidence packet/.test(packet.report) || !/failover_eligible=/.test(packet.report)) {
    throw new Error("HA evidence report missing packet header or failover eligibility line");
  }
  if (!/does not execute peer sync or failover/.test(packet.report)) {
    throw new Error("HA evidence report overclaimed peer sync or failover mutation");
  }
  await page.keyboard.press("Escape");
  await page.waitForTimeout(80);

  await assertReadinessHACockpit(page, viewport);
}

async function assertReadinessHACockpit(page, viewport) {
  const action = await page.evaluate(() => {
    const el = document.querySelector("[data-readiness-action='open-ha-cockpit']");
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      text: el.textContent || "",
      visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0,
      width: rect.width,
      height: rect.height,
    };
  });
  if (!action?.visible || !/Operations cockpit/.test(action.text)) {
    throw new Error("readiness HA operations cockpit action was not visible");
  }
  if (viewport.name === "mobile" && (action.width < 128 || action.height < 34)) {
    throw new Error(`mobile HA cockpit action too small: ${Math.round(action.width)}x${Math.round(action.height)}`);
  }
  await page.evaluate(() => document.querySelector("[data-readiness-action='open-ha-cockpit']")?.click());
  await waitForReadinessDrawer(page, "[data-readiness-ha-cockpit='true']");
  const cockpit = await page.evaluate(() => {
    const root = document.querySelector("[data-readiness-ha-cockpit='true']");
    const drawer = root?.closest?.(".drawer");
    const report = root?.querySelector("[data-readiness-ha-cockpit-report]")?.value || "";
    const rows = [...(root?.querySelectorAll("[data-system-evidence-row]") || [])].map((row) => row.dataset.systemEvidenceRow || "");
    const rect = drawer?.getBoundingClientRect?.();
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      visible: Boolean(root),
      text: root?.textContent || "",
      report,
      rows,
      overflow,
    };
  });
  if (!cockpit.visible) {
    throw new Error("HA operations cockpit drawer did not open");
  }
  if (cockpit.overflow > 2) {
    throw new Error(`HA operations cockpit drawer overflow at ${viewport.name}: ${cockpit.overflow}px`);
  }
  for (const required of ["Local node", "Peer node", "Policy comparison", "Sync blockers", "Recovery point", "Automatic passive replication", "Failover eligibility", "Manual recovery policy pull", "Post-activation split-brain review"]) {
    if (!cockpit.text.includes(required)) {
      throw new Error(`HA operations cockpit missing "${required}" at ${viewport.name}`);
    }
  }
  for (const id of ["ha-cockpit-policy-compare", "ha-cockpit-sync-blockers", "ha-cockpit-recovery-point", "ha-cockpit-auto-replication", "ha-cockpit-failover-readiness", "ha-cockpit-policy-pull", "ha-cockpit-failover-activation", "ha-cockpit-post-activation-review"]) {
    if (!cockpit.rows.includes(id)) {
      throw new Error(`HA operations cockpit missing row ${id}`);
    }
  }
  if (!/OpenNGFW high availability operations cockpit/.test(cockpit.report) || !/mutation_surface=automatic-passive-policy-replication-and-manual-activation/.test(cockpit.report) || !/post_activation_review=/.test(cockpit.report)) {
    throw new Error("HA operations cockpit report missing header or guarded mutation line");
  }
  await assertReadinessHAMutationWorkflows(page, viewport);
  await assertReadinessHACockpitAutomationContext(page, viewport);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(80);
}

async function assertReadinessHAMutationWorkflows(page, viewport) {
  await installHAMutationFetchRecorder(page);
  const actions = await collectHACockpitFooterActions(page);
  if (!actions.pull.present || !actions.activation.present) {
    throw new Error(`HA cockpit mutation actions missing at ${viewport.name}: ${JSON.stringify(actions)}`);
  }
  if (actions.pull.enabled) {
    await assertReadinessHAPolicyPullWorkflow(page, viewport, { allowMutation: process.env.WEBUI_SMOKE_ALLOW_HA_MUTATIONS === "1" });
    await reopenReadinessHACockpit(page);
  }
  const refreshed = await collectHACockpitFooterActions(page);
  if (refreshed.activation.enabled) {
    await assertReadinessHAActivationWorkflow(page, viewport, { allowMutation: process.env.WEBUI_SMOKE_ALLOW_HA_MUTATIONS === "1" });
    await page.evaluate(() => { location.hash = "#/readiness"; });
    await waitForRouteReady(page, "/readiness");
    await page.evaluate(() => document.querySelector("[data-readiness-action='open-ha-cockpit']")?.click());
    await waitForReadinessDrawer(page, "[data-readiness-ha-cockpit='true']");
  }
}

async function collectHACockpitFooterActions(page) {
  return await page.evaluate(() => {
    const drawer = document.querySelector("[data-readiness-ha-cockpit='true']")?.closest(".drawer");
    const buttons = [...(drawer?.querySelectorAll(".drawer-foot button") || [])].map((button) => ({
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      disabled: Boolean(button.disabled),
      title: button.getAttribute("title") || "",
      type: button.getAttribute("type") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
      action: button.getAttribute("data-readiness-action") || "",
    }));
    const byText = (label) => {
      const found = buttons.find((button) => button.text === label);
      return { present: Boolean(found), enabled: Boolean(found && !found.disabled), title: found?.title || "" };
    };
    return {
      pull: byText("Review pull"),
      activation: byText("Review activation"),
      buttons,
    };
  });
}

async function reopenReadinessHACockpit(page) {
  await page.evaluate(() => { location.hash = "#/readiness?drawer=ha-cockpit"; });
  await waitForRouteReady(page, "/readiness");
  await waitForReadinessDrawer(page, "[data-readiness-ha-cockpit='true']");
}

async function installHAMutationFetchRecorder(page) {
  await page.evaluate(() => {
    if (globalThis.__haMutationFetchRecorderInstalled) {
      globalThis.__haMutationRequests = [];
      return;
    }
    globalThis.__haMutationFetchRecorderInstalled = true;
    globalThis.__haMutationRequests = [];
    const nativeFetch = globalThis.fetch?.bind(globalThis);
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      let parsed = null;
      try { parsed = new URL(url, location.href); } catch {}
      const path = parsed?.pathname || "";
      const tracked = path === "/v1/system/ha/policy:pull" || path === "/v1/system/ha/failover:activate";
      if (!tracked) return nativeFetch(input, init);
      const entry = {
        path,
        method: String(init?.method || (typeof input !== "string" ? input?.method : "") || "GET").toUpperCase(),
        body: null,
        status: 0,
        response: "",
      };
      try { entry.body = JSON.parse(init?.body || "{}"); } catch { entry.body = init?.body || ""; }
      globalThis.__haMutationRequests.push(entry);
      const response = await nativeFetch(input, init);
      entry.status = response.status;
      try { entry.response = await response.clone().text(); } catch {}
      return response;
    };
  });
}

async function assertReadinessHAPolicyPullWorkflow(page, viewport, { allowMutation = false } = {}) {
  await clickDrawerFooterButton(page, "Review pull");
  await waitForDrawerTitle(page, "Manual HA policy resync");
  await page.click('[data-ha-policy-pull-submit="resync"]');
  await assertPerformanceToast(page, "Audit comment required", "pulling the active peer policy");
  if (!allowMutation) {
    await page.keyboard.press("Escape");
    await waitForDrawerClosed(page).catch(() => {});
    return;
  }
  const comment = `visual smoke HA resync ${viewport.name}`;
  await page.fill('[data-ha-policy-pull-field="comment"]', comment);
  await page.check('[data-ha-policy-pull-ack="risk"]');
  await page.check('[data-ha-policy-pull-ack="runtime"]');
  await page.click('[data-ha-policy-pull-submit="resync"]');
  await page.waitForFunction(() => {
    const text = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ");
    return text.includes("HA policy pulled") || text.includes("HA policy pull failed");
  }, null, { timeout: 10000 });
  const request = await latestHAMutationRequest(page, "/v1/system/ha/policy:pull");
  if (!request || request.method !== "POST" || request.body?.comment !== comment || request.body?.ackPull !== true || request.body?.ackRisk !== true || request.body?.ackRuntime !== true) {
    throw new Error(`HA policy pull did not submit expected audited body at ${viewport.name}: ${JSON.stringify(request)}`);
  }
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page).catch(() => {});
}

async function assertReadinessHAActivationWorkflow(page, viewport, { allowMutation = false } = {}) {
  const beforeAudit = allowMutation ? await haAuditCount(page, "ha-failover-activate") : 0;
  await clickDrawerFooterButton(page, "Review activation");
  await waitForDrawerTitle(page, "Activate passive node");
  await page.click('[data-ha-failover-submit="activate"]');
  await assertPerformanceToast(page, "Audit comment required", "being marked active");
  const comment = `visual smoke HA activation ${viewport.name}`;
  await page.fill('[data-ha-failover-field="comment"]', comment);
  await page.click('[data-ha-failover-submit="activate"]');
  await assertPerformanceToast(page, "Acknowledgements required", "external peer fencing");
  if (!allowMutation) {
    await page.keyboard.press("Escape");
    await waitForDrawerClosed(page).catch(() => {});
    return;
  }
  await page.check('[data-ha-failover-ack="failover"]');
  await page.check('[data-ha-failover-ack="external-cutover"]');
  await page.check('[data-ha-failover-ack="external-fencing"]');
  await page.click('[data-ha-failover-submit="activate"]');
  await page.waitForFunction(() => {
    const text = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ");
    return text.includes("HA node activated") || text.includes("HA activation failed");
  }, null, { timeout: 12000 });
  const request = await latestHAMutationRequest(page, "/v1/system/ha/failover:activate");
  if (!request || request.method !== "POST" || request.body?.comment !== comment || request.body?.ackFailover !== true || request.body?.ackExternalCutover !== true || request.body?.ackExternalFencing !== true) {
    throw new Error(`HA activation did not submit expected audited body at ${viewport.name}: ${JSON.stringify(request)}`);
  }
  if (request.status >= 200 && request.status < 300) {
    await waitForDrawerClosed(page);
    await waitForHAAuditEntry(page, "ha-failover-activate", comment, beforeAudit);
  } else {
    throw new Error(`HA activation workflow was enabled but backend rejected it at ${viewport.name}: ${JSON.stringify(request)}`);
  }
}

async function latestHAMutationRequest(page, path) {
  return await page.evaluate((targetPath) => {
    const requests = globalThis.__haMutationRequests || [];
    return [...requests].reverse().find((item) => item.path === targetPath) || null;
  }, path);
}

async function haAuditCount(page, action) {
  return await page.evaluate(async (actionName) => {
    const res = await fetch(`/v1/audit?action=${encodeURIComponent(actionName)}&limit=100`);
    const body = await res.json();
    return (body.entries || []).length;
  }, action);
}

async function waitForHAAuditEntry(page, action, comment, beforeCount) {
  await page.waitForFunction(async ({ action, comment, beforeCount }) => {
    const res = await fetch(`/v1/audit?action=${encodeURIComponent(action)}&limit=100`);
    if (!res.ok) return false;
    const body = await res.json();
    const entries = body.entries || [];
    return entries.length > beforeCount && entries.some((entry) => entry.action === action && String(entry.detail || "").includes(comment));
  }, { action, comment, beforeCount }, { timeout: 10000 });
}

async function assertReadinessHACockpitAutomationContext(page, viewport) {
  await page.evaluate(() => {
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  const clicked = await page.evaluate(() => {
    const button = document.querySelector('[data-readiness-action="ha-cockpit-api-cli"]');
    if (!button || button.disabled) return false;
    button.click();
    return true;
  });
  if (!clicked) {
    throw new Error(`HA operations cockpit API / CLI action was not available at ${viewport.name}`);
  }
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  const drawerRequiredText = [
    "API / CLI context",
    "Readiness",
    "Current view",
    "#/readiness?drawer=ha-cockpit",
    "/v1/system/ha/status",
    "/v1/system/ha/policy:pull",
    "/v1/system/ha/failover:activate",
    "ngfwctl status",
    "ngfwctl system ha pull-policy",
    "ngfwctl system ha activate-passive",
    "HA operations cockpit",
    "acknowledgement",
    "VIP/route cutover",
  ];
  const copiedRequiredText = [
    "# Phragma API/CLI context: Readiness",
    "Current view:",
    "#/readiness?drawer=ha-cockpit",
    "GET /v1/system/ha/status",
    "POST /v1/system/ha/policy:pull",
    "POST /v1/system/ha/failover:activate",
    "ngfwctl status",
    "ngfwctl system ha pull-policy --ack-pull",
    "ngfwctl system ha activate-passive --ack-failover",
    "HA operations cockpit",
    "VIP/route cutover",
  ];
  assertDrawerContains(drawer, viewport, "readiness HA cockpit API / CLI context", drawerRequiredText, ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `readiness HA cockpit API / CLI drawer ${viewport.name}`);
  assertNoReadinessHAContextLeak(drawer.text, `readiness HA cockpit API / CLI drawer ${viewport.name}`);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `readiness HA cockpit workflow session JSON ${viewport.name}`);
  assertNoReadinessHAContextLeak(sessionJson, `readiness HA cockpit workflow session JSON ${viewport.name}`);
  let sessionPacket = null;
  try {
    sessionPacket = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`readiness HA cockpit workflow session JSON was not parseable at ${viewport.name}: ${err.message}`);
  }
  if (sessionPacket.schemaVersion !== "phragma.webui.workflow-session.v1" ||
      sessionPacket.routeState?.hash !== "#/readiness?drawer=ha-cockpit" ||
      sessionPacket.custody?.serverStored !== false ||
      !sessionPacket.endpoints?.some((endpoint) => endpoint.path === "/v1/system/ha/policy:pull") ||
      !sessionPacket.endpoints?.some((endpoint) => endpoint.path === "/v1/system/ha/failover:activate") ||
      !sessionPacket.cli?.some((item) => String(item.command || "").includes("ngfwctl system ha activate-passive"))) {
    throw new Error(`readiness HA cockpit workflow session JSON had unexpected shape at ${viewport.name}: ${JSON.stringify(sessionPacket)}`);
  }
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  for (const required of copiedRequiredText) {
    if (!copied.includes(required)) {
      throw new Error(`readiness HA cockpit copied API / CLI context missing ${required} at ${viewport.name}`);
    }
  }
  assertAutomationContextRedaction(copied, `readiness HA cockpit copied API / CLI context ${viewport.name}`);
  assertNoReadinessHAContextLeak(copied, `readiness HA cockpit copied API / CLI context ${viewport.name}`);
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

function assertNoReadinessHAContextLeak(text, label) {
  const leaked = [
    /peer[_-]?token/i,
    /ha[_-]?token/i,
    /Bearer\s+(?!\$\{|\[redacted\])[A-Za-z0-9._~+/-]{12,}/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
    /api[_-]?key=(?!\[redacted\])/i,
    /https?:\/\/[^/\s"']+:[^@\s"']+@/i,
    /\/Users\/[^\s"',;}]+/i,
    /\/private\/tmp\/[^\s"',;}]+/i,
    /\/var\/(?:lib|log)\/openngfw[^\s"',;}]*/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked sensitive HA automation context: ${leaked}`);
  }
}

async function assertReadinessRouteBackedDrawers(page, viewport) {
  await resetReadinessDrawerState(page);
  await page.evaluate(() => { location.hash = "#/readiness?drawer=system"; });
  await waitForReadinessDrawer(page, "[data-readiness-system-evidence='true']");
  let state = await collectRouteBackedDrawerState(page, "[data-readiness-system-evidence='true']");
  if (!/OpenNGFW system evidence packet/.test(state.report || state.text)) {
    throw new Error("route-backed system evidence drawer did not expose packet report");
  }
  if (state.overflow > 2) {
    throw new Error(`route-backed system evidence drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  assertRouteBackedDrawerFooterActions(state, `system evidence ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForReadinessHashCleared(page);

  await page.evaluate(() => { location.hash = "#/readiness?drawer=ha"; });
  await waitForReadinessDrawer(page, "[data-readiness-ha-evidence='true']");
  state = await collectRouteBackedDrawerState(page, "[data-readiness-ha-evidence='true']");
  if (!/OpenNGFW high availability evidence packet/.test(state.report || state.text)) {
    throw new Error("route-backed HA evidence drawer did not expose packet report");
  }
  if (state.overflow > 2) {
    throw new Error(`route-backed HA evidence drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  assertRouteBackedDrawerFooterActions(state, `HA evidence ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForReadinessHashCleared(page);

  await page.evaluate(() => { location.hash = "#/readiness?drawer=ha-cockpit"; });
  await waitForReadinessDrawer(page, "[data-readiness-ha-cockpit='true']");
  state = await collectRouteBackedDrawerState(page, "[data-readiness-ha-cockpit='true']");
  if (!/OpenNGFW high availability operations cockpit/.test(state.report || state.text) || !/Automatic passive replication/.test(state.text)) {
    throw new Error("route-backed HA cockpit drawer did not expose operations report");
  }
  if (state.overflow > 2) {
    throw new Error(`route-backed HA cockpit drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  assertRouteBackedDrawerFooterActions(state, `HA cockpit ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForReadinessHashCleared(page);

  await page.evaluate(() => { location.hash = "#/readiness?packet=m3-field-evidence"; });
  await waitForReadinessDrawer(page, ".drawer [data-release-evidence-packet='m3-field-evidence']");
  state = await collectRouteBackedDrawerState(page, ".drawer [data-release-evidence-packet='m3-field-evidence']");
  if (!/m3-field-evidence/.test(state.text) || state.path !== "release/field-evidence/m3" || !state.commands.some((command) => /\bmake m3-field-evidence-check\b/.test(command))) {
    throw new Error("route-backed release packet drawer missing M3 evidence path or command");
  }
  if (state.overflow > 2) {
    throw new Error(`route-backed release packet drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  assertRouteBackedDrawerFooterActions(state, `M3 release packet ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForReadinessHashCleared(page);

  await page.evaluate(() => { location.hash = "#/readiness?packet=ha-readiness-recovery"; });
  await waitForReadinessDrawer(page, ".drawer [data-release-evidence-packet='ha-readiness-recovery']");
  state = await collectRouteBackedDrawerState(page, ".drawer [data-release-evidence-packet='ha-readiness-recovery']");
  if (!/ha-readiness-recovery/.test(state.text) ||
      state.path !== "release/evidence" ||
      !state.commands.some((command) => /\bmake ha-readiness-recovery-check\b/.test(command)) ||
      !state.commands.some((command) => /release-evidence-ha-readiness-recovery/.test(command))) {
    throw new Error("route-backed release packet drawer missing HA readiness recovery path or command");
  }
  if (state.overflow > 2) {
    throw new Error(`route-backed HA release packet drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  assertRouteBackedDrawerFooterActions(state, `HA release packet ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForReadinessHashCleared(page);
}

async function resetReadinessDrawerState(page) {
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(80);
  await page.evaluate(() => {
    if (location.hash.startsWith("#/readiness")) {
      history.replaceState(null, "", "#/readiness");
    }
  });
}

async function waitForReadinessDrawer(page, selector) {
  await page.waitForFunction((sel) => {
    const el = document.querySelector(sel);
    if (!el) return false;
    const drawer = el.closest(".drawer");
    if (!drawer || drawer.hidden) return false;
    const rect = drawer.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }, selector, { timeout: 5000 });
  await page.waitForTimeout(220);
}

async function waitForReadinessHashCleared(page) {
  await page.waitForFunction(() => {
    const hash = location.hash || "";
    return hash === "#/readiness" || hash === "" || (hash.startsWith("#/readiness") && !/[?&](drawer|packet)=/.test(hash));
  }, { timeout: 5000 });
}

async function collectRouteBackedDrawerState(page, selector) {
  return await page.evaluate((sel) => {
    const root = document.querySelector(sel);
    const drawer = root?.closest?.(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const report = root?.querySelector?.("[data-readiness-system-evidence-report], [data-readiness-ha-evidence-report]")?.value || "";
    const commands = [...(root?.querySelectorAll?.("[data-release-evidence-command]") || [])].map((el) => el.textContent || "");
    const path = root?.querySelector?.("[data-release-evidence-path]")?.textContent || "";
    const footerActions = [...(drawer?.querySelectorAll?.(".drawer-footer button, .drawer-footer a.btn") || [])].map((el) => {
      const datasetKeys = Object.keys(el.dataset || {});
      return {
        tag: el.tagName.toLowerCase(),
        text: (el.textContent || "").trim(),
        type: el.getAttribute("type") || "",
        title: el.getAttribute("title") || "",
        ariaLabel: el.getAttribute("aria-label") || "",
        datasetKeys,
        hasStableHook: datasetKeys.some((key) => /action/i.test(key)),
      };
    });
    const overflow = drawer ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 0;
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: root?.textContent || "",
      report,
      commands,
      path,
      footerActions,
      overflow,
    };
  }, selector);
}

function assertRouteBackedDrawerFooterActions(state, label) {
  const invalid = (state.footerActions || []).filter((action) =>
    !action.title ||
    !action.ariaLabel ||
    !action.hasStableHook ||
    (action.tag === "button" && action.type !== "button")
  );
  if (invalid.length) {
    throw new Error(`route-backed ${label} drawer footer actions were not accessible/stable: ${JSON.stringify(invalid)}`);
  }
}

async function assertRulesBulkDensityControls(page, viewport) {
  const previousPolicy = await seedRulesWorkspaceCandidate(page);
  try {
    await page.reload({ waitUntil: "networkidle", timeout: 30000 });
    await waitForRouteReady(page, "/rules");

    const controls = await page.evaluate(() => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    const density = document.querySelector("[data-rule-control='density']");
    const group = document.querySelector("[data-rule-control='group']");
    const filterControls = document.querySelector("[data-rules-toolbar-group='filters']");
    const viewControls = document.querySelector("[data-rules-toolbar-group='view']");
    const toolbar = document.querySelector("[data-rule-bulk-toolbar='true']");
    const rulebaseMap = document.querySelector("[data-rulebase-map='true']");
    const table = document.querySelector(".rules-table");
    const selectCells = [...document.querySelectorAll("[data-rule-select='visible'], [data-rule-select='group'], [data-rule-select='row']")].filter(visible);
    const selectLabels = selectCells.map((el) => ({
      kind: el.dataset.ruleSelect || "",
      title: el.getAttribute("title") || "",
      ariaLabel: el.getAttribute("aria-label") || "",
    }));
    const mapBands = [...document.querySelectorAll("[data-rulebase-band]")].filter(visible).map((el) => ({
      state: el.dataset.rulebaseBand || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
      type: el.getAttribute("type") || "",
      title: el.getAttribute("title") || "",
      ariaLabel: el.getAttribute("aria-label") || "",
      width: el.getBoundingClientRect().width,
    }));
    const rulebaseActions = [...document.querySelectorAll("[data-rulebase-action]")].filter(visible).map((el) => ({
      action: el.dataset.rulebaseAction || "",
      type: el.getAttribute("type") || "",
      title: el.getAttribute("title") || "",
      ariaLabel: el.getAttribute("aria-label") || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const bulkButtons = [...document.querySelectorAll(".rule-bulk-actions .btn")].filter(visible).map((el) => {
      const rect = el.getBoundingClientRect();
      return {
        action: el.dataset.ruleBulkAction || "",
        text: el.textContent || "",
        type: el.getAttribute("type") || "",
        title: el.getAttribute("title") || "",
        ariaLabel: el.getAttribute("aria-label") || "",
        width: rect.width,
        height: rect.height,
      };
    });
    return {
      densityVisible: visible(density),
      densityValue: density?.value || "",
      densityLabel: density?.getAttribute("aria-label") || "",
      groupVisible: visible(group),
      groupValue: group?.value || "",
      groupLabel: group?.getAttribute("aria-label") || "",
      filterControlsVisible: visible(filterControls),
      filterControlsClass: filterControls?.className || "",
      filterControlSelects: [...(filterControls?.querySelectorAll("select") || [])].map((el) => ({ className: el.className || "", value: el.value || "" })),
      viewControlsVisible: visible(viewControls),
      viewControlsClass: viewControls?.className || "",
      viewControlSelects: [...(viewControls?.querySelectorAll("select") || [])].map((el) => ({ className: el.className || "", value: el.value || "" })),
      toolbarControlOverflow: Math.max(
        0,
        filterControls ? Math.ceil(filterControls.scrollWidth - filterControls.clientWidth) : 0,
        viewControls ? Math.ceil(viewControls.scrollWidth - viewControls.clientWidth) : 0,
      ),
      toolbarVisible: visible(toolbar),
      toolbarText: toolbar?.textContent || "",
      rulebaseMapVisible: visible(rulebaseMap),
      rulebaseMapText: (rulebaseMap?.textContent || "").replace(/\s+/g, " ").trim(),
      mapBands,
      rulebaseActions,
      tableVisible: visible(table),
      selectCellCount: selectCells.length,
      selectLabels,
      bulkButtons,
    };
  });
    if (!controls.densityVisible || !["comfortable", "compact"].includes(controls.densityValue) || !controls.groupVisible) {
      throw new Error(`rules density/group controls missing or invalid: ${JSON.stringify({ densityVisible: controls.densityVisible, densityValue: controls.densityValue, groupVisible: controls.groupVisible, groupValue: controls.groupValue })}`);
    }
    if (!controls.filterControlsVisible || !controls.filterControlsClass.includes("rules-filter-controls") || controls.filterControlSelects.length !== 3) {
      throw new Error(`rules filter control group missing or incomplete: ${JSON.stringify(controls)}`);
    }
    if (!controls.viewControlsVisible || !controls.viewControlsClass.includes("rules-view-controls") || controls.viewControlSelects.length !== 2) {
      throw new Error(`rules view control group missing or incomplete: ${JSON.stringify(controls)}`);
    }
    for (const className of ["rules-action-filter", "rules-zone-filter", "rules-tag-filter"]) {
      if (!controls.filterControlSelects.some((item) => item.className.includes(className))) {
        throw new Error(`rules toolbar filter select ${className} was missing: ${JSON.stringify(controls.filterControlSelects)}`);
      }
    }
    if (!controls.viewControlSelects.some((item) => item.className.includes("rules-density-control")) ||
        !controls.viewControlSelects.some((item) => item.className.includes("rules-group-control"))) {
      throw new Error(`rules toolbar view selects were missing stable classes: ${JSON.stringify(controls.viewControlSelects)}`);
    }
    if (controls.toolbarControlOverflow > 2) {
      throw new Error(`rules toolbar controls overflowed: ${controls.toolbarControlOverflow}px ${JSON.stringify(controls)}`);
    }
    if (!controls.toolbarVisible || !/Rule operations/.test(controls.toolbarText)) {
      throw new Error("rules bulk toolbar was not visible");
    }
    if (!controls.rulebaseMapVisible || !/Rulebase map/.test(controls.rulebaseMapText) || !/allow paths/i.test(controls.rulebaseMapText)) {
      throw new Error(`rules rulebase map missing or incomplete: ${controls.rulebaseMapText || "<empty>"}`);
    }
    if (!controls.mapBands.some((band) => band.state === "allow") || !controls.mapBands.some((band) => band.state === "review")) {
      throw new Error(`rules rulebase map missing expected bands: ${JSON.stringify(controls.mapBands)}`);
    }
    const invalidMapBands = controls.mapBands.filter((band) => band.type !== "button" || !band.ariaLabel);
    if (invalidMapBands.length) {
      throw new Error(`rules rulebase map bands missed button semantics: ${JSON.stringify(invalidMapBands)}`);
    }
    const invalidRulebaseActions = controls.rulebaseActions.filter((button) => button.type !== "button" || !button.title || button.ariaLabel !== button.title);
    if (invalidRulebaseActions.length || controls.rulebaseActions.length < 3) {
      throw new Error(`rules rulebase map actions missed explicit semantics: ${JSON.stringify(controls.rulebaseActions)}`);
    }
    if (controls.tableVisible && controls.selectCellCount < 1) {
      throw new Error("rules table did not expose selection controls");
    }
    if (controls.densityLabel !== "Rule table density" || controls.groupLabel !== "Group visible rules") {
      throw new Error(`rules density/group controls missed accessible labels: ${JSON.stringify({ densityLabel: controls.densityLabel, groupLabel: controls.groupLabel })}`);
    }
    const missingSelectionLabels = controls.selectLabels.filter((item) =>
      item.kind === "visible" ? item.ariaLabel !== "Select visible rules" :
      item.kind === "group" ? item.ariaLabel !== "Select this visible rule group" :
      item.kind === "row" ? !/^Select rule .+/.test(item.ariaLabel) :
      true);
    if (missingSelectionLabels.length) {
      throw new Error(`rules selection controls missed accessible labels: ${JSON.stringify(missingSelectionLabels)}`);
    }
    const required = ["Select visible", "Enable", "Disable", "Add tag", "Remove tag"];
    const missing = required.filter((label) => !controls.bulkButtons.some((button) => button.text.includes(label)));
    if (missing.length) {
      throw new Error(`rules bulk toolbar missing action(s): ${missing.join(", ")}`);
    }
    const invalidBulkButtons = controls.bulkButtons.filter((button) => button.type !== "button" || !button.title || button.ariaLabel !== button.title || !button.action);
    if (invalidBulkButtons.length) {
      throw new Error(`rules bulk toolbar actions missed explicit semantics: ${JSON.stringify(invalidBulkButtons)}`);
    }
    if (viewport.name === "mobile") {
      const cramped = controls.bulkButtons.filter((button) => button.width < 88 || button.height < 38);
      if (cramped.length) {
        throw new Error(`mobile rules bulk buttons too small: ${cramped.map((button) => `${button.text.trim()} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
      }
    }

    await runSmokeStep("rules baseline drawer layout", () => assertRulesBaselineDrawerLayout(page, viewport));
    await runSmokeStep("rules row evidence actions", () => assertRulesRowEvidenceActions(page, viewport));
    await runSmokeStep("rules bulk interaction", () => assertRulesBulkInteraction(page, viewport));
    await runSmokeStep("rules inspection bypass coverage", () => assertRulesInspectionBypassCoverageWorkflow(page, viewport));
    await runSmokeStep("rules lifecycle reseed", () => seedRulesWorkspaceCandidate(page));
    await runSmokeStep("rules lifecycle reload", () => page.reload({ waitUntil: "networkidle", timeout: 30000 }));
    await page.evaluate(() => { location.hash = "#/rules"; });
    await runSmokeStep("rules lifecycle route ready", () => waitForRouteReady(page, "/rules"));
    await runSmokeStep("rules manual lifecycle workflow", () => assertRulesManualLifecycleWorkflow(page, viewport));
    await runSmokeStep("rules cleanup reseed", () => seedRulesWorkspaceCandidate(page));
    await runSmokeStep("rules cleanup reload", () => page.reload({ waitUntil: "networkidle", timeout: 30000 }));
    await page.evaluate(() => { location.hash = "#/rules"; });
    await runSmokeStep("rules cleanup route ready", () => waitForRouteReady(page, "/rules"));
    await runSmokeStep("rules cleanup remediation workflow", () => assertRulesCleanupRemediationWorkflow(page, viewport));
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertObjectNatDependencyWorkflow(page, viewport) {
  const previousPolicy = await seedObjectNatCandidate(page);
  try {
    await page.reload({ waitUntil: "networkidle", timeout: 30000 });
    await waitForRouteReady(page, "/nat");
    await assertSourceNatLifecycleWorkflow(page, viewport);
    await page.reload({ waitUntil: "networkidle", timeout: 30000 });
    await waitForRouteReady(page, "/nat");
    await openDestinationNatPublishAssistant(page, viewport);
    await fillAndSaveDestinationNatPublishAssistant(page);
    await waitForDrawerClosed(page);
    await assertPublishedServiceCandidate(page);
    await assertPublishedServiceNatPreview(page, viewport);
    await assertPublishedServiceRulesRow(page, viewport);
    await assertPublishedServiceObjectReferences(page, viewport);
    await assertPublishedServiceRenameDependencyRewrite(page, viewport);
    await assertPublishedServiceDeleteCleanup(page, viewport);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertObjectsZoneInterfaceWorkflow(page, viewport) {
  const previousPolicy = await seedObjectsZoneInterfaceCandidate(page);
  try {
    await page.reload({ waitUntil: "networkidle", timeout: 30000 });
    await page.evaluate(() => { location.hash = "#/objects?tab=zones"; });
    await waitForRouteReady(page, "/objects");
    await page.waitForSelector('[data-zone-inventory="true"]', { timeout: 10000 });
    await assertZoneInterfaceInventoryVisible(page);

    await page.click('[data-object-action="new"][data-object-kind="zones"]');
    await waitForDrawerTitleStep(page, "New zone", "zone interface add drawer");
    await fillZoneEditor(page, { name: "visual-zone-check", interfaces: "eth1", description: "visual smoke duplicate check" });
    await waitForZoneReview(page, "bad", "already assigned to lan");
    await page.click('#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="zones"]');
    await waitForZoneBlockedState(page, "visual-zone-check", "already assigned to lan");

    await fillZoneEditor(page, { interfaces: "lo", description: "visual smoke loopback check" });
    await waitForZoneReview(page, "bad", "Loopback cannot be assigned");
    await page.click('#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="zones"]');
    await waitForZoneBlockedState(page, "visual-zone-check", "Loopback cannot be assigned");

    await fillZoneEditor(page, { interfaces: "future0", description: "visual smoke warning stage" });
    await waitForZoneReview(page, "warn", "future0 was not reported");
    await page.click('#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="zones"]');
    await waitForDrawerClosed(page);
    await waitForZoneCandidateOnly(page, "visual-zone-check", "future0");
    await assertSavedZonePosture(page, viewport, "visual-zone-check", "review");
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertObjectsGenericLifecycleParity(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const names = {
    addressReferenced: `visual-ref-address-${marker}`,
    addressUnreferenced: `visual-free-address-${marker}`,
    addressDuplicate: `visual-dup-address-${marker}`,
    addressAdded: `visual-added-address-${marker}`,
    addressEdited: `visual-edited-address-${marker}`,
    applicationReferenced: `visual-ref-app-${marker}`,
    applicationUnreferenced: `visual-free-app-${marker}`,
    applicationDuplicate: `visual-dup-app-${marker}`,
    applicationAdded: `visual-added-app-${marker}`,
    applicationEdited: `visual-edited-app-${marker}`,
    profileReferenced: `visual-ref-profile-${marker}`,
    profileUnreferenced: `visual-free-profile-${marker}`,
    profileDuplicate: `visual-dup-profile-${marker}`,
    profileAdded: `visual-added-profile-${marker}`,
    profileEdited: `visual-edited-profile-${marker}`,
    rule: `visual-object-lifecycle-rule-${marker}`,
  };
  try {
    const runningFingerprint = await seedObjectsGenericLifecycleCandidate(page, names);
    await page.reload({ waitUntil: "networkidle", timeout: 30000 });
    await waitForRouteReady(page, "/objects");

    await assertObjectReferencedDeleteReview(page, viewport, "addresses", "address", names.addressReferenced, [
      "security rule",
      names.rule,
      "source address",
      "candidate policy reference",
    ]);
    await assertObjectRouteDrawerState(page, viewport, "addresses", "references", names.addressReferenced, [
      names.addressReferenced,
      "candidate policy reference",
      "security rule",
      names.rule,
      "Open rule",
    ]);
    await assertObjectDuplicateGuard(page, viewport, "addresses", "address", names.addressDuplicate, {
      name: names.addressDuplicate,
      cidr: "10.77.0.10/32",
      description: "attempted duplicate address",
    });
    await assertObjectAddEditDeleteLifecycle(page, viewport, "addresses", "address", {
      added: names.addressAdded,
      edited: names.addressEdited,
      unreferenced: names.addressUnreferenced,
      addValues: { name: names.addressAdded, cidr: "10.77.0.20/32", description: "visual smoke address add" },
      editValues: { name: names.addressEdited, cidr: "10.77.0.21/32", description: "visual smoke address edit" },
    }, runningFingerprint);

    await switchObjectsTab(page, "applications");
    await assertObjectReferencedDeleteReview(page, viewport, "applications", "application", names.applicationReferenced, [
      "security rule",
      names.rule,
      "application",
      "candidate policy reference",
    ]);
    await assertObjectRouteDrawerState(page, viewport, "applications", "references", names.applicationReferenced, [
      names.applicationReferenced,
      "candidate policy reference",
      "security rule",
      names.rule,
      "Open rule",
    ]);
    await assertObjectDuplicateGuard(page, viewport, "applications", "application", names.applicationDuplicate, {
      name: names.applicationDuplicate,
      displayName: "Visual Duplicate App",
      category: "business-app",
      engineSignals: "visual-dup-app",
      tcpPorts: "9443",
      udpPorts: "",
      description: "attempted duplicate application",
    });
    await assertObjectAddEditDeleteLifecycle(page, viewport, "applications", "application", {
      added: names.applicationAdded,
      edited: names.applicationEdited,
      unreferenced: names.applicationUnreferenced,
      addValues: {
        name: names.applicationAdded,
        displayName: "Visual Added App",
        category: "business-app",
        engineSignals: names.applicationAdded,
        tcpPorts: "9443",
        udpPorts: "",
        description: "visual smoke application add",
      },
      editValues: {
        name: names.applicationEdited,
        displayName: "Visual Edited App",
        category: "admin-app",
        engineSignals: names.applicationEdited,
        tcpPorts: "9444",
        udpPorts: "",
        description: "visual smoke application edit",
      },
    }, runningFingerprint);

    await switchObjectsTab(page, "securityProfiles");
    await assertSecurityProfileReferencedImpactRoute(page, viewport, names.profileReferenced, names.rule);
    await assertObjectReferencedDeleteReview(page, viewport, "securityProfiles", "security profile", names.profileReferenced, [
      "security rule",
      names.rule,
      "security profile",
      "candidate policy reference",
    ]);
    await assertObjectDuplicateGuard(page, viewport, "securityProfiles", "security profile", names.profileDuplicate, {
      name: names.profileDuplicate,
      tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
      urlCategories: "malware",
      dnsSecurity: "DNS_SECURITY_MODE_LOG_ONLY",
      fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
      description: "attempted duplicate security profile",
    });
    await assertObjectAddEditDeleteLifecycle(page, viewport, "securityProfiles", "security profile", {
      added: names.profileAdded,
      edited: names.profileEdited,
      unreferenced: names.profileUnreferenced,
      addValues: {
        name: names.profileAdded,
        tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
        urlCategories: "malware, phishing",
        dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
        fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
        description: "visual smoke security profile add",
      },
      editValues: {
        name: names.profileEdited,
        tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
        urlCategories: "malware, phishing, command-and-control",
        dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
        fileSecurity: "FILE_SECURITY_MODE_BLOCK_EXECUTABLES",
        description: "visual smoke security profile edit",
      },
    }, runningFingerprint);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertSecurityProfileImpactWorkbench(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const profileName = `visual-impact-profile-${marker}`;
  const ruleName = `visual-impact-allow-${marker}`;
  try {
    await page.evaluate(async ({ profileName, ruleName }) => {
      const policy = {
        zones: [
          { name: "lan", interfaces: ["eth1"], description: "Visual smoke LAN zone." },
          { name: "wan", interfaces: ["eth0"], description: "Visual smoke WAN zone." },
        ],
        addresses: [
          { name: "inside-net", cidr: "10.0.0.0/24" },
          { name: "internet", cidr: "0.0.0.0/0" },
        ],
        services: [{ name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }],
        applications: [],
        securityProfiles: [{
          name: profileName,
          tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
          urlCategories: ["malware", "phishing"],
          dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
          fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
          description: "Visual smoke layered inspection intent.",
        }],
        ids: {
          enabled: true,
          mode: "IDS_MODE_PREVENT",
          failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
        },
        rules: [{
          name: ruleName,
          fromZones: ["lan"],
          toZones: ["wan"],
          sourceAddresses: ["inside-net"],
          destinationAddresses: ["internet"],
          services: ["https"],
          applications: ["any"],
          securityProfiles: [profileName],
          action: "ACTION_ALLOW",
          log: true,
          description: "Visual smoke security profile impact rule.",
        }],
        nat: { source: [], destination: [] },
      };
      const response = await fetch("/v1/candidate", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ policy }),
      });
      if (!response.ok) {
        throw new Error(`seed security profile impact candidate failed with HTTP ${response.status}: ${await response.text()}`);
      }
      localStorage.removeItem("phragma.investigation.case.v1");
      globalThis.__securityProfileImpactCopiedText = "";
      try {
        Object.defineProperty(navigator, "clipboard", {
          configurable: true,
          value: {
            writeText: async (text) => {
              globalThis.__securityProfileImpactCopiedText = String(text || "");
            },
          },
        });
      } catch {}
      location.hash = `#/objects?tab=securityProfiles&drawer=impact&object=${encodeURIComponent(profileName)}`;
    }, { profileName, ruleName });
    await waitForRouteReady(page, "/objects");
    const impactButton = await page.evaluate((profileName) => {
      const button = document.querySelector(`[data-object-action="impact"][data-object-kind="securityProfiles"][data-object-name="${CSS.escape(profileName)}"]`);
      const rect = button?.getBoundingClientRect?.();
      return {
        present: Boolean(button),
        className: button?.className || "",
        title: button?.getAttribute("title") || "",
        ariaLabel: button?.getAttribute("aria-label") || "",
        type: button?.getAttribute("type") || "",
        width: rect?.width || 0,
        height: rect?.height || 0,
      };
    }, profileName);
    if (!impactButton.present ||
        !impactButton.className.includes("icon-btn") ||
        impactButton.title !== "Review security profile impact" ||
        impactButton.ariaLabel !== `Review security profile impact for ${profileName}` ||
        impactButton.type !== "button" ||
        impactButton.width < 34 ||
        impactButton.height < 34) {
      throw new Error(`security profile impact button was not accessible at ${viewport.name}: ${JSON.stringify(impactButton)}`);
    }
	    await waitForDrawerTitle(page, "Security profile impact");
    const drawer = await collectDrawerState(page);
    assertDrawerContains(drawer, viewport, "security profile impact", [
      profileName,
      ruleName,
      "Affected rules",
      "Active allow",
      "blocking intent",
      "IPS fail-closed",
      "profile enforced",
      "Open rule",
    ], ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
    assertNoInvestigationLeak(drawer.text, `security profile impact drawer ${viewport.name}`);

    await clickDrawerFooterButton(page, "Copy handoff");
    await page.waitForFunction(() => Boolean(globalThis.__securityProfileImpactCopiedText), null, { timeout: 5000 });
    const copied = await page.evaluate(() => globalThis.__securityProfileImpactCopiedText || "");
    if (!copied.includes("Security profile impact") || !copied.includes(profileName) || !copied.includes(ruleName) || !copied.includes("profile enforced")) {
      throw new Error(`security profile impact handoff copy missed expected evidence: ${copied}`);
    }
    assertNoInvestigationLeak(copied, `security profile impact copy ${viewport.name}`);

    await clickDrawerFooterButton(page, "Pin to case");
    const pinned = await page.evaluate(() => {
      const raw = localStorage.getItem("phragma.investigation.case.v1") || "";
      let parsed = {};
      try { parsed = JSON.parse(raw || "{}"); } catch {}
      const packet = (parsed.items || []).find((item) => item.packet?.kind === "security-profile-impact")?.packet || null;
      return {
        raw,
        schemaVersion: parsed.schemaVersion || "",
        title: packet?.title || "",
        kind: packet?.kind || "",
        route: packet?.source?.route || "",
      };
    });
    if (pinned.schemaVersion !== "phragma.investigation.case.v1" ||
        pinned.kind !== "security-profile-impact" ||
        !pinned.title.includes(profileName) ||
        !pinned.route.includes("drawer=impact")) {
      throw new Error(`security profile impact pin-to-case failed at ${viewport.name}: ${pinned.raw}`);
    }
    assertNoInvestigationLeak(pinned.raw, `security profile impact pin ${viewport.name}`);

    await clickDrawerFooterButton(page, "API / CLI");
    await waitForDrawerTitle(page, "API / CLI context");
    const contextDrawer = await collectDrawerState(page);
    assertDrawerContains(contextDrawer, viewport, "security profile impact API / CLI context", [
      "API / CLI context",
      "#/objects?tab=securityProfiles&drawer=impact",
      profileName,
      "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SECURITY_PROFILE",
      "/v1/policy?source=POLICY_SOURCE_CANDIDATE",
      "/v1/candidate/validate",
      "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE",
      "ngfwctl policy references --source candidate --kind security-profile --name",
      "ngfwctl policy validate",
      "ngfwctl policy diff",
      "candidate rule blast radius",
      "remain hardening evidence",
    ], ["Copy session JSON", "Copy context"]);
    assertAutomationContextRedaction(contextDrawer.text, `security profile impact API / CLI drawer ${viewport.name}`);

    await page.evaluate((profileName) => {
      location.hash = `#/objects?tab=securityProfiles&drawer=impact&object=${encodeURIComponent(profileName)}`;
    }, profileName);
    await waitForRouteReady(page, "/objects");
    await waitForDrawerTitle(page, "Security profile impact");

    const ruleHash = await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const target = [...(drawer?.querySelectorAll("a") || [])]
        .find((link) => (link.textContent || "").replace(/\s+/g, " ").trim() === "Open rule");
      if (!target) throw new Error("security profile impact Open rule link was not found");
      target.click();
      return location.hash || "";
    });
    await waitForRouteReady(page, "/rules");
    if (!ruleHash.includes(`rule=${encodeURIComponent(ruleName)}`)) {
      throw new Error(`security profile impact Open rule route mismatch at ${viewport.name}: ${ruleHash}`);
    }
    assertNoInvestigationLeak(ruleHash, `security profile impact rule route ${viewport.name}`);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertObjectsAppIdPortHintHygiene(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const signalOnly = `visual-signal-only-${marker}`;
  const portScoped = `visual-port-app-${marker}`;
  try {
    await page.evaluate(async ({ signalOnly, portScoped }) => {
      const policy = {
        zones: [],
        addresses: [],
        services: [],
        applications: [
          {
            name: signalOnly,
            displayName: "Visual Signal Only",
            category: "business-app",
            engineSignals: [signalOnly],
            ports: [],
            description: "Visual smoke App-ID classification without an enforceable port hint.",
          },
          {
            name: portScoped,
            displayName: "Visual Port Scoped",
            category: "business-app",
            engineSignals: [portScoped],
            ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
            description: "Visual smoke App-ID with enforceable port hint.",
          },
        ],
        securityProfiles: [],
        rules: [],
        nat: { source: [], destination: [] },
      };
      const response = await fetch("/v1/candidate", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ policy }),
      });
      if (!response.ok) {
        throw new Error(`seed Objects App-ID hygiene candidate failed with HTTP ${response.status}: ${await response.text()}`);
      }
      location.hash = "#/objects?tab=applications";
    }, { signalOnly, portScoped });
    await waitForRouteReady(page, "/objects");
    await page.waitForSelector(".object-hygiene", { timeout: 10000 });
    const hygiene = await page.evaluate(() => {
      const panel = document.querySelector(".object-hygiene");
      return {
        text: (panel?.textContent || "").replace(/\s+/g, " ").trim(),
        overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
      };
    });
    for (const expected of [
      "App-ID without port hints",
      signalOnly,
      "enforcement requires either TCP/UDP port hints or a supported IDS/IPS signal",
    ]) {
      if (!hygiene.text.includes(expected)) {
        throw new Error(`Objects App-ID hygiene missing ${expected} at ${viewport.name}: ${hygiene.text}`);
      }
    }
    if (hygiene.text.includes(`${portScoped} can classify traffic`)) {
      throw new Error(`Objects App-ID hygiene incorrectly flagged port-scoped App-ID at ${viewport.name}: ${hygiene.text}`);
    }
    if (hygiene.overflow > 2) {
      throw new Error(`Objects App-ID hygiene overflow at ${viewport.name}: ${hygiene.overflow}px`);
    }
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertObjectsMissingRouteReview(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/objects?tab=services&drawer=references&object=missing-service-route";
  });
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, "Object references");
  const refs = await collectDrawerState(page);
  assertDrawerContains(refs, viewport, "missing object reference route", [
    "Service not found",
    "missing-service-route",
    "shared route may be stale",
    "No remaining references",
    "Back to Objects",
  ], ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
  assertNoInvestigationLeak(refs.text, `missing object reference route ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);

  await page.evaluate(() => {
    location.hash = "#/objects?tab=securityProfiles&drawer=impact&object=missing-profile-route";
  });
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, "Security profile impact");
  const impact = await collectDrawerState(page);
  assertDrawerContains(impact, viewport, "missing security profile impact route", [
    "Security profile not found",
    "missing-profile-route",
    "shared route may be stale",
    "No impact can be computed",
    "Back to Objects",
  ], ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
  assertNoInvestigationLeak(impact.text, `missing security profile impact route ${viewport.name}`);
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function seedObjectsGenericLifecycleCandidate(page, names) {
  return await page.evaluate(async (names) => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before Objects lifecycle seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const runningPolicy = (await running.json())?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"], description: "Visual smoke LAN zone." },
        { name: "wan", interfaces: ["eth0"], description: "Visual smoke WAN zone." },
      ],
      addresses: [
        { name: names.addressReferenced, cidr: "10.77.0.5/32", description: "referenced address delete review" },
        { name: names.addressUnreferenced, cidr: "10.77.0.6/32", description: "unreferenced address delete" },
        { name: names.addressDuplicate, cidr: "10.77.0.7/32", description: "duplicate address guard" },
      ],
      services: [{ name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }],
      applications: [
        {
          name: names.applicationReferenced,
          displayName: "Visual Referenced App",
          category: "business-app",
          engineSignals: [names.applicationReferenced],
          ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 9443 }] }],
          description: "referenced application delete review",
        },
        {
          name: names.applicationUnreferenced,
          displayName: "Visual Free App",
          category: "business-app",
          engineSignals: [names.applicationUnreferenced],
          ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 9444 }] }],
          description: "unreferenced application delete",
        },
        {
          name: names.applicationDuplicate,
          displayName: "Visual Duplicate App",
          category: "business-app",
          engineSignals: ["visual-dup-app"],
          ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 9445 }] }],
          description: "duplicate application guard",
        },
      ],
      securityProfiles: [
        {
          name: names.profileReferenced,
          tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
          urlCategories: ["malware"],
          dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
          fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
          description: "referenced security profile impact review",
        },
        {
          name: names.profileUnreferenced,
          tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
          urlCategories: [],
          dnsSecurity: "DNS_SECURITY_MODE_LOG_ONLY",
          fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
          description: "unreferenced security profile delete",
        },
        {
          name: names.profileDuplicate,
          tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
          urlCategories: ["malware"],
          dnsSecurity: "DNS_SECURITY_MODE_LOG_ONLY",
          fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
          description: "duplicate security profile guard",
        },
      ],
      ids: {
        enabled: true,
        mode: "IDS_MODE_PREVENT",
        failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
      },
      rules: [{
        name: names.rule,
        fromZones: ["lan"],
        toZones: ["wan"],
        sourceAddresses: [names.addressReferenced],
        destinationAddresses: ["any"],
        services: ["https"],
        applications: [names.applicationReferenced],
        securityProfiles: [names.profileReferenced],
        action: "ACTION_ALLOW",
        log: true,
        description: "Visual smoke generic object lifecycle reference.",
      }],
      nat: { source: [], destination: [] },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed Objects lifecycle candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    location.hash = "#/objects?tab=addresses";
    return stable(runningPolicy);
  }, names);
}

async function assertObjectReferencedDeleteReview(page, viewport, kind, labelKind, name, requiredText) {
  await switchObjectsTab(page, kind);
  await page.click(`[data-object-action="delete"][data-object-kind="${kind}"][data-object-name="${name}"]`);
  await waitForDrawerTitleStep(page, `Delete ${labelKind}?`, `${labelKind} referenced delete review`);
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, `${labelKind} referenced delete review`, [
    name,
    "referenced by",
    ...requiredText,
  ], ["Cancel", "Delete"]);
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
  await assertObjectCandidatePresence(page, kind, name, true);
}

async function assertObjectRouteDrawerState(page, viewport, kind, drawerKind, name, requiredText) {
  const route = drawerKind === "impact"
    ? `#/objects?tab=${encodeURIComponent(kind)}&drawer=impact&object=${encodeURIComponent(name)}`
    : `#/objects?tab=${encodeURIComponent(kind)}&drawer=references&object=${encodeURIComponent(name)}`;
  await page.evaluate((route) => { location.hash = route; }, route);
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, drawerKind === "impact" ? "Security profile impact" : "Object references");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, `${kind} ${drawerKind} route state`, requiredText, drawerKind === "impact"
    ? ["Close", "Pin to case", "Copy handoff", "Export JSON"]
    : ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await page.waitForFunction((kind) => {
    const hash = location.hash || "";
    if (kind === "addresses" && (hash === "#/objects" || hash === "#/objects?")) return true;
    return hash === `#/objects?tab=${kind}` || hash === `#/objects?tab=${encodeURIComponent(kind)}`;
  }, kind, { timeout: 5000 });
}

async function assertSecurityProfileReferencedImpactRoute(page, viewport, profileName, ruleName) {
  await assertObjectRouteDrawerState(page, viewport, "securityProfiles", "impact", profileName, [
    profileName,
    ruleName,
    "Affected rules",
    "candidate only",
    "profile enforced",
    "Open rule",
  ]);
}

async function assertObjectDuplicateGuard(page, viewport, kind, labelKind, existingName, values) {
  await switchObjectsTab(page, kind);
  const before = await objectPolicyCount(page, kind, existingName);
  await page.click(`[data-object-action="new"][data-object-kind="${kind}"]`);
  await waitForDrawerTitleStep(page, `New ${labelKind}`, `${labelKind} duplicate add drawer`);
  await fillObjectEditor(page, kind, values);
  await page.click(`#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="${kind}"]`);
  await page.waitForFunction((existingName) => {
    const toastText = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
    return toastText.includes("Name already exists") && toastText.includes(existingName) &&
      Boolean(document.querySelector("#drawer:not([hidden])"));
  }, existingName, { timeout: 10000 });
  const after = await objectPolicyCount(page, kind, existingName);
  if (before !== 1 || after !== 1) {
    throw new Error(`${labelKind} duplicate guard changed candidate count at ${viewport.name}: before=${before} after=${after}`);
  }
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
}

async function assertObjectAddEditDeleteLifecycle(page, viewport, kind, labelKind, spec, runningFingerprint) {
  await switchObjectsTab(page, kind);
  await page.click(`[data-object-action="new"][data-object-kind="${kind}"]`);
  await waitForDrawerTitleStep(page, `New ${labelKind}`, `${labelKind} add drawer`);
  await fillObjectEditor(page, kind, spec.addValues);
  await page.click(`#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="${kind}"]`);
  await waitForDrawerClosed(page);
  await waitForObjectLifecycleState(page, `${labelKind} add`, kind, runningFingerprint, {
    present: [spec.added],
    runningAbsent: [spec.added],
    object: objectLifecyclePayload(kind, spec.addValues),
  });

  await page.click(`[data-object-action="edit"][data-object-kind="${kind}"][data-object-name="${spec.added}"]`);
  await waitForDrawerTitleStep(page, `Edit ${labelKind}`, `${labelKind} edit drawer`);
  await fillObjectEditor(page, kind, spec.editValues);
  await page.click(`#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="${kind}"]`);
  await waitForDrawerClosed(page);
  await waitForObjectLifecycleState(page, `${labelKind} edit`, kind, runningFingerprint, {
    present: [spec.edited],
    absent: [spec.added],
    runningAbsent: [spec.edited],
    object: objectLifecyclePayload(kind, spec.editValues),
  });

  await page.click(`[data-object-action="delete"][data-object-kind="${kind}"][data-object-name="${spec.unreferenced}"]`);
  await waitForDrawerTitleStep(page, `Delete ${labelKind}?`, `${labelKind} unreferenced delete confirmation`);
  const deleteReview = await collectDrawerState(page);
  assertDrawerContains(deleteReview, viewport, `${labelKind} unreferenced delete`, [
    spec.unreferenced,
    `Delete "${spec.unreferenced}"?`,
  ], ["Cancel", "Delete"]);
  await clickDrawerFooterButton(page, "Delete");
  await waitForDrawerClosed(page);
  await waitForObjectLifecycleState(page, `${labelKind} delete`, kind, runningFingerprint, {
    present: [spec.edited],
    absent: [spec.unreferenced],
    runningAbsent: [spec.unreferenced],
    object: objectLifecyclePayload(kind, spec.editValues),
  });
}

async function switchObjectsTab(page, kind) {
  await page.evaluate((kind) => { location.hash = `#/objects?tab=${encodeURIComponent(kind)}`; }, kind);
  await waitForRouteReady(page, "/objects");
  await page.waitForFunction((kind) => {
    const active = document.querySelector(`[data-object-tab="${kind}"].active`);
    const newButton = document.querySelector(`[data-object-action="new"][data-object-kind="${kind}"]`);
    return Boolean(active && newButton);
  }, kind, { timeout: 10000 });
}

async function fillObjectEditor(page, kind, values = {}) {
  await page.evaluate(({ kind, values }) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error(`${kind} object editor drawer was not open`);
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const labelControl = (label) => {
      const field = [...drawer.querySelectorAll("label.field")]
        .find((candidate) => textOf(candidate.querySelector("span")).startsWith(label));
      const control = field?.querySelector("input, select, textarea");
      if (!control) throw new Error(`${kind} object editor field ${label} was not found`);
      return control;
    };
    const setControl = (control, value) => {
      control.value = String(value ?? "");
      control.dispatchEvent(new Event(control.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
      if (control.value !== String(value ?? "")) {
        throw new Error(`${kind} object editor field did not accept ${value}`);
      }
    };
    const setLabel = (label, value) => {
      if (value === undefined) return;
      setControl(labelControl(label), value);
    };
    const setSecurityProfileField = (field, value) => {
      if (value === undefined) return;
      const control = drawer.querySelector(`[data-security-profile-field="${field}"]`);
      if (!control) throw new Error(`security profile field ${field} was not found`);
      setControl(control, value);
    };

    if (kind === "addresses") {
      setLabel("Name", values.name);
      setLabel("CIDR", values.cidr);
      setLabel("Description", values.description);
      return;
    }
    if (kind === "applications") {
      setLabel("App-ID", values.name);
      setLabel("Display name", values.displayName);
      setLabel("Category", values.category);
      setLabel("Inspection signals", values.engineSignals);
      setLabel("TCP ports", values.tcpPorts);
      setLabel("UDP ports", values.udpPorts);
      setLabel("Description", values.description);
      return;
    }
    if (kind === "securityProfiles") {
      setSecurityProfileField("name", values.name);
      setSecurityProfileField("tls-inspection", values.tlsInspection);
      setSecurityProfileField("url-categories", values.urlCategories);
      setSecurityProfileField("dns-security", values.dnsSecurity);
      setSecurityProfileField("file-security", values.fileSecurity);
      setSecurityProfileField("description", values.description);
    }
  }, { kind, values });
}

function objectLifecyclePayload(kind, values = {}) {
  if (kind !== "applications") return null;
  return {
    name: String(values.name || ""),
    displayName: String(values.displayName || ""),
    category: String(values.category || ""),
    engineSignals: String(values.engineSignals || "").split(",").map((value) => value.trim()).filter(Boolean),
    description: String(values.description || ""),
  };
}

async function objectPolicyCount(page, kind, name) {
  return await page.evaluate(async ({ kind, name }) => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (!response.ok) throw new Error(`read candidate for object count failed with HTTP ${response.status}: ${await response.text()}`);
    const policy = (await response.json())?.policy || {};
    return (policy[kind] || []).filter((item) => item?.name === name).length;
  }, { kind, name });
}

async function assertObjectCandidatePresence(page, kind, name, expected) {
  const count = await objectPolicyCount(page, kind, name);
  if (expected && count !== 1) throw new Error(`${kind}/${name} was not present in candidate exactly once; count=${count}`);
  if (!expected && count !== 0) throw new Error(`${kind}/${name} was unexpectedly present in candidate; count=${count}`);
}

async function waitForObjectLifecycleState(page, label, kind, runningFingerprint, expected = {}) {
  await page.waitForFunction(async ({ kind, runningFingerprint, expected }) => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok) return false;
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const state = {
      names: (candidate[kind] || []).map((item) => item?.name || ""),
      runningText: JSON.stringify(running),
      runningFingerprint: stable(running),
    };
    if (state.runningFingerprint !== runningFingerprint) return false;
    const expectedObject = expected.object || null;
    const candidateObject = expectedObject
      ? (candidate[kind] || []).find((item) => item?.name === expectedObject.name)
      : null;
    const objectMatches = !expectedObject || (Boolean(candidateObject) && Object.entries(expectedObject)
      .every(([key, value]) => stable(candidateObject[key]) === stable(value)));
    return (expected.present || []).every((name) => state.names.includes(name)) &&
      (expected.absent || []).every((name) => !state.names.includes(name)) &&
      (expected.runningAbsent || []).every((name) => !state.runningText.includes(name)) &&
      objectMatches;
  }, { kind, runningFingerprint, expected }, { timeout: 10000 }).catch(async (error) => {
    const state = await page.evaluate(async (kind) => {
      const [candidateResponse, runningResponse] = await Promise.all([
        fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
        fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      ]);
      const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
      const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
      return {
        names: (candidate[kind] || []).map((item) => item?.name || ""),
        objects: (candidate[kind] || []).filter((item) => item?.name),
        runningText: JSON.stringify(running),
      };
    }, kind);
    throw new Error(`${label} lifecycle state did not settle: ${error.message}; state=${JSON.stringify(state)}`);
  });
}

async function seedObjectsZoneInterfaceCandidate(page) {
  return await page.evaluate(async () => {
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before Objects zone seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const previousPolicy = (await running.json())?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"], description: "Visual smoke LAN zone." },
        { name: "guest", interfaces: ["eth2"], description: "Visual smoke guest zone." },
      ],
      addresses: [],
      services: [],
      applications: [],
      securityProfiles: [],
      rules: [],
      nat: { source: [], destination: [] },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed Objects zone candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return previousPolicy;
  });
}

async function assertZoneInterfaceInventoryVisible(page) {
  const inventory = await page.evaluate(() => {
    const panel = document.querySelector('[data-zone-inventory="true"]');
    const chips = [...document.querySelectorAll("[data-zone-interface]")].map((chip) => ({
      name: chip.dataset.zoneInterface || "",
      text: (chip.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    return {
      text: (panel?.textContent || "").replace(/\s+/g, " ").trim(),
      chips,
    };
  });
  if (!inventory.text.includes("Zone interface inventory")) {
    throw new Error(`Objects zones inventory panel was not visible: ${inventory.text}`);
  }
  if (!inventory.chips.length) {
    throw new Error(`Objects zones inventory had no live host interfaces: ${inventory.text}`);
  }
}

async function fillZoneEditor(page, fields = {}) {
  await page.evaluate((values) => {
    const root = document.querySelector('[data-zone-editor="true"]');
    if (!root) throw new Error("zone editor was not open");
    const setField = (name, value) => {
      if (value == null) return;
      const input = root.querySelector(`[data-zone-field="${name}"]`);
      if (!input) throw new Error(`zone editor field ${name} was not found`);
      input.value = String(value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setField("name", values.name);
    setField("interfaces", values.interfaces);
    setField("description", values.description);
  }, fields);
}

async function waitForZoneReview(page, severity, needle) {
  await page.waitForFunction(({ expectedSeverity, textNeedle }) => {
    const review = document.querySelector('[data-zone-review="editor"]');
    const text = (review?.textContent || "").replace(/\s+/g, " ").trim();
    return review?.dataset?.zoneReviewSeverity === expectedSeverity && text.includes(textNeedle);
  }, { expectedSeverity: severity, textNeedle: needle }, { timeout: 5000 });
}

async function waitForZoneBlockedState(page, zoneName, needle) {
  await page.waitForFunction(({ name, textNeedle }) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const review = drawer?.querySelector('[data-zone-review="editor"]');
    const reviewText = (review?.textContent || "").replace(/\s+/g, " ").trim();
    const input = drawer?.querySelector('[data-zone-field="name"]');
    return Boolean(drawer) &&
      input?.value === name &&
      review?.dataset?.zoneReviewSeverity === "bad" &&
      reviewText.includes(textNeedle);
  }, { name: zoneName, textNeedle: needle }, { timeout: 5000 });
  const staged = await zonePolicyState(page, zoneName);
  if (staged.candidateZone || staged.runningZone) {
    throw new Error(`blocked zone ${zoneName} staged unexpectedly: ${JSON.stringify(staged)}`);
  }
}

async function waitForZoneCandidateOnly(page, zoneName, iface) {
  await page.waitForFunction(async ({ name, interfaceName }) => {
    const candidate = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    const status = await fetch("/v1/candidate/status");
    if (!candidate.ok || !running.ok || !status.ok) return false;
    const candidateZone = ((await candidate.json())?.policy?.zones || []).find((zone) => zone.name === name);
    const runningZone = ((await running.json())?.policy?.zones || []).find((zone) => zone.name === name);
    const statusBody = await status.json();
    return Boolean(candidateZone) &&
      (candidateZone.interfaces || []).includes(interfaceName) &&
      !runningZone &&
      Boolean(statusBody.dirty) &&
      Boolean(statusBody.hasCandidate || statusBody.has_candidate);
  }, { name: zoneName, interfaceName: iface }, { timeout: 8000 });
}

async function zonePolicyState(page, zoneName) {
  return await page.evaluate(async (name) => {
    const readPolicy = async (source) => {
      const response = await fetch(`/v1/policy?source=${source}`);
      if (!response.ok) return {};
      return (await response.json())?.policy || {};
    };
    const candidate = await readPolicy("POLICY_SOURCE_CANDIDATE");
    const running = await readPolicy("POLICY_SOURCE_RUNNING");
    return {
      candidateZone: (candidate.zones || []).find((zone) => zone.name === name) || null,
      runningZone: (running.zones || []).find((zone) => zone.name === name) || null,
    };
  }, zoneName);
}

async function assertSavedZonePosture(page, viewport, zoneName, expectedPosture) {
  const state = await page.evaluate((name) => {
    const row = document.querySelector(`[data-zone-row="${CSS.escape(name)}"]`);
    const posture = row?.querySelector("[data-zone-posture]");
    const rect = row?.getBoundingClientRect?.();
    const overflow = row ? Math.max(0, Math.ceil(row.scrollWidth - row.clientWidth)) : 0;
    return {
      text: (row?.textContent || "").replace(/\s+/g, " ").trim(),
      posture: posture?.dataset?.zonePosture || "",
      width: rect?.width || 0,
      overflow,
    };
  }, zoneName);
  if (!state.text.includes(zoneName) || !state.text.includes("future0")) {
    throw new Error(`saved zone row did not show staged warning interface: ${JSON.stringify(state)}`);
  }
  if (state.posture !== expectedPosture) {
    throw new Error(`saved zone posture=${state.posture || "<missing>"} want ${expectedPosture}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`saved zone row overflow at ${viewport.name}: ${state.overflow}px`);
  }
}

async function seedObjectNatCandidate(page) {
  return await page.evaluate(async () => {
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before object/NAT seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const previousPolicy = (await running.json())?.policy || {};
    const policy = {
      zones: [
        { name: "untrust", interfaces: ["eth0"] },
        { name: "dmz", interfaces: ["eth2"] },
        { name: "trust", interfaces: ["eth1"] },
      ],
      addresses: [
        { name: "mgmt-net", cidr: "10.10.0.0/24" },
        { name: "internet", cidr: "0.0.0.0/0" },
        { name: "egress-public-ip", cidr: "198.51.100.50/32" },
      ],
      services: [
        { name: "ssh", protocol: "PROTOCOL_TCP", ports: [{ start: 22 }] },
      ],
      rules: [
        {
          name: "drop-inbound-default",
          fromZones: ["untrust"],
          toZones: ["dmz"],
          sourceAddresses: [],
          destinationAddresses: [],
          services: [],
          applications: [],
          action: "ACTION_DENY",
          log: true,
          disabled: false,
          description: "Visual smoke default inbound guardrail.",
        },
        {
          name: "allow-trust-outbound",
          fromZones: ["trust"],
          toZones: ["untrust"],
          sourceAddresses: ["mgmt-net"],
          destinationAddresses: ["internet"],
          services: [],
          applications: [],
          action: "ACTION_ALLOW",
          log: true,
          disabled: false,
          description: "Visual smoke outbound path for source NAT preview.",
        },
      ],
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed object/NAT candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return previousPolicy;
  });
}

async function assertSourceNatLifecycleWorkflow(page, viewport) {
  const before = await sourceNatLifecycleState(page);
  await assertNatActionControls(page, viewport, "NAT route add actions", ["add-source", "add-destination"]);
  await page.click('[data-nat-action="add-source"]');
  await waitForDrawerTitleStep(page, "Add source NAT", "source NAT add drawer");
  await assertNatActionControls(page, viewport, "source NAT add drawer", ["save-source"]);
  await fillSourceNatEditor(page, {
    name: "visual-snat",
    egressZone: "untrust",
    sourceAddress: "mgmt-net",
    mode: "masquerade",
  });
  await page.click('#drawer:not([hidden]) [data-nat-action="save-source"]');
  await waitForDrawerClosed(page);
  await waitForSourceNatLifecycleState(page, "add masquerade", (state) => {
    const rule = state.candidate.source.find((item) => item.name === "visual-snat");
    return Boolean(rule) &&
      rule.toZone === "untrust" &&
      rule.sourceAddress === "mgmt-net" &&
      rule.masquerade === true &&
      state.status.dirty === true &&
      state.status.natChanged === true &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes("visual-snat") &&
      state.previewText.includes("Source NAT visual-snat staged in candidate");
  });

  await page.click('[data-nat-action="edit-source"][data-nat-rule-name="visual-snat"]');
  await waitForDrawerTitleStep(page, "Edit source NAT", "source NAT edit drawer");
  await assertNatActionControls(page, viewport, "source NAT edit drawer", ["save-source"]);
  await fillSourceNatEditor(page, {
    name: "visual-snat-edited",
    egressZone: "untrust",
    sourceAddress: "mgmt-net",
    mode: "static",
    translatedAddress: "egress-public-ip",
  });
  await page.click('#drawer:not([hidden]) [data-nat-action="save-source"]');
  await waitForDrawerClosed(page);
  await waitForSourceNatLifecycleState(page, "edit static", (state) => {
    const rule = state.candidate.source.find((item) => item.name === "visual-snat-edited");
    return Boolean(rule) &&
      rule.toZone === "untrust" &&
      rule.sourceAddress === "mgmt-net" &&
      rule.translatedAddress === "egress-public-ip" &&
      !rule.masquerade &&
      state.previewSourceAction &&
      !state.candidate.source.some((item) => item.name === "visual-snat") &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes("visual-snat-edited") &&
      state.previewText.includes("Source NAT visual-snat-edited edited in candidate");
  });
  const sourceActionState = await sourceNatLifecycleState(page);
  assertNatRowActionButtons(sourceActionState.sourceActionButtons, "source NAT row actions");
  await page.click('[data-nat-action="preview-source"][data-nat-rule-name="visual-snat-edited"]');
  await waitForSourceNatLifecycleState(page, "row preview", (state) => (
    state.previewText.includes("Source NAT visual-snat-edited path review queued") &&
    state.previewText.includes("Path coupling review") &&
    state.previewText.includes("Open running/candidate compare")
  ));

  await page.click('[data-nat-action="delete-source"][data-nat-rule-name="visual-snat-edited"]');
  await waitForDrawerTitleStep(page, "Delete source NAT?", "source NAT delete confirmation");
  await assertDrawerFooterButtonSemantics(page, viewport, "source NAT delete confirmation", ["Cancel", "Delete"]);
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const button = [...(drawer?.querySelectorAll("button") || [])]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Delete");
    if (!button) throw new Error("source NAT delete confirmation button was not found");
    button.click();
  });
  await waitForSourceNatLifecycleState(page, "delete", (state) => (
    !state.candidate.source.some((item) => item.name === "visual-snat-edited") &&
    state.runningFingerprint === before.runningFingerprint &&
    state.previewText.includes("Source NAT visual-snat-edited deleted from candidate")
  ));
  await page.keyboard.press("Escape");

  const finalState = await sourceNatLifecycleState(page);
  if (finalState.overflow > 2) {
    throw new Error(`source NAT lifecycle introduced overflow at ${viewport.name}: ${finalState.overflow}px`);
  }
}

async function fillSourceNatEditor(page, values = {}) {
  await page.evaluate((input) => {
    const drawer = document.querySelector("#drawer:not([hidden]) [data-nat-source-editor='true']");
    if (!drawer) throw new Error("source NAT editor was not open");
    const setValue = (field, value) => {
      if (value == null) return;
      const el = drawer.querySelector(`[data-nat-source-field="${field}"]`);
      if (!el) throw new Error(`source NAT field ${field} was not found`);
      el.value = String(value);
      el.dispatchEvent(new Event(el.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      if (el.value !== String(value)) throw new Error(`source NAT field ${field} did not accept ${value}`);
    };
    setValue("name", input.name);
    setValue("egress-zone", input.egressZone);
    setValue("source-address", input.sourceAddress);
    setValue("translation-mode", input.mode);
    setValue("translated-address", input.translatedAddress);
  }, values);
}

async function waitForSourceNatLifecycleState(page, label, predicate, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await sourceNatLifecycleState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`source NAT lifecycle ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function sourceNatLifecycleState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const changes = Array.isArray(status.changes) ? status.changes : [];
    const natChange = changes.find((change) => change?.section === "nat") || null;
    return {
      candidate: {
        source: candidate.nat?.source || [],
        destination: candidate.nat?.destination || [],
      },
      runningText: JSON.stringify(running),
      runningFingerprint: stable(running),
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        natChanged: Boolean(natChange && Number(natChange.added || 0) + Number(natChange.modified || 0) + Number(natChange.removed || 0) > 0),
        changes,
      },
      previewText: (document.querySelector(".rule-simulator")?.textContent || "").replace(/\s+/g, " ").trim(),
      previewSourceAction: Boolean(document.querySelector('[data-nat-action="preview-source"]')),
      sourceActionButtons: [...document.querySelectorAll('[data-nat-rule-name="visual-snat-edited"]')].map((button) => ({
        action: button.dataset.natAction || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        type: button.getAttribute("type") || "",
      })),
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
}

async function openDestinationNatPublishAssistant(page, viewport) {
  await assertNatActionControls(page, viewport, "NAT destination add actions", ["add-destination"]);
  await page.evaluate(() => {
    const buttons = [...document.querySelectorAll("#content button")];
    const target = buttons.find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === "Add destination NAT");
    if (!target) throw new Error("Add destination NAT button was not found");
    target.click();
  });
  await waitForDrawerTitle(page, "Add destination NAT");
  await assertNatActionControls(page, viewport, "destination NAT add drawer", ["save-destination"]);
}

async function fillAndSaveDestinationNatPublishAssistant(page) {
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("destination NAT drawer was not open");
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const fieldControl = (label, root = drawer) => {
      const field = [...root.querySelectorAll("label.field")]
        .find((candidate) => textOf(candidate.querySelector("span")).startsWith(label));
      const control = field?.querySelector("input, select, textarea");
      if (!control) throw new Error(`field ${label} was not found`);
      return control;
    };
    const section = (title) => {
      const nodes = [...drawer.querySelectorAll(".posture-metric")];
      const found = nodes.find((node) => textOf(node.querySelector("strong")) === title);
      if (!found) throw new Error(`publish assistant section ${title} was not found`);
      return found;
    };
    const setInput = (control, value) => {
      control.value = value;
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setSelect = (control, value) => {
      control.value = value;
      control.dispatchEvent(new Event("change", { bubbles: true }));
      if (control.value !== value) throw new Error(`select did not accept ${value}`);
    };
    const clickButton = (root, label) => {
      const button = [...root.querySelectorAll("button")]
        .find((candidate) => textOf(candidate).includes(label));
      if (!button) throw new Error(`button ${label} was not found`);
      button.click();
    };

    setInput(fieldControl("Name"), "publish-web-entry");
    setSelect(fieldControl("Ingress zone"), "untrust");

    const svc = section("Create service object");
    setInput(fieldControl("Name", svc), "publish-service-8443");
    setSelect(fieldControl("Protocol", svc), "PROTOCOL_TCP");
    setInput(fieldControl("Ports", svc), "8443");
    clickButton(svc, "Create");

    const publicHost = section("Create public host");
    setInput(fieldControl("Name", publicHost), "publish-public-host");
    setInput(fieldControl("Host IP/CIDR", publicHost), "203.0.113.20/32");
    clickButton(publicHost, "Create");

    const internalHost = section("Create internal host");
    setInput(fieldControl("Name", internalHost), "publish-private-host");
    setInput(fieldControl("Host IP/CIDR", internalHost), "10.50.0.10/32");
    clickButton(internalHost, "Create");

    setSelect(fieldControl("Service"), "publish-service-8443");
    setSelect(fieldControl("Public destination"), "publish-public-host");
    setSelect(fieldControl("Translated address"), "publish-private-host");
    setSelect(fieldControl("Target zone"), "dmz");

    if (!drawer.querySelector("[data-nat-publish-assistant='true']")) {
      throw new Error("destination NAT drawer did not render the publish plan");
    }
    const save = drawer.querySelector('.drawer-foot [data-nat-action="save-destination"]');
    if (!save) throw new Error("Add destination NAT footer action was not found");
    save.click();
  });
}

async function assertPublishedServiceCandidate(page) {
  const state = await page.evaluate(async () => {
    const [response, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    const body = await response.json();
    const runningBody = await runningResponse.json();
    const policy = body?.policy || {};
    const runningPolicy = runningBody?.policy || {};
    const rule = (policy.rules || []).find((item) => item.name === "allow-untrust-to-dmz-publish-private-host-publish-service-8443");
    const dnat = (policy.nat?.destination || []).find((item) => item.name === "publish-web-entry");
    const runningText = JSON.stringify(runningPolicy);
    return {
      status: response.status,
      runningStatus: runningResponse.status,
      addresses: (policy.addresses || []).map((item) => ({ name: item.name, cidr: item.cidr })),
      services: (policy.services || []).map((item) => ({ name: item.name, protocol: item.protocol, ports: item.ports || [] })),
      dnat,
      rule,
      runningLeakedPublishNames: ["publish-web-entry", "publish-public-host", "publish-private-host", "publish-service-8443", "allow-untrust-to-dmz-publish-private-host-publish-service-8443"]
        .filter((name) => runningText.includes(name)),
    };
  });
  if (state.status !== 200) {
    throw new Error(`candidate policy fetch failed with HTTP ${state.status}`);
  }
  if (state.runningStatus !== 200) {
    throw new Error(`running policy fetch failed with HTTP ${state.runningStatus}`);
  }
  if (state.runningLeakedPublishNames.length) {
    throw new Error(`publish workflow mutated running policy: ${state.runningLeakedPublishNames.join(", ")}`);
  }
  for (const expected of [
    ["publish-public-host", "203.0.113.20/32"],
    ["publish-private-host", "10.50.0.10/32"],
  ]) {
    if (!state.addresses.some((item) => item.name === expected[0] && item.cidr === expected[1])) {
      throw new Error(`published service address object missing: ${expected.join("=")} in ${JSON.stringify(state.addresses)}`);
    }
  }
  const service = state.services.find((item) => item.name === "publish-service-8443");
  if (!service || service.protocol !== "PROTOCOL_TCP" || !service.ports.some((port) => Number(port.start) === 8443)) {
    throw new Error(`published service object missing or wrong: ${JSON.stringify(service || state.services)}`);
  }
  if (!state.dnat || state.dnat.fromZone !== "untrust" || state.dnat.destinationAddress !== "publish-public-host" ||
      state.dnat.translatedAddress !== "publish-private-host" || state.dnat.service !== "publish-service-8443") {
    throw new Error(`destination NAT was not staged correctly: ${JSON.stringify(state.dnat)}`);
  }
  if (!state.rule || state.rule.action !== "ACTION_ALLOW" || state.rule.disabled ||
      !sameArray(state.rule.fromZones, ["untrust"]) || !sameArray(state.rule.toZones, ["dmz"]) ||
      !sameArray(state.rule.destinationAddresses, ["publish-private-host"]) || !sameArray(state.rule.services, ["publish-service-8443"])) {
    throw new Error(`matching allow rule was not staged correctly: ${JSON.stringify(state.rule)}`);
  }
}

async function assertPublishedServiceRulesRow(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/rules?rule=allow-untrust-to-dmz-publish-private-host-publish-service-8443";
  });
  await waitForRouteReady(page, "/rules");
  await page.waitForFunction(() => {
    const row = document.querySelector('tr[data-rule-name="allow-untrust-to-dmz-publish-private-host-publish-service-8443"][data-rule-change="added"]');
    return Boolean(row && (row.textContent || "").includes("publish-service-8443"));
  }, null, { timeout: 10000 });
  const row = await page.evaluate(() => {
    const el = document.querySelector('tr[data-rule-name="allow-untrust-to-dmz-publish-private-host-publish-service-8443"]');
    const rect = el?.getBoundingClientRect?.();
    return {
      text: (el?.textContent || "").replace(/\s+/g, " ").trim(),
      change: el?.dataset?.ruleChange || "",
      selected: el?.classList?.contains("selected-row") || el?.getAttribute("aria-current") === "true",
      width: rect?.width || 0,
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
  if (row.overflow > 2) {
    throw new Error(`published service Rules row introduced overflow at ${viewport.name}: ${row.overflow}px`);
  }
  if (row.change !== "added" || !row.selected) {
    throw new Error(`published service generated rule was not route-focused as an added row: ${JSON.stringify(row)}`);
  }
  const required = ["allow-untrust-to-dmz-publish-private-host-publish-service-8443", "untrust", "dmz", "publish-private-host", "publish-service-8443", "Allow"];
  const missing = required.filter((part) => !row.text.includes(part));
  if (missing.length) {
    throw new Error(`published service generated rule row missing ${missing.join(", ")}: ${row.text}`);
  }
}

async function assertPublishedServiceNatPreview(page, viewport) {
  await page.waitForFunction(() => {
    const content = document.querySelector("#content");
    const text = content?.textContent || "";
    return text.includes("NAT path preview") &&
      text.includes("203.0.113.20:8443") &&
      Boolean(content?.querySelector(".sim-summary"));
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => {
    const content = document.querySelector("#content");
    const text = (content?.textContent || "").replace(/\s+/g, " ").trim();
    const hash = location.hash || "";
    const buttons = [...content.querySelectorAll(".sim-actions button")].map((button) => (button.textContent || "").replace(/\s+/g, " ").trim());
    const deltaTable = content?.querySelector(".nat-path-delta-table");
    const deltaRow = deltaTable?.querySelector("tbody tr");
    const deltaLabels = [...(deltaRow?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
    const coupling = content?.querySelector("[data-nat-coupling-review='true']");
    const couplingRows = [...(coupling?.querySelectorAll("[data-nat-coupling-row]") || [])].map((row) => ({
      key: row.dataset.natCouplingRow || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const couplingActions = [...(coupling?.querySelectorAll("[data-nat-coupling-action]") || [])].map((action) => ({
      key: action.dataset.natCouplingAction || "",
      href: action.getAttribute("href") || "",
      text: (action.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const selectedRows = [...content.querySelectorAll('[data-nat-rule-type="destination"]')].map((row) => ({
      name: row.dataset.natRuleName || "",
      selected: row.classList.contains("selected-row") || row.getAttribute("aria-current") === "true",
    }));
    return {
      hash,
      text,
      buttons,
      deltaTableClass: deltaTable?.className || "",
      deltaLabels,
      deltaOverflow: deltaTable ? Math.max(0, Math.ceil(deltaTable.scrollWidth - deltaTable.clientWidth)) : 0,
      deltaMobileLabelsRendered: window.innerWidth > 820 || [...(deltaRow?.querySelectorAll("td") || [])].every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
      couplingText: (coupling?.textContent || "").replace(/\s+/g, " ").trim(),
      couplingRows,
      couplingActions,
      selectedRows,
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
  if (state.overflow > 2) {
    throw new Error(`published NAT workflow introduced overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.deltaTableClass.includes("responsive-evidence") || !state.deltaTableClass.includes("nat-path-delta-table")) {
    throw new Error(`published NAT preview missing responsive delta table at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingDeltaLabels = ["Decision point", "Running", "Candidate"].filter((label) => !state.deltaLabels.includes(label));
  if (missingDeltaLabels.length) {
    throw new Error(`published NAT preview delta table missing labels at ${viewport.name}: ${JSON.stringify({ missingDeltaLabels, state })}`);
  }
  if (state.deltaOverflow > 2) {
    throw new Error(`published NAT preview delta table overflow at ${viewport.name}: ${state.deltaOverflow}px`);
  }
  if (!state.couplingText.includes("Path coupling review") || !state.couplingText.includes("Candidate path changes")) {
    throw new Error(`published NAT preview missing path coupling review at ${viewport.name}: ${state.couplingText || "<empty>"}`);
  }
  for (const key of ["policy", "dnat"]) {
    if (!state.couplingRows.some((row) => row.key === key)) {
      throw new Error(`published NAT preview coupling review missing ${key} row at ${viewport.name}: ${JSON.stringify(state.couplingRows)}`);
    }
  }
  if (!state.couplingActions.some((action) => action.key === "troubleshoot" && action.href.includes("#/troubleshoot?")) ||
      !state.couplingActions.some((action) => action.key === "candidate" && action.href === "#/changes?tab=candidate")) {
    throw new Error(`published NAT preview coupling actions missing at ${viewport.name}: ${JSON.stringify(state.couplingActions)}`);
  }
  if (!state.deltaMobileLabelsRendered) {
    throw new Error(`published NAT preview mobile delta labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const expected of ["fromZone=untrust", "toZone=dmz", "destIp=203.0.113.20", "destPort=8443", "run=1"]) {
    if (!state.hash.includes(expected)) {
      throw new Error(`published NAT preview hash missing ${expected}: ${state.hash}`);
    }
  }
  const requiredText = [
    "Publish assistant staged publish-web-entry",
    "allow-untrust-to-dmz-publish-private-host-publish-service-8443",
    "Candidate NAT",
  ];
  const missingText = requiredText.filter((item) => !state.text.includes(item));
  if (missingText.length) {
    throw new Error(`published NAT preview missing text: ${missingText.join(", ")}`);
  }
  for (const label of ["Copy link", "Open in Troubleshoot", "Pin to case", "Export handoff"]) {
    if (!state.buttons.includes(label)) {
      throw new Error(`published NAT preview missing action ${label}: ${JSON.stringify(state.buttons)}`);
    }
  }
  const rowActions = await page.evaluate(() => [...document.querySelectorAll('[data-nat-rule-name="publish-web-entry"]')].map((button) => ({
    action: button.dataset.natAction || "",
    title: button.getAttribute("title") || "",
    ariaLabel: button.getAttribute("aria-label") || "",
    type: button.getAttribute("type") || "",
  })));
  assertNatRowActionButtons(rowActions, "published destination NAT row actions");
  if (!state.couplingActions.some((action) => action.key === "dnat" && action.href.includes("#/nat?"))) {
    throw new Error(`published NAT preview coupling DNAT action missing at ${viewport.name}: ${JSON.stringify(state.couplingActions)}`);
  }
  await page.click('[data-nat-action="preview-destination"][data-nat-rule-name="publish-web-entry"]');
  await page.waitForFunction(() => {
    const text = (document.querySelector("[data-nat-preview-result='true']")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Destination NAT publish-web-entry path review queued") && text.includes("Path coupling review");
  }, null, { timeout: 10000 });
  await assertPublishedServiceNatPreviewActions(page, viewport, state.hash);
  await assertNatPreviewIgnoresStaleResponses(page, viewport);
}

function assertNatRowActionButtons(buttons, label) {
  const expected = {
    preview: "Preview path",
    edit: "Edit",
    delete: "Delete",
  };
  const missing = Object.entries(expected).filter(([action, title]) => !buttons.some((button) =>
    button.action.includes(action) &&
    button.title === title &&
    button.ariaLabel === title &&
    button.type === "button"));
  if (missing.length) {
    throw new Error(`${label} missed accessible action(s): ${JSON.stringify({ missing, buttons })}`);
  }
}

async function assertNatActionControls(page, viewport, label, expectedActions = []) {
  const state = await page.evaluate((expectedActions) => {
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const buttons = [...document.querySelectorAll("button[data-nat-action]")]
      .filter(visible)
      .map((button) => ({
        action: button.dataset.natAction || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      }));
    return {
      buttons,
      invalid: buttons.filter((button) => (
        expectedActions.includes(button.action) &&
        (button.type !== "button" || !button.title.trim() || !button.ariaLabel.trim())
      )),
    };
  }, expectedActions);
  if (state.invalid.length) {
    throw new Error(`${label} NAT action controls missing semantics at ${viewport.name}: ${JSON.stringify(state.invalid)}`);
  }
  for (const action of expectedActions) {
    if (!state.buttons.some((button) => button.action === action)) {
      throw new Error(`${label} missing NAT action ${action} at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
}

async function assertDrawerFooterButtonSemantics(page, viewport, label, expectedLabels = []) {
  const state = await page.evaluate((expectedLabels) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const buttons = [...(drawer?.querySelectorAll(".drawer-foot button") || [])].map((button) => ({
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
    return {
      buttons,
      invalid: buttons.filter((button) => (
        expectedLabels.includes(button.text) &&
        (button.type !== "button" || !button.title.trim() || !button.ariaLabel.trim())
      )),
    };
  }, expectedLabels);
  if (state.invalid.length) {
    throw new Error(`${label} drawer footer controls missing semantics at ${viewport.name}: ${JSON.stringify(state.invalid)}`);
  }
  for (const text of expectedLabels) {
    if (!state.buttons.some((button) => button.text === text)) {
      throw new Error(`${label} missing drawer footer button ${text} at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
}

async function assertPublishedServiceNatPreviewActions(page, viewport, natHash) {
  await page.evaluate(() => {
    globalThis.__natPreviewCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__natPreviewCopiedText = String(text || "");
          },
        },
      });
    } catch {
      try {
        navigator.clipboard.writeText = async (text) => {
          globalThis.__natPreviewCopiedText = String(text || "");
        };
      } catch {}
    }
  });
  await clickContentButton(page, "Copy link");
  await page.waitForFunction(() => Boolean(globalThis.__natPreviewCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__natPreviewCopiedText || "");
  for (const expected of ["#/nat?", "fromZone=untrust", "toZone=dmz", "destIp=203.0.113.20", "destPort=8443", "run=1"]) {
    if (!copied.includes(expected)) {
      throw new Error(`published NAT preview copied link missing ${expected} at ${viewport.name}: ${copied}`);
    }
  }
  assertNoInvestigationLeak(copied, `published NAT preview copied link ${viewport.name}`);

  await page.evaluate(() => localStorage.removeItem("phragma.investigation.case.v1"));
  await clickContentButton(page, "Pin to case");
  const pinnedRaw = await page.evaluate(() => localStorage.getItem("phragma.investigation.case.v1") || "");
  assertNoInvestigationLeak(pinnedRaw, `published NAT preview pinned case ${viewport.name}`);
  let pinned = null;
  try {
    pinned = JSON.parse(pinnedRaw || "{}");
  } catch (err) {
    throw new Error(`published NAT preview pinned case was not JSON at ${viewport.name}: ${err.message}`);
  }
  const pinnedPacket = (pinned.items || []).find((item) => item.packet?.kind === "nat-path")?.packet;
  if (pinned?.schemaVersion !== "phragma.investigation.case.v1" ||
      pinnedPacket?.schemaVersion !== "phragma.investigation.handoff.v1" ||
      pinnedPacket?.title !== "NAT path preview handoff" ||
      pinnedPacket?.summary?.fromZone !== "untrust" ||
      pinnedPacket?.summary?.toZone !== "dmz") {
    throw new Error(`published NAT preview pinned unexpected case packet at ${viewport.name}: ${pinnedRaw}`);
  }

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickContentButton(page, "Export handoff");
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^phragma-investigation-nat-path-.+\.json$/.test(filename || "")) {
    throw new Error(`published NAT preview export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const downloadPath = await download.path();
  if (!downloadPath) {
    throw new Error(`published NAT preview export did not produce a readable file at ${viewport.name}`);
  }
  const exportedText = await readFile(downloadPath, "utf8");
  assertNoInvestigationLeak(exportedText, `published NAT preview export ${viewport.name}`);
  let exported = null;
  try {
    exported = JSON.parse(exportedText);
  } catch (err) {
    throw new Error(`published NAT preview export was not JSON at ${viewport.name}: ${err.message}`);
  }
  if (exported?.schemaVersion !== "phragma.investigation.handoff.v1" ||
      exported?.kind !== "nat-path" ||
      exported?.title !== "NAT path preview handoff" ||
      exported?.summary?.candidateChanged !== true ||
      exported?.subject?.tuple?.destIp !== "203.0.113.20") {
    throw new Error(`published NAT preview export had unexpected packet identity at ${viewport.name}: ${JSON.stringify({ schemaVersion: exported?.schemaVersion, kind: exported?.kind, title: exported?.title, summary: exported?.summary, tuple: exported?.subject?.tuple })}`);
  }

  await clickContentButton(page, "Open in Troubleshoot");
  await waitForRouteReady(page, "/troubleshoot");
  const troubleshoot = await page.evaluate(() => {
    const params = new URLSearchParams((location.hash.split("?")[1] || ""));
    return {
      hash: location.hash || "",
      intent: params.get("intent") || "",
      source: params.get("source") || "",
      runtime: params.get("runtime") || "",
      run: params.get("run") || "",
      fromZone: params.get("fromZone") || "",
      toZone: params.get("toZone") || "",
      src: params.get("src") || "",
      dst: params.get("dst") || "",
      dport: params.get("dport") || "",
    };
  });
  if (troubleshoot.intent !== "compare" ||
      troubleshoot.source !== "POLICY_SOURCE_CANDIDATE" ||
      troubleshoot.runtime !== "1" ||
      troubleshoot.run !== "1" ||
      troubleshoot.fromZone !== "untrust" ||
      troubleshoot.toZone !== "dmz" ||
      troubleshoot.dst !== "203.0.113.20" ||
      troubleshoot.dport !== "8443") {
    throw new Error(`published NAT preview Troubleshoot route mismatch at ${viewport.name}: ${JSON.stringify(troubleshoot)}`);
  }
  assertNoInvestigationLeak(troubleshoot.hash, `published NAT preview Troubleshoot route ${viewport.name}`);

  await page.evaluate((hash) => { location.hash = hash; }, natHash);
  await waitForRouteReady(page, "/nat");
  await page.waitForFunction(() => {
    const text = document.querySelector("#content")?.textContent || "";
    return text.includes("NAT path preview") && text.includes("203.0.113.20:8443") && Boolean(document.querySelector("#content .sim-summary"));
  }, null, { timeout: 10000 });
}

async function assertNatPreviewIgnoresStaleResponses(page, viewport) {
  await page.evaluate(() => {
    const originalFetch = window.fetch.bind(window);
    const gate = {
      held: [],
      explainCount: 0,
      restore: () => {
        window.fetch = originalFetch;
      },
      release: () => {
        const held = gate.held.splice(0);
        for (const release of held) release();
      },
    };
    window.__natPreviewFetchGate = gate;
    window.fetch = async (...args) => {
      const input = args[0];
      const url = typeof input === "string" ? input : input?.url || "";
      if (String(url).includes("/v1/explain/flow")) {
        gate.explainCount += 1;
        if (gate.explainCount <= 2) {
          await new Promise((resolve) => gate.held.push(resolve));
        }
      }
      return originalFetch(...args);
    };
  });
  try {
    await submitNatPreviewTuple(page, {
      fromZone: "untrust",
      toZone: "dmz",
      srcIp: "198.51.100.44",
      srcPort: "51515",
      destIp: "203.0.113.20",
      destPort: "8443",
      protocol: "PROTOCOL_TCP",
    });
    await page.waitForFunction(() => window.__natPreviewFetchGate?.held?.length === 2, null, { timeout: 5000 });
    await submitNatPreviewTuple(page, {
      fromZone: "untrust",
      toZone: "dmz",
      srcIp: "198.51.100.55",
      srcPort: "52525",
      destIp: "203.0.113.21",
      destPort: "9443",
      protocol: "PROTOCOL_TCP",
    });
    await page.waitForFunction(() => {
      const root = document.querySelector("[data-nat-preview-result='true']");
      const text = (root?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("203.0.113.21:9443") &&
        (root?.dataset?.natPreviewKey || "").includes("203.0.113.21");
    }, null, { timeout: 10000 });
    await page.evaluate(() => window.__natPreviewFetchGate?.release?.());
    await page.waitForTimeout(250);
    const state = await collectNatPreviewEvidenceState(page);
    if (!state.text.includes("203.0.113.21:9443") ||
        state.text.includes("203.0.113.20:8443") ||
        !state.hash.includes("destIp=203.0.113.21") ||
        !state.hash.includes("destPort=9443") ||
        state.hash.includes("destIp=203.0.113.20")) {
      throw new Error(`NAT preview accepted stale response at ${viewport.name}: ${JSON.stringify(state)}`);
    }
    await assertNatPreviewCurrentTupleActions(page, viewport, "203.0.113.21", "9443");
    await assertAutomationContextDrawer(page, viewport, "NAT preview current tuple automation context", [
      "#/nat?fromZone=untrust",
      "203.0.113.21",
      "9443",
      "POLICY_SOURCE_RUNNING",
      "POLICY_SOURCE_CANDIDATE",
      "/v1/explain/flow",
      "ngfwctl explain --source running --from-zone untrust --to-zone dmz --src 198.51.100.55 --sport 52525 --dst 203.0.113.21 --dport 9443 --protocol tcp",
      "ngfwctl explain --source candidate --from-zone untrust --to-zone dmz --src 198.51.100.55 --sport 52525 --dst 203.0.113.21 --dport 9443 --protocol tcp",
    ]);
  } finally {
    await page.evaluate(() => {
      window.__natPreviewFetchGate?.release?.();
      window.__natPreviewFetchGate?.restore?.();
    });
  }
}

async function submitNatPreviewTuple(page, tuple) {
  await page.evaluate((next) => {
    const form = document.querySelector("#content .sim-form");
    if (!form) throw new Error("NAT preview form was not found");
    const setField = (label, value) => {
      const field = [...form.querySelectorAll("label.field")]
        .find((candidate) => (candidate.querySelector("span")?.textContent || "").trim() === label);
      const control = field?.querySelector("input, select");
      if (!control) throw new Error(`NAT preview field ${label} was not found`);
      control.value = value;
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setField("From", next.fromZone);
    setField("To", next.toZone);
    setField("Protocol", next.protocol);
    setField("Source IP", next.srcIp);
    setField("Source port", next.srcPort);
    setField("Destination IP", next.destIp);
    setField("Destination port", next.destPort);
    form.requestSubmit();
  }, tuple);
}

async function collectNatPreviewEvidenceState(page) {
  return page.evaluate(() => {
    const root = document.querySelector("[data-nat-preview-result='true']");
    return {
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      key: root?.dataset?.natPreviewKey || "",
      hash: location.hash || "",
    };
  });
}

async function assertNatPreviewCurrentTupleActions(page, viewport, expectedDestIp, expectedDestPort) {
  await page.evaluate(() => {
    globalThis.__natPreviewCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__natPreviewCopiedText = String(text || "");
          },
        },
      });
    } catch {
      try {
        navigator.clipboard.writeText = async (text) => {
          globalThis.__natPreviewCopiedText = String(text || "");
        };
      } catch {}
    }
  });
  await page.click('[data-nat-preview-action="copy"]');
  await page.waitForFunction(() => Boolean(globalThis.__natPreviewCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__natPreviewCopiedText || "");
  if (!copied.includes(`destIp=${expectedDestIp}`) || !copied.includes(`destPort=${expectedDestPort}`)) {
    throw new Error(`NAT preview stale copy action at ${viewport.name}: ${copied}`);
  }

  await page.evaluate(() => localStorage.removeItem("phragma.investigation.case.v1"));
  await page.click('[data-nat-preview-action="pin"]');
  const pinnedRaw = await page.evaluate(() => localStorage.getItem("phragma.investigation.case.v1") || "");
  const pinned = JSON.parse(pinnedRaw || "{}");
  const pinnedPacket = (pinned.items || []).find((item) => item.packet?.kind === "nat-path")?.packet;
  if (pinnedPacket?.subject?.tuple?.destIp !== expectedDestIp ||
      String(pinnedPacket?.subject?.tuple?.destPort || "") !== expectedDestPort) {
    throw new Error(`NAT preview stale pinned tuple at ${viewport.name}: ${pinnedRaw}`);
  }

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('[data-nat-preview-action="export"]');
  const download = await downloadPromise;
  const downloadPath = await download.path();
  if (!downloadPath) throw new Error(`NAT preview stale-response export missing download path at ${viewport.name}`);
  const exported = JSON.parse(await readFile(downloadPath, "utf8"));
  if (exported?.subject?.tuple?.destIp !== expectedDestIp ||
      String(exported?.subject?.tuple?.destPort || "") !== expectedDestPort) {
    throw new Error(`NAT preview stale exported tuple at ${viewport.name}: ${JSON.stringify(exported?.subject?.tuple)}`);
  }
}

async function assertPublishedServiceObjectReferences(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/objects?tab=services&drawer=references&object=publish-service-8443";
  });
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, "Object references");
  await page.evaluate(() => {
    globalThis.__objectReferenceCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__objectReferenceCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "object reference", [
    "publish-service-8443",
    "2 candidate policy references",
    "security rule",
    "allow-untrust-to-dmz-publish-private-host-publish-service-8443",
    "destination NAT",
    "publish-web-entry",
    "Open rule",
    "Open destination NAT",
  ], ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
  assertNoInvestigationLeak(drawer.text, `published object reference drawer ${viewport.name}`);

  await clickDrawerFooterButton(page, "Copy handoff");
  await page.waitForFunction(() => Boolean(globalThis.__objectReferenceCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__objectReferenceCopiedText || "");
  if (!copied.includes("Object reference review") || !copied.includes("destination NAT: publish-web-entry") || !copied.includes("security rule: allow-untrust-to-dmz-publish-private-host-publish-service-8443")) {
    throw new Error(`object reference handoff copy missed expected references: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `published object reference copy ${viewport.name}`);

  await assertAutomationContextDrawer(page, viewport, "object reference automation context", [
    "#/objects?tab=services&drawer=references&object=publish-service-8443",
    "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SERVICE&name=publish-service-8443",
    "ngfwctl policy references --source candidate --kind service --name publish-service-8443",
  ], { keepActiveDrawer: true });
  await page.evaluate(() => {
    location.hash = "#/objects?tab=services&drawer=references&object=publish-service-8443";
  });
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, "Object references");

  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const target = [...(drawer?.querySelectorAll("a") || [])]
      .find((link) => (link.textContent || "").replace(/\s+/g, " ").trim() === "Open destination NAT");
    if (!target) throw new Error("Open destination NAT link was not found");
    target.click();
  });
  await waitForRouteReady(page, "/nat");
  await page.waitForFunction(() => {
    const hash = location.hash || "";
    const params = new URLSearchParams(hash.split("?")[1] || "");
    const selected = document.querySelector('[data-nat-rule-type="destination"].selected-row,[data-nat-rule-type="destination"][aria-current="true"]');
    const routeToken = params.get("rule") || "";
    return params.get("nat") === "destination" &&
      (routeToken === "publish-web-entry" || routeToken.startsWith("dnat-")) &&
      selected?.dataset?.natRuleName === "publish-web-entry";
  }, null, { timeout: 5000 });
}

async function assertPublishedServiceRenameDependencyRewrite(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/objects?tab=services";
  });
  await waitForRouteReady(page, "/objects");
  await assertObjectRowActionLabels(page, viewport, "services", "service", "publish-service-8443");
  await page.click('[data-object-action="edit"][data-object-kind="services"][data-object-name="publish-service-8443"]');
  await waitForDrawerTitleStep(page, "Edit service", "service rename edit drawer");
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("service editor drawer was not open");
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const field = [...drawer.querySelectorAll("label.field")]
      .find((candidate) => textOf(candidate.querySelector("span")).startsWith("Name"));
    const input = field?.querySelector("input");
    if (!input) throw new Error("service editor name field was not found");
    input.value = "publish-service-renamed";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.click('#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="services"]');
  await waitForDrawerTitleStep(page, "Rename service?", "service rename review drawer");
  const review = await collectDrawerState(page);
  assertDrawerContains(review, viewport, "service rename review", [
    "Referenced object rename",
    "publish-service-8443",
    "publish-service-renamed",
    "Security rules",
    "security rule",
    "allow-untrust-to-dmz-publish-private-host-publish-service-8443",
    "Destination NAT",
    "destination NAT",
    "publish-web-entry",
  ], ["Cancel", "Stage rename"]);
  const groupedReview = await page.evaluate(() => {
    const root = document.querySelector('#drawer:not([hidden]) [data-object-rename-review="true"][data-object-kind="services"][data-object-old-name="publish-service-8443"][data-object-new-name="publish-service-renamed"]');
    const groupText = (area) => (root?.querySelector(`[data-object-rename-area="${area}"]`)?.textContent || "").replace(/\s+/g, " ").trim();
    return {
      hasRoot: Boolean(root),
      security: groupText("security rule"),
      destinationNat: groupText("destination NAT"),
    };
  });
  if (!groupedReview.hasRoot ||
      !groupedReview.security.includes("Security rules") ||
      !groupedReview.security.includes("1 reference") ||
      !groupedReview.security.includes("service") ||
      !groupedReview.security.includes("allow-untrust-to-dmz-publish-private-host-publish-service-8443") ||
      !groupedReview.destinationNat.includes("Destination NAT") ||
      !groupedReview.destinationNat.includes("1 reference") ||
      !groupedReview.destinationNat.includes("service") ||
      !groupedReview.destinationNat.includes("publish-web-entry")) {
    throw new Error(`service rename grouped dependency rows missing expected content at ${viewport.name}: ${JSON.stringify(groupedReview)}`);
  }
  await page.click('#drawer:not([hidden]) [data-object-action="confirm-rename"][data-object-kind="services"]');
  await waitForDrawerClosed(page);
  await page.waitForFunction(async () => {
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok || !statusResponse.ok) return false;
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const status = await statusResponse.json();
    const rule = (candidate.rules || []).find((item) => item.name === "allow-untrust-to-dmz-publish-private-host-publish-service-8443");
    const dnat = (candidate.nat?.destination || []).find((item) => item.name === "publish-web-entry");
    const runningText = JSON.stringify(running);
    const sameRefs = (actual, expected) => JSON.stringify([...(actual || [])].sort()) === JSON.stringify([...(expected || [])].sort());
    return Boolean((candidate.services || []).find((item) => item.name === "publish-service-renamed")) &&
      !(candidate.services || []).some((item) => item.name === "publish-service-8443") &&
      Boolean(rule && sameRefs(rule.services || [], ["publish-service-renamed"])) &&
      Boolean(dnat && dnat.service === "publish-service-renamed") &&
      !runningText.includes("publish-service-renamed") &&
      Boolean(status.dirty);
  }, null, { timeout: 10000 });

  await page.evaluate(() => {
    location.hash = "#/objects?tab=services&drawer=references&object=publish-service-renamed";
  });
  await waitForRouteReady(page, "/objects");
  await waitForDrawerTitle(page, "Object references");
  const refs = await collectDrawerState(page);
  assertDrawerContains(refs, viewport, "renamed service object references", [
    "publish-service-renamed",
    "2 candidate policy references",
    "security rule",
    "allow-untrust-to-dmz-publish-private-host-publish-service-8443",
    "destination NAT",
    "publish-web-entry",
  ], ["Close", "Pin to case", "Copy handoff", "Export JSON"]);
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
  const overflow = await page.evaluate(() => Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)));
  if (overflow > 2) {
    throw new Error(`published service rename workflow introduced overflow at ${viewport.name}: ${overflow}px`);
  }
}

async function assertObjectRowActionLabels(page, viewport, objectKind, objectLabelKind, objectName) {
  const rowActions = await page.evaluate(({ kind, name }) => {
    return [...document.querySelectorAll(`[data-object-kind="${kind}"][data-object-name="${name}"]`)]
      .filter((button) => button.getAttribute("data-object-action") === "edit" || button.getAttribute("data-object-action") === "delete")
      .map((button) => ({
        action: button.getAttribute("data-object-action") || "",
        type: button.getAttribute("type") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
      }));
  }, { kind: objectKind, name: objectName });
  for (const expected of [
    { action: "edit", ariaLabel: `Edit ${objectLabelKind} ${objectName}` },
    { action: "delete", ariaLabel: `Delete ${objectLabelKind} ${objectName}` },
  ]) {
    const actual = rowActions.find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel) {
      throw new Error(`object row action mismatch at ${viewport.name} for ${objectKind}/${objectName}/${expected.action}: ${JSON.stringify(rowActions)}`);
    }
  }
}

async function assertPublishedServiceDeleteCleanup(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/nat?nat=destination&rule=publish-web-entry&idx=0";
  });
  await waitForRouteReady(page, "/nat");
  await page.waitForFunction(() => {
    const selected = document.querySelector('[data-nat-rule-type="destination"].selected-row,[data-nat-rule-type="destination"][aria-current="true"]');
    return selected?.dataset?.natRuleName === "publish-web-entry";
  }, null, { timeout: 5000 });
  await page.click('[data-nat-action="delete-destination"][data-nat-rule-name="publish-web-entry"]');
  await waitForDrawerTitleStep(page, "Delete destination NAT?", "destination NAT delete review");
  await assertNatActionControls(page, viewport, "destination NAT delete review", ["confirm-delete-destination"]);
  await assertDrawerFooterButtonSemantics(page, viewport, "destination NAT delete review", ["Cancel", "Delete destination NAT"]);
  const review = await collectDrawerState(page);
  assertDrawerContains(review, viewport, "destination NAT delete review", [
    "publish-web-entry",
    "Linked generated allow rule found",
    "allow-untrust-to-dmz-publish-private-host-publish-service-8443",
    "Delete linked generated allow rule",
    "operator can review the candidate impact",
  ], ["Cancel", "Delete destination NAT"]);
  const cleanupDefault = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return Boolean(drawer?.querySelector('[data-nat-linked-publish-rule="allow-untrust-to-dmz-publish-private-host-publish-service-8443"] input[type="checkbox"]')?.checked);
  });
  if (!cleanupDefault) {
    throw new Error("destination NAT delete review did not default to linked generated-rule cleanup");
  }
  await page.click('#drawer:not([hidden]) [data-nat-action="confirm-delete-destination"]');
  await waitForDrawerClosed(page);
  await page.waitForFunction(async () => {
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok) return false;
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const candidateText = JSON.stringify(candidate);
    const runningText = JSON.stringify(running);
    return !candidateText.includes("publish-web-entry") &&
      !candidateText.includes("allow-untrust-to-dmz-publish-private-host-publish-service-8443") &&
      !runningText.includes("publish-web-entry") &&
      !runningText.includes("allow-untrust-to-dmz-publish-private-host-publish-service-8443") &&
      (document.querySelector(".rule-simulator")?.textContent || "").includes("linked generated allow rule allow-untrust-to-dmz-publish-private-host-publish-service-8443 removed");
  }, null, { timeout: 10000 });
  const state = await page.evaluate(() => ({
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (state.overflow > 2) {
    throw new Error(`published service delete cleanup introduced overflow at ${viewport.name}: ${state.overflow}px`);
  }
  for (const expected of ["Destination NAT publish-web-entry deleted from candidate", "Candidate NAT", "former published path"]) {
    if (!state.text.includes(expected)) {
      throw new Error(`published service delete cleanup missing ${expected}: ${state.text}`);
    }
  }
}

function sameArray(actual = [], expected = []) {
  return JSON.stringify([...(actual || [])].sort()) === JSON.stringify([...(expected || [])].sort());
}

async function seedRulesWorkspaceCandidate(page) {
  return await page.evaluate(async () => {
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before rules seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const runningBody = await running.json();
    const previousPolicy = runningBody?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"] },
        { name: "dmz", interfaces: ["eth2"] },
        { name: "wan", interfaces: ["eth0"] },
      ],
      addresses: [
        { name: "inside-net", cidr: "10.100.1.0/24" },
        { name: "web-server", cidr: "10.100.2.20/32" },
        { name: "internet", cidr: "0.0.0.0/0" },
      ],
      services: [
        { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] },
        { name: "ssh", protocol: "PROTOCOL_TCP", ports: [{ start: 22 }] },
        { name: "dns", protocol: "PROTOCOL_UDP", ports: [{ start: 53 }] },
      ],
      applications: [
        { name: "web-browsing", displayName: "Web browsing", category: "business", ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }] },
      ],
      hostInput: {
        defaultAction: "ACTION_DENY",
        rules: [{
          name: "allow-admin-ssh",
          sourceAddresses: ["inside-net"],
          services: ["ssh"],
          action: "ACTION_ALLOW",
          log: false,
        }],
      },
      rules: [
        {
          name: "allow-web",
          fromZones: ["lan"],
          toZones: ["dmz"],
          sourceAddresses: ["inside-net"],
          destinationAddresses: ["web-server"],
          services: ["https"],
          applications: ["any"],
          action: "ACTION_ALLOW",
          log: true,
          disabled: false,
          tags: ["owner:web", "env:prod"],
          description: "Visual smoke seed allow path.",
        },
        {
          name: "drop-ssh",
          fromZones: ["wan"],
          toZones: ["lan"],
          sourceAddresses: ["internet"],
          destinationAddresses: ["inside-net"],
          services: ["ssh"],
          applications: ["any"],
          action: "ACTION_DENY",
          log: false,
          disabled: false,
          tags: ["cleanup"],
          description: "Visual smoke seed cleanup candidate.",
        },
        {
          name: "allow-dns",
          fromZones: ["lan"],
          toZones: ["wan"],
          sourceAddresses: ["inside-net"],
          destinationAddresses: ["internet"],
          services: ["dns"],
          applications: ["any"],
          action: "ACTION_ALLOW",
          log: true,
          disabled: true,
          tags: ["owner:dns"],
          description: "Visual smoke disabled rule.",
        },
      ],
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return previousPolicy;
  });
}

async function seedRulesInspectionBypassCandidate(page) {
  await page.evaluate(async () => {
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"] },
        { name: "dmz", interfaces: ["eth2"] },
        { name: "wan", interfaces: ["eth0"] },
      ],
      addresses: [
        { name: "inside-net", cidr: "10.100.1.0/24" },
        { name: "web-server", cidr: "10.100.2.20/32" },
        { name: "internet", cidr: "0.0.0.0/0" },
      ],
      services: [
        { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] },
        { name: "ssh", protocol: "PROTOCOL_TCP", ports: [{ start: 22 }] },
      ],
      ids: {
        enabled: true,
        mode: "IDS_MODE_PREVENT",
        monitorInterfaces: ["eth1"],
        homeNetworks: ["10.100.1.0/24"],
        ruleFiles: ["visual-smoke-threat.rules"],
        queueNum: 12,
        failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      },
      rules: [
        {
          name: "allow-web",
          fromZones: ["lan"],
          toZones: ["dmz"],
          sourceAddresses: ["inside-net"],
          destinationAddresses: ["web-server"],
          services: ["https"],
          applications: ["any"],
          action: "ACTION_ALLOW",
          log: true,
          disabled: false,
          tags: ["owner:web", "inspection:bypass-risk"],
          description: "Visual smoke fail-open inspection coverage.",
        },
        {
          name: "drop-ssh",
          fromZones: ["wan"],
          toZones: ["lan"],
          sourceAddresses: ["internet"],
          destinationAddresses: ["inside-net"],
          services: ["ssh"],
          applications: ["any"],
          action: "ACTION_DENY",
          log: true,
          disabled: false,
          tags: ["inspection:prefilter-drop"],
          description: "Visual smoke drop before inspection.",
        },
      ],
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed inspection bypass candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
  });
}

async function assertRulesInspectionBypassCoverageWorkflow(page, viewport) {
  await seedRulesInspectionBypassCandidate(page);
  await page.reload({ waitUntil: "networkidle", timeout: 30000 });
  await page.evaluate(() => { location.hash = "#/rules"; });
  await waitForRouteReady(page, "/rules");
  await page.waitForSelector('[data-rule-hygiene-panel="true"]', { timeout: 10000 });

  const initial = await rulesInspectionCoverageState(page);
  if (!initial.hygieneText.includes("Bypass-risk allows") || !initial.hygieneText.includes("Open inspection")) {
    throw new Error(`rules bypass-risk hygiene was not actionable at ${viewport.name}: ${initial.hygieneText}`);
  }
  if (initial.allowInspection.state !== "ips-fail-open" || initial.allowInspection.bypass !== "true") {
    throw new Error(`allow-web inspection state did not expose fail-open bypass risk: ${JSON.stringify(initial.allowInspection)}`);
  }
  if (!initial.allowInspection.text.includes("Inline prevention can bypass traffic")) {
    throw new Error(`allow-web inspection detail did not explain bypass risk: ${initial.allowInspection.text}`);
  }
  if (initial.dropInspection.state !== "pre-filter-drop" || initial.dropInspection.bypass !== "false") {
    throw new Error(`drop-ssh inspection state did not show pre-filter drop: ${JSON.stringify(initial.dropInspection)}`);
  }
  if (initial.runningText.includes("visual-smoke-threat.rules")) {
    throw new Error("inspection bypass candidate leaked into running policy before commit");
  }

  await page.evaluate(() => {
    const chip = [...document.querySelectorAll('[data-rule-hygiene-title="Bypass-risk allows"]')]
      .find((candidate) => candidate.matches(".rule-hygiene-chip"));
    if (!chip) throw new Error("Bypass-risk allows hygiene chip was not found");
    chip.click();
  });
  await page.waitForFunction(() => {
    const hash = location.hash || "";
    const rows = [...document.querySelectorAll("tr[data-rule-name]")].map((row) => row.dataset.ruleName || "");
    return hash.includes("q=bypass-risk") && rows.length === 1 && rows[0] === "allow-web";
  }, null, { timeout: 5000 });
  const filtered = await rulesInspectionCoverageState(page);
  if (filtered.visibleRuleNames.join(",") !== "allow-web") {
    throw new Error(`bypass-risk filter did not isolate allow-web: ${JSON.stringify(filtered.visibleRuleNames)}`);
  }
  if (filtered.overflow > 2) {
    throw new Error(`rules inspection coverage introduced overflow at ${viewport.name}: ${filtered.overflow}px`);
  }

  await page.evaluate(() => {
    const link = document.querySelector('[data-rule-hygiene-action="open-route"][data-rule-hygiene-route="#/inspection"]');
    if (!link) throw new Error("Open inspection action was not present on bypass-risk finding");
    link.click();
  });
  await waitForRouteReady(page, "/inspection");
  await page.waitForSelector("[data-inspection-workspace='true']", { timeout: 10000 });
  const inspectionText = await page.evaluate(() => (document.querySelector("[data-inspection-workspace='true']")?.textContent || "").replace(/\s+/g, " ").trim());
  if (!inspectionText.includes("Inspection profile") || !inspectionText.includes("Runtime posture")) {
    throw new Error(`inspection pivot from bypass-risk finding did not land on workspace: ${inspectionText}`);
  }
}

async function rulesInspectionCoverageState(page) {
  return await page.evaluate(async () => {
    const rowState = (name) => {
      const row = document.querySelector(`tr[data-rule-name="${CSS.escape(name)}"]`);
      const inspection = row?.querySelector("[data-rule-inspection-state]");
      return {
        present: Boolean(row),
        text: (inspection?.textContent || "").replace(/\s+/g, " ").trim(),
        state: inspection?.dataset?.ruleInspectionState || "",
        bypass: inspection?.dataset?.ruleInspectionBypass || "",
      };
    };
    const runningResponse = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    return {
      hygieneText: (document.querySelector('[data-rule-hygiene-panel="true"]')?.textContent || "").replace(/\s+/g, " ").trim(),
      allowInspection: rowState("allow-web"),
      dropInspection: rowState("drop-ssh"),
      visibleRuleNames: [...document.querySelectorAll("tr[data-rule-name]")].map((row) => row.dataset.ruleName || ""),
      runningText: JSON.stringify(running),
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
}

async function restoreRulesWorkspaceCandidate(page, previousPolicy = {}) {
  await page.evaluate(async (policy) => {
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy: policy || {} }),
    });
    if (!response.ok) {
      throw new Error(`restore candidate after rules smoke failed with HTTP ${response.status}: ${await response.text()}`);
    }
  }, previousPolicy);
}

async function assertPerformanceBenchmarkEvidenceVerifier(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/performance";
  });
  await waitForRouteReady(page, "/performance");
  await page.waitForSelector('[data-perf-route="true"]', { timeout: 10000 });
  await assertPerformanceActionButtons(page, viewport);
  await assertPerformanceCollectionRunbook(page, viewport);
  await assertPerformanceAutomationContext(page, viewport);

  const inspected = await resolvePerfFixturePath("publishable-inspected");
  const mismatch = await resolvePerfFixturePath("mismatch-blocked");

  await selectSyntheticPerfRunDirectory(page, [
    { path: "perf/results/dupe/summary.json", text: "{}" },
    { path: "perf/results/dupe/archive/summary.json", text: "{}" },
  ]);
  await assertPerformanceToast(page, "Benchmark run not loaded", "Duplicate artifact names");
  await waitForPerformanceState(page, "duplicate directory rejected", (state) => (
    state.verdict === "empty" &&
    state.artifacts.iperf?.includes("not loaded") &&
    state.text.includes("No summary loaded")
  ));

  await selectSyntheticPerfRunDirectory(page, [
    { path: "perf/results/oversize/summary.json", text: "x".repeat((2 * 1024 * 1024) + 1) },
  ]);
  await assertPerformanceToast(page, "Benchmark run not loaded", "over the 2.0 MiB limit");
  await waitForPerformanceState(page, "oversized directory rejected", (state) => state.verdict === "empty");

  await uploadPerfFile(page, "summary", inspected.summary);
  await waitForPerformanceState(page, "summary warnings", (state) => (
    state.verdict === "warn" &&
    state.artifacts.iperf?.includes("not loaded") &&
    state.artifacts.status?.includes("not loaded") &&
    state.artifacts.nft?.includes("not loaded") &&
    hasPerformanceSummaryOnlyRawWarnings(state) &&
    state.repairs.some((step) => step.text.includes("Load raw iperf3 evidence")) &&
    state.repairs.some((step) => step.text.includes("Load active runtime status"))
  ));
  await assertPerformanceRepairCommandCopy(page, viewport, "load-active-runtime-status", "ngfwctl status > ngfw-status-active.txt");

  await page.check('[data-perf-toggle="strict"]');
  await waitForPerformanceState(page, "strict warning gate", (state) => (
    state.verdict === "bad" &&
    state.gateState === "bad" &&
    state.artifacts.iperf?.includes("not loaded") &&
    state.artifacts.status?.includes("not loaded") &&
    state.artifacts.nft?.includes("not loaded") &&
    hasPerformanceSummaryOnlyRawWarnings(state) &&
    state.text.includes("Strict gate failed")
  ));

  await page.click('[data-perf-action="clear"]');
  await waitForPerformanceState(page, "clear after strict", (state) => state.verdict === "empty");

  await uploadPerfFile(page, "summary", inspected.summary);
  await uploadPerfFile(page, "iperf", inspected.iperf);
  await uploadPerfFile(page, "status", inspected.status);
  await waitForPerformanceState(page, "publishable inspected evidence", (state) => (
    state.verdict === "ok" &&
    state.gateState === "ok" &&
    state.artifacts.iperf?.includes("iperf3.json") &&
    state.artifacts.status?.includes("ngfw-status-active.txt") &&
    state.artifacts.nft?.includes("not loaded") &&
    state.metrics.throughput === "1.000 Gbps" &&
    state.metrics.rawIperf.includes("1.000 Gbps") &&
    state.metrics.rawStatus.includes("ready") &&
    state.metrics.rawNft.includes("not loaded") &&
    state.text.includes("No findings.")
  ));
  const inspectedState = await collectPerformanceState(page);
  if (inspectedState.overflow > 2) {
    throw new Error(`performance publishable verifier overflow at ${viewport.name}: ${inspectedState.overflow}px`);
  }
  await assertPerformanceReleaseEvidenceOwnership(page, viewport);
  await page.evaluate(() => { location.hash = "#/performance"; });
  await waitForRouteReady(page, "/performance");
  await page.waitForSelector('[data-perf-route="true"]', { timeout: 10000 });
  await uploadPerfFile(page, "summary", inspected.summary);
  await uploadPerfFile(page, "iperf", inspected.iperf);
  await uploadPerfFile(page, "status", inspected.status);
  await waitForPerformanceState(page, "publishable inspected evidence restored after owner check", (state) => (
    state.verdict === "ok" &&
    state.gateState === "ok" &&
    state.artifacts.iperf?.includes("iperf3.json") &&
    state.artifacts.status?.includes("ngfw-status-active.txt") &&
    state.metrics.rawIperf.includes("1.000 Gbps") &&
    state.metrics.rawStatus.includes("ready") &&
    state.metrics.rawNft.includes("not loaded")
  ));

  await page.click('[data-perf-action="use-live-status"]');
  await waitForPerformanceState(page, "live status label", (state) => (
    state.artifacts.status === "status: live /v1/system/status"
  ), 15000);

  await page.click('[data-perf-action="clear"]');
  await waitForPerformanceState(page, "clear before mismatch", (state) => state.verdict === "empty");
  await uploadPerfFile(page, "summary", mismatch.summary);
  await uploadPerfFile(page, "iperf", mismatch.iperf);
  await uploadPerfFile(page, "status", mismatch.status);
  await waitForPerformanceState(page, "mismatch blocked", (state) => (
    state.verdict === "bad" &&
    state.gateState === "bad" &&
    state.findings.some((finding) => finding.text.includes("tcp_bits_per_second")) &&
    state.findings.some((finding) => finding.text.includes("target.ip")) &&
    state.repairs.some((step) => step.text.includes("Fix blocking evidence errors")) &&
    state.repairs.some((step) => step.text.includes("Regenerate the summary from the raw artifacts"))
  ));
  await assertPerformanceRepairCommandCopy(page, viewport, "fix-blocking-evidence-errors", "ngfwperf verify --strict --publishable perf/results/<run>");
  await assertPerformanceRepairCommandCopy(page, viewport, "regenerate-the-summary-from-the-raw-artifacts", "ngfwperf verify --strict perf/results/<run>");

  await page.click('[data-perf-action="clear"]');
  await waitForPerformanceState(page, "final clear", (state) => state.verdict === "empty");
}

function hasPerformanceSummaryOnlyRawWarnings(state) {
  const expected = [
    "raw iperf3.json is not loaded; throughput cannot be traced to raw iperf evidence",
    "inspection_evidence.status_captured is true but no raw ngfwctl status artifact is loaded",
    "host_tuning_evidence.status_captured is true but no raw ngfwctl status artifact is loaded",
    "conntrack_evidence.status_captured is true but no raw ngfwctl status artifact is loaded",
  ];
  return state.findings.length === expected.length && expected.every((message) => (
    state.findings.some((finding) => finding.text.includes(message))
  ));
}

async function assertPerformanceReleaseEvidenceOwnership(page, viewport) {
  const state = await collectPerformanceState(page);
  if (state.retiredReadinessHref) {
    throw new Error(`performance release handoff linked to retired readiness ownership at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const required of [
    "It does not record release evidence or certify a performance claim.",
    "Benchmark collection runbook",
    "make benchmark-verify-release",
    "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status",
  ]) {
    if (!state.text.includes(required)) {
      throw new Error(`performance release handoff missed ${required} at ${viewport.name}: ${state.text}`);
    }
  }
}

async function assertPerformanceAutomationContext(page, viewport) {
  const copied = await assertAutomationContextDrawer(page, viewport, "performance automation context", [
    "#/performance",
    "/v1/system/status",
    "make benchmark-netns-check",
    "sudo DURATION=30 PARALLEL=8 make benchmark-netns",
    "make benchmark-check",
    "make benchmark",
    "ngfwperf verify perf/results",
    "make benchmark-verify-release",
    "ngfwctl status > ngfw-status-active.txt",
    "sudo nft list table inet openngfw > nft-openngfw-final.txt",
    "Claims must stay scoped to loaded raw evidence",
  ]);
  for (const required of [
    "GET /v1/system/status",
    "make benchmark-netns-check",
    "sudo DURATION=30 PARALLEL=8 make benchmark-netns",
    "make benchmark-check",
    "make benchmark",
    "ngfwperf verify perf/results",
    "make benchmark-verify-release",
    "ngfwctl status > ngfw-status-active.txt",
    "sudo nft list table inet openngfw > nft-openngfw-final.txt",
  ]) {
    if (!copied.includes(required)) {
      throw new Error(`performance automation copied context missing ${required} at ${viewport.name}`);
    }
  }
}

async function assertPerformanceActionButtons(page, viewport) {
  const state = await page.evaluate(() => {
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = window.getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    const buttons = [...document.querySelectorAll('[data-perf-route="true"] button[data-perf-action]')]
      .filter(visible)
      .map((button) => ({
        action: button.getAttribute("data-perf-action") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      }));
    return {
      buttons,
      actions: buttons.map((button) => button.action),
      invalid: buttons.filter((button) => (
        button.type !== "button" ||
        !button.title.trim() ||
        !button.ariaLabel.trim() ||
        !button.action
      )),
    };
  });
  if (state.invalid.length) {
    throw new Error(`performance action controls missing button semantics at ${viewport.name}: ${JSON.stringify(state.invalid)}`);
  }
  for (const action of ["verify", "use-live-status", "clear", "copy-runbook-command", "copy-runbook-release", "copy-runbook"]) {
    if (!state.actions.includes(action)) {
      throw new Error(`performance missing ${action} action button at ${viewport.name}: ${JSON.stringify(state.actions)}`);
    }
  }
}

async function assertPerformanceCollectionRunbook(page, viewport) {
  const state = await page.evaluate(() => {
    const route = document.querySelector('[data-perf-route="true"]');
    const root = route?.querySelector("[data-perf-runbook='true']")?.closest(".card") ||
      route?.querySelector("[data-perf-runbook='true']");
    const rect = root?.getBoundingClientRect?.();
    const workflowTexts = [...(root?.querySelectorAll("[data-perf-runbook-workflow]") || [])].map((el) => ({
      id: el.getAttribute("data-perf-runbook-workflow") || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    const commands = [...(root?.querySelectorAll("[data-perf-runbook-command]") || [])].map((el) => ({
      id: el.getAttribute("data-perf-runbook-command") || "",
      text: (el.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    return {
      visible: Boolean(root && rect && rect.width > 0 && rect.height > 0 && getComputedStyle(root).display !== "none"),
      text: (root?.textContent || "").replace(/\s+/g, " ").trim(),
      workflowTexts,
      commands,
      overflow: root ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(root.scrollWidth - root.clientWidth),
      ) : 0,
    };
  });
  if (!state.visible) throw new Error(`performance collection runbook was not visible at ${viewport.name}`);
  if (state.overflow > 2) throw new Error(`performance collection runbook overflow at ${viewport.name}: ${state.overflow}px`);
  for (const required of [
    "Benchmark collection runbook",
    "Local netns smoke",
    "Three-host field run",
    "make benchmark-netns-check",
    "sudo DURATION=30 PARALLEL=8 make benchmark-netns",
    "make benchmark-check",
    "make benchmark",
    "go run ./cmd/ngfwperf verify --strict perf/results",
    "make benchmark-verify-release",
    "Use live status is current posture only",
  ]) {
    if (!state.text.includes(required)) {
      throw new Error(`performance collection runbook missing ${required} at ${viewport.name}`);
    }
  }
  if (!state.workflowTexts.some((workflow) => workflow.id === "local-netns") ||
      !state.workflowTexts.some((workflow) => workflow.id === "three-host")) {
    throw new Error(`performance collection runbook missing workflow hooks at ${viewport.name}: ${JSON.stringify(state.workflowTexts)}`);
  }
  if (!state.commands.some((command) => command.id === "local-netns-check-host-prerequisites")) {
    throw new Error(`performance collection runbook missing command hook at ${viewport.name}: ${JSON.stringify(state.commands)}`);
  }
  await assertPerformanceRunbookCopy(page, viewport, {
    selector: '[data-perf-runbook-command="local-netns-check-host-prerequisites"] [data-perf-action="copy-runbook-command"]',
    required: ["make benchmark-netns-check"],
    label: "local netns check command",
  });
  await assertPerformanceRunbookCopy(page, viewport, {
    selector: '[data-perf-action="copy-runbook"]',
    required: ["Benchmark collection runbook", "make benchmark-netns-check", "make benchmark-check", "make benchmark-verify-release", "browser-local command handoff"],
    label: "full runbook",
  });
}

async function assertPerformanceRunbookCopy(page, viewport, { selector, required, label }) {
  await page.evaluate(() => {
    globalThis.__performanceCopiedCommand = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__performanceCopiedCommand = String(text || "");
          },
        },
      });
    } catch {
      try {
        navigator.clipboard.writeText = async (text) => {
          globalThis.__performanceCopiedCommand = String(text || "");
        };
      } catch {}
    }
  });
  await page.click(selector);
  await page.waitForFunction(() => Boolean(globalThis.__performanceCopiedCommand), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__performanceCopiedCommand || "");
  for (const item of required) {
    if (!copied.includes(item)) {
      throw new Error(`performance ${label} copy missing ${item} at ${viewport.name}: ${JSON.stringify(copied)}`);
    }
  }
  assertNoInvestigationLeak(copied, `performance ${label} copy ${viewport.name}`);
}

async function assertPerformanceRepairCommandCopy(page, viewport, stepId, expectedCommand) {
  await page.evaluate(() => {
    globalThis.__performanceCopiedCommand = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__performanceCopiedCommand = String(text || "");
          },
        },
      });
    } catch {
      try {
        navigator.clipboard.writeText = async (text) => {
          globalThis.__performanceCopiedCommand = String(text || "");
        };
      } catch {}
    }
  });
  await page.evaluate((id) => {
    const row = document.querySelector(`[data-perf-repair-step="${id}"]`);
    const button = row?.querySelector('[data-perf-action="copy-command"]');
    if (!button) throw new Error(`performance repair copy button was not found for ${id}`);
    const metadata = {
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    };
    if (metadata.type !== "button" || !metadata.title || !metadata.ariaLabel) {
      throw new Error(`performance repair copy button missing semantics for ${id}: ${JSON.stringify(metadata)}`);
    }
    button.click();
  }, stepId);
  await page.waitForFunction(() => Boolean(globalThis.__performanceCopiedCommand), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__performanceCopiedCommand || "");
  if (copied !== expectedCommand) {
    throw new Error(`performance repair command copy mismatch at ${viewport.name}: got ${JSON.stringify(copied)}, want ${JSON.stringify(expectedCommand)}`);
  }
  assertNoInvestigationLeak(copied, `performance repair command copy ${viewport.name}`);
}

function perfFixturePath(name) {
  const base = join(repoRoot, "e2e", "fixtures", "performance", name);
  return {
    summary: join(base, "summary.json"),
    iperf: join(base, "iperf3.json"),
    status: join(base, "ngfw-status-active.txt"),
  };
}

async function resolvePerfFixturePath(name) {
  const paths = perfFixturePath(name);
  if (await perfFixtureExists(paths)) return paths;
  const fixture = performanceFixturePayload(name);
  const base = await mkdtemp(join(tmpdir(), `openngfw-perf-fixture-${name}-`));
  const fallback = {
    summary: join(base, "summary.json"),
    iperf: join(base, "iperf3.json"),
    status: join(base, "ngfw-status-active.txt"),
  };
  await writeFile(fallback.summary, fixture.summary);
  await writeFile(fallback.iperf, fixture.iperf);
  await writeFile(fallback.status, fixture.status);
  return fallback;
}

async function perfFixtureExists(paths = {}) {
  try {
    await Promise.all([access(paths.summary), access(paths.iperf), access(paths.status)]);
    return true;
  } catch {
    return false;
  }
}

function performanceFixturePayload(name) {
  const status = [
    "policy dataplane:",
    "  inspection:      IPS prevent",
    "  inspection ready:ready",
    "  inspection eng:  suricata managed/active",
    "  fail behavior:   fail-closed",
    "  kernel tuning:  ready",
    "  state table:    ready 25/1048576 entries (0.002%)",
    "",
  ].join("\n");
  const summary = JSON.stringify({
    schema_version: "phragma.perf.v1",
    generated_at: "2026-06-17T05:00:00Z",
    profile: "ids-prevent-large-flow",
    security_services: "suricata-prevent",
    inspection_state: "fully-inspected",
    target: { ip: "10.0.2.20", port: 5201 },
    duration_seconds: 60,
    parallel_streams: 4,
    tcp_bits_per_second: 1000000000,
    tcp_gbps: 1.0,
    tcp_retransmits: 7,
    inspection_evidence: {
      state: "ready",
      status_captured: true,
      inspection_state: "fully-inspected",
      engine_name: "suricata",
      engine_mode: "managed",
      engine_state: "active",
      failure_behavior: "fail-closed",
    },
    host_tuning_evidence: {
      state: "ready",
      status_captured: true,
      profile: "throughput",
    },
    conntrack_evidence: {
      state: "ready",
      status_captured: true,
      current_entries: 25,
      max_entries: 1048576,
      usage_percent: 0.002,
    },
    claim_scope: "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details",
  }, null, 2) + "\n";
  const publishableIperf = {
    start: { connecting_to: { host: "10.0.2.20", port: 5201 }, test_start: { num_streams: 4, duration: 60 } },
    end: { sum_received: { bits_per_second: 1000000000 }, sum_sent: { bits_per_second: 1001000000, retransmits: 7 } },
  };
  const mismatchIperf = {
    start: { connecting_to: { host: "10.0.9.99", port: 5201 }, test_start: { num_streams: 4, duration: 60 } },
    end: { sum_received: { bits_per_second: 900000000 }, sum_sent: { bits_per_second: 900000000, retransmits: 7 } },
  };
  if (name === "publishable-inspected") {
    return { summary, iperf: JSON.stringify(publishableIperf, null, 2) + "\n", status };
  }
  if (name === "mismatch-blocked") {
    return { summary, iperf: JSON.stringify(mismatchIperf, null, 2) + "\n", status };
  }
  throw new Error(`unknown performance fixture ${name}`);
}

async function uploadPerfFile(page, kind, path) {
  await page.setInputFiles(`[data-perf-file="${kind}"]`, path);
}

async function selectSyntheticPerfRunDirectory(page, files) {
  await page.evaluate((items) => {
    const input = document.querySelector('[data-perf-file="run-directory"]');
    if (!input) throw new Error("performance run-directory input was not found");
    const transfer = new DataTransfer();
    for (const item of items) {
      const name = String(item.path || "artifact.txt").split("/").pop();
      const file = new File([String(item.text || "")], name, { type: item.type || "application/octet-stream" });
      Object.defineProperty(file, "webkitRelativePath", { configurable: true, value: item.path });
      transfer.items.add(file);
    }
    input.files = transfer.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, files);
}

async function assertPerformanceToast(page, title, body) {
  await page.waitForFunction(({ expectedTitle, expectedBody }) => {
    const text = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes(expectedTitle) && text.includes(expectedBody);
  }, { expectedTitle: title, expectedBody: body }, { timeout: 5000 });
}

async function waitForPerformanceState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await collectPerformanceState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`performance ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function collectPerformanceState(page) {
  return await page.evaluate(() => {
    const content = document.querySelector("#content");
    const route = document.querySelector('[data-perf-route="true"]');
    const rect = route?.getBoundingClientRect?.();
    const metricValue = (name) => {
      const node = route?.querySelector(`[data-perf-metric="${name}"] strong`);
      return (node?.textContent || "").replace(/\s+/g, " ").trim();
    };
    const artifactValue = (name) => (
      route?.querySelector(`[data-perf-artifact="${name}"]`)?.textContent || ""
    ).replace(/\s+/g, " ").trim();
    const rowList = (selector) => [...(route?.querySelectorAll(selector) || [])].map((row) => ({
      id: row.getAttribute(selector.includes("repair") ? "data-perf-repair-step" : selector.includes("finding") ? "data-perf-finding" : "data-perf-gate") || "",
      text: (row.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    return {
      text: (content?.textContent || "").replace(/\s+/g, " ").trim(),
      toasts: (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim(),
      verdict: route?.querySelector("[data-perf-verdict]")?.getAttribute("data-perf-verdict") || "",
      gateState: route?.querySelector("[data-perf-gate-state]")?.getAttribute("data-perf-gate-state") || "",
      retiredReadinessHref: route?.querySelector('a[href^="#/readiness"]')?.getAttribute("href") || "",
      artifacts: {
        iperf: artifactValue("iperf"),
        status: artifactValue("status"),
        nft: artifactValue("packet-filter"),
      },
      metrics: {
        throughput: metricValue("throughput"),
        rawIperf: metricValue("raw-iperf"),
        rawStatus: metricValue("raw-status"),
        rawNft: metricValue("raw-packet-filter"),
      },
      repairs: rowList("[data-perf-repair-step]"),
      findings: rowList("[data-perf-finding]"),
      overflow: route ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(route.scrollWidth - route.clientWidth),
      ) : 0,
    };
  });
}

async function assertNetvpnDynamicRoutingEditors(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const seed = await seedNetvpnDynamicRoutingCandidate(page);
  const markers = {
    bgpDescription: `visual-bgp-${viewport.name}`,
    localAsn: "65101",
    bgpPrefix: "10.200.10.0/24",
    ospfOne: "10.200.20.0/24",
    ospfTwo: "10.200.21.0/24",
  };
  try {
    await forceRouteReload(page, "/netvpn");
    await assertNetvpnActionControls(page, viewport, [
      { action: "add-route", ariaLabel: "Add static route to candidate", title: "Add static route" },
      { action: "configure-bgp", ariaLabel: "Configure BGP candidate settings", title: "Configure BGP candidate settings" },
      { action: "configure-ospf", ariaLabel: "Configure OSPF candidate settings", title: "Configure OSPF candidate settings" },
      { action: "add-ipsec", ariaLabel: "Add IPsec tunnel to candidate", title: "Add IPsec tunnel" },
      { action: "open-wireguard-rollout", ariaLabel: "Open WireGuard branch rollout workflow", title: "Open WireGuard branch rollout" },
      { action: "add-wireguard", ariaLabel: "Add WireGuard interface to candidate", title: "Add WireGuard interface" },
    ]);

    await page.click('[data-netvpn-action="configure-bgp"]');
    await waitForDrawerTitleStep(page, "Configure BGP", "netvpn BGP drawer open");
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="local-asn"]', markers.localAsn);
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="router-id"]', "192.0.2.999");
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="neighbor-address"]', "198.51.100.20");
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="neighbor-remote-asn"]', "65102");
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="neighbor-description"]', markers.bgpDescription);
    await page.click('#drawer:not([hidden]) [data-netvpn-action="add-bgp-prefix"]');
    await assertNetvpnActionControls(page, viewport, [
      { action: "add-bgp-neighbor", ariaLabel: "Add BGP neighbor row", title: "Add BGP neighbor row" },
      { action: "add-bgp-prefix", ariaLabel: "Add BGP announced prefix row", title: "Add BGP announced prefix row" },
      { action: "cancel-bgp", ariaLabel: "Cancel BGP configuration", title: "Cancel BGP configuration" },
      { action: "stage-bgp", ariaLabel: "Stage BGP candidate settings", title: "Stage BGP candidate settings" },
    ], "#drawer:not([hidden])");
    await assertNetvpnEditorRemoveActions(page, viewport, [
      { action: "remove-bgp-neighbor", ariaLabel: "Remove BGP neighbor", title: "Remove neighbor" },
      { action: "remove-bgp-prefix", ariaLabel: "Remove BGP announced prefix", title: "Remove prefix" },
    ]);
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="announce-prefix"]', "10.200.10.0/33");
    await assertNetvpnStageBlocked(page, {
      label: "BGP invalid router ID",
      clickSelector: '#drawer:not([hidden]) [data-netvpn-action="stage-bgp"]',
      toastTitle: "BGP not staged",
      toastBody: "Router ID must be an IPv4 address.",
      before: await netvpnDynamicRoutingState(page),
    });
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="router-id"]', "192.0.2.10");
    await page.fill('#drawer:not([hidden]) [data-netvpn-bgp-field="announce-prefix"]', markers.bgpPrefix);
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-bgp"]');
    await waitForDrawerClosed(page);
    await waitForNetvpnDynamicRoutingState(page, "BGP candidate", (state) => (
      state.candidate.bgp?.enabled === true &&
      state.candidate.bgp?.asn === Number(markers.localAsn) &&
      state.candidate.bgp?.routerId === "192.0.2.10" &&
      state.candidate.bgpNeighbor?.address === "198.51.100.20" &&
      state.candidate.bgpNeighbor?.remoteAsn === 65102 &&
      state.candidate.bgpNeighbor?.description === markers.bgpDescription &&
      state.candidate.bgp?.announceNetworks?.includes(markers.bgpPrefix) &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    await page.click('[data-netvpn-action="configure-ospf"]');
    await waitForDrawerTitleStep(page, "Configure OSPF", "netvpn OSPF drawer open");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ospf-field="router-id"]', "192.0.2.20");
    await assertNetvpnActionControls(page, viewport, [
      { action: "add-ospf-area", ariaLabel: "Add OSPF area row", title: "Add OSPF area row" },
      { action: "cancel-ospf", ariaLabel: "Cancel OSPF configuration", title: "Cancel OSPF configuration" },
      { action: "stage-ospf", ariaLabel: "Stage OSPF candidate settings", title: "Stage OSPF candidate settings" },
    ], "#drawer:not([hidden])");
    await assertNetvpnEditorRemoveActions(page, viewport, [
      { action: "remove-ospf-area", ariaLabel: "Remove OSPF area", title: "Remove area" },
    ]);
    await page.fill('#drawer:not([hidden]) [data-netvpn-ospf-field="area-id"]', "area-zero");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ospf-field="networks"]', "10.200.20.0/33");
    await assertNetvpnStageBlocked(page, {
      label: "OSPF invalid area",
      clickSelector: '#drawer:not([hidden]) [data-netvpn-action="stage-ospf"]',
      toastTitle: "OSPF not staged",
      toastBody: "OSPF area area-zero must use dotted IPv4 format.",
      before: await netvpnDynamicRoutingState(page),
    });
    await page.fill('#drawer:not([hidden]) [data-netvpn-ospf-field="area-id"]', "0.0.0.0");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ospf-field="networks"]', `${markers.ospfOne}, ${markers.ospfTwo}`);
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-ospf"]');
    await waitForDrawerClosed(page);
    await waitForNetvpnDynamicRoutingState(page, "OSPF candidate", (state) => (
      state.candidate.ospf?.enabled === true &&
      state.candidate.ospf?.routerId === "192.0.2.20" &&
      state.candidate.ospfArea?.area === "0.0.0.0" &&
      state.candidate.ospfArea?.networks?.includes(markers.ospfOne) &&
      state.candidate.ospfArea?.networks?.includes(markers.ospfTwo) &&
      state.status.dirty === true &&
      state.status.routingChanged === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    await page.waitForFunction((expected) => {
      const text = [...document.querySelectorAll('[data-netvpn-section="bgp"], [data-netvpn-section="ospf"]')]
        .map((section) => section.textContent || "")
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      return text.includes(expected.bgpDescription) &&
        text.includes(expected.bgpPrefix) &&
        text.includes(expected.ospfOne) &&
        text.includes(expected.ospfTwo) &&
        text.includes("candidate edit");
    }, markers, { timeout: 10000 });

    const routeState = await collectNetvpnDynamicRoutingPanelState(page);
    for (const required of ["BGP", "candidate edit", markers.bgpDescription, markers.bgpPrefix, "OSPF", markers.ospfOne, markers.ospfTwo]) {
      if (!routeState.text.includes(required)) {
        throw new Error(`netvpn dynamic routing panel missing ${required} at ${viewport.name}: ${routeState.text}`);
      }
    }
    if (routeState.overflow > 2) {
      throw new Error(`netvpn dynamic routing panel overflow at ${viewport.name}: ${routeState.overflow}px`);
    }

    await page.click('[data-netvpn-action="disable-bgp"]');
    await waitForDrawerTitleStep(page, "Disable BGP?", "netvpn BGP disable confirmation");
    await clickDrawerFooterButton(page, "Disable");
    await waitForDrawerClosed(page);
    await page.waitForFunction(() => {
      const text = (document.querySelector('[data-netvpn-section="bgp"]')?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("BGP not enabled") && text.includes("Configure BGP");
    }, null, { timeout: 10000 });
    await waitForNetvpnDynamicRoutingState(page, "BGP disabled candidate", (state) => (
      state.candidate.bgp?.enabled === false &&
      state.candidate.ospf?.enabled === true &&
      state.status.dirty === true &&
      state.status.routingChanged === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    await page.click('[data-netvpn-action="disable-ospf"]');
    await waitForDrawerTitleStep(page, "Disable OSPF?", "netvpn OSPF disable confirmation");
    await clickDrawerFooterButton(page, "Disable");
    await waitForDrawerClosed(page);
    await page.waitForFunction(() => {
      const text = (document.querySelector('[data-netvpn-section="ospf"]')?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("OSPF not enabled") && text.includes("Configure OSPF");
    }, null, { timeout: 10000 });
    await waitForNetvpnDynamicRoutingState(page, "dynamic routing disabled candidate", (state) => (
      state.candidate.bgp?.enabled === false &&
      state.candidate.ospf?.enabled === false &&
      state.status.dirty === true &&
      state.status.routingChanged === true &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    await page.waitForFunction(() => {
      const text = [...document.querySelectorAll('[data-netvpn-section="bgp"], [data-netvpn-section="ospf"]')]
        .map((section) => section.textContent || "")
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      return text.includes("BGP not enabled") &&
        text.includes("OSPF not enabled") &&
        text.includes("candidate edit");
    }, null, { timeout: 10000 });

    await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
    await waitForRouteReady(page, "/changes");
    await page.waitForFunction(() => {
      const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("Current candidate") && text.includes("Dynamic routing changed") && text.includes("FRR/BGP/OSPF behavior can change forwarding paths");
    }, null, { timeout: 10000 });
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await forceRouteReload(page, "/netvpn");
  }
}

async function seedNetvpnDynamicRoutingCandidate(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before netvpn dynamic routing seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const runningPolicy = (await running.json())?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"] },
        { name: "wan", interfaces: ["eth0"] },
      ],
      addresses: [
        { name: "lan-net", cidr: "10.100.1.0/24" },
        { name: "wan-net", cidr: "198.51.100.0/24" },
      ],
      services: [],
      rules: [],
      staticRoutes: [],
      routing: {},
      vpn: { ipsecTunnels: [], wireguardInterfaces: [] },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed netvpn dynamic routing candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return { runningFingerprint: stable(runningPolicy) };
  });
}

async function waitForNetvpnDynamicRoutingState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await netvpnDynamicRoutingState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`netvpn ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function assertNetvpnEditorRemoveActions(page, viewport, expected) {
  const actions = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return [...(drawer?.querySelectorAll("[data-netvpn-action]") || [])].map((button) => ({
      action: button.getAttribute("data-netvpn-action") || "",
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
  });
  for (const item of expected) {
    const match = actions.find((button) => button.action === item.action);
    if (!match || match.type !== "button" || match.ariaLabel !== item.ariaLabel || match.title !== item.title) {
      throw new Error(`netvpn editor remove action mismatch at ${viewport.name} for ${item.action}: ${JSON.stringify(actions)}`);
    }
  }
}

async function assertNetvpnActionControls(page, viewport, expected, scopeSelector = "#content") {
  let waitError = null;
  try {
    await page.waitForFunction(({ selector, expectedItems }) => {
      const scope = document.querySelector(selector);
      const actions = [...(scope?.querySelectorAll("[data-netvpn-action]") || [])].map((button) => ({
        action: button.getAttribute("data-netvpn-action") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
      }));
      return expectedItems.every((item) => actions.some((button) =>
        button.action === item.action &&
        button.type === "button" &&
        button.ariaLabel === item.ariaLabel &&
        button.title === item.title));
    }, { selector: scopeSelector, expectedItems: expected }, { timeout: 10000 });
  } catch (err) {
    waitError = err;
  }
  const actions = await page.evaluate((selector) => {
    const scope = document.querySelector(selector);
    return [...(scope?.querySelectorAll("[data-netvpn-action]") || [])].map((button) => ({
      action: button.getAttribute("data-netvpn-action") || "",
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
    }));
  }, scopeSelector);
  if (waitError) {
    const routeState = await page.evaluate((selector) => ({
      hash: location.hash,
      activePath: document.querySelector("#nav a.active")?.dataset?.path || "",
      scopeText: (document.querySelector(selector)?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
      contentText: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 500),
    }), scopeSelector);
    throw new Error(`netvpn action controls were not ready at ${viewport.name}: ${waitError.message}; route=${JSON.stringify(routeState)} expected=${JSON.stringify(expected)} all=${JSON.stringify(actions)}`);
  }
  for (const item of expected) {
    const matches = actions.filter((button) => button.action === item.action);
    const actual = matches.find((button) => button.ariaLabel === item.ariaLabel) || matches[0] || null;
    if (!actual || actual.type !== "button" || actual.ariaLabel !== item.ariaLabel || actual.title !== item.title) {
      throw new Error(`netvpn action-control mismatch at ${viewport.name} for ${item.action}: expected=${JSON.stringify(item)} actual=${JSON.stringify(actual)} all=${JSON.stringify(actions)}`);
    }
  }
}

async function assertNetvpnStageBlocked(page, { label, clickSelector, toastTitle, toastBody, before }) {
  await page.click(clickSelector);
  await page.waitForFunction(({ title, body }) => {
    const drawerOpen = Boolean(document.querySelector("#drawer:not([hidden])"));
    const toastText = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
    return drawerOpen && toastText.includes(title) && toastText.includes(body);
  }, { title: toastTitle, body: toastBody }, { timeout: 10000 });
  const after = await netvpnDynamicRoutingState(page);
  if (JSON.stringify(after.candidate) !== JSON.stringify(before.candidate) ||
      after.status.changeCount !== before.status.changeCount ||
      after.status.routingChanged !== before.status.routingChanged) {
    throw new Error(`${label} mutated candidate before a valid stage: before=${JSON.stringify(before)} after=${JSON.stringify(after)}`);
  }
}

async function assertNetvpnVpnEditorInvalidPreflight(page, viewport) {
  const previousPolicy = await seedNetvpnEmptyCandidate(page);
  try {
    await forceRouteReload(page, "/netvpn");

    await page.click('[data-netvpn-action="add-ipsec"]');
    await waitForDrawerTitleStep(page, "Add IPsec tunnel", "netvpn IPsec drawer open");
    await assertNetvpnActionControls(page, viewport, [
      { action: "cancel-ipsec", ariaLabel: "Cancel IPsec tunnel edit", title: "Cancel IPsec tunnel edit" },
      { action: "stage-ipsec", ariaLabel: "Stage new IPsec tunnel to candidate", title: "Stage new IPsec tunnel" },
    ], "#drawer:not([hidden])");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ipsec-field="name"]', "Site-B");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ipsec-field="remote-address"]', "203.0.113.1");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ipsec-field="local-subnets"]', "10.10.0.0/24");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ipsec-field="remote-subnets"]', "10.20.0.0/24");
    await page.fill('#drawer:not([hidden]) [data-netvpn-ipsec-field="psk-file"]', "/etc/phragma/secrets/site-b.conf");
    await assertCandidatePolicyStageBlocked(page, {
      label: `IPsec invalid name ${viewport.name}`,
      clickSelector: '#drawer:not([hidden]) [data-netvpn-action="stage-ipsec"]',
      toastTitle: "IPsec not staged",
      toastBody: "Tunnel name must be lowercase alphanumeric",
      before: await snapshotCandidatePolicy(page),
    });
    await clickDrawerFooterButton(page, "Cancel");
    await waitForDrawerClosed(page);

    await page.click('[data-netvpn-action="add-wireguard"]');
    await waitForDrawerTitleStep(page, "Add WireGuard interface", "netvpn WireGuard drawer open");
    await assertNetvpnActionControls(page, viewport, [
      { action: "add-wireguard-peer", ariaLabel: "Add WireGuard peer row", title: "Add WireGuard peer row" },
      { action: "cancel-wireguard", ariaLabel: "Cancel WireGuard interface edit", title: "Cancel WireGuard interface edit" },
      { action: "stage-wireguard", ariaLabel: "Stage new WireGuard interface to candidate", title: "Stage new WireGuard interface" },
    ], "#drawer:not([hidden])");
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="name"]', "wg0");
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="address"]', "10.99.0.1/33");
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="private-key-file"]', "/etc/phragma/keys/wg0.key");
    await page.click('#drawer:not([hidden]) [data-netvpn-action="add-wireguard-peer"]');
    await assertNetvpnEditorRemoveActions(page, viewport, [
      { action: "remove-wireguard-peer", ariaLabel: "Remove WireGuard peer", title: "Remove peer" },
    ]);
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="peer-name"]', "laptop");
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="peer-public-key"]', "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    await page.fill('#drawer:not([hidden]) [data-netvpn-wireguard-field="peer-allowed-ips"]', "10.99.0.2/32");
    await assertCandidatePolicyStageBlocked(page, {
      label: `WireGuard invalid address ${viewport.name}`,
      clickSelector: '#drawer:not([hidden]) [data-netvpn-action="stage-wireguard"]',
      toastTitle: "WireGuard not staged",
      toastBody: "Interface address must be a valid IPv4/IPv6 CIDR.",
      before: await snapshotCandidatePolicy(page),
    });
    await page.keyboard.press("Escape");
    await waitForDrawerClosed(page);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertNetvpnStaticRouteIpsecLifecycle(page, viewport) {
  const previousPolicy = await seedNetvpnEmptyCandidate(page);
  const route = {
    addDestination: "10.130.10.0/24",
    editDestination: "10.130.20.0/24",
    via: "10.100.1.254",
    iface: "eth1",
    metric: 42,
  };
  const tunnel = {
    name: "site-smoke",
    editedRemote: "203.0.113.41",
    pskFile: "/etc/phragma/secrets/site-smoke.psk",
    localPrefix: "10.100.1.0/24",
    remotePrefix: "10.130.20.0/24",
  };
  try {
    await forceRouteReload(page, "/netvpn");

    await page.click('[data-netvpn-action="add-route"]');
    await waitForDrawerTitleStep(page, "Add static route", "netvpn static route add drawer open");
    await fillNetvpnStaticRouteDrawer(page, {
      destination: route.addDestination,
      via: route.via,
      iface: route.iface,
      metric: route.metric,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-route"]');
    await waitForDrawerClosedStep(page, "netvpn static route add drawer close");
    await waitForNetvpnLifecycleState(page, "static route add", (state) => (
      state.candidateRoute?.destination === route.addDestination &&
      state.candidateRoute?.via === route.via &&
      state.candidateRoute?.interface === route.iface &&
      state.candidateRoute?.metric === route.metric &&
      !state.runningRoute &&
      state.status.dirty === true &&
      state.status.staticRoutesChanged === true
    ));

    await assertNetvpnStaticRouteActionLabels(page, viewport, route.addDestination);
    await page.click(`[aria-label="Edit static route ${route.addDestination}"]`);
    await waitForDrawerTitleStep(page, "Edit static route", "netvpn static route edit drawer open");
    await fillNetvpnStaticRouteDrawer(page, {
      destination: route.editDestination,
      via: route.via,
      iface: route.iface,
      metric: route.metric + 1,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-route"]');
    await waitForDrawerClosedStep(page, "netvpn static route edit drawer close");
    await waitForNetvpnLifecycleState(page, "static route edit", (state) => (
      !state.addedCandidateRoute &&
      state.candidateRoute?.destination === route.editDestination &&
      state.candidateRoute?.metric === route.metric + 1 &&
      !state.runningRoute &&
      state.status.dirty === true &&
      state.status.staticRoutesChanged === true
    ));

    await page.click('[data-netvpn-action="add-ipsec"]');
    await waitForDrawerTitleStep(page, "Add IPsec tunnel", "netvpn valid IPsec add drawer open");
    await fillNetvpnIpsecDrawer(page, {
      name: tunnel.name,
      localAddress: "%any",
      remoteAddress: "203.0.113.40",
      localSubnets: tunnel.localPrefix,
      remoteSubnets: tunnel.remotePrefix,
      pskFile: tunnel.pskFile,
      ikeProposal: "aes256-sha256-modp2048",
      espProposal: "aes256gcm16-prfsha256-ecp256",
      initiate: true,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-ipsec"]');
    await waitForDrawerClosedStep(page, "netvpn IPsec add drawer close");
    await waitForNetvpnLifecycleState(page, "IPsec add", (state) => (
      state.candidateTunnel?.name === tunnel.name &&
      state.candidateTunnel?.remoteAddress === "203.0.113.40" &&
      state.candidateTunnel?.pskFile === tunnel.pskFile &&
      state.candidateTunnel?.initiate === true &&
      !state.runningTunnel &&
      state.status.dirty === true &&
      state.status.vpnChanged === true
    ));

    await page.evaluate((name) => {
      location.hash = `#/netvpn?drawer=tunnel&kind=ipsec&name=${encodeURIComponent(name)}`;
    }, tunnel.name);
    await waitForRouteReady(page, "/netvpn");
    await page.waitForFunction(() => Boolean(document.querySelector('[data-netvpn-tunnel-drawer="true"]')), null, { timeout: 10000 });
    const handoff = await collectNetvpnTunnelDrawerState(page);
    assertNetvpnTunnelHandoffState(handoff, viewport, "netvpn route-backed IPsec tunnel drawer", {
      kindLabel: "IPsec",
      name: tunnel.name,
      localPrefix: tunnel.localPrefix,
      remotePrefix: tunnel.remotePrefix,
      secretBasename: "site-smoke.psk",
    });
    await assertNetvpnIpsecHandoffCopy(page, viewport, tunnel);
    await clickDrawerFooterButton(page, "Close");
    await waitForDrawerClosedStep(page, "netvpn IPsec handoff drawer close");
    await forceRouteReload(page, "/netvpn");

    await page.click(`[aria-label="Edit IPsec tunnel ${tunnel.name}"]`);
    await waitForDrawerTitleStep(page, "Edit IPsec tunnel", "netvpn valid IPsec edit drawer open");
    await fillNetvpnIpsecDrawer(page, {
      name: tunnel.name,
      remoteAddress: tunnel.editedRemote,
      localSubnets: tunnel.localPrefix,
      remoteSubnets: tunnel.remotePrefix,
      pskFile: tunnel.pskFile,
      initiate: false,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-ipsec"]');
    await waitForDrawerClosedStep(page, "netvpn IPsec edit drawer close");
    await waitForNetvpnLifecycleState(page, "IPsec edit", (state) => (
      state.candidateTunnel?.name === tunnel.name &&
      state.candidateTunnel?.remoteAddress === tunnel.editedRemote &&
      state.candidateTunnel?.initiate === false &&
      !state.runningTunnel &&
      state.status.dirty === true &&
      state.status.vpnChanged === true
    ));

    await page.click(`[aria-label="Delete static route ${route.editDestination}"]`);
    await waitForDrawerTitleStep(page, "Delete route?", "netvpn static route delete confirmation");
    await clickDrawerFooterButton(page, "Delete");
    await waitForDrawerClosedStep(page, "netvpn static route delete drawer close");
    await waitForNetvpnLifecycleState(page, "static route delete", (state) => (
      !state.candidateRoute &&
      !state.runningRoute &&
      state.candidateTunnel?.name === tunnel.name &&
      state.status.vpnChanged === true
    ));

    await page.click(`[aria-label="Delete IPsec tunnel ${tunnel.name}"]`);
    await waitForDrawerTitleStep(page, "Delete IPsec tunnel?", "netvpn IPsec delete confirmation");
    await clickDrawerFooterButton(page, "Delete");
    await waitForDrawerClosedStep(page, "netvpn IPsec delete drawer close");
    await waitForNetvpnLifecycleState(page, "IPsec delete", (state) => (
      !state.candidateTunnel &&
      !state.runningTunnel &&
      !state.candidateRoute &&
      !state.runningRoute
    ));

    await page.click('[data-netvpn-action="add-route"]');
    await waitForDrawerTitleStep(page, "Add static route", "netvpn static route candidate-review drawer open");
    await fillNetvpnStaticRouteDrawer(page, {
      destination: route.editDestination,
      via: route.via,
      iface: route.iface,
      metric: route.metric,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-route"]');
    await waitForDrawerClosedStep(page, "netvpn candidate-review static route drawer close");
    await page.click('[data-netvpn-action="add-ipsec"]');
    await waitForDrawerTitleStep(page, "Add IPsec tunnel", "netvpn IPsec candidate-review drawer open");
    await fillNetvpnIpsecDrawer(page, {
      name: tunnel.name,
      localAddress: "%any",
      remoteAddress: tunnel.editedRemote,
      localSubnets: tunnel.localPrefix,
      remoteSubnets: tunnel.remotePrefix,
      pskFile: tunnel.pskFile,
      initiate: true,
    });
    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-ipsec"]');
    await waitForDrawerClosedStep(page, "netvpn candidate-review IPsec drawer close");
    await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
    await waitForRouteReady(page, "/changes");
    const changesText = await page.evaluate(() => (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim());
    for (const expected of ["Current candidate", "Static routes changed", "VPN changed"]) {
      if (!changesText.includes(expected)) {
        throw new Error(`netvpn static route/IPsec candidate review missed ${expected} at ${viewport.name}: ${changesText}`);
      }
    }
    assertNoNetvpnVpnLeak(changesText, `netvpn static route/IPsec Changes review ${viewport.name}`);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/netvpn"; });
    await waitForRouteReady(page, "/netvpn");
  }
}

async function fillNetvpnStaticRouteDrawer(page, values = {}) {
  await page.evaluate((next) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("static route drawer was not open");
    const setField = (labelText, value) => {
      const field = [...drawer.querySelectorAll("label.field")]
        .find((candidate) => (candidate.querySelector("span")?.textContent || "").replace(/\s+/g, " ").trim().startsWith(labelText));
      const control = field?.querySelector("input, textarea, select");
      if (!control) throw new Error(`static route field ${labelText} was not found`);
      control.value = value == null ? "" : String(value);
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    };
    setField("Destination prefix", next.destination);
    setField("Via", next.via);
    setField("Egress interface", next.iface);
    setField("Metric", next.metric);
  }, values);
}

async function fillNetvpnIpsecDrawer(page, values = {}) {
  await page.evaluate((next) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("IPsec drawer was not open");
    const setValue = (field, value) => {
      const control = drawer.querySelector(`[data-netvpn-ipsec-field="${field}"]`);
      if (!control) throw new Error(`IPsec field ${field} was not found`);
      control.value = value == null ? "" : String(value);
      control.dispatchEvent(new Event("input", { bubbles: true }));
      control.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setChecked = (field, checked) => {
      const control = drawer.querySelector(`[data-netvpn-ipsec-field="${field}"]`);
      if (!control) throw new Error(`IPsec field ${field} was not found`);
      const checkbox = control.matches?.('input[type="checkbox"]') ? control : control.querySelector?.('input[type="checkbox"]');
      if (!checkbox) throw new Error(`IPsec checkbox field ${field} was not found`);
      checkbox.checked = Boolean(checked);
      checkbox.dispatchEvent(new Event("input", { bubbles: true }));
      checkbox.dispatchEvent(new Event("change", { bubbles: true }));
    };
    if ("name" in next) setValue("name", next.name);
    if ("localAddress" in next) setValue("local-address", next.localAddress);
    if ("remoteAddress" in next) setValue("remote-address", next.remoteAddress);
    if ("localSubnets" in next) setValue("local-subnets", next.localSubnets);
    if ("remoteSubnets" in next) setValue("remote-subnets", next.remoteSubnets);
    if ("pskFile" in next) setValue("psk-file", next.pskFile);
    if ("ikeProposal" in next) setValue("ike-proposal", next.ikeProposal);
    if ("espProposal" in next) setValue("esp-proposal", next.espProposal);
    if ("initiate" in next) setChecked("initiate", next.initiate);
  }, values);
}

async function waitForNetvpnLifecycleState(page, label, predicate, timeout = 7000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await netvpnLifecycleState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`netvpn ${label} did not reach expected lifecycle state: ${JSON.stringify(state)}`);
}

async function netvpnLifecycleState(page) {
  return await page.evaluate(async () => {
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read netvpn candidate failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read netvpn running failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const changes = Array.isArray(status.changes) ? status.changes : [];
    const changed = (section) => {
      const change = changes.find((item) => item?.section === section) || null;
      return Boolean(change && Number(change.added || 0) + Number(change.modified || 0) + Number(change.removed || 0) > 0);
    };
    const routeMatch = (route) => ["10.130.10.0/24", "10.130.20.0/24"].includes(route?.destination);
    const tunnelMatch = (tunnel) => tunnel?.name === "site-smoke";
    return {
      addedCandidateRoute: candidate.staticRoutes?.find((route) => route?.destination === "10.130.10.0/24") || null,
      candidateRoute: candidate.staticRoutes?.find(routeMatch) || null,
      runningRoute: running.staticRoutes?.find(routeMatch) || null,
      candidateTunnel: candidate.vpn?.ipsecTunnels?.find(tunnelMatch) || null,
      runningTunnel: running.vpn?.ipsecTunnels?.find(tunnelMatch) || null,
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        staticRoutesChanged: changed("staticRoutes"),
        vpnChanged: changed("vpn"),
        changes,
      },
    };
  });
}

async function assertNetvpnIpsecHandoffCopy(page, viewport, tunnel) {
  await page.evaluate(() => {
    globalThis.__netvpnHandoffCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__netvpnHandoffCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await clickDrawerButton(page, "Copy handoff");
  try {
    await page.waitForFunction(() => Boolean(globalThis.__netvpnHandoffCopiedText), null, { timeout: 5000 });
  } catch (err) {
    throw new Error(`netvpn IPsec handoff copy did not populate clipboard text at ${viewport.name}: ${err.message}`);
  }
  const handoff = await page.evaluate(() => globalThis.__netvpnHandoffCopiedText || "");
  for (const required of [
    "VPN tunnel handoff",
    "tunnel type: IPsec",
    tunnel.name,
    tunnel.localPrefix,
    tunnel.remotePrefix,
    "file paths and private key material are redacted",
    "secret material: PSK file configured",
  ]) {
    if (!handoff.includes(required)) {
      throw new Error(`netvpn IPsec handoff copy missing ${required} at ${viewport.name}`);
    }
  }
  assertNoNetvpnVpnLeak(handoff, `netvpn IPsec handoff copy ${viewport.name}`);
}

async function assertCandidatePolicyStageBlocked(page, { label, clickSelector, toastTitle, toastBody, before }) {
  await page.click(clickSelector);
  await page.waitForFunction(({ title, body }) => {
    const drawerOpen = Boolean(document.querySelector("#drawer:not([hidden])"));
    const toastText = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
    return drawerOpen && toastText.includes(title) && toastText.includes(body);
  }, { title: toastTitle, body: toastBody }, { timeout: 5000 });
  const after = await snapshotCandidatePolicy(page);
  if (JSON.stringify(after) !== JSON.stringify(before)) {
    throw new Error(`${label} mutated candidate before a valid stage: before=${JSON.stringify(before)} after=${JSON.stringify(after)}`);
  }
}

async function netvpnDynamicRoutingState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const changes = Array.isArray(status.changes) ? status.changes : [];
    const routingChange = changes.find((change) => change?.section === "routing") || null;
    return {
      candidateStatus: candidateResponse.status,
      runningStatus: runningResponse.status,
      runningFingerprint: stable(running),
      candidate: {
        bgp: candidate.routing?.bgp || null,
        bgpNeighbor: (candidate.routing?.bgp?.neighbors || []).find((neighbor) => neighbor.address === "198.51.100.20") || null,
        ospf: candidate.routing?.ospf || null,
        ospfArea: (candidate.routing?.ospf?.areas || []).find((area) => area.area === "0.0.0.0") || null,
      },
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        routingChanged: Boolean(routingChange && Number(routingChange.added || 0) + Number(routingChange.modified || 0) + Number(routingChange.removed || 0) > 0),
        changes,
      },
    };
  });
}

async function collectNetvpnDynamicRoutingPanelState(page) {
  return await page.evaluate(() => {
    const sections = [...document.querySelectorAll('[data-netvpn-section="bgp"], [data-netvpn-section="ospf"]')];
    const overflow = sections.reduce((max, section) => {
      const rect = section.getBoundingClientRect();
      return Math.max(max,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(section.scrollWidth - section.clientWidth));
    }, 0);
    return {
      text: sections.map((section) => section.textContent || "").join(" ").replace(/\s+/g, " ").trim(),
      overflow: Math.max(0, overflow),
    };
  });
}

async function assertNetvpnWireguardRolloutWorkflow(page, viewport) {
  const previousPolicy = await seedNetvpnEmptyCandidate(page);
  try {
    await forceRouteReload(page, "/netvpn");
    await assertNetvpnActionControls(page, viewport, [
      { action: "open-wireguard-rollout", ariaLabel: "Open WireGuard branch rollout workflow", title: "Open WireGuard branch rollout" },
    ]);
    await page.click('[data-netvpn-action="open-wireguard-rollout"]');
    await waitForDrawerTitle(page, "WireGuard branch rollout");
    await assertNetvpnActionControls(page, viewport, [
      { action: "cancel-wireguard-rollout", ariaLabel: "Cancel WireGuard branch rollout", title: "Cancel WireGuard branch rollout" },
      { action: "stage-wireguard-rollout", ariaLabel: "Stage WireGuard branch rollout to candidate", title: "Stage WireGuard branch rollout" },
    ], "#drawer:not([hidden])");
    await page.fill('#drawer:not([hidden]) input[placeholder="base64 peer public key"]', "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    await page.waitForFunction(() => {
      const preview = document.querySelector("[data-netvpn-rollout-preview='true']");
      const text = (preview?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("ready") && text.includes("wg-branch-01") && text.includes("10.120.10.0/24");
    }, null, { timeout: 5000 });
    const rollout = await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const rect = drawer?.getBoundingClientRect?.();
      return {
        text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
        overflow: drawer ? Math.max(
          0,
          Math.ceil(rect.right - window.innerWidth),
          Math.ceil(0 - rect.left),
          Math.ceil(drawer.scrollWidth - drawer.clientWidth),
        ) : 0,
      };
    });
    if (rollout.overflow > 2) {
      throw new Error(`netvpn rollout drawer overflow at ${viewport.name}: ${rollout.overflow}px`);
    }
    for (const required of [
      "Candidate-only rollout",
      "one WireGuard interface",
      "one peer",
      "one static route",
      "Running policy is unchanged until commit",
      "Candidate review",
      "wg-branch-01",
      "branch-01",
      "10.120.10.0/24",
    ]) {
      if (!rollout.text.includes(required)) {
        throw new Error(`netvpn rollout drawer missing ${required}`);
      }
    }

    await page.click('#drawer:not([hidden]) [data-netvpn-action="stage-wireguard-rollout"]');
    await waitForDrawerTitle(page, "WireGuard tunnel handoff");
    await page.waitForFunction(() => Boolean(document.querySelector('[data-netvpn-tunnel-drawer="true"]')), null, { timeout: 10000 });
    await page.fill('#drawer:not([hidden]) [data-netvpn-enrollment-field="firewall-public-endpoint"]', "vpn.visual-smoke.example:51820");
    await page.fill('#drawer:not([hidden]) [data-netvpn-enrollment-field="firewall-public-key"]', "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");

    const candidateState = await page.evaluate(async () => {
      const [candidateResponse, runningResponse] = await Promise.all([
        fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
        fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      ]);
      if (!candidateResponse.ok) throw new Error(`read candidate after netvpn rollout failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
      if (!runningResponse.ok) throw new Error(`read running after netvpn rollout failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
      const candidate = (await candidateResponse.json())?.policy || {};
      const running = (await runningResponse.json())?.policy || {};
      return {
        candidateInterface: candidate.vpn?.wireguardInterfaces?.find((iface) => iface.name === "wg-branch-01") || null,
        candidateRoute: candidate.staticRoutes?.find((route) => route.destination === "10.120.10.0/24") || null,
        runningInterface: running.vpn?.wireguardInterfaces?.find((iface) => iface.name === "wg-branch-01") || null,
        runningRoute: running.staticRoutes?.find((route) => route.destination === "10.120.10.0/24") || null,
      };
    });
    if (!candidateState.candidateInterface || candidateState.candidateInterface.peers?.[0]?.name !== "branch-01") {
      throw new Error(`netvpn rollout did not stage expected WireGuard interface: ${JSON.stringify(candidateState)}`);
    }
    if (!candidateState.candidateRoute || candidateState.candidateRoute.interface !== "wg-branch-01") {
      throw new Error(`netvpn rollout did not stage expected static route: ${JSON.stringify(candidateState)}`);
    }
    if (candidateState.runningInterface || candidateState.runningRoute) {
      throw new Error(`netvpn rollout leaked into running policy before commit: ${JSON.stringify(candidateState)}`);
    }

    const handoff = await collectNetvpnTunnelDrawerState(page);
    assertNetvpnTunnelHandoffState(handoff, viewport, "netvpn rollout tunnel drawer", {
      name: "wg-branch-01:branch-01",
      localPrefix: "10.99.10.1/24",
      remotePrefix: "10.120.10.0/24",
      enrollmentEndpoint: "vpn.visual-smoke.example:51820",
      enrollmentPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    });
    await assertNetvpnWireguardEnrollmentCopy(page, viewport);
    await assertNetvpnWireguardEnrollmentExport(page, viewport);
    await assertNetvpnWireguardEnrollmentQrExport(page, viewport);
    await assertNetvpnPeerTemplateCopy(page, viewport);
    await assertNetvpnPeerTemplateExport(page, viewport);
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])") && (location.hash === "#/netvpn" || location.hash === ""), null, { timeout: 5000 });
    await assertNetvpnStaticRouteActionLabels(page, viewport, "10.120.10.0/24");

    await page.evaluate(() => {
      location.hash = "#/changes?tab=candidate";
    });
    await waitForRouteReady(page, "/changes");
    const changes = await page.evaluate(() => (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim());
    for (const expected of ["Candidate", "Static routes changed", "VPN changed"]) {
      if (!changes.includes(expected)) {
        throw new Error(`netvpn rollout candidate review missed ${expected}`);
      }
    }
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertNetvpnTunnelWorkbench(page, viewport) {
  const previousPolicy = await seedNetvpnCandidate(page);
  try {
    await forceRouteReload(page, "/netvpn");
    await assertNetvpnTunnelRowActionLabels(page, viewport);
    await assertNetvpnTunnelPathCheckActionLabels(page, viewport);
    await page.evaluate(() => { location.hash = "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop"; });
    await waitForRouteReady(page, "/netvpn");
    await page.waitForFunction(() => Boolean(document.querySelector('[data-netvpn-tunnel-drawer="true"]')), null, { timeout: 10000 });
    await page.waitForTimeout(120);
    const state = await collectNetvpnTunnelDrawerState(page);
    assertNetvpnTunnelHandoffState(state, viewport, "netvpn tunnel drawer", {
      name: "wg0:laptop",
      localPrefix: "10.99.0.1/24",
      remotePrefix: "10.99.0.2/32",
    });
    await assertNetvpnTunnelAutomationContext(page, viewport, [
      "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop",
      "Current Routing & VPN drawer: wireguard tunnel wg0:laptop",
      "/v1/policy?source=POLICY_SOURCE_CANDIDATE",
      "/v1/explain/flow",
      "/v1/sessions?protocol=UDP&port=51820&limit=100",
      "ngfwctl policy show --source candidate --json",
      "ngfwctl explain --source candidate",
      "--src 10.99.0.1",
      "--dst 10.99.0.2",
      "ngfwctl sessions --protocol UDP --port 51820 --limit 100",
      "Selected representative path: 10.99.0.1/24 -> 10.99.0.2/32",
      "secret file paths, private keys, PSKs",
    ], [
      "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop",
      "Current Routing & VPN drawer: wireguard tunnel wg0:laptop",
      "GET /v1/policy?source=POLICY_SOURCE_CANDIDATE",
      "POST /v1/explain/flow",
      "10.99.0.1",
      "10.99.0.2",
      "GET /v1/sessions?protocol=UDP&port=51820&limit=100",
      "ngfwctl policy show --source candidate --json",
      "ngfwctl explain --source candidate",
      "--src 10.99.0.1",
      "--dst 10.99.0.2",
      "ngfwctl sessions --protocol UDP --port 51820 --limit 100",
      "Selected representative path: 10.99.0.1/24 -> 10.99.0.2/32",
      "secret file paths, private keys, PSKs",
    ]);
    await page.evaluate(() => {
      location.hash = "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop";
    });
    await waitForRouteReady(page, "/netvpn");
    await page.waitForFunction(() => Boolean(document.querySelector('[data-netvpn-tunnel-drawer="true"]')), null, { timeout: 10000 });
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => !document.querySelector("#drawer:not([hidden])") && (location.hash === "#/netvpn" || location.hash === ""), null, { timeout: 5000 });
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
  }
}

async function assertNetvpnTunnelRowActionLabels(page, viewport) {
  const actions = await page.evaluate(() => {
    const collect = (selector) => [...document.querySelectorAll(selector)].map((button) => ({
      action: button.getAttribute("data-netvpn-action") || "",
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
    return {
      ipsec: collect('[data-netvpn-action="inspect-ipsec"], [data-netvpn-action="edit-ipsec"], [data-netvpn-action="delete-ipsec"]'),
      wireguard: collect('[data-netvpn-action="edit-wireguard"], [data-netvpn-action="delete-wireguard"], [data-netvpn-action="inspect-wireguard-peer"]'),
    };
  });
  for (const expected of [
    { group: "ipsec", action: "inspect-ipsec", ariaLabel: "Inspect IPsec tunnel site-b", title: "Inspect tunnel handoff" },
    { group: "ipsec", action: "edit-ipsec", ariaLabel: "Edit IPsec tunnel site-b", title: "Edit tunnel" },
    { group: "ipsec", action: "delete-ipsec", ariaLabel: "Delete IPsec tunnel site-b", title: "Delete tunnel" },
    { group: "wireguard", action: "edit-wireguard", ariaLabel: "Edit WireGuard interface wg0", title: "Edit interface" },
    { group: "wireguard", action: "delete-wireguard", ariaLabel: "Delete WireGuard interface wg0", title: "Delete interface" },
    { group: "wireguard", action: "inspect-wireguard-peer", ariaLabel: "Inspect WireGuard tunnel wg0:laptop", title: "Inspect tunnel handoff" },
  ]) {
    const actual = actions[expected.group].find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel || actual.title !== expected.title) {
      throw new Error(`netvpn tunnel row action mismatch at ${viewport.name} for ${expected.action}: ${JSON.stringify(actions)}`);
    }
  }
}

async function assertNetvpnTunnelPathCheckActionLabels(page, viewport) {
  const actions = await page.evaluate(() => {
    const pathAction = [...document.querySelectorAll('[data-netvpn-action="inspect-tunnel"]')]
      .find((button) => (button.getAttribute("title") || "").includes("wg0:laptop")) ||
      document.querySelector('[data-netvpn-action="inspect-tunnel"]');
    const row = pathAction?.closest("tr") || null;
    return [...(row?.querySelectorAll("[data-netvpn-action]") || [])].map((button) => ({
      action: button.getAttribute("data-netvpn-action") || "",
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
  });
  for (const expected of [
    { action: "inspect-tunnel", ariaLabel: "Inspect tunnel handoff for wg0:laptop", title: "Inspect tunnel handoff for wg0:laptop" },
    { action: "explain-tunnel", ariaLabel: "Explain candidate path for wg0:laptop", title: "Explain candidate path for wg0:laptop" },
    { action: "capture-tunnel", ariaLabel: "Start packet capture workflow for wg0:laptop", title: "Start packet capture workflow for wg0:laptop" },
    { action: "sessions-tunnel", ariaLabel: "Open live sessions for wg0:laptop", title: "Open live sessions for wg0:laptop" },
  ]) {
    const actual = actions.find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel || actual.title !== expected.title) {
      throw new Error(`netvpn tunnel path-check action mismatch at ${viewport.name} for ${expected.action}: ${JSON.stringify(actions)}`);
    }
  }
}

async function assertNetvpnTunnelAutomationContext(page, viewport, drawerRequiredText = [], copiedRequiredText = drawerRequiredText) {
  await page.evaluate(() => {
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  await page.click('#drawer:not([hidden]) [data-netvpn-action="api-cli"]');
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, "netvpn tunnel API / CLI context", [
    "API / CLI context",
    "Current view",
    "REST endpoints",
    "CLI equivalents",
    "Copy session JSON",
    "Copy context",
    ...drawerRequiredText,
  ], ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `netvpn tunnel API / CLI drawer ${viewport.name}`);
  assertNoNetvpnVpnLeak(drawer.text, `netvpn tunnel API / CLI drawer ${viewport.name}`);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `netvpn tunnel workflow session JSON ${viewport.name}`);
  assertNoNetvpnVpnLeak(sessionJson, `netvpn tunnel workflow session JSON ${viewport.name}`);
  let sessionPacket = null;
  try {
    sessionPacket = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`netvpn tunnel workflow session JSON was not parseable: ${err.message}`);
  }
  if (!String(sessionPacket.routeState?.hash || "").startsWith("#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop") ||
      !String(sessionPacket.routeState?.hash || "").includes("src=10.99.0.1") ||
      !String(sessionPacket.routeState?.hash || "").includes("dst=10.99.0.2")) {
    throw new Error(`netvpn tunnel workflow session route mismatch: ${JSON.stringify(sessionPacket.routeState)}`);
  }
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  for (const required of copiedRequiredText) {
    if (!copied.includes(required)) {
      throw new Error(`netvpn tunnel copied context missing ${required}`);
    }
  }
  assertAutomationContextRedaction(copied, `netvpn tunnel copied context ${viewport.name}`);
  assertNoNetvpnVpnLeak(copied, `netvpn tunnel copied context ${viewport.name}`);
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

async function assertNetvpnStaticRouteActionLabels(page, viewport, destination) {
  const routeActions = await page.evaluate((routeDestination) => {
    const routeRow = [...document.querySelectorAll("#content tbody tr")]
      .find((row) => (row.textContent || "").includes(routeDestination));
    return [...(routeRow?.querySelectorAll("[data-netvpn-action]") || [])].map((button) => ({
      action: button.getAttribute("data-netvpn-action") || "",
      type: button.getAttribute("type") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
    }));
  }, destination);
  for (const expected of [
    { action: "edit-route", ariaLabel: `Edit static route ${destination}` },
    { action: "delete-route", ariaLabel: `Delete static route ${destination}` },
  ]) {
    const actual = routeActions.find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel) {
      throw new Error(`netvpn rollout static route action mismatch at ${viewport.name} for ${expected.action}: ${JSON.stringify(routeActions)}`);
    }
  }
}

async function collectNetvpnTunnelDrawerState(page) {
  return await page.evaluate(() => {
    const root = document.querySelector('[data-netvpn-tunnel-drawer="true"]');
    const drawer = root?.closest(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const overflowDetails = drawer ? [...drawer.querySelectorAll("*")]
      .filter((el) => !["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName))
      .map((el) => {
        const b = el.getBoundingClientRect();
        const overflow = Math.max(0, Math.ceil(el.scrollWidth - el.clientWidth), Math.ceil(b.right - drawer.clientWidth - rect.left));
        return {
          tag: el.tagName.toLowerCase(),
          cls: String(el.className || ""),
          dataset: Object.keys(el.dataset || {}).join(","),
          text: (el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 80),
          overflow,
          scrollWidth: el.scrollWidth,
          clientWidth: el.clientWidth,
        };
      })
      .filter((item) => item.overflow > 0)
      .sort((a, b) => b.overflow - a.overflow)
      .slice(0, 5) : [];
    const childOverflow = overflowDetails.reduce((max, item) => Math.max(max, item.overflow || 0), 0);
    const links = [...(drawer?.querySelectorAll("a[href]") || [])].map((link) => ({
      text: (link.textContent || "").replace(/\s+/g, " ").trim(),
      href: link.getAttribute("href") || "",
    }));
    const buttons = [...(drawer?.querySelectorAll("button") || [])].map((button) => {
      const b = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.getAttribute("data-netvpn-action") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        width: b.width,
        height: b.height,
        disabled: button.disabled,
      };
    });
    const qr = drawer?.querySelector('[data-netvpn-enrollment-qr="true"] svg');
    const qrRect = qr?.getBoundingClientRect?.();
    return {
      hash: location.hash || "",
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      links,
      buttons,
      qr: qr ? {
        present: true,
        width: qrRect?.width || 0,
        height: qrRect?.height || 0,
        role: qr.getAttribute("role") || "",
        viewBox: qr.getAttribute("viewBox") || "",
        label: (qr.textContent || "").replace(/\s+/g, " ").trim(),
      } : { present: false },
      overflow: drawer ? Math.max(
        0,
        Math.ceil(0 - rect.left),
        childOverflow,
      ) : 0,
      overflowDetails,
    };
  });
}

function assertNetvpnTunnelHandoffState(state, viewport, label, expected = {}) {
  if (state.overflow > 2) {
    throw new Error(`${label} overflow at ${viewport.name}: ${state.overflow}px ${JSON.stringify(state.overflowDetails || [])}`);
  }
  const kindLabel = expected.kindLabel || "WireGuard";
  const requiredText = [
    `${kindLabel} tunnel handoff`,
    expected.name,
    "Candidate tunnel context",
    "Secret material",
    "path redacted",
    "Local prefixes",
    "Remote prefixes",
    expected.localPrefix,
    expected.remotePrefix,
    "Path checks",
    "API / CLI",
    "Copy handoff",
    "Export JSON",
    "Copy template",
    "Export template",
    expected.kindLabel === "IPsec" ? null : "Enrollment bundle",
    expected.kindLabel === "IPsec" ? null : "QR-ready config",
    expected.enrollmentEndpoint,
    expected.enrollmentPublicKey,
  ].filter(Boolean);
  const missing = requiredText.filter((part) => !state.text.includes(part) && state.title !== part);
  if (missing.length) {
    throw new Error(`${label} missing text: ${missing.join(", ")}`);
  }
  for (const leaked of ["/etc/phragma", "wg0.key", "wg-branch-01.key", "site-b.conf", expected.secretBasename, "privateKeyFile", "pskFile"].filter(Boolean)) {
    if (state.text.includes(leaked)) {
      throw new Error(`${label} leaked secret/path text: ${leaked}`);
    }
  }
  assertNoNetvpnVpnLeak(state.text, label);
  if (!state.links.some((link) => link.text === "Explain" && link.href.includes("#/troubleshoot?") && link.href.includes("intent=explain") && link.href.includes("POLICY_SOURCE_CANDIDATE"))) {
    throw new Error(`${label} missing candidate explain link: ${JSON.stringify(state.links)}`);
  }
  if (!state.links.some((link) => link.text === "Capture" && link.href.includes("#/troubleshoot?") && link.href.includes("intent=capture") && link.href.includes("POLICY_SOURCE_CANDIDATE"))) {
    throw new Error(`${label} missing candidate capture link: ${JSON.stringify(state.links)}`);
  }
  if (!state.links.some((link) => link.text === "Sessions" && link.href.includes("#/traffic?") && link.href.includes("mode=sessions"))) {
    throw new Error(`${label} missing sessions link: ${JSON.stringify(state.links)}`);
  }
  if (!state.buttons.some((button) => button.text === "API / CLI")) {
    throw new Error(`${label} missing API / CLI action: ${JSON.stringify(state.buttons)}`);
  }
  if (!state.buttons.some((button) => button.text === "Copy handoff") || !state.buttons.some((button) => button.text === "Export JSON")) {
    throw new Error(`${label} missing handoff actions: ${JSON.stringify(state.buttons)}`);
  }
  if (!state.buttons.some((button) => button.text === "Copy template") || !state.buttons.some((button) => button.text === "Export template")) {
    throw new Error(`${label} missing template actions: ${JSON.stringify(state.buttons)}`);
  }
  if (kindLabel === "WireGuard") {
    if (!state.buttons.some((button) => button.text === "Copy enrollment") || !state.buttons.some((button) => button.text === "Export enrollment")) {
      throw new Error(`${label} missing enrollment actions: ${JSON.stringify(state.buttons)}`);
    }
    if (!state.buttons.some((button) => button.text === "Export QR")) {
      throw new Error(`${label} missing enrollment QR action: ${JSON.stringify(state.buttons)}`);
    }
  }
  const expectedActions = [
    { action: "close-tunnel-handoff", ariaLabel: "Close tunnel handoff", title: "Close tunnel handoff" },
    { action: "api-cli", ariaLabel: "Open VPN tunnel API and CLI context", title: "Open VPN tunnel API and CLI context" },
    { action: "pin-vpn-handoff", ariaLabel: "Pin VPN tunnel handoff to investigation case", title: "Pin VPN tunnel handoff to investigation case" },
    { action: "copy-vpn-handoff", ariaLabel: "Copy VPN tunnel handoff", title: "Copy VPN tunnel handoff" },
    { action: "export-vpn-handoff", ariaLabel: "Export VPN tunnel handoff JSON", title: "Export VPN tunnel handoff JSON" },
    { action: "copy-vpn-peer-template", ariaLabel: "Copy VPN peer template", title: "Copy VPN peer template" },
    { action: "export-vpn-peer-template", ariaLabel: "Export VPN peer template", title: "Export VPN peer template" },
  ];
  if (kindLabel === "WireGuard") {
    expectedActions.push(
      { action: "copy-wireguard-enrollment", ariaLabel: "Copy WireGuard enrollment config", title: "Copy WireGuard enrollment config" },
      { action: "export-wireguard-enrollment", ariaLabel: "Export WireGuard enrollment config", title: "Export WireGuard enrollment config" },
      { action: "export-wireguard-enrollment-qr", ariaLabel: "Export WireGuard enrollment QR code", title: "Export WireGuard enrollment QR code" },
    );
  }
  for (const expected of expectedActions) {
    const actual = state.buttons.find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel || actual.title !== expected.title) {
      throw new Error(`${label} action-control mismatch for ${expected.action}: ${JSON.stringify(state.buttons)}`);
    }
  }
  if (kindLabel === "WireGuard" && (!state.qr?.present || state.qr.width < 120 || state.qr.height < 120 || state.qr.role !== "img" || !state.qr.label.includes("WireGuard enrollment QR code"))) {
    throw new Error(`${label} QR preview missing or undersized: ${JSON.stringify(state.qr)}`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => !button.disabled && button.text && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`${label} mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
}

async function assertNetvpnWireguardEnrollmentCopy(page, viewport) {
  await page.evaluate(() => {
    globalThis.__netvpnEnrollmentCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__netvpnEnrollmentCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await clickDrawerButton(page, "Copy enrollment");
  await page.waitForFunction(() => Boolean(globalThis.__netvpnEnrollmentCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__netvpnEnrollmentCopiedText || "");
  assertNetvpnWireguardEnrollmentText(copied, `netvpn enrollment copy ${viewport.name}`);
}

async function assertNetvpnWireguardEnrollmentExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickDrawerButton(page, "Export enrollment");
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^wireguard-wg-branch-01-branch-01-enrollment\.conf$/.test(filename)) {
    throw new Error(`netvpn enrollment export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`netvpn enrollment export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNetvpnWireguardEnrollmentText(text, `netvpn enrollment export ${viewport.name}`);
}

async function assertNetvpnWireguardEnrollmentQrExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickDrawerButton(page, "Export QR");
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^wireguard-wg-branch-01-branch-01-enrollment-qr\.svg$/.test(filename)) {
    throw new Error(`netvpn enrollment QR export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`netvpn enrollment QR export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  if (!/^<svg /.test(text) || !text.includes("WireGuard enrollment QR code") || !text.includes("QR code containing the WireGuard enrollment configuration")) {
    throw new Error(`netvpn enrollment QR export was not a labeled SVG at ${viewport.name}`);
  }
  assertNoNetvpnVpnLeak(text, `netvpn enrollment QR export ${viewport.name}`);
}

function assertNetvpnWireguardEnrollmentText(text, label) {
  for (const required of [
    "Phragma WireGuard enrollment bundle",
    "QR-ready client configuration",
    "PrivateKey = <client-private-key>",
    "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "Endpoint = vpn.visual-smoke.example:51820",
    "AllowedIPs = 10.99.10.1/24",
    "10.120.10.0/24",
  ]) {
    if (!text.includes(required)) {
      throw new Error(`${label} missing ${required}`);
    }
  }
  for (const placeholder of ["<firewall-public-key>", "<firewall-public-endpoint>"]) {
    if (text.includes(placeholder)) {
      throw new Error(`${label} still contained placeholder ${placeholder}`);
    }
  }
  assertNoNetvpnVpnLeak(text, label);
}

async function assertNetvpnPeerTemplateCopy(page, viewport) {
  await page.evaluate(() => {
    globalThis.__netvpnTemplateCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__netvpnTemplateCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await clickDrawerButton(page, "Copy template");
  await page.waitForFunction(() => Boolean(globalThis.__netvpnTemplateCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__netvpnTemplateCopiedText || "");
  assertNetvpnPeerTemplateText(copied, `netvpn template copy ${viewport.name}`);
}

async function assertNetvpnPeerTemplateExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickDrawerButton(page, "Export template");
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^wireguard-wg-branch-01-branch-01\.txt$/.test(filename)) {
    throw new Error(`netvpn template export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`netvpn template export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNetvpnPeerTemplateText(text, `netvpn template export ${viewport.name}`);
}

function assertNetvpnPeerTemplateText(text, label) {
  for (const required of [
    "Phragma WireGuard peer/client template",
    "PrivateKey = <client-private-key>",
    "PublicKey = <firewall-public-key>",
    "Endpoint = <firewall-public-endpoint>:51820",
    "AllowedIPs = 10.99.10.1/24",
    "10.120.10.0/24",
  ]) {
    if (!text.includes(required)) {
      throw new Error(`${label} missing ${required}`);
    }
  }
  for (const leaked of ["/etc/phragma", "wg-branch-01.key", "privateKeyFile", "private_key_file", "pskFile", "psk_file"]) {
    if (text.includes(leaked)) {
      throw new Error(`${label} leaked secret/path text: ${leaked}`);
    }
  }
  assertNoNetvpnVpnLeak(text, label);
}

function assertNoNetvpnVpnLeak(text, label) {
  const leaked = [
    /\/etc\/(?:phragma|openngfw)\/(?:keys|secrets)\/[^\s"',;}]+/i,
    /\bprivateKeyFile\b|\bprivate_key_file\b/i,
    /\bpskFile\b|\bpsk_file\b/i,
    /\.key\b/i,
    /PresharedKey\s*=\s*(?!<)[A-Za-z0-9+/=]{20,}/i,
    /PrivateKey\s*=\s*(?!<client-private-key>)[A-Za-z0-9+/=]{20,}/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked VPN secret/path text: ${leaked}`);
  }
}

async function seedNetvpnEmptyCandidate(page) {
  return await page.evaluate(async () => {
    const candidate = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (!candidate.ok) {
      throw new Error(`read candidate policy before netvpn rollout seed failed with HTTP ${candidate.status}: ${await candidate.text()}`);
    }
    const previousPolicy = (await candidate.json())?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"] },
        { name: "wan", interfaces: ["eth0"] },
      ],
      addresses: [
        { name: "lan-net", cidr: "10.100.1.0/24" },
        { name: "branch-net", cidr: "10.120.10.0/24" },
      ],
      services: [],
      rules: [],
      staticRoutes: [],
      vpn: { ipsecTunnels: [], wireguardInterfaces: [] },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed netvpn empty candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return previousPolicy;
  });
}

async function seedNetvpnCandidate(page) {
  return await page.evaluate(async () => {
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before netvpn seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const previousPolicy = (await running.json())?.policy || {};
    const policy = {
      zones: [
        { name: "lan", interfaces: ["eth1"] },
        { name: "wan", interfaces: ["eth0"] },
      ],
      addresses: [
        { name: "lan-net", cidr: "10.100.1.0/24" },
        { name: "branch-net", cidr: "10.120.0.0/24" },
      ],
      services: [],
      rules: [],
      staticRoutes: [
        { destination: "10.120.0.0/24", interface: "wg0", metric: 50 },
      ],
      vpn: {
        ipsecTunnels: [{
          name: "site-b",
          localAddress: "%any",
          remoteAddress: "203.0.113.20",
          localSubnets: ["10.100.1.0/24"],
          remoteSubnets: ["10.120.0.0/24"],
          pskFile: "/etc/phragma/secrets/site-b.conf",
          initiate: true,
        }],
        wireguardInterfaces: [{
          name: "wg0",
          address: "10.99.0.1/24",
          listenPort: 51820,
          privateKeyFile: "/etc/phragma/keys/wg0.key",
          peers: [{
            name: "laptop",
            publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            endpoint: "198.51.100.8:51820",
            allowedIps: ["10.99.0.2/32", "10.120.0.0/24"],
            persistentKeepalive: 25,
          }],
        }],
      },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed netvpn candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return previousPolicy;
  });
}

async function assertRulesRowEvidenceActions(page, viewport) {
  const actions = await page.evaluate(() => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    return ["explain", "capture"].map((action) => {
      const button = document.querySelector(`[data-rule-action="${action}"][data-rule-name="allow-web"]`);
      const rect = button?.getBoundingClientRect?.();
      return {
        action,
        visible: visible(button),
        title: button?.getAttribute("title") || "",
        ariaLabel: button?.getAttribute("aria-label") || "",
        type: button?.getAttribute("type") || "",
        width: rect?.width || 0,
        height: rect?.height || 0,
      };
    });
  });
  const missing = actions.filter((item) =>
    !item.visible ||
    !new RegExp(item.action, "i").test(item.title) ||
    item.ariaLabel !== item.title ||
    item.type !== "button");
  if (missing.length) {
    throw new Error(`rules row evidence action(s) missing: ${JSON.stringify(actions)}`);
  }
  if (viewport.name === "mobile") {
    const cramped = actions.filter((item) => item.width < 28 || item.height < 28);
    if (cramped.length) {
      throw new Error(`mobile rules row evidence buttons too small: ${cramped.map((item) => `${item.action} ${Math.round(item.width)}x${Math.round(item.height)}`).join(", ")}`);
    }
  }

  await focusRuleRowAction(page, "allow-web", "explain");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => {
    const hash = location.hash || "";
    if (!hash.startsWith("#/rules?")) return false;
    const params = new URLSearchParams(hash.slice(hash.indexOf("?") + 1));
    const targetRule = params.get("rule") === "allow-web" ||
      (params.get("rule") === null && /^rule-allow-web-[a-z0-9]+/.test(params.get("ruleId") || ""));
    return targetRule &&
      params.get("simRun") === "1" &&
      params.get("simSource") === "POLICY_SOURCE_CANDIDATE" &&
      params.get("simFrom") === "lan" &&
      params.get("simTo") === "dmz" &&
      params.get("simSrc") === "10.100.1.1" &&
      params.get("simSport") === "51515" &&
      params.get("simDst") === "10.100.2.20" &&
      params.get("simDport") === "443";
  }, null, { timeout: 5000 });
  await page.waitForTimeout(160);
  const explainState = await page.evaluate(() => {
    const selects = [...document.querySelectorAll(".sim-form select")].map((el) => el.value);
    const inputs = [...document.querySelectorAll(".sim-form input")].map((el) => el.value);
    const actions = document.querySelector(".sim-result .sim-actions.start");
    const rect = actions?.getBoundingClientRect?.();
    const actionButtons = [...(actions?.querySelectorAll("button[data-rule-simulation-action]") || [])].map((button) => ({
      action: button.getAttribute("data-rule-simulation-action") || "",
      type: button.getAttribute("type") || "",
      title: button.getAttribute("title") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    return {
      selects,
      inputs,
      hash: location.hash || "",
      drawerOpen: Boolean(document.querySelector("#drawer:not([hidden])")),
      simActionsClass: actions?.className || "",
      simActionsButtonCount: actions?.querySelectorAll("button").length || 0,
      actionButtons,
      simActionsOverflow: actions && rect ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(actions.scrollWidth - actions.clientWidth)) : 0,
    };
  });
	const expectedSelects = ["POLICY_SOURCE_CANDIDATE", "lan", "dmz", "PROTOCOL_TCP", ""];
	const expectedInputs = ["10.100.1.1", "51515", "10.100.2.20", "443"];
	const tupleInputs = explainState.inputs.slice(-expectedInputs.length);
	if (expectedSelects.some((value, index) => explainState.selects[index] !== value) ||
	    expectedInputs.some((value, index) => tupleInputs[index] !== value)) {
		throw new Error(`rules explain row action did not prefill flow check: ${JSON.stringify(explainState)}`);
	}
  if (explainState.drawerOpen) {
    throw new Error("rules explain row action opened the rule editor over the flow check");
  }
  if (!explainState.simActionsClass.includes("sim-actions") || !explainState.simActionsClass.includes("start") || explainState.simActionsButtonCount < 3 || explainState.simActionsOverflow > 2) {
    throw new Error(`rules explain row action rendered invalid simulator actions at ${viewport.name}: ${JSON.stringify(explainState)}`);
  }
  const requiredSimActions = ["stage-allow", "stage-drop", "capture", "copy-link", "pin-handoff", "export-handoff"];
  const missingSimActions = requiredSimActions.filter((action) => !explainState.actionButtons.some((button) => button.action === action));
  const invalidSimActions = explainState.actionButtons.filter((button) => button.type !== "button" || !button.title || button.ariaLabel !== button.title);
  if (missingSimActions.length || invalidSimActions.length) {
    throw new Error(`rules flow-check result actions missed explicit semantics at ${viewport.name}: ${JSON.stringify({ missingSimActions, invalidSimActions, actionButtons: explainState.actionButtons })}`);
  }

  await focusRuleRowAction(page, "allow-web", "capture");
  await page.keyboard.press("Enter");
  const captureHash = await page.evaluate(() => location.hash || "");
  const captureParams = new URLSearchParams(captureHash.includes("?") ? captureHash.slice(captureHash.indexOf("?") + 1) : "");
  const expectedCapture = {
    source: "POLICY_SOURCE_CANDIDATE",
    fromZone: "lan",
    toZone: "dmz",
    src: "10.100.1.1",
    sport: "51515",
    dst: "10.100.2.20",
    dport: "443",
    run: "1",
    intent: "capture",
  };
  const wrong = Object.entries(expectedCapture).filter(([key, value]) => captureParams.get(key) !== value);
  if (wrong.length) {
    throw new Error(`rules capture row action produced wrong handoff hash (${wrong.map(([key]) => key).join(", ")}): ${captureHash}`);
  }
  await waitForRouteReady(page, "/troubleshoot");
  await page.evaluate(() => { location.hash = "#/rules"; });
  await waitForRouteReady(page, "/rules");
}

async function focusRuleRowAction(page, ruleName, action) {
  await page.evaluate(({ ruleName, action }) => {
    const button = document.querySelector(`[data-rule-action="${action}"][data-rule-name="${ruleName}"]`);
    if (!button) throw new Error(`rules row action ${action} was not found for ${ruleName}`);
    button.focus();
    if (document.activeElement !== button) {
      throw new Error(`rules row action ${action} did not receive keyboard focus`);
    }
  }, { ruleName, action });
}

async function assertRulesBulkInteraction(page, viewport) {
  await page.selectOption("[data-rule-control='density']", "compact");
  await page.selectOption("[data-rule-control='group']", "tag");
  await page.waitForTimeout(250);

  let grouped = await rulesInteractionState(page);
  if (!grouped.hash.includes("density=compact") || !grouped.hash.includes("group=tag")) {
    throw new Error(`rules density/group controls did not persist URL state: ${JSON.stringify(grouped)}`);
  }
  if (!grouped.compactTable) {
    throw new Error(`rules density control did not apply compact table class: ${JSON.stringify(grouped)}`);
  }
  if (grouped.ruleCount < 3) {
    throw new Error(`rules smoke seed did not render enough rules: ${JSON.stringify(grouped)}`);
  }
  const expectedGroupTags = ["env:prod", "cleanup", "owner:dns"];
  const missingGroupTags = expectedGroupTags.filter((tag) => !grouped.groupLabels.some((label) => label.includes(tag)));
  if (grouped.groupCount < expectedGroupTags.length || missingGroupTags.length) {
    throw new Error(`rules grouped view did not expose expected tag groups (${missingGroupTags.join(", ") || "count"}): ${JSON.stringify(grouped)}`);
  }
  if (grouped.visibleSelectCount < 1 || grouped.groupSelectCount < expectedGroupTags.length || grouped.rowSelectCount < grouped.ruleCount) {
    throw new Error(`rules grouped view missing stable selection hooks: ${JSON.stringify({ visibleSelectCount: grouped.visibleSelectCount, groupSelectCount: grouped.groupSelectCount, rowSelectCount: grouped.rowSelectCount, ruleCount: grouped.ruleCount, groupKeys: grouped.groupKeys })}`);
  }
  if (grouped.draggableRows !== 0 || grouped.disabledDragHandles < grouped.ruleCount) {
    throw new Error(`grouped rules did not pause drag reorder (draggable=${grouped.draggableRows}, disabledHandles=${grouped.disabledDragHandles}, rules=${grouped.ruleCount})`);
  }

  await page.evaluate(() => { location.hash = "#/rules?density=compact&group=tag&drawer=bulk-disable"; });
  await waitForRouteReady(page, "/rules");
  await waitForDrawerTitle(page, "Disable selected rules");
  const routeReview = await collectDrawerState(page);
  assertDrawerContains(routeReview, viewport, "rules route-backed bulk disable review", [
    "Disable selected rules",
    "Selected",
    "Visible",
    "Will change",
    "No-op / blocked",
    "#1 allow-web",
    "#2 drop-ssh",
    "#3 allow-dns",
  ], ["Copy review context", "Cancel", "Stage disable"]);
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
  await page.waitForFunction(() => !(location.hash || "").includes("drawer="), null, { timeout: 5000 });
  grouped = await rulesInteractionState(page);
  if (!grouped.hash.includes("density=compact") || !grouped.hash.includes("group=tag") || grouped.groupCount < expectedGroupTags.length) {
    throw new Error(`route-backed rules bulk drawer close did not preserve grouped route context: ${JSON.stringify(grouped)}`);
  }

  await clickRulesToolbarButton(page, "Select visible");
  await page.waitForTimeout(250);
  const selected = await rulesInteractionState(page);
  if (!/selected/i.test(selected.toolbarText)) {
    throw new Error(`rules bulk toolbar did not report selected rows: ${JSON.stringify(selected)}`);
  }
  if (selected.selectedRows < 3) {
    throw new Error(`rules select-visible did not select visible rows: ${selected.selectedRows}`);
  }
  const disabledActions = selected.bulkButtons
    .filter((button) => ["Enable", "Disable", "Log on", "Log off", "Add tag", "Remove tag"].includes(button.text))
    .filter((button) => button.disabled);
  if (disabledActions.length) {
    throw new Error(`rules selected bulk action(s) stayed disabled: ${disabledActions.map((button) => button.text).join(", ")}`);
  }
  if (!/Drag reorder is paused while filtered, grouped, or selecting\./.test(selected.toolbarText)) {
    throw new Error("rules bulk toolbar did not explain reorder pause while selecting/grouped");
  }

  await clickRulesToolbarButton(page, "Clear");
  await page.selectOption("[data-rule-control='group']", "none");
  await page.waitForTimeout(250);
  const orderView = await rulesInteractionState(page);
  if (!orderView.hash.includes("density=compact") || orderView.hash.includes("group=tag")) {
    throw new Error(`rules ordered view did not preserve compact density and clear grouping: ${JSON.stringify(orderView)}`);
  }
  if (orderView.selectedRows !== 0 || orderView.groupCount !== 0) {
    throw new Error(`rules ordered view did not clear selection/group rows: ${JSON.stringify(orderView)}`);
  }
  if (orderView.draggableRows !== orderView.ruleCount || orderView.disabledDragHandles !== 0) {
    throw new Error(`ungrouped unselected rules did not restore drag reorder (draggable=${orderView.draggableRows}, disabledHandles=${orderView.disabledDragHandles}, rules=${orderView.ruleCount})`);
  }
  await assertRulesExplicitReorderActions(page);
  if (viewport.name === "mobile" && orderView.horizontalOverflow > 2) {
    throw new Error(`rules interaction introduced mobile horizontal overflow: ${orderView.horizontalOverflow}px`);
  }
  if (viewport.name === "mobile" || viewport.name === "desktop") {
    if (orderView.actionButtonCount < orderView.ruleCount * 8) {
      throw new Error(`rules ${viewport.name} action column missed row actions: ${JSON.stringify(orderView)}`);
    }
    const cramped = orderView.actionButtons.filter((button) => button.width < 34 || button.height < 34);
    if (cramped.length) {
      throw new Error(`rules ${viewport.name} action buttons too small: ${cramped.map((button) => `${button.action || "unknown"} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
    const overflowing = orderView.actionButtons.filter((button) => button.overflow > 2);
    if (overflowing.length) {
      throw new Error(`rules ${viewport.name} action buttons overflowed their action cell: ${overflowing.map((button) => button.action || "unknown").join(", ")}`);
    }
  }
}

async function assertRulesExplicitReorderActions(page) {
  const before = await rulesOrder(page);
  if (before.slice(0, 3).join(",") !== "allow-web,drop-ssh,allow-dns") {
    throw new Error(`rules explicit reorder seed order unexpected before move: ${before.join(",")}`);
  }
  const controls = await page.evaluate(() => {
    const firstUp = document.querySelector('[data-rule-action="move-up"][data-rule-name="allow-web"]');
    const firstDown = document.querySelector('[data-rule-action="move-down"][data-rule-name="allow-web"]');
    const lastDown = document.querySelector('[data-rule-action="move-down"][data-rule-name="allow-dns"]');
    return {
      firstUpDisabled: Boolean(firstUp?.disabled),
      firstDownEnabled: Boolean(firstDown && !firstDown.disabled),
      lastDownDisabled: Boolean(lastDown?.disabled),
    };
  });
  if (!controls.firstUpDisabled || !controls.firstDownEnabled || !controls.lastDownDisabled) {
    throw new Error(`rules explicit reorder controls have wrong edge state: ${JSON.stringify(controls)}`);
  }
  await page.evaluate(() => document.querySelector('[data-rule-action="move-down"][data-rule-name="allow-web"]')?.click());
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll(".rules-table tbody tr")]
      .filter((row) => !row.classList.contains("rule-group-row"))
      .map((row) => row.dataset.ruleName || "");
    return rows[0] === "drop-ssh" && rows[1] === "allow-web";
  }, null, { timeout: 5000 });
  let moved = await rulesOrder(page);
  if (moved.slice(0, 3).join(",") !== "drop-ssh,allow-web,allow-dns") {
    throw new Error(`rules explicit move-down did not stage candidate order: ${moved.join(",")}`);
  }
  await page.evaluate(() => document.querySelector('[data-rule-action="move-up"][data-rule-name="allow-web"]')?.click());
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll(".rules-table tbody tr")]
      .filter((row) => !row.classList.contains("rule-group-row"))
      .map((row) => row.dataset.ruleName || "");
    return rows[0] === "allow-web" && rows[1] === "drop-ssh";
  }, null, { timeout: 5000 });
  moved = await rulesOrder(page);
  if (moved.slice(0, 3).join(",") !== "allow-web,drop-ssh,allow-dns") {
    throw new Error(`rules explicit move-up did not restore candidate order: ${moved.join(",")}`);
  }
}

async function rulesOrder(page) {
  return await page.evaluate(async () => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (!response.ok) {
      throw new Error(`read candidate policy for rules order failed with HTTP ${response.status}: ${await response.text()}`);
    }
    const body = await response.json();
    return (body?.policy?.rules || []).map((rule) => rule.name || "");
  });
}

async function assertRulesManualLifecycleWorkflow(page, viewport) {
  await page.evaluate(() => { location.hash = "#/rules"; });
  await waitForRouteReady(page, "/rules");
  await page.selectOption(".rules-density-control", "comfortable");
  await page.selectOption(".rules-group-control", "none");
  await page.waitForTimeout(200);
  const before = await rulesLifecyclePolicyState(page);
  const marker = String(viewport.name || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const names = {
    added: `visual-add-${marker}`,
    edited: `visual-edit-${marker}`,
    inserted: `visual-insert-${marker}`,
    deleted: "drop-ssh",
    source: "allow-web",
  };
  const profileName = await ensureSecurityProfileObject(page, marker);
  await ensureRulesProfileFailClosedInspection(page);
  await page.evaluate(() => { location.hash = "#/rules"; });
  await waitForRouteReady(page, "/rules");

  await page.evaluate(() => {
    const button = [...document.querySelectorAll("#content button")]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Add rule");
    if (!button) throw new Error("rules Add rule action was not found");
    button.click();
  });
  await waitForDrawerTitleStep(page, "New rule", "rules manual add drawer");
  await assertRulesEditorLayout(page, viewport, "rules manual add drawer");
  await fillRulesEditor(page, {
    name: names.added,
    tags: "owner:visual, lifecycle:add",
    fromZones: ["lan"],
    toZones: ["wan"],
    sourceAddresses: ["inside-net"],
    destinationAddresses: ["internet"],
    services: ["https"],
    applications: ["any"],
    securityProfiles: [profileName],
    action: "ACTION_ALLOW",
    log: true,
    disabled: false,
    description: `Manual lifecycle add ${marker}`,
  });
  await saveRulesEditor(page);
  await waitForDrawerClosed(page);
  await waitForRulesLifecycleState(page, "add", (state) => {
    const rule = state.candidate.rules.find((item) => item.name === names.added);
    return Boolean(rule) &&
      rule.action === "ACTION_ALLOW" &&
      rule.log === true &&
      sameArray(rule.securityProfiles || [], [profileName]) &&
      rule.description === `Manual lifecycle add ${marker}` &&
      state.status.dirty === true &&
      state.status.rulesChanged === true &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes(names.added);
  });

  await clickRuleRowAction(page, names.source, "edit");
  await waitForDrawerTitleStep(page, "Edit rule", "rules manual edit drawer");
  await assertRulesEditorLayout(page, viewport, "rules manual edit drawer");
  await fillRulesEditor(page, {
    name: names.edited,
    tags: "owner:web, env:prod, lifecycle:edit",
    securityProfiles: [profileName],
    action: "ACTION_DENY",
    log: true,
    disabled: false,
    description: `Manual lifecycle edit ${marker}`,
  });
  await saveRulesEditor(page);
  await waitForDrawerClosed(page);
  await waitForRulesLifecycleState(page, "edit", (state) => {
    const rule = state.candidate.rules.find((item) => item.name === names.edited);
    return Boolean(rule) &&
      !state.candidate.rules.some((item) => item.name === names.source) &&
      rule.action === "ACTION_DENY" &&
      rule.log === true &&
      sameArray(rule.securityProfiles || [], [profileName]) &&
      (rule.tags || []).includes("lifecycle:edit") &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes(names.edited);
  });

  await clickRuleRowAction(page, names.edited, "duplicate");
  await waitForRulesLifecycleState(page, "duplicate", (state) => {
    const index = state.candidate.order.indexOf(names.edited);
    return index >= 0 &&
      state.candidate.order[index + 1] === `${names.edited}-copy` &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes(`${names.edited}-copy`);
  });

  await clickRuleRowAction(page, names.edited, "insert-below");
  await waitForDrawerTitleStep(page, "New rule", "rules manual insert drawer");
  await fillRulesEditor(page, {
    name: names.inserted,
    tags: "owner:visual, lifecycle:insert",
    fromZones: ["wan"],
    toZones: ["lan"],
    sourceAddresses: ["internet"],
    destinationAddresses: ["inside-net"],
    services: ["ssh"],
    applications: ["any"],
    action: "ACTION_DENY",
    log: true,
    disabled: false,
    description: `Manual lifecycle insert ${marker}`,
  });
  await saveRulesEditor(page);
  await waitForDrawerClosed(page);
  await waitForRulesLifecycleState(page, "insert", (state) => {
    const index = state.candidate.order.indexOf(names.edited);
    return index >= 0 &&
      state.candidate.order[index + 1] === names.inserted &&
      state.candidate.rules.some((rule) => rule.name === names.inserted && rule.action === "ACTION_DENY") &&
      state.runningFingerprint === before.runningFingerprint &&
      !state.runningText.includes(names.inserted);
  });

  await clickRuleRowAction(page, names.deleted, "delete");
  await waitForDrawerTitleStep(page, "Delete rule?", "rules manual delete confirmation");
  await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const button = [...(drawer?.querySelectorAll("button") || [])]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Delete");
    if (!button) throw new Error("rules delete confirmation action was not found");
    button.click();
  });
  await waitForRulesLifecycleState(page, "delete", (state) => (
    !state.candidate.rules.some((rule) => rule.name === names.deleted) &&
    state.runningFingerprint === before.runningFingerprint
  ));
  await page.keyboard.press("Escape");

  await reorderRuleByDom(page, "allow-dns", names.edited);
  await waitForRulesLifecycleState(page, "reorder", (state) => (
    state.candidate.order.indexOf("allow-dns") < state.candidate.order.indexOf(names.edited) &&
    state.runningFingerprint === before.runningFingerprint &&
    state.status.rulesChanged === true
  ));

  const finalState = await rulesLifecyclePolicyState(page);
  const profileStatus = finalState.status.changes.find((change) => change?.section === "securityProfiles");
  if (!finalState.candidate.securityProfiles.some((profile) => profile.name === profileName)) {
    throw new Error(`security profile ${profileName} was not staged in candidate`);
  }
  if (finalState.runningText.includes(profileName)) {
    throw new Error(`security profile ${profileName} leaked into running policy before commit`);
  }
  if (!profileStatus || Number(profileStatus.added || 0) < 1) {
    throw new Error(`candidate status did not report security profile change: ${JSON.stringify(finalState.status.changes)}`);
  }
  await assertSecurityProfileCandidateReview(page, viewport, profileName);
  if (finalState.overflow > 2) {
    throw new Error(`rules manual lifecycle introduced horizontal overflow at ${viewport.name}: ${finalState.overflow}px`);
  }
}

async function assertRulesEditorLayout(page, viewport, label) {
  const state = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const root = drawer?.querySelector("[data-rule-editor='true']");
    const rect = drawer?.getBoundingClientRect?.();
    const tokenEditors = [...(root?.querySelectorAll("[data-rule-field]") || [])]
      .filter((node) => node.classList.contains("rules-token-editor"))
      .map((node) => ({
        field: node.dataset.ruleField || "",
        className: node.className || "",
        selectClassName: node.querySelector("select")?.className || "",
        removeButtons: [...node.querySelectorAll("[data-rule-token-action='remove']")].map((button) => ({
          field: button.getAttribute("data-rule-token-field") || "",
          value: button.getAttribute("data-rule-token-value") || "",
          title: button.getAttribute("title") || "",
          ariaLabel: button.getAttribute("aria-label") || "",
          type: button.getAttribute("type") || "",
        })),
        overflow: Math.max(0, Math.ceil(node.scrollWidth - node.clientWidth)),
      }));
    return {
      rootPresent: Boolean(root),
      tokenEditors,
      drawerOverflow: drawer && rect ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 999,
    };
  });
  if (!state.rootPresent) {
    throw new Error(`${label} did not expose the rules editor root at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const expected = ["from-zones", "to-zones", "source-addresses", "destination-addresses", "services", "applications", "security-profiles"];
  const missing = expected.filter((field) => !state.tokenEditors.some((item) =>
    item.field === field &&
    item.className.includes("rules-token-editor") &&
    item.selectClassName.includes("rules-token-select")));
  if (missing.length) {
    throw new Error(`${label} missed token editor layout hook(s) at ${viewport.name}: ${missing.join(", ")} ${JSON.stringify(state.tokenEditors)}`);
  }
  const overflowing = state.tokenEditors.filter((item) => item.overflow > 2);
  if (state.drawerOverflow > 2 || overflowing.length) {
    throw new Error(`${label} token editor layout overflowed at ${viewport.name}: ${JSON.stringify({ drawerOverflow: state.drawerOverflow, overflowing })}`);
  }
  const populated = state.tokenEditors.flatMap((item) => item.removeButtons.map((button) => ({ ...button, editorField: item.field })));
  if (populated.length && populated.some((button) => {
    const expectedField = String(button.editorField || "").replace(/[-_]+/g, " ");
    return button.type !== "button" ||
      button.field !== button.editorField ||
      !button.value ||
      button.title !== `Remove ${button.value}` ||
      button.ariaLabel !== `Remove ${button.value} from ${expectedField}`;
  })) {
    throw new Error(`${label} token remove buttons were not accessible at ${viewport.name}: ${JSON.stringify(populated)}`);
  }
}

async function assertRulesBaselineDrawerLayout(page, viewport) {
  await page.evaluate(() => {
    const button = [...document.querySelectorAll("#content button")]
      .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Set up baseline");
    if (!button) throw new Error("rules Set up baseline action was not found");
    button.click();
  });
  await waitForDrawerTitleStep(page, "Set up baseline policy", "rules baseline drawer");
  const state = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const rect = drawer?.getBoundingClientRect?.();
    const rows = [...(drawer?.querySelectorAll(".baseline-toggle") || [])].map((row) => {
      const copy = row.querySelector(".baseline-toggle-copy");
      const sw = row.querySelector(".switch");
      const swRect = sw?.getBoundingClientRect?.();
      return {
        className: row.className || "",
        copyText: (copy?.textContent || "").replace(/\s+/g, " ").trim(),
        hasCopy: Boolean(copy),
        switchVisible: Boolean(sw && swRect && swRect.width > 0 && swRect.height > 0),
        switchWidth: swRect?.width || 0,
        switchHeight: swRect?.height || 0,
        overflow: Math.max(0, Math.ceil(row.scrollWidth - row.clientWidth)),
      };
    });
    return {
      rows,
      drawerOverflow: drawer && rect ? Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left), Math.ceil(drawer.scrollWidth - drawer.clientWidth)) : 999,
    };
  });
  if (state.rows.length < 6) {
    throw new Error(`rules baseline drawer missed toggle rows at ${viewport.name}: ${JSON.stringify(state.rows)}`);
  }
  const broken = state.rows.filter((row) => !row.hasCopy || !row.switchVisible || row.overflow > 2);
  if (state.drawerOverflow > 2 || broken.length) {
    throw new Error(`rules baseline drawer layout overflowed at ${viewport.name}: ${JSON.stringify({ drawerOverflow: state.drawerOverflow, broken })}`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.rows.filter((row) => row.switchWidth < 38 || row.switchHeight < 22);
    if (cramped.length) {
      throw new Error(`rules baseline drawer mobile switches too small: ${JSON.stringify(cramped)}`);
    }
  }
  await clickDrawerFooterButton(page, "Cancel");
  await waitForDrawerClosed(page);
}

async function assertSecurityProfileCandidateReview(page, viewport, profileName) {
  await page.evaluate(() => {
    location.hash = "#/changes?tab=candidate";
  });
  await waitForRouteReady(page, "/changes");
  await page.waitForFunction((name) => {
    const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Commit impact") &&
      text.includes("Added security profile") &&
      text.includes(name) &&
      text.includes("TLS/DNS/URL/file inspection intent");
  }, profileName, { timeout: 10000 });
  const state = await page.evaluate(() => ({
    text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
  }));
  if (state.overflow > 2) {
    throw new Error(`security profile candidate review overflow at ${viewport.name}: ${state.overflow}px`);
  }
}

async function ensureSecurityProfileObject(page, marker) {
  const profileName = `visual-profile-${marker}`;
  await page.evaluate(() => {
    location.hash = "#/objects?tab=securityProfiles";
  });
  await waitForRouteReady(page, "/objects");
  await page.evaluate(() => {
    const button = document.querySelector('[data-object-action="new"][data-object-kind="securityProfiles"]');
    if (!button) throw new Error("security profile New action was not found");
    button.click();
  });
  await waitForDrawerTitleStep(page, "New security profile", "security profile object drawer");
  await page.evaluate((name) => {
    const drawer = document.querySelector("#drawer:not([hidden]) [data-security-profile-editor='true']");
    if (!drawer) throw new Error("security profile editor was not open");
    const setValue = (field, value) => {
      const el = drawer.querySelector(`[data-security-profile-field="${field}"]`);
      if (!el) throw new Error(`security profile field ${field} was not found`);
      el.value = String(value);
      el.dispatchEvent(new Event(el.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      if (el.value !== String(value)) throw new Error(`security profile field ${field} did not accept ${value}`);
    };
    setValue("name", name);
    setValue("tls-inspection", "TLS_INSPECTION_MODE_METADATA_ONLY");
    setValue("url-categories", "malware, phishing");
    setValue("dns-security", "DNS_SECURITY_MODE_BLOCK_MALICIOUS");
    setValue("file-security", "FILE_SECURITY_MODE_LOG_ONLY");
    setValue("description", "Visual smoke layered inspection intent.");
  }, profileName);
  await page.evaluate(() => {
    const button = document.querySelector('#drawer:not([hidden]) [data-object-action="save-editor"][data-object-kind="securityProfiles"]');
    if (!button) throw new Error("security profile save action was not found");
    button.click();
  });
  await waitForDrawerClosed(page);
  await page.waitForFunction(async (name) => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (!response.ok) return false;
    const policy = (await response.json())?.policy || {};
    return (policy.securityProfiles || []).some((profile) =>
      profile.name === name &&
      profile.tlsInspection === "TLS_INSPECTION_MODE_METADATA_ONLY" &&
      (profile.urlCategories || []).includes("malware") &&
      profile.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS");
  }, profileName, { timeout: 5000 });
  return profileName;
}

async function ensureRulesProfileFailClosedInspection(page) {
  await page.evaluate(async () => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
    if (!response.ok) throw new Error(`read candidate before profile inspection setup failed with HTTP ${response.status}: ${await response.text()}`);
    const policy = (await response.json())?.policy || {};
    policy.ids = {
      ...(policy.ids || {}),
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    };
    const update = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!update.ok) throw new Error(`stage profile-required IPS fail-closed candidate failed with HTTP ${update.status}: ${await update.text()}`);
  });
}

async function fillRulesEditor(page, values = {}) {
  await page.evaluate((input) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("rules editor drawer was not open");
    const setNativeValue = (element, value) => {
      const proto = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : element instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
      descriptor?.set?.call(element, value);
      element.dispatchEvent(new Event(element.tagName === "SELECT" ? "change" : "input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setText = (field, value) => {
      if (value == null) return;
      const el = drawer.querySelector(`[data-rule-field="${field}"]`);
      if (!el) throw new Error(`rules editor field ${field} was not found`);
      setNativeValue(el, String(value));
    };
    const setCheck = (field, value) => {
      if (value == null) return;
      const el = drawer.querySelector(`[data-rule-field="${field}"]`);
      if (!el) throw new Error(`rules editor checkbox ${field} was not found`);
      el.checked = Boolean(value);
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setTokens = (field, values = []) => {
      if (!Array.isArray(values)) return;
      const wrap = drawer.querySelector(`[data-rule-field="${field}"]`);
      if (!wrap) throw new Error(`rules editor token field ${field} was not found`);
      for (const button of [...wrap.querySelectorAll("button[title='Remove']")]) button.click();
      for (const value of values) {
        const select = wrap.querySelector("select");
        if (!select) throw new Error(`rules editor token select ${field} was not found`);
        select.value = value;
        select.dispatchEvent(new Event("change", { bubbles: true }));
        if (!wrap.textContent.includes(value)) throw new Error(`rules editor token ${field} did not accept ${value}`);
      }
    };
    setText("name", input.name);
    setText("tags", input.tags);
    setTokens("from-zones", input.fromZones);
    setTokens("to-zones", input.toZones);
    setTokens("source-addresses", input.sourceAddresses);
    setTokens("destination-addresses", input.destinationAddresses);
    setTokens("services", input.services);
    setTokens("applications", input.applications);
    setTokens("security-profiles", input.securityProfiles);
    setText("action", input.action);
    setCheck("log", input.log);
    setCheck("disabled", input.disabled);
    setText("description", input.description);
  }, values);
}

async function saveRulesEditor(page) {
  await page.evaluate(() => {
    const button = document.querySelector('#drawer:not([hidden]) [data-rule-action="save-editor"]');
    if (!button) throw new Error("rules editor save action was not found");
    button.click();
  });
}

async function clickRuleRowAction(page, ruleName, action) {
  await page.evaluate(({ ruleName, action }) => {
    const button = document.querySelector(`[data-rule-action="${action}"][data-rule-name="${ruleName}"]`);
    if (!button) throw new Error(`rules row action ${action} was not found for ${ruleName}`);
    button.click();
  }, { ruleName, action });
}

async function reorderRuleByDom(page, sourceName, targetName) {
  const cssAttr = (value) => String(value || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const sourceSelector = `.rules-table tbody tr[data-rule-name="${cssAttr(sourceName)}"] .drag-handle`;
  const targetSelector = `.rules-table tbody tr[data-rule-name="${cssAttr(targetName)}"]`;
  const sourceBeforeTarget = async () => {
    const order = await rulesOrder(page);
    const sourceIndex = order.indexOf(sourceName);
    const targetIndex = order.indexOf(targetName);
    return sourceIndex >= 0 && targetIndex >= 0 && sourceIndex < targetIndex;
  };
  await page.evaluate(({ sourceName, targetName }) => {
    const source = document.querySelector(`.rules-table tbody tr[data-rule-name="${CSS.escape(sourceName)}"]`);
    const target = document.querySelector(`.rules-table tbody tr[data-rule-name="${CSS.escape(targetName)}"]`);
    if (!source || !target) throw new Error(`rules reorder source/target missing: ${sourceName} -> ${targetName}`);
    if (source.getAttribute("draggable") !== "true") throw new Error(`rules reorder source was not draggable: ${sourceName}`);
    if (!source.querySelector(".drag-handle")) throw new Error(`rules reorder drag handle missing: ${sourceName}`);
  }, { sourceName, targetName });
  await page.dragAndDrop(sourceSelector, targetSelector, { timeout: 5000 }).catch(() => {});
  if (await sourceBeforeTarget()) return;
  await page.evaluate(({ sourceName, targetName }) => {
    const source = document.querySelector(`.rules-table tbody tr[data-rule-name="${CSS.escape(sourceName)}"]`);
    const target = document.querySelector(`.rules-table tbody tr[data-rule-name="${CSS.escape(targetName)}"]`);
    if (!source || !target) throw new Error(`rules reorder source/target missing: ${sourceName} -> ${targetName}`);
    const dataTransfer = new DataTransfer();
    const dispatch = (node, type) => node.dispatchEvent(new DragEvent(type, {
      bubbles: true,
      cancelable: true,
      dataTransfer,
    }));
    dispatch(source.querySelector(".drag-handle") || source, "dragstart");
    dispatch(target, "dragover");
    dispatch(target, "drop");
    dispatch(source, "dragend");
  }, { sourceName, targetName });
  if (await sourceBeforeTarget()) return;
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const order = await rulesOrder(page);
    const sourceIndex = order.indexOf(sourceName);
    const targetIndex = order.indexOf(targetName);
    if (sourceIndex >= 0 && targetIndex >= 0 && sourceIndex < targetIndex) return;
    if (sourceIndex < 1 || targetIndex < 0) break;
    await page.evaluate((name) => {
      const button = document.querySelector(`.rules-table [data-rule-action="move-up"][data-rule-name="${CSS.escape(name)}"]`);
      if (!button || button.disabled) throw new Error(`rules move-up fallback unavailable for ${name}`);
      button.click();
    }, sourceName);
    await page.waitForTimeout(150);
  }
}

async function waitForRulesLifecycleState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await rulesLifecyclePolicyState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`rules manual lifecycle ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function rulesLifecyclePolicyState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const changes = Array.isArray(status.changes) ? status.changes : [];
    const rulesChange = changes.find((change) => change?.section === "rules") || null;
    return {
      candidateStatus: candidateResponse.status,
      runningStatus: runningResponse.status,
      statusStatus: statusResponse.status,
      candidate: {
        rules: candidate.rules || [],
        securityProfiles: candidate.securityProfiles || [],
        order: (candidate.rules || []).map((rule) => rule.name || ""),
      },
      running: {
        order: (running.rules || []).map((rule) => rule.name || ""),
      },
      runningText: JSON.stringify(running),
      runningFingerprint: stable(running),
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        rulesChanged: Boolean(rulesChange && Number(rulesChange.added || 0) + Number(rulesChange.modified || 0) + Number(rulesChange.removed || 0) > 0),
        changes,
      },
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
}

async function assertRulesCleanupRemediationWorkflow(page, viewport) {
  await page.evaluate(() => { location.hash = "#/rules"; });
  await runSmokeStep("rules cleanup route ready initial", () => waitForRouteReady(page, "/rules"));
  const before = await rulesCleanupPolicyState(page);

  await runSmokeStep("rules cleanup seed server overlap candidate", async () => {
    await page.evaluate(async () => {
      const response = await fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE");
      if (!response.ok) throw new Error(`read candidate for overlap seed failed with HTTP ${response.status}: ${await response.text()}`);
      const policy = (await response.json())?.policy || {};
      const srcName = "visual-overlap-src";
      const dstName = "visual-overlap-dst";
      const svcName = "visual-overlap-https";
      const ruleNames = new Set(["visual-overlap-dst-https", "visual-overlap-src-any"]);
      policy.addresses = (policy.addresses || []).filter((item) => ![srcName, dstName].includes(item?.name));
      policy.services = (policy.services || []).filter((item) => item?.name !== svcName);
      policy.rules = (policy.rules || []).filter((rule) => !ruleNames.has(rule?.name));
      policy.addresses.push({ name: srcName, cidr: "10.91.1.10/32", description: "Visual smoke overlap source." });
      policy.addresses.push({ name: dstName, cidr: "10.91.2.20/32", description: "Visual smoke overlap destination." });
      policy.services.push({ name: svcName, protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] });
      policy.rules.push(
        {
          name: "visual-overlap-dst-https",
          fromZones: ["any"],
          toZones: ["any"],
          sourceAddresses: ["any"],
          destinationAddresses: [dstName],
          services: [svcName],
          action: "ACTION_ALLOW",
          log: true,
          tags: ["visual-smoke", "overlap-review"],
        },
        {
          name: "visual-overlap-src-any",
          fromZones: ["any"],
          toZones: ["any"],
          sourceAddresses: [srcName],
          destinationAddresses: ["any"],
          services: ["any"],
          action: "ACTION_ALLOW",
          log: true,
          tags: ["visual-smoke", "overlap-review"],
        },
      );
      const put = await fetch("/v1/candidate", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ policy }),
      });
      if (!put.ok) throw new Error(`seed overlap candidate failed with HTTP ${put.status}: ${await put.text()}`);
    });
    await page.evaluate(() => { location.hash = "#/rules?density=compact"; });
    await waitForRouteReady(page, "/rules");
  });

  await page.evaluate(() => {
    const button = document.querySelector('[data-rules-action="validate-cleanup"]');
    if (!button) throw new Error("Validate cleanup action was not found");
    button.click();
  });
  await runSmokeStep("rules cleanup wait for validation findings", () => page.waitForFunction(() => {
    const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Rule cleanup queue") &&
      text.includes("server checked") &&
      Boolean(document.querySelector('[data-rule-hygiene-action="review-logging"][data-rule-hygiene-title="Missing logs"]')) &&
      Boolean(document.querySelector('[data-rule-hygiene-action="review-overlap"][data-rule-hygiene-title="Server rule overlaps"]')) &&
      Boolean(document.querySelector('[data-rule-hygiene-action="stage-host-input-logging"][data-rule-hygiene-title="Host-input missing logs"]'));
  }, null, { timeout: 10000 }));

  await runSmokeStep("rules cleanup review server overlap drawer", async () => {
    await page.evaluate(() => {
      const button = document.querySelector('[data-rule-hygiene-action="review-overlap"][data-rule-hygiene-title="Server rule overlaps"]');
      if (!button) throw new Error("Server rule overlap Review overlaps action was not found");
      button.click();
    });
    await waitForDrawerTitle(page, "Review server rule overlaps");
    await page.waitForFunction(() => (document.querySelector("#content")?.textContent || document.body.textContent || "").includes("first-match order"), null, { timeout: 5000 });
    const overlapHooks = await page.evaluate(() => ({
      hash: location.hash,
      hasDrawerHook: Boolean(document.querySelector('[data-rule-overlap-review="true"]')),
      hasItemHook: Boolean(document.querySelector('[data-rule-overlap-item]')),
      peerCount: document.querySelectorAll("[data-rule-overlap-peer]").length,
      dimensionKeys: [...document.querySelectorAll("[data-rule-overlap-dimension]")].map((el) => el.dataset.ruleOverlapDimension || ""),
      riskText: [...document.querySelectorAll("[data-rule-overlap-risk]")].map((el) => (el.textContent || "").replace(/\s+/g, " ").trim()).join(" | "),
      recommendation: (document.querySelector("[data-rule-overlap-action='recommendation']")?.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    if (!overlapHooks.hash.includes("drawer=server-overlap-review") || !overlapHooks.hasDrawerHook || !overlapHooks.hasItemHook) {
      throw new Error(`rules server-overlap drawer hooks missing: ${JSON.stringify(overlapHooks)}`);
    }
    for (const requiredDimension of ["zones", "source", "destination", "service"]) {
      if (!overlapHooks.dimensionKeys.includes(requiredDimension)) {
        throw new Error(`rules server-overlap drawer missing ${requiredDimension} dimension: ${JSON.stringify(overlapHooks)}`);
      }
    }
    if (overlapHooks.peerCount < 1 || !/same action|log gap|order review|allow before deny|deny before allow/i.test(overlapHooks.riskText) || !overlapHooks.recommendation) {
      throw new Error(`rules server-overlap impact hooks incomplete: ${JSON.stringify(overlapHooks)}`);
    }
    const overlapReview = await collectDrawerState(page);
    assertDrawerContains(overlapReview, viewport, "rules server-overlap review", [
      "Review server rule overlaps",
      "first-match order",
      "Overlap impact review",
      "Representative",
      "Logging",
    ], ["Copy review context", "API / CLI", "Close", "Enable logging", "Add review tag"]);
    await clickDrawerFooterButton(page, "API / CLI");
    await waitForDrawerTitle(page, "API / CLI context");
    const contextDrawer = await collectDrawerState(page);
    assertDrawerContains(contextDrawer, viewport, "rules server-overlap API / CLI context", [
      "API / CLI context",
      "#/rules?q=server-overlap",
      "drawer=server-overlap-review",
      "/v1/policy?source=POLICY_SOURCE_CANDIDATE",
      "/v1/candidate/validate",
      "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE",
      "ngfwctl policy show --source candidate --json",
      "ngfwctl policy validate",
      "ngfwctl policy diff",
      "server overlap",
      "first-match order",
      "candidate rulebase",
    ], ["Copy session JSON", "Copy context"]);
    assertAutomationContextRedaction(contextDrawer.text, `rules server-overlap API / CLI drawer ${viewport.name}`);
    const copied = await copyAutomationContextFromDrawer(page);
    for (const required of ["server overlap", "ngfwctl policy validate", "/v1/candidate/validate", "first-match order"]) {
      if (!copied.includes(required)) {
        throw new Error(`rules server-overlap copied API / CLI context missing ${required} at ${viewport.name}`);
      }
    }
    assertAutomationContextRedaction(copied, `rules server-overlap copied API / CLI context ${viewport.name}`);
    await closeActiveDrawer(page);
    await waitForDrawerClosed(page);
  });

  await runSmokeStep("rules cleanup stage host-input logging", async () => {
    await page.evaluate(() => {
      const button = document.querySelector('[data-rule-hygiene-action="stage-host-input-logging"][data-rule-hygiene-title="Host-input missing logs"]');
      if (!button) throw new Error("Host-input missing logs stage action was not found");
      button.click();
    });
    await waitForRulesCleanupState(page, "host-input logging candidate", (state) => state.candidate.hostRule?.log === true);
  });
  await runSmokeStep("rules cleanup stale validation warning after candidate mutation", () => page.waitForFunction(() => {
    const warning = document.querySelector('[data-rule-validation-stale="true"]');
    const text = (warning?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Server cleanup findings are stale") &&
      text.includes("Rerun Validate cleanup") &&
      !document.querySelector('[data-rule-hygiene-action="stage-host-input-logging"][data-rule-hygiene-title="Host-input missing logs"]');
  }, null, { timeout: 5000 }));

  await page.evaluate(() => {
    const button = document.querySelector('[data-rule-hygiene-action="review-logging"][data-rule-hygiene-title="Missing logs"]');
    if (!button) throw new Error("Missing logs Review logging action was not found");
    button.click();
  });
  await runSmokeStep("rules cleanup wait for security-rule logging drawer", () => waitForDrawerTitle(page, "Enable logging on selected rules"));
  const logReview = await collectDrawerState(page);
  assertDrawerContains(logReview, viewport, "rules missing-log cleanup review", [
    "Enable logging on selected rules",
    "Selected",
    "Will change",
    "drop-ssh",
    "logging off",
    "logging on",
  ], ["Cancel", "Stage logging on"]);
  if (!(await drawerFooterActionEnabled(page, "Stage logging on"))) {
    throw new Error("rules missing-log review did not enable Stage logging on");
  }
  await clickDrawerFooterButton(page, "Stage logging on");
  await runSmokeStep("rules cleanup security-rule drawer closed", () => waitForDrawerClosed(page));
  await waitForRulesCleanupState(page, "security-rule logging candidate", (state) => state.candidate.dropSsh?.log === true);

  let staged = await rulesCleanupPolicyState(page);
  if (!staged.candidate.dropSsh?.log || !staged.candidate.hostRule?.log) {
    throw new Error(`rules cleanup did not stage logging fixes: ${JSON.stringify(staged.candidate)}`);
  }
  if (staged.runningFingerprint !== before.runningFingerprint) {
    throw new Error("rules cleanup logging remediation mutated running policy before commit");
  }

  await page.evaluate(() => { location.hash = "#/rules"; });
  await runSmokeStep("rules cleanup route ready before tag", () => waitForRouteReady(page, "/rules"));
  await clickRulesToolbarButton(page, "Select visible");
  await clickRulesToolbarButton(page, "Add tag");
  await runSmokeStep("rules cleanup wait for tag drawer", () => waitForDrawerTitle(page, "Add tag to selected rules"));
  await page.fill('[data-rule-bulk-tag-input="add"]', "owner:secops-reviewed");
  await runSmokeStep("rules cleanup wait for bulk tag review", () => page.waitForFunction(() => {
    const review = document.querySelector('[data-rule-bulk-review="tag"]');
    const text = (review?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("owner:secops-reviewed") && text.includes("Will change");
  }, null, { timeout: 5000 }));
  const tagReview = await collectDrawerState(page);
  assertDrawerContains(tagReview, viewport, "rules bulk tag cleanup review", [
    "Add tag to selected rules",
    "owner:secops-reviewed",
    "Will change",
  ], ["Cancel", "Review and add"]);
  await assertRulesBulkReviewContextClipboard(page, viewport, "rules bulk tag cleanup review", [
    "Add tag to selected rules",
    "Drawer: bulk-tag-add",
    "Visible targets:",
    "Will change:",
    "No-op:",
    "Target rules:",
    "owner:secops-reviewed",
    "#1 allow-web",
    "#2 drop-ssh",
    "- ngfwctl policy validate",
    "- ngfwctl policy diff",
  ]);
  await clickDrawerFooterButton(page, "Review and add");
  await runSmokeStep("rules cleanup tag drawer closed", () => waitForDrawerClosed(page));
  await waitForRulesCleanupState(page, "bulk tag candidate", (state) => state.candidate.allRulesHaveReviewTag === true);

  await page.evaluate(() => {
    const input = document.querySelector('[data-rule-bulk-action="changed-only"] input');
    if (!input) throw new Error("Changed only rule filter was not found");
    if (!input.checked) input.click();
  });
  await runSmokeStep("rules cleanup wait for changed-only rows", () => page.waitForFunction(() => {
    const hash = location.hash || "";
    const rows = [...document.querySelectorAll(".rules-table tbody tr")]
      .filter((row) => !row.classList.contains("rule-group-row") && row.getBoundingClientRect().height > 0);
    return hash.includes("changed=1") &&
      rows.length > 0 &&
      rows.every((row) => row.dataset.ruleChange && row.dataset.ruleChange !== "unchanged") &&
      !((document.querySelector("[data-rule-change-summary='true']")?.textContent || "").includes("No staged rule changes"));
  }, null, { timeout: 5000 }));
  await clickRulesToolbarButton(page, "Verify changed");
  await runSmokeStep("rules cleanup wait for changed-rule verification drawer", () => waitForDrawerTitle(page, "Verify changed rules"));
  let verificationDrawer = await collectDrawerState(page);
  assertDrawerContains(verificationDrawer, viewport, "rules changed verification review", [
    "Verify changed rules",
    "candidate explain-flow evidence",
  ], ["Close", "Run verification"]);
  await assertRulesReviewContextClipboard(page, viewport, "rules changed verification review");
  await clickDrawerFooterButton(page, "Run verification");
  await runSmokeStep("rules cleanup wait for changed-rule verification result", () => page.waitForFunction(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const items = [...(drawer?.querySelectorAll("[data-rule-verification-item]") || [])];
    const runButton = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
      .find((button) => (button.textContent || "").replace(/\s+/g, " ").trim() === "Run verification");
    return items.length > 0 &&
      runButton &&
      !runButton.disabled;
  }, null, { timeout: 10000 }));
  const verificationResult = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return [...(drawer?.querySelectorAll("[data-rule-verification-item]") || [])].map((item) => ({
      name: item.dataset.ruleName || "",
      state: item.dataset.ruleVerificationItem || "",
      text: (item.textContent || "").replace(/\s+/g, " ").trim(),
      hasHead: Boolean(item.querySelector(".rule-verification-head")),
      hasTitle: Boolean(item.querySelector(".rule-verification-title")),
      hasKind: Boolean(item.querySelector(".rule-verification-kind")),
      badgeState: item.querySelector("[data-rule-verification-state]")?.dataset.ruleVerificationState || "",
      overflow: Math.max(0, Math.ceil(item.scrollWidth - item.clientWidth)),
    }));
  });
  const failedVerification = verificationResult.filter((item) => item.state === "error");
  if (failedVerification.length) {
    throw new Error(`rules changed verification reported error item(s) at ${viewport.name}: ${JSON.stringify(failedVerification)}`);
  }
  if (!verificationResult.some((item) => item.state === "verified" && ["allow-web", "drop-ssh"].includes(item.name))) {
    throw new Error(`rules changed verification did not prove a concrete changed rule at ${viewport.name}: ${JSON.stringify(verificationResult)}`);
  }
  const badVerificationLayout = verificationResult.filter((item) => !item.hasHead || !item.hasTitle || !item.hasKind || item.badgeState !== item.state || item.overflow > 2);
  if (badVerificationLayout.length) {
    throw new Error(`rules changed verification layout missed classed rows or overflowed at ${viewport.name}: ${JSON.stringify(badVerificationLayout)}`);
  }
  verificationDrawer = await collectDrawerState(page);
  assertDrawerContains(verificationDrawer, viewport, "rules changed verification result", [
    "Verify changed rules",
    "changed verified",
  ], ["Close", "Run verification"]);
  await clickDrawerFooterButton(page, "Close");
  await runSmokeStep("rules cleanup changed verification drawer closed", () => waitForDrawerClosed(page));
  await runSmokeStep("rules cleanup changed rows show verification", () => page.waitForFunction(() =>
    [...document.querySelectorAll(".rules-table [data-rule-verification-state]")]
      .some((node) => !["needed", "not-applicable"].includes(node.dataset.ruleVerificationState || "")), null, { timeout: 5000 }));

  staged = await rulesCleanupPolicyState(page);
  if (!staged.candidate.allRulesHaveReviewTag || staged.runningFingerprint !== before.runningFingerprint) {
    throw new Error(`rules cleanup tag remediation failed or leaked to running: ${JSON.stringify(staged)}`);
  }

  await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
  await runSmokeStep("rules cleanup route ready changes review", () => waitForRouteReady(page, "/changes"));
  await runSmokeStep("rules cleanup wait for changes candidate review", () => page.waitForFunction(() => {
    const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Current candidate") && text.includes("Open diff") && text.includes("Discard candidate");
  }, null, { timeout: 10000 }));
  await clickContentButton(page, "Open diff");
  await runSmokeStep("rules cleanup wait for diff drawer", () => waitForDrawerOpen(page));
  const diff = await collectDrawerState(page);
  assertDrawerContains(diff, viewport, "rules cleanup candidate diff", [
    "Diff:",
    "candidate",
    "drop-ssh",
    "owner:secops-reviewed",
  ], ["Close"]);
  await page.keyboard.press("Escape");
  await runSmokeStep("rules cleanup diff drawer closed", () => waitForDrawerClosed(page));

  await clickContentButton(page, "Discard candidate");
  await runSmokeStep("rules cleanup wait for discard drawer", () => waitForDrawerTitle(page, "Discard pending changes?"));
  await clickDrawerFooterButton(page, "Discard");
  await waitForRulesCleanupState(page, "discard clean candidate", (state) => !state.status.dirty && state.status.changeCount === 0, 10000);
  await assertCandidateClean(page);
  const discarded = await rulesCleanupPolicyState(page);
  if (discarded.runningFingerprint !== before.runningFingerprint) {
    throw new Error("rules cleanup discard changed running policy");
  }
}

async function assertRulesReviewContextClipboard(page, viewport, label) {
  const copied = await copyRulesReviewContextFromDrawer(page);
  for (const required of [
    "Changed rule verification",
    "Commands:",
    "- ngfwctl policy status --json",
    "- ngfwctl policy validate",
    "- ngfwctl policy diff",
    "- ngfwctl explain --source candidate",
  ]) {
    if (!copied.includes(required)) {
      throw new Error(`${label} copied context missing ${required}`);
    }
  }
  if (/policy validate --source candidate|policy diff --running --candidate/.test(copied)) {
    throw new Error(`${label} copied context included obsolete policy CLI flags: ${copied}`);
  }
  assertAutomationContextRedaction(copied, `${label} copied context`);
}

async function assertRulesBulkReviewContextClipboard(page, viewport, label, required = []) {
  const copied = await copyRulesReviewContextFromDrawer(page);
  for (const text of required) {
    if (!copied.includes(text)) {
      throw new Error(`${label} copied context missing ${text}`);
    }
  }
  if (/policy validate --source candidate|policy diff --running --candidate/.test(copied)) {
    throw new Error(`${label} copied context included obsolete policy CLI flags: ${copied}`);
  }
  assertAutomationContextRedaction(copied, `${label} copied context`);
}

async function copyRulesReviewContextFromDrawer(page) {
  await page.evaluate(() => {
    globalThis.__rulesReviewContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__rulesReviewContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  await clickDrawerFooterButton(page, "Copy review context");
  await page.waitForFunction(() => Boolean(globalThis.__rulesReviewContextCopiedText), null, { timeout: 5000 });
  return await page.evaluate(() => globalThis.__rulesReviewContextCopiedText || "");
}

async function copyAutomationContextFromDrawer(page) {
  await page.evaluate(() => {
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  return await page.evaluate(() => globalThis.__automationContextCopiedText || "");
}

async function waitForRulesCleanupState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await rulesCleanupPolicyState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`rules cleanup ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function rulesCleanupPolicyState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const findRule = (policy, name) => (policy.rules || []).find((rule) => rule.name === name) || null;
    const findHostRule = (policy, name) => (policy.hostInput?.rules || []).find((rule) => rule.name === name) || null;
    const reviewTag = "owner:secops-reviewed";
    return {
      candidateStatus: candidateResponse.status,
      runningStatus: runningResponse.status,
      statusStatus: statusResponse.status,
      runningFingerprint: stable(running),
      candidate: {
        dropSsh: findRule(candidate, "drop-ssh"),
        hostRule: findHostRule(candidate, "allow-admin-ssh"),
        allRulesHaveReviewTag: (candidate.rules || []).length >= 3 &&
          (candidate.rules || []).every((rule) => (rule.tags || []).includes(reviewTag)),
      },
      running: {
        dropSsh: findRule(running, "drop-ssh"),
        hostRule: findHostRule(running, "allow-admin-ssh"),
      },
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
        changes: status.changes || [],
      },
    };
  });
}

async function clickRulesToolbarButton(page, label) {
  const action = {
    "Select visible": "select-visible",
    Clear: "clear",
    "Verify changed": "verify-changed",
    Enable: "enable",
    Disable: "disable",
    "Log on": "log-on",
    "Log off": "log-off",
    "Add tag": "add-tag",
    "Remove tag": "remove-tag",
  }[label] || "";
  await page.evaluate(({ buttonLabel, action }) => {
    const target = action
      ? document.querySelector(`[data-rule-bulk-action="${action}"]`)
      : null;
    if (!target) throw new Error(`rules toolbar button "${buttonLabel}" was not found`);
    target.click();
  }, { buttonLabel: label, action });
}

async function rulesInteractionState(page) {
  return await page.evaluate(() => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    const rows = [...document.querySelectorAll(".rules-table tbody tr")]
      .filter((row) => !row.classList.contains("rule-group-row") && visible(row));
    const dragHandles = rows.map((row) => row.querySelector(".drag-handle")).filter(Boolean);
    const toolbar = document.querySelector("[data-rule-bulk-toolbar='true']");
    const actionButtons = rows.flatMap((row) => {
      const cell = row.querySelector('td[data-label="Actions"]');
      const cellRect = cell?.getBoundingClientRect?.();
      return [...(cell?.querySelectorAll(".icon-btn") || [])].filter(visible).map((button) => {
        const rect = button.getBoundingClientRect();
        return {
          action: button.dataset.ruleAction || "",
          width: rect.width,
          height: rect.height,
          overflow: cellRect ? Math.max(
            0,
            Math.ceil(rect.right - cellRect.right),
            Math.ceil(cellRect.left - rect.left),
            Math.ceil(rect.bottom - cellRect.bottom),
            Math.ceil(cellRect.top - rect.top),
          ) : 0,
        };
      });
    });
    return {
      hash: location.hash || "",
      compactTable: Boolean(document.querySelector(".rules-table.compact")),
      ruleCount: rows.length,
      groupCount: document.querySelectorAll(".rules-table tr.rule-group-row").length,
      groupLabels: [...document.querySelectorAll("[data-rule-group] .rule-group-label")].map((el) => (el.textContent || "").replace(/\s+/g, " ").trim()),
      groupKeys: [...document.querySelectorAll("[data-rule-group]")].map((el) => el.dataset.ruleGroup || ""),
      selectedRows: rows.filter((row) => row.classList.contains("row-selected")).length,
      rowSelectCount: document.querySelectorAll("[data-rule-select='row']").length,
      groupSelectCount: document.querySelectorAll("[data-rule-select='group']").length,
      visibleSelectCount: document.querySelectorAll("[data-rule-select='visible']").length,
      draggableRows: rows.filter((row) => row.getAttribute("draggable") === "true").length,
      disabledDragHandles: dragHandles.filter((handle) => getComputedStyle(handle).cursor === "not-allowed").length,
      toolbarText: (toolbar?.textContent || "").replace(/\s+/g, " ").trim(),
      bulkButtons: [...document.querySelectorAll(".rule-bulk-actions .btn")]
        .filter(visible)
        .map((button) => ({
          text: (button.textContent || "").replace(/\s+/g, " ").trim(),
          action: button.dataset.ruleBulkAction || "",
          disabled: Boolean(button.disabled),
        })),
      actionButtonCount: actionButtons.length,
      actionButtons,
      horizontalOverflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
    };
  });
}

async function assertReadinessExternalGateDetails(page, viewport, externalGateIds, releaseEvidence) {
  await page.evaluate((ids) => {
    const externalIds = new Set(ids);
    for (const detail of document.querySelectorAll("#content details")) {
      const gate = detail.closest("[data-release-evidence]")?.dataset?.releaseEvidence || detail.dataset?.releaseEvidence || "";
      if (externalIds.has(gate)) detail.open = true;
    }
  }, externalGateIds);

  const missingValidGateIds = (state) => {
    const validIds = new Set(state.valid.map((item) => item.id));
    return externalGateIds.filter((id) => !validIds.has(id));
  };
  let detailState = await collectReadinessExternalGateDetails(page, externalGateIds, releaseEvidence);
  for (let attempt = 0; missingValidGateIds(detailState).length && attempt < detailState.openerCount; attempt += 1) {
    const clicked = await page.evaluate(({ ids, index }) => {
      const externalIds = new Set(ids);
      const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
      const visible = (el) => {
        if (!el) return false;
        const style = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
      };
      const releaseRows = [...document.querySelectorAll("#content [data-release-evidence]")]
        .filter((el) => externalIds.has(el.dataset.releaseEvidence || ""));
      const controls = [];
      const addControl = (el) => {
        if (!el || !visible(el) || controls.includes(el)) return;
        if (el.tagName === "A" && el.getAttribute("href")) return;
        const actionText = [
          textOf(el),
          el.getAttribute("aria-label") || "",
          el.getAttribute("title") || "",
          el.dataset?.releaseEvidenceAction || "",
          el.dataset?.releaseEvidenceDetailAction || "",
        ].join(" ");
        if (el.matches("[data-release-evidence-action],[data-release-evidence-detail-action]") || /packet|detail|reference|evidence|review/i.test(actionText)) {
          controls.push(el);
        }
      };
      for (const row of releaseRows) {
        if (row.matches("button,[role='button'],summary,[data-release-evidence-action],[data-release-evidence-detail-action]")) addControl(row);
        for (const el of row.querySelectorAll("button,[role='button'],summary,[data-release-evidence-action],[data-release-evidence-detail-action]")) {
          addControl(el);
        }
      }
      const target = controls[index];
      if (!target) return "";
      if (target.tagName === "SUMMARY") {
        const details = target.closest("details");
        if (details) details.open = true;
      } else {
        target.click();
      }
      return textOf(target) || target.getAttribute("aria-label") || target.getAttribute("title") || target.dataset?.releaseEvidenceAction || "details";
    }, { ids: externalGateIds, index: attempt });
    if (!clicked) break;
    await page.waitForTimeout(120);
    detailState = await collectReadinessExternalGateDetails(page, externalGateIds, releaseEvidence);
  }

  if (detailState.badLinks.length) {
    throw new Error(`external release evidence detail UI has dead app route link(s): ${detailState.badLinks.join("; ")}`);
  }
  if (detailState.overflow.length) {
    throw new Error(`external release evidence detail UI overflow at ${viewport.name}: ${detailState.overflow.join("; ")}`);
  }
  const missingValid = missingValidGateIds(detailState);
  if (missingValid.length) {
    const inspected = detailState.details.length
      ? detailState.details.map((item) => `${item.id || "<unknown>"} command=${item.hasCopyableCommand} path=${item.hasReferenceOrEvidencePath} packet=${item.hasPacketMarker}`).join("; ")
      : "no external detail surfaces found";
    throw new Error(`external release evidence gate(s) missing packet/detail UI with copyable command text and reference/evidence path: ${missingValid.join(", ")} (${inspected})`);
  }
}

async function collectReadinessExternalGateDetails(page, externalGateIds, releaseEvidence) {
  return await page.evaluate(({ ids, routeState }) => {
    const externalIds = new Set(ids);
    const supportedHashRoutes = new Set(routeState.supportedHashRoutes || []);
    const visible = (el) => {
      if (!el || el.hidden || el.closest("[hidden],[aria-hidden='true']")) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
    };
    const textOf = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const valueOf = (el) => [
      textOf(el),
      el?.value || "",
      el?.getAttribute?.("data-command") || "",
      el?.getAttribute?.("data-copy") || "",
      el?.getAttribute?.("aria-label") || "",
      el?.getAttribute?.("title") || "",
    ].filter(Boolean).join(" ");
    const describe = (el, fallback = "") => {
      const tag = el?.tagName?.toLowerCase?.() || "node";
      const id = el?.id ? `#${el.id}` : "";
      const classes = [...(el?.classList || [])].slice(0, 3).map((name) => `.${name}`).join("");
      const label = textOf(el) || fallback;
      return `${tag}${id}${classes}${label ? ` "${label.slice(0, 64)}${label.length > 64 ? "..." : ""}"` : ""}`;
    };
    const gatePatterns = [
      ["content-production-readiness", /content-production-readiness|production content readiness/i],
      ["privileged-integration", /privileged-integration|privileged integration/i],
      ["m3-field-evidence", /m3-field-evidence|m3 external field evidence|external bgp peer|external wireguard/i],
      ["ebpf-ol9-field-evidence", /ebpf-ol9-field-evidence|ebpf ol9 field evidence|ol9\/oci linux-root|xdp\/tc|renderer scaffold/i],
      ["m5-oidc-field-evidence", /m5-oidc-field-evidence|oidc real-provider|real issuer/i],
    ];
    const gateIdFor = (el) => {
      const data = el?.dataset || {};
      const explicit = data.releaseEvidenceDetail ||
        data.releaseEvidenceDetails ||
        data.releaseEvidencePacket ||
        data.releaseEvidencePacketFor ||
        data.releaseEvidenceFor ||
        data.releaseEvidence ||
        el.closest("[data-release-evidence]")?.dataset?.releaseEvidence ||
        "";
      if (explicit) return explicit;
      const text = textOf(el);
      return gatePatterns.find(([, pattern]) => pattern.test(text))?.[0] || "";
    };
    const detailSelector = [
      "[data-release-evidence-detail]",
      "[data-release-evidence-details]",
      "[data-release-evidence-packet]",
      "[data-release-evidence-packet-for]",
      "[data-release-evidence-for]",
      ".release-evidence-detail",
      ".release-evidence-details",
      ".release-evidence-packet",
      ".release-evidence-drawer",
      ".evidence-packet",
      ".evidence-detail",
      "details[open]",
      "[role='dialog']",
      ".drawer",
    ].join(",");
    const commandSelector = [
      "[data-release-evidence-command]",
      "[data-command]",
      "[data-copy]",
      ".command-box",
      ".copy-command",
      ".setup-host-command code",
      ".warning-actions code",
      "pre",
      "code",
      "textarea",
      "input[readonly]",
    ].join(",");
    const commandPattern = /\b(make|ngfwctl|ngfwperf|curl|sudo|go test|node|npm|podman|ssh)\b/i;
    const pathPattern = /\b(docs\/[A-Za-z0-9._/-]+\.md(?:#[A-Za-z0-9._/-]+)?|release\/(?:field-)?evidence(?:\/[A-Za-z0-9._/-]+)?|evidence\/[A-Za-z0-9._/-]+|release\/acceptance\.json)\b/i;
    const packetPattern = /\b(packet|details?|reference|field evidence|release evidence|acceptance evidence|evidence path)\b/i;
    const copyPattern = /\bcopy\b/i;
    const releaseRows = [...document.querySelectorAll("#content [data-release-evidence]")]
      .filter((el) => externalIds.has(el.dataset.releaseEvidence || ""));
    const openerControls = [];
    const addOpener = (el) => {
      if (!el || !visible(el) || openerControls.includes(el)) return;
      if (el.tagName === "A" && el.getAttribute("href")) return;
      const actionText = [
        textOf(el),
        el.getAttribute("aria-label") || "",
        el.getAttribute("title") || "",
        el.dataset?.releaseEvidenceAction || "",
        el.dataset?.releaseEvidenceDetailAction || "",
      ].join(" ");
      if (el.matches("[data-release-evidence-action],[data-release-evidence-detail-action]") || /packet|detail|reference|evidence|review/i.test(actionText)) {
        openerControls.push(el);
      }
    };
    for (const row of releaseRows) {
      if (row.matches("button,[role='button'],summary,[data-release-evidence-action],[data-release-evidence-detail-action]")) addOpener(row);
      for (const el of row.querySelectorAll("button,[role='button'],summary,[data-release-evidence-action],[data-release-evidence-detail-action]")) {
        addOpener(el);
      }
    }

    const appSupportsNonHashRoutes = Boolean(routeState.appSupportsNonHashRoutes);
    const rowDetails = releaseRows.flatMap((row) => [...row.querySelectorAll(detailSelector)]);
    const globalDetails = [...document.querySelectorAll(detailSelector)]
      .filter((el) => !el.closest("#content [data-release-evidence]"));
    const details = [...new Set([...rowDetails, ...globalDetails])]
      .filter(visible)
      .map((el) => {
        const id = gateIdFor(el);
        if (!externalIds.has(id)) return null;
        const rect = el.getBoundingClientRect();
        const text = textOf(el);
        const commandNodes = [...el.querySelectorAll(commandSelector)].filter(visible);
        const copyControls = [...el.querySelectorAll("button,[role='button'],[data-release-evidence-action],[data-copy]")].filter((candidate) => (
          visible(candidate) && copyPattern.test(valueOf(candidate))
        ));
        const commands = commandNodes.map(valueOf).filter((value) => commandPattern.test(value));
        const links = [...el.querySelectorAll("a[href]")].filter(visible).map((link) => {
          const href = link.getAttribute("href") || "";
          let resolvedHash = "";
          let sameOrigin = false;
          try {
            const resolved = new URL(href || "", location.href);
            resolvedHash = resolved.hash || "";
            sameOrigin = resolved.origin === location.origin;
          } catch {}
          return { href, resolvedHash, sameOrigin };
        });
        const badLinks = links.flatMap((link) => {
          const href = String(link.href || "").trim();
          if (!href) return [];
          if (link.resolvedHash.startsWith("#/")) {
            const route = link.resolvedHash.slice(1).split(/[?#]/, 1)[0] || "/";
            if (supportedHashRoutes.has(route)) return [];
            return [`${id || "<unknown>"} detail href "${href}" targets unsupported hash route "${route}"`];
          }
          if (link.sameOrigin && !appSupportsNonHashRoutes) {
            return [`${id || "<unknown>"} detail href "${href}" is a non-hash same-origin route, but this WebUI nav only advertises hash routes`];
          }
          return [];
        });
        const elementOverflow = Math.max(0, Math.ceil(rect.right - window.innerWidth), Math.ceil(0 - rect.left));
        const internalOverflow = Math.max(0, Math.ceil(el.scrollWidth - el.clientWidth));
        return {
          id,
          description: describe(el, id),
          hasPacketMarker: packetPattern.test(text) || /packet|detail/i.test(el.className || ""),
          hasCopyableCommand: commands.length > 0 && copyControls.length > 0,
          hasReferenceOrEvidencePath: pathPattern.test(text) || links.some((link) => pathPattern.test(link.href)),
          commandCount: commands.length,
          copyCount: copyControls.length,
          badLinks,
          overflow: elementOverflow > 2 || internalOverflow > 2 ? `${id || "<unknown>"} ${describe(el, id)} overflow=${Math.max(elementOverflow, internalOverflow)}px` : "",
        };
      })
      .filter(Boolean);
    const valid = details.filter((detail) => detail.hasPacketMarker && detail.hasCopyableCommand && detail.hasReferenceOrEvidencePath);
    return {
      openerCount: openerControls.length,
      details,
      valid,
      badLinks: details.flatMap((detail) => detail.badLinks),
      overflow: details.map((detail) => detail.overflow).filter(Boolean),
    };
  }, { ids: externalGateIds, routeState: releaseEvidence });
}

async function assertChangesImportPreviewGuardrail(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const before = await candidateStatusSnapshot(page);
  try {
    await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
    await waitForRouteReady(page, "/changes");
    const exported = await assertChangesRunningPolicyExport(page, viewport);
    const importMarker = `visual-import-restore-${viewport.name}`;
    const importText = changesImportEnvelopeFromExport(exported.packet, importMarker);

    const opened = await page.evaluate(() => {
      const label = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
      const target = [...document.querySelectorAll("#content button")]
        .find((button) => label(button) === "Import to candidate");
      if (!target) return false;
      target.click();
      return true;
    });
    if (!opened) {
      throw new Error("changes import action was not visible");
    }
    await waitForDrawerTitle(page, "Import policy to candidate");
    await page.fill("#drawer:not([hidden]) textarea.input", importText);
    await clickDrawerFooterButton(page, "Preview import");
    await waitForDrawerTitle(page, "Import preview");

    const preview = await page.evaluate(() => {
      const drawer = document.querySelector("#drawer:not([hidden])");
      const rect = drawer?.getBoundingClientRect?.();
      const label = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
      const footerButtons = [...(drawer?.querySelectorAll(".drawer-foot button") || [])].map((button) => {
        const buttonRect = button.getBoundingClientRect();
        return {
          text: label(button),
          disabled: Boolean(button.disabled),
          width: buttonRect.width,
          height: buttonRect.height,
        };
      });
      return {
        title: drawer?.querySelector("h2")?.textContent?.trim() || "",
        text: label(drawer),
        footerButtons,
        overflow: drawer ? Math.max(
          0,
          Math.ceil(rect.right - window.innerWidth),
          Math.ceil(0 - rect.left),
          Math.ceil(drawer.scrollWidth - drawer.clientWidth),
        ) : 0,
      };
    });

    if (preview.title !== "Import preview") {
      throw new Error(`policy import preview opened "${preview.title || "<none>"}"`);
    }
    if (preview.overflow > 2) {
      throw new Error(`policy import preview drawer overflow at ${viewport.name}: ${preview.overflow}px`);
    }
    const requiredText = [
      "Review server validation and impact before replacing the staged candidate.",
      "Imported policy",
      "Validation",
      "passed",
      "Candidate",
      "unchanged",
      "Imported policy validated successfully",
      "existing candidate has not been changed",
      "Commit impact if staged",
      "Diff against running policy",
    ];
    const missingText = requiredText.filter((text) => !preview.text.includes(text));
    if (missingText.length) {
      throw new Error(`policy import preview missing text: ${missingText.join(", ")}`);
    }
    const requiredButtons = ["Cancel", "Edit JSON", "Stage import"];
    const missingButtons = requiredButtons.filter((label) => !preview.footerButtons.some((button) => button.text === label));
    if (missingButtons.length) {
      throw new Error(`policy import preview missing footer action(s): ${missingButtons.join(", ")}`);
    }
    const stageButton = preview.footerButtons.find((button) => button.text === "Stage import");
    if (!stageButton || stageButton.disabled) {
      throw new Error("policy import preview did not expose an enabled Stage import action after successful validation");
    }
    if (viewport.name === "mobile") {
      const cramped = preview.footerButtons.filter((button) => button.width < 70 || button.height < 36);
      if (cramped.length) {
        throw new Error(`mobile policy import preview footer action(s) too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
      }
    }

    const afterPreview = await candidateStatusSnapshot(page);
    if (JSON.stringify(afterPreview) !== JSON.stringify(before)) {
      throw new Error(`policy import preview mutated candidate status: before=${JSON.stringify(before)} after=${JSON.stringify(afterPreview)}`);
    }
    await clickDrawerFooterButton(page, "Stage import");
    await waitForDrawerClosed(page);
    await assertChangesImportedCandidateOnly(page, importMarker);
  } finally {
    await page.keyboard.press("Escape").catch(() => {});
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
    await waitForRouteReady(page, "/changes");
  }
}

async function assertChangesRunningPolicyExport(page, viewport) {
  const download = await clickValidatedDownloadAction(page, {
    selector: '#content [data-changes-action="export-running"]',
    expectedText: "Export running",
    unavailableMessage: "changes export running action was not uniquely visible and enabled",
  });
  const filename = download.suggestedFilename();
  if (!/^phragma-running(?:-v\d+)?-\d{4}-\d{2}-\d{2}T[0-9-]+Z\.json$/.test(filename || "")) {
    throw new Error(`changes running export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`changes running export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  return {
    filename,
    text,
    packet: assertChangesPolicyExportEnvelope(text, `changes running export ${viewport.name}`, { source: "running" }),
  };
}

async function assertChangesVersionPolicyExport(page, viewport, version, expectedPolicyMarker = "") {
  await page.evaluate(() => { location.hash = "#/changes?tab=versions"; });
  await waitForRouteReady(page, "/changes");
  const download = await clickValidatedDownloadAction(page, {
    selector: `[data-changes-version-row="${String(version)}"] [data-changes-action="export-version"]`,
    expectedText: "Export",
    unavailableMessage: `changes version export action for v${version} was not uniquely visible and enabled`,
  });
  const filename = download.suggestedFilename();
  const expectedName = new RegExp(`^phragma-version-v${String(version).replace(/^v/i, "")}-\\d{4}-\\d{2}-\\d{2}T[0-9-]+Z\\.json$`);
  if (!expectedName.test(filename || "")) {
    throw new Error(`changes version export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`changes version export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  const packet = assertChangesPolicyExportEnvelope(text, `changes version export ${viewport.name}`, { source: "version", version });
  if (expectedPolicyMarker && !text.includes(expectedPolicyMarker)) {
    throw new Error(`changes version export v${version} did not contain committed policy marker ${expectedPolicyMarker}`);
  }
  return { filename, text, packet };
}

async function clickValidatedDownloadAction(page, { selector, expectedText = "", unavailableMessage }) {
  const action = page.locator(selector);
  const count = await action.count();
  if (count !== 1) {
    throw new Error(`${unavailableMessage}: found ${count} matching controls`);
  }
  const [visible, enabled, text] = await Promise.all([
    action.isVisible(),
    action.isEnabled(),
    action.textContent(),
  ]);
  const normalizedText = String(text || "").replace(/\s+/g, " ").trim();
  if (!visible || !enabled || (expectedText && normalizedText !== expectedText)) {
    throw new Error(`${unavailableMessage}: visible=${visible} enabled=${enabled} text=${JSON.stringify(normalizedText)}`);
  }
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 5000 }),
    action.click(),
  ]);
  return download;
}

function assertChangesPolicyExportEnvelope(text, label, expected = {}) {
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} was not valid JSON: ${err.message}`);
  }
  const expectedSource = expected.source || "running";
  const expectedVersion = expected.version == null ? "" : String(expected.version).replace(/^v/i, "");
  if (packet.schemaVersion !== "phragma.policy.export.v1" ||
      packet.source !== expectedSource ||
      (expected.version != null && String(packet.version || "").replace(/^v/i, "") !== expectedVersion) ||
      !packet.exportedAt ||
      !packet.policy ||
      typeof packet.policy !== "object" ||
      Array.isArray(packet.policy)) {
    throw new Error(`${label} had unexpected export envelope: ${JSON.stringify(packet)}`);
  }
  const leaked = [
    /Bearer\s+(?!\$\{|\[redacted\])[A-Za-z0-9._~+/-]{12,}/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
    /api[_-]?key=(?!\[redacted\])/i,
    /https?:\/\/[^/\s"']+:[^@\s"']+@/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked secret-like policy export text: ${leaked}`);
  }
  return packet;
}

function changesImportEnvelopeFromExport(packet, marker) {
  const policy = JSON.parse(JSON.stringify(packet.policy || {}));
  policy.addresses = Array.isArray(policy.addresses) ? policy.addresses.filter((item) => item?.name !== marker) : [];
  policy.addresses.push({
    name: marker,
    cidr: "198.51.100.250/32",
    description: "visual smoke backup restore import drill",
  });
  return JSON.stringify({
    schemaVersion: "phragma.policy.export.v1",
    source: "visual-smoke-restore",
    version: packet.version || "",
    policy,
  }, null, 2);
}

async function assertChangesImportedCandidateOnly(page, marker) {
  await page.waitForFunction(async (name) => {
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok || !statusResponse.ok) return false;
    const candidate = (await candidateResponse.json())?.policy || {};
    const status = await statusResponse.json();
    return Boolean((candidate.addresses || []).some((item) => item.name === name) && status.dirty);
  }, marker, { timeout: 5000 });
  await page.waitForFunction(() => {
    const text = (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("Current candidate") && text.includes("Commit impact");
  }, null, { timeout: 10000 });
  const state = await page.evaluate(async (name) => {
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read imported candidate failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read running after import failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    if (!statusResponse.ok) throw new Error(`read candidate status after import failed with HTTP ${statusResponse.status}: ${await statusResponse.text()}`);
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const status = await statusResponse.json();
    return {
      candidateAddress: (candidate.addresses || []).find((item) => item.name === name) || null,
      runningAddress: (running.addresses || []).find((item) => item.name === name) || null,
      dirty: Boolean(status.dirty),
      changeCount: Number(status.changeCount || status.change_count || 0),
      changesText: JSON.stringify(status.changes || []),
      pageText: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  }, marker);
  if (!state.candidateAddress || state.candidateAddress.cidr !== "198.51.100.250/32") {
    throw new Error(`policy import did not stage expected candidate address: ${JSON.stringify(state)}`);
  }
  if (state.runningAddress) {
    throw new Error(`policy import mutated running policy before commit: ${JSON.stringify(state.runningAddress)}`);
  }
  if (!state.dirty || state.changeCount < 1 || !state.changesText.includes("addresses")) {
    throw new Error(`policy import did not produce address candidate status: ${JSON.stringify(state)}`);
  }
  if (!state.pageText.includes("Current candidate") || !state.pageText.includes("Commit impact")) {
    throw new Error(`policy import did not return operator to candidate review: ${JSON.stringify(state)}`);
  }
}

async function assertChangesCommitRollbackLifecycle(page, viewport) {
  const plan = await seedChangesLifecycleCandidate(page, viewport.name);
  let committedVersion = 0;
  try {
    await changesStep("open candidate review", async () => {
      await page.evaluate(() => { location.hash = "#/changes?tab=versions"; });
      await waitForRouteReady(page, "/changes");
      await page.evaluate(() => { location.hash = "#/changes?tab=candidate"; });
      await waitForRouteReady(page, "/changes");
    });
    await changesStep("wait for candidate review actions", () => page.waitForFunction(() => {
      const text = document.querySelector("#content")?.textContent || "";
      return text.includes("Current candidate") && text.includes("Commit candidate") && text.includes("Prepare approval") && text.includes("Open diff");
    }, null, { timeout: 10000 }));
    const candidateReview = await changesStep("assert candidate review", () => assertChangesCandidateReview(page, viewport, plan));
    await changesStep("assert mobile candidate bar actions", () => assertMobileCandidateBarActions(page, viewport));
    await changesStep("assert governance approval packet", () => assertChangesGovernanceApprovalPacket(page, viewport, plan));

    await changesStep("open candidate diff", async () => {
      await clickContentButton(page, "Open diff");
      await waitForDrawerOpen(page);
      await assertChangesLifecycleDrawer(page, viewport, "candidate diff", [plan.ruleName, "running policy", "candidate"]);
      await page.keyboard.press("Escape");
      await waitForDrawerClosed(page);
    });

	if (candidateReview.commitEnabled) {
		committedVersion = await changesStep("commit candidate via UI", async () => {
			await clickChangesAction(page, "commit-candidate");
			await waitForDrawerTitle(page, "Commit candidate");
			const approvalId = await createChangeApprovalViaApi(page, plan.commitComment);
			await fillAndSubmitApplyDrawer(page, plan.commitComment, "commit", { approvalId });
			return await waitForRunningVersionAbove(page, plan.beforeVersion);
		});
    } else {
      if (requireChangesUIApply) {
        throw new Error("WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1 requires Commit candidate to be enabled in the UI");
      }
      committedVersion = await changesStep("commit candidate via API", () => commitCandidateViaApi(page, plan.commitComment));
    }
    await changesStep("assert candidate clean after commit", () => assertCandidateClean(page));
    await changesStep("assert version history responsive table", () => assertChangesVersionHistoryTable(page, viewport, plan.beforeVersion));
    await changesStep("export committed version artifact", () => assertChangesVersionPolicyExport(page, viewport, committedVersion, plan.ruleName));

    await changesStep("open version diff drawer", async () => {
      await openVersionRouteDrawer(page, plan.beforeVersion, "diff");
      await waitForDrawerOpen(page, 15000);
      await assertChangesLifecycleDrawer(page, viewport, "version diff", [plan.ruleName, `version ${plan.beforeVersion}`]);
      await page.keyboard.press("Escape");
      await waitForDrawerClosed(page);
      await waitForChangesHashCleared(page, "versions");
    });

    await changesStep("open rollback review drawer", async () => {
      await openVersionRouteDrawer(page, plan.beforeVersion, "rollback");
      await waitForDrawerTitle(page, `Rollback review: v${plan.beforeVersion}`, 30000);
      await assertChangesLifecycleDrawer(page, viewport, "rollback review", ["Recovery metadata", "Rollback impact", "Audit comment"]);
    });
    await changesStep("apply rollback", async () => {
      try {
        await fillAndSubmitApplyDrawer(page, plan.rollbackComment, "rollback");
        await waitForRunningVersionAbove(page, committedVersion);
      } catch (err) {
        if (requireChangesUIApply) {
          throw err;
        }
        await rollbackVersionViaApi(page, plan.beforeVersion, plan.rollbackComment);
        await page.keyboard.press("Escape");
        await waitForDrawerClosed(page);
      }
    });
    await changesStep("assert running restored", () => assertRunningPolicyRestored(page, plan));
    await changesStep("restore candidate after rollback", async () => {
      await restoreRulesWorkspaceCandidate(page, plan.beforePolicy);
      await assertCandidateClean(page);
    });
    await changesStep("assert commit rollback audit", () => assertChangesLifecycleAudit(page, plan));
  } catch (err) {
    await cleanupChangesLifecycle(page, plan, committedVersion).catch(() => {});
    throw err;
  }
}

async function changesStep(label, fn) {
  try {
    return await fn();
  } catch (err) {
    throw new Error(`${label}: ${err.message || String(err)}`);
  }
}

async function seedChangesLifecycleCandidate(page, viewportName) {
	return await page.evaluate(async ({ viewportName, token }) => {
		const mintStepUpToken = async (action, comment) => {
			const response = await fetch("/v1/system/access-administration/step-up", {
				method: "POST",
				headers: {
					...(token ? { "Authorization": `Bearer ${token}` } : {}),
					"content-type": "application/json",
				},
				body: JSON.stringify({ action, comment, ackStepUp: true }),
			});
			if (!response.ok) {
				throw new Error(`mint ${action} step-up token failed with HTTP ${response.status}: ${await response.text()}`);
			}
			const body = await response.json();
			return body?.token || "";
		};
		const createChangeApproval = async (comment) => {
			const statusResponse = await fetch("/v1/candidate/status");
			if (!statusResponse.ok) {
				throw new Error(`read candidate status before approval failed with HTTP ${statusResponse.status}: ${await statusResponse.text()}`);
			}
			const status = await statusResponse.json();
			const candidateRevision = status?.candidateRevision || status?.candidate_revision || "";
			if (!candidateRevision) {
				throw new Error(`candidate revision missing before approval: ${JSON.stringify(status)}`);
			}
			const approvalResponse = await fetch("/v1/change-approvals", {
				method: "POST",
				headers: {
					...(token ? { "Authorization": `Bearer ${token}` } : {}),
					"content-type": "application/json",
				},
				body: JSON.stringify({ candidateRevision, comment, ackRisk: true, ackRuntime: true }),
			});
			if (!approvalResponse.ok) {
				throw new Error(`create change approval failed with HTTP ${approvalResponse.status}: ${await approvalResponse.text()}`);
			}
			const approvalBody = await approvalResponse.json();
			return approvalBody?.approval?.id || "";
		};
		const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
		if (!running.ok) {
			throw new Error(`read running policy before changes lifecycle failed with HTTP ${running.status}: ${await running.text()}`);
		}
    const runningBody = await running.json();
    let beforePolicy = runningBody?.policy || {};
    let beforeVersion = Number(runningBody?.version || 0);
    if (beforeVersion <= 0) {
      const baselinePolicy = structuredClone(beforePolicy);
      baselinePolicy.addresses = baselinePolicy.addresses || [];
      if (!baselinePolicy.addresses.some((address) => address?.name === "visual-smoke-baseline")) {
        baselinePolicy.addresses.push({
          name: "visual-smoke-baseline",
          cidr: "198.51.100.249/32",
          description: "Browser smoke baseline object so rollback has a committed target.",
        });
      }
      const baselineCandidate = await fetch("/v1/candidate", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ policy: baselinePolicy }),
      });
      if (!baselineCandidate.ok) {
        throw new Error(`seed baseline candidate failed with HTTP ${baselineCandidate.status}: ${await baselineCandidate.text()}`);
      }
			const comment = "visual smoke baseline before changes lifecycle";
			const stepUpToken = await mintStepUpToken("commit", comment);
			const approvalId = await createChangeApproval(comment);
			const baselineStatus = await fetch("/v1/candidate/status");
			if (!baselineStatus.ok) {
				throw new Error(`read baseline candidate status failed with HTTP ${baselineStatus.status}: ${await baselineStatus.text()}`);
			}
			const baselineStatusBody = await baselineStatus.json();
			const reviewedCandidateRevision = String(baselineStatusBody?.candidateRevision || baselineStatusBody?.candidate_revision || "").trim();
			if (!reviewedCandidateRevision) {
				throw new Error(`baseline candidate revision missing before commit: ${JSON.stringify(baselineStatusBody)}`);
			}
			const baselineCommit = await fetch("/v1/commit", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					comment,
					ackRisk: true,
					ackRuntime: true,
					approvalId,
					stepUpToken,
					reviewedCandidateRevision,
				}),
			});
      if (!baselineCommit.ok) {
        throw new Error(`commit baseline failed with HTTP ${baselineCommit.status}: ${await baselineCommit.text()}`);
      }
      const baselineRunning = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
      if (!baselineRunning.ok) {
        throw new Error(`read baseline running policy failed with HTTP ${baselineRunning.status}: ${await baselineRunning.text()}`);
      }
      const baselineBody = await baselineRunning.json();
      beforePolicy = baselineBody?.policy || baselinePolicy;
      beforeVersion = Number(baselineBody?.version || 0);
    }
    const suffix = String(viewportName || "viewport").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
    const ruleName = `visual-smoke-address-change-${suffix}`;
    const nextPolicy = structuredClone(beforePolicy);
    nextPolicy.addresses = (nextPolicy.addresses || []).filter((address) => address?.name !== ruleName);
    nextPolicy.addresses.push({
      name: ruleName,
      cidr: "198.51.100.250/32",
      description: "Browser smoke address object for commit and rollback lifecycle.",
    });
    const candidate = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy: nextPolicy }),
    });
    if (!candidate.ok) {
      throw new Error(`seed changes lifecycle candidate failed with HTTP ${candidate.status}: ${await candidate.text()}`);
    }
    return {
      beforePolicy,
      beforeVersion,
      ruleName,
      commitComment: `visual smoke commit lifecycle ${suffix}`,
			rollbackComment: `visual smoke rollback lifecycle ${suffix}`,
		};
	}, { viewportName, token: smokeAdminToken });
}

async function assertChangesCandidateReview(page, viewport, plan) {
  const state = await page.evaluate(() => {
    const content = document.querySelector("#content");
    const overflow = Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth));
    const buttons = [...(content?.querySelectorAll("button") || [])].map((button) => {
      const rect = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        changesAction: button.dataset.changesAction || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        disabled: Boolean(button.disabled),
        width: rect.width,
        height: rect.height,
      };
    });
    const links = [...(content?.querySelectorAll("a[data-changes-link]") || [])].map((link) => ({
      text: (link.textContent || "").replace(/\s+/g, " ").trim(),
      changesLink: link.getAttribute("data-changes-link") || "",
      href: link.getAttribute("href") || "",
      title: link.getAttribute("title") || "",
      ariaLabel: link.getAttribute("aria-label") || "",
    }));
    return {
      text: (content?.textContent || "").replace(/\s+/g, " ").trim(),
      buttons,
      links,
      invalidButtons: buttons.filter((button) => button.changesAction && (
        button.type !== "button" ||
        !button.title.trim() ||
        !button.ariaLabel.trim()
      )),
      invalidLinks: links.filter((link) => !link.href || !link.title.trim() || !link.ariaLabel.trim()),
      overflow,
    };
  });
  if (state.overflow > 2) {
    throw new Error(`changes candidate review overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const requiredText = [
    "Current candidate",
    "Validation",
    "Runtime",
    "Impact",
    "Commit impact",
    "Strict UI apply evidence",
    "Field evidence claim",
    "not claimed by Changes",
    "Diff:",
    plan.ruleName,
  ];
  const missingText = requiredText.filter((text) => !state.text.includes(text));
  if (missingText.length) {
    throw new Error(`changes candidate review missing text: ${missingText.join(", ")}`);
  }
  const commit = state.buttons.find((button) => button.changesAction === "commit-candidate");
  const approval = state.buttons.find((button) => button.changesAction === "prepare-approval");
  const diff = state.buttons.find((button) => button.changesAction === "open-diff");
  if (!commit || !approval || approval.disabled || !diff || diff.disabled) {
    throw new Error(`changes candidate review actions unavailable: ${JSON.stringify({ commit, approval, diff })}`);
  }
  if (state.invalidButtons.length || state.invalidLinks.length) {
    throw new Error(`changes candidate review controls missing semantics at ${viewport.name}: ${JSON.stringify({ invalidButtons: state.invalidButtons, invalidLinks: state.invalidLinks })}`);
  }
  for (const action of ["refresh-review", "commit-candidate", "prepare-approval", "open-diff", "discard-candidate"]) {
    if (!state.buttons.some((button) => button.changesAction === action)) {
      throw new Error(`changes candidate review missing ${action} action at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
  if (state.links.some((link) => link.href.startsWith("#/readiness"))) {
    throw new Error(`changes candidate review exposed the retired readiness route at ${viewport.name}: ${JSON.stringify(state.links)}`);
  }
  if (commit.disabled && !/blocked|not ready|runtime/i.test(state.text)) {
    throw new Error(`changes candidate commit disabled without a visible blocker: ${JSON.stringify({ commit })}`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => ["Commit candidate", "Prepare approval", "Open diff"].includes(button.text) && (button.width < 76 || button.height < 36));
    if (cramped.length) {
      throw new Error(`mobile changes candidate buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
  return { commitEnabled: !commit.disabled };
}

async function assertMobileCandidateBarActions(page, viewport) {
  if (viewport.name !== "mobile") return;
  const state = await page.evaluate(() => {
    const bar = document.querySelector("#candidate-bar");
    const barRect = bar?.getBoundingClientRect();
    const actions = [...(bar?.querySelectorAll(".cb-actions .btn") || [])].map((button) => {
      const rect = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.getAttribute("data-candidate-bar-action") || button.getAttribute("href") || "",
        disabled: Boolean(button.disabled),
        width: rect.width,
        height: rect.height,
        left: rect.left,
        right: rect.right,
        top: rect.top,
      };
    });
    const actionWraps = actions.length > 1 && new Set(actions.map((button) => Math.round(button.top))).size > 1;
    const actionCluster = bar?.querySelector(".cb-actions");
    const actionRect = actionCluster?.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    return {
      hidden: Boolean(bar?.hidden),
      className: bar?.className || "",
      text: (bar?.textContent || "").replace(/\s+/g, " ").trim(),
      width: barRect?.width || 0,
      left: barRect?.left || 0,
      right: barRect?.right || 0,
      scrollWidth: bar?.scrollWidth || 0,
      clientWidth: bar?.clientWidth || 0,
      actionWidth: actionRect?.width || 0,
      actionScrollWidth: actionCluster?.scrollWidth || 0,
      actionClientWidth: actionCluster?.clientWidth || 0,
      viewportWidth,
      documentOverflow: Math.max(
        0,
        Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - viewportWidth),
      ),
      actions,
      actionWraps,
    };
  });
  if (state.hidden || !/(dirty|blocked)/.test(state.className)) {
    throw new Error(`mobile candidate bar did not expose a dirty or blocked state: ${JSON.stringify(state)}`);
  }
  if (!/(pending change|staged|candidate|reload)/i.test(state.text) || state.actions.length < 5) {
    throw new Error(`mobile candidate bar did not render expected actions: ${JSON.stringify(state)}`);
  }
  const overflow = Math.max(
    state.documentOverflow,
    Math.ceil(state.right - state.viewportWidth),
    Math.ceil(0 - state.left),
    Math.ceil(state.scrollWidth - state.clientWidth),
    Math.ceil(state.actionScrollWidth - state.actionClientWidth),
  );
  if (overflow > 2) {
    throw new Error(`mobile candidate bar actions overflow by ${overflow}px: ${JSON.stringify(state)}`);
  }
  if (!state.actionWraps) {
    throw new Error(`mobile candidate bar actions did not wrap into a usable cluster: ${JSON.stringify(state)}`);
  }
  const cramped = state.actions.filter((button) => button.width < 64 || button.height < 40);
  if (cramped.length) {
    throw new Error(`mobile candidate bar actions too small: ${cramped.map((button) => `${button.text || button.action} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
  }
}

async function assertChangesGovernanceApprovalPacket(page, viewport, plan) {
  await page.evaluate(() => {
    globalThis.__changesGovernanceCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__changesGovernanceCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  const before = await changesPolicySnapshot(page);
  await clickChangesAction(page, "prepare-approval");
  await waitForDrawerTitle(page, "Governance review packet");
  let state = await collectGovernanceApprovalDrawerState(page);
  assertGovernanceApprovalDrawerState(state, viewport, plan, "governance approval packet");

  await page.click('[data-governance-approval-action="copy"]');
  await page.waitForFunction(() => Boolean(globalThis.__changesGovernanceCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__changesGovernanceCopiedText || "");
  assertNoInvestigationLeak(copied, `governance approval copy ${viewport.name}`);
  assertGovernanceApprovalPacketText(copied, viewport, "copy");

  await page.click('[data-governance-approval-action="pin-case"]');
  await page.waitForFunction(() => {
    const text = (document.body?.textContent || "").replace(/\s+/g, " ");
    return /Pinned|case/i.test(text);
  }, null, { timeout: 5000 }).catch(() => {});

  const downloadPromise = page.waitForEvent("download", { timeout: 15000 });
  const clickedExport = await page.evaluate(() => {
    const button = document.querySelector('[data-governance-approval-action="export-json"]');
    if (!button || button.disabled) return false;
    button.click();
    return true;
  });
  if (!clickedExport) {
    throw new Error(`governance approval export action was not available at ${viewport.name}`);
  }
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^phragma-investigation-governance-approval-.+\.json$/.test(filename)) {
    throw new Error(`governance approval export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) throw new Error(`governance approval export was not readable at ${viewport.name}`);
  const exportedText = await readFile(path, "utf8");
  assertNoInvestigationLeak(exportedText, `governance approval export ${viewport.name}`);
  const exported = parseInvestigationJson(exportedText, `governance approval export ${viewport.name}`);
  assertGovernanceApprovalPacketJson(exported, viewport, "export");

  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/changes", ["drawer"]);
  await assertChangesPolicySnapshotUnchanged(page, before, "governance approval actions");

  await page.evaluate(() => { location.hash = "#/changes?tab=candidate&drawer=governance-approval"; });
  await waitForRouteReady(page, "/changes");
  await waitForDrawerTitle(page, "Governance review packet");
  state = await collectGovernanceApprovalDrawerState(page);
  assertGovernanceApprovalDrawerState(state, viewport, plan, "route-backed governance approval packet");
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/changes", ["drawer"]);
  await assertChangesPolicySnapshotUnchanged(page, before, "route-backed governance approval");
}

async function collectGovernanceApprovalDrawerState(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-governance-approval-drawer='true']");
    const drawer = root?.closest(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const buttons = [...(drawer?.querySelectorAll("button") || [])].map((button) => {
      const b = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.dataset.governanceApprovalAction || "",
        disabled: button.disabled,
        width: b.width,
        height: b.height,
      };
    });
    return {
      hash: location.hash || "",
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      buttons,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

function assertGovernanceApprovalDrawerState(state, viewport, plan, label) {
  if (state.overflow > 2) {
    throw new Error(`${label} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const requiredText = [
    "Governance review packet",
    "Browser-local CAB handoff",
    "Review handoff only",
    "server-side approval",
    "Required reviewers",
    "Risk factors",
    "Candidate summary",
    plan.ruleName,
  ];
  const missing = requiredText.filter((text) => !state.text.includes(text) && !state.title.includes(text));
  if (missing.length) {
    throw new Error(`${label} missing text at ${viewport.name}: ${missing.join(", ")}`);
  }
  for (const action of ["copy", "export-json", "pin-case"]) {
    if (!state.buttons.some((button) => button.action === action && !button.disabled)) {
      throw new Error(`${label} missing enabled ${action} action at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => !button.disabled && button.text && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`${label} mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
  assertNoInvestigationLeak(state.text, `${label} drawer ${viewport.name}`);
}

function assertGovernanceApprovalPacketText(text, viewport, label) {
  if (!text.includes("schema=phragma.investigation.handoff.v1") ||
      !text.includes("kind=governance-approval") ||
      !text.includes("Governance review packet") ||
      !text.includes("server-side approval") ||
      !text.includes("hardening work")) {
    throw new Error(`governance approval ${label} text had unexpected shape at ${viewport.name}: ${text.slice(0, 600)}`);
  }
}

function parseInvestigationJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} was not valid JSON: ${err.message}`);
  }
}

function assertGovernanceApprovalPacketJson(packet, viewport, label) {
  if (packet?.schemaVersion !== "phragma.investigation.handoff.v1" ||
      packet?.kind !== "governance-approval" ||
      packet?.source?.interface !== "webui" ||
      !String(packet?.source?.route || "").includes("drawer=governance-approval") ||
	      !Array.isArray(packet?.summary?.reviewerRoles) ||
	      !Array.isArray(packet?.summary?.riskFactors) ||
	      packet?.artifacts?.approval?.ticketRequired !== true ||
	      !String(packet?.summary?.custody || "").includes("server-side approval record")) {
    throw new Error(`governance approval ${label} JSON had unexpected shape at ${viewport.name}: ${JSON.stringify(packet)}`);
  }
}

async function changesPolicySnapshot(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    if (!candidateResponse.ok || !runningResponse.ok || !statusResponse.ok) {
      throw new Error(`snapshot failed: candidate=${candidateResponse.status} running=${runningResponse.status} status=${statusResponse.status}`);
    }
    const candidate = await candidateResponse.json();
    const running = await runningResponse.json();
    const status = await statusResponse.json();
    return {
      candidate: stable(candidate?.policy || {}),
      running: stable(running?.policy || {}),
      dirty: Boolean(status?.dirty),
      changeCount: Number(status?.changeCount || status?.change_count || 0),
    };
  });
}

async function assertChangesPolicySnapshotUnchanged(page, before, label) {
  const after = await changesPolicySnapshot(page);
  if (after.candidate !== before.candidate || after.running !== before.running || after.dirty !== before.dirty || after.changeCount !== before.changeCount) {
    throw new Error(`${label} mutated policy state: before=${JSON.stringify(before)} after=${JSON.stringify(after)}`);
  }
}

async function assertChangesVersionHistoryTable(page, viewport, targetVersion) {
  await page.evaluate(() => { location.hash = "#/changes?tab=versions"; });
  await waitForRouteReady(page, "/changes");
  await page.waitForSelector(".changes-version-table [data-changes-version-row]", { timeout: 10000 });
  const state = await page.evaluate((version) => {
    const table = document.querySelector(".changes-version-table");
    const row = document.querySelector(`[data-changes-version-row="${String(version)}"]`) ||
      document.querySelector(".changes-version-table [data-changes-version-row]");
    const labels = [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
    const actions = [...(row?.querySelectorAll("[data-changes-action]") || [])].map((button) => {
      const rect = button.getBoundingClientRect();
      return {
        action: button.getAttribute("data-changes-action") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        disabled: Boolean(button.disabled),
        width: rect.width,
        height: rect.height,
      };
    });
    return {
      tableClass: table?.className || "",
      rowVersion: row?.getAttribute("data-changes-version-row") || "",
      labels,
      actions,
      invalidActions: actions.filter((button) => (
        button.type !== "button" ||
        !button.title.trim() ||
        !button.ariaLabel.trim() ||
        !button.action
      )),
      hasActionCell: Boolean(row?.querySelector("td.cell-actions[data-label='Actions']")),
      mobileLabelsRendered: window.innerWidth <= 820
        ? [...(row?.querySelectorAll("td") || [])].every((cell) => {
            if (cell.classList.contains("cell-actions")) return true;
            const before = getComputedStyle(cell, "::before").content || "";
            return before !== "none" && before !== "\"\"" && before.length > 2;
          })
        : true,
      overflow: Math.max(0, Math.ceil((document.scrollingElement || document.documentElement).scrollWidth - window.innerWidth)),
      text: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  }, targetVersion);
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes("changes-version-table")) {
    throw new Error(`changes version table missing responsive classes at ${viewport.name}: ${state.tableClass}`);
  }
  const expectedLabels = ["Version", "Comment", "Recovery", "Actor", "Time", "Actions"];
  const missingLabels = expectedLabels.filter((label) => !state.labels.includes(label));
  if (missingLabels.length || !state.hasActionCell) {
    throw new Error(`changes version table labels/actions mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  for (const action of ["diff-version", "export-version"]) {
    if (!state.actions.some((button) => button.action === action && !button.disabled)) {
      throw new Error(`changes version table missing enabled ${action} action at ${viewport.name}: ${JSON.stringify(state.actions)}`);
    }
  }
  if (state.invalidActions.length) {
    throw new Error(`changes version table actions missing semantics at ${viewport.name}: ${JSON.stringify(state.invalidActions)}`);
  }
  if (String(state.rowVersion) === String(targetVersion) && !state.actions.some((button) => button.action === "rollback-version" && !button.disabled)) {
    throw new Error(`changes version table missing rollback action for v${targetVersion} at ${viewport.name}: ${JSON.stringify(state.actions)}`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`changes version table mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`changes version table overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.actions.filter((button) => button.width < 56 || button.height < 34);
    if (cramped.length) {
      throw new Error(`changes version mobile action buttons too small: ${cramped.map((button) => `${button.action} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
}

async function clickContentButton(page, label) {
  await page.evaluate((buttonLabel) => {
    const norm = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const target = [...document.querySelectorAll("#content button")]
      .find((button) => norm(button) === buttonLabel);
    if (!target) throw new Error(`content button "${buttonLabel}" was not found`);
    target.click();
  }, label);
}

async function clickChangesAction(page, action) {
  await page.evaluate((changesAction) => {
    const target = document.querySelector(`[data-changes-action="${changesAction}"]`);
    if (!target) throw new Error(`changes action "${changesAction}" was not found`);
    if (target.disabled) throw new Error(`changes action "${changesAction}" was disabled`);
    target.click();
  }, action);
}

async function assertChangesLifecycleDrawer(page, viewport, label, requiredText = []) {
  const drawer = await collectDrawerState(page);
  if (drawer.overflow > 2) {
    throw new Error(`${label} drawer overflow at ${viewport.name}: ${drawer.overflow}px`);
  }
  const missingText = requiredText.filter((text) => !drawer.text.includes(text));
  if (missingText.length) {
    throw new Error(`${label} drawer missing text: ${missingText.join(", ")}`);
  }
}

async function fillAndSubmitApplyDrawer(page, comment, action, opts = {}) {
	await page.evaluate(({ comment, action, approvalId }) => {
		const drawer = document.querySelector("#drawer:not([hidden])");
		if (!drawer) throw new Error(`${action} drawer was not open`);
		const commentBox = drawer.querySelector(`[data-changes-field="${action}-comment"]`);
		if (!commentBox) throw new Error(`${action} drawer audit comment box was not found`);
    commentBox.value = comment;
    commentBox.dispatchEvent(new Event("input", { bubbles: true }));
    commentBox.dispatchEvent(new Event("change", { bubbles: true }));
    const ack = drawer.querySelector(`[data-changes-ack="${action}-runtime-risk"]`);
    if (ack && !ack.checked) {
			ack.checked = true;
			ack.dispatchEvent(new Event("change", { bubbles: true }));
		}
		if (approvalId && action === "commit") {
			const approval = drawer.querySelector('[data-changes-field="commit-approval-id"]');
			if (!approval) throw new Error("commit approval id field was not found");
			approval.value = approvalId;
			approval.dispatchEvent(new Event("input", { bubbles: true }));
			approval.dispatchEvent(new Event("change", { bubbles: true }));
		}
		const target = drawer.querySelector(`[data-changes-submit="${action}"]`);
		if (!target) throw new Error(`${action} footer action was not found`);
		if (target.disabled) throw new Error(`${action} footer action was disabled`);
		target.click();
	}, { comment, action, approvalId: opts.approvalId || "" });
	await waitForDrawerClosed(page);
}

async function createChangeApprovalViaApi(page, comment) {
	return await page.evaluate(async ({ comment, token }) => {
		const statusResponse = await fetch("/v1/candidate/status");
		if (!statusResponse.ok) {
			throw new Error(`read candidate status before approval failed with HTTP ${statusResponse.status}: ${await statusResponse.text()}`);
		}
		const status = await statusResponse.json();
		const candidateRevision = status?.candidateRevision || status?.candidate_revision || "";
		if (!candidateRevision) {
			throw new Error(`candidate revision missing before approval: ${JSON.stringify(status)}`);
		}
		const approvalResponse = await fetch("/v1/change-approvals", {
			method: "POST",
			headers: {
				...(token ? { "Authorization": `Bearer ${token}` } : {}),
				"content-type": "application/json",
			},
			body: JSON.stringify({ candidateRevision, comment, ackRisk: true, ackRuntime: true }),
		});
		if (!approvalResponse.ok) {
			throw new Error(`create change approval failed with HTTP ${approvalResponse.status}: ${await approvalResponse.text()}`);
		}
		const body = await approvalResponse.json();
		return body?.approval?.id || "";
	}, { comment, token: smokeAdminToken });
}

async function waitForRunningVersionAbove(page, beforeVersion) {
  await page.waitForFunction(async (version) => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!response.ok) return false;
    const body = await response.json();
    return Number(body?.version || 0) > Number(version || 0);
  }, beforeVersion, { timeout: 15000 });
  return await page.evaluate(async () => {
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    const body = await response.json();
    return Number(body?.version || 0);
  });
}

async function commitCandidateViaApi(page, comment) {
	return await page.evaluate(async ({ comment, token }) => {
		const statusResponse = await fetch("/v1/candidate/status");
		if (!statusResponse.ok) {
			throw new Error(`API commit status lookup failed with HTTP ${statusResponse.status}: ${await statusResponse.text()}`);
		}
		const status = await statusResponse.json();
		const candidateRevision = status?.candidateRevision || status?.candidate_revision || "";
		if (!candidateRevision) {
			throw new Error(`API commit candidate revision missing: ${JSON.stringify(status)}`);
		}
		const approval = await fetch("/v1/change-approvals", {
			method: "POST",
			headers: {
				...(token ? { "Authorization": `Bearer ${token}` } : {}),
				"content-type": "application/json",
			},
			body: JSON.stringify({ candidateRevision, comment, ackRisk: true, ackRuntime: true }),
		});
		if (!approval.ok) {
			throw new Error(`API commit approval failed with HTTP ${approval.status}: ${await approval.text()}`);
		}
		const approvalBody = await approval.json();
		const approvalId = approvalBody?.approval?.id || "";
		const stepUp = await fetch("/v1/system/access-administration/step-up", {
			method: "POST",
			headers: {
				...(token ? { "Authorization": `Bearer ${token}` } : {}),
				"content-type": "application/json",
			},
			body: JSON.stringify({ action: "commit", comment, ackStepUp: true }),
		});
		if (!stepUp.ok) {
			throw new Error(`API commit step-up failed with HTTP ${stepUp.status}: ${await stepUp.text()}`);
		}
		const stepUpBody = await stepUp.json();
		const response = await fetch("/v1/commit", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ comment, ackRisk: true, ackRuntime: true, approvalId, stepUpToken: stepUpBody?.token || "", reviewedCandidateRevision: candidateRevision }),
		});
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { message: text };
    }
    if (!response.ok) {
      throw new Error(`API commit failed with HTTP ${response.status}: ${body.message || body.error || text}`);
		}
		return Number(body.version || 0);
	}, { comment, token: smokeAdminToken });
}

async function rollbackVersionViaApi(page, version, comment) {
	return await page.evaluate(async ({ version, comment, token }) => {
		const stepUp = await fetch("/v1/system/access-administration/step-up", {
			method: "POST",
			headers: {
				...(token ? { "Authorization": `Bearer ${token}` } : {}),
				"content-type": "application/json",
			},
			body: JSON.stringify({ action: "rollback", comment, ackStepUp: true }),
		});
		if (!stepUp.ok) {
			throw new Error(`API rollback step-up failed with HTTP ${stepUp.status}: ${await stepUp.text()}`);
		}
		const stepUpBody = await stepUp.json();
		const response = await fetch("/v1/rollback", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ version: String(version), comment, ackRisk: true, ackRuntime: true, stepUpToken: stepUpBody?.token || "" }),
		});
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { message: text };
    }
    if (!response.ok) {
      throw new Error(`API rollback failed with HTTP ${response.status}: ${body.message || body.error || text}`);
		}
		return Number(body.version || 0);
	}, { version, comment, token: smokeAdminToken });
}

async function drawerFooterActionEnabled(page, label) {
  return await page.evaluate((buttonLabel) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const norm = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
    const target = [...(drawer?.querySelectorAll(".drawer-foot button") || [])]
      .find((button) => norm(button) === buttonLabel);
    if (!target) throw new Error(`drawer footer action "${buttonLabel}" was not found`);
    return !target.disabled;
  }, label);
}

async function assertCandidateClean(page) {
  const state = await candidateStatusSnapshot(page);
  if (state.dirty || Number(state.changeCount || 0) !== 0) {
    throw new Error(`candidate was not clean after commit: ${JSON.stringify(state)}`);
  }
}

async function openVersionRouteDrawer(page, version, drawer) {
  await page.evaluate(({ version, drawer }) => {
    location.hash = `#/changes?tab=versions&version=${encodeURIComponent(version)}&drawer=${encodeURIComponent(drawer)}`;
  }, { version, drawer });
}

async function waitForChangesHashCleared(page, tab) {
  await page.waitForFunction((expectedTab) => {
    const hash = location.hash || "";
    if (!hash.startsWith("#/changes")) return false;
    const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
    const params = new URLSearchParams(query);
    return params.get("tab") === expectedTab && !params.get("drawer") && !params.get("version");
  }, tab, { timeout: 5000 });
}

async function assertRunningPolicyRestored(page, plan) {
  const state = await page.evaluate(async ({ beforePolicy, ruleName }) => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const response = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    const body = await response.json();
    const policy = body?.policy || {};
    return {
      status: response.status,
      restored: stable(policy) === stable(beforePolicy || {}),
      leakedRule: JSON.stringify(policy).includes(ruleName),
      version: Number(body?.version || 0),
    };
  }, plan);
  if (state.status !== 200 || !state.restored || state.leakedRule) {
    throw new Error(`running policy was not restored after rollback: ${JSON.stringify(state)}`);
  }
}

async function assertChangesLifecycleAudit(page, plan) {
  const state = await page.evaluate(async ({ commitComment, rollbackComment }) => {
    const response = await fetch("/v1/audit?limit=100");
    const body = await response.json();
    const entries = body?.entries || [];
    const hasCommit = entries.some((entry) => entry.action === "commit" && String(entry.detail || "").includes(commitComment));
    const hasRollback = entries.some((entry) => entry.action === "rollback" && String(entry.detail || "").includes(rollbackComment));
    return { status: response.status, hasCommit, hasRollback };
  }, plan);
  if (state.status !== 200 || !state.hasCommit || !state.hasRollback) {
    throw new Error(`changes lifecycle audit entries missing: ${JSON.stringify(state)}`);
  }
}

async function cleanupChangesLifecycle(page, plan, committedVersion = 0) {
	await page.evaluate(async ({ plan, committedVersion, token }) => {
		const mintStepUpToken = async (action, comment) => {
			const response = await fetch("/v1/system/access-administration/step-up", {
				method: "POST",
				headers: {
					...(token ? { "Authorization": `Bearer ${token}` } : {}),
					"content-type": "application/json",
				},
				body: JSON.stringify({ action, comment, ackStepUp: true }),
			});
			if (!response.ok) return "";
			const body = await response.json();
			return body?.token || "";
		};
		const stable = (value) => {
			if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
			if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
		const body = running.ok ? await running.json() : {};
		const currentPolicy = body?.policy || {};
		if (stable(currentPolicy) !== stable(plan.beforePolicy || {}) && Number(plan.beforeVersion || 0) > 0) {
			const comment = `visual smoke cleanup rollback after failed changes lifecycle ${committedVersion || ""}`.trim();
			const stepUpToken = await mintStepUpToken("rollback", comment);
			await fetch("/v1/rollback", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					version: String(plan.beforeVersion),
					comment,
					ackRisk: true,
					ackRuntime: true,
					stepUpToken,
				}),
			});
		}
    await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
			body: JSON.stringify({ policy: plan.beforePolicy || {} }),
		});
	}, { plan, committedVersion, token: smokeAdminToken });
}

async function assertChangesAuditWorkbench(page, viewport) {
  await assertSavedFilterLifecycle(page, viewport, {
    label: "changes audit saved filter",
    routeHash: "#/changes?tab=audit",
    routePath: "/changes",
    scope: "changes-audit",
    filterRoot: ".audit-filters",
    fields: [
      { label: "Search", value: "visual smoke" },
      { label: "Action", value: "commit" },
      { label: "Limit", value: "100" },
    ],
    expectedParams: { tab: "audit", query: "visual smoke", action: "commit", limit: "100" },
    forbiddenStateKeys: ["entry"],
  });

  await assertChangesAuditTable(page, viewport);
  await assertChangesAuditLogHandoffActions(page, viewport);
  await assertChangesAuditReportBuilder(page, viewport);

  const entry = await page.evaluate(async () => {
    const response = await fetch("/v1/audit?limit=20");
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (err) {
      throw new Error(`audit response was not JSON: ${err.message}`);
    }
    if (!response.ok) {
      throw new Error(`audit fetch returned HTTP ${response.status}: ${(data && (data.message || data.error)) || text}`);
    }
    const item = (data?.entries || []).find((candidate) => candidate?.id || candidate?.entryHash || candidate?.time);
    if (!item) throw new Error("audit API returned no entries for route-backed drawer smoke");
    const key = String(item.id || item.entryHash || item.time || "").trim().replace(/\s+/g, "-");
    return {
      key,
      id: item.id ? String(item.id) : "",
      action: item.action || "",
      detail: item.detail || "",
      entryHash: item.entryHash || "",
    };
  });

  await page.evaluate((key) => {
    location.hash = "#/changes?tab=audit&entry=" + encodeURIComponent(key);
  }, entry.key);
  await waitForRouteReady(page, "/changes");
  await changesStep("wait for audit entry drawer", () =>
    page.waitForFunction(() => Boolean(document.querySelector("[data-audit-entry-drawer='true']")), null, { timeout: 10000 }));
  await changesStep("wait for audit entry drawer settled", () =>
    page.waitForFunction(() => {
      const drawer = document.querySelector("[data-audit-entry-drawer='true']")?.closest(".drawer");
      const rect = drawer?.getBoundingClientRect?.();
      return Boolean(rect && rect.right <= window.innerWidth + 2 && rect.left >= -2);
    }, null, { timeout: 2000 }));

  const state = await page.evaluate(() => {
    const root = document.querySelector("[data-audit-entry-drawer='true']");
    const drawer = root?.closest(".drawer");
    const rect = drawer?.getBoundingClientRect?.();
    const buttons = [...(drawer?.querySelectorAll("button") || [])].map((button) => {
      const b = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        width: b.width,
        height: b.height,
        disabled: button.disabled,
      };
    });
    return {
      hash: location.hash || "",
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      buttons,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });

  if (state.overflow > 2) {
    throw new Error(`audit entry drawer overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const requiredText = [
    "Audit entry",
    "Action",
    entry.action,
    "Actor",
    "Auth source",
    "Entry hash",
    "Previous hash",
    "Integrity",
    "Audit detail",
    "append-only evidence",
  ].filter(Boolean);
  const missingText = requiredText.filter((text) => !state.text.includes(text) && !state.title.includes(text));
  if (missingText.length) {
    throw new Error(`audit entry drawer missing text: ${missingText.join(", ")}`);
  }
  if (!state.buttons.some((button) => button.text === "Copy handoff") || !state.buttons.some((button) => button.text === "Export JSON")) {
    throw new Error(`audit entry drawer missing handoff actions: ${JSON.stringify(state.buttons)}`);
  }
  if (!state.buttons.some((button) => button.text === "Close")) {
    throw new Error(`audit entry drawer missing close action: ${JSON.stringify(state.buttons)}`);
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => !button.disabled && button.text && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`audit entry mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
  await assertChangesAuditHandoffActions(page, viewport, entry);
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/changes", ["entry"]);
}

async function assertChangesAuditReportBuilder(page, viewport) {
  await page.evaluate(() => {
    globalThis.__changesAuditCopiedText = "";
    localStorage.removeItem("phragma.investigation.case.v1");
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__changesAuditCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.click('[data-audit-action="open-report-builder"]');
  await waitForDrawerTitle(page, "Audit report builder");
  let state = await collectAuditReportDrawerState(page);
  assertChangesAuditReportDrawerState(state, viewport, "audit report builder");
  await page.selectOption('#drawer:not([hidden]) [data-audit-compliance-profile]', "change-control");
  state = await collectAuditReportDrawerState(page);
  if (state.profileValue !== "change-control" || !state.text.includes("Change control coverage")) {
    throw new Error(`audit report builder did not switch compliance profile at ${viewport.name}: ${JSON.stringify({ profile: state.profileValue, text: state.text.slice(0, 400) })}`);
  }
  await page.selectOption('#drawer:not([hidden]) [data-audit-compliance-profile]', "operational");
  state = await collectAuditReportDrawerState(page);
  assertChangesAuditReportDrawerState(state, viewport, "audit report builder operational profile");
  await page.click('[data-audit-action="copy-report"]');
  await page.waitForFunction(() => Boolean(globalThis.__changesAuditCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__changesAuditCopiedText || "");
  const copiedPacket = parseAuditReportJson(copied, `changes audit report copy ${viewport.name}`);
  assertChangesAuditReportPacket(copiedPacket, viewport, "copy");
  assertNoInvestigationLeak(copied, `changes audit report copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 15000 });
  const clickedExport = await page.evaluate(() => {
    const button = document.querySelector('[data-audit-action="export-report"]');
    if (!button || button.disabled) return false;
    button.click();
    return true;
  });
  if (!clickedExport) {
    throw new Error(`changes audit report export action was not available at ${viewport.name}`);
  }
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^phragma-audit-report-.+\.json$/.test(filename)) {
    throw new Error(`changes audit report export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`changes audit report export was not readable at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `changes audit report export ${viewport.name}`);
  const exportedPacket = parseAuditReportJson(text, `changes audit report export ${viewport.name}`);
  assertChangesAuditReportPacket(exportedPacket, viewport, "export");
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/changes", ["drawer"]);

  await page.evaluate(() => { location.hash = "#/changes?tab=audit&drawer=report"; });
  await waitForRouteReady(page, "/changes");
  await waitForDrawerTitle(page, "Audit report builder");
  state = await collectAuditReportDrawerState(page);
  assertChangesAuditReportDrawerState(state, viewport, "route-backed audit report builder");
  await page.keyboard.press("Escape");
  await waitForSelectionCleared(page, "/changes", ["drawer"]);
}

async function collectAuditReportDrawerState(page) {
  return await page.evaluate(() => {
    const root = document.querySelector("[data-audit-report-drawer='true']");
    const drawer = root?.closest(".drawer");
    const profile = drawer?.querySelector("[data-audit-compliance-profile]");
    const rect = drawer?.getBoundingClientRect?.();
    const buttons = [...(drawer?.querySelectorAll("button") || [])].map((button) => {
      const b = button.getBoundingClientRect();
      return {
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        action: button.dataset.auditAction || "",
        disabled: button.disabled,
        width: b.width,
        height: b.height,
      };
    });
    return {
      hash: location.hash || "",
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      profileValue: profile?.value || "",
      profileOptions: [...(profile?.querySelectorAll("option") || [])].map((option) => option.value),
      buttons,
      overflow: drawer ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(drawer.scrollWidth - drawer.clientWidth),
      ) : 0,
    };
  });
}

function assertChangesAuditReportDrawerState(state, viewport, label) {
  if (state.overflow > 2) {
    throw new Error(`${label} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  const requiredText = [
    "Audit report builder",
    "Browser-generated compliance report",
    "Operational report only",
    "not signed, server-stored, or retention-enforced",
    "Schema",
    "phragma.audit.report.v1",
    "Compliance profile",
    "Operational",
    "API replay",
    "/v1/audit",
    "GET /v1/audit/verify",
    "CLI replay",
    "ngfwctl audit",
    "--hashes",
    "Integrity",
    "Compliance coverage",
    "Audit chain integrity",
    "Actor attribution",
    "Custody boundary",
    "Included entry hashes",
  ];
  const missing = requiredText.filter((text) => !state.text.includes(text) && !state.title.includes(text));
  if (missing.length) {
    throw new Error(`${label} missing text at ${viewport.name}: ${missing.join(", ")}`);
  }
  for (const option of ["operational", "change-control", "privileged-access", "content-lifecycle", "incident-evidence"]) {
    if (!state.profileOptions.includes(option)) {
      throw new Error(`${label} missing compliance profile option ${option} at ${viewport.name}: ${JSON.stringify(state.profileOptions)}`);
    }
  }
  if (state.profileValue !== "operational") {
    throw new Error(`${label} expected operational profile at ${viewport.name}, got ${state.profileValue || "<empty>"}`);
  }
  for (const action of ["copy-report", "export-report"]) {
    if (!state.buttons.some((button) => button.action === action && !button.disabled)) {
      throw new Error(`${label} missing enabled ${action} action at ${viewport.name}: ${JSON.stringify(state.buttons)}`);
    }
  }
  if (viewport.name === "mobile") {
    const cramped = state.buttons.filter((button) => !button.disabled && button.text && (button.width < 56 || button.height < 34));
    if (cramped.length) {
      throw new Error(`${label} mobile buttons too small: ${cramped.map((button) => `${button.text} ${Math.round(button.width)}x${Math.round(button.height)}`).join(", ")}`);
    }
  }
  assertNoInvestigationLeak(state.text, `${label} drawer ${viewport.name}`);
}

function parseAuditReportJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} was not valid JSON: ${err.message}`);
  }
}

function assertChangesAuditReportPacket(packet, viewport, label) {
  if (packet?.schemaVersion !== "phragma.audit.report.v1" ||
      packet?.source !== "browser-generated" ||
      packet?.unsigned !== true ||
      packet?.custody?.serverStored !== false ||
      packet?.custody?.signed !== false ||
      packet?.request?.method !== "GET" ||
      packet?.request?.path !== "/v1/audit" ||
      !String(packet?.replay?.cli || "").includes("--hashes") ||
      packet?.replay?.verifyApi !== "GET /v1/audit/verify" ||
      packet?.compliance?.scope !== "visible-audit-window" ||
      packet?.compliance?.profile !== "operational" ||
      packet?.compliance?.profileLabel !== "Operational" ||
      !Array.isArray(packet?.compliance?.controls) ||
      !packet.compliance.controls.some((control) => control.id === "audit-integrity") ||
      !packet.compliance.controls.some((control) => control.id === "profile-coverage") ||
      !packet.compliance.controls.some((control) => control.id === "custody-boundary" && control.status === "review") ||
      !Array.isArray(packet?.entryHashes) ||
      !Array.isArray(packet?.entries) ||
      Number(packet?.includedEntryCount || 0) !== packet.entries.length) {
    throw new Error(`changes audit report ${label} had unexpected shape at ${viewport.name}: ${JSON.stringify(packet)}`);
  }
  if (!packet.entries.length || !packet.entryHashes.length) {
    throw new Error(`changes audit report ${label} did not include visible audit hashes at ${viewport.name}: ${JSON.stringify(packet)}`);
  }
  if (!String(packet?.custody?.note || "").includes("Unsigned browser-generated operational report")) {
    throw new Error(`changes audit report ${label} missing custody boundary at ${viewport.name}`);
  }
}

async function assertChangesAuditTable(page, viewport) {
  const state = await page.evaluate(() => {
    const table = document.querySelector(".audit-table");
    const row = table?.querySelector("[data-audit-entry-row]");
    const labels = [...(row?.querySelectorAll("td") || [])].map((cell) => cell.getAttribute("data-label") || "");
    return {
      tableClass: table?.className || "",
      rowKey: row?.getAttribute("data-audit-entry-row") || "",
      rowClass: row?.className || "",
      rowRole: row?.getAttribute("role") || "",
      rowTabindex: row?.getAttribute("tabindex") || "",
      labels,
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      mobileLabelsRendered: window.innerWidth > 820 || [...(row?.querySelectorAll("td") || [])].every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
    };
  });
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes("audit-table")) {
    throw new Error(`changes audit table missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = ["#", "Action", "Detail", "Actor", "Version", "Hash", "Time"].filter((label) => !state.labels.includes(label));
  if (missingLabels.length) {
    throw new Error(`changes audit table missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (!state.rowKey || !state.rowClass.includes("clickable") || state.rowRole !== "button" || state.rowTabindex !== "0") {
    throw new Error(`changes audit table row hook/accessibility mismatch at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (state.overflow > 2) {
    throw new Error(`changes audit table overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`changes audit mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertChangesAuditLogHandoffActions(page, viewport) {
  await page.evaluate(() => {
    globalThis.__changesAuditCopiedText = "";
    localStorage.removeItem("phragma.investigation.case.v1");
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__changesAuditCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.click('[data-audit-action="pin-filtered-log"]');
  const pinned = await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    const data = JSON.parse(raw);
    const item = (data.items || []).find((candidate) => candidate.packet?.kind === "audit-log");
    return {
      hasPacket: Boolean(item),
      title: item?.packet?.title || "",
      includedEntries: Number(item?.packet?.summary?.includedEntries || 0),
      artifactCount: Array.isArray(item?.packet?.artifacts?.auditEntries) ? item.packet.artifacts.auditEntries.length : 0,
      integrityOk: Boolean(item?.packet?.summary?.integrityOk),
      raw,
    };
  });
  if (!pinned.hasPacket || pinned.title !== "Filtered audit log handoff" || pinned.includedEntries < 1 || pinned.artifactCount < 1 || !pinned.integrityOk) {
    throw new Error(`changes audit filtered-log pin missed expected case packet at ${viewport.name}: ${JSON.stringify(pinned)}`);
  }
  assertNoInvestigationLeak(pinned.raw, `changes audit filtered-log pin ${viewport.name}`);

  await page.click('[data-audit-action="copy-filtered-log"]');
  await page.waitForFunction(() => Boolean(globalThis.__changesAuditCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__changesAuditCopiedText || "");
  if (!copied.includes("Filtered audit log handoff") || !copied.includes("kind=audit-log") || !copied.includes("integrityOk=true")) {
    throw new Error(`changes audit filtered-log copy missed expected evidence at ${viewport.name}: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `changes audit filtered-log copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('[data-audit-action="export-filtered-log"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^phragma-investigation-audit-log-.+\.json$/.test(filename)) {
    throw new Error(`changes audit filtered-log export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`changes audit filtered-log export was not readable at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `changes audit filtered-log export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`changes audit filtered-log export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.kind !== "audit-log" || packet?.title !== "Filtered audit log handoff") {
    throw new Error(`changes audit filtered-log export had unexpected identity at ${viewport.name}: ${JSON.stringify({ kind: packet?.kind, title: packet?.title })}`);
  }
  if (!packet?.summary?.includedEntries || !Array.isArray(packet?.artifacts?.auditEntries) || !packet.artifacts.auditEntries.length) {
    throw new Error(`changes audit filtered-log export missed entries at ${viewport.name}: ${JSON.stringify(packet?.summary || {})}`);
  }
}

async function assertChangesAuditHandoffActions(page, viewport, entry = {}) {
  await page.evaluate(() => {
    globalThis.__changesAuditCopiedText = "";
    localStorage.removeItem("phragma.investigation.case.v1");
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__changesAuditCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.click('[data-audit-action="copy-handoff"]');
  await page.waitForFunction(() => Boolean(globalThis.__changesAuditCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__changesAuditCopiedText || "");
  if (!copied.includes("Audit entry handoff") || !copied.includes(entry.action || "")) {
    throw new Error(`changes audit copy missed expected evidence at ${viewport.name}: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `changes audit copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('[data-audit-action="export-handoff"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^phragma-investigation-audit-entry-.+\.json$/.test(filename)) {
    throw new Error(`changes audit export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`changes audit export was not readable at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `changes audit export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`changes audit export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.kind !== "audit-entry" || packet?.title !== "Audit entry handoff") {
    throw new Error(`changes audit export had unexpected identity at ${viewport.name}: ${JSON.stringify({ kind: packet?.kind, title: packet?.title })}`);
  }

  await page.click('[data-audit-action="pin-handoff"]');
  const pinned = await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "{}";
    const data = JSON.parse(raw);
    const item = (data.items || []).find((candidate) => candidate.packet?.kind === "audit-entry");
    return {
      hasPacket: Boolean(item),
      title: item?.packet?.title || "",
      action: item?.packet?.summary?.action || "",
      entryHash: item?.packet?.summary?.entryHash || "",
      raw,
    };
  });
  if (!pinned.hasPacket || pinned.title !== "Audit entry handoff" || pinned.action !== (entry.action || "") || (entry.entryHash && pinned.entryHash !== entry.entryHash)) {
    throw new Error(`changes audit entry pin missed expected case packet at ${viewport.name}: ${JSON.stringify({ pinned, entry })}`);
  }
  assertNoInvestigationLeak(pinned.raw, `changes audit entry pin ${viewport.name}`);
}

async function candidateStatusSnapshot(page) {
  return await page.evaluate(async () => {
    const response = await fetch("/v1/candidate/status");
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { message: text };
    }
    const changes = Array.isArray(body.changes) ? body.changes.map((change) => ({
      section: change.section || "",
      added: Number(change.added || 0),
      modified: Number(change.modified || 0),
      removed: Number(change.removed || 0),
    })).sort((a, b) => a.section.localeCompare(b.section)) : [];
    return {
      status: response.status,
      hasCandidate: Boolean(body.hasCandidate || body.has_candidate),
      dirty: Boolean(body.dirty),
      runningVersion: String(body.runningVersion || body.running_version || ""),
      changeCount: Number(body.changeCount || body.change_count || 0),
      changes,
    };
  });
}

async function assertSettingsAccessPosture(page, viewport) {
  const posture = await page.evaluate(() => {
    const visible = (el) => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
    };
    return [...document.querySelectorAll("[data-access-posture-item]")]
      .filter(visible)
      .map((el) => {
        const rect = el.getBoundingClientRect();
        return {
          id: el.getAttribute("data-access-posture-item") || "",
          text: el.textContent || "",
          width: rect.width,
          height: rect.height,
        };
      });
  });
  const ids = new Set(posture.map((item) => item.id));
  const required = ["runtime-auth", "browser-sso", "session", "mutation-guard"];
  const missing = required.filter((id) => !ids.has(id));
  if (missing.length) {
    throw new Error(`settings access posture missing item(s): ${missing.join(", ")}`);
  }
  if (!posture.some((item) => /CSRF|token scoped|after sign-in/.test(item.text))) {
    throw new Error("settings access posture did not describe the mutation guard");
  }
  if (viewport.name === "mobile") {
    const cramped = posture.filter((item) => item.width < 150 || item.height < 52);
    if (cramped.length) {
      throw new Error(`mobile settings access posture rows too small: ${cramped.map((item) => `${item.id} ${Math.round(item.width)}x${Math.round(item.height)}`).join(", ")}`);
    }
  }
}

async function assertSettingsAccessLifecycle(page, viewport) {
  await page.evaluate(() => {
    location.hash = "#/settings?panel=access";
  });
  await runSmokeStep("settings access route activation", () => waitForRouteReady(page, "/settings"));
  await runSmokeStep("settings access panel activation", () => page.waitForSelector("#settings-panel-access.active", { timeout: 10000 }));
  await assertSettingsResponsiveTable(page, viewport, "access", ".settings-access-inventory-table", ["Posture", "State"]);
  await assertSettingsResponsiveTable(page, viewport, "access", ".settings-access-governance-table", ["Workflow", "Required role", "Viewer", "Operator", "Admin", "Current", "Audit"]);
  await assertSettingsResponsiveTable(page, viewport, "access", ".settings-access-role-preview-table", ["Role", "Allowed workflows", "Restricted workflows"]);
  await assertSettingsAccessGovernanceAuditLinks(page, viewport);
  await assertSettingsAccessAutomationContext(page, viewport);
  await runSmokeStep("settings access create action visible", () => page.waitForSelector('[data-access-action="create-local-user"]', { timeout: 10000 }));
  await assertSettingsAccessActionButtonA11y(page, viewport, "[data-settings-panel='access']");
  await page.click('[data-access-action="access-lifecycle-review"]');
  await waitForDrawerTitleStep(page, "Access lifecycle review", "settings access lifecycle review drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])");
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await assertSettingsOIDCRolloutWorkflow(page, viewport);
  await assertSettingsSAMLRolloutWorkflow(page, viewport);
  await assertSettingsAccessSessionRevocation(page, viewport);

  const user = `visual-access-${viewport.name}`;
  await page.click('[data-access-action="create-local-user"]');
  await waitForDrawerTitleStep(page, "Create local user", "settings access create drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="create-local-user"]'] });
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-name"]', user);
  await page.selectOption('#drawer:not([hidden]) [data-access-field="local-user-role"]', "operator");
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke create ${viewport.name}`);
  await clickDrawerFooterButton(page, "Create");
  await waitForDrawerTitleStep(page, "Local user created", "settings access create submit");
  const createdToken = await collectOneTimeAccessToken(page, viewport, "create");
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await runSmokeStep("settings access created user row refresh", () => waitForLocalUserRow(page, user, { role: "operator", enabled: true }));
  await assertAccessIdentity(page, createdToken, { actor: user, role: "operator", label: "created local user token" });
  await assertAccessInventoryDoesNotLeakTokens(page, [createdToken], viewport, "after create");

  await clickLocalUserAction(page, user, "update-local-user", viewport);
  await waitForDrawerTitleStep(page, `Change role: ${user}`, "settings access update drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="update-local-user"]'] });
  await page.selectOption('#drawer:not([hidden]) [data-access-field="local-user-role"]', "viewer");
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke reduce role ${viewport.name}`);
  await clickDrawerFooterButton(page, "Update");
  await waitForDrawerClosed(page);
  await runSmokeStep("settings access updated user row refresh", () => waitForLocalUserRow(page, user, { role: "viewer", enabled: true }));
  await assertAccessIdentity(page, createdToken, { actor: user, role: "viewer", label: "role-updated local user token" });

  await clickLocalUserAction(page, user, "rotate-local-user", viewport);
  await waitForDrawerTitleStep(page, `Rotate token: ${user}`, "settings access rotate drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="rotate-local-user"]'] });
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke rotate ${viewport.name}`);
  await clickDrawerFooterButton(page, "Rotate");
  await waitForDrawerTitleStep(page, "Token rotated", "settings access rotate submit");
  const rotatedToken = await collectOneTimeAccessToken(page, viewport, "rotate");
  if (rotatedToken === createdToken) {
    throw new Error(`settings access rotate returned the original token at ${viewport.name}`);
  }
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await assertAccessTokenRejected(page, createdToken, "pre-rotation local user token");
  await assertAccessIdentity(page, rotatedToken, { actor: user, role: "viewer", label: "rotated local user token" });
  await assertAccessInventoryDoesNotLeakTokens(page, [createdToken, rotatedToken], viewport, "after rotate");

  await clickLocalUserAction(page, user, "disable-local-user", viewport);
  await waitForDrawerTitleStep(page, `Disable user: ${user}`, "settings access disable drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="disable-local-user"]'] });
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke disable ${viewport.name}`);
  await clickDrawerFooterButton(page, "Disable");
  await waitForDrawerTitleStep(page, "Disable local user?", "settings access disable confirm");
  await clickDrawerFooterButton(page, "Disable");
  await runSmokeStep("settings access disabled user row refresh", () => waitForLocalUserRow(page, user, { role: "viewer", enabled: false }));
  await assertAccessTokenRejected(page, rotatedToken, "disabled local user token");
  await assertAccessInventoryDoesNotLeakTokens(page, [createdToken, rotatedToken], viewport, "after disable");
  await assertSettingsBreakGlassRotationWorkflow(page, viewport, [createdToken, rotatedToken]);
}

async function assertSettingsAccessSessionRevocation(page, viewport) {
  const sessionId = "oidc-session-sha256:" + "a".repeat(64);
  const sessionFingerprint = "oidc-session-sha256:aaaaaaaaaaaa...aaaaaaaa";
  const rawTokenSentinel = "visual-session-raw-token";
  let revoked = false;
  let revokeCalls = 0;
  const sessionPayload = () => ({
    authEnabled: true,
    localUsers: [
      {
        name: "visual-smoke-admin",
        role: "admin",
        enabled: true,
        editable: false,
        tokenHash: "inventory-sha256:" + "b".repeat(64),
        detail: rawTokenSentinel,
      },
    ],
    oidc: {
      enabled: true,
      issuer: "https://idp.example.com",
      clientId: "phragma-webui",
      roleClaim: "groups",
      defaultRole: "viewer",
      cookieSecure: true,
      scopes: ["openid", "profile", "email"],
      trustedProxyCidrs: ["10.0.0.0/8"],
      sessionTtlSeconds: 28800,
    },
    saml: {
      enabled: false,
      runtimeAvailable: false,
      detail: "SAML is not configured for this visual-smoke session revoke proof.",
    },
    sessions: {
      oidcActiveSessions: revoked ? 0 : 1,
      oidcMaxSessions: 20,
      sessionRevocationAvailable: true,
      detail: "Admins can revoke active browser SSO sessions.",
      activeSessions: revoked ? [] : [
        {
          sessionId,
          actor: "visual-session-admin@example.com",
          role: "admin",
          authSource: "oidc-session",
          expiresAt: "2026-06-18T12:00:00Z",
          secondsUntilExpiry: 3600,
        },
      ],
    },
    breakGlass: {
      state: "ready",
      detail: "Local break-glass admin exists.",
      nextAction: "Rotate on the approved schedule.",
    },
    blockers: [],
  });
  const accessRoute = "**/v1/system/access-administration";
  const revokeRoute = "**/v1/system/access-administration/sessions/*:revoke";
  const fulfillJSON = async (route, body) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
  await page.route(accessRoute, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    return fulfillJSON(route, sessionPayload());
  });
  await page.route(revokeRoute, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const url = route.request().url();
    if (!url.includes(encodeURIComponent(sessionId))) {
      throw new Error(`settings access revoke used unexpected session URL at ${viewport.name}: ${url}`);
    }
    revokeCalls += 1;
    revoked = true;
    return fulfillJSON(route, {
      revoked: true,
      session: {
        sessionId,
        actor: "visual-session-admin@example.com",
        role: "admin",
        authSource: "oidc-session",
        expiresAt: "2026-06-18T12:00:00Z",
        secondsUntilExpiry: 3600,
      },
      detail: "visual-session-admin@example.com session revoked.",
    });
  });
  try {
    await page.evaluate(() => {
      location.hash = "#/settings?panel=access";
    });
    await runSmokeStep("settings access session revoke route activation", () => waitForRouteReady(page, "/settings"));
    await runSmokeStep("settings access session revoke panel activation", () => page.waitForSelector("#settings-panel-access.active", { timeout: 10000 }));
    const revokeSelector = `[data-access-action="revoke-session"][data-access-session="${sessionFingerprint}"]`;
    await runSmokeStep("settings access revoke session action visible", () => page.waitForSelector(revokeSelector, { timeout: 10000 }));
    await page.click(revokeSelector);
    await waitForDrawerTitleStep(page, "Revoke browser SSO session?", "settings access revoke session confirm");
    await clickDrawerFooterButton(page, "Revoke session");
    await runSmokeStep("settings access revoked session inventory refresh", async () => {
      await page.waitForSelector("text=No active browser SSO sessions reported.", { timeout: 10000 });
      await page.waitForFunction((selector) => !document.querySelector(selector), revokeSelector, { timeout: 10000 });
    });
    if (revokeCalls !== 1) {
      throw new Error(`settings access session revoke made ${revokeCalls} API call(s) at ${viewport.name}`);
    }
    const visibleText = await page.locator("#content").innerText();
    if (visibleText.includes(rawTokenSentinel) || visibleText.includes(sessionId)) {
      throw new Error(`settings access session revoke leaked raw session data at ${viewport.name}`);
    }
  } finally {
    await page.unroute(accessRoute);
    await page.unroute(revokeRoute);
    if (!await page.locator("#drawer:not([hidden])").count().then(Boolean).catch(() => false)) {
      return;
    }
    await clickDrawerFooterButton(page, "Cancel").catch(async () => {
      await clickDrawerFooterButton(page, "Close").catch(() => {});
    });
    await waitForDrawerClosed(page).catch(() => {});
  }
}

async function assertSettingsAccessAutomationContext(page, viewport) {
  const copied = await assertAutomationContextDrawer(page, viewport, "settings access automation context", [
    "#/settings?panel=access",
    "panel = access",
    "/v1/system/identity",
    "/v1/system/access-administration",
    "/v1/system/access-administration/oidc/config",
    "/v1/system/access-administration/oidc/config:disable",
    "/v1/system/access-administration/saml/config",
    "/v1/system/access-administration/sessions/{sessionId}:revoke",
    "/v1/audit?action=access-saml-provider-set&limit=300",
    "ngfwctl whoami",
    "ngfwctl access users list",
    "ngfwctl access oidc provider validate",
    "ngfwctl access saml provider validate",
    "ngfwctl access sessions revoke <session-id> --ack-revoke-session",
    "ngfwctl audit --action access-saml-provider-set --hashes",
  ]);
  for (const required of [
    "GET /v1/system/identity",
    "GET /v1/system/access-administration",
    "PUT /v1/system/access-administration/oidc/config",
    "POST /v1/system/access-administration/oidc/config:disable",
    "PUT /v1/system/access-administration/saml/config",
    "POST /v1/system/access-administration/sessions/{sessionId}:revoke",
    "GET /v1/audit?action=access-saml-provider-set&limit=300",
  ]) {
    if (!copied.includes(required)) {
      throw new Error(`settings access automation copied context missing ${required} at ${viewport.name}`);
    }
  }
}

async function assertSettingsAccessGovernanceAuditLinks(page, viewport) {
  const state = await page.evaluate(() => {
    const table = document.querySelector(".settings-access-governance-table");
    const links = [...(table?.querySelectorAll("a[href]") || [])].map((link) => ({
      text: (link.textContent || "").replace(/\s+/g, " ").trim(),
      href: link.getAttribute("href") || "",
    }));
    return {
      text: (table?.textContent || "").replace(/\s+/g, " ").trim(),
      links,
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
    };
  });
  if (!state.text.includes("Saml Provider Set") || !state.text.includes("Saml Provider Disable")) {
    throw new Error(`settings access governance table missing SAML audit labels at ${viewport.name}: ${state.text}`);
  }
  for (const href of [
    "#/changes?tab=audit&action=access-saml-provider-set&limit=300",
    "#/changes?tab=audit&action=access-saml-provider-disable&limit=300",
  ]) {
    if (!state.links.some((link) => link.href === href)) {
      throw new Error(`settings access governance table missing audit link ${href} at ${viewport.name}: ${JSON.stringify(state.links)}`);
    }
  }
  if (state.overflow > 2) {
    throw new Error(`settings access governance audit links overflow at ${viewport.name}: ${state.overflow}px`);
  }
}

async function assertSettingsBreakGlassRotationWorkflow(page, viewport, priorTokens = []) {
  const user = `visual-breakglass-${viewport.name}`;
  await runSmokeStep("settings break-glass panel visible", () => page.waitForSelector('[data-access-breakglass-panel="true"]', { timeout: 10000 }));
  await page.click('[data-access-action="create-breakglass-admin"]');
  await waitForDrawerTitleStep(page, "Create break-glass admin", "settings break-glass create drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="create-breakglass-admin"]'] });
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-name"]', user);
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke create break-glass ${viewport.name}`);
  await clickDrawerFooterButton(page, "Create admin");
  await waitForDrawerTitleStep(page, "Break-glass admin created", "settings break-glass create submit");
  const createdToken = await collectOneTimeAccessToken(page, viewport, "break-glass create");
  await assertBreakGlassEvidenceActions(page, viewport, "create", [createdToken, ...priorTokens]);
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await runSmokeStep("settings break-glass admin row refresh", () => waitForLocalUserRow(page, user, { role: "admin", enabled: true }));
  await assertAccessIdentity(page, createdToken, { actor: user, role: "admin", label: "break-glass local admin token" });
  await assertAccessInventoryDoesNotLeakTokens(page, [createdToken, ...priorTokens], viewport, "after break-glass create");

  await page.selectOption('[data-access-field="breakglass-user"]', user);
  await page.click('[data-access-action="rotate-breakglass"]');
  await waitForDrawerTitleStep(page, `Rotate break-glass: ${user}`, "settings break-glass rotate drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", { required: ['[data-access-submit="rotate-breakglass"]'] });
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke rotate break-glass ${viewport.name}`);
  await clickDrawerFooterButton(page, "Rotate break-glass");
  await waitForDrawerTitleStep(page, "Break-glass token rotated", "settings break-glass rotate submit");
  const rotatedToken = await collectOneTimeAccessToken(page, viewport, "break-glass rotate");
  if (rotatedToken === createdToken) {
    throw new Error(`settings break-glass rotation returned the original token at ${viewport.name}`);
  }
  await assertBreakGlassEvidenceActions(page, viewport, "rotate", [createdToken, rotatedToken, ...priorTokens]);
  await clickDrawerFooterButton(page, "Close");
  await waitForDrawerClosed(page);
  await assertAccessTokenRejected(page, createdToken, "pre-rotation break-glass token");
  await assertAccessIdentity(page, rotatedToken, { actor: user, role: "admin", label: "rotated break-glass token" });
  await assertAccessInventoryDoesNotLeakTokens(page, [createdToken, rotatedToken, ...priorTokens], viewport, "after break-glass rotate");

  await clickLocalUserAction(page, user, "disable-local-user", viewport);
  await waitForDrawerTitleStep(page, `Disable user: ${user}`, "settings break-glass disable drawer open");
  await page.fill('#drawer:not([hidden]) [data-access-field="local-user-comment"]', `visual smoke disable break-glass ${viewport.name}`);
  await clickDrawerFooterButton(page, "Disable");
  await waitForDrawerTitleStep(page, "Disable local user?", "settings break-glass disable confirm");
  await clickDrawerFooterButton(page, "Disable");
  await runSmokeStep("settings break-glass disabled row refresh", () => waitForLocalUserRow(page, user, { role: "admin", enabled: false }));
  await assertAccessTokenRejected(page, rotatedToken, "disabled break-glass token");
}

async function assertSettingsOIDCRolloutWorkflow(page, viewport) {
  if (!oidcSmokeIssuer || !oidcSmokeSecretFile) {
    throw new Error("OIDC smoke provider was not initialized");
  }
  const viewportSlug = viewport.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const oidcClientId = `phragma-web-${viewportSlug || "viewport"}`;
  const oidcRedirectUrl = "http://127.0.0.1/v1/auth/oidc/callback";
  await forceDisableOIDCProviderForSmoke(page, viewport, "before OIDC rollout");
  await page.click('[data-access-action="configure-oidc"]');
  await waitForDrawerTitleStep(page, "Configure OIDC", "settings OIDC rollout drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: ['[data-access-action="close-oidc-rollout"]', '[data-access-submit="validate-oidc"]', '[data-access-submit="save-oidc-provider"]'],
  });
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-issuer"]', oidcSmokeIssuer);
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-client-id"]', oidcClientId);
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-redirect-url"]', oidcRedirectUrl);
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-role-claim"]', "groups");
  await page.selectOption('#drawer:not([hidden]) [data-access-field="oidc-default-role"]', "viewer");
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-scopes"]', "openid,profile,email");
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-trusted-proxy-cidrs"]', "10.0.0.0/8");
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-client-secret-file"]', oidcSmokeSecretFile);
  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-audit-comment"]', `visual smoke save oidc ${viewport.name}`);
  await page.click('#drawer:not([hidden]) [data-access-submit="validate-oidc"]');
  await page.waitForFunction(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const text = (drawer?.textContent || "").replace(/\s+/g, " ").trim();
    return /OIDC rollout: (ready|[0-9]+ review item)/.test(text) &&
      text.includes("Break-glass") &&
      text.includes("Activation command") &&
      text.includes("controld --oidc-issuer");
  }, null, { timeout: 5000 });
  await assertDrawerResponsiveTable(page, viewport, ".settings-oidc-preflight-table", ["Check", "State", "Detail", "Evidence", "Next action"], "settings OIDC rollout preflight");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: [
      '[data-access-action="copy-oidc-rollout"]',
      '[data-access-action="export-oidc-rollout"]',
      '[data-access-action="pin-oidc-rollout"]',
      '[data-access-submit="save-oidc-provider"]',
      '[data-access-action="close-oidc-rollout"]',
    ],
  });
  const visible = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return (drawer?.textContent || "").replace(/\s+/g, " ").trim();
  });
  assertNoInvestigationLeak(visible, `settings OIDC rollout visible ${viewport.name}`);

  await page.evaluate(() => {
    globalThis.__settingsOIDCRolloutCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__settingsOIDCRolloutCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.click('#drawer:not([hidden]) [data-access-action="copy-oidc-rollout"]');
  await page.waitForFunction(() => Boolean(globalThis.__settingsOIDCRolloutCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__settingsOIDCRolloutCopiedText || "");
  if (!/OIDC rollout plan: (ready|review)/.test(copied) || !copied.includes("break_glass_local_admins=")) {
    throw new Error(`settings OIDC rollout copy missed expected evidence at ${viewport.name}: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `settings OIDC rollout copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('#drawer:not([hidden]) [data-access-action="export-oidc-rollout"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^openngfw-oidc-rollout-.+\.json$/.test(filename)) {
    throw new Error(`settings OIDC rollout export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`settings OIDC rollout export was not readable at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `settings OIDC rollout export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`settings OIDC rollout export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.schemaVersion !== "openngfw.oidc-rollout.v1" || !["ready", "review"].includes(packet?.state) || !packet?.breakGlassReady) {
    throw new Error(`settings OIDC rollout export had unexpected packet at ${viewport.name}: ${JSON.stringify({ schemaVersion: packet?.schemaVersion, state: packet?.state, breakGlassReady: packet?.breakGlassReady })}`);
  }
  await page.click('#drawer:not([hidden]) [data-access-action="pin-oidc-rollout"]');
  const pinned = await page.evaluate(() => {
    try {
      return localStorage.getItem("phragma.investigation.case.v1") || "";
    } catch {
      return "";
    }
  });
  if (!pinned.includes("oidc-rollout") || !pinned.includes("openngfw.oidc-rollout.v1")) {
    throw new Error(`settings OIDC rollout pin did not reach investigation case at ${viewport.name}: ${pinned}`);
  }
  assertNoInvestigationLeak(pinned, `settings OIDC rollout pin ${viewport.name}`);

	await clickDrawerFooterButton(page, "Save provider");
	await page.waitForFunction(async ({ issuer, clientId }) => {
		try {
			const response = await fetch("/v1/system/access-administration/oidc/config");
			const body = await response.json();
			return response.ok && body?.config?.enabled && body.config.issuer === issuer && body.config.clientId === clientId;
    } catch {
      return false;
    }
	}, { issuer: oidcSmokeIssuer, clientId: oidcClientId }, { timeout: 45000 });
	await waitForDrawerClosed(page);
  const saved = await page.evaluate(async () => {
    const response = await fetch("/v1/system/access-administration/oidc/config");
    let body = null;
    try {
      body = await response.json();
    } catch {}
    return { ok: response.ok, body };
  });
  if (!saved.ok || !saved.body?.config?.enabled || saved.body.config.issuer !== oidcSmokeIssuer || saved.body.config.clientId !== oidcClientId || saved.body.config.redirectUrl !== oidcRedirectUrl) {
    const saveUiState = await page.evaluate(() => ({
      drawer: (document.querySelector("#drawer:not([hidden])")?.textContent || "").replace(/\s+/g, " ").trim(),
      toasts: (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    throw new Error(`settings OIDC provider save did not persist expected config at ${viewport.name}: ${JSON.stringify({ saved, saveUiState })}`);
  }
  if (saved.body.config.clientSecretFile || !saved.body.config.clientSecretFileConfigured || JSON.stringify(saved.body).includes(oidcSmokeSecretFile)) {
    throw new Error(`settings OIDC provider save leaked or missed secret-file posture at ${viewport.name}: ${JSON.stringify(saved.body.config)}`);
  }

	await waitForDrawerClosed(page);
	await page.waitForSelector('[data-access-action="configure-oidc"]', { timeout: 10000 });
  await page.click('[data-access-action="configure-oidc"]');
  await waitForDrawerTitleStep(page, "Configure OIDC", "settings OIDC rollout drawer reopen after save");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: [
      '[data-access-submit="validate-oidc"]',
      '[data-access-submit="save-oidc-provider"]',
      '[data-access-action="disable-oidc-provider"]',
      '[data-access-action="close-oidc-rollout"]',
    ],
  });
  const prefill = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const value = (field) => drawer?.querySelector(`[data-access-field="${field}"]`)?.value || "";
    return {
      issuer: value("oidc-issuer"),
      clientId: value("oidc-client-id"),
      redirectUrl: value("oidc-redirect-url"),
      roleClaim: value("oidc-role-claim"),
      defaultRole: value("oidc-default-role"),
      scopes: value("oidc-scopes"),
      trustedProxyCidrs: value("oidc-trusted-proxy-cidrs"),
      secretValue: value("oidc-client-secret-file"),
      secretPlaceholder: drawer?.querySelector('[data-access-field="oidc-client-secret-file"]')?.getAttribute("placeholder") || "",
      disableVisible: Boolean(drawer?.querySelector('[data-access-action="disable-oidc-provider"]')),
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  });
  const expectedPrefill = {
    issuer: oidcSmokeIssuer,
    clientId: oidcClientId,
    redirectUrl: oidcRedirectUrl,
    roleClaim: "groups",
    defaultRole: "viewer",
    scopes: "openid,profile,email",
    trustedProxyCidrs: "10.0.0.0/8",
  };
  for (const [key, value] of Object.entries(expectedPrefill)) {
    if (prefill[key] !== value) {
      throw new Error(`settings OIDC provider prefill ${key} mismatch at ${viewport.name}: ${JSON.stringify(prefill)}`);
    }
  }
  if (prefill.secretValue || !prefill.secretPlaceholder.includes("configured") || !prefill.disableVisible || prefill.text.includes(oidcSmokeSecretFile)) {
    throw new Error(`settings OIDC provider reopen missed redacted secret posture or disable control at ${viewport.name}: ${JSON.stringify(prefill)}`);
  }

  await page.fill('#drawer:not([hidden]) [data-access-field="oidc-audit-comment"]', `visual smoke disable oidc ${viewport.name}`);
  await page.click('#drawer:not([hidden]) [data-access-action="disable-oidc-provider"]');
  await waitForDrawerTitleStep(page, "Disable OIDC provider?", "settings OIDC disable confirm");
  await clickDrawerFooterButton(page, "Disable OIDC");
  await waitForDrawerClosed(page);
  const disabled = await waitForOIDCProviderDisabled(page, viewport, "after OIDC disable");
  if (disabled.configStatus !== 200 || disabled.config?.enabled !== false) {
    throw new Error(`settings OIDC provider disable did not persist at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  if (disabled.administrationOidc?.enabled !== false || disabled.administrationOidc?.clientId === oidcClientId) {
    throw new Error(`settings OIDC access administration did not refresh disabled provider at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  await page.click('[data-access-action="configure-oidc"]');
  await waitForDrawerTitleStep(page, "Configure OIDC", "settings OIDC rollout drawer reopen after disable");
  const disabledPrefill = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const value = (field) => drawer?.querySelector(`[data-access-field="${field}"]`)?.value || "";
    return {
      issuer: value("oidc-issuer"),
      clientId: value("oidc-client-id"),
      redirectUrl: value("oidc-redirect-url"),
      disableVisible: Boolean(drawer?.querySelector('[data-access-action="disable-oidc-provider"]')),
      secretPlaceholder: drawer?.querySelector('[data-access-field="oidc-client-secret-file"]')?.getAttribute("placeholder") || "",
    };
  });
  if (disabledPrefill.issuer || disabledPrefill.clientId || disabledPrefill.redirectUrl || disabledPrefill.disableVisible || /configured/i.test(disabledPrefill.secretPlaceholder)) {
    throw new Error(`settings OIDC provider disable left stale drawer prefill at ${viewport.name}: ${JSON.stringify(disabledPrefill)}`);
  }
  await page.click('#drawer:not([hidden]) [aria-label="Close dialog"]');
  await waitForDrawerClosed(page);
}

async function assertOIDCProviderDisabled(page, viewport, label) {
  const state = await oidcProviderLifecycleState(page);
  if (state.configStatus !== 200 || state.config?.enabled !== false || state.administrationStatus !== 200 || state.administrationOidc?.enabled !== false) {
    throw new Error(`settings OIDC provider was not disabled ${label} at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function forceDisableOIDCProviderForSmoke(page, viewport, label) {
	const state = await oidcProviderLifecycleState(page);
	if (state.configStatus === 200 && state.config?.enabled === false && state.administrationStatus === 200 && state.administrationOidc?.enabled === false) {
		return state;
	}
	const disabled = await page.evaluate(async ({ token, comment }) => {
		const stepUp = await fetch("/v1/system/access-administration/step-up", {
			method: "POST",
			headers: {
				...(token ? { "Authorization": `Bearer ${token}` } : {}),
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ action: "access-oidc-disable", comment, ackStepUp: true }),
		});
		if (!stepUp.ok) {
			return { ok: false, status: stepUp.status, body: { message: await stepUp.text() } };
		}
		const stepUpBody = await stepUp.json();
		const response = await fetch("/v1/system/access-administration/oidc/config:disable", {
			method: "POST",
			headers: {
				"Authorization": `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ comment, ackDisableOidc: true, stepUpToken: stepUpBody?.token || "" }),
		});
    let body = null;
    try {
      body = await response.json();
    } catch {}
    return { ok: response.ok, status: response.status, body };
  }, { token: smokeAdminToken, comment: `visual smoke OIDC cleanup ${viewport.name} ${label}` });
  if (!disabled.ok) {
    throw new Error(`settings OIDC provider cleanup failed ${label} at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  return await waitForOIDCProviderDisabled(page, viewport, label);
}

async function waitForOIDCProviderDisabled(page, viewport, label) {
  const deadline = Date.now() + 10000;
  let stableSamples = 0;
  let state = null;
  while (Date.now() < deadline) {
    state = await oidcProviderLifecycleState(page);
    if (state.configStatus === 200 &&
        state.config?.enabled === false &&
        state.administrationStatus === 200 &&
        state.administrationOidc?.enabled === false) {
      stableSamples += 1;
      if (stableSamples >= 3) return state;
    } else {
      stableSamples = 0;
    }
    await page.waitForTimeout(250);
  }
  throw new Error(`settings OIDC provider did not become disabled ${label} at ${viewport.name}: state=${JSON.stringify(state)}`);
}

async function oidcProviderLifecycleState(page) {
  return await page.evaluate(async () => {
    const readJSON = async (url) => {
      const response = await fetch(url);
      let body = null;
      try {
        body = await response.json();
      } catch {}
      return { status: response.status, body };
    };
    const [config, administration] = await Promise.all([
      readJSON("/v1/system/access-administration/oidc/config"),
      readJSON("/v1/system/access-administration"),
    ]);
    return {
      configStatus: config.status,
      config: config.body?.config || null,
      administrationStatus: administration.status,
      administrationOidc: administration.body?.oidc || null,
    };
  });
}

async function forceDisableSAMLProviderForSmoke(page, viewport, label) {
  const state = await samlProviderLifecycleState(page);
  if (state.configStatus === 200 && state.config?.enabled === false && state.administrationStatus === 200 && state.administrationSaml?.enabled === false) {
    return state;
  }
  const disabled = await page.evaluate(async ({ token, comment }) => {
    const stepUp = await fetch("/v1/system/access-administration/step-up", {
      method: "POST",
      headers: {
        ...(token ? { "Authorization": `Bearer ${token}` } : {}),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ action: "access-saml-disable", comment, ackStepUp: true }),
    });
    if (!stepUp.ok) {
      return { ok: false, status: stepUp.status, body: { message: await stepUp.text() } };
    }
    const stepUpBody = await stepUp.json();
    const response = await fetch("/v1/system/access-administration/saml/config:disable", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ comment, ackDisableSaml: true, stepUpToken: stepUpBody?.token || "" }),
    });
    let body = null;
    try {
      body = await response.json();
    } catch {}
    return { ok: response.ok, status: response.status, body };
  }, { token: smokeAdminToken, comment: `visual smoke SAML cleanup ${viewport.name} ${label}` });
  if (!disabled.ok) {
    throw new Error(`settings SAML provider cleanup failed ${label} at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  return await waitForSAMLProviderDisabled(page, viewport, label);
}

async function waitForSAMLProviderDisabled(page, viewport, label) {
  const deadline = Date.now() + 10000;
  let stableSamples = 0;
  let state = null;
  while (Date.now() < deadline) {
    state = await samlProviderLifecycleState(page);
    if (state.configStatus === 200 &&
        state.config?.enabled === false &&
        state.administrationStatus === 200 &&
        state.administrationSaml?.enabled === false) {
      stableSamples += 1;
      if (stableSamples >= 3) return state;
    } else {
      stableSamples = 0;
    }
    await page.waitForTimeout(250);
  }
  throw new Error(`settings SAML provider did not become disabled ${label} at ${viewport.name}: state=${JSON.stringify(state)}`);
}

async function samlProviderLifecycleState(page) {
  return await page.evaluate(async () => {
    const readJSON = async (url) => {
      const response = await fetch(url);
      let body = null;
      try {
        body = await response.json();
      } catch {}
      return { status: response.status, body };
    };
    const [config, administration] = await Promise.all([
      readJSON("/v1/system/access-administration/saml/config"),
      readJSON("/v1/system/access-administration"),
    ]);
    return {
      configStatus: config.status,
      config: config.body?.config || null,
      administrationStatus: administration.status,
      administrationSaml: administration.body?.saml || null,
    };
  });
}

async function assertSettingsSAMLRolloutWorkflow(page, viewport) {
  await forceDisableSAMLProviderForSmoke(page, viewport, "before SAML rollout");
  await page.click('[data-access-action="prepare-saml"]');
  await waitForDrawerTitleStep(page, "Prepare SAML", "settings SAML rollout drawer open");
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: ['[data-access-action="close-saml-rollout"]', '[data-access-submit="validate-saml"]', '[data-access-submit="save-saml-provider"]'],
  });
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-idp-entity-id"]', "https://idp.example.com/saml");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-metadata-url"]', "");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-sso-url"]', "https://idp.example.com/sso");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-sp-entity-id"]', "https://firewall.example.com/ui");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-acs-url"]', "https://firewall.example.com/v1/auth/saml/acs");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-role-attribute"]', "groups");
  await page.selectOption('#drawer:not([hidden]) [data-access-field="saml-default-role"]', "viewer");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-certificate-fingerprint"]', "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  await page.fill('#drawer:not([hidden]) [data-access-field="saml-audit-comment"]', `visual smoke save saml ${viewport.name}`);
  await page.click('#drawer:not([hidden]) [data-access-submit="validate-saml"]');
  await page.waitForFunction(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const text = (drawer?.textContent || "").replace(/\s+/g, " ").trim();
    return text.includes("SAML rollout:") &&
      text.includes("Server validation:") &&
      text.includes("SAML runtime") &&
      Boolean(drawer?.querySelector('[data-access-saml-rollout-state="ready"]')) &&
      Array.from(drawer?.querySelectorAll("button") || []).some((button) => button.textContent.includes("Test SAML login") || button.textContent.includes("Runtime inactive"));
  }, null, { timeout: 5000 });
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: [
      '[data-access-action="copy-saml-rollout"]',
      '[data-access-action="export-saml-rollout"]',
      '[data-access-action="pin-saml-rollout"]',
      '[data-access-submit="save-saml-provider"]',
      '[data-access-action="close-saml-rollout"]',
    ],
  });
  const visible = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return (drawer?.textContent || "").replace(/\s+/g, " ").trim();
  });
  assertNoInvestigationLeak(visible, `settings SAML rollout visible ${viewport.name}`);

  await page.evaluate(() => {
    globalThis.__settingsSAMLRolloutCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__settingsSAMLRolloutCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await page.click('#drawer:not([hidden]) [data-access-action="copy-saml-rollout"]');
  await page.waitForFunction(() => Boolean(globalThis.__settingsSAMLRolloutCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__settingsSAMLRolloutCopiedText || "");
  if (!copied.includes("SAML rollout plan: ready") || !copied.includes("Planned validation command") || !copied.includes("acs_url=https://firewall.example.com/v1/auth/saml/acs")) {
    throw new Error(`settings SAML rollout copy missed expected evidence at ${viewport.name}: ${copied}`);
  }
  assertNoInvestigationLeak(copied, `settings SAML rollout copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 15000 });
  await page.click('#drawer:not([hidden]) [data-access-action="export-saml-rollout"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename() || "";
  if (!/^openngfw-saml-rollout-.+\.json$/.test(filename)) {
    throw new Error(`settings SAML rollout export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`settings SAML rollout export was not readable at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertNoInvestigationLeak(text, `settings SAML rollout export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`settings SAML rollout export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet?.schemaVersion !== "openngfw.saml-rollout.v1" || packet?.state !== "ready") {
    throw new Error(`settings SAML rollout export had unexpected packet at ${viewport.name}: ${JSON.stringify({ schemaVersion: packet?.schemaVersion, state: packet?.state })}`);
  }

  await page.click('#drawer:not([hidden]) [data-access-action="pin-saml-rollout"]');
  const pinned = await page.evaluate(() => {
    try {
      return localStorage.getItem("phragma.investigation.case.v1") || "";
    } catch {
      return "";
    }
  });
  if (!pinned.includes("saml-rollout") || !pinned.includes("openngfw.saml-rollout.v1")) {
    throw new Error(`settings SAML rollout pin did not reach investigation case at ${viewport.name}: ${pinned}`);
  }
  assertNoInvestigationLeak(pinned, `settings SAML rollout pin ${viewport.name}`);

		await page.click('#drawer:not([hidden]) [data-access-submit="save-saml-provider"]');
		await page.waitForFunction(() => {
			const toastText = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
			if (/SAML save failed/i.test(toastText)) throw new Error(toastText);
			return !document.querySelector("#drawer:not([hidden])");
	  }, null, { timeout: 25000 });
		await page.waitForFunction(async () => {
			try {
				const [configResponse, administrationResponse] = await Promise.all([
					fetch("/v1/system/access-administration/saml/config"),
					fetch("/v1/system/access-administration"),
				]);
				const configBody = await configResponse.json();
				const administrationBody = await administrationResponse.json();
				return configResponse.ok &&
					administrationResponse.ok &&
					configBody.config?.enabled === true &&
					configBody.config?.idpEntityId === "https://idp.example.com/saml" &&
					configBody.config?.certificateFingerprintConfigured &&
					administrationBody.saml?.enabled === true &&
					administrationBody.saml?.idpEntityId === "https://idp.example.com/saml";
			} catch {
				return false;
			}
	  }, null, { timeout: 5000 });
  const saved = await page.evaluate(async () => {
    const [configResponse, administrationResponse] = await Promise.all([
      fetch("/v1/system/access-administration/saml/config"),
      fetch("/v1/system/access-administration"),
    ]);
    let configBody = null;
    let administrationBody = null;
    try {
      configBody = await configResponse.json();
      administrationBody = await administrationResponse.json();
    } catch {}
    return {
      ok: configResponse.ok && administrationResponse.ok,
      configStatus: configResponse.status,
      config: configBody?.config || null,
      administrationStatus: administrationResponse.status,
      administrationSaml: administrationBody?.saml || null,
    };
  });
	if (!saved.ok || !saved.config?.enabled || saved.config?.idpEntityId !== "https://idp.example.com/saml" || saved.config.ssoUrl !== "https://idp.example.com/sso") {
		const saveUiState = await page.evaluate(() => ({
			drawer: (document.querySelector("#drawer:not([hidden])")?.textContent || "").replace(/\s+/g, " ").trim(),
			toasts: (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim(),
    }));
    throw new Error(`settings SAML provider save did not persist expected config at ${viewport.name}: ${JSON.stringify({ saved, saveUiState })}`);
  }
  if (saved.config.certificateFingerprint || !saved.config.certificateFingerprintConfigured) {
    throw new Error(`settings SAML provider save leaked or missed certificate posture at ${viewport.name}: ${JSON.stringify(saved.config)}`);
  }
  if (!saved.administrationSaml?.enabled || saved.administrationSaml?.idpEntityId !== "https://idp.example.com/saml") {
    throw new Error(`settings SAML access administration did not refresh saved provider at ${viewport.name}: ${JSON.stringify(saved)}`);
  }

  await page.waitForSelector('[data-access-action="prepare-saml"]', { timeout: 10000 });
  await page.click('[data-access-action="prepare-saml"]');
  await waitForDrawerTitleStep(page, "Prepare SAML", "settings SAML rollout drawer reopen after save");
  const prefill = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const value = (field) => drawer?.querySelector(`[data-access-field="${field}"]`)?.value || "";
    return {
      idpEntityId: value("saml-idp-entity-id"),
      metadataUrl: value("saml-metadata-url"),
      ssoUrl: value("saml-sso-url"),
      spEntityId: value("saml-sp-entity-id"),
      acsUrl: value("saml-acs-url"),
      roleAttribute: value("saml-role-attribute"),
      defaultRole: value("saml-default-role"),
      certValue: value("saml-certificate-fingerprint"),
      certPlaceholder: drawer?.querySelector('[data-access-field="saml-certificate-fingerprint"]')?.getAttribute("placeholder") || "",
      disableVisible: Boolean(drawer?.querySelector('[data-access-action="disable-saml-provider"]')),
    };
  });
  const expectedPrefill = {
    idpEntityId: "https://idp.example.com/saml",
    metadataUrl: "",
    ssoUrl: "https://idp.example.com/sso",
    spEntityId: "https://firewall.example.com/ui",
    acsUrl: "https://firewall.example.com/v1/auth/saml/acs",
    roleAttribute: "groups",
    defaultRole: "viewer",
  };
  for (const [key, value] of Object.entries(expectedPrefill)) {
    if (prefill[key] !== value) {
      throw new Error(`settings SAML provider prefill ${key} mismatch at ${viewport.name}: ${JSON.stringify(prefill)}`);
    }
  }
	if (prefill.certValue || !prefill.certPlaceholder.includes("configured")) {
		throw new Error(`settings SAML provider reopen missed redacted cert posture at ${viewport.name}: ${JSON.stringify(prefill)}`);
	}
	if (!prefill.disableVisible) {
		await closeDrawerIfOpen(page);
		return;
	}
	await page.fill('#drawer:not([hidden]) [data-access-field="saml-audit-comment"]', `visual smoke disable saml ${viewport.name}`);
	  await page.click('#drawer:not([hidden]) [data-access-action="disable-saml-provider"]');
	  await waitForDrawerTitleStep(page, "Disable SAML provider?", "settings SAML disable confirm");
	  await clickDrawerFooterButton(page, "Disable SAML");
	  await page.waitForFunction(() => {
	    const toastText = (document.querySelector("#toasts")?.textContent || "").replace(/\s+/g, " ").trim();
	    if (/SAML disable failed/i.test(toastText)) throw new Error(toastText);
	    return !document.querySelector("#drawer:not([hidden])");
	  }, null, { timeout: 20000 });
  const disabled = await waitForSAMLProviderDisabled(page, viewport, "after SAML disable");
  if (disabled.configStatus !== 200 || disabled.config?.enabled !== false) {
    throw new Error(`settings SAML provider disable did not persist at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  if (disabled.administrationSaml?.enabled !== false) {
    throw new Error(`settings SAML access administration did not refresh disabled provider at ${viewport.name}: ${JSON.stringify(disabled)}`);
  }
  await page.click('[data-access-action="prepare-saml"]');
  await waitForDrawerTitleStep(page, "Prepare SAML", "settings SAML rollout drawer reopen after disable");
  const disabledPrefill = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const value = (field) => drawer?.querySelector(`[data-access-field="${field}"]`)?.value || "";
    return {
      idpEntityId: value("saml-idp-entity-id"),
      ssoUrl: value("saml-sso-url"),
      acsUrl: value("saml-acs-url"),
      disableVisible: Boolean(drawer?.querySelector('[data-access-action="disable-saml-provider"]')),
      certPlaceholder: drawer?.querySelector('[data-access-field="saml-certificate-fingerprint"]')?.getAttribute("placeholder") || "",
    };
  });
  if (disabledPrefill.idpEntityId || disabledPrefill.ssoUrl || disabledPrefill.acsUrl || disabledPrefill.disableVisible || /configured/i.test(disabledPrefill.certPlaceholder)) {
    throw new Error(`settings SAML provider disable left stale drawer prefill at ${viewport.name}: ${JSON.stringify(disabledPrefill)}`);
  }
  await closeDrawerIfOpen(page);
}

async function collectOneTimeAccessToken(page, viewport, label) {
  const tokenState = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const tokenNode = drawer?.querySelector("[data-one-time-token]");
    return {
      title: drawer?.querySelector("h2")?.textContent?.trim() || "",
      text: (drawer?.textContent || "").replace(/\s+/g, " ").trim(),
      token: tokenNode?.textContent?.trim() || "",
    };
  });
  if (!tokenState.text.includes("Copy this token now.") || !tokenState.text.includes("not available from inventory")) {
    throw new Error(`settings access ${label} one-time token custody copy missing at ${viewport.name}: ${tokenState.text}`);
  }
  if (!/^phr_[A-Za-z0-9_-]{30,}$/.test(tokenState.token)) {
    throw new Error(`settings access ${label} returned malformed one-time token at ${viewport.name}: ${tokenState.token || "<empty>"}`);
  }
  return tokenState.token;
}

async function assertBreakGlassEvidenceActions(page, viewport, label, forbiddenTokens = []) {
  await assertSettingsAccessActionButtonA11y(page, viewport, "#drawer:not([hidden])", {
    required: [
      '[data-access-action="copy-breakglass-evidence"]',
      '[data-access-action="export-breakglass-evidence"]',
      '[data-access-action="pin-breakglass-evidence"]',
      '[data-access-action="copy-one-time-token"]',
      '[data-access-action="close-token-result"]',
    ],
  });
  await page.evaluate(() => {
    globalThis.__breakGlassEvidenceCopiedText = "";
    const originalWrite = navigator.clipboard?.writeText?.bind(navigator.clipboard);
    navigator.clipboard.writeText = async (text) => {
      globalThis.__breakGlassEvidenceCopiedText = String(text || "");
      if (originalWrite) {
        try { return await originalWrite(text); } catch {}
      }
      return Promise.resolve();
    };
  });
  await page.click('#drawer:not([hidden]) [data-access-action="copy-breakglass-evidence"]');
  await page.waitForFunction(() => Boolean(globalThis.__breakGlassEvidenceCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__breakGlassEvidenceCopiedText || "");
  if (!copied.includes("one_time_token_shown=true") || !copied.includes("token_stored_in_inventory=false")) {
    throw new Error(`settings break-glass ${label} evidence copy missed custody flags at ${viewport.name}: ${copied}`);
  }
  assertNoAccessTokenLeak(copied, forbiddenTokens, `settings break-glass ${label} copied evidence ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('#drawer:not([hidden]) [data-access-action="export-breakglass-evidence"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^openngfw-breakglass-.*\.json$/.test(filename)) {
    throw new Error(`settings break-glass ${label} export filename had unexpected shape at ${viewport.name}: ${filename}`);
  }
  const path = await download.path();
  if (!path) throw new Error(`settings break-glass ${label} export was not readable at ${viewport.name}`);
  const text = await readFile(path, "utf8");
  assertNoAccessTokenLeak(text, forbiddenTokens, `settings break-glass ${label} export ${viewport.name}`);
  const packet = JSON.parse(text);
  if (packet?.schemaVersion !== "openngfw.breakglass-token.v1" || packet?.tokenStoredInInventory !== false || packet?.oneTimeTokenShown !== true) {
    throw new Error(`settings break-glass ${label} export had unexpected packet at ${viewport.name}: ${JSON.stringify(packet)}`);
  }

  await page.click('#drawer:not([hidden]) [data-access-action="pin-breakglass-evidence"]');
  await runSmokeStep(`settings break-glass ${label} evidence pinned`, () => page.waitForFunction(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem("phragma.investigation.case.v1") || "{}");
      return (parsed.items || []).some((item) => item.kind === "break-glass" || item.packet?.kind === "break-glass");
    } catch {
      return false;
    }
  }, null, { timeout: 5000 }));
  const pinnedText = await page.evaluate(() => localStorage.getItem("phragma.investigation.case.v1") || "");
  assertNoAccessTokenLeak(pinnedText, forbiddenTokens, `settings break-glass ${label} pinned evidence ${viewport.name}`);
}

async function assertSettingsAccessActionButtonA11y(page, viewport, scopeSelector, opts = {}) {
  const state = await page.evaluate(({ scopeSelector, required }) => {
    const scope = document.querySelector(scopeSelector);
    const buttons = [...(scope?.querySelectorAll("button[data-access-action], button[data-access-submit], button[data-access-lifecycle-action]") || [])]
      .filter((button) => {
        const rect = button.getBoundingClientRect();
        const style = getComputedStyle(button);
        return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
      })
      .map((button) => {
        const row = button.closest("tr[data-local-user]");
        return {
          selector:
            button.getAttribute("data-access-action")
              ? `[data-access-action="${button.getAttribute("data-access-action")}"]`
              : button.getAttribute("data-access-submit")
              ? `[data-access-submit="${button.getAttribute("data-access-submit")}"]`
              : `[data-access-lifecycle-action="${button.getAttribute("data-access-lifecycle-action")}"]`,
          action: button.getAttribute("data-access-action") || button.getAttribute("data-access-submit") || button.getAttribute("data-access-lifecycle-action") || "",
          type: button.getAttribute("type") || "",
          title: button.getAttribute("title") || "",
          ariaLabel: button.getAttribute("aria-label") || "",
          localUser: row?.getAttribute("data-local-user") || "",
          text: (button.textContent || "").replace(/\s+/g, " ").trim(),
        };
      });
    return {
      scopePresent: Boolean(scope),
      buttons,
      requiredMissing: (required || []).filter((selector) => !scope?.querySelector(selector)),
    };
  }, { scopeSelector, required: opts.required || [] });
  if (!state.scopePresent) {
    throw new Error(`settings access action scope missing ${scopeSelector} at ${viewport.name}`);
  }
  if (state.requiredMissing.length) {
    throw new Error(`settings access action required controls missing at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const invalid = state.buttons.filter((button) =>
    button.type !== "button" ||
    !button.title ||
    !button.ariaLabel ||
    (button.localUser && !button.ariaLabel.includes(button.localUser)));
  if (invalid.length) {
    throw new Error(`settings access action button accessibility mismatch at ${viewport.name}: ${JSON.stringify({ scopeSelector, invalid, state })}`);
  }
}

async function clickLocalUserAction(page, user, action, viewport) {
  const selector = `tr[data-local-user="${user}"] [data-access-action="${action}"]`;
  await page.waitForSelector(selector, { timeout: 10000 });
  await page.locator(selector).scrollIntoViewIfNeeded();
  await page.waitForFunction(({ selector: actionSelector }) => {
    const button = document.querySelector(actionSelector);
    if (!button || button.disabled) return false;
    const rect = button.getBoundingClientRect();
    const style = getComputedStyle(button);
    if (rect.width <= 0 || rect.height <= 0 || style.visibility === "hidden" || style.display === "none") return false;
    const x = rect.left + Math.min(rect.width - 1, Math.max(1, rect.width / 2));
    const y = rect.top + Math.min(rect.height - 1, Math.max(1, rect.height / 2));
    const hit = document.elementFromPoint(x, y);
    return hit === button || button.contains(hit);
  }, { selector }, { timeout: 10000 });
  const clicked = await page.evaluate(({ selector: actionSelector }) => {
    const button = document.querySelector(actionSelector);
    if (!button || button.disabled) return false;
    button.click();
    return true;
  }, { selector });
  if (!clicked) {
    throw new Error(`settings local user ${action} click failed for ${user} at ${viewport.name}`);
  }
}

async function waitForLocalUserRow(page, user, expected) {
  try {
    await page.waitForFunction(({ name, role, enabled }) => {
      const row = document.querySelector(`tr[data-local-user="${name}"]`);
      if (!row) return false;
      const text = (row.textContent || "").replace(/\s+/g, " ").trim();
      const stateOk = text.toLowerCase().includes(enabled ? "enabled" : "disabled");
      return text.includes(role) && stateOk;
    }, { name: user, role: expected.role, enabled: expected.enabled }, { timeout: 10000 });
  } catch (err) {
    const debug = await page.evaluate(async ({ name }) => {
      const rows = [...document.querySelectorAll("tr")].map((row) => ({
        localUser: row.getAttribute("data-local-user") || "",
        text: (row.textContent || "").replace(/\s+/g, " ").trim().slice(0, 220),
      })).filter((row) => row.localUser || /local|user|admin|visual-access/i.test(row.text));
      let inventory = {};
      let status = 0;
      try {
        const response = await fetch("/v1/system/access-administration");
        status = response.status;
        inventory = await response.json();
      } catch (e) {
        inventory = { error: e.message || String(e) };
      }
      return {
        target: name,
        rows,
        status,
        users: (Array.isArray(inventory.localUsers) ? inventory.localUsers : []).map((user) => ({
          name: user.name || "",
          role: user.role || "",
          enabled: user.enabled,
          editable: user.editable,
          tokenMaterial: user.tokenMaterial || "",
        })),
      };
    }, { name: user });
    throw new Error(`local user row ${user} did not reach role=${expected.role} enabled=${expected.enabled}: ${err.message}; debug=${JSON.stringify(debug)}`);
  }
}

async function accessIdentityWithToken(page, token) {
  return await page.evaluate(async (bearer) => {
    const response = await fetch("/v1/system/identity", {
      headers: { Authorization: `Bearer ${bearer}` },
    });
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { message: text };
    }
    return { status: response.status, body };
  }, token);
}

async function assertAccessIdentity(page, token, expected) {
  const identity = await accessIdentityWithToken(page, token);
  const actor = identity.body.actor || "";
  const role = identity.body.role || "";
  if (identity.status !== 200 || actor !== expected.actor || role !== expected.role) {
    throw new Error(`${expected.label} identity mismatch: status=${identity.status} actor=${actor || "<none>"} role=${role || "<none>"}`);
  }
}

async function assertAccessTokenRejected(page, token, label) {
  const identity = await accessIdentityWithToken(page, token);
  if (identity.status < 400) {
    throw new Error(`${label} was still accepted: status=${identity.status} body=${JSON.stringify(identity.body)}`);
  }
}

function assertNoAccessTokenLeak(text, tokens = [], label = "access evidence") {
  const value = String(text || "");
  const leaked = tokens.filter((token) => token && value.includes(token));
  if (leaked.length) {
    throw new Error(`${label} leaked one-time access token`);
  }
}

async function assertAccessInventoryDoesNotLeakTokens(page, tokens, viewport, label) {
  const inventory = await page.evaluate(async () => {
    const response = await fetch("/v1/system/access-administration");
    const text = await response.text();
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { message: text };
    }
    return {
      status: response.status,
      body,
      pageText: (document.querySelector("#content")?.textContent || "").replace(/\s+/g, " ").trim(),
    };
  });
  if (inventory.status !== 200) {
    throw new Error(`settings access inventory failed ${label} at ${viewport.name}: HTTP ${inventory.status}`);
  }
  const encoded = JSON.stringify(inventory.body);
  const leaked = tokens.filter((token) => token && (encoded.includes(token) || inventory.pageText.includes(token)));
  if (leaked.length) {
    throw new Error(`settings access inventory leaked one-time token ${label} at ${viewport.name}`);
  }
  const users = Array.isArray(inventory.body.localUsers) ? inventory.body.localUsers : [];
  const unsafe = users.filter((user) => !/redacted/i.test(String(user.tokenMaterial || user.token_material || "")));
  if (unsafe.length) {
    throw new Error(`settings access inventory had unredacted token material ${label} at ${viewport.name}: ${unsafe.map((user) => user.name).join(", ")}`);
  }
}

async function assertSettingsNetworkHostInputWorkflow(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  const seed = await seedSettingsNetworkHostInputCandidate(page);
  try {
    await page.evaluate(() => {
      location.hash = "#/settings?panel=network";
    });
    await waitForRouteReady(page, "/settings");
    await page.waitForSelector('[data-settings-panel="network"].active', { timeout: 10000 });
    await assertSettingsActionControlAttributes(page, viewport, "settings network panel", '[data-settings-panel="network"]', [
      { selector: '[data-settings-network-profile="edge-vpn"]', ariaLabel: "Apply Internet / VPN edge network profile" },
      { selector: '[data-settings-network-action="stage"]', ariaLabel: "Stage network settings to candidate", title: "Stage network settings" },
    ]);
    await page.click('[data-settings-network-profile="edge-vpn"]');
    await page.fill('[data-settings-network-interface-mtu="eth1"]', "1400");
    await page.fill('[data-settings-network-field="custom-interface-mtus"]', "ha0=9000");
    await setSettingsSwitch(page, '[data-settings-panel="network"]', "settingsNetworkField", "manage-offloads", true);
    await page.click('[data-settings-network-action="stage"]');
    await waitForSettingsNetworkHostInputState(page, "network candidate", (state) => (
      state.candidate.network?.mtu === 1500 &&
      state.candidate.network?.clampMssToPmtu === true &&
      state.candidate.network?.manageNicOffloads === true &&
      state.candidate.network?.enableFlowOffload === false &&
      state.candidate.interfaceMtus?.eth1 === 1400 &&
      state.candidate.interfaceMtus?.ha0 === 9000 &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    const networkPanel = await collectSettingsPanelState(page, "network");
    for (const required of ["Dataplane (global network)", "Network delta", "will change", "MTU overrides"]) {
      if (!networkPanel.text.includes(required)) {
        throw new Error(`settings network panel missing ${required} at ${viewport.name}: ${networkPanel.text}`);
      }
    }
    if (networkPanel.overflow > 2) {
      throw new Error(`settings network panel overflow at ${viewport.name}: ${networkPanel.overflow}px`);
    }
    await assertSettingsResponsiveTable(page, viewport, "network", ".settings-interface-mtu-table", ["Interface", "MTU override"]);
    await assertAutomationContextDrawer(page, viewport, "settings network automation context", [
      "#/settings?panel=network",
      "Workflow runbook",
      "Inspect baseline",
      "Stage candidate",
      "Validate candidate",
      "Review diff",
      "Commit candidate",
      "Rollback or discard",
      "PUT /v1/candidate",
      "POST /v1/candidate/validate",
      "POST /v1/commit",
      "ngfwctl policy network profile throughput",
      "ngfwctl policy network set --mtu 9000 --clamp-mss on --manage-nic-offloads on",
      "ngfwctl policy diff",
      "Stage throughput network profile",
    ]);

    await page.evaluate(() => {
      location.hash = "#/settings?panel=host-input";
    });
    await waitForRouteReady(page, "/settings");
    await page.waitForSelector('[data-settings-panel="host-input"].active', { timeout: 10000 });
    await assertSettingsActionControlAttributes(page, viewport, "settings host-input panel", '[data-settings-panel="host-input"]', [
      { selector: '[data-host-input-action="stage-default"]', ariaLabel: "Stage host-input default action to candidate", title: "Stage host-input default action" },
      { selector: '[data-host-input-action="add-rule"]', ariaLabel: "Add host-input rule to candidate", title: "Add host-input rule" },
      { selector: '[data-host-input-action="add-management-allow"]', ariaLabel: "Add host-input management allow rule to candidate", title: "Add management allow rule" },
    ]);
    await page.selectOption('[data-host-input-field="default-action"]', "ACTION_DENY");
    await page.click('[data-host-input-action="stage-default"]');
    await waitForDrawerTitleStep(page, "Add host-input rule", "settings host-input lockout guard drawer open");
    await assertSettingsActionControlAttributes(page, viewport, "settings host-input rule drawer", "#drawer:not([hidden])", [
      { selector: '[data-host-input-action="cancel-rule"]', ariaLabel: "Cancel host-input rule edit", title: "Cancel host-input rule edit" },
      { selector: '[data-host-input-action="stage-rule"]', ariaLabel: "Stage new host-input rule to candidate", title: "Stage new host-input rule" },
    ]);
    const blocked = await settingsNetworkHostInputPolicyState(page);
    if (blocked.candidate.hostDefault === "ACTION_DENY") {
      throw new Error(`settings host-input staged default drop before management coverage existed: ${JSON.stringify(blocked.candidate.hostInput)}`);
    }

    await fillHostInputRuleDrawer(page, {
      name: "allow-smoke-management",
      fromZones: "mgmt",
      sourceAddresses: "admin-net",
      services: "ssh, webui",
      action: "ACTION_ALLOW",
      log: true,
      disabled: false,
      description: "Visual smoke management-plane allow before default drop.",
    });
    await clickDrawerFooterButton(page, "Stage rule");
    await waitForDrawerClosed(page);
    await waitForSettingsNetworkHostInputState(page, "host-input allow rule", (state) => (
      state.candidate.hostRule?.action === "ACTION_ALLOW" &&
      state.candidate.hostRule?.log === true &&
      state.candidate.hostDefault !== "ACTION_DENY" &&
      state.runningFingerprint === seed.runningFingerprint
    ));

    await page.selectOption('[data-host-input-field="default-action"]', "ACTION_DENY");
    await page.click('[data-host-input-action="stage-default"]');
    await waitForSettingsNetworkHostInputState(page, "host-input default deny", (state) => (
      state.candidate.hostDefault === "ACTION_DENY" &&
      state.candidate.hostRule?.action === "ACTION_ALLOW" &&
      state.candidate.hostRule?.sourceAddresses?.includes("admin-net") &&
      state.candidate.hostRule?.services?.includes("ssh") &&
      state.candidate.hostRule?.services?.includes("webui") &&
      state.runningFingerprint === seed.runningFingerprint
    ));
    await page.waitForFunction(() => {
      const text = (document.querySelector('[data-settings-panel="host-input"]')?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("Management path coverage is explicit") &&
        text.includes("allow-smoke-management") &&
        text.includes("dropped unless a rule allows it");
    }, null, { timeout: 5000 });
    await assertSettingsHostInputRuleActionLabels(page, viewport, "allow-smoke-management");
    const hostPanel = await collectSettingsPanelState(page, "host-input");
    for (const required of ["Host input", "Management path coverage is explicit", "allow-smoke-management", "Drop by default"]) {
      if (!hostPanel.text.includes(required)) {
        throw new Error(`settings host-input panel missing ${required} at ${viewport.name}: ${hostPanel.text}`);
      }
    }
    if (hostPanel.overflow > 2) {
      throw new Error(`settings host-input panel overflow at ${viewport.name}: ${hostPanel.overflow}px`);
    }
    await assertAutomationContextDrawer(page, viewport, "settings host-input automation context", [
      "#/settings?panel=host-input",
      "Candidate host-input default action and management allow rules",
      "POST /v1/candidate/validate",
      "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE",
      "ngfwctl policy show --source candidate --json",
      "ngfwctl policy validate",
      "ngfwctl policy diff",
      "harden-host-input",
      "Unsaved host-input form values are not encoded",
    ]);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => {
      location.hash = "#/settings";
    });
    await waitForRouteReady(page, "/settings");
  }
}

async function assertSettingsHostInputRuleActionLabels(page, viewport, ruleName) {
  const rowActions = await page.evaluate((expectedRuleName) => {
    const row = [...document.querySelectorAll('[data-settings-panel="host-input"] tbody tr')]
      .find((candidate) => (candidate.textContent || "").includes(expectedRuleName));
    return [...(row?.querySelectorAll("[data-host-input-action]") || [])].map((button) => ({
      action: button.getAttribute("data-host-input-action") || "",
      type: button.getAttribute("type") || "",
      ariaLabel: button.getAttribute("aria-label") || "",
      title: button.getAttribute("title") || "",
    }));
  }, ruleName);
  for (const expected of [
    { action: "edit-rule", ariaLabel: `Edit host-input rule ${ruleName}`, title: "Edit host-input rule" },
    { action: "delete-rule", ariaLabel: `Delete host-input rule ${ruleName}`, title: "Delete host-input rule" },
  ]) {
    const actual = rowActions.find((button) => button.action === expected.action);
    if (!actual || actual.type !== "button" || actual.ariaLabel !== expected.ariaLabel || actual.title !== expected.title) {
      throw new Error(`settings host-input row action mismatch at ${viewport.name} for ${expected.action}: ${JSON.stringify(rowActions)}`);
    }
  }
}

async function assertSettingsActionControlAttributes(page, viewport, label, rootSelector, expectedControls) {
  const controls = await page.evaluate(({ rootSelector, expectedControls }) => {
    const root = document.querySelector(rootSelector);
    return expectedControls.map((expected) => {
      const button = root?.querySelector(expected.selector);
      return {
        selector: expected.selector,
        exists: Boolean(button),
        type: button?.getAttribute("type") || "",
        title: button?.getAttribute("title") || "",
        ariaLabel: button?.getAttribute("aria-label") || "",
        text: (button?.textContent || "").replace(/\s+/g, " ").trim(),
      };
    });
  }, { rootSelector, expectedControls });
  for (let i = 0; i < expectedControls.length; i += 1) {
    const expected = expectedControls[i];
    const actual = controls[i];
    if (!actual.exists || actual.type !== "button") {
      throw new Error(`${label} action missing button semantics at ${viewport.name}: ${JSON.stringify(actual)}`);
    }
    if (expected.title ? actual.title !== expected.title : !actual.title) {
      throw new Error(`${label} action missing title at ${viewport.name}: ${JSON.stringify(actual)}`);
    }
    if (expected.ariaLabel ? actual.ariaLabel !== expected.ariaLabel : !actual.ariaLabel) {
      throw new Error(`${label} action missing aria label at ${viewport.name}: ${JSON.stringify(actual)}`);
    }
  }
}

async function seedSettingsNetworkHostInputCandidate(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const running = await fetch("/v1/policy?source=POLICY_SOURCE_RUNNING");
    if (!running.ok) {
      throw new Error(`read running policy before settings seed failed with HTTP ${running.status}: ${await running.text()}`);
    }
    const runningPolicy = (await running.json())?.policy || {};
    let webuiPort = 8080;
    try {
      const statusResponse = await fetch("/v1/system/status");
      const status = statusResponse.ok ? await statusResponse.json() : {};
      const listen = String(status.runtime?.httpListen || status.runtime?.http_listen || "");
      const match = listen.match(/:(\d+)$/) || listen.match(/^(\d+)$/);
      const parsed = match ? Number(match[1]) : 0;
      if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) webuiPort = parsed;
    } catch {}
    const policy = {
      zones: [
        { name: "mgmt", interfaces: ["eth0"] },
        { name: "lan", interfaces: ["eth1"] },
      ],
      addresses: [
        { name: "admin-net", cidr: "10.55.0.0/24" },
      ],
      services: [
        { name: "ssh", protocol: "PROTOCOL_TCP", ports: [{ start: 22 }] },
        { name: "webui", protocol: "PROTOCOL_TCP", ports: [{ start: webuiPort }] },
      ],
      rules: [],
      ids: { enabled: false },
    };
    const response = await fetch("/v1/candidate", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy }),
    });
    if (!response.ok) {
      throw new Error(`seed settings candidate failed with HTTP ${response.status}: ${await response.text()}`);
    }
    return { runningFingerprint: stable(runningPolicy), webuiPort };
  });
}

async function setSettingsSwitch(page, panelSelector, datasetName, field, checked) {
  await page.evaluate(({ panelSelector, datasetName, field, checked }) => {
    const panel = document.querySelector(panelSelector);
    if (!panel) throw new Error(`settings panel ${panelSelector} was not found`);
    const root = [...panel.querySelectorAll(`[data-${datasetName.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase())}]`)]
      .find((candidate) => candidate.dataset?.[datasetName] === field);
    const input = root?.matches?.('input[type="checkbox"]') ? root : root?.querySelector?.('input[type="checkbox"]');
    if (!input) throw new Error(`settings switch ${field} was not found`);
    input.checked = Boolean(checked);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }, { panelSelector, datasetName, field, checked });
}

async function fillHostInputRuleDrawer(page, values) {
  await page.evaluate((next) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    if (!drawer) throw new Error("host-input rule drawer was not open");
    const dispatch = (el) => {
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setValue = (field, value) => {
      const control = drawer.querySelector(`[data-host-input-field="${field}"]`);
      if (!control) throw new Error(`host-input drawer field ${field} was not found`);
      control.value = value;
      dispatch(control);
    };
    const setSwitch = (field, checked) => {
      const root = drawer.querySelector(`[data-host-input-field="${field}"]`);
      const input = root?.matches?.('input[type="checkbox"]') ? root : root?.querySelector?.('input[type="checkbox"]');
      if (!input) throw new Error(`host-input drawer switch ${field} was not found`);
      input.checked = Boolean(checked);
      dispatch(input);
    };
    if ("name" in next) setValue("rule-name", next.name);
    if ("fromZones" in next) setValue("rule-from-zones", next.fromZones);
    if ("sourceAddresses" in next) setValue("rule-source-addresses", next.sourceAddresses);
    if ("services" in next) setValue("rule-services", next.services);
    if ("action" in next) setValue("rule-action", next.action);
    if ("description" in next) setValue("rule-description", next.description);
    if ("log" in next) setSwitch("rule-log", next.log);
    if ("disabled" in next) setSwitch("rule-disabled", next.disabled);
  }, values);
}

async function waitForSettingsNetworkHostInputState(page, label, predicate, timeout = 5000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await settingsNetworkHostInputPolicyState(page);
    if (predicate(state)) return state;
    await page.waitForTimeout(150);
  }
  throw new Error(`settings ${label} did not reach expected state: ${JSON.stringify(state)}`);
}

async function settingsNetworkHostInputPolicyState(page) {
  return await page.evaluate(async () => {
    const stable = (value) => {
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
      }
      return JSON.stringify(value);
    };
    const [candidateResponse, runningResponse, statusResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
      fetch("/v1/candidate/status"),
    ]);
    const candidate = candidateResponse.ok ? (await candidateResponse.json())?.policy || {} : {};
    const running = runningResponse.ok ? (await runningResponse.json())?.policy || {} : {};
    const status = statusResponse.ok ? await statusResponse.json() : {};
    const interfaceMtus = {};
    for (const item of candidate.network?.interfaceMtus || []) {
      if (item?.interface) interfaceMtus[item.interface] = Number(item.mtu || 0);
    }
    const hostRule = (candidate.hostInput?.rules || []).find((rule) => rule.name === "allow-smoke-management") || null;
    return {
      candidateStatus: candidateResponse.status,
      runningStatus: runningResponse.status,
      runningFingerprint: stable(running),
      candidate: {
        network: candidate.network || null,
        interfaceMtus,
        hostInput: candidate.hostInput || null,
        hostDefault: candidate.hostInput?.defaultAction || "ACTION_ALLOW",
        hostRule,
      },
      status: {
        dirty: Boolean(status.dirty),
        changeCount: Number(status.changeCount || status.change_count || 0),
      },
    };
  });
}

async function collectSettingsPanelState(page, panelId) {
  return await page.evaluate((id) => {
    const section = document.querySelector(`[data-settings-panel="${id}"]`);
    const rect = section?.getBoundingClientRect?.();
    return {
      text: (section?.textContent || "").replace(/\s+/g, " ").trim(),
      overflow: section ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(section.scrollWidth - section.clientWidth),
      ) : 0,
    };
  }, panelId);
}

async function assertSettingsResponsiveTable(page, viewport, panelId, selector, expectedLabels) {
  const state = await page.evaluate(({ panelId, selector }) => {
    const section = document.querySelector(`[data-settings-panel="${panelId}"]`);
    const table = section?.querySelector(selector);
    const row = table?.querySelector("tbody tr");
    const cells = [...(row?.querySelectorAll("td") || [])];
    return {
      tableClass: table?.className || "",
      labels: cells.map((cell) => cell.getAttribute("data-label") || ""),
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      mobileLabelsRendered: window.innerWidth > 820 || cells.every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
    };
  }, { panelId, selector });
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes(selector.replace(".", ""))) {
    throw new Error(`settings responsive table ${selector} missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.labels.length) {
    throw new Error(`settings responsive table ${selector} rendered no data row at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = expectedLabels.filter((label) => !state.labels.includes(label));
  if (missingLabels.length) {
    throw new Error(`settings responsive table ${selector} missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (state.overflow > 2) {
    throw new Error(`settings responsive table ${selector} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`settings responsive table ${selector} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertDrawerResponsiveTable(page, viewport, selector, expectedLabels, label) {
  const state = await page.evaluate(({ selector }) => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const table = drawer?.querySelector(selector);
    const row = table?.querySelector("tbody tr");
    const cells = [...(row?.querySelectorAll("td") || [])];
    return {
      tableClass: table?.className || "",
      labels: cells.map((cell) => cell.getAttribute("data-label") || ""),
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      mobileLabelsRendered: window.innerWidth > 820 || cells.every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
    };
  }, { selector });
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes(selector.replace(".", ""))) {
    throw new Error(`${label} responsive table ${selector} missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.labels.length) {
    throw new Error(`${label} responsive table ${selector} rendered no data row at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = expectedLabels.filter((expectedLabel) => !state.labels.includes(expectedLabel));
  if (missingLabels.length) {
    throw new Error(`${label} responsive table ${selector} missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (state.overflow > 2) {
    throw new Error(`${label} responsive table ${selector} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`${label} responsive table ${selector} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertPageResponsiveTable(page, viewport, selector, expectedLabels, label) {
  const state = await page.evaluate(({ selector }) => {
    const table = document.querySelector(selector);
    const row = table?.querySelector("tbody tr");
    const cells = [...(row?.querySelectorAll("td") || [])];
    return {
      tableClass: table?.className || "",
      labels: cells.map((cell) => cell.getAttribute("data-label") || ""),
      overflow: table ? Math.max(0, Math.ceil(table.scrollWidth - table.clientWidth)) : 0,
      mobileLabelsRendered: window.innerWidth > 820 || cells.every((cell) => {
        const before = getComputedStyle(cell, "::before").content || "";
        return before !== "none" && before !== "\"\"" && before.length > 2;
      }),
    };
  }, { selector });
  if (!state.tableClass.includes("responsive-evidence") || !state.tableClass.includes(selector.replace(".", ""))) {
    throw new Error(`${label} responsive table ${selector} missing responsive class at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  if (!state.labels.length) {
    throw new Error(`${label} responsive table ${selector} rendered no data row at ${viewport.name}: ${JSON.stringify(state)}`);
  }
  const missingLabels = expectedLabels.filter((expectedLabel) => !state.labels.includes(expectedLabel));
  if (missingLabels.length) {
    throw new Error(`${label} responsive table ${selector} missing labels at ${viewport.name}: ${JSON.stringify({ missingLabels, state })}`);
  }
  if (state.overflow > 2) {
    throw new Error(`${label} responsive table ${selector} overflow at ${viewport.name}: ${state.overflow}px`);
  }
  if (!state.mobileLabelsRendered) {
    throw new Error(`${label} responsive table ${selector} mobile labels did not render at ${viewport.name}: ${JSON.stringify(state)}`);
  }
}

async function assertSettingsTelemetryExportWorkflow(page, viewport) {
  const previousPolicy = await snapshotCandidatePolicy(page);
  try {
    await page.evaluate(() => {
      location.hash = "#/settings?panel=telemetry";
    });
    await waitForRouteReady(page, "/settings");
    await page.waitForSelector('[data-settings-panel="telemetry"].active', { timeout: 10000 });

    await setSettingsTelemetryValues(page, {
      enabled: true,
      clickhouseUrl: "https://writer:secret@clickhouse.example:8443?access_token=bad",
      database: "openngfw_prod",
      jsonFileEnabled: true,
      jsonFilePath: "/var/log/openngfw/exports/eve-visual.json",
      jsonStreamEnabled: true,
      jsonStreamTarget: "siem.example:5514",
      jsonStreamProtocol: "tcp",
    });
    const invalid = await collectSettingsTelemetryState(page);
    if (!invalid.text.includes("Telemetry cannot be staged") ||
        !invalid.text.includes("ClickHouse endpoint must not include URL userinfo") ||
        !invalid.text.includes('ClickHouse endpoint must not include sensitive query parameter "access_token"') ||
        !invalid.stageDisabled) {
      throw new Error(`settings telemetry invalid ClickHouse URL was not blocked: ${JSON.stringify(invalid)}`);
    }

    await setSettingsTelemetryValues(page, {
      enabled: true,
      clickhouseUrl: "https://clickhouse.example:8443",
      database: "openngfw_prod",
      jsonFileEnabled: true,
      jsonFilePath: "/var/log/openngfw/exports/eve-visual.json",
      jsonStreamEnabled: true,
      jsonStreamTarget: "siem.example:5514",
      jsonStreamProtocol: "tcp",
    });
    await page.waitForFunction(() => {
      const section = document.querySelector('[data-settings-panel="telemetry"]');
      const button = [...(section?.querySelectorAll("button") || [])]
        .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim() === "Stage telemetry");
      const text = section?.textContent || "";
      return Boolean(button && !button.disabled && text.includes("Vector -> ClickHouse + 2 exports"));
    }, null, { timeout: 5000 });
    await clickContentButton(page, "Stage telemetry");
    await page.waitForFunction(() => {
      const section = document.querySelector('[data-settings-panel="telemetry"]');
      const text = (section?.textContent || "").replace(/\s+/g, " ").trim();
      return text.includes("candidate edit") && text.includes("Vector -> ClickHouse + 2 exports");
    }, null, { timeout: 5000 });
    const staged = await collectSettingsTelemetryState(page);
    if (staged.overflow > 2) {
      throw new Error(`settings telemetry panel overflow at ${viewport.name}: ${staged.overflow}px`);
    }
    await assertSettingsActionControlAttributes(page, viewport, "settings telemetry panel", '[data-settings-panel="telemetry"]', [
      { selector: '[data-telemetry-action="stage"]', ariaLabel: "Stage telemetry settings to candidate", title: "Stage telemetry settings" },
      { selector: '[data-telemetry-action="pin-evidence-plan"]', ariaLabel: "Pin telemetry evidence plan to investigation case", title: "Pin telemetry evidence plan to investigation case" },
      { selector: '[data-telemetry-action="copy-evidence-plan"]', ariaLabel: "Copy telemetry evidence plan", title: "Copy telemetry evidence plan" },
      { selector: '[data-telemetry-action="export-evidence-json"]', ariaLabel: "Export telemetry evidence JSON", title: "Export telemetry evidence JSON" },
      { selector: '[data-telemetry-action="receiver-proof"]', ariaLabel: "Attach telemetry receiver proof", title: "Attach receiver-side SIEM evidence" },
    ]);
    await assertSettingsResponsiveTable(page, viewport, "telemetry", ".settings-telemetry-capability-table", ["Capability", "Status", "Operator note"]);
    for (const required of [
      "Telemetry readiness",
      "Vector -> ClickHouse + 2 exports",
      "Passive export status",
      "JSON file export",
      "Remote JSON SIEM stream",
      "Copy plan",
      "Export JSON",
      "Pin to case",
      "Attach receiver proof",
    ]) {
      if (!staged.text.includes(required)) {
        throw new Error(`settings telemetry panel missing ${required}`);
      }
    }
    await assertSettingsTelemetryCandidateOnly(page);
    await assertSettingsTelemetryCopyPlan(page, viewport);
    await assertSettingsTelemetryExport(page, viewport);
    await assertSettingsTelemetryPin(page, viewport);
    await assertSettingsTelemetryReceiverProof(page, viewport);
    await assertAutomationContextDrawer(page, viewport, "settings telemetry automation context", [
      "#/settings?panel=telemetry",
      "panel = telemetry",
      "/v1/system/telemetry/exports/status",
      "/v1/policy?source=POLICY_SOURCE_CANDIDATE",
      "ngfwctl system telemetry-export-status --json",
      "Telemetry evidence packet",
    ]);
  } finally {
    await restoreRulesWorkspaceCandidate(page, previousPolicy);
    await page.evaluate(() => {
      location.hash = "#/settings";
    });
    await waitForRouteReady(page, "/settings");
  }
}

async function setSettingsTelemetryValues(page, values) {
  await page.evaluate((next) => {
    const section = document.querySelector('[data-settings-panel="telemetry"]');
    if (!section) throw new Error("settings telemetry panel was not found");
    const dispatch = (el) => {
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const field = (labelText) => {
      const label = [...section.querySelectorAll("label.field")]
        .find((candidate) => (candidate.textContent || "").replace(/\s+/g, " ").trim().includes(labelText));
      if (!label) throw new Error(`settings telemetry field "${labelText}" was not found`);
      return label;
    };
    const setInput = (labelText, value) => {
      const control = field(labelText).querySelector("input,textarea,select");
      if (!control) throw new Error(`settings telemetry control "${labelText}" was not found`);
      control.value = value;
      dispatch(control);
    };
    const setCheckbox = (labelText, checked) => {
      const control = field(labelText).querySelector("input[type='checkbox']");
      if (!control) throw new Error(`settings telemetry checkbox "${labelText}" was not found`);
      control.checked = Boolean(checked);
      dispatch(control);
    };
    if ("enabled" in next) setCheckbox("Enable ClickHouse local retention", next.enabled);
    if ("clickhouseUrl" in next) setInput("ClickHouse HTTP endpoint", next.clickhouseUrl);
    if ("database" in next) setInput("Database", next.database);
    if ("jsonFileEnabled" in next) setCheckbox("Mirror parsed events to local JSON file", next.jsonFileEnabled);
    if ("jsonFilePath" in next) setInput("JSON export path", next.jsonFilePath);
    if ("jsonStreamEnabled" in next) setCheckbox("Stream parsed events to remote SIEM", next.jsonStreamEnabled);
    if ("jsonStreamTarget" in next) setInput("Remote JSON target", next.jsonStreamTarget);
    if ("jsonStreamProtocol" in next) setInput("Remote JSON protocol", next.jsonStreamProtocol);
  }, values);
}

async function collectSettingsTelemetryState(page) {
  return await page.evaluate(() => {
    const section = document.querySelector('[data-settings-panel="telemetry"]');
    const rect = section?.getBoundingClientRect?.();
    const buttons = [...(section?.querySelectorAll("button") || [])].map((button) => ({
      text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      disabled: button.disabled,
      width: button.getBoundingClientRect().width,
      height: button.getBoundingClientRect().height,
    }));
    const stage = buttons.find((button) => button.text === "Stage telemetry");
    return {
      text: (section?.textContent || "").replace(/\s+/g, " ").trim(),
      buttons,
      stageDisabled: Boolean(stage?.disabled),
      overflow: section ? Math.max(
        0,
        Math.ceil(rect.right - window.innerWidth),
        Math.ceil(0 - rect.left),
        Math.ceil(section.scrollWidth - section.clientWidth),
      ) : 0,
    };
  });
}

async function assertSettingsTelemetryCandidateOnly(page) {
  const state = await page.evaluate(async () => {
    const [candidateResponse, runningResponse] = await Promise.all([
      fetch("/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
      fetch("/v1/policy?source=POLICY_SOURCE_RUNNING"),
    ]);
    if (!candidateResponse.ok) throw new Error(`read telemetry candidate failed with HTTP ${candidateResponse.status}: ${await candidateResponse.text()}`);
    if (!runningResponse.ok) throw new Error(`read telemetry running failed with HTTP ${runningResponse.status}: ${await runningResponse.text()}`);
    const candidate = (await candidateResponse.json())?.policy || {};
    const running = (await runningResponse.json())?.policy || {};
    const exports = candidate.telemetry?.exports || [];
    return {
      candidateTelemetry: candidate.telemetry || null,
      localJson: exports.find((item) => item.name === "local-json") || null,
      siemJson: exports.find((item) => item.name === "siem-json") || null,
      runningText: JSON.stringify(running),
    };
  });
  if (!state.candidateTelemetry?.enabled ||
      state.candidateTelemetry.clickhouseUrl !== "https://clickhouse.example:8443" ||
      state.candidateTelemetry.database !== "openngfw_prod") {
    throw new Error(`settings telemetry candidate not staged correctly: ${JSON.stringify(state.candidateTelemetry)}`);
  }
  if (!state.localJson?.enabled || state.localJson.target !== "/var/log/openngfw/exports/eve-visual.json") {
    throw new Error(`settings telemetry local JSON export missing: ${JSON.stringify(state.localJson)}`);
  }
  if (!state.siemJson?.enabled || state.siemJson.target !== "siem.example:5514") {
    throw new Error(`settings telemetry SIEM JSON export missing: ${JSON.stringify(state.siemJson)}`);
  }
  for (const leaked of ["clickhouse.example", "eve-visual.json", "siem.example:5514"]) {
    if (state.runningText.includes(leaked)) {
      throw new Error(`settings telemetry workflow mutated running policy before commit: ${leaked}`);
    }
  }
}

async function assertSettingsTelemetryCopyPlan(page, viewport) {
  await page.evaluate(() => {
    globalThis.__settingsTelemetryCopiedText = "";
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            globalThis.__settingsTelemetryCopiedText = String(text || "");
          },
        },
      });
    } catch {}
  });
  await clickContentButton(page, "Copy plan");
  await page.waitForFunction(() => Boolean(globalThis.__settingsTelemetryCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__settingsTelemetryCopiedText || "");
  assertSettingsTelemetryEvidenceText(copied, `settings telemetry copy ${viewport.name}`);
}

async function assertSettingsTelemetryExport(page, viewport) {
  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await clickContentButton(page, "Export JSON");
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^phragma-telemetry-evidence-.+\.json$/.test(filename)) {
    throw new Error(`settings telemetry export filename had unexpected shape at ${viewport.name}: ${filename || "<none>"}`);
  }
  const path = await download.path();
  if (!path) {
    throw new Error(`settings telemetry export did not produce a readable file at ${viewport.name}`);
  }
  const text = await readFile(path, "utf8");
  assertSettingsTelemetryEvidenceText(text, `settings telemetry export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`settings telemetry export was not valid JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet.schemaVersion !== "phragma.telemetry.evidence.v1" || packet.surface !== "settings.telemetry") {
    throw new Error(`settings telemetry export had unexpected identity at ${viewport.name}: ${JSON.stringify(packet)}`);
  }
  if (!packet.sinks?.some((sink) => sink.id === "json-file") || !packet.sinks?.some((sink) => sink.id === "json-stream")) {
    throw new Error(`settings telemetry export missed configured sinks at ${viewport.name}: ${JSON.stringify(packet.sinks)}`);
  }
}

async function assertSettingsTelemetryPin(page, viewport) {
  await page.evaluate(() => localStorage.removeItem("phragma.investigation.case.v1"));
  await clickContentButton(page, "Pin to case");
  const pinned = await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "";
    try {
      const parsed = JSON.parse(raw);
      return {
        schemaVersion: parsed.schemaVersion || "",
        itemCount: parsed.items?.length || 0,
        kinds: (parsed.items || []).map((item) => item.packet?.kind || item.kind || ""),
        text: raw,
      };
    } catch {
      return { schemaVersion: "", itemCount: 0, kinds: [], text: raw };
    }
  });
  if (pinned.schemaVersion !== "phragma.investigation.case.v1" ||
      pinned.itemCount < 1 ||
      !pinned.kinds.includes("telemetry-evidence")) {
    throw new Error(`settings telemetry pin-to-case failed at ${viewport.name}: ${JSON.stringify(pinned)}`);
  }
  assertSettingsTelemetryEvidenceText(pinned.text, `settings telemetry pinned case ${viewport.name}`);
}

async function assertSettingsTelemetryReceiverProof(page, viewport) {
  await closeActiveDrawer(page);
  await page.evaluate(() => {
    globalThis.__settingsTelemetryReceiverProofCopiedText = "";
    globalThis.__settingsTelemetryReceiverProofExportedText = "";
    const originalCreateObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      if (blob?.type === "application/json") {
        blob.text().then((text) => {
          globalThis.__settingsTelemetryReceiverProofExportedText = String(text || "");
        }).catch(() => {});
      }
      return originalCreateObjectURL(blob);
    };
    const writeText = async (text) => {
      globalThis.__settingsTelemetryReceiverProofCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try { navigator.clipboard.writeText = writeText; } catch {}
    }
  });
  await clickContentButton(page, "Attach receiver proof");
  await page.waitForSelector("#drawer:not([hidden]) [data-telemetry-proof-drawer='true']", { timeout: 5000 });
  await assertSettingsActionControlAttributes(page, viewport, "settings telemetry receiver proof drawer", "#drawer:not([hidden])", [
    { selector: '[data-telemetry-proof-action="close"]', ariaLabel: "Close telemetry receiver proof drawer", title: "Close telemetry receiver proof drawer" },
    { selector: '[data-telemetry-proof-action="copy"]', ariaLabel: "Copy telemetry receiver proof", title: "Copy telemetry receiver proof" },
    { selector: '[data-telemetry-proof-action="export"]', ariaLabel: "Export telemetry receiver proof JSON", title: "Export telemetry receiver proof JSON" },
    { selector: '[data-telemetry-proof-action="pin"]', ariaLabel: "Pin telemetry receiver proof to investigation case", title: "Pin telemetry receiver proof to investigation case" },
  ]);
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='target']", "siem.example:5514");
  await page.selectOption("#drawer:not([hidden]) [data-telemetry-proof-field='protocol']", "tcp");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='window-start']", "2026-06-19T15:10:00Z");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='window-end']", "2026-06-19T15:15:00Z");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='event-count']", "7");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='hashes']", [
    "aaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ].join("\n"));
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='collected-by']", "soc-operator");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='commands']", "wc -l siem-json.ndjson\njq -c .event_type siem-json.ndjson");
  await page.fill("#drawer:not([hidden]) [data-telemetry-proof-field='notes']", "receiver accepted events for change CHG-123");
  await page.waitForFunction(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    return Boolean(drawer?.textContent?.includes("Receiver proof ready"));
  }, null, { timeout: 5000 });

  await page.click("#drawer:not([hidden]) [data-telemetry-proof-action='copy']");
  await page.waitForFunction(() => Boolean(globalThis.__settingsTelemetryReceiverProofCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__settingsTelemetryReceiverProofCopiedText || "");
  assertSettingsTelemetryEvidenceText(copied, `settings telemetry receiver proof copy ${viewport.name}`);
  assertSettingsTelemetryReceiverProofText(copied, `settings telemetry receiver proof copy ${viewport.name}`);

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 }).catch(() => null);
  await page.click("#drawer:not([hidden]) [data-telemetry-proof-action='export']");
  const download = await downloadPromise;
  let text = "";
  if (download) {
    const path = await download.path();
    if (path) text = await readFile(path, "utf8");
  }
  if (!text) {
    await page.waitForFunction(() => Boolean(globalThis.__settingsTelemetryReceiverProofExportedText), null, { timeout: 5000 });
    text = await page.evaluate(() => globalThis.__settingsTelemetryReceiverProofExportedText || "");
  }
  if (!text) throw new Error(`settings telemetry receiver proof export did not produce a readable packet at ${viewport.name}`);
  assertSettingsTelemetryEvidenceText(text, `settings telemetry receiver proof export ${viewport.name}`);
  assertSettingsTelemetryReceiverProofText(text, `settings telemetry receiver proof export ${viewport.name}`);
  let packet = null;
  try {
    packet = JSON.parse(text);
  } catch (err) {
    throw new Error(`settings telemetry receiver proof export was not JSON at ${viewport.name}: ${err.message}`);
  }
  if (packet.receiverProof?.schemaVersion !== "phragma.telemetry.receiver-proof.v1" ||
      packet.receiverProof?.observedEventCount !== 7 ||
      packet.receiverProof?.target !== "siem.example:5514") {
    throw new Error(`settings telemetry receiver proof export missed proof payload at ${viewport.name}: ${JSON.stringify(packet.receiverProof)}`);
  }

  await page.evaluate(() => localStorage.removeItem("phragma.investigation.case.v1"));
  await page.click("#drawer:not([hidden]) [data-telemetry-proof-action='pin']");
  const pinned = await page.evaluate(() => {
    const raw = localStorage.getItem("phragma.investigation.case.v1") || "";
    try {
      const parsed = JSON.parse(raw);
      return {
        schemaVersion: parsed.schemaVersion || "",
        itemCount: parsed.items?.length || 0,
        kinds: (parsed.items || []).map((item) => item.packet?.kind || item.kind || ""),
        text: raw,
      };
    } catch {
      return { schemaVersion: "", itemCount: 0, kinds: [], text: raw };
    }
  });
  if (pinned.schemaVersion !== "phragma.investigation.case.v1" ||
      pinned.itemCount < 1 ||
      !pinned.kinds.includes("telemetry-evidence")) {
    throw new Error(`settings telemetry receiver proof pin failed at ${viewport.name}: ${JSON.stringify(pinned)}`);
  }
  assertSettingsTelemetryEvidenceText(pinned.text, `settings telemetry receiver proof pin ${viewport.name}`);
  assertSettingsTelemetryReceiverProofText(pinned.text, `settings telemetry receiver proof pin ${viewport.name}`);
  await closeActiveDrawer(page);
}

function assertSettingsTelemetryReceiverProofText(text, label) {
  const required = [
    "browser-local unsigned receiver evidence; passive status did not dial the SIEM",
    "siem.example:5514",
  ];
  if (text.includes("phragma.telemetry.receiver-proof.v1")) {
    required.push("observedEventCount", "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  } else {
    required.push("Receiver proof", "observed_events=7", "sample_hashes=aaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  }
  for (const item of required) {
    if (!text.includes(item)) {
      throw new Error(`${label} missing ${item}`);
    }
  }
  const leaked = [
    /token=(?!\[redacted\])/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /\/etc\/[^\s"',;}]+/i,
    /\/Users\/[^\s"',;}]+/i,
    /\/private\/tmp\/[^\s"',;}]+/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked receiver proof evidence: ${leaked}`);
  }
}

function assertSettingsTelemetryEvidenceText(text, label) {
  if (!text.includes("Phragma telemetry export evidence plan") &&
      !text.includes("phragma.telemetry.evidence.v1") &&
      !text.includes("Telemetry evidence handoff")) {
    throw new Error(`${label} missing telemetry evidence identity`);
  }
  for (const required of [
    "Vector -> ClickHouse + 2 exports",
    "ngfwctl system telemetry-export-status --json",
    "ClickHouse rows",
    "JSON file export",
    "SIEM stream",
    "clickhouse.example:8443",
    "openngfw_prod",
  ]) {
    if (!text.includes(required)) {
      throw new Error(`${label} missing ${required}`);
    }
  }
  const leaked = [
    /writer:secret/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
    /api[_-]?key=(?!\[redacted\])/i,
    /https?:\/\/[^/\s"']+:[^@\s"']+@/i,
    /\/etc\/[^\s"',;}]+/i,
    /\/Users\/[^\s"',;}]+/i,
    /\/private\/tmp\/[^\s"',;}]+/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked sensitive telemetry evidence: ${leaked}`);
  }
}

async function assertAutomationContextDrawer(page, viewport, label, requiredText = [], opts = {}) {
  if (!opts.keepActiveDrawer) await closeActiveDrawer(page);
  await page.evaluate(() => {
    localStorage.removeItem("phragma.webui.automation-recorder.v1");
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });
  if (opts.keepActiveDrawer && opts.drawerButtonLabel) {
    await clickDrawerFooterButton(page, opts.drawerButtonLabel);
  } else if (opts.keepActiveDrawer) {
    await page.evaluate(() => {
      const button = document.querySelector("#open-automation");
      if (!button) throw new Error("API / CLI context button was not found");
      button.click();
    });
  } else {
    await page.click("#open-automation");
  }
  await waitForDrawerTitle(page, "API / CLI context");
  const drawer = await collectDrawerState(page);
  assertDrawerContains(drawer, viewport, label, [
    "API / CLI context",
    "Current view",
    "API contract",
    "Workflow session",
    "Automation recorder",
    "REST endpoints",
    "CLI equivalents",
    "Copy session JSON",
    "Download JSON",
    "Copy recording",
    "Copy shell runbook",
    "Copy shell",
    "Download shell",
    "Copy context",
    ...requiredText,
  ], ["Copy session JSON", "Copy context"]);
  assertAutomationContextRedaction(drawer.text, `${label} drawer`);
  await assertAutomationContextActionButtons(page, viewport, label);
  await clickDrawerFooterButton(page, "Copy session JSON");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const sessionJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(sessionJson, `${label} workflow session JSON`);
  let sessionPacket = null;
  try {
    sessionPacket = JSON.parse(sessionJson);
  } catch (err) {
    throw new Error(`${label} workflow session JSON was not parseable: ${err.message}`);
  }
  if (sessionPacket.schemaVersion !== "phragma.webui.workflow-session.v1" ||
      sessionPacket.source !== "browser-local" ||
      sessionPacket.custody?.serverStored !== false ||
      sessionPacket.custody?.signed !== false ||
      !Array.isArray(sessionPacket.endpoints) ||
      !Array.isArray(sessionPacket.cli)) {
    throw new Error(`${label} workflow session JSON had unexpected packet shape: ${JSON.stringify(sessionPacket)}`);
  }
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="start"]');
  await page.waitForFunction(() => {
    const root = document.querySelector("#drawer:not([hidden])");
    return root?.querySelector("[data-automation-recorder='status']")?.textContent?.includes("Recording");
  }, null, { timeout: 5000 });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="record-view"]');
  await page.waitForFunction(() => {
    const root = document.querySelector("#drawer:not([hidden])");
    return root?.querySelector("[data-automation-recorder='step-count']")?.textContent?.trim() === "1";
  }, null, { timeout: 5000 });
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="copy"]');
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const recordingJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(recordingJson, `${label} automation recording JSON`);
  let recordingPacket = null;
  try {
    recordingPacket = JSON.parse(recordingJson);
  } catch (err) {
    throw new Error(`${label} automation recording JSON was not parseable: ${err.message}`);
  }
  if (recordingPacket.schemaVersion !== "phragma.webui.automation-recorder.v1" ||
      recordingPacket.source !== "browser-local" ||
      recordingPacket.custody?.serverStored !== false ||
      recordingPacket.custody?.signed !== false ||
      recordingPacket.steps?.length !== 1 ||
      recordingPacket.steps?.[0]?.session?.schemaVersion !== "phragma.webui.workflow-session.v1") {
    throw new Error(`${label} automation recording JSON had unexpected packet shape: ${JSON.stringify(recordingPacket)}`);
  }
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="copy-runbook"]');
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const recorderRunbook = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationRecordingRunbookText(recorderRunbook, `${label} recorder shell runbook`, 1);
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await clickDrawerFooterButton(page, "Copy context");
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copied = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  for (const required of requiredText) {
    if (!copied.includes(required)) {
      throw new Error(`${label} copied context missing ${required}`);
    }
  }
  assertAutomationContextRedaction(copied, `${label} copied context`);
  const closedByButton = await page.locator('#drawer:not([hidden]) [aria-label="Close dialog"]').click({ timeout: 1500 }).then(() => true).catch(() => false);
  if (!closedByButton) await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
  return copied;
}

async function assertAutomationContextActionButtons(page, viewport, label) {
  const state = await page.evaluate(() => {
    const drawer = document.querySelector("#drawer:not([hidden])");
    const buttons = [...(drawer?.querySelectorAll("button[data-automation-action], button[data-automation-recorder-action]") || [])]
      .filter((button) => {
        const rect = button.getBoundingClientRect();
        const style = getComputedStyle(button);
        return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
      })
      .map((button) => ({
        action: button.getAttribute("data-automation-action") || button.getAttribute("data-automation-recorder-action") || "",
        type: button.getAttribute("type") || "",
        title: button.getAttribute("title") || "",
        ariaLabel: button.getAttribute("aria-label") || "",
        text: (button.textContent || "").replace(/\s+/g, " ").trim(),
      }));
    return {
      drawerPresent: Boolean(drawer),
      buttons,
      hasApiContractCopy: Boolean(drawer?.querySelector('[data-automation-action="copy-api-contract-curl"]')),
      hasEndpointCopy: Boolean(drawer?.querySelector('[data-automation-action="copy-endpoint-curl"]')),
      hasCliCopy: Boolean(drawer?.querySelector('[data-automation-action="copy-cli-command"]')),
      hasFooterCopy: Boolean(drawer?.querySelector('[data-automation-action="copy-context"]')),
      hasRecorderStart: Boolean(drawer?.querySelector('[data-automation-recorder-action="start"], [data-automation-recorder-action="stop"]')),
    };
  });
  if (!state.drawerPresent) {
    throw new Error(`${label} automation context drawer missing at ${viewport.name}`);
  }
  for (const [key, present] of Object.entries({
    hasApiContractCopy: state.hasApiContractCopy,
    hasEndpointCopy: state.hasEndpointCopy,
    hasCliCopy: state.hasCliCopy,
    hasFooterCopy: state.hasFooterCopy,
    hasRecorderStart: state.hasRecorderStart,
  })) {
    if (!present) {
      throw new Error(`${label} automation context missing ${key} at ${viewport.name}: ${JSON.stringify(state)}`);
    }
  }
  const invalid = state.buttons.filter((button) => button.type !== "button" || !button.title || !button.ariaLabel);
  if (invalid.length) {
    throw new Error(`${label} automation context action accessibility mismatch at ${viewport.name}: ${JSON.stringify({ invalid, state })}`);
  }
}

async function assertAutomationRecorderMultiRouteRunbook(page, viewport) {
  if (viewport.name !== "desktop") return;
  await closeActiveDrawer(page);
  await page.evaluate(() => {
    localStorage.removeItem("phragma.webui.automation-recorder.v1");
    globalThis.__automationContextCopiedText = "";
    const writeText = async (text) => {
      globalThis.__automationContextCopiedText = String(text || "");
    };
    try {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
      });
    } catch {
      try {
        navigator.clipboard.writeText = writeText;
      } catch {}
    }
  });

  await page.click("#open-automation");
  await waitForDrawerTitle(page, "API / CLI context");
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="start"]');
  await waitForRecorderStepCount(page, 0);
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="record-view"]');
  await waitForRecorderStepCount(page, 1);
  await closeActiveDrawer(page);

  const routes = [
    ["#/traffic?mode=flows&limit=100", "/traffic"],
    ["#/threats?limit=100", "/threats"],
    ["#/settings?panel=network", "/settings"],
  ];
  let expectedCount = 1;
  for (const [hash, path] of routes) {
    await page.evaluate((nextHash) => {
      location.hash = nextHash;
    }, hash);
    await waitForRouteReady(page, path);
    await page.click("#open-automation");
    await waitForDrawerTitle(page, "API / CLI context");
    const status = await page.locator('#drawer:not([hidden]) [data-automation-recorder="status"]').textContent();
    if (!/Recording/.test(status || "")) {
      throw new Error(`automation recorder did not persist active state on ${hash}`);
    }
    await page.click('#drawer:not([hidden]) [data-automation-recorder-action="record-view"]');
    expectedCount += 1;
    await waitForRecorderStepCount(page, expectedCount);
    await closeActiveDrawer(page);
  }

  await page.click("#open-automation");
  await waitForDrawerTitle(page, "API / CLI context");
  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="copy"]');
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const recordingJson = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationContextRedaction(recordingJson, "desktop multi-route automation recording JSON");
  const recordingPacket = JSON.parse(recordingJson);
  assertAutomationRecordingPacket(recordingPacket, "desktop copied multi-route automation recording", 4);
  const paths = recordingPacket.steps.map((step) => step.routeState?.path || step.session?.routeState?.path || "");
  for (const expectedPath of ["/", "/traffic", "/threats", "/settings"]) {
    if (!paths.includes(expectedPath)) {
      throw new Error(`multi-route automation recording missed ${expectedPath}: ${JSON.stringify(paths)}`);
    }
  }

  await page.evaluate(() => { globalThis.__automationContextCopiedText = ""; });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="copy-runbook"]');
  await page.waitForFunction(() => Boolean(globalThis.__automationContextCopiedText), null, { timeout: 5000 });
  const copiedRunbook = await page.evaluate(() => globalThis.__automationContextCopiedText || "");
  assertAutomationRecordingRunbookText(copiedRunbook, "desktop copied multi-route automation runbook", 4);
  for (const required of ["Dashboard", "Traffic", "Threat", "Settings", "ngfwctl", "curl -sk"]) {
    if (!copiedRunbook.includes(required)) {
      throw new Error(`desktop copied multi-route automation runbook missing ${required}`);
    }
  }

  const downloadPromise = page.waitForEvent("download", { timeout: 5000 });
  await page.click('#drawer:not([hidden]) [data-automation-recorder-action="download-runbook"]');
  const download = await downloadPromise;
  const filename = download.suggestedFilename();
  if (!/^phragma-automation-runbook-.+\.sh$/.test(filename || "")) {
    throw new Error(`desktop multi-route runbook download filename had unexpected shape: ${filename || "<none>"}`);
  }
  const downloadPath = await download.path();
  if (!downloadPath) {
    throw new Error("desktop multi-route runbook download did not produce a readable file");
  }
  const downloadedRunbook = await readFile(downloadPath, "utf8");
  assertAutomationRecordingRunbookText(downloadedRunbook, "desktop downloaded multi-route automation runbook", 4);
  assertAutomationContextRedaction(downloadedRunbook, "desktop downloaded multi-route automation runbook");
  await closeActiveDrawer(page);
}

async function waitForRecorderStepCount(page, expected) {
  await page.waitForFunction((count) => {
    return document
      .querySelector("#drawer:not([hidden]) [data-automation-recorder='step-count']")
      ?.textContent?.trim() === String(count);
  }, expected, { timeout: 5000 });
}

function assertAutomationRecordingPacket(packet, label, expectedSteps) {
  if (packet.schemaVersion !== "phragma.webui.automation-recorder.v1" ||
      packet.source !== "browser-local" ||
      packet.custody?.serverStored !== false ||
      packet.custody?.signed !== false ||
      packet.steps?.length !== expectedSteps ||
      !packet.steps.every((step) => step.session?.schemaVersion === "phragma.webui.workflow-session.v1")) {
    throw new Error(`${label} had unexpected packet shape: ${JSON.stringify(packet)}`);
  }
}

function assertAutomationRecordingRunbookText(text, label, expectedStepCount) {
  assertAutomationContextRedaction(text, label);
  const required = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "PHRAGMA_API_ORIGIN",
    "PHRAGMA_TOKEN",
    "/ui/api-spec.yaml",
    "phragma.webui.automation-recorder.v1",
    "not server-retained",
  ];
  for (const item of required) {
    if (!text.includes(item)) {
      throw new Error(`${label} missing ${item}`);
    }
  }
  const stepMatches = text.match(/^# Step \d+:/gm) || [];
  if (stepMatches.length !== expectedStepCount) {
    throw new Error(`${label} expected ${expectedStepCount} recorded steps, found ${stepMatches.length}`);
  }
}

async function closeActiveDrawer(page) {
  const open = await page.evaluate(() => Boolean(document.querySelector("#drawer:not([hidden])")));
  if (!open) return;
  await page.keyboard.press("Escape");
  await waitForDrawerClosed(page);
}

function assertAutomationContextRedaction(text, label) {
  const leaked = [
    /Bearer\s+(?!\$\{|\[redacted\])[A-Za-z0-9._~+/-]{12,}/i,
    /access[_-]?token=(?!\[redacted\])/i,
    /password=(?!\[redacted\])/i,
    /api[_-]?key=(?!\[redacted\])/i,
    /writer:secret/i,
    /https?:\/\/[^/\s"']+:[^@\s"']+@/i,
    /\/Users\/[^\s"',;}]+/i,
    /\/private\/tmp\/[^\s"',;}]+/i,
    /\/tmp\/[^\s"',;}]+/i,
  ].find((pattern) => pattern.test(text || ""));
  if (leaked) {
    throw new Error(`${label} leaked sensitive automation context: ${leaked}`);
  }
}

async function launchBrowser(playwright) {
  try {
    return {
      browser: await withSmokeTimeout(
        "Chromium launch",
        playwright.chromium.launch({ headless: true }),
        positiveIntEnv("WEBUI_SMOKE_BROWSER_LAUNCH_TIMEOUT_MS", 30000),
      ),
      error: null,
    };
  } catch (err) {
    const message = String(err?.message || err);
    if (/Executable doesn't exist|browserType.launch|Host system is missing dependencies/i.test(message)) {
      return { browser: null, error: err };
    }
    throw err;
  }
}

function criticalResourceType(type) {
  return ["document", "script", "stylesheet", "image", "font"].includes(type);
}

function isGenericResourceConsoleError(message = "") {
  return /^Failed to load resource:/i.test(String(message || ""));
}

function isHandledHTTPFailure(failure = "") {
  const text = String(failure || "");
  return /^fetch 403 .*\/v1\/system\/runtime-readiness:check(?:\?|$)/.test(text);
}

function envFlag(name) {
  const value = process.env[name];
  return value != null && value !== "" && !/^(0|false|no|off)$/i.test(String(value).trim());
}

function browserRequiredError(reason, cause) {
  const lines = [
    "WEBUI_SMOKE_REQUIRE_BROWSER=1 was set, so WebUI visual smoke must run in a real browser.",
    `Reason: ${reason}.`,
    "HTTP/static fallback was not run. Install Playwright plus a launchable Chromium browser in the CI image, or unset WEBUI_SMOKE_REQUIRE_BROWSER to allow fallback.",
  ];
  if (cause) lines.push(`Original error: ${String(cause?.message || cause).split("\n")[0]}`);
  const err = new Error(lines.join("\n"));
  err.messageOnly = true;
  return err;
}

async function runHTTPFallback(baseURL) {
  await assertAPISpecServed(baseURL);
  const checks = [
    ["index", baseURL, /<div id="app"/],
    ["app bootstrap", new URL("js/app.js", baseURL).toString(), /const NAV = \[/],
    ["stylesheet", new URL("css/app.css", baseURL).toString(), /\.content\b/],
  ];
  for (const screen of screens) {
    const viewName = screen.view || (screen.path === "/" ? "dashboard" : screen.path.slice(1));
    checks.push([`${screen.name} view`, new URL(`js/views/${viewName}.js`, baseURL).toString(), /export async function render/]);
  }

  for (const [label, url, pattern] of checks) {
    const response = await fetchText(url);
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`${label}: got HTTP ${response.status} from ${url}`);
    }
    if (!pattern.test(response.body)) {
      throw new Error(`${label}: response from ${url} did not match ${pattern}`);
    }
  }

  const app = await fetchText(new URL("js/app.js", baseURL).toString());
  if (!app.body.includes("Open API contract") || !app.body.includes("API_CONTRACT.path")) {
    throw new Error("command palette API contract action is missing from the WebUI bundle");
  }
  for (const screen of screens) {
    const pathNeedle = `path: "${screen.path}"`;
    const titleNeedle = `title: "${screen.navTitle || screen.name}`;
    if (!app.body.includes(pathNeedle) || !app.body.includes(titleNeedle)) {
      throw new Error(`${screen.name}: route is not present in WebUI NAV`);
    }
  }
}

async function assertAPISpecServed(baseURL) {
  const rootSpec = await fetchText(apiURL(baseURL, "/api-spec.yaml"));
  if (rootSpec.status !== 200) {
    throw new Error(`api spec root route returned HTTP ${rootSpec.status}`);
  }
  for (const pattern of [/swagger: "2\.0"/, /title: Phragma Control Plane API/, /\/v1\/system\/release-acceptance\/status:/, /\/v1\/auth\/oidc\/status:/, /\/v1\/auth\/saml\/status:/, /\/v1\/auth\/saml\/login:/, /\/v1\/auth\/saml\/acs:/, /\/v1\/auth\/logout:/, /X-Phragma-CSRF/, /BearerAuth:/]) {
    if (!pattern.test(rootSpec.body)) {
      throw new Error(`api spec root route did not match ${pattern}`);
    }
  }

  const uiSpec = await fetchText(new URL("api-spec.yaml", baseURL).toString());
  if (uiSpec.status !== 200) {
    throw new Error(`api spec UI asset returned HTTP ${uiSpec.status}`);
  }
  if (uiSpec.body !== rootSpec.body) {
    throw new Error("api spec root route and UI asset returned different content");
  }
}

async function startControld() {
  const grpcPort = await freePort();
  const httpPort = await freePort();
  const workDir = await mkdtemp(join(tmpdir(), "openngfw-webui-visual-smoke."));
  started.workDir = workDir;

  const dataDir = join(workDir, "data");
  const logDir = join(workDir, "log");
  started.logDir = logDir;
  const gocache = join(workDir, "go-cache");
  const usersFile = join(workDir, "users.yaml");
  smokeAdminToken = `phr_smoke_admin_${randomBytes(18).toString("base64url")}`;
  await writeFile(usersFile, `users:
  - name: visual-smoke-admin
    token: ${smokeAdminToken}
    role: admin
`, { encoding: "utf8", mode: 0o600 });
  oidcSmokeSecretFile = join(workDir, "oidc-client-secret");
  await writeFile(oidcSmokeSecretFile, "visual-smoke-oidc-secret\n", { encoding: "utf8", mode: 0o600 });
  oidcSmokeProvider = await startOIDCDiscoveryProvider();
  oidcSmokeIssuer = oidcSmokeProvider.issuer;
  await seedVisualSmokeContentPackages(dataDir);
  await seedInvestigationTelemetry(logDir);
  await seedPacketCaptureArtifacts(logDir);
  const ebpfFixture = requireEbpfRuntimeEvidence ? await seedEbpfRuntimeEvidenceFixture(workDir) : null;
  const controldPath = join(repoRoot, "bin", "controld");
  const explicitControld = process.env.WEBUI_SMOKE_CONTROLD || "";
  const useBuiltBinary = explicitControld || await executable(controldPath);
  const command = useBuiltBinary ? (explicitControld || controldPath) : "go";
  const args = useBuiltBinary ? [] : ["run", "./cmd/controld"];

  args.push(
    "--dry-run",
    "--users-file", usersFile,
    "--tls=false",
    "--listen", `127.0.0.1:${grpcPort}`,
    "--http-listen", `127.0.0.1:${httpPort}`,
    "--data-dir", dataDir,
    "--log-dir", logDir,
    "--rate-limit-rpm", "0",
  );
  if (ebpfFixture) {
    args.push(
      "--ebpf-runtime-probes",
      "--ebpf-attach-probe-interfaces", ebpfFixture.iface,
      "--ebpf-artifact-dir", ebpfFixture.artifactDir,
    );
  }

  started.detached = process.platform !== "win32";
  const env = { ...process.env, GOCACHE: gocache };
  if (ebpfFixture) {
    env.PATH = `${ebpfFixture.binDir}:${env.PATH || ""}`;
  }
  started.process = spawn(command, args, {
    cwd: repoRoot,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: started.detached,
  });

  let serverLog = "";
  started.process.stdout.on("data", (chunk) => { serverLog += chunk.toString(); });
  started.process.stderr.on("data", (chunk) => { serverLog += chunk.toString(); });

  const uiURL = normalizeUIURL(`http://127.0.0.1:${httpPort}/ui/`);
  try {
    await waitForStatus(uiURL, started.process);
  } catch (err) {
    const detail = serverLog.trim() ? `\n--- controld log ---\n${serverLog.split("\n").slice(-120).join("\n")}` : "";
    throw new Error(`${err.message}${detail}`);
  }
  return uiURL;
}

function seededTelemetryRoute(path) {
  return path === "/" || path === "/traffic" || path === "/threats" || path === "/logs";
}

async function ensureSeededInvestigationTelemetry() {
  if (!started.logDir) return;
  await seedInvestigationTelemetry(started.logDir);
}

async function seedEbpfRuntimeEvidenceFixture(workDir) {
  const binDir = join(workDir, "ebpf-bin");
  const artifactDir = join(workDir, "ebpf-artifacts");
  await mkdir(binDir, { recursive: true });
  await mkdir(artifactDir, { recursive: true });
  const commands = {
    bpftool: `#!/usr/bin/env sh
if [ "$1" = "net" ]; then
  cat <<'EOF'
xdp:
openngfw-ebpf0(2) prog/xdp id 10 name xdp_probe
tc:
openngfw-ebpf0(2) clsact/ingress prog/tc id 11 name tc_ingress
EOF
  exit 0
fi
printf 'bpftool v7.0.0 visual-smoke\\n'
`,
    clang: "#!/usr/bin/env sh\nprintf 'clang visual-smoke\\n'\n",
    tc: "#!/usr/bin/env sh\nprintf 'tc utility, iproute2 visual-smoke\\n'\n",
    ip: "#!/usr/bin/env sh\nprintf 'ip utility, iproute2 visual-smoke\\n'\n",
  };
  for (const [name, script] of Object.entries(commands)) {
    const path = join(binDir, name);
    await writeFile(path, script, { encoding: "utf8", mode: 0o700 });
    await chmod(path, 0o700);
  }
  await writeFile(join(artifactDir, "manifest.txt"), [
    "drill_schema=phragma.ebpf.ol9.attach-drill.v1",
    "interface=openngfw-ebpf0",
    "xdp_attach_result=passed",
    "tc_attach_result=passed",
    "active_dataplane=nftables/conntrack",
    "",
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  await writeFile(join(artifactDir, "ebpf-plan.txt"), [
    "state=planned",
    "authoritative_renderer=nftables",
    "supported_hooks=xdp,tc",
    "",
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  await writeFile(join(artifactDir, "system-status-ebpf.json"), JSON.stringify({
    state: "ready",
    attach_state: "ready",
    renderer_state: "planned",
    active_dataplane: "nftables/conntrack",
  }, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  return { binDir, artifactDir, iface: "openngfw-ebpf0" };
}

async function seedVisualSmokeContentPackages(dataDir) {
  const contentDir = join(dataDir, "content");
  const packageDir = join(contentDir, "app-id");
  const evidenceDir = join(packageDir, "evidence");
  await mkdir(join(contentDir, ".trust", "ed25519"), { recursive: true });
  await mkdir(evidenceDir, { recursive: true });

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const rawPublicKey = publicKeyDer.subarray(-32);
  await writeFile(join(contentDir, ".trust", "ed25519", "visual-smoke.b64"), rawPublicKey.toString("base64"), "utf8");

  const version = "1.2.3";
  const contentRaw = Buffer.from(JSON.stringify({ apps: ["corp-admin"], generated_by: "visual-smoke" }));
  await writeFile(join(packageDir, "content.json"), contentRaw);

  const evidenceSpecs = [
    ["app-taxonomy", { type: "app-taxonomy", status: "passed" }],
    ["confidence-model", { type: "confidence-model", status: "passed" }],
    ["app-regression-corpus", {
      type: "app-regression-corpus",
      status: "passed",
      package_version: version,
      samples: [
        {
          id: "corp-admin-login",
          pcap_sha256: "a".repeat(64),
          expected_app: "corp-admin",
          observed_app: "corp-admin",
          verdict: "passed",
        },
        {
          id: "corp-admin-api",
          pcap_sha256: "b".repeat(64),
          expected_app: "corp-admin-api",
          observed_app: "corp-admin-api",
          verdict: "passed",
        },
      ],
    }],
    ["license-review", { type: "license-review", status: "passed" }],
    ["staged-rollout", { type: "staged-rollout", status: "passed" }],
    ["rollback-drill", { type: "rollback-drill", status: "passed" }],
  ];
  const files = [{ path: "content.json", sha256: sha256Hex(contentRaw) }];
  const evidence = [];
  for (const [type, body] of evidenceSpecs) {
    const raw = Buffer.from(JSON.stringify(body));
    const artifact = `evidence/${type}.json`;
    await writeFile(join(packageDir, artifact), raw);
    const digest = sha256Hex(raw);
    files.push({ path: artifact, sha256: digest });
    evidence.push({ type, artifact, sha256: digest, generated_at: "2026-06-17T12:03:00Z" });
  }

  const manifest = {
    schema_version: "phragma.content.package.v1",
    kind: "app-id",
    name: "App-ID catalog",
    version,
    source: "visual smoke content seed",
    created_at: "2026-06-17T12:00:00Z",
    installed_at: "2026-06-17T12:05:00Z",
    files,
    regression: { status: "passed", corpus: "visual-smoke", passed: 1, run_at: "2026-06-17T12:04:00Z" },
    rollout: { state: "stable", scope: "all" },
    rollback: { available: true },
    provenance: [{
      name: "Phragma visual smoke",
      url: "https://example.invalid/phragma/visual-smoke",
      license: "Apache-2.0",
      allows_commercial_use: true,
      allows_redistribution: true,
    }],
    content_readiness: {
      scope: "production",
      production_content: true,
      required_production_evidence: evidenceSpecs.map(([type]) => type),
      evidence,
    },
  };
  const signaturePayload = Buffer.from(JSON.stringify(manifest));
  const signature = sign(null, signaturePayload, privateKey);
  manifest.signature = {
    algorithm: "ed25519",
    key_id: "visual-smoke",
    public_key: rawPublicKey.toString("base64"),
    signature: signature.toString("base64"),
  };
  await writeFile(join(packageDir, "manifest.json"), JSON.stringify(manifest, null, 2));
}

function sha256Hex(raw) {
  return createHash("sha256").update(raw).digest("hex");
}

async function seedInvestigationTelemetry(logDir) {
  await mkdir(logDir, { recursive: true });
  const flow = {
    timestamp: "2026-06-18T12:00:00.000001+0000",
    event_type: "flow",
    flow_id: investigationSeed.flowId,
    src_ip: investigationSeed.srcIp,
    src_port: investigationSeed.srcPort,
    dest_ip: investigationSeed.destIp,
    dest_port: investigationSeed.destPort,
    proto: investigationSeed.protocol,
    app_proto: investigationSeed.appProto,
    flow: {
      pkts_toserver: 3,
      pkts_toclient: 4,
      bytes_toserver: 512,
      bytes_toclient: 2048,
    },
  };
  const alert = {
    timestamp: "2026-06-18T12:00:01.000001+0000",
    event_type: "alert",
    flow_id: investigationSeed.flowId,
    src_ip: investigationSeed.srcIp,
    src_port: investigationSeed.srcPort,
    dest_ip: investigationSeed.destIp,
    dest_port: investigationSeed.destPort,
    proto: investigationSeed.protocol,
    alert: {
      action: "blocked",
      signature_id: investigationSeed.signatureId,
      signature: investigationSeed.signature,
      category: "Misc Attack",
      severity: 1,
    },
  };
  const appIdQueueFlow = {
    timestamp: "2026-06-18T12:00:02.000001+0000",
    event_type: "flow",
    flow_id: appIdQueueSeed.flowId,
    src_ip: appIdQueueSeed.srcIp,
    src_port: appIdQueueSeed.srcPort,
    dest_ip: appIdQueueSeed.destIp,
    dest_port: appIdQueueSeed.destPort,
    proto: appIdQueueSeed.protocol,
    app_proto: appIdQueueSeed.appProto,
    flow: {
      pkts_toserver: 5,
      pkts_toclient: 7,
      bytes_toserver: 1536,
      bytes_toclient: 4096,
    },
  };
  await writeFile(join(logDir, "eve.json"), `${JSON.stringify(flow)}\n${JSON.stringify(alert)}\n${JSON.stringify(appIdQueueFlow)}\n`, "utf8");
  await writeFile(join(logDir, "suricata.log"), `${JSON.stringify({
    timestamp: "2026-06-18T12:00:03Z",
    level: "warning",
    facility: "engine.runtime",
    message: `suricata engine degraded Authorization: Bearer abc.def.ghi access_token=writer-secret flow_id=${investigationSeed.flowId} src_ip=${investigationSeed.srcIp} src_port=${investigationSeed.srcPort} dest_ip=${investigationSeed.destIp} dest_port=${investigationSeed.destPort} proto=${investigationSeed.protocol} app_proto=${investigationSeed.appProto} signature_id=${investigationSeed.signatureId} path=/var/log/openngfw/secrets.log`,
  })}\n`, "utf8");
  seededInvestigationTelemetry = true;
}

async function seedPacketCaptureArtifacts(logDir) {
  const captureDir = join(logDir, "pcap");
  await mkdir(captureDir, { recursive: true });
  const pcapPath = join(captureDir, captureArtifactSeed.filename);
  const raw = Buffer.concat([
    Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from("visual smoke packet capture\n", "utf8"),
  ]);
  const sha256 = sha256Hex(raw);
  await writeFile(pcapPath, raw);
  const plan = {
    interface: "any",
    protocol: "PROTOCOL_TCP",
    srcIp: investigationSeed.srcIp,
    srcPort: investigationSeed.srcPort,
    destIp: investigationSeed.destIp,
    destPort: investigationSeed.destPort,
    durationSeconds: 20,
    packetCount: 500,
    snaplenBytes: 256,
    flowId: investigationSeed.flowId,
    outputPath: pcapPath,
    bpfFilter: `tcp and src host ${investigationSeed.srcIp} and src port ${investigationSeed.srcPort} and dst host ${investigationSeed.destIp} and dst port ${investigationSeed.destPort}`,
    command: `tcpdump -i any -w ${pcapPath} -G 20 -W 1 -c 500 -s 256 tcp and src host ${investigationSeed.srcIp} and src port ${investigationSeed.srcPort} and dst host ${investigationSeed.destIp} and dst port ${investigationSeed.destPort}`,
    commandArgv: ["tcpdump", "-i", "any", "-w", pcapPath, "-G", "20", "-W", "1", "-c", "500", "-s", "256", "tcp"],
  };
  await writeFile(join(captureDir, `${captureArtifactSeed.filename}.json`), JSON.stringify({
    id: "pcap-visual-lifecycle-001",
    state: "completed",
    detail: "visual smoke completed packet capture fixture",
    plan,
    completedAt: captureArtifactSeed.completedAt,
    bytesWritten: raw.length,
    sha256,
  }, null, 2), "utf8");
}

async function waitForStatus(baseURL, child) {
  const deadline = Date.now() + 60000;
  let lastError = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`controld exited with status ${child.exitCode}`);
    }
    try {
      const response = await fetchText(
        apiURL(baseURL, "/v1/system/status"),
        0,
        smokeAdminToken ? { Authorization: `Bearer ${smokeAdminToken}` } : {},
      );
      if (response.status === 200 && /"dryRun"\s*:\s*true/.test(response.body)) return;
    } catch (err) {
      lastError = err;
    }
    await sleep(500);
  }
  throw new Error(`timed out waiting for controld (${lastError?.message || "no response"})`);
}

async function executable(path) {
  try {
    const fs = await import("node:fs/promises");
    await fs.access(path, 0o111);
    return true;
  } catch {
    return false;
  }
}

async function freePort() {
  return await new Promise((resolvePromise, rejectPromise) => {
    const server = createServer();
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolvePromise(address.port));
    });
  });
}

async function startOIDCDiscoveryProvider() {
  const port = await freePort();
  const issuer = `http://127.0.0.1:${port}`;
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const signingKey = { ...jwk, kid: "oidc-visual-smoke-key", alg: "RS256", use: "sig" };
  const server = createHttpServer((req, res) => {
    let body = null;
    if (req.url === "/.well-known/openid-configuration") {
      body = {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      };
    } else if (req.url === "/jwks") {
      body = { keys: [signingKey] };
    }
    if (!body) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(port, "127.0.0.1", resolvePromise);
  });
  return { issuer, server };
}

async function fetchText(url, redirects = 0, headers = {}) {
  const target = new URL(url);
  const transport = target.protocol === "https:" ? httpsRequest : httpRequest;
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = transport(target, {
      rejectUnauthorized: false,
      timeout: 15000,
      headers: { "User-Agent": "openngfw-webui-visual-smoke", ...headers },
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", async () => {
        const status = res.statusCode || 0;
        const location = res.headers.location;
        if ([301, 302, 303, 307, 308].includes(status) && location && redirects < 5) {
          try {
            resolvePromise(await fetchText(new URL(location, target).toString(), redirects + 1, headers));
          } catch (err) {
            rejectPromise(err);
          }
          return;
        }
        resolvePromise({ status, body });
      });
    });
    req.on("timeout", () => req.destroy(new Error(`timeout fetching ${url}`)));
    req.on("error", rejectPromise);
    req.end();
  });
}

function routeURL(baseURL, path) {
  const url = new URL(baseURL);
  url.hash = "#" + path;
  return url.toString();
}

function apiURL(baseURL, path) {
  const url = new URL(baseURL);
  url.pathname = path;
  url.search = "";
  url.hash = "";
  return url.toString();
}

function normalizeUIURL(value) {
  const url = new URL(value);
  if (!url.pathname || url.pathname === "/") {
    url.pathname = "/ui/";
  } else if (!url.pathname.endsWith("/")) {
    url.pathname += "/";
  }
  if (!url.pathname.endsWith("/ui/")) {
    url.pathname = "/ui/";
  }
  url.search = "";
  url.hash = "";
  return url.toString();
}

function formatFailure(screen, viewport, detail) {
  return `- ${screen.name} @ ${viewport.name} ${viewport.width}px: ${detail}`;
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function cleanup() {
  if (started.process && started.process.exitCode === null) {
    signalStartedProcess("SIGTERM");
    await new Promise((resolvePromise) => {
      const timer = setTimeout(() => {
        signalStartedProcess("SIGKILL");
        resolvePromise();
      }, 3000);
      started.process.once("exit", () => {
        clearTimeout(timer);
        resolvePromise();
      });
    });
    started.process.stdout?.destroy();
    started.process.stderr?.destroy();
  }
  if (oidcSmokeProvider?.server) {
    try {
      await new Promise((resolvePromise) => oidcSmokeProvider.server.close(() => resolvePromise()));
    } catch {}
    oidcSmokeProvider = null;
    oidcSmokeIssuer = "";
    oidcSmokeSecretFile = "";
  }
  if (started.workDir) {
    await rm(started.workDir, { recursive: true, force: true });
    started.workDir = "";
  }
}

function signalStartedProcess(signal) {
  if (!started.process?.pid) return;
  try {
    if (started.detached) {
      process.kill(-started.process.pid, signal);
    } else {
      started.process.kill(signal);
    }
  } catch {
    try {
      started.process.kill(signal);
    } catch {}
  }
}

withSmokeTimeout("WebUI visual smoke total runtime", main(), totalTimeoutMs).catch(async (err) => {
  const message = `- run @ total ${formatDuration(totalTimeoutMs)}: ${err?.message || err}`;
  if (smokeRun.artifactDir && !smokeRun.manifestPath) {
    smokeRun.failureRecords.push({
      route: "<run>",
      routeName: "WebUI visual smoke",
      viewport: "<all>",
      width: 0,
      detail: String(err?.message || err),
      message,
      stage: smokeStage,
      active: smokeProgress.currentLabel,
      artifact: "",
    });
    await writeSmokeEvidenceManifest(smokeRun.artifactDir, [message]).catch(() => {});
  }
  await cleanup();
  console.error(`[webui-smoke] last stage: ${smokeStage}`);
  console.error(`[webui-smoke] progress: ${smokeProgressSummary()}`);
  console.error(err?.messageOnly ? err.message : err?.stack || err?.message || String(err));
  process.exit(1);
});

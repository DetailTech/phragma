export function hostInputManagementCoverage(policy = {}, status = {}) {
  const host = policy.hostInput || {};
  if (hostInputDefault(host) !== "ACTION_DENY") {
    return {
      state: "open",
      cls: "warn",
      title: "Host input is allow-by-default.",
      detail: "Set default drop and add explicit SSH/WebUI management allows before exposing the appliance.",
      requiredServices: managementRequirements(status),
      allowRules: [],
    };
  }

  const allowRules = (host.rules || []).filter((rule) => !rule.disabled && rule.action === "ACTION_ALLOW");
  const requirements = managementRequirements(status);
  if (!allowRules.length) {
    return lockoutResult(requirements, "No enabled host-input allow rule exists.");
  }

  const services = new Map((policy.services || []).map((svc) => [svc.name, svc]));
  const matching = allowRules.filter((rule) => ruleCoversRequirements(rule, services, requirements));
  if (!matching.length) {
    return lockoutResult(requirements, "Enabled allow rules do not cover SSH plus the WebUI/API listener.");
  }
  if (matching.some((rule) => ruleUnverified(rule, services))) {
    return {
      state: "unverified",
      cls: "warn",
      title: "Management allow coverage is unverified.",
      detail: "At least one enabled allow rule references a service object that is missing or cannot be resolved before validation.",
      requiredServices: requirements,
      allowRules: matching.map((rule) => rule.name || "unnamed"),
    };
  }
  if (matching.some((rule) => ruleOverbroad(rule, services))) {
    return {
      state: "overbroad",
      cls: "warn",
      title: "Management path is covered, but the allow is broad.",
      detail: "Restrict the host-input allow rule to management zones, source address objects, and SSH/WebUI services before production exposure.",
      requiredServices: requirements,
      allowRules: matching.map((rule) => rule.name || "unnamed"),
    };
  }
  return {
    state: "covered",
    cls: "ok",
    title: "Management path coverage is explicit.",
    detail: "Default-deny host input has enabled allow coverage for SSH and WebUI/API services.",
    requiredServices: requirements,
    allowRules: matching.map((rule) => rule.name || "unnamed"),
  };
}

export function managementRuleTemplate(policy = {}, status = {}) {
  const zones = (policy.zones || []).map((zone) => zone.name).filter(Boolean);
  const serviceNames = preferredManagementServices(policy, status);
  return {
    name: "allow-management",
    fromZones: zones.length ? [zones[0]] : [],
    sourceAddresses: [],
    services: serviceNames.length ? serviceNames : [],
    action: "ACTION_ALLOW",
    log: true,
    disabled: false,
    description: "Explicit management access for default-deny host input. Restrict source addresses before production exposure.",
  };
}

function hostInputDefault(host = {}) {
  return host.defaultAction || "ACTION_ALLOW";
}

function lockoutResult(requirements, detail) {
  return {
    state: "lockout",
    cls: "bad",
    title: "Management lockout likely.",
    detail,
    requiredServices: requirements,
    allowRules: [],
  };
}

function managementRequirements(status = {}) {
  const httpPort = parseListenPort(status.runtime?.httpListen) || 8080;
  return [
    { key: "ssh", label: "SSH", protocol: "PROTOCOL_TCP", port: 22 },
    { key: "webui", label: "WebUI/API", protocol: "PROTOCOL_TCP", port: httpPort },
  ];
}

function preferredManagementServices(policy = {}, status = {}) {
  const services = new Map((policy.services || []).map((svc) => [svc.name, svc]));
  const names = [];
  for (const req of managementRequirements(status)) {
    const exact = [...services.values()].find((svc) => serviceCoversRequirement(svc, req));
    if (exact?.name && !names.includes(exact.name)) names.push(exact.name);
  }
  return names.length ? names : ["ssh", "webui"];
}

function ruleCoversRequirements(rule, services, requirements) {
  return requirements.every((req) => ruleCoversRequirement(rule, services, req));
}

function ruleCoversRequirement(rule, services, req) {
  const refs = rule.services || [];
  if (!refs.length || refs.includes("any")) return true;
  return refs.some((ref) => {
    const svc = services.get(ref);
    return svc ? serviceCoversRequirement(svc, req) : false;
  });
}

function serviceCoversRequirement(service, req) {
  const protocol = service.protocol || "PROTOCOL_ANY";
  if (protocol !== "PROTOCOL_ANY" && protocol !== req.protocol) return false;
  const ports = service.ports || [];
  if (!ports.length) return true;
  return ports.some((port) => {
    const start = Number(port.start || 0);
    const end = Number(port.end || 0) || start;
    return start <= req.port && req.port <= end;
  });
}

function ruleUnverified(rule, services) {
  return (rule.services || []).some((ref) => ref && ref !== "any" && !services.has(ref));
}

function ruleOverbroad(rule, services) {
  if (!(rule.fromZones || []).length) return true;
  if (!(rule.sourceAddresses || []).length) return true;
  const refs = rule.services || [];
  if (!refs.length || refs.includes("any")) return true;
  return refs.some((ref) => {
    const svc = services.get(ref);
    return svc && serviceOverbroad(svc);
  });
}

function serviceOverbroad(service) {
  if ((service.protocol || "PROTOCOL_ANY") === "PROTOCOL_ANY") return true;
  return !(service.ports || []).length;
}

function parseListenPort(value) {
  const raw = String(value || "").trim();
  if (!raw) return 0;
  const match = raw.match(/:(\d+)$/) || raw.match(/^(\d+)$/);
  const port = match ? Number(match[1]) : 0;
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 0;
}

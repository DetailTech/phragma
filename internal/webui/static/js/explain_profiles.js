export function natProfileLines(profile = {}) {
  const p = profile || {};
  const dest = p.destination || {};
  const source = p.source || {};
  const lines = [];

  if (dest.evaluated || dest.matched || dest.reason) {
    if (dest.matched) {
      lines.push(`destination NAT ${dest.matchedRule || "matched"}: ${endpoint(dest.originalDestinationIp, dest.originalDestinationPort)} -> ${endpoint(dest.translatedDestinationIp, dest.translatedDestinationPort)}`);
    } else {
      lines.push(`destination NAT: ${dest.reason || "no match"}`);
    }
  }

  if (source.evaluated || source.matched || source.reason) {
    if (source.matched) {
      const translated = source.masquerade ? "masquerade" : source.translatedSourceIp || "translated source unknown";
      lines.push(`source NAT ${source.matchedRule || "matched"}: ${source.originalSourceIp || "source"} -> ${translated}`);
    } else if (source.evaluated) {
      lines.push(`source NAT: ${source.reason || "no match"}`);
    } else {
      lines.push(`source NAT: ${source.reason || "not evaluated"}`);
    }
  }

  return lines;
}

export function natProfileSummary(profile = {}) {
  const dest = profile?.destination || {};
  const source = profile?.source || {};
  if (dest.matched && source.matched) return "DNAT + SNAT";
  if (dest.matched) return "DNAT";
  if (source.matched) return "SNAT";
  if (dest.evaluated || source.evaluated) return "no NAT match";
  return "not evaluated";
}

export function natEvidence(profile = {}) {
  return Array.from(new Set([
    ...(profile?.evidence || []),
    ...(profile?.destination?.evidence || []),
    ...(profile?.source?.evidence || []),
  ].filter(Boolean)));
}

function endpoint(ip, port) {
  const value = String(ip || "").trim();
  const n = Number(port || 0);
  return n > 0 ? `${value}:${n}` : value || "-";
}

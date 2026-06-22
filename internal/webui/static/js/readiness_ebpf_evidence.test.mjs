import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("./views/readiness.js", import.meta.url), "utf8");

assert.match(source, /readinessEbpfEvidenceAction:\s*"field-evidence"/);
assert.match(source, /href:\s*"#\/readiness\?packet=ebpf-ol9-field-evidence"/);
assert.match(source, /Field evidence/);
assert.match(source, /readinessEbpfTable:\s*"probes"/);
assert.match(source, /readiness-ebpf-probe-table/);
assert.match(source, /readinessEbpfProbe:\s*key/);
assert.match(source, /responsiveTable\(\["Scope", "Probe", "Key", "State", "Detail"\]/);
assert.match(source, /class:\s*"row-actions readiness-ebpf-actions"/);
assert.match(source, /class:\s*"release-acceptance-problem-list readiness-ebpf-blockers"/);
assert.doesNotMatch(source, /class:\s*"row-actions",\s*style:\s*\{\s*marginTop:\s*"12px"\s*\}/);
assert.match(source, /readiness-ebpf-attachment-table/);
assert.match(source, /readinessEbpfTable:\s*"attachments"/);
assert.match(source, /responsiveTable\(\["Interface \/ hook", "Program", "State", "Detail"\]/);
assert.match(source, /labeledCell\("Interface \/ hook"/);
assert.match(source, /labeledCell\("Program"/);
assert.match(source, /readiness-ebpf-artifact-table/);
assert.match(source, /readinessEbpfTable:\s*"artifacts"/);
assert.match(source, /responsiveTable\(\["Artifact", "Path", "State", "Digest"\]/);
assert.match(source, /labeledCell\("Artifact"/);
assert.match(source, /labeledCell\("Digest"/);

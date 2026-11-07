const wasm = require("./wasm/tidemark.js");

const SEVERITY = ["info", "low", "medium", "high", "critical"];

async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

async function account(url, key) {
  const r = await rpc(url, "getAccountInfo", [key, { encoding: "base64", commitment: "finalized" }]);
  if (!r.value) throw new Error(`account ${key} not found`);
  return { owner: r.value.owner, data: Buffer.from(r.value.data[0], "base64") };
}

const LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";

async function fetchDeployed(url, programId) {
  const prog = await account(url, programId);
  if (prog.owner !== LOADER) {
    throw new Error(`${programId} is not an upgradeable program (owner ${prog.owner})`);
  }
  const pdKey = wasm.programDataAddress(prog.data);
  const pd = await account(url, pdKey);
  if (pd.owner !== LOADER) throw new Error(`ProgramData ${pdKey} is not owned by the loader`);
  const info = JSON.parse(wasm.deployedInfo(pd.data));
  return { ...info, programData: pdKey, elf: wasm.deployedElf(pd.data) };
}

function review(oldBytes, newBytes) {
  return JSON.parse(wasm.review(oldBytes, newBytes));
}

function format(result, hunks = 3) {
  const r = result.report;
  const out = [
    `Tidemark upgrade review  (${r.rules_version})`,
    `  old  ${r.old.sha256.slice(0, 16)}  ${r.old.instructions} insns`,
    `  new  ${r.new.sha256.slice(0, 16)}  ${r.new.instructions} insns`,
    `  changed instructions: ${r.changed_instructions} (${r.churn_pct}%)`,
    `  overall risk: ${r.risk.toUpperCase()}`,
    "",
  ];
  for (const f of r.findings) {
    out.push(`[${f.severity.toUpperCase().padEnd(8)}] ${f.id}  ${f.title}`);
    for (const d of f.detail) out.push(`             ${d}`);
  }
  if (!r.findings.length) out.push("No findings. Nothing obvious changed.");
  for (const h of r.hunks.slice(0, hunks)) {
    out.push("", `@@ old ${h.old_start.toString(16)} / new ${h.new_start.toString(16)} @@`);
    out.push(...h.lines.slice(0, 30));
  }
  out.push("", `verdict hash  ${result.verdict_hash}`);
  return out.join("\n");
}

function atLeast(risk, gate) {
  return SEVERITY.indexOf(risk) >= SEVERITY.indexOf(gate);
}

module.exports = { fetchDeployed, review, format, atLeast, rulesVersion: wasm.rulesVersion };

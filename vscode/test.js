const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { review, format, atLeast, fetchDeployed, rulesVersion } = require("./review.js");

const fixture = (n) => fs.readFileSync(path.join(__dirname, "..", "fixtures", n));
const v1 = fixture("demo_vault_v1.so");
const v2 = fixture("demo_vault_v2.so");

const r = review(v1, v2);
assert.equal(r.report.risk, "high");
assert.equal(r.report.rules_version, rulesVersion());
const text = format(r);
assert.match(text, /9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin/);
assert.match(text, /withdraw: ConstraintHasOne \(2001\): 1 → 0 check sites/);
assert.match(text, /\+ sweep/);
assert.equal(review(v1, v1).report.findings.length, 0);
assert.ok(atLeast("high", "high") && atLeast("critical", "medium") && !atLeast("low", "high"));

const registered = [];
const fakeVscode = {
  window: { createOutputChannel: () => ({ dispose() {} }) },
  commands: { registerCommand: (id) => (registered.push(id), { dispose() {} }) },
  workspace: { getConfiguration: () => ({ get: () => undefined }) },
};
const resolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  return req === "vscode" ? "vscode" : resolve.call(this, req, ...rest);
};
require.cache.vscode = { id: "vscode", filename: "vscode", loaded: true, exports: fakeVscode };
const ext = require("./extension.js");
const ctx = { subscriptions: [] };
ext.activate(ctx);
assert.deepEqual(registered.sort(), ["tidemark.reviewDeployed", "tidemark.reviewFiles"]);
assert.equal(ctx.subscriptions.length, 3);

async function live() {
  const d = await fetchDeployed("https://api.devnet.solana.com", "5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3");
  assert.deepEqual(Buffer.from(d.elf), v2);
  assert.equal(review(v1, d.elf).report.risk, "high");
  console.log("live ok, slot", d.slot, "authority", d.authority);
}

(process.env.TIDEMARK_LIVE ? live() : Promise.resolve()).then(() => console.log("ok"));

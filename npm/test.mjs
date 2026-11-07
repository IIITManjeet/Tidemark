import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { initSync, review, inspect, rulesVersion, verifyLedger } from "./dist/tidemark.js";

const here = (p) => new URL(p, import.meta.url);
initSync({ module: readFileSync(here("./dist/tidemark_bg.wasm")) });

const v1 = readFileSync(here("../fixtures/demo_vault_v1.so"));
const v2 = readFileSync(here("../fixtures/demo_vault_v2.so"));
const saved = JSON.parse(readFileSync(here("../fixtures/demo_report.json"), "utf8"));

const r = JSON.parse(review(v1, v2));
assert.equal(r.report.risk, "high");
assert.deepEqual(r.report.findings, saved.findings);
assert.equal(r.report.rules_version, rulesVersion());
assert.match(r.verdict_hash, /^[0-9a-f]{64}$/);

const info = JSON.parse(inspect(v2));
assert.ok(info.handlers.some((h) => h.name === "sweep"));

assert.throws(() => review(new Uint8Array(10), v2));
assert.throws(() => verifyLedger("{}"));
console.log("ok", r.verdict_hash.slice(0, 16));

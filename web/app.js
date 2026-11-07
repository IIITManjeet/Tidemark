import init, { review, rulesVersion } from "./npm/dist/tidemark.js";
import { fetchLedger } from "./npm/ledger.js";

const $ = (id) => document.getElementById(id);
const RISKS = ["info", "low", "medium", "high", "critical"];
const files = { old: null, new: null };

const ready = init().then(() => {
  $("rules").textContent = rulesVersion();
});

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const k of kids) n.append(k);
  return n;
}

function short(s, n = 8) {
  return s.length > 2 * n ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

function showError(id, msg) {
  const e = $(id);
  e.textContent = msg;
  e.hidden = !msg;
}

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) {
      const on = t === tab;
      t.setAttribute("aria-selected", on);
      $(t.dataset.tab).hidden = !on;
    }
  });
}

function setFile(side, name, bytes) {
  files[side] = bytes;
  const d = document.querySelector(`.drop[data-side="${side}"]`);
  d.classList.add("filled");
  d.querySelector(".drop-v").textContent = name;
  d.querySelector(".drop-meta").textContent = `${(bytes.length / 1024).toFixed(1)} KiB`;
  $("run").disabled = !(files.old && files.new);
}

async function readFile(side, file) {
  setFile(side, file.name, new Uint8Array(await file.arrayBuffer()));
}

for (const drop of document.querySelectorAll(".drop")) {
  const side = drop.dataset.side;
  const input = drop.querySelector("input");
  input.addEventListener("change", () => input.files[0] && readFile(side, input.files[0]));
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const f = e.dataTransfer.files[0];
    if (f) readFile(side, f);
  });
}

function renderReview(r) {
  const rep = r.report;
  const risk = $("risk");
  risk.className = `risk risk-${rep.risk}`;
  risk.replaceChildren(el("small", {}, "Overall risk"), el("b", {}, rep.risk.toUpperCase()));
  $("changed").replaceChildren(
    `${rep.changed_instructions} instructions`,
    el("small", { class: "sub" }, `${rep.churn_pct}% of the program`),
  );
  $("old-sha").textContent = short(rep.old.sha256);
  $("new-sha").textContent = short(rep.new.sha256);
  $("verdict").textContent = short(r.verdict_hash);
  $("verdict").title = r.verdict_hash;

  const list = $("findings");
  list.replaceChildren();
  if (!rep.findings.length) {
    list.append(el("li", { class: "finding glass" }, "No findings. Nothing obvious changed."));
  }
  for (const f of rep.findings) {
    const hot = f.severity === "high" || f.severity === "critical";
    const detail = el("ul");
    for (const d of f.detail) detail.append(el("li", {}, d));
    list.append(
      el(
        "li",
        { class: `finding glass${hot ? " hot" : ""}` },
        el(
          "header",
          {},
          el("span", { class: `sev sev-${f.severity}` }, f.severity),
          el("span", { class: "title" }, f.title),
          el("span", { class: "id" }, f.id),
        ),
        detail,
      ),
    );
  }

  const hunks = $("hunks");
  hunks.replaceChildren();
  rep.hunks.forEach((h, i) => {
    const pre = el("pre");
    for (const line of h.lines) {
      const kind = line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "ctx";
      pre.append(el("span", { class: kind }, line));
    }
    const added = h.lines.filter((l) => l.startsWith("+")).length;
    const removed = h.lines.filter((l) => l.startsWith("-")).length;
    const d = el(
      "details",
      { class: "hunk glass" },
      el("summary", {}, `@@ old ${h.old_start.toString(16)} / new ${h.new_start.toString(16)}  +${added} −${removed}`),
      pre,
    );
    if (i < 2) d.open = true;
    hunks.append(d);
  });
  $("result").hidden = false;
}

$("run").addEventListener("click", async () => {
  showError("review-error", "");
  await ready;
  try {
    renderReview(JSON.parse(review(files.old, files.new)));
  } catch (e) {
    $("result").hidden = true;
    showError("review-error", `Could not review: ${e.message ?? e}`);
  }
});

$("demo").addEventListener("click", async () => {
  showError("review-error", "");
  try {
    for (const [side, name] of [["old", "demo_vault_v1.so"], ["new", "demo_vault_v2.so"]]) {
      const res = await fetch(`fixtures/${name}`);
      if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
      setFile(side, name, new Uint8Array(await res.arrayBuffer()));
    }
    $("run").click();
  } catch (e) {
    showError("review-error", `Could not load the demo: ${e.message ?? e}`);
  }
});

function explorer(kind, key) {
  return `https://explorer.solana.com/${kind}/${key}?cluster=devnet`;
}

function sameChain(a, b) {
  const hashes = (v) => v.entries.map((e) => e.entry_hash).join(",");
  return a.registry.head === b.registry.head && a.registry.count === b.registry.count && hashes(a) === hashes(b);
}

function renderLedger(v, rpcs) {
  const chain = $("chain");
  chain.className = `risk ${v.ok ? "risk-ok" : "risk-bad"}`;
  const note = !v.ok
    ? v.error
    : rpcs > 1
      ? `links, addresses and quorums check out; ${rpcs} RPCs agree on the head`
      : "links, addresses and quorums check out, as served by this one RPC";
  chain.replaceChildren(el("small", {}, "Chain"), el("b", {}, v.ok ? "VERIFIED" : "BROKEN"), el("small", {}, note));
  $("count").textContent = v.registry.count;
  $("quorum").textContent = `${v.registry.threshold} of ${v.registry.active_reviewers}`;
  $("authority").textContent = short(v.registry.authority, 6);
  $("head").textContent = short(v.registry.head);
  $("head").title = v.registry.head;

  const body = $("entries");
  body.replaceChildren();
  if (!v.entries.length) {
    body.append(el("tr", {}, el("td", { colspan: "7" }, "No attestations yet.")));
  }
  for (const e of v.entries) {
    const risk = RISKS[e.risk] ?? "info";
    const link = el("a", { href: explorer("address", e.program), target: "_blank", rel: "noopener" }, short(e.program, 6));
    body.append(
      el(
        "tr",
        {},
        el("td", {}, String(e.index)),
        el("td", { class: "mono" }, link),
        el("td", {}, el("span", { class: `sev sev-${risk}` }, risk)),
        el("td", {}, `${e.approvals}/${e.threshold}${e.final ? " · final" : ""}`),
        el("td", { class: "mono" }, e.rules_version),
        el("td", { class: "mono" }, String(e.slot)),
        el("td", { class: "mono", title: e.verdict_hash }, short(e.verdict_hash)),
      ),
    );
  }
  $("ledger-result").hidden = false;
}

$("ledger-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError("ledger-error", "");
  const form = new FormData(ev.target);
  const btn = ev.target.querySelector("button");
  btn.disabled = true;
  btn.textContent = "Verifying…";
  try {
    await ready;
    const ledger = form.get("ledger").trim();
    const registry = form.get("registry").trim();
    const urls = [form.get("rpc").trim(), form.get("rpc2").trim()].filter(Boolean);
    const views = await Promise.all(urls.map((u) => fetchLedger(u, ledger, registry)));
    const [v] = views;
    if (views.length > 1 && !sameChain(views[0], views[1])) {
      v.ok = false;
      v.error = "the two RPCs disagree about this chain; trust neither";
    }
    renderLedger(v, views.length);
  } catch (e) {
    $("ledger-result").hidden = true;
    showError("ledger-error", `Could not verify: ${e.message ?? e}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Fetch and verify";
  }
});

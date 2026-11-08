"use client";

import { useState } from "react";
import { asset, review } from "@/lib/engine";
import { short } from "@/lib/ledger";
import type { Hunk, Review } from "@/lib/types";
import { Drop, type Picked } from "./Drop";
import { JudgePanel } from "./JudgePanel";
import { Button, ErrorNote, Headline, Hero, SectionTitle, Sev, Stat, Summary } from "./ui";

const DEMO = ["demo_vault_v1.so", "demo_vault_v2.so"] as const;

function HunkView({ hunk, open }: { hunk: Hunk; open: boolean }) {
  const added = hunk.lines.filter((l) => l.startsWith("+")).length;
  const removed = hunk.lines.filter((l) => l.startsWith("-")).length;
  return (
    <details open={open} className="rounded-2xl border border-line bg-bg/60 group overflow-hidden">
      <summary className="cursor-pointer list-none border-line bg-panel-2 px-4 py-2.5 font-mono text-[12.5px] text-muted group-open:border-b [&::-webkit-details-marker]:hidden">
        <span className="text-faint group-open:hidden">{"▸ "}</span>
        <span className="hidden text-faint group-open:inline">{"▾ "}</span>
        {`@@ old ${hunk.old_start.toString(16)} / new ${hunk.new_start.toString(16)}  +${added} −${removed}`}
      </summary>
      <pre className="m-0 max-h-[420px] overflow-auto pt-1.5 pb-2.5 font-mono text-[12.5px] leading-5">
        {hunk.lines.map((line, i) => {
          const tone = line.startsWith("+")
            ? "border-accent bg-accent/10 text-[#cfdcf7]"
            : line.startsWith("-")
              ? "border-orange bg-orange/10 text-[#f0d2bd]"
              : "border-transparent text-faint";
          return (
            <span key={i} className={`block h-5 border-l-2 px-4 whitespace-pre ${tone}`}>
              {line}
            </span>
          );
        })}
      </pre>
    </details>
  );
}

function Result({ r }: { r: Review }) {
  const rep = r.report;
  return (
    <div>
      <Summary head={<Headline label="Overall risk" value={rep.risk.toUpperCase()} tone={rep.risk} />}>
        <Stat label="Changed">
          {rep.changed_instructions} instructions
          <small className="block text-xs break-normal text-muted">{rep.churn_pct}% of the program</small>
        </Stat>
        <Stat label="Old" title={rep.old.sha256}>
          <span className="font-mono text-[13px]">{short(rep.old.sha256)}</span>
        </Stat>
        <Stat label="New" title={rep.new.sha256}>
          <span className="font-mono text-[13px]">{short(rep.new.sha256)}</span>
        </Stat>
        <Stat label="Verdict hash" title={r.verdict_hash}>
          <span className="font-mono text-[13px]">{short(r.verdict_hash)}</span>
        </Stat>
      </Summary>

      <SectionTitle>Findings</SectionTitle>
      <ul className="rounded-2xl border border-line bg-bg/60 m-0 list-none divide-y divide-line overflow-hidden p-0">
        {rep.findings.length === 0 && <li className="px-5 py-4">No findings. Nothing obvious changed.</li>}
        {rep.findings.map((f, i) => (
          <li
            key={i}
            className={`px-5 py-4 ${f.severity === "high" || f.severity === "critical" ? "shadow-[inset_3px_0_0_var(--color-orange)]" : ""}`}
          >
            <header className="flex flex-wrap items-center gap-3">
              <Sev risk={f.severity} />
              <span className="font-semibold">{f.title}</span>
              <span className="font-mono text-xs text-faint md:ml-auto">{f.id}</span>
            </header>
            <ul className="mt-2.5 list-none space-y-0.5 p-0 font-mono text-[12.5px] break-all text-[#c3cad6] md:ml-[76px]">
              {f.detail.map((d, j) => (
                <li key={j}>{d}</li>
              ))}
            </ul>
          </li>
        ))}
      </ul>

      <SectionTitle>Code changes</SectionTitle>
      <div className="grid gap-2.5">
        {rep.hunks.map((h, i) => (
          <HunkView key={i} hunk={h} open={i < 2} />
        ))}
      </div>

      <JudgePanel key={r.verdict_hash} report={rep} />
    </div>
  );
}

export function ReviewPanel() {
  const [old, setOld] = useState<Picked | null>(null);
  const [next, setNext] = useState<Picked | null>(null);
  const [result, setResult] = useState<Review | null>(null);
  const [error, setError] = useState("");

  async function run(a: Picked | null, b: Picked | null) {
    if (!a || !b) return;
    setError("");
    try {
      setResult(await review(a.bytes, b.bytes));
    } catch (e) {
      setResult(null);
      setError(`Could not review: ${e instanceof Error ? e.message : e}`);
    }
  }

  async function demo() {
    setError("");
    try {
      const [a, b] = await Promise.all(
        DEMO.map(async (name) => {
          const res = await fetch(asset(`fixtures/${name}`));
          if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
          return { name, bytes: new Uint8Array(await res.arrayBuffer()) };
        }),
      );
      setOld(a);
      setNext(b);
      await run(a, b);
    } catch (e) {
      setError(`Could not load the demo: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <section role="tabpanel">
      <Hero title="What changed in this upgrade?">
        Drop the deployed program and the new build. Tidemark reads the sBPF bytecode, diffs it and flags risky changes.
        Everything runs in your browser; no file leaves this page.
      </Hero>

      <div className="grid items-stretch gap-4 md:grid-cols-[1fr_auto_1fr]">
        <Drop kind="Current" hint="Drop old .so" file={old} onFile={setOld} />
        <div aria-hidden className="self-center justify-self-center text-lg text-faint max-md:rotate-90">
          →
        </div>
        <Drop kind="Upgrade" hint="Drop new .so" file={next} onFile={setNext} />
      </div>

      <div className="mt-5 mb-2 flex flex-wrap gap-2.5">
        <Button variant="primary" disabled={!old || !next} onClick={() => run(old, next)}>
          Review upgrade
        </Button>
        <Button onClick={demo}>Load demo: backdoored vault</Button>
      </div>

      <ErrorNote message={error} />
      {result && <Result r={result} />}
    </section>
  );
}

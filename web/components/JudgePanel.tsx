"use client";

import { useState } from "react";
import { DEFAULT_MODEL, runJudge } from "@/lib/judge";
import type { Judgement, Report } from "@/lib/types";
import { Button, ErrorNote, SectionTitle, Sev } from "./ui";

const VOTES = 3;

const FIELD =
  "w-full rounded-xl border border-line bg-bg/60 px-3.5 py-2.5 font-mono text-[13px] text-text outline-none focus:border-accent";

function Verdict({ j }: { j: Judgement }) {
  const raised = j.risk_after !== j.risk_before;
  return (
    <div className="mt-5 grid gap-4">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="text-muted">Risk</span>
        <Sev risk={j.risk_before} />
        <span className="text-faint">→</span>
        <Sev risk={j.risk_after} />
        <span className="text-muted">{raised ? "raised by a cited majority" : "unchanged"}</span>
      </div>
      {j.explanation && <p className="m-0 max-w-[760px] whitespace-pre-line text-[#c3cad6]">{j.explanation}</p>}
      {j.explanation_error && <p className="m-0 text-sm text-amber">Explanation failed: {j.explanation_error}</p>}
      <ul className="m-0 list-none divide-y divide-line overflow-hidden rounded-2xl border border-line bg-bg/60 p-0">
        {j.questions.map((q) => (
          <li key={q.id} className="px-5 py-4">
            <div className="flex flex-wrap items-start gap-3">
              <span className="flex-1 min-w-0">{q.question}</span>
              <span className={`font-mono text-sm ${q.yes * 2 > VOTES ? "text-orange" : "text-muted"}`}>
                {q.yes} yes · {q.no} no
                {q.dropped > 0 && ` · ${q.dropped} uncited`}
                {q.failed > 0 && ` · ${q.failed} failed`}
              </span>
            </div>
            {q.cites.length > 0 && (
              <p className="mt-1.5 mb-0 font-mono text-xs text-faint">cites {q.cites.join(", ")}</p>
            )}
            {q.errors.length > 0 && <p className="mt-1.5 mb-0 text-xs text-amber">{q.errors.join("; ")}</p>}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function JudgePanel({ report }: { report: Report }) {
  const [key, setKey] = useState("");
  const [model, setModel] = useState(DEFAULT_MODEL);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Judgement | null>(null);
  const [error, setError] = useState("");

  async function run() {
    setError("");
    setResult(null);
    try {
      setResult(await runJudge(report, key.trim(), model.trim() || DEFAULT_MODEL, (d, t) => setBusy(`${d}/${t}`)));
    } catch (e) {
      setError(`Judge failed: ${e instanceof Error ? e.message : e}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <SectionTitle>AI judge (optional)</SectionTitle>
      <div className="rounded-2xl border border-line bg-panel-2/60 px-5 py-5">
        <p className="m-0 max-w-[760px] text-sm text-muted">
          A model explains the findings and answers three yes/no questions, three times each. A yes only counts if it
          cites a finding or hunk from this report, and a cited majority can raise the risk to High, never lower it.
          Nothing here changes the verdict hash. Your key goes from this browser straight to Google and is not stored.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_220px_auto] sm:items-end">
          <label className="grid gap-1.5 text-xs text-faint">
            Gemini API key
            <input
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className={FIELD}
            />
          </label>
          <label className="grid gap-1.5 text-xs text-faint">
            Model
            <input value={model} onChange={(e) => setModel(e.target.value)} spellCheck={false} className={FIELD} />
          </label>
          <Button variant="primary" disabled={!key.trim() || busy !== null} onClick={run}>
            {busy ? `Asking ${busy}` : "Ask the judge"}
          </Button>
        </div>
        <ErrorNote message={error} />
        {result && <Verdict j={result} />}
      </div>
    </section>
  );
}

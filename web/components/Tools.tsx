"use client";

import { useEffect, useState } from "react";
import { engine } from "@/lib/engine";
import { LedgerPanel } from "./LedgerPanel";
import { ReviewPanel } from "./ReviewPanel";

const TABS = [
  ["review", "Review an upgrade"],
  ["ledger", "Verify the ledger"],
] as const;

type Tab = (typeof TABS)[number][0];

export function Tools() {
  const [tab, setTab] = useState<Tab>("review");
  const [rules, setRules] = useState("");

  useEffect(() => {
    if (window.location.hash === "#ledger") setTab("ledger");
    engine().then(
      (w) => setRules(w.rulesVersion()),
      () => setRules(""),
    );
  }, []);

  return (
    <section className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Try Tidemark</h1>
          <p className="mt-2 max-w-2xl text-muted">
            The same engine as the command line, compiled to WebAssembly. Files stay in your browser; ledger checks go
            straight to the RPC you choose.
          </p>
        </div>
        {rules && <span className="rounded-full border border-line px-3 py-1 font-mono text-xs text-faint">{rules}</span>}
      </div>
      <div className="card p-4 shadow-glow sm:p-8">
        <div role="tablist" className="mb-8 flex gap-1 rounded-2xl bg-bg/70 p-1 sm:inline-flex">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className="flex-1 cursor-pointer rounded-xl px-3 py-2.5 text-sm font-medium text-muted transition-colors hover:text-text aria-selected:bg-accent aria-selected:text-white sm:flex-none sm:px-6"
            >
              {label}
            </button>
          ))}
        </div>
        <div hidden={tab !== "review"}>
          <ReviewPanel />
        </div>
        <div hidden={tab !== "ledger"}>
          <LedgerPanel active={tab === "ledger"} />
        </div>
      </div>
    </section>
  );
}

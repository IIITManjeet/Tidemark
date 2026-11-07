"use client";

import { useEffect, useState } from "react";
import { engine } from "@/lib/engine";
import { LedgerPanel } from "./LedgerPanel";
import { ReviewPanel } from "./ReviewPanel";

const TABS = [
  ["review", "Review"],
  ["ledger", "Ledger"],
] as const;

type Tab = (typeof TABS)[number][0];

function Mark() {
  return (
    <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden className="text-accent">
      <path d="M3 20c4-6 8-6 13 0s9 6 13 0" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
      <path d="M3 13c4-6 8-6 13 0s9 6 13 0" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" opacity=".45" />
    </svg>
  );
}

export function App() {
  const [tab, setTab] = useState<Tab>("review");
  const [rules, setRules] = useState("");

  useEffect(() => {
    engine().then((w) => setRules(w.rulesVersion()), () => setRules(""));
  }, []);

  return (
    <>
      <header className="sticky top-0 z-10 flex h-14 items-center gap-7 border-b border-line bg-bg/90 px-[max(16px,calc((100%-1100px)/2))] backdrop-blur">
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="font-serif text-[19px] font-semibold tracking-[0.01em]">Tidemark</span>
        </div>
        <nav role="tablist" className="flex h-full gap-5.5">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className="h-full cursor-pointer border-b-2 border-transparent px-0.5 text-sm font-medium text-muted hover:text-text aria-selected:border-accent aria-selected:text-text"
            >
              {label}
            </button>
          ))}
        </nav>
        <span className="ml-auto font-mono text-[13px] text-faint max-md:hidden">{rules}</span>
      </header>

      <main className="mx-auto w-[min(1100px,calc(100%-32px))] pt-10 pb-14">
        <div hidden={tab !== "review"}>
          <ReviewPanel />
        </div>
        <div hidden={tab !== "ledger"}>
          <LedgerPanel />
        </div>
      </main>

      <footer className="mx-auto flex w-[min(1100px,calc(100%-32px))] flex-wrap justify-between gap-2 border-t border-line pt-5 pb-10 text-[13px] text-faint">
        <a href="https://github.com/IIITManjeet/Tidemark" className="text-muted hover:text-text">
          Source on GitHub
        </a>
        <span>Heuristic review, not proof of safety.</span>
      </footer>
    </>
  );
}

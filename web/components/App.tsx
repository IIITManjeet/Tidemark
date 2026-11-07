"use client";

import { useEffect, useState } from "react";
import { engine } from "@/lib/engine";
import { HeroArt, Icon, Logo, Rings, type IconName } from "./art";
import { LedgerPanel } from "./LedgerPanel";
import { ReviewPanel } from "./ReviewPanel";

const REPO = "https://github.com/IIITManjeet/Tidemark";

const TABS = [
  ["review", "Review an upgrade"],
  ["ledger", "Verify the ledger"],
] as const;

type Tab = (typeof TABS)[number][0];

const FEATURES: [IconName, string, string][] = [
  ["diff", "Bytecode diff", "Disassembles both sBPF builds and aligns them, so moved code does not drown the real change."],
  ["rules", "Risk rules", "New hardcoded keys, neutralized account checks, new handlers, retargeted branches, new CPIs."],
  ["ledger", "Quorum ledger", "Verdicts are hash-linked on Solana and co-signed by independent reviewers."],
  ["census", "Authority census", "Who can upgrade a program today: a single key, a multisig, governance or nobody."],
  ["watch", "Upgrade watcher", "Snapshots a program and reviews every upgrade as it lands."],
  ["browser", "Runs where you are", "Same engine in the CLI, the browser, an npm package and a VS Code extension."],
];

const STACK = ["Anchor", "Solana", "Squads", "VS Code", "npm", "WebAssembly"];

const STEPS = [
  ["Fetch", "Pull the deployed ELF out of ProgramData, or drop two .so files."],
  ["Diff", "Disassemble, normalize addresses and align the two builds."],
  ["Flag", "Versioned rules rank each change; the verdict gets a hash."],
  ["Attest", "Reviewers publish and co-sign the verdict on-chain."],
];

const COMMANDS = ["tidemark diff old.so new.so", "npm install tidemark-wasm", "VS Code: Tidemark: Review a build"];

function Nav({ onTab }: { onTab: (t: Tab) => void }) {
  const [open, setOpen] = useState(false);
  const links: [string, string, Tab?][] = [
    ["Features", "#features"],
    ["Review", "#app", "review"],
    ["Ledger", "#app", "ledger"],
    ["How it works", "#how"],
  ];
  return (
    <header className="sticky top-0 z-20 border-b border-line/60 bg-bg/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <a href="#top" className="flex items-center gap-2.5 text-xl font-semibold">
          <Logo />
          Tidemark
        </a>
        <nav className="ml-auto hidden items-center gap-7 text-sm text-muted md:flex">
          {links.map(([label, href, tab]) => (
            <a key={label} href={href} onClick={() => tab && onTab(tab)} className="hover:text-text">
              {label}
            </a>
          ))}
        </nav>
        <a
          href={REPO}
          className="ml-auto hidden rounded-xl bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-2 sm:inline-block md:ml-0"
        >
          GitHub
        </a>
        <button
          className="ml-auto grid size-10 cursor-pointer place-items-center rounded-xl border border-line text-muted sm:ml-0 md:hidden"
          aria-label="Menu"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
            <path d={open ? "M6 6l12 12M18 6 6 18" : "M4 7h16M4 12h16M4 17h16"} />
          </svg>
        </button>
      </div>
      {open && (
        <nav className="border-t border-line/60 px-4 py-3 md:hidden">
          {links.map(([label, href, tab]) => (
            <a
              key={label}
              href={href}
              onClick={() => {
                if (tab) onTab(tab);
                setOpen(false);
              }}
              className="block rounded-lg px-2 py-2.5 text-muted hover:bg-panel hover:text-text"
            >
              {label}
            </a>
          ))}
          <a href={REPO} className="block rounded-lg px-2 py-2.5 text-muted hover:bg-panel hover:text-text">
            GitHub
          </a>
        </nav>
      )}
    </header>
  );
}

function Hero({ onTab }: { onTab: (t: Tab) => void }) {
  return (
    <section id="top" className="mx-auto grid max-w-6xl items-center gap-10 px-4 pt-12 pb-8 sm:px-6 lg:grid-cols-[1.05fr_1fr] lg:pt-20">
      <div>
        <span className="mb-5 inline-flex items-center gap-2 rounded-full border border-line bg-panel/70 px-3 py-1 text-xs text-muted">
          <span className="size-1.5 rounded-full bg-green" />
          Solana program upgrade reviewer
        </span>
        <h1 className="text-[clamp(2.2rem,5.5vw,3.6rem)] leading-[1.08] font-semibold tracking-tight">
          See what a program upgrade <span className="text-glow">really</span> changes
        </h1>
        <p className="mt-5 max-w-xl text-base text-muted sm:text-lg">
          Source and audits don&apos;t tell you what was deployed. Tidemark reads the bytecode, diffs the old and new
          builds and flags the changes that move money or remove checks. Everything runs in your browser.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a
            href="#app"
            onClick={() => onTab("review")}
            className="rounded-xl bg-accent px-6 py-3 font-medium text-white shadow-glow hover:bg-accent-2"
          >
            Review an upgrade
          </a>
          <a href="#app" onClick={() => onTab("ledger")} className="rounded-xl bg-panel-2 px-6 py-3 font-medium text-text hover:bg-line">
            Verify the ledger
          </a>
        </div>
      </div>
      <HeroArt />
    </section>
  );
}

function Stack() {
  return (
    <section className="mx-auto flex max-w-6xl flex-col gap-5 px-4 py-8 sm:px-6 md:flex-row md:items-center">
      <span className="shrink-0 text-sm font-medium text-muted">Built for</span>
      <ul className="flex flex-wrap items-center gap-x-10 gap-y-3 text-lg font-semibold text-faint md:ml-auto">
        {STACK.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
    </section>
  );
}

function Features() {
  return (
    <section id="features" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
      <div className="mb-10 grid gap-4 md:grid-cols-2 md:items-end">
        <h2 className="text-3xl font-semibold sm:text-4xl">Why review the bytecode?</h2>
        <p className="text-muted">
          An upgrade can silently swap the code users trust. Tidemark checks what the chain will actually run, not what a
          repository says it should.
        </p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map(([icon, title, body]) => (
          <div key={title} className="card flex flex-col items-center p-7 text-center transition-colors hover:border-line-2">
            <Icon name={icon} />
            <h3 className="mt-5 text-lg font-semibold">{title}</h3>
            <p className="mt-2 text-sm text-muted">{body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function Tool({ tab, onTab }: { tab: Tab; onTab: (t: Tab) => void }) {
  return (
    <section id="app" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-10 sm:px-6">
      <div className="card p-4 shadow-glow sm:p-8">
        <div role="tablist" className="mb-8 flex gap-1 rounded-2xl bg-bg/70 p-1 sm:inline-flex">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              onClick={() => onTab(id)}
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
          <LedgerPanel />
        </div>
      </div>
    </section>
  );
}

function How() {
  return (
    <section id="how" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
      <div className="card relative overflow-hidden p-6 sm:p-12">
        <Rings className="pointer-events-none absolute -right-48 -bottom-48 w-[560px] opacity-70 sm:-right-24" />
        <div className="relative max-w-xl">
          <h2 className="text-3xl leading-tight font-semibold sm:text-4xl">Reviewed by a quorum, checkable by anyone</h2>
          <p className="mt-4 text-muted">
            The same deterministic rules run everywhere, so any reviewer can rebuild a verdict and only co-sign if their own
            review hashes the same.
          </p>
        </div>
        <ol className="relative mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map(([title, body], i) => (
            <li key={title} className="rounded-2xl border border-line bg-bg/60 p-5 backdrop-blur">
              <span className="font-mono text-xs text-glow">0{i + 1}</span>
              <h3 className="mt-2 font-semibold">{title}</h3>
              <p className="mt-1 text-sm text-muted">{body}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

function Cta() {
  return (
    <section className="mx-auto max-w-6xl px-4 pb-16 sm:px-6">
      <div className="relative overflow-hidden rounded-(--radius-card) bg-gradient-to-br from-accent to-[#1238b8] p-6 sm:p-12">
        <div className="absolute -top-24 -right-16 size-72 rounded-full bg-white/10 blur-2xl" />
        <div className="relative grid gap-8 lg:grid-cols-2 lg:items-center">
          <div>
            <h2 className="text-3xl font-semibold text-white sm:text-4xl">Check your next upgrade before you sign</h2>
            <p className="mt-3 text-white/80">Use it from your terminal, your editor or your own app.</p>
          </div>
          <div className="space-y-2 font-mono text-[13px]">
            {COMMANDS.map((c) => (
              <div key={c} className="truncate rounded-xl bg-black/25 px-4 py-3 text-white/90">
                {c}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

export function App() {
  const [tab, setTab] = useState<Tab>("review");
  const [rules, setRules] = useState("");

  useEffect(() => {
    engine().then(
      (w) => setRules(w.rulesVersion()),
      () => setRules(""),
    );
  }, []);

  return (
    <>
      <Nav onTab={setTab} />
      <main>
        <Hero onTab={setTab} />
        <Stack />
        <Features />
        <Tool tab={tab} onTab={setTab} />
        <How />
        <Cta />
      </main>
      <footer className="border-t border-line/60">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-8 text-sm text-faint sm:px-6">
          <span className="flex items-center gap-2">
            <Logo size={22} /> Tidemark <span className="font-mono text-xs">{rules}</span>
          </span>
          <span>Heuristic review, not proof of safety.</span>
          <a href={REPO} className="text-muted hover:text-text">
            Source on GitHub
          </a>
        </div>
      </footer>
    </>
  );
}

"use client";

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { SolMark } from "./art";

const STEP_MS = 6000;
const EASE = "cubic-bezier(.2,.7,.2,1)";

const play = (name: string, delay: number, dur = 0.6, extra = ""): CSSProperties => ({
  animation: `${name} ${dur}s ${EASE} ${delay}s both${extra ? ` ${extra}` : ""}`,
});

function Frame({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="relative h-full overflow-hidden rounded-2xl border border-line bg-bg/70" role="img" aria-label={label}>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_70%_20%,rgb(47_107_255/0.16),transparent_60%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgb(52_64_106/0.25)_1px,transparent_1px),linear-gradient(90deg,rgb(52_64_106/0.25)_1px,transparent_1px)] bg-[size:28px_28px] [mask-image:radial-gradient(circle_at_center,black,transparent_75%)]" />
      <div className="relative h-full">{children}</div>
    </div>
  );
}

const OLD_BYTES = ["7f 45 4c 46 02 01 01 00", "b7 01 00 00 00 00 00 00", "79 a1 88 ff 00 00 00 00"];
const NEW_BYTES = ["7f 45 4c 46 02 01 01 00", "18 02 00 00 c1 e2 b4 7f", "05 00 01 00 00 00 00 00", "85 10 00 00 ff ff ff ff"];

function SignScene() {
  return (
    <Frame label="The upgrade authority signs, and ProgramData gets new bytes">
      <div className="absolute top-1/2 left-[6%] w-[34%] -translate-y-1/2" style={play("tm-rise", 0.1)}>
        <div className="rounded-2xl border border-orange/50 bg-panel p-4 shadow-[0_20px_50px_-20px_rgb(255_154_77/0.45)]">
          <div className="flex items-center gap-2.5">
            <span className="relative grid size-9 place-items-center rounded-full bg-orange/15 text-orange">
              <span className="absolute inset-0 rounded-full border border-orange/60" style={play("tm-ping", 0.9, 1.4, "infinite")} />
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
                <circle cx="8" cy="15" r="4" />
                <path d="m11 12 9-9M17 6l3 3M15 8l2 2" />
              </svg>
            </span>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold">Upgrade authority</div>
              <div className="truncate font-mono text-[11px] text-faint">9fxL…mCB1</div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 rounded-lg bg-bg/70 px-2.5 py-1.5 font-mono text-[10.5px] text-muted">
            <span className="text-green" style={play("tm-pop", 1.1, 0.4)}>✓</span>
            <span style={play("tm-type", 0.7, 0.8, "")} className="truncate">
              signed: Upgrade
            </span>
          </div>
        </div>
      </div>

      <svg className="absolute top-1/2 left-[40%] h-10 w-[14%] -translate-y-1/2 overflow-visible" viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden>
        <path
          d="M0 10 H96"
          stroke="#5b8cff"
          strokeWidth="2"
          fill="none"
          strokeDasharray="100"
          style={{ ["--len" as string]: 100, ...play("tm-draw", 0.9, 0.7) }}
          vectorEffect="non-scaling-stroke"
        />
        <path d="M90 4 100 10 90 16" stroke="#5b8cff" strokeWidth="2" fill="none" style={play("tm-fade", 1.5, 0.3)} vectorEffect="non-scaling-stroke" />
      </svg>

      <div className="absolute top-1/2 right-[6%] w-[38%] -translate-y-1/2" style={play("tm-rise", 0.3)}>
        <div className="rounded-2xl border border-line-2 bg-panel p-4">
          <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
            <span className="text-sm font-semibold">ProgramData</span>
            <span className="rounded-md border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] whitespace-nowrap text-link" style={play("tm-pop", 3.3, 0.4)}>
              slot 519460274
            </span>
          </div>
          <div className="relative mt-3 h-[104px] font-mono text-[10.5px] leading-6">
            <div className="absolute inset-0" style={play("tm-out", 1.6, 0.5, "")}>
              {OLD_BYTES.map((b) => (
                <div key={b} className="truncate text-faint">
                  {b}
                </div>
              ))}
            </div>
            <div className="absolute inset-0">
              {NEW_BYTES.map((b, i) => (
                <div key={b} className="rounded bg-panel" style={play("tm-rise", 1.9 + i * 0.3, 0.5)}>
                  <div className="truncate rounded bg-accent/10 px-1 text-[#cfdcff]">{b}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </Frame>
  );
}

const OLD_CODE = ["ldxdw r1, [r10-136]", "ldxdw r2, [r10-96]", "jne r2, r1, +0x1e", "ldxdw r1, [r10-128]", "call sol_invoke", "exit"];
const NEW_CODE = ["ldxdw r1, [r10-136]", "ldxdw r2, [r10-96]", "ja +0x1", "ldxdw r1, [r10-128]", "lddw r2, 0x7fd3…", "call sol_invoke"];

function Code({ title, lines, tone, changed, base }: { title: string; lines: string[]; tone: "old" | "new"; changed: number[]; base: number }) {
  return (
    <div className="min-w-0 flex-1 overflow-hidden rounded-2xl border border-line-2 bg-panel p-3">
      <div className="mb-2 flex items-center justify-between font-mono text-[10.5px] text-faint">
        <span>{title}</span>
        <span>sBPF v3</span>
      </div>
      <div className="space-y-1 font-mono text-[10.5px] leading-5">
        {lines.map((l, i) => {
          const hit = changed.includes(i);
          const hl = tone === "old" ? "bg-orange/15 text-[#ffd6b8]" : "bg-accent/15 text-[#cfdcff]";
          return (
            <div key={i} className="relative" style={play("tm-rise", base + i * 0.12, 0.45)}>
              <div className="truncate rounded px-1.5 text-muted">{l}</div>
              {hit && (
                <div className="absolute inset-0 rounded bg-panel" style={play("tm-fade", 2 + i * 0.15, 0.4)}>
                  <div className={`h-full truncate rounded px-1.5 ${hl}`}>
                    {tone === "old" ? "- " : "+ "}
                    {l}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DiffScene() {
  return (
    <Frame label="Tidemark decodes both builds and lines up the changed instructions">
      <div className="absolute inset-x-[7%] top-[7%] bottom-[17%] flex gap-3">
        <Code title="old.so" lines={OLD_CODE} tone="old" changed={[2, 5]} base={0.1} />
        <Code title="new.so" lines={NEW_CODE} tone="new" changed={[2, 4]} base={0.3} />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-[9%] bg-gradient-to-b from-transparent via-glow/25 to-transparent" style={play("tm-scan", 0.8, 2.2, "infinite")} />
      </div>
      <div className="absolute right-[7%] bottom-[4%] rounded-full border border-line-2 bg-panel px-3 py-1 font-mono text-[10.5px] text-muted" style={play("tm-pop", 3, 0.4)}>
        996 instructions changed · 4 hunks
      </div>
    </Frame>
  );
}

const FINDINGS: [string, string, string][] = [
  ["HIGH", "TM-KEY-ADD", "New hardcoded key 9xQe…VFin"],
  ["HIGH", "TM-GUARD-GONE", "Signer check can no longer fail"],
  ["HIGH", "TM-CHECK-GONE", "withdraw lost has_one, signer"],
  ["MEDIUM", "TM-IX-CHANGE", "New instruction: sweep"],
];

function RiskScene() {
  return (
    <Frame label="Rules rank the findings and the verdict gets a reproducible hash">
      <div className="absolute inset-[7%] grid grid-cols-[1.35fr_1fr] gap-3">
        <ul className="m-0 list-none space-y-2 p-0">
          {FINDINGS.map(([sev, id, text], i) => (
            <li key={id} className="flex items-center gap-2.5 rounded-xl border border-line-2 bg-panel px-3 py-2" style={play("tm-slide", 0.2 + i * 0.35, 0.5)}>
              <span
                className={`rounded border px-1.5 py-0.5 text-[9px] font-semibold tracking-wider ${
                  sev === "HIGH" ? "border-orange/50 bg-orange/10 text-orange" : "border-amber/45 bg-amber/5 text-amber"
                }`}
              >
                {sev}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-[10.5px] text-faint">{id}</span>
                <span className="block truncate text-xs">{text}</span>
              </span>
            </li>
          ))}
        </ul>
        <div className="flex flex-col justify-between rounded-2xl border border-line-2 bg-panel p-4">
          <div>
            <span className="label-caps">Overall risk</span>
            <div className="mt-1 text-3xl font-semibold text-orange" style={play("tm-pop", 1.9, 0.45)}>
              HIGH
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-bg">
              <div className="h-full w-[82%] origin-left rounded-full bg-gradient-to-r from-accent via-amber to-orange" style={play("tm-grow", 0.4, 1.6)} />
            </div>
          </div>
          <div>
            <span className="label-caps">Verdict hash</span>
            <div className="mt-1 truncate font-mono text-[11px] text-link" style={play("tm-type", 2.4, 1.1, "")}>
              39acf9f9066d5e72c8a7e1b7
            </div>
          </div>
        </div>
      </div>
    </Frame>
  );
}

function Block({ n, hash, fresh = false, delay }: { n: number; hash: string; fresh?: boolean; delay: number }) {
  return (
    <div
      className={`relative w-[30%] rounded-2xl border p-3 ${fresh ? "border-accent bg-accent/10 shadow-[0_0_40px_-10px_rgb(47_107_255/0.8)]" : "border-line-2 bg-panel"}`}
      style={play(fresh ? "tm-slide" : "tm-rise", delay, fresh ? 0.7 : 0.5)}
    >
      <div className="flex items-center justify-between font-mono text-[10px] text-faint">
        <span>entry #{n}</span>
        <SolMark className="h-2.5 w-auto" id={`sol-block-${n}`} />
      </div>
      <div className="mt-1.5 truncate font-mono text-[11px] text-text">{hash}</div>
      <div className="mt-1 truncate text-[10.5px] text-muted">{fresh ? "risk HIGH · slot 519460795" : "prev ok"}</div>
    </div>
  );
}

const REVIEWERS = ["9fxL", "BWue", "788c"];

function LedgerScene() {
  return (
    <Frame label="The review is recorded on the ledger and co-signed by independent reviewers">
      <div className="absolute inset-x-[6%] top-[12%] flex items-center justify-between">
        <Block n={0} hash="a1f0…77c2" delay={0.1} />
        <span className="h-px flex-1 bg-line-2" style={play("tm-fade", 0.4, 0.4)} />
        <Block n={1} hash="5c3e…09ab" delay={0.3} />
        <span className="h-px flex-1 origin-left bg-accent" style={play("tm-grow", 1.1, 0.5)} />
        <Block n={2} hash="a475…6f9a" fresh delay={0.7} />
      </div>
      <div className="absolute inset-x-[6%] bottom-[10%] rounded-2xl border border-line-2 bg-panel p-4" style={play("tm-rise", 1.4, 0.5)}>
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold">Reviewers re-run the diff, then co-sign</span>
          <span className="rounded-md border border-green/50 bg-green/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-green" style={play("tm-pop", 3.6, 0.4)}>
            FINAL 2 / 2
          </span>
        </div>
        <div className="mt-3 flex gap-3">
          {REVIEWERS.map((r, i) => (
            <div key={r} className="flex flex-1 items-center gap-2 rounded-xl bg-bg/70 px-2.5 py-2">
              <span className="grid size-7 shrink-0 place-items-center rounded-full bg-panel-2 font-mono text-[10px] text-muted">{r.slice(0, 2)}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-faint">{r}…</span>
              {i < 2 ? (
                <span className="grid size-5 place-items-center rounded-full bg-green/20 text-[11px] text-green" style={play("tm-pop", 2.2 + i * 0.7, 0.4)}>
                  ✓
                </span>
              ) : (
                <span className="text-[10px] text-faint" style={play("tm-fade", 3.4, 0.4)}>
                  not needed
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </Frame>
  );
}

const STEPS = [
  {
    label: "Step one",
    title: "An upgrade is signed",
    body: "One signature from the upgrade authority swaps the bytes in ProgramData. No source code is involved, and nothing forces a review.",
    tag: "ProgramData",
    Scene: SignScene,
  },
  {
    label: "Step two",
    title: "Tidemark diffs the bytecode",
    body: "Both ELFs are decoded, sBPF v0 to v3, then aligned so moved code doesn't hide what really changed.",
    tag: "old.so ⇄ new.so",
    Scene: DiffScene,
  },
  {
    label: "Step three",
    title: "Rules rank the risk",
    body: "Deterministic rules flag new keys, neutralized checks, new handlers and CPIs. Every honest reviewer gets the same verdict hash.",
    tag: "tm-rules-0.7",
    Scene: RiskScene,
  },
  {
    label: "Step four",
    title: "A quorum co-signs on-chain",
    body: "The verdict is attested to the ledger, bound to the deployed bytes and slot, and becomes final once k of n reviewers co-sign.",
    tag: "k-of-n",
    Scene: LedgerScene,
  },
];

function Thumb({ i }: { i: number }) {
  if (i === 0)
    return (
      <div className="flex items-center gap-1.5">
        <span className="size-6 rounded-full border border-orange/50 bg-orange/10" />
        <span className="h-px w-5 bg-glow" />
        <span className="grid gap-1">
          <span className="h-1.5 w-12 rounded bg-line-2" />
          <span className="h-1.5 w-9 rounded bg-accent/60" />
          <span className="h-1.5 w-11 rounded bg-accent/40" />
        </span>
      </div>
    );
  if (i === 1)
    return (
      <div className="flex gap-1.5">
        {[0, 1].map((c) => (
          <span key={c} className="grid w-11 gap-1">
            <span className="h-1.5 rounded bg-line-2" />
            <span className={`h-1.5 rounded ${c ? "bg-accent/60" : "bg-orange/60"}`} />
            <span className="h-1.5 rounded bg-line-2" />
          </span>
        ))}
      </div>
    );
  if (i === 2)
    return (
      <div className="grid gap-1">
        {["bg-orange/70", "bg-orange/70", "bg-amber/60"].map((c, k) => (
          <span key={k} className="flex items-center gap-1">
            <span className={`h-1.5 w-3 rounded ${c}`} />
            <span className="h-1.5 w-12 rounded bg-line-2" />
          </span>
        ))}
      </div>
    );
  return (
    <div className="flex items-center gap-1">
      {[0, 1, 2].map((b) => (
        <span key={b} className={`h-5 w-5 rounded-md border ${b === 2 ? "border-accent bg-accent/20" : "border-line-2 bg-panel-2"}`} />
      ))}
      <span className="ml-1 text-[10px] text-green">✓✓</span>
    </div>
  );
}

export function HowItWorks() {
  const [active, setActive] = useState(0);
  const [cycle, setCycle] = useState(0);
  const still = useRef(false);

  useEffect(() => {
    still.current = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);

  useEffect(() => {
    if (still.current) return;
    const t = setTimeout(() => setActive((a) => (a + 1) % STEPS.length), STEP_MS);
    return () => clearTimeout(t);
  }, [active, cycle]);

  const pick = (i: number) => {
    setActive(i);
    setCycle((c) => c + 1);
  };

  const step = STEPS[active];
  const Scene = step.Scene;

  return (
    <section id="how" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
      <div className="mx-auto mb-10 max-w-2xl text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-line bg-panel/70 px-3 py-1 text-xs text-muted">
          <span className="size-1.5 rounded-full bg-accent" />
          How it works
        </span>
        <h2 className="mt-4 text-3xl leading-tight font-semibold sm:text-4xl">From one signature to a co-signed review</h2>
        <p className="mt-3 text-muted">Four steps, the same on every machine, so anyone can check the result.</p>
      </div>

      <div className="card grid gap-6 p-4 sm:p-6 lg:grid-cols-[0.9fr_1.3fr] lg:items-center lg:p-8">
        <div key={`t${active}`} className="lg:pr-4">
          <span className="font-mono text-xs text-glow" style={play("tm-fade", 0, 0.4)}>
            {step.label}
          </span>
          <h3 className="mt-2 text-2xl font-semibold sm:text-3xl" style={play("tm-rise", 0.05, 0.5)}>
            {step.title}
          </h3>
          <p className="mt-3 text-muted" style={play("tm-rise", 0.15, 0.5)}>
            {step.body}
          </p>
          <div className="mt-6 flex gap-1.5" aria-hidden>
            {STEPS.map((_, i) => (
              <span key={i} className={`h-1.5 rounded-full transition-all duration-500 ${i === active ? "w-8 bg-accent" : "w-1.5 bg-line-2"}`} />
            ))}
          </div>
        </div>
        <div className="h-[300px] min-w-0 sm:h-[320px]">
          <div key={`s${active}-${cycle}`} className="h-full" style={play("tm-fade", 0, 0.45)}>
            <Scene />
          </div>
        </div>
      </div>

      <ol className="relative m-0 mt-4 grid list-none gap-3 p-0 sm:grid-cols-2 lg:grid-cols-4">
        {STEPS.map((s, i) => {
          const on = i === active;
          return (
            <li key={s.label} className="relative">
              <button
                type="button"
                onClick={() => pick(i)}
                aria-current={on ? "step" : undefined}
                className={`relative flex h-full w-full cursor-pointer flex-col items-start overflow-hidden rounded-2xl border p-4 text-left transition-colors ${
                  on ? "border-accent/70 bg-panel-2/80" : "border-line bg-panel/60 hover:border-line-2"
                }`}
              >
                <span className="label-caps">{s.label}</span>
                <span className="mt-1 font-semibold">{s.title}</span>
                <span className="mt-4 mb-4 flex h-12 items-center">
                  <Thumb i={i} />
                </span>
                <span className="mt-auto rounded-md border border-line-2 bg-bg/60 px-2 py-0.5 font-mono text-[10.5px] text-muted">{s.tag}</span>
                {on && (
                  <span
                    key={`p${cycle}`}
                    className="absolute inset-x-0 bottom-0 h-0.5 origin-left bg-accent"
                    style={{ animation: `tm-grow ${STEP_MS}ms linear both` }}
                  />
                )}
              </button>
              {i < STEPS.length - 1 && (
                <span className="absolute top-1/2 -right-[17px] z-10 hidden size-6 -translate-y-1/2 place-items-center rounded-full border border-line-2 bg-panel text-[11px] text-muted lg:grid" aria-hidden>
                  ›
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

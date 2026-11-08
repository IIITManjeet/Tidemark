import Link from "next/link";
import { DEMO_PROGRAM, LEDGER_V2, REGISTRY_V2, REPO, RULES, explorer } from "@/lib/site";
import { HeroArt, Icon, SolMark, type IconName } from "./art";
import { HowItWorks } from "./HowItWorks";

const FEATURES: [IconName, string, string, string][] = [
  ["diff", "Bytecode diff", "Disassembles both sBPF builds, v0 to v3, and aligns them so moved code doesn't hide the real change.", "/docs/rules"],
  ["rules", "Risk rules", "New hardcoded keys, neutralized account checks, new handlers, retargeted branches and new CPIs, ranked by severity.", "/docs/rules"],
  ["ledger", "Quorum ledger", "Reviews are hash-linked on Solana, bound to the deployed bytes and co-signed by independent reviewers.", "/docs/ledger"],
  ["census", "Authority census", "See who can upgrade a program today: a single key, a multisig, governance, a program or nobody.", "/docs/cli#census"],
  ["watch", "Upgrade watcher", "Snapshots a program and reviews every upgrade as it lands, with optional on-chain attestation.", "/docs/cli#watch"],
  ["browser", "Runs where you work", "One engine in the CLI, CI, VS Code, an npm package and this site. Files never leave your machine.", "/docs/quickstart"],
];

const ENTRY: { title: string; who: string; cmd: string; href: string; cta: string }[] = [
  {
    title: "Command line",
    who: "Auditors, multisig signers, CI pipelines",
    cmd: "tidemark diff old.so new.so",
    href: "/docs/cli",
    cta: "CLI guide",
  },
  {
    title: "VS Code",
    who: "Program developers before anchor deploy",
    cmd: "Tidemark: Review a build against the deployed program",
    href: "/docs/vscode",
    cta: "Extension guide",
  },
  {
    title: "npm package",
    who: "Wallets, explorers and dashboards",
    cmd: "review(oldBytes, newBytes)",
    href: "/docs/npm",
    cta: "Library guide",
  },
  {
    title: "Web app",
    who: "Anyone, no install",
    cmd: "Drop two .so files, or verify the ledger",
    href: "/app",
    cta: "Open the app",
  },
];


const STATS = [
  ["16 / 16", "SBPF version pairs where the demo backdoor scores HIGH"],
  ["0", "bytes uploaded: review runs locally"],
  ["k-of-n", "independent reviewers before an entry is final"],
];

export function Landing() {
  return (
    <>
      <section className="mx-auto grid max-w-6xl items-center gap-10 px-4 pt-12 pb-8 sm:px-6 lg:grid-cols-[1.05fr_1fr] lg:pt-20">
        <div>
          <div className="mb-5 flex flex-wrap gap-2">
            <span className="inline-flex items-center gap-2 rounded-full border border-line bg-panel/70 px-3 py-1 text-xs text-muted">
              <SolMark className="h-3 w-auto" id="sol-badge" />
              Built on Solana
            </span>
            <span className="inline-flex items-center gap-2 rounded-full border border-line bg-panel/70 px-3 py-1 text-xs text-muted">
              <span className="size-1.5 rounded-full bg-green" />
              Upgrade reviewer · {RULES}
            </span>
          </div>
          <h1 className="text-[clamp(2.2rem,5.5vw,3.6rem)] leading-[1.08] font-semibold tracking-tight">
            See what a program upgrade <span className="text-glow">really</span> changes
          </h1>
          <p className="mt-5 max-w-xl text-base text-muted sm:text-lg">
            Any upgradeable Solana program can be replaced by whoever holds its key. Tidemark reads the new bytecode,
            shows what changed and how risky it is, and records the review on a public ledger.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/app" className="rounded-xl bg-accent px-6 py-3 font-medium text-white shadow-glow hover:bg-accent-2">
              Review an upgrade
            </Link>
            <Link href="/docs/quickstart" className="rounded-xl bg-panel-2 px-6 py-3 font-medium text-text hover:bg-line">
              Get started
            </Link>
          </div>
        </div>
        <HeroArt />
      </section>

      <section className="mx-auto max-w-6xl px-4 py-6 sm:px-6">
        <dl className="grid gap-4 sm:grid-cols-3">
          {STATS.map(([v, l]) => (
            <div key={l} className="card px-6 py-5">
              <dt className="text-3xl font-semibold text-glow">{v}</dt>
              <dd className="mt-1 text-sm text-muted">{l}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <div className="grid gap-8 lg:grid-cols-2">
          <div>
            <span className="label-caps">The problem</span>
            <h2 className="mt-3 text-3xl font-semibold sm:text-4xl">Signers approve a hash they cannot read</h2>
            <p className="mt-4 text-muted">
              Verified builds prove which source produced a binary. Monitors tell you an upgrade happened. Neither tells a
              multisig signer, an integrator or a user what the new code does differently, and source can differ from
              what is deployed.
            </p>
          </div>
          <div className="card p-6">
            <span className="label-caps">What Tidemark answers</span>
            <ul className="mt-4 space-y-3 text-sm">
              {[
                "Did a new key appear that could receive funds?",
                "Was a signer, owner or has_one check removed, or patched so it can't fail?",
                "Is there a new instruction, CPI or indirect call?",
                "Is what was reviewed exactly what is deployed now?",
              ].map((q) => (
                <li key={q} className="flex gap-3">
                  <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-accent" />
                  <span className="text-muted">{q}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section id="features" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-10 sm:px-6">
        <div className="mb-10 grid gap-4 md:grid-cols-2 md:items-end">
          <h2 className="text-3xl font-semibold sm:text-4xl">Everything an upgrade review needs</h2>
          <p className="text-muted">
            Deterministic rules do the detection. An optional AI judge explains the findings in plain English and can
            only ever raise the risk.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(([icon, title, body, href]) => (
            <Link key={title} href={href} className="card group flex flex-col items-start p-7 transition-colors hover:border-line-2">
              <Icon name={icon} />
              <h3 className="mt-5 text-lg font-semibold">{title}</h3>
              <p className="mt-2 text-sm text-muted">{body}</p>
              <span className="mt-4 text-sm text-link group-hover:underline">Learn more →</span>
            </Link>
          ))}
        </div>
      </section>

      <section id="start" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-16 sm:px-6">
        <div className="mb-10 max-w-2xl">
          <span className="label-caps">Get started</span>
          <h2 className="mt-3 text-3xl font-semibold sm:text-4xl">Pick your entry point</h2>
          <p className="mt-3 text-muted">The same engine and the same verdict hash, wherever you start.</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {ENTRY.map((e) => (
            <div key={e.title} className="card flex flex-col p-6">
              <div className="flex items-baseline justify-between gap-3">
                <h3 className="text-xl font-semibold">{e.title}</h3>
                <span className="text-right text-xs text-faint">{e.who}</span>
              </div>
              <code className="mt-4 block truncate rounded-xl border border-line bg-bg/80 px-4 py-3 font-mono text-[13px] text-[#d6deef]">
                {e.cmd}
              </code>
              <Link href={e.href} className="mt-4 self-start text-sm font-medium text-link hover:underline">
                {e.cta} →
              </Link>
            </div>
          ))}
        </div>
      </section>

      <HowItWorks />

      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <div className="grid gap-6 lg:grid-cols-[1fr_1.1fr] lg:items-center">
          <div>
            <span className="label-caps inline-flex items-center gap-2">
              <SolMark className="h-3 w-auto" id="sol-devnet" />
              Live on devnet
            </span>
            <h2 className="mt-3 text-3xl font-semibold sm:text-4xl">A real upgrade, reviewed and co-signed</h2>
            <p className="mt-4 text-muted">
              A demo vault was upgraded on devnet to a build with a hidden sweep. Reviewer one attested HIGH, reviewer two
              re-ran the review independently and co-signed. Anyone can check the chain.
            </p>
            <Link href="/app#ledger" className="mt-6 inline-block rounded-xl bg-panel-2 px-5 py-2.5 text-sm font-medium hover:bg-line">
              Verify it in your browser
            </Link>
          </div>
          <div className="card divide-y divide-line/70 font-mono text-[13px]">
            {[
              ["Ledger program", LEDGER_V2],
              ["Registry", REGISTRY_V2],
              ["Upgraded program", DEMO_PROGRAM],
            ].map(([k, v]) => (
              <a key={k} href={explorer(v)} target="_blank" rel="noopener" className="flex flex-col gap-1 px-5 py-4 hover:bg-panel-2/60">
                <span className="font-sans text-xs text-faint">{k}</span>
                <span className="truncate text-link">{v}</span>
              </a>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 pb-10 sm:px-6">
        <div className="relative overflow-hidden rounded-(--radius-card) bg-gradient-to-br from-accent to-[#1238b8] p-6 sm:p-12">
          <div className="absolute -top-24 -right-16 size-72 rounded-full bg-white/10 blur-2xl" />
          <div className="relative flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-3xl font-semibold text-white sm:text-4xl">Check your next upgrade before you sign</h2>
              <p className="mt-3 text-white/80">Open source, MIT licensed, and running entirely on your machine.</p>
            </div>
            <div className="flex flex-wrap gap-3">
              <Link href="/docs/quickstart" className="rounded-xl bg-white px-6 py-3 font-medium text-[#1238b8] hover:bg-white/90">
                Read the quickstart
              </Link>
              <a href={REPO} className="rounded-xl bg-black/25 px-6 py-3 font-medium text-white hover:bg-black/35">
                View on GitHub
              </a>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

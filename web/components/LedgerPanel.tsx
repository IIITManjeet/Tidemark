"use client";

import { useState } from "react";
import { fetchLedger, sameChain, short } from "@/lib/ledger";
import { RISKS, type Ledger } from "@/lib/types";
import { Button, ErrorNote, Headline, Hero, Sev, Stat, Summary } from "./ui";

const DEFAULTS = {
  rpc: "https://api.devnet.solana.com",
  rpc2: "",
  ledger: "BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc",
  registry: "72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU",
};

const explorer = (key: string) => `https://explorer.solana.com/address/${key}?cluster=devnet`;

function Field({ name, label, placeholder }: { name: keyof typeof DEFAULTS; label: string; placeholder?: string }) {
  return (
    <label className="label-caps flex min-w-0 flex-col gap-1.5">
      {label}
      <input
        name={name}
        defaultValue={DEFAULTS[name]}
        placeholder={placeholder}
        spellCheck={false}
        className="min-w-0 rounded-md font-mono border border-line-2 bg-bg px-2.5 py-2 text-[13px] tracking-normal text-text normal-case focus:border-accent focus:outline-none"
      />
    </label>
  );
}

function Result({ v, rpcs }: { v: Ledger; rpcs: number }) {
  const note = !v.ok
    ? v.error
    : rpcs > 1
      ? `links, addresses and quorums check out; ${rpcs} RPCs agree on the head`
      : "links, addresses and quorums check out, as served by this one RPC";
  return (
    <div>
      <Summary head={<Headline label="Chain" value={v.ok ? "VERIFIED" : "BROKEN"} tone={v.ok ? "ok" : "bad"} note={note} />}>
        <Stat label="Entries">{v.registry.count}</Stat>
        <Stat label="Quorum">
          {v.registry.threshold} of {v.registry.active_reviewers}
        </Stat>
        <Stat label="Authority" title={v.registry.authority}>
          <span className="font-mono text-[13px]">{short(v.registry.authority, 6)}</span>
        </Stat>
        <Stat label="Head" title={v.registry.head}>
          <span className="font-mono text-[13px]">{short(v.registry.head)}</span>
        </Stat>
      </Summary>
      <div className="panel mt-4 overflow-x-auto">
        <table className="w-full border-collapse text-[13.5px]">
          <thead>
            <tr>
              {["#", "Program", "Risk", "Approvals", "Rules", "Slot", "Verdict"].map((h) => (
                <th key={h} className="label-caps border-b border-line bg-panel-2 px-4.5 py-3 text-left font-semibold whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="[&_td]:border-b [&_td]:border-line [&_td]:px-4.5 [&_td]:py-3 [&_td]:whitespace-nowrap [&_tr:last-child_td]:border-0">
            {v.entries.length === 0 && (
              <tr>
                <td colSpan={7}>No attestations yet.</td>
              </tr>
            )}
            {v.entries.map((e) => (
              <tr key={e.index}>
                <td>{e.index}</td>
                <td className="font-mono">
                  <a href={explorer(e.program)} target="_blank" rel="noopener" className="text-link hover:underline">
                    {short(e.program, 6)}
                  </a>
                </td>
                <td>
                  <Sev risk={RISKS[e.risk] ?? "info"} />
                </td>
                <td>
                  {e.approvals}/{e.threshold}
                  {e.final ? " · final" : ""}
                </td>
                <td className="font-mono">{e.rules_version}</td>
                <td className="font-mono">{e.slot}</td>
                <td className="font-mono" title={e.verdict_hash}>
                  {short(e.verdict_hash)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function LedgerPanel() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<{ v: Ledger; rpcs: number } | null>(null);

  async function submit(ev: React.FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    const form = new FormData(ev.currentTarget);
    const get = (k: string) => String(form.get(k) ?? "").trim();
    setError("");
    setBusy(true);
    try {
      const urls = [get("rpc"), get("rpc2")].filter(Boolean);
      const views = await Promise.all(urls.map((u) => fetchLedger(u, get("ledger"), get("registry"))));
      const v = views[0];
      if (views.length > 1 && !sameChain(views[0], views[1])) {
        v.ok = false;
        v.error = "the two RPCs disagree about this chain; trust neither";
      }
      setResult({ v, rpcs: views.length });
    } catch (e) {
      setResult(null);
      setError(`Could not verify: ${e instanceof Error ? e.message : e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section role="tabpanel">
      <Hero title="Attestation ledger">
        Reviews are written to a hash-linked ledger on Solana and co-signed by a quorum of reviewers. This page fetches the
        raw accounts over RPC and checks every link, address and signature count itself.
      </Hero>
      <form onSubmit={submit} className="panel mb-1 grid items-end gap-3.5 px-5 py-4.5 md:grid-cols-2">
        <Field name="rpc" label="RPC" />
        <Field name="rpc2" label="Cross-check RPC" placeholder="optional second endpoint" />
        <Field name="ledger" label="Ledger program" />
        <Field name="registry" label="Registry" />
        <Button variant="primary" type="submit" disabled={busy} className="justify-self-start">
          {busy ? "Verifying…" : "Fetch and verify"}
        </Button>
      </form>
      <ErrorNote message={error} />
      {result && <Result {...result} />}
    </section>
  );
}

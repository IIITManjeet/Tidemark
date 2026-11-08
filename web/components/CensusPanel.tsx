"use client";

import { useEffect, useRef, useState } from "react";
import { survey, type Entry } from "@/lib/census";
import { short } from "@/lib/ledger";
import { DEMO_PROGRAM, LEDGER_V3, UPGRADE_MULTISIG, explorer } from "@/lib/site";
import { Button, ErrorNote, Hero } from "./ui";

const DEFAULTS = {
  rpc: "https://api.devnet.solana.com",
  programs: `${LEDGER_V3}\n${DEMO_PROGRAM}`,
  multisigs: UPGRADE_MULTISIG,
};

const INPUT =
  "min-w-0 rounded-md font-mono border border-line-2 bg-bg px-2.5 py-2 text-[13px] tracking-normal text-text normal-case focus:border-accent focus:outline-none";

const lines = (s: string) => s.split(/\s+/).filter(Boolean);

function Result({ entries }: { entries: Entry[] }) {
  return (
    <div className="rounded-2xl border border-line bg-bg/60 mt-4 overflow-x-auto">
      <table className="w-full border-collapse text-[13.5px]">
        <thead>
          <tr>
            {["Program", "Who can upgrade", "Authority", "Last deploy slot"].map((h) => (
              <th key={h} className="label-caps border-b border-line bg-panel-2 px-4.5 py-3 text-left font-semibold whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&_td]:border-b [&_td]:border-line [&_td]:px-4.5 [&_td]:py-3 [&_td]:whitespace-nowrap [&_tr:last-child_td]:border-0">
          {entries.map((e) => (
            <tr key={e.program}>
              <td className="font-mono">
                <a href={explorer(e.program)} target="_blank" rel="noopener" className="text-link hover:underline">
                  {short(e.program, 6)}
                </a>
              </td>
              {e.error ? (
                <td colSpan={3} role="alert" className="text-red">
                  {e.error}
                </td>
              ) : (
                <>
                  <td>{e.control}</td>
                  <td className="font-mono" title={e.authority ?? undefined}>
                    {e.authority ? short(e.authority, 6) : "none"}
                  </td>
                  <td className="font-mono">{e.slot ?? "n/a"}</td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CensusPanel({ active }: { active: boolean }) {
  const form = useRef<HTMLFormElement>(null);
  const ran = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [entries, setEntries] = useState<Entry[] | null>(null);

  useEffect(() => {
    if (active && !ran.current) {
      ran.current = true;
      form.current?.requestSubmit();
    }
  }, [active]);

  async function submit(ev: React.FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    const form = new FormData(ev.currentTarget);
    const get = (k: string) => String(form.get(k) ?? "").trim();
    const programs = [...new Set(lines(get("programs")))];
    setError("");
    if (!get("rpc") || programs.length === 0) {
      setError("Enter an RPC and at least one program id.");
      return;
    }
    setBusy(true);
    try {
      const squads = lines(get("multisigs"));
      setEntries(await Promise.all(programs.map((p) => survey(get("rpc"), p, squads))));
    } catch (e) {
      setEntries(null);
      setError(`Could not survey: ${e instanceof Error ? e.message : e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section role="tabpanel">
      <Hero title="Who can upgrade?">
        Every upgradeable Solana program has an authority that can replace its code. This page reads each program over RPC
        and says whether that authority is a single key, a multisig, a governance or nobody at all.
      </Hero>
      <form ref={form} onSubmit={submit} className="rounded-2xl border border-line bg-bg/60 mb-1 grid items-end gap-3.5 px-5 py-4.5 md:grid-cols-2">
        <label className="label-caps flex min-w-0 flex-col gap-1.5 md:col-span-2">
          RPC
          <input name="rpc" defaultValue={DEFAULTS.rpc} spellCheck={false} className={INPUT} />
        </label>
        <label className="label-caps flex min-w-0 flex-col gap-1.5">
          Programs, one per line
          <textarea name="programs" rows={4} defaultValue={DEFAULTS.programs} spellCheck={false} className={INPUT} />
        </label>
        <label className="label-caps flex min-w-0 flex-col gap-1.5">
          Squads multisigs, one per line (optional)
          <textarea name="multisigs" rows={4} defaultValue={DEFAULTS.multisigs} spellCheck={false} className={INPUT} />
        </label>
        <Button variant="primary" type="submit" disabled={busy} className="justify-self-start">
          {busy ? "Surveying…" : "Survey"}
        </Button>
      </form>
      <ErrorNote message={error} />
      {entries && <Result entries={entries} />}
    </section>
  );
}

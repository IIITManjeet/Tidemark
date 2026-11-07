"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { DOCS } from "@/lib/site";

export function Code({ children, title }: { children: string; title?: string }) {
  const [copied, setCopied] = useState(false);
  const text = children.trim();
  return (
    <div className="group my-5 overflow-hidden rounded-xl border border-line bg-bg/80">
      <div className="flex items-center justify-between border-b border-line bg-panel-2/70 px-4 py-2 text-xs text-faint">
        <span>{title ?? "shell"}</span>
        <button
          className="cursor-pointer rounded-md px-2 py-0.5 text-muted hover:bg-line hover:text-text"
          onClick={() => {
            navigator.clipboard?.writeText(text).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-6 text-[#d6deef]">{text}</pre>
    </div>
  );
}

export function Callout({ tone = "info", title, children }: { tone?: "info" | "warn"; title: string; children: React.ReactNode }) {
  const c = tone === "warn" ? "border-orange/40 bg-orange/5" : "border-accent/40 bg-accent/5";
  return (
    <div className={`my-5 rounded-xl border px-4 py-3 ${c}`}>
      <div className="font-medium">{title}</div>
      <div className="mt-1 text-sm text-muted">{children}</div>
    </div>
  );
}

export function DocTable({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="my-5 overflow-x-auto rounded-xl border border-line">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h} className="border-b border-line bg-panel-2 px-4 py-2.5 text-left font-medium whitespace-nowrap text-muted">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="align-top">
              {r.map((c, j) => (
                <td key={j} className="border-b border-line/60 px-4 py-2.5 last:text-muted">
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function H2({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="mt-12 mb-3 scroll-mt-24 text-2xl font-semibold tracking-tight">
      <a href={`#${id}`} className="hover:text-glow">
        {children}
      </a>
    </h2>
  );
}

export function P({ children }: { children: React.ReactNode }) {
  return <p className="my-3 leading-7 text-muted">{children}</p>;
}

export function Ul({ children }: { children: React.ReactNode }) {
  return <ul className="my-3 list-disc space-y-1.5 pl-5 leading-7 text-muted marker:text-faint">{children}</ul>;
}

export function C({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-[0.85em] text-text">{children}</code>;
}

export function Steps({ items }: { items: { title: string; body: React.ReactNode }[] }) {
  return (
    <ol className="my-6 space-y-6 border-l border-line pl-6">
      {items.map((s, i) => (
        <li key={s.title} className="relative">
          <span className="absolute -left-[37px] grid size-6 place-items-center rounded-full bg-accent text-xs font-semibold text-white">
            {i + 1}
          </span>
          <div className="font-medium">{s.title}</div>
          <div className="text-muted">{s.body}</div>
        </li>
      ))}
    </ol>
  );
}

const ALL = DOCS.flatMap((g) => g.pages);

function current(path: string) {
  const p = path.replace(/\/$/, "") || "/docs";
  return ALL.findIndex((d) => d.href === p);
}

export function DocsNav() {
  const path = usePathname();
  const at = current(path);
  return (
    <>
      <div className="mb-6 lg:hidden">
        <label className="label-caps">On this site</label>
        <select
          className="mt-2 w-full rounded-xl border border-line-2 bg-panel px-3 py-2.5 text-sm"
          value={ALL[at]?.href ?? "/docs"}
          onChange={(e) => {
            window.location.href = `${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}${e.target.value}`;
          }}
        >
          {DOCS.map((g) => (
            <optgroup key={g.group} label={g.group}>
              {g.pages.map((d) => (
                <option key={d.href} value={d.href}>
                  {d.title}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
      </div>
      <nav className="sticky top-24 hidden max-h-[calc(100vh-7rem)] overflow-y-auto pr-4 lg:block">
        {DOCS.map((g) => (
          <div key={g.group} className="mb-6">
            <div className="label-caps mb-2">{g.group}</div>
            <ul className="space-y-0.5">
              {g.pages.map((d) => (
                <li key={d.href}>
                  <Link
                    href={d.href}
                    aria-current={ALL[at]?.href === d.href ? "page" : undefined}
                    className="block rounded-lg px-3 py-1.5 text-sm text-muted hover:bg-panel hover:text-text aria-[current=page]:bg-accent/15 aria-[current=page]:text-text"
                  >
                    {d.title}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </>
  );
}

export function DocPage({ title, lead, children }: { title: string; lead: string; children: React.ReactNode }) {
  const path = usePathname();
  const at = current(path);
  const prev = at > 0 ? ALL[at - 1] : null;
  const next = at >= 0 && at < ALL.length - 1 ? ALL[at + 1] : null;
  return (
    <article className="min-w-0">
      <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
      <p className="mt-3 text-lg text-muted">{lead}</p>
      <div className="mt-6">{children}</div>
      <div className="mt-14 grid gap-3 border-t border-line pt-6 sm:grid-cols-2">
        {prev ? (
          <Link href={prev.href} className="card px-5 py-4 hover:border-line-2">
            <div className="text-xs text-faint">Previous</div>
            <div className="font-medium">{prev.title}</div>
          </Link>
        ) : (
          <span />
        )}
        {next && (
          <Link href={next.href} className="card px-5 py-4 text-right hover:border-line-2">
            <div className="text-xs text-faint">Next</div>
            <div className="font-medium">{next.title}</div>
          </Link>
        )}
      </div>
    </article>
  );
}

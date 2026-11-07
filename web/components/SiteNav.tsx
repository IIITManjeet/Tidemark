"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { REPO } from "@/lib/site";
import { Logo } from "./art";

const LINKS = [
  { href: "/", label: "Product" },
  { href: "/docs", label: "Docs" },
  { href: "/app", label: "Try it" },
];

function active(path: string, href: string) {
  const p = path.replace(/\/$/, "") || "/";
  return href === "/" ? p === "/" : p === href || p.startsWith(`${href}/`);
}

export function SiteNav() {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-30 border-b border-line/60 bg-bg/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5 text-xl font-semibold" onClick={() => setOpen(false)}>
          <Logo />
          Tidemark
        </Link>
        <nav className="ml-auto hidden items-center gap-7 text-sm md:flex">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              aria-current={active(path, l.href) ? "page" : undefined}
              className="text-muted hover:text-text aria-[current=page]:text-text"
            >
              {l.label}
            </Link>
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
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              onClick={() => setOpen(false)}
              className="block rounded-lg px-2 py-2.5 text-muted hover:bg-panel hover:text-text"
            >
              {l.label}
            </Link>
          ))}
          <a href={REPO} className="block rounded-lg px-2 py-2.5 text-muted hover:bg-panel hover:text-text">
            GitHub
          </a>
        </nav>
      )}
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="mt-10 border-t border-line/60">
      <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 text-sm sm:grid-cols-[1.4fr_1fr_1fr_1fr] sm:px-6">
        <div>
          <div className="flex items-center gap-2 font-semibold">
            <Logo size={22} /> Tidemark
          </div>
          <p className="mt-3 max-w-xs text-faint">
            Bytecode review for Solana program upgrades. Heuristic review, not proof of safety.
          </p>
        </div>
        {[
          ["Product", [["Overview", "/"], ["Try it", "/app"], ["Quickstart", "/docs/quickstart"]]],
          ["Use it", [["Command line", "/docs/cli"], ["VS Code", "/docs/vscode"], ["npm", "/docs/npm"]]],
          ["Learn", [["Risk rules", "/docs/rules"], ["Ledger", "/docs/ledger"], ["Security model", "/docs/security"]]],
        ].map(([title, links]) => (
          <div key={title as string}>
            <div className="font-medium text-text">{title as string}</div>
            <ul className="mt-3 space-y-2">
              {(links as string[][]).map(([label, href]) => (
                <li key={href}>
                  <Link href={href} className="text-muted hover:text-text">
                    {label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="mx-auto flex max-w-6xl flex-wrap justify-between gap-2 border-t border-line/60 px-4 py-5 text-xs text-faint sm:px-6">
        <span>MIT licensed</span>
        <a href={REPO} className="hover:text-text">
          Source on GitHub
        </a>
      </div>
    </footer>
  );
}

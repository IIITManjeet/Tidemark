import { engine } from "./engine";
import type { Ledger } from "./types";

const SIZES = { attestation: 332, reviewer: 82, approval: 81 };

interface Raw {
  address: string;
  data: string;
}

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result as T;
}

async function accounts(url: string, ledger: string, size: number, registry?: string): Promise<Raw[]> {
  const filters: object[] = [{ dataSize: size }];
  if (registry) filters.push({ memcmp: { offset: 8, bytes: registry } });
  const list = await rpc<{ pubkey: string; account: { data: [string, string] } }[]>(url, "getProgramAccounts", [
    ledger,
    { encoding: "base64", commitment: "finalized", filters },
  ]);
  return list.map((a) => ({ address: a.pubkey, data: a.account.data[0] }));
}

export async function fetchLedger(url: string, ledger: string, registry: string): Promise<Ledger> {
  const info = await rpc<{ value: { owner: string; data: [string, string] } | null }>(url, "getAccountInfo", [
    registry,
    { encoding: "base64", commitment: "finalized" },
  ]);
  if (!info.value) throw new Error(`registry ${registry} not found`);
  if (info.value.owner !== ledger) throw new Error(`registry ${registry} is not owned by ${ledger}`);
  const [attestations, reviewers, approvals] = await Promise.all([
    accounts(url, ledger, SIZES.attestation, registry),
    accounts(url, ledger, SIZES.reviewer, registry),
    accounts(url, ledger, SIZES.approval),
  ]);
  const input = JSON.stringify({
    ledger,
    registry: { address: registry, data: info.value.data[0] },
    attestations,
    reviewers,
    approvals,
  });
  return JSON.parse((await engine()).verifyLedger(input));
}

export function sameChain(a: Ledger, b: Ledger): boolean {
  const hashes = (v: Ledger) => v.entries.map((e) => e.entry_hash).join(",");
  return a.registry.head === b.registry.head && a.registry.count === b.registry.count && hashes(a) === hashes(b);
}

export const short = (s: string, n = 8) => (s.length > 2 * n ? `${s.slice(0, n)}…${s.slice(-n)}` : s);

export const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
export const SQUADS_V3 = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu";
export const SPL_GOVERNANCE = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
const SYSTEM = "11111111111111111111111111111111";
const UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const LEGACY_LOADERS = [
  "BPFLoader1111111111111111111111111111111111",
  "BPFLoader2111111111111111111111111111111111",
  "NativeLoader1111111111111111111111111111111",
];
const VAULTS_CHECKED = 8;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export interface Squads {
  threshold: number;
  voters: number;
  timeLock: number;
}

export interface Entry {
  program: string;
  control: string;
  authority: string | null;
  slot: string | null;
  error: string | null;
}

export function decodeBase58(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const d = ALPHABET.indexOf(c);
    if (d < 0) throw new Error(`invalid base58 character '${c}'`);
    n = n * 58n + BigInt(d);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  const zeros = s.length - s.replace(/^1+/, "").length;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
}

export function encodeBase58(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  const first = b.findIndex((x) => x !== 0);
  return "1".repeat(first < 0 ? b.length : first) + out;
}

export function decodePubkey(s: string): Uint8Array {
  const b = decodeBase58(s);
  if (b.length !== 32) throw new Error(`'${s}' is not a 32-byte address`);
  return b;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = ((base % m) + m) % m;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}

const P = (1n << 255n) - 19n;
const D = (((-121665n * modPow(121666n, P - 2n, P)) % P) + P) % P;

export function onCurve(key: Uint8Array): boolean {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? key[i] & 0x7f : key[i]);
  y %= P;
  const y2 = (y * y) % P;
  const u = (y2 - 1n + P) % P;
  const v = (D * y2 + 1n) % P;
  if (u === 0n) return true;
  const ratio = (u * modPow(v, P - 2n, P)) % P;
  return modPow(ratio, (P - 1n) / 2n, P) === 1n;
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    buf.set(p, at);
    at += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

async function findPda(seeds: Uint8Array[], program: Uint8Array): Promise<Uint8Array> {
  const tag = new TextEncoder().encode("ProgramDerivedAddress");
  for (let bump = 255; bump >= 0; bump--) {
    const out = await sha256([...seeds, Uint8Array.of(bump), program, tag]);
    if (!onCurve(out)) return out;
  }
  throw new Error("no viable bump for PDA");
}

export async function squadsV4Vault(multisig: string, index: number): Promise<string> {
  const text = new TextEncoder();
  const vault = await findPda(
    [text.encode("multisig"), decodePubkey(multisig), text.encode("vault"), Uint8Array.of(index)],
    decodePubkey(SQUADS_V4),
  );
  return encodeBase58(vault);
}

export async function squadsVaultOf(authority: string, multisigs: string[]): Promise<string | null> {
  for (const ms of multisigs) {
    for (let i = 0; i < VAULTS_CHECKED; i++) if ((await squadsV4Vault(ms, i)) === authority) return ms;
  }
  return null;
}

export function timelock(secs: number): string {
  if (secs === 0) return "no";
  if (secs % 86400 === 0) return `${secs / 86400}d`;
  if (secs % 3600 === 0) return `${secs / 3600}h`;
  if (secs % 60 === 0) return `${secs / 60}m`;
  return `${secs}s`;
}

export function decodeSquads(data: Uint8Array): Squads {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const threshold = v.getUint16(72, true);
  const timeLock = v.getUint32(74, true);
  let at = 94;
  at += v.getUint8(at) === 1 ? 33 : 1;
  at += 1;
  const count = v.getUint32(at, true);
  at += 4;
  let voters = 0;
  for (let i = 0; i < count; i++) if (v.getUint8(at + i * 33 + 32) & 2) voters++;
  return { threshold, voters, timeLock };
}

export function classify(authority: string | null, authorityOwner: string | null): string {
  if (!authority) return "immutable";
  if (onCurve(decodePubkey(authority))) return "single key";
  if (authorityOwner === SQUADS_V4) return "multisig (Squads v4)";
  if (authorityOwner === SQUADS_V3) return "multisig (Squads v3)";
  if (authorityOwner === SPL_GOVERNANCE) return "governance (SPL Governance)";
  return authorityOwner && authorityOwner !== SYSTEM
    ? `program-controlled (owner ${authorityOwner})`
    : "program-controlled (PDA)";
}

interface Account {
  owner: string;
  data: Uint8Array;
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

async function account(url: string, key: string): Promise<Account | null> {
  const r = await rpc<{ value: { owner: string; data: [string, string] } | null }>(url, "getAccountInfo", [
    key,
    { encoding: "base64", commitment: "finalized" },
  ]);
  if (!r.value) return null;
  return { owner: r.value.owner, data: Uint8Array.from(atob(r.value.data[0]), (c) => c.charCodeAt(0)) };
}

export async function survey(url: string, program: string, squads: string[]): Promise<Entry> {
  const e: Entry = { program, control: "", authority: null, slot: null, error: null };
  try {
    const acc = await account(url, program);
    if (!acc) throw new Error("account not found");
    if (LEGACY_LOADERS.includes(acc.owner)) return { ...e, control: "immutable" };
    if (acc.owner !== UPGRADEABLE_LOADER) throw new Error(`owned by ${acc.owner}, not a loader this census reads`);
    const head = new DataView(acc.data.buffer, acc.data.byteOffset, acc.data.byteLength);
    if (acc.data.length < 36 || head.getUint32(0, true) !== 2) throw new Error("not a program account");
    const pd = await account(url, encodeBase58(acc.data.slice(4, 36)));
    if (!pd) throw new Error("program data account not found");
    const d = new DataView(pd.data.buffer, pd.data.byteOffset, pd.data.byteLength);
    if (pd.data.length < 13 || d.getUint32(0, true) !== 3) throw new Error("not a program data account");
    e.slot = d.getBigUint64(4, true).toString();
    if (pd.data[12] === 1) {
      if (pd.data.length < 45) throw new Error("truncated program data account");
      e.authority = encodeBase58(pd.data.slice(13, 45));
    }
    const owner = e.authority ? ((await account(url, e.authority))?.owner ?? null) : null;
    e.control = classify(e.authority, owner);
    if (e.authority && e.control.startsWith("program-controlled")) {
      const ms = await squadsVaultOf(e.authority, squads);
      const msAcc = ms ? await account(url, ms) : null;
      if (ms && msAcc?.owner === SQUADS_V4) {
        const s = decodeSquads(msAcc.data);
        e.control = `multisig (Squads v4, ${s.threshold} of ${s.voters}, ${timelock(s.timeLock)} timelock)`;
      }
    }
  } catch (err) {
    e.error = err instanceof Error ? err.message : String(err);
  }
  return e;
}

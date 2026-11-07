import type { Review } from "./types";

interface Wasm {
  default: (input?: { module_or_path: string }) => Promise<unknown>;
  review(old: Uint8Array, next: Uint8Array): string;
  rulesVersion(): string;
  verifyLedger(input: string): string;
}

export const asset = (path: string) => `${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}/${path}`;

let loading: Promise<Wasm> | null = null;

export function engine(): Promise<Wasm> {
  loading ??= (async () => {
    const mod: Wasm = await import(/* webpackIgnore: true */ asset("wasm/tidemark.js"));
    await mod.default({ module_or_path: asset("wasm/tidemark_bg.wasm") });
    return mod;
  })();
  return loading;
}

export async function review(old: Uint8Array, next: Uint8Array): Promise<Review> {
  return JSON.parse((await engine()).review(old, next));
}

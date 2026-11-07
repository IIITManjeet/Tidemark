"use client";

import { useState } from "react";

export interface Picked {
  name: string;
  bytes: Uint8Array;
}

export function Drop({ kind, hint, file, onFile }: { kind: string; hint: string; file: Picked | null; onFile: (f: Picked) => void }) {
  const [over, setOver] = useState(false);

  async function take(f: File | undefined) {
    if (f) onFile({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
  }

  return (
    <label
      className={`rounded-2xl border bg-bg/60 flex min-h-28 cursor-pointer flex-col gap-1 px-5.5 py-5 transition-colors focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-accent motion-reduce:transition-none ${
        over ? "border-accent bg-panel-2" : file ? "border-line-2" : "border-dashed border-line-2 hover:border-accent hover:bg-panel-2"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        take(e.dataTransfer.files[0]);
      }}
    >
      <input type="file" accept=".so,application/octet-stream" className="sr-only" onChange={(e) => take(e.target.files?.[0])} />
      <span className="label-caps tracking-[0.12em]">{kind}</span>
      <span className="text-base font-semibold break-all">{file ? file.name : hint}</span>
      {file && <span className="font-mono text-[13px] text-muted">{(file.bytes.length / 1024).toFixed(1)} KiB</span>}
    </label>
  );
}

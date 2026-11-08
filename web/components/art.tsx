export function Logo({ size = 34 }: { size?: number }) {
  return (
    <svg viewBox="0 0 40 40" width={size} height={size} aria-hidden>
      <defs>
        <linearGradient id="logo-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#5b8cff" />
          <stop offset="1" stopColor="#1f55e6" />
        </linearGradient>
      </defs>
      <circle cx="20" cy="20" r="20" fill="url(#logo-g)" />
      <path d="M9 23c3.5-5 7-5 11 0s7.5 5 11 0" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" />
      <path d="M9 16c3.5-5 7-5 11 0s7.5 5 11 0" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" opacity=".5" />
    </svg>
  );
}

function Cube({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} aria-hidden>
      <defs>
        <linearGradient id="cube-top" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#9db9ff" />
          <stop offset="1" stopColor="#4f7dff" />
        </linearGradient>
        <linearGradient id="cube-left" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#3a6cff" />
          <stop offset="1" stopColor="#1638b8" />
        </linearGradient>
        <linearGradient id="cube-right" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#2452e8" />
          <stop offset="1" stopColor="#0f2a8f" />
        </linearGradient>
      </defs>
      <path d="M50 8 88 28 50 48 12 28Z" fill="url(#cube-top)" />
      <path d="M12 28 50 48v44L12 72Z" fill="url(#cube-left)" />
      <path d="M88 28 50 48v44l38-20Z" fill="url(#cube-right)" />
    </svg>
  );
}

function Orb({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} aria-hidden>
      <defs>
        <radialGradient id="orb" cx="0.35" cy="0.3" r="0.75">
          <stop offset="0" stopColor="#a9c2ff" />
          <stop offset="0.45" stopColor="#3d6dff" />
          <stop offset="1" stopColor="#0d2585" />
        </radialGradient>
      </defs>
      <circle cx="50" cy="50" r="46" fill="url(#orb)" />
    </svg>
  );
}

function Prism({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} aria-hidden>
      <defs>
        <linearGradient id="prism-a" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#7aa0ff" />
          <stop offset="1" stopColor="#2452e8" />
        </linearGradient>
      </defs>
      <path d="M50 6 92 86 50 72Z" fill="#1638b8" />
      <path d="M50 6 8 86 50 72Z" fill="url(#prism-a)" />
      <path d="M8 86 50 72 92 86 50 96Z" fill="#0f2a8f" />
    </svg>
  );
}

const DIFF = [
  ["ctx", "1b0a  ldxdw r1, [r10-136]"],
  ["ctx", "1b0b  ldxdw r2, [r10-96]"],
  ["del", "1b0c  jne r2, r1, 0x1aec"],
  ["add", "1b0c  ja 0x1b0d"],
  ["ctx", "1b0d  ldxdw r1, [r10-128]"],
  ["add", "1c40  lddw r2, 0x7fd3a9c1e2b4…"],
];

export function HeroArt() {
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[520px]" aria-hidden>
      <div className="absolute inset-[12%] rounded-full bg-accent/30 blur-3xl" />
      <div className="absolute inset-x-[14%] bottom-[4%] h-[22%] rounded-[2rem] border border-line-2/60 bg-gradient-to-b from-panel-2 to-bg" />
      <div className="absolute top-[10%] left-1/2 w-[64%] -translate-x-1/2 -rotate-3 rounded-[1.75rem] border border-line-2 bg-panel/95 p-4 shadow-2xl shadow-black/50 xs:p-5">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-xs text-muted">upgrade review</span>
          <span className="rounded-md border border-orange/50 bg-orange/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-orange">
            HIGH
          </span>
        </div>
        <div className="mb-3 text-2xl font-semibold xs:text-3xl">4 findings</div>
        <div className="space-y-1.5 rounded-xl bg-bg/70 p-2.5 font-mono text-[9px] leading-4 xs:text-[10px]">
          {DIFF.map(([k, l], i) => (
            <div
              key={i}
              className={`truncate rounded px-1.5 ${
                k === "add" ? "bg-accent/15 text-[#cfdcff]" : k === "del" ? "bg-orange/15 text-[#ffd6b8]" : "text-faint"
              }`}
            >
              {k === "add" ? "+ " : k === "del" ? "- " : "  "}
              {l}
            </div>
          ))}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
          {["TM-GUARD-GONE", "TM-KEY-ADD", "TM-CHECK-GONE", "TM-IX-CHANGE"].map((r) => (
            <div key={r} className="truncate rounded-lg border border-line bg-panel-2 px-2 py-1.5 font-mono text-muted">
              {r}
            </div>
          ))}
        </div>
      </div>
      <Cube className="animate-float absolute right-[2%] bottom-[16%] w-[22%]" />
      <SolCoin className="animate-float-slow absolute top-[3%] right-[5%] w-[17%]" />
      <Prism className="animate-float-slow absolute top-[30%] left-[0%] w-[16%] -rotate-12" />
      <Orb className="animate-float absolute bottom-[22%] left-[6%] w-[9%] opacity-80" />
    </div>
  );
}

export function Rings({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 600 600" className={className} aria-hidden>
      <defs>
        <radialGradient id="rings-fade" cx="0.3" cy="0.3" r="0.8">
          <stop offset="0" stopColor="#5b8cff" stopOpacity="0.9" />
          <stop offset="1" stopColor="#1f55e6" stopOpacity="0.15" />
        </radialGradient>
      </defs>
      <g fill="none" stroke="url(#rings-fade)" strokeWidth="1.4">
        {Array.from({ length: 22 }, (_, i) => (
          <circle key={i} cx={360 - i * 7} cy={360 - i * 7} r={300 - i * 13} />
        ))}
      </g>
    </svg>
  );
}

const ICONS: Record<string, React.ReactNode> = {
  diff: <path d="M8 6v12M16 6v12M5 9h6M13 15h6" />,
  rules: <path d="M12 3 4 6v6c0 4.4 3.4 8.3 8 9 4.6-.7 8-4.6 8-9V6l-8-3Zm-3 9 2 2 4-4" />,
  ledger: <path d="M7 7h10M7 12h10M7 17h6M5 3h14v18H5z" />,
  census: <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />,
  watch: <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />,
  browser: <path d="M3 5h18v14H3zM3 9h18M7 7h.01M10 7h.01" />,
};

export function Icon({ name }: { name: keyof typeof ICONS }) {
  return (
    <span className="grid size-12 place-items-center rounded-full bg-accent text-white shadow-[0_8px_24px_-6px_rgb(47_107_255/0.7)]">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        {ICONS[name]}
      </svg>
    </span>
  );
}

export type IconName = keyof typeof ICONS;

const SOL_BARS = [
  "M64.6 237.9c2.4-2.4 5.7-3.8 9.2-3.8h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7c-2.4 2.4-5.7 3.8-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1z",
  "M64.6 3.8C67.1 1.4 70.4 0 73.8 0h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7c-2.4 2.4-5.7 3.8-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1z",
  "M333.1 120.1c-2.4-2.4-5.7-3.8-9.2-3.8H6.5c-5.8 0-8.7 7-4.6 11.1l62.7 62.7c2.4 2.4 5.7 3.8 9.2 3.8h317.4c5.8 0 8.7-7 4.6-11.1z",
];

export function SolMark({ className = "", id = "sol" }: { className?: string; id?: string }) {
  return (
    <svg viewBox="0 0 398 312" className={className} aria-hidden>
      <defs>
        <linearGradient id={id} x1="360" y1="-37" x2="141" y2="383" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#00ffa3" />
          <stop offset="1" stopColor="#dc1fff" />
        </linearGradient>
      </defs>
      {SOL_BARS.map((d) => (
        <path key={d} d={d} fill={`url(#${id})`} />
      ))}
    </svg>
  );
}

export function SolCoin({ className = "" }: { className?: string }) {
  return (
    <div className={`grid aspect-square place-items-center rounded-full border border-white/15 bg-[radial-gradient(circle_at_35%_30%,#2a2f4a,#0b0f1f)] shadow-[0_18px_40px_-12px_rgb(220_31_255/0.45)] ${className}`} aria-hidden>
      <SolMark className="w-[52%]" id="sol-coin" />
    </div>
  );
}

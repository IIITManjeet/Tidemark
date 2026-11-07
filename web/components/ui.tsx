import type { Risk } from "@/lib/types";

const SEV: Record<Risk, string> = {
  critical: "text-red border-red/50 bg-red/10",
  high: "text-orange border-orange/50 bg-orange/10",
  medium: "text-amber border-amber/45 bg-amber/5",
  low: "text-link border-accent/45 bg-accent/5",
  info: "text-muted border-line-2",
};

export function Sev({ risk }: { risk: Risk }) {
  return (
    <span
      className={`inline-block min-w-16 rounded border px-2 py-0.5 text-center text-[10.5px] font-semibold tracking-[0.1em] uppercase ${SEV[risk]}`}
    >
      {risk}
    </span>
  );
}

const HEADLINE: Record<string, string> = {
  critical: "text-red",
  high: "text-orange",
  medium: "text-amber",
  low: "text-accent",
  info: "text-accent",
  ok: "text-green",
  bad: "text-red",
};

export function Headline({ label, value, tone, note }: { label: string; value: string; tone: string; note?: string }) {
  return (
    <div className="flex min-w-36 flex-col items-start gap-0.5 md:border-r md:border-line md:pr-7">
      <small className="label-caps">{label}</small>
      <b className={`text-3xl font-semibold tracking-wide ${HEADLINE[tone]}`}>{value}</b>
      {note && <small className="max-w-56 text-xs text-muted">{note}</small>}
    </div>
  );
}

export function Stat({ label, children, title }: { label: string; children: React.ReactNode; title?: string }) {
  return (
    <div>
      <dt className="label-caps">{label}</dt>
      <dd className="mt-1 break-all" title={title}>
        {children}
      </dd>
    </div>
  );
}

export function Summary({ head, children }: { head: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="mt-6 flex flex-wrap items-center gap-7 rounded-2xl border border-line bg-bg/60 px-5 py-5 sm:px-6">
      {head}
      <dl className="m-0 grid flex-1 grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-x-7 gap-y-3.5">{children}</dl>
    </div>
  );
}

export function Hero({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-6">
      <h2 className="mb-2 text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h2>
      <p className="m-0 max-w-[680px] text-muted">{children}</p>
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  if (!message) return null;
  return (
    <p role="alert" className="mt-3 rounded-xl border border-red/35 bg-red/10 px-3.5 py-2.5 text-[#f2b8b5]">
      {message}
    </p>
  );
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="mt-9 mb-3 text-xs font-semibold tracking-[0.12em] text-faint uppercase">{children}</h2>;
}

const BTN = {
  primary: "border-accent bg-accent text-white hover:border-accent-2 hover:bg-accent-2",
  ghost: "border-transparent bg-panel-2 text-text hover:bg-line",
};

export function Button({
  variant = "ghost",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof BTN }) {
  return (
    <button
      className={`cursor-pointer rounded-xl border px-5 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 motion-reduce:transition-none ${BTN[variant]} ${className}`}
      {...props}
    />
  );
}

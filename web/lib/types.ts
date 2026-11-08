export const RISKS = ["info", "low", "medium", "high", "critical"] as const;
export type Risk = (typeof RISKS)[number];

export interface Finding {
  id: string;
  severity: Risk;
  title: string;
  detail: string[];
}

export interface Hunk {
  old_start: number;
  new_start: number;
  lines: string[];
}

export interface Side {
  sha256: string;
  instructions: number;
}

export interface Report {
  rules_version: string;
  risk: Risk;
  old: Side;
  new: Side;
  changed_instructions: number;
  churn_pct: number;
  findings: Finding[];
  hunks: Hunk[];
}

export interface Review {
  report: Report;
  verdict_hash: string;
}

export interface Entry {
  index: number;
  program: string;
  risk: number;
  approvals: number;
  threshold: number;
  final: boolean;
  rules_version: string;
  slot: number;
  verdict_hash: string;
  entry_hash: string;
  deployed_slot: number | null;
  late_approvals: number;
}

export interface Ledger {
  ok: boolean;
  error?: string;
  registry: {
    layout: string;
    config_version: number;
    authority: string;
    head: string;
    count: number;
    threshold: number;
    active_reviewers: number;
  };
  entries: Entry[];
}

export interface Tally {
  id: string;
  question: string;
  yes: number;
  no: number;
  dropped: number;
  failed: number;
  cites: string[];
  errors: string[];
}

export interface Judgement {
  backend: string;
  explanation: string | null;
  explanation_error: string | null;
  questions: Tally[];
  risk_before: Risk;
  risk_after: Risk;
}

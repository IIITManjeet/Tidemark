export const REPO = "https://github.com/IIITManjeet/Tidemark";
export const ISSUES = `${REPO}/issues`;
export const LEDGER_V2 = "BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc";
export const REGISTRY_V2 = "72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU";
export const LEDGER_V3 = "8f43wqFP4wZ8NLrJgBrGXDrXp92FgxSvM9Ng21GrgPq6";
export const DEMO_PROGRAM = "5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3";
export const RULES = "tm-rules-0.7";

export const explorer = (key: string) => `https://explorer.solana.com/address/${key}?cluster=devnet`;

export const DOCS: { group: string; pages: { href: string; title: string }[] }[] = [
  {
    group: "Start",
    pages: [
      { href: "/docs", title: "Overview" },
      { href: "/docs/quickstart", title: "Quickstart" },
    ],
  },
  {
    group: "Use it",
    pages: [
      { href: "/docs/cli", title: "Command line" },
      { href: "/docs/vscode", title: "VS Code extension" },
      { href: "/docs/npm", title: "npm package" },
      { href: "/docs/web-app", title: "Web app" },
      { href: "/docs/ci", title: "CI gate" },
    ],
  },
  {
    group: "How it works",
    pages: [
      { href: "/docs/rules", title: "Risk rules" },
      { href: "/docs/ledger", title: "Attestation ledger" },
      { href: "/docs/ai-judge", title: "AI judge" },
      { href: "/docs/security", title: "Security model and limits" },
    ],
  },
];

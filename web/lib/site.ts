export const REPO = "https://github.com/IIITManjeet/Tidemark";
export const ISSUES = `${REPO}/issues`;
export const RELEASE = `${REPO}/releases/tag/v0.1.0`;
export const NPM = "https://www.npmjs.com/package/tidemark-wasm";
export const LEDGER_V2 = "BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc";
export const REGISTRY_V2 = "72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU";
export const LEDGER_V3 = "8f43wqFP4wZ8NLrJgBrGXDrXp92FgxSvM9Ng21GrgPq6";
export const REGISTRY_V3 = "GpkPYw7vbvyj3mZAKQY4zbsD9Pojtnpk78Sf4AQCsc9v";
export const UPGRADE_MULTISIG = "8jGmTqcvXfp8taPTq6u5Tmorbu7pByKGDmy4eYU2xki9";
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

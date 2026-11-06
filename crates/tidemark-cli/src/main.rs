use anyhow::{Context, Result};
use std::io::Write;

macro_rules! out {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tidemark_core::diff::{self, Severity};
use tidemark_core::{elf, ledger, report_hash, rpc, submit};

#[derive(Parser)]
#[command(
    name = "tidemark",
    version,
    about = "See what a Solana program upgrade actually changed"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Compare two program binaries (old -> new)")]
    Diff {
        old: PathBuf,
        new: PathBuf,
        #[arg(long, help = "Write the JSON report here")]
        json: Option<PathBuf>,
        #[arg(long, default_value_t = 4, help = "Code hunks to print")]
        hunks: usize,
    },
    #[command(about = "Summarize one program binary")]
    Inspect { file: PathBuf },
    #[command(about = "Download deployed bytecode and show its upgrade authority")]
    Fetch {
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    #[command(about = "Rebuild a registry's attestation chain and check it")]
    VerifyLedger {
        #[arg(long, help = "tidemark-ledger program id")]
        program: String,
        #[arg(long, help = "Registry account address")]
        registry: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    #[command(about = "Create your reviewer registry on the ledger")]
    InitRegistry {
        #[arg(long)]
        ledger: String,
        #[arg(long, default_value = "tidemark")]
        name: String,
        #[arg(long, default_value = "~/.config/solana/id.json")]
        keypair: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    #[command(about = "Publish a report's hash as the next ledger entry")]
    Attest {
        #[arg(help = "JSON report from `tidemark diff --json`")]
        report: PathBuf,
        #[arg(long, help = "Program that was reviewed")]
        program: String,
        #[arg(long)]
        ledger: String,
        #[arg(long, help = "Registry address (defaults to your own)")]
        registry: Option<String>,
        #[arg(long, default_value = "~/.config/solana/id.json")]
        keypair: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
}

fn expand(p: &str) -> String {
    match (
        p.strip_prefix("~/"),
        std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")),
    ) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => p.to_string(),
    }
}

fn read(p: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bs58_short(k: &[u8; 32]) -> String {
    let s = tidemark_core::bs58_encode(k);
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

fn sev(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Diff {
            old,
            new,
            json,
            hunks,
        } => {
            let o = elf::load(&read(&old)?)?;
            let n = elf::load(&read(&new)?)?;
            let r = diff::compare(&o, &n);
            out!("Tidemark upgrade review  ({})", r.rules_version);
            out!(
                "  old  {}  {} insns",
                &r.old.sha256[..16],
                r.old.instructions
            );
            out!(
                "  new  {}  {} insns",
                &r.new.sha256[..16],
                r.new.instructions
            );
            out!(
                "  changed instructions: {} ({}%)",
                r.changed_instructions,
                r.churn_pct
            );
            out!("  overall risk: {}\n", sev(r.risk));
            if !r.diff_exact {
                out!("  note: the code diff hit its time limit; hunks and churn are approximate\n");
            }
            for f in &r.findings {
                out!("[{:8}] {}  {}", sev(f.severity), f.id, f.title);
                for d in &f.detail {
                    out!("             {d}");
                }
            }
            for h in r.hunks.iter().take(hunks) {
                out!("\n@@ old {:#x} / new {:#x} @@", h.old_start, h.new_start);
                for l in h.lines.iter().take(30) {
                    out!("{l}");
                }
            }
            let rh = report_hash(&r);
            out!("\nreport hash (attest this): {rh}");
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_string_pretty(&r)?)?;
                out!("JSON report written to {}", p.display());
            }
            if r.risk >= Severity::High {
                std::process::exit(2);
            }
        }
        Cmd::Inspect { file } => {
            let p = elf::load(&read(&file)?)?;
            out!("sha256        {}", p.sha256);
            out!(
                "size          {} bytes, {} instructions",
                p.size,
                p.insn_count
            );
            out!("syscalls      {:?}", p.syscalls);
            out!("callx sites   {}", p.callx);
            out!("32-byte consts {}", p.consts32.len());
            out!(
                "security.txt  {}",
                if p.security_txt.is_some() {
                    "present"
                } else {
                    "absent"
                }
            );
        }
        Cmd::Fetch {
            program_id,
            rpc: url,
            out,
        } => {
            let d = rpc::fetch(&url, &program_id)?;
            std::fs::write(&out, &d.elf)?;
            out!("program data account  {}", d.programdata);
            out!("last deployed at slot {}", d.last_deploy_slot);
            out!(
                "upgrade authority     {}",
                d.upgrade_authority.as_deref().unwrap_or("none (immutable)")
            );
            out!("wrote {} bytes to {}", d.elf.len(), out.display());
        }
        Cmd::InitRegistry {
            ledger,
            name,
            keypair,
            rpc: url,
        } => {
            let key = submit::load_keypair(&expand(&keypair))?;
            let (registry, sig) =
                submit::init_registry(&url, submit::decode_pubkey(&ledger)?, &key, &name)?;
            out!("registry  {}", tidemark_core::bs58_encode(&registry));
            out!("tx        {sig}");
        }
        Cmd::Attest {
            report,
            program,
            ledger,
            registry,
            keypair,
            rpc: url,
        } => {
            let key = submit::load_keypair(&expand(&keypair))?;
            let ledger_pk = submit::decode_pubkey(&ledger)?;
            let registry_pk = match registry {
                Some(r) => submit::decode_pubkey(&r)?,
                None => submit::registry_address(&ledger_pk, key.verifying_key().as_bytes())?,
            };
            let raw = read(&report)?;
            let v: serde_json::Value =
                serde_json::from_slice(&raw).context("report is not valid JSON")?;
            let risk =
                tidemark_core::parse_risk(v["risk"].as_str().context("report has no risk field")?)?;
            let mut rules = [0u8; 16];
            let rv = v["rules_version"].as_str().unwrap_or("").as_bytes();
            rules[..rv.len().min(16)].copy_from_slice(&rv[..rv.len().min(16)]);
            let input = submit::AttestInput {
                program: submit::decode_pubkey(&program)?,
                old_code_hash: tidemark_core::parse_hash32(
                    v["old"]["sha256"]
                        .as_str()
                        .context("report missing old.sha256")?,
                )?,
                new_code_hash: tidemark_core::parse_hash32(
                    v["new"]["sha256"]
                        .as_str()
                        .context("report missing new.sha256")?,
                )?,
                report_hash: tidemark_core::parse_hash32(&tidemark_core::canonical_hash(&v))?,
                risk,
                rules_version: rules,
                model_id: [0u8; 32],
            };
            let (att, sig) = submit::attest(&url, ledger_pk, registry_pk, &key, &input)?;
            out!("attestation  {}", tidemark_core::bs58_encode(&att));
            out!("registry     {}", tidemark_core::bs58_encode(&registry_pk));
            out!("risk         {risk}");
            out!("tx           {sig}");
        }
        Cmd::VerifyLedger {
            program,
            registry,
            rpc: url,
        } => {
            let (reg, entries) = ledger::fetch(&url, &program, &registry)?;
            out!("registry  {registry}");
            out!(
                "entries   {} on-chain, registry count {}",
                entries.len(),
                reg.count
            );
            for a in {
                let mut e = entries.clone();
                e.sort_by_key(|a| a.index);
                e
            } {
                out!(
                    "  #{:<4} slot {:<10} risk {}  program {}  entry {}",
                    a.index,
                    a.slot,
                    a.risk,
                    bs58_short(&a.program),
                    &hex(&a.entry_hash)[..12]
                );
            }
            match ledger::verify_chain(&reg, entries) {
                Ok(n) => out!("chain OK: {n} entries, head {}", &hex(&reg.last_hash)[..16]),
                Err(e) => {
                    out!("chain BROKEN: {e:?}");
                    std::process::exit(3);
                }
            }
        }
    }
    Ok(())
}

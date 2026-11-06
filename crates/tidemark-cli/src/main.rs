use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::path::PathBuf;
use tidemark_core::diff::{self, Report, Severity};
use tidemark_core::submit::{self, Ctx, Pubkey};
use tidemark_core::{elf, ledger, report_hash, rpc, verdict_hash, verdict_risk};

macro_rules! out {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

const DEVNET: &str = "https://api.devnet.solana.com";
const DEFAULT_KEYPAIR: &str = "~/.config/solana/id.json";

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

#[derive(clap::Args)]
struct Chain {
    #[arg(long, help = "tidemark-ledger program id")]
    ledger: String,
    #[arg(long, default_value = DEVNET)]
    rpc: String,
    #[arg(long, default_value = DEFAULT_KEYPAIR, help = "Signer: registry authority or reviewer")]
    keypair: String,
    #[arg(long, help = "Fee payer, if different from the signer")]
    payer: Option<String>,
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
        #[arg(
            long,
            default_value = "high",
            help = "Exit with code 2 when risk reaches this level (info, low, medium, high, critical)"
        )]
        fail_on: String,
    },
    #[command(about = "Summarize one program binary")]
    Inspect { file: PathBuf },
    #[command(about = "Download deployed bytecode and show its upgrade authority")]
    Fetch {
        program_id: String,
        #[arg(long, default_value = DEVNET)]
        rpc: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    #[command(about = "Create a reviewer registry with a k-of-n approval threshold")]
    InitRegistry {
        #[command(flatten)]
        chain: Chain,
        #[arg(long, default_value = "tidemark")]
        name: String,
        #[arg(long, default_value_t = 1)]
        threshold: u8,
    },
    #[command(about = "Allow a key to attest and approve in your registry")]
    AddReviewer {
        #[command(flatten)]
        chain: Chain,
        key: String,
    },
    #[command(about = "Enable or disable a reviewer in your registry")]
    SetReviewer {
        #[command(flatten)]
        chain: Chain,
        key: String,
        #[arg(long, action = clap::ArgAction::Set)]
        active: bool,
    },
    #[command(about = "Change how many reviewers must approve an entry")]
    SetThreshold {
        #[command(flatten)]
        chain: Chain,
        threshold: u8,
    },
    #[command(about = "Start handing your registry to a new authority")]
    ProposeAuthority {
        #[command(flatten)]
        chain: Chain,
        new_authority: String,
    },
    #[command(about = "Accept a registry handed to you")]
    AcceptAuthority {
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        registry: String,
    },
    #[command(about = "Review a deployed upgrade and publish the verdict")]
    Attest {
        #[command(flatten)]
        chain: Chain,
        #[arg(long, help = "Program that was upgraded")]
        program: String,
        #[arg(long, help = "Snapshot of the program before the upgrade")]
        old: PathBuf,
        #[arg(
            long,
            help = "Registry address (defaults to the one your key controls)"
        )]
        registry: Option<String>,
        #[arg(long, help = "Write the full JSON report here")]
        json: Option<PathBuf>,
    },
    #[command(about = "Re-run a published review yourself and co-sign it if you agree")]
    Approve {
        #[command(flatten)]
        chain: Chain,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        index: u64,
        #[arg(long, help = "Snapshot of the program before the upgrade")]
        old: PathBuf,
    },
    #[command(about = "Rebuild a registry's chain, reviewers and approvals, and check them")]
    VerifyLedger {
        #[arg(long, help = "tidemark-ledger program id")]
        program: String,
        #[arg(long, help = "Registry account address")]
        registry: String,
        #[arg(long = "rpc", default_value = DEVNET, help = "RPC to read from; repeat to cross-check")]
        rpcs: Vec<String>,
    },
}

fn expand(p: &str) -> String {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
    match (p, home) {
        ("~", Ok(h)) => h,
        (_, Ok(h)) if p.starts_with("~/") || p.starts_with("~\\") => format!("{h}/{}", &p[2..]),
        _ => p.to_string(),
    }
}

fn read(p: &PathBuf) -> Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b58(k: &[u8]) -> String {
    tidemark_core::bs58_encode(k)
}

fn short(k: &[u8; 32]) -> String {
    let s = b58(k);
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

struct Keys {
    signer: SigningKey,
    payer: SigningKey,
}

fn keys(c: &Chain) -> Result<Keys> {
    let signer = submit::load_keypair(&expand(&c.keypair))?;
    let payer = match &c.payer {
        Some(p) => submit::load_keypair(&expand(p))?,
        None => signer.clone(),
    };
    Ok(Keys { signer, payer })
}

fn ctx<'a>(c: &'a Chain, k: &'a Keys) -> Result<Ctx<'a>> {
    Ok(Ctx {
        url: &c.rpc,
        ledger: submit::decode_pubkey(&c.ledger)?,
        payer: &k.payer,
    })
}

fn print_report(r: &Report, hunks: usize) {
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
}

fn review_deployed(rpc_url: &str, program: &str, old: &PathBuf) -> Result<Report> {
    let deployed = rpc::fetch(rpc_url, program)?;
    let o = elf::load(&read(old)?)?;
    let n = elf::load(&deployed.elf)?;
    Ok(diff::compare(&o, &n))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Diff {
            old,
            new,
            json,
            hunks,
            fail_on,
        } => {
            let gate = Severity::parse(&fail_on)?;
            let o = elf::load(&read(&old)?)?;
            let n = elf::load(&read(&new)?)?;
            let r = diff::compare(&o, &n);
            print_report(&r, hunks);
            out!("\nverdict hash  {}", verdict_hash(&r));
            out!("report hash   {}", report_hash(&r));
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_string_pretty(&r)?)?;
                out!("JSON report written to {}", p.display());
            }
            if r.risk >= gate {
                std::process::exit(2);
            }
        }
        Cmd::Inspect { file } => {
            let p = elf::load(&read(&file)?)?;
            out!("sha256         {}", p.sha256);
            out!(
                "size           {} bytes, {} instructions",
                p.size,
                p.insn_count
            );
            out!("syscalls       {:?}", p.syscalls);
            out!("callx sites    {}", p.callx);
            out!("32-byte consts {}", p.consts32.len());
            out!(
                "security.txt   {}",
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
            chain,
            name,
            threshold,
        } => {
            let k = keys(&chain)?;
            let (registry, sig) = ctx(&chain, &k)?.init_registry(&k.signer, &name, threshold)?;
            out!("registry   {}", b58(&registry));
            out!("threshold  {threshold}");
            out!("tx         {sig}");
        }
        Cmd::AddReviewer { chain, key } => {
            let k = keys(&chain)?;
            let sig = ctx(&chain, &k)?.add_reviewer(&k.signer, submit::decode_pubkey(&key)?)?;
            out!("added reviewer {key}\ntx {sig}");
        }
        Cmd::SetReviewer { chain, key, active } => {
            let k = keys(&chain)?;
            let sig = ctx(&chain, &k)?.set_reviewer_active(
                &k.signer,
                submit::decode_pubkey(&key)?,
                active,
            )?;
            out!("reviewer {key} active={active}\ntx {sig}");
        }
        Cmd::SetThreshold { chain, threshold } => {
            let k = keys(&chain)?;
            let sig = ctx(&chain, &k)?.set_threshold(&k.signer, threshold)?;
            out!("threshold {threshold}\ntx {sig}");
        }
        Cmd::ProposeAuthority {
            chain,
            new_authority,
        } => {
            let k = keys(&chain)?;
            let sig = ctx(&chain, &k)?
                .propose_authority(&k.signer, submit::decode_pubkey(&new_authority)?)?;
            out!("proposed {new_authority}; they must run accept-authority\ntx {sig}");
        }
        Cmd::AcceptAuthority { chain, registry } => {
            let k = keys(&chain)?;
            let sig =
                ctx(&chain, &k)?.accept_authority(&k.signer, submit::decode_pubkey(&registry)?)?;
            out!("you now control {registry}\ntx {sig}");
        }
        Cmd::Attest {
            chain,
            program,
            old,
            registry,
            json,
        } => {
            let k = keys(&chain)?;
            let c = ctx(&chain, &k)?;
            let registry: Pubkey = match registry {
                Some(r) => submit::decode_pubkey(&r)?,
                None => c.registry_address(&submit::pubkey_of(&k.signer))?,
            };
            let r = review_deployed(&chain.rpc, &program, &old)?;
            print_report(&r, 0);
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_string_pretty(&r)?)?;
            }
            let mut rules = [0u8; 16];
            let rv = r.rules_version.as_bytes();
            rules[..rv.len().min(16)].copy_from_slice(&rv[..rv.len().min(16)]);
            let input = submit::AttestInput {
                program: submit::decode_pubkey(&program)?,
                old_code_hash: tidemark_core::parse_hash32(&r.old.sha256)?,
                new_code_hash: tidemark_core::parse_hash32(&r.new.sha256)?,
                report_hash: tidemark_core::parse_hash32(&verdict_hash(&r))?,
                risk: verdict_risk(&r),
                rules_version: rules,
                model_id: [0u8; 32],
            };
            let (att, index, sig) = c.attest(&k.signer, registry, &input)?;
            out!("\nattestation  #{index} {}", b58(&att));
            out!("registry     {}", b58(&registry));
            out!("verdict      {}", verdict_hash(&r));
            out!("tx           {sig} (confirmed)");
        }
        Cmd::Approve {
            chain,
            registry,
            index,
            old,
        } => {
            let k = keys(&chain)?;
            let c = ctx(&chain, &k)?;
            let reg = submit::decode_pubkey(&registry)?;
            let snap = ledger::fetch(&chain.rpc, &chain.ledger, &registry)?;
            let a = snap
                .attestations
                .iter()
                .find(|a| a.index == index)
                .with_context(|| format!("entry #{index} not found in {registry}"))?;
            let r = review_deployed(&chain.rpc, &b58(&a.program), &old)?;
            let mine = tidemark_core::parse_hash32(&verdict_hash(&r))?;
            if hex(&a.old_code_hash) != r.old.sha256 || hex(&a.new_code_hash) != r.new.sha256 {
                bail!("entry #{index} reviewed different code than your snapshot and the deployed program");
            }
            if mine != a.report_hash {
                bail!(
                    "your review disagrees with entry #{index} (yours {}, theirs {}); not approving",
                    hex(&mine),
                    hex(&a.report_hash)
                );
            }
            let sig = c.approve(&k.signer, reg, index, mine)?;
            out!(
                "approved #{index}: independent review matches {}\ntx {sig} (confirmed)",
                hex(&mine)
            );
        }
        Cmd::VerifyLedger {
            program,
            registry,
            rpcs,
        } => {
            let ledger_pk = submit::decode_pubkey(&program)?;
            let mut heads = Vec::new();
            for (n, url) in rpcs.iter().enumerate() {
                let s = ledger::fetch(url, &program, &registry)?;
                if n == 0 {
                    out!("registry   {registry}");
                    out!("authority  {}", b58(&s.registry.authority));
                    out!(
                        "threshold  {} of {} active reviewers",
                        s.registry.threshold,
                        s.registry.active_reviewers
                    );
                    for (key, r) in &s.reviewers {
                        out!(
                            "  reviewer {} {}",
                            b58(key),
                            if r.active { "active" } else { "inactive" }
                        );
                    }
                }
                match ledger::verify(&ledger_pk, &s) {
                    Ok(status) => {
                        if n == 0 {
                            for st in &status {
                                let a = s
                                    .attestations
                                    .iter()
                                    .find(|x| x.index == st.index)
                                    .expect("entry");
                                out!(
                                    "  #{:<3} slot {:<10} risk {}  program {}  by {}  {}/{} {}",
                                    a.index,
                                    a.slot,
                                    a.risk,
                                    short(&a.program),
                                    short(&a.reviewer),
                                    st.approvals,
                                    st.threshold,
                                    if st.final_ { "final" } else { "pending" }
                                );
                            }
                        }
                        out!(
                            "{url}: chain OK, {} entries, head {}",
                            status.len(),
                            &hex(&s.registry.last_hash)[..16]
                        );
                        heads.push(s.registry.last_hash);
                    }
                    Err(e) => {
                        out!("{url}: chain BROKEN: {e:?}");
                        std::process::exit(3);
                    }
                }
            }
            if heads.windows(2).any(|w| w[0] != w[1]) {
                out!("RPCs disagree on the chain head");
                std::process::exit(3);
            }
        }
    }
    Ok(())
}

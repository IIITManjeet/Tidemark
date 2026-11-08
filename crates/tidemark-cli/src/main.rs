use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::path::PathBuf;
use tidemark_core::diff::{self, Report, Severity};
use tidemark_core::submit::{self, Ctx, Pubkey};
use tidemark_core::{elf, ledger, rpc, verdict_hash, verdict_risk};

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
        #[arg(
            long,
            help = "Reuse and store reviews in this directory, keyed by both hashes and the rules version"
        )]
        cache: Option<PathBuf>,
        #[arg(
            long,
            help = "Ask an AI jury about the findings (needs GEMINI_KEY); advisory, never part of the verdict hash"
        )]
        judge: bool,
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
    #[command(about = "Snapshot a program and review every upgrade as it lands")]
    Watch {
        program: String,
        #[arg(long, default_value = DEVNET)]
        rpc: String,
        #[arg(
            long,
            default_value = "snapshots",
            help = "Where snapshots and reports are kept"
        )]
        dir: PathBuf,
        #[arg(long, default_value_t = 30, help = "Seconds between checks")]
        interval: u64,
        #[arg(long, help = "Check once and exit")]
        once: bool,
        #[arg(long, help = "Attest each review to this tidemark-ledger program")]
        attest: Option<String>,
        #[arg(
            long,
            help = "Registry to attest into (defaults to the one your key controls)"
        )]
        registry: Option<String>,
        #[arg(long, default_value = DEFAULT_KEYPAIR)]
        keypair: String,
    },
    #[command(about = "Review a Squads v4 upgrade proposal before approving it")]
    Proposal {
        #[arg(long, help = "Squads v4 multisig address")]
        multisig: String,
        #[arg(long, help = "Transaction index of the proposal")]
        index: u64,
        #[arg(long, default_value = DEVNET)]
        rpc: String,
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
    #[command(about = "Classify who can upgrade each program")]
    Census {
        programs: Vec<String>,
        #[arg(long, help = "Read program ids from this file, one per line")]
        file: Option<PathBuf>,
        #[arg(long, default_value = DEVNET)]
        rpc: String,
        #[arg(long, help = "Print JSON instead of a table")]
        json: bool,
        #[arg(
            long = "squads",
            value_name = "MULTISIG",
            help = "Squads v4 multisig whose vaults may hold upgrade authority (repeatable)"
        )]
        squads: Vec<String>,
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
        layout: ledger::layout_for(&c.ledger),
        payer: &k.payer,
    })
}

fn print_report(r: &Report, hunks: usize) {
    print_value(&serde_json::to_value(r).expect("report serializes"), hunks);
}

fn print_value(r: &serde_json::Value, hunks: usize) {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
    let label = |v: &serde_json::Value| text(v).to_uppercase();
    let sha = |side: &str| {
        text(&r[side]["sha256"])
            .chars()
            .take(16)
            .collect::<String>()
    };
    out!("Tidemark upgrade review  ({})", text(&r["rules_version"]));
    out!("  old  {}  {} insns", sha("old"), r["old"]["instructions"]);
    out!("  new  {}  {} insns", sha("new"), r["new"]["instructions"]);
    out!(
        "  changed instructions: {} ({}%)",
        r["changed_instructions"],
        r["churn_pct"]
    );
    out!("  overall risk: {}\n", label(&r["risk"]));
    if r["diff_exact"] == false {
        out!("  note: the code diff hit its time limit; hunks and churn are approximate\n");
    }
    for f in r["findings"].as_array().into_iter().flatten() {
        out!(
            "[{:8}] {}  {}",
            label(&f["severity"]),
            text(&f["id"]),
            text(&f["title"])
        );
        for d in f["detail"].as_array().into_iter().flatten() {
            out!("             {}", text(d));
        }
    }
    for h in r["hunks"].as_array().into_iter().flatten().take(hunks) {
        let at = |k: &str| h[k].as_u64().unwrap_or(0);
        out!(
            "\n@@ old {:#x} / new {:#x} @@",
            at("old_start"),
            at("new_start")
        );
        for l in h["lines"].as_array().into_iter().flatten().take(30) {
            out!("{}", text(l));
        }
    }
}

fn review_deployed(rpc_url: &str, program: &str, old: &PathBuf) -> Result<Report> {
    Ok(review_deployed_at(rpc_url, program, old)?.0)
}

fn review_deployed_at(rpc_url: &str, program: &str, old: &PathBuf) -> Result<(Report, u64)> {
    let deployed = rpc::fetch(rpc_url, program)?;
    let o = elf::load(&read(old)?)?;
    let n = elf::load(&deployed.elf)?;
    Ok((diff::compare(&o, &n), deployed.last_deploy_slot))
}

fn rules16(v: &str) -> [u8; 16] {
    let mut rules = [0u8; 16];
    let rv = v.as_bytes();
    rules[..rv.len().min(16)].copy_from_slice(&rv[..rv.len().min(16)]);
    rules
}

fn print_judgement(j: &tidemark_core::judge::Judgement) {
    out!(
        "\nAI judge ({}), advisory: not part of the verdict hash or any attestation",
        j.backend
    );
    if let Some(e) = &j.explanation {
        out!("");
        for line in e.lines() {
            out!("  {line}");
        }
    }
    if let Some(e) = &j.explanation_error {
        out!("  explanation failed: {e}");
    }
    out!("");
    for t in &j.questions {
        let cites = if t.cites.is_empty() {
            String::new()
        } else {
            format!("  cites {}", t.cites.join(", "))
        };
        out!(
            "  [{}/{} yes] {}{cites}",
            t.yes,
            tidemark_core::judge::VOTES,
            t.question
        );
        if t.dropped > 0 {
            out!(
                "             {} yes without a valid citation dropped",
                t.dropped
            );
        }
        if t.failed > 0 {
            out!(
                "             {} vote(s) failed: {}",
                t.failed,
                t.errors.join("; ")
            );
        }
    }
    if j.risk_after > j.risk_before {
        out!(
            "  risk raised by the jury: {} -> {}",
            sev_name(j.risk_before),
            sev_name(j.risk_after)
        );
    }
}

fn sev_name(s: Severity) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_uppercase))
        .unwrap_or_default()
}

fn attest_report(
    c: &Ctx,
    signer: &SigningKey,
    registry: Pubkey,
    program: &str,
    r: &Report,
) -> Result<()> {
    let input = submit::AttestInput {
        program: submit::decode_pubkey(program)?,
        old_code_hash: tidemark_core::parse_hash32(&r.old.sha256)?,
        new_code_hash: tidemark_core::parse_hash32(&r.new.sha256)?,
        report_hash: tidemark_core::parse_hash32(&verdict_hash(r))?,
        risk: verdict_risk(r),
        rules_version: rules16(r.rules_version),
        model_id: [0u8; 32],
        elf_len: u32::try_from(r.new.size).context("program too large")?,
    };
    let (att, index, sig) = c.attest(signer, registry, &input)?;
    out!("\nattestation  #{index} {}", b58(&att));
    out!("registry     {}", b58(&registry));
    out!("verdict      {}", verdict_hash(r));
    out!("tx           {sig} (confirmed)");
    Ok(())
}

fn watch_once(
    rpc_url: &str,
    program: &str,
    dir: &std::path::Path,
    attest: Option<(&Ctx, &SigningKey, Pubkey)>,
) -> Result<()> {
    use tidemark_core::snapshots;
    let d = rpc::fetch(rpc_url, program)?;
    let slot = d.last_deploy_slot;
    if snapshots::path_for(dir, program, slot)?.exists() {
        return Ok(());
    }
    let Some(prev) = snapshots::previous(dir, program, slot)? else {
        snapshots::store(dir, program, slot, &d.elf)?;
        out!("{program}: baseline snapshot at slot {slot}");
        return Ok(());
    };
    out!("{program}: upgraded, slot {prev} -> {slot}\n");
    let old = elf::load(&read(&snapshots::path_for(dir, program, prev)?)?)?;
    let new = elf::load(&d.elf)?;
    let r = diff::compare(&old, &new);
    print_report(&r, 0);
    let report = dir.join(program).join(format!("{prev}-{slot}.json"));
    std::fs::write(&report, serde_json::to_string_pretty(&r)?)?;
    out!("\nreport written to {}", report.display());
    if let Some((c, signer, registry)) = attest {
        attest_report(c, signer, registry, program, &r)?;
    }
    snapshots::store(dir, program, slot, &d.elf)?;
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Diff {
            old,
            new,
            json,
            hunks,
            fail_on,
            cache,
            judge,
        } => {
            let gate = Severity::parse(&fail_on)?;
            let (a, b) = (read(&old)?, read(&new)?);
            let (sa, sb) = (elf::sha256_hex(&a), elf::sha256_hex(&b));
            let hit = cache
                .as_deref()
                .and_then(|d| tidemark_core::cache::get(d, &sa, &sb));
            let cached = hit.is_some();
            let e = match hit {
                Some(e) => e,
                None => {
                    let r = diff::compare(&elf::load(&a)?, &elf::load(&b)?);
                    let e = tidemark_core::cache::entry(&r);
                    if let Some(d) = &cache {
                        tidemark_core::cache::put(d, &sa, &sb, &e)?;
                    }
                    e
                }
            };
            let r = &e["report"];
            print_value(r, hunks);
            out!(
                "\nverdict hash  {}",
                e["verdict_hash"].as_str().unwrap_or("")
            );
            out!("report hash   {}", e["report_hash"].as_str().unwrap_or(""));
            if cached {
                out!("(from cache)");
            }
            let mut risk = Severity::parse(r["risk"].as_str().context("report has no risk")?)?;
            let mut judged = None;
            if judge {
                match tidemark_core::judge::gemini::Gemini::from_env() {
                    None => out!(
                        "\nAI judge skipped: set {} in the environment to use --judge",
                        tidemark_core::judge::gemini::KEY_VAR
                    ),
                    Some(g) => {
                        let j = tidemark_core::judge::judge(&g, r)?;
                        print_judgement(&j);
                        risk = risk.max(j.risk_after);
                        judged = Some(j);
                    }
                }
            }
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_string_pretty(r)?)?;
                out!("JSON report written to {}", p.display());
                if let Some(j) = &judged {
                    let jp = p.with_extension("judge.json");
                    std::fs::write(&jp, serde_json::to_string_pretty(j)?)?;
                    out!("AI judgement written to {}", jp.display());
                }
            }
            if risk >= gate {
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
        Cmd::Proposal {
            multisig,
            index,
            rpc: url,
            json,
            hunks,
            fail_on,
        } => {
            let gate = Severity::parse(&fail_on)?;
            let tx = tidemark_core::proposal::transaction_address(&multisig, index)?;
            let (data, owner) = rpc::fetch_account(&url, &tx)?;
            if owner != tidemark_core::census::SQUADS_V4 {
                bail!("{tx} is not owned by Squads v4 (owner {owner})");
            }
            let upgrades = tidemark_core::proposal::parse_vault_transaction(&data)?;
            if upgrades.is_empty() {
                bail!("proposal #{index} on {multisig} contains no program upgrade");
            }
            let mut worst = Severity::Info;
            for (i, u) in upgrades.iter().enumerate() {
                if i > 0 {
                    out!("");
                }
                out!(
                    "proposal #{index} on {multisig}: upgrade {} from buffer {}",
                    u.program,
                    u.buffer
                );
                let live = rpc::fetch(&url, &u.program)?;
                let (new, buffer_authority) = rpc::fetch_buffer(&url, &u.buffer)?;
                out!(
                    "  buffer authority  {}",
                    buffer_authority.as_deref().unwrap_or("none")
                );
                let r = diff::compare(&elf::load(&live.elf)?, &elf::load(&new)?);
                print_report(&r, hunks);
                out!("\nverdict hash  {}", verdict_hash(&r));
                out!("report hash   {}", tidemark_core::report_hash(&r));
                worst = worst.max(r.risk);
                if let Some(p) = &json {
                    let p = if upgrades.len() == 1 {
                        p.clone()
                    } else {
                        p.with_extension(format!("{i}.json"))
                    };
                    std::fs::write(&p, serde_json::to_string_pretty(&r)?)?;
                    out!("JSON report written to {}", p.display());
                }
            }
            if worst >= gate {
                std::process::exit(2);
            }
        }
        Cmd::Watch {
            program,
            rpc: url,
            dir,
            interval,
            once,
            attest,
            registry,
            keypair,
        } => {
            let chain = attest.map(|ledger| Chain {
                ledger,
                rpc: url.clone(),
                keypair,
                payer: None,
            });
            let k = chain.as_ref().map(keys).transpose()?;
            let c = match (&chain, &k) {
                (Some(ch), Some(k)) => Some(ctx(ch, k)?),
                _ => None,
            };
            let reg = match (&c, &k) {
                (Some(c), Some(k)) => Some(match &registry {
                    Some(r) => submit::decode_pubkey(r)?,
                    None => c.registry_address(&submit::pubkey_of(&k.signer))?,
                }),
                _ => None,
            };
            loop {
                let target = match (&c, &k, reg) {
                    (Some(c), Some(k), Some(r)) => Some((c, &k.signer, r)),
                    _ => None,
                };
                match watch_once(&url, &program, &dir, target) {
                    Ok(()) => {}
                    Err(e) if !once => eprintln!("{program}: {e:#}"),
                    Err(e) => return Err(e),
                }
                if once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(interval.max(5)));
            }
        }
        Cmd::Census {
            mut programs,
            file,
            rpc: url,
            json,
            squads,
        } => {
            if let Some(f) = file {
                let text = std::fs::read_to_string(&f)?;
                programs.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(String::from),
                );
            }
            if programs.is_empty() {
                bail!("give program ids as arguments or with --file");
            }
            let rows: Vec<_> = programs
                .iter()
                .map(|p| tidemark_core::census::survey(&url, p, &squads))
                .collect();
            if json {
                out!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                out!(
                    "{:<44}  {:<28}  {:<10}  {}",
                    "program",
                    "upgrade control",
                    "sec.txt",
                    "authority"
                );
                for r in &rows {
                    let control = match &r.error {
                        Some(e) => format!("error: {e}"),
                        None => r.control.label(),
                    };
                    out!(
                        "{:<44}  {:<28}  {:<10}  {}",
                        r.program,
                        control,
                        if r.security_txt { "yes" } else { "no" },
                        r.authority.as_deref().unwrap_or("-")
                    );
                }
            }
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
            attest_report(&c, &k.signer, registry, &program, &r)?;
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
            if let Err(e) = ledger::verify(&c.ledger, &snap) {
                bail!(
                    "the chain served by {} does not verify ({e:?}); not approving",
                    chain.rpc
                );
            }
            if snap.registry.layout != c.layout {
                bail!(
                    "registry layout {:?} does not match the ledger program ({:?})",
                    snap.registry.layout,
                    c.layout
                );
            }
            let a = snap
                .attestations
                .iter()
                .find(|a| a.index == index)
                .with_context(|| format!("entry #{index} not found in {registry}"))?;
            let (r, slot) = review_deployed_at(&chain.rpc, &b58(&a.program), &old)?;
            let mine = tidemark_core::parse_hash32(&verdict_hash(&r))?;
            if let Some(d) = &a.deploy {
                if d.deployed_slot != slot {
                    bail!(
                        "entry #{index} was attested against the deploy at slot {}, but the program was redeployed at slot {slot}; not approving",
                        d.deployed_slot
                    );
                }
            }
            if hex(&a.old_code_hash) != r.old.sha256 || hex(&a.new_code_hash) != r.new.sha256 {
                bail!("entry #{index} reviewed different code than your snapshot and the deployed program");
            }
            if a.risk != verdict_risk(&r) || a.rules_version != rules16(r.rules_version) {
                bail!(
                    "entry #{index} records risk {} under {:?}, but the review it commits to is risk {} under {}; not approving",
                    a.risk,
                    String::from_utf8_lossy(&a.rules_version).trim_end_matches('\0'),
                    verdict_risk(&r),
                    r.rules_version
                );
            }
            if mine != a.report_hash {
                bail!(
                    "your review disagrees with entry #{index} (yours {}, theirs {}); not approving",
                    hex(&mine),
                    hex(&a.report_hash)
                );
            }
            let bound = match snap.registry.layout {
                ledger::Layout::V2 => mine,
                ledger::Layout::V3 => ledger::approval_digest(&a.entry_hash),
            };
            let sig = c.approve(&k.signer, reg, index, bound)?;
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
                    out!("registry   {registry} ({:?})", s.registry.layout);
                    out!("authority  {}", b58(&s.registry.authority));
                    if s.registry.layout == ledger::Layout::V3 {
                        out!(
                            "config     version {} (bumps on every reviewer, threshold or authority change)",
                            s.registry.config_version
                        );
                    }
                    match rpc::fetch(url, &program) {
                        Ok(d) => {
                            let who = d
                                .upgrade_authority
                                .as_deref()
                                .map_or("none (frozen)".to_string(), |a| a.to_string());
                            out!(
                                "ledger     {program} upgrade authority {who}, last deployed at slot {}",
                                d.last_deploy_slot
                            );
                            let first = s.attestations.iter().map(|a| a.slot).min();
                            if let Some(first) = first.filter(|f| d.last_deploy_slot > *f) {
                                out!(
                                    "  warning: the ledger program was redeployed at slot {} after entries were written (first at {first}); its new code can rewrite them",
                                    d.last_deploy_slot
                                );
                            }
                            if d.upgrade_authority.is_some() {
                                out!("  note: whoever holds the ledger's upgrade authority can change its rules");
                            }
                        }
                        Err(e) => out!("ledger     could not read the ledger program: {e:#}"),
                    }
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
                                let deployed = a
                                    .deploy
                                    .map(|d| format!("  deployed@{}", d.deployed_slot))
                                    .unwrap_or_default();
                                let late = if st.late_approvals > 0 {
                                    format!(
                                        "  ({} by reviewers added after this entry)",
                                        st.late_approvals
                                    )
                                } else {
                                    String::new()
                                };
                                out!(
                                    "  #{:<3} slot {:<10} risk {}  program {}  by {}  {}/{} {}{deployed}{late}",
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

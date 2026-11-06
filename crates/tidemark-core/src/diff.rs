use crate::elf::{Program, WideLoad};
use crate::syscalls;
use serde::Serialize;
use sha2::{Digest, Sha256};
use similar::{Algorithm, ChangeTag, TextDiff};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                anyhow::bail!("unknown severity {other:?}; use info, low, medium, high or critical")
            }
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Hunk {
    pub old_start: usize,
    pub new_start: usize,
    pub lines: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Side {
    pub sha256: String,
    pub size: usize,
    pub instructions: usize,
    pub sbpf_version: u8,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub rules_version: &'static str,
    pub old: Side,
    pub new: Side,
    pub risk: Severity,
    pub changed_instructions: usize,
    pub churn_pct: f64,
    pub diff_exact: bool,
    pub findings: Vec<Finding>,
    pub hunks: Vec<Hunk>,
}

pub const RULES_VERSION: &str = "tm-rules-0.2";

const KNOWN: &[(&str, &str)] = &[
    ("11111111111111111111111111111111", "System Program"),
    ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SPL Token"),
    (
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "SPL Token-2022",
    ),
    (
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "Associated Token Account",
    ),
    (
        "BPFLoaderUpgradeab1e11111111111111111111111",
        "BPF Upgradeable Loader",
    ),
    (
        "ComputeBudget111111111111111111111111111111",
        "Compute Budget",
    ),
    ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "SPL Memo"),
    (
        "Sysvar1nstructions1111111111111111111111111",
        "Instructions sysvar",
    ),
];

fn name_key(k: &[u8; 32]) -> String {
    let b58 = bs58::encode(k).into_string();
    match KNOWN.iter().find(|(id, _)| *id == b58) {
        Some((_, n)) => format!("{b58} ({n})"),
        None => b58,
    }
}

const ANCHOR_CHECKS: &[(i64, &str)] = &[
    (2001, "ConstraintHasOne"),
    (2002, "ConstraintSigner"),
    (2003, "ConstraintRaw"),
    (2004, "ConstraintOwner"),
    (2006, "ConstraintSeeds"),
    (2012, "ConstraintAddress"),
    (3007, "AccountOwnedByWrongProgram"),
    (3010, "AccountNotSigner"),
];

const DIFF_DEADLINE: Duration = Duration::from_secs(10);
const MAX_NAME_LEN: usize = 64;
const MAX_NAME_WORDS: usize = 8;
const KEY_PC_WINDOW: usize = 64;

fn discriminator(name: &str) -> u64 {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
}

fn camel_words(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices().skip(1) {
        if c.is_ascii_uppercase() {
            out.push(&s[start..i]);
            start = i;
        }
    }
    out.push(&s[start..]);
    out
}

fn handler_names(p: &Program) -> Vec<(String, u64)> {
    let wide: BTreeSet<u64> = p.wide.iter().map(|w| w.value).collect();
    let needle = b"Instruction: ";
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(pos) = p.rodata[i..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let at = i + pos + needle.len();
        let run: String = p.rodata[at..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .take(MAX_NAME_LEN)
            .map(|b| *b as char)
            .collect();
        let mut words = camel_words(&run);
        words.truncate(MAX_NAME_WORDS);
        for k in (1..=words.len()).rev() {
            let name = words[..k]
                .iter()
                .map(|w| w.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join("_");
            let d = discriminator(&name);
            if wide.contains(&d) {
                out.push((name, d));
                break;
            }
        }
        i = at;
    }
    out
}

fn anchor_handlers(p: &Program) -> BTreeSet<String> {
    handler_names(p).into_iter().map(|(n, _)| n).collect()
}

fn handler_discriminators(p: &Program) -> Vec<u64> {
    handler_names(p).into_iter().map(|(_, d)| d).collect()
}

fn high_entropy(v: u64) -> bool {
    let distinct = v.to_le_bytes().iter().collect::<BTreeSet<_>>().len();
    distinct >= 6 && (v >> 32) > 0x10
}

fn inline_keys(old: &Program, new: &Program, skip: &BTreeSet<u64>) -> Vec<[u8; 32]> {
    let seen: BTreeSet<u64> = old.wide.iter().map(|w| w.value).collect();
    let fresh: Vec<&WideLoad> = new
        .wide
        .iter()
        .filter(|w| {
            w.slot.is_some()
                && high_entropy(w.value)
                && !seen.contains(&w.value)
                && !skip.contains(&w.value)
        })
        .collect();
    let mut by_slot: HashMap<(u8, i16), Vec<usize>> = HashMap::new();
    for (i, w) in fresh.iter().enumerate() {
        by_slot
            .entry(w.slot.expect("filtered"))
            .or_default()
            .push(i);
    }
    let mut used = vec![false; fresh.len()];
    let mut keys = Vec::new();
    for (a, w) in fresh.iter().enumerate() {
        if used[a] {
            continue;
        }
        let (base, off) = w.slot.expect("filtered");
        let mut parts = vec![a];
        for step in 1..4i16 {
            let Some(want_off) = off.checked_add(8 * step) else {
                break;
            };
            let Some(cands) = by_slot.get(&(base, want_off)) else {
                break;
            };
            let lo = w.pc.saturating_sub(KEY_PC_WINDOW);
            let first = cands.partition_point(|&i| fresh[i].pc < lo);
            let hit = cands[first..]
                .iter()
                .take_while(|&&i| fresh[i].pc <= w.pc + KEY_PC_WINDOW)
                .find(|&&i| !used[i] && i != a);
            match hit {
                Some(&b) => parts.push(b),
                None => break,
            }
        }
        if parts.len() == 4 {
            let mut k = [0u8; 32];
            for (j, idx) in parts.iter().enumerate() {
                used[*idx] = true;
                k[j * 8..j * 8 + 8].copy_from_slice(&fresh[*idx].value.to_le_bytes());
            }
            keys.push(k);
        }
    }
    keys
}

fn is_known(k: &[u8; 32]) -> bool {
    let b58 = bs58::encode(k).into_string();
    KNOWN.iter().any(|(id, _)| *id == b58)
}

pub fn compare(old: &Program, new: &Program) -> Report {
    let mut findings = Vec::new();

    let mut added_sc = Vec::new();
    let mut removed_sc = Vec::new();
    let mut sc_weight = 0u8;
    for (name, &n) in &new.syscalls {
        let o = old.syscalls.get(name).copied().unwrap_or(0);
        if n > o {
            sc_weight = sc_weight.max(syscalls::weight(name));
            added_sc.push(format!("{name}: {o} → {n} call sites"));
        }
    }
    for (name, &o) in &old.syscalls {
        let n = new.syscalls.get(name).copied().unwrap_or(0);
        if n < o {
            removed_sc.push(format!("{name}: {o} → {n} call sites"));
        }
    }
    if !added_sc.is_empty() {
        let (sev, title) = match sc_weight {
            3 => (
                Severity::High,
                "New signed cross-program invocations (invoke_signed)",
            ),
            1 => (Severity::Low, "New uses of sensitive syscalls"),
            _ => (Severity::Info, "Syscall usage increased"),
        };
        findings.push(Finding {
            id: "TM-SYSCALL-ADD",
            severity: sev,
            title: title.into(),
            detail: added_sc,
        });
    }
    if !removed_sc.is_empty() {
        findings.push(Finding {
            id: "TM-SYSCALL-DEL",
            severity: Severity::Info,
            title: "Syscall usage decreased".into(),
            detail: removed_sc,
        });
    }

    if new.callx > old.callx {
        findings.push(Finding {
            id: "TM-CALLX-ADD",
            severity: Severity::Medium,
            title: "New indirect calls (callx)".into(),
            detail: vec![format!(
                "{} → {} indirect call sites; targets are computed at runtime",
                old.callx, new.callx
            )],
        });
    }

    let mut new_keys: Vec<[u8; 32]> = new.consts32.difference(&old.consts32).copied().collect();
    let skip: BTreeSet<u64> = handler_discriminators(new).into_iter().collect();
    for k in inline_keys(old, new, &skip) {
        if !new_keys.contains(&k) {
            new_keys.push(k);
        }
    }
    let unknown: Vec<String> = new_keys
        .iter()
        .filter(|k| !is_known(k))
        .take(12)
        .map(name_key)
        .collect();
    let known: Vec<String> = new_keys
        .iter()
        .filter(|k| is_known(k))
        .map(name_key)
        .collect();
    if !unknown.is_empty() {
        findings.push(Finding {
            id: "TM-KEY-ADD",
            severity: Severity::High,
            title: format!("{} new hardcoded key(s)", unknown.len()),
            detail: unknown,
        });
    }
    if !known.is_empty() {
        findings.push(Finding {
            id: "TM-PROG-REF",
            severity: Severity::Low,
            title: "New references to well-known programs".into(),
            detail: known,
        });
    }

    let (oi, ni) = (anchor_handlers(old), anchor_handlers(new));
    let added_ix: Vec<_> = ni.difference(&oi).map(|s| format!("+ {s}")).collect();
    let removed_ix: Vec<_> = oi.difference(&ni).map(|s| format!("- {s}")).collect();
    if !added_ix.is_empty() || !removed_ix.is_empty() {
        let mut d = added_ix.clone();
        d.extend(removed_ix);
        findings.push(Finding {
            id: "TM-IX-CHANGE",
            severity: if added_ix.is_empty() {
                Severity::Low
            } else {
                Severity::Medium
            },
            title: "Instruction handlers added or removed".into(),
            detail: d,
        });
    }

    let mut gone = Vec::new();
    for (code, name) in ANCHOR_CHECKS {
        let o = old.imm_counts.get(code).copied().unwrap_or(0);
        let n = new.imm_counts.get(code).copied().unwrap_or(0);
        if n < o {
            gone.push(format!("{name} ({code}): {o} → {n} check sites"));
        }
    }
    if !gone.is_empty() {
        findings.push(Finding {
            id: "TM-CHECK-GONE",
            severity: Severity::High,
            title: "Account checks were removed".into(),
            detail: gone,
        });
    }

    if old.security_txt != new.security_txt {
        findings.push(Finding {
            id: "TM-SECTXT",
            severity: if new.security_txt.is_none() {
                Severity::Medium
            } else {
                Severity::Low
            },
            title: match (&old.security_txt, &new.security_txt) {
                (Some(_), None) => "security.txt was removed".into(),
                (None, Some(_)) => "security.txt was added".into(),
                _ => "security.txt contents changed".into(),
            },
            detail: vec![],
        });
    }

    let a = old.norm.join("\n");
    let b = new.norm.join("\n");
    let started = Instant::now();
    let td = TextDiff::configure()
        .algorithm(Algorithm::Patience)
        .timeout(DIFF_DEADLINE)
        .diff_lines(&a, &b);
    let diff_exact = started.elapsed() < DIFF_DEADLINE;
    let mut changed = 0usize;
    for c in td.iter_all_changes() {
        if c.tag() != ChangeTag::Equal {
            changed += 1;
        }
    }
    let mut hunks = Vec::new();
    for group in td.grouped_ops(3).into_iter().take(40) {
        let first = &group[0];
        let mut lines = Vec::new();
        for op in &group {
            for c in td.iter_changes(op) {
                let line = match c.tag() {
                    ChangeTag::Equal => format!(
                        "  {}",
                        old.lines
                            .get(c.old_index().unwrap_or(0))
                            .map(|s| s.as_str())
                            .unwrap_or("")
                    ),
                    ChangeTag::Delete => format!(
                        "- {}",
                        old.lines
                            .get(c.old_index().unwrap_or(0))
                            .map(|s| s.as_str())
                            .unwrap_or("")
                    ),
                    ChangeTag::Insert => format!(
                        "+ {}",
                        new.lines
                            .get(c.new_index().unwrap_or(0))
                            .map(|s| s.as_str())
                            .unwrap_or("")
                    ),
                };
                lines.push(line);
            }
        }
        hunks.push(Hunk {
            old_start: first.old_range().start,
            new_start: first.new_range().start,
            lines,
        });
    }
    let churn = if old.insn_count.max(new.insn_count) == 0 {
        0.0
    } else {
        (changed as f64 * 100.0 / (old.insn_count + new.insn_count) as f64 * 100.0).round() / 100.0
    };
    if churn >= 25.0 && old.insn_count.max(new.insn_count) >= 200 {
        findings.push(Finding {
            id: "TM-CHURN",
            severity: Severity::Medium,
            title: format!("Large rewrite: {churn}% of instructions changed"),
            detail: vec!["Big diffs hide small malicious changes; review carefully.".into()],
        });
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let risk = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);

    Report {
        tool: concat!("tidemark-core ", env!("CARGO_PKG_VERSION")),
        rules_version: RULES_VERSION,
        old: Side {
            sha256: old.sha256.clone(),
            size: old.size,
            instructions: old.insn_count,
            sbpf_version: old.sbpf_version,
        },
        new: Side {
            sha256: new.sha256.clone(),
            size: new.size,
            instructions: new.insn_count,
            sbpf_version: new.sbpf_version,
        },
        risk,
        changed_instructions: changed,
        churn_pct: churn,
        diff_exact,
        findings,
        hunks,
    }
}

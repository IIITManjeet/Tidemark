use crate::elf::Program;
use crate::syscalls;
use serde::Serialize;
use similar::{ChangeTag, TextDiff};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
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
    pub findings: Vec<Finding>,
    pub hunks: Vec<Hunk>,
}

pub const RULES_VERSION: &str = "tm-rules-0.1";

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

    let new_keys: Vec<_> = new.consts32.difference(&old.consts32).collect();
    let unknown: Vec<String> = new_keys
        .iter()
        .filter(|k| !is_known(k))
        .take(12)
        .map(|k| name_key(k))
        .collect();
    let known: Vec<String> = new_keys
        .iter()
        .filter(|k| is_known(k))
        .map(|k| name_key(k))
        .collect();
    if !unknown.is_empty() {
        findings.push(Finding {
            id: "TM-KEY-ADD",
            severity: Severity::High,
            title: format!(
                "{} new hardcoded 32-byte value(s), possibly pubkeys",
                new_keys.len() - known.len()
            ),
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

    let ix = |p: &Program| -> std::collections::BTreeSet<String> {
        p.strings
            .iter()
            .filter_map(|s| {
                s.find("Instruction: ").map(|i| {
                    s[i + 13..]
                        .split(|c: char| !c.is_alphanumeric())
                        .next()
                        .unwrap_or("")
                        .to_string()
                })
            })
            .filter(|s| !s.is_empty())
            .collect()
    };
    let (oi, ni) = (ix(old), ix(new));
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

    let check_words = [
        "signer",
        "Signer",
        "owner",
        "Owner",
        "has_one",
        "HasOne",
        "constraint",
        "Constraint",
        "Unauthorized",
        "authority",
    ];
    let gone: Vec<String> = old
        .strings
        .difference(&new.strings)
        .filter(|s| check_words.iter().any(|w| s.contains(w)))
        .take(10)
        .cloned()
        .collect();
    if !gone.is_empty() {
        findings.push(Finding {
            id: "TM-CHECK-GONE",
            severity: Severity::High,
            title: "Strings tied to access checks disappeared".into(),
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
    let td = TextDiff::from_lines(&a, &b);
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
        },
        new: Side {
            sha256: new.sha256.clone(),
            size: new.size,
            instructions: new.insn_count,
        },
        risk,
        changed_instructions: changed,
        churn_pct: churn,
        findings,
        hunks,
    }
}

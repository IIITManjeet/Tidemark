use crate::elf::{Program, WideLoad};
use crate::handlers::{self, Handler};
use crate::syscalls;
use serde::Serialize;
use similar::{Algorithm, ChangeTag, TextDiff};
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

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

pub const RULES_VERSION: &str = "tm-rules-0.3";

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
const KEY_PC_WINDOW: usize = 64;

fn check_name(code: i64) -> String {
    match ANCHOR_CHECKS.iter().find(|(c, _)| *c == code) {
        Some((_, n)) => format!("{n} ({code})"),
        None if code >= 6000 => format!("custom error {code}"),
        None => format!("error {code}"),
    }
}

fn check_findings(
    old: &Program,
    new: &Program,
    oh: &BTreeMap<u64, Handler>,
    nh: &BTreeMap<u64, Handler>,
    findings: &mut Vec<Finding>,
) {
    let (mut anchor, mut custom) = (Vec::new(), Vec::new());
    let per_handler = oh.values().any(|h| h.dispatched) && nh.values().any(|h| h.dispatched);
    if per_handler {
        for (d, a) in oh.iter().filter(|(_, h)| h.dispatched) {
            let Some(b) = nh.get(d).filter(|h| h.dispatched) else {
                continue;
            };
            for (code, &o) in &a.checks {
                let n = b.checks.get(code).copied().unwrap_or(0);
                if n >= o {
                    continue;
                }
                let line = format!(
                    "{}: {}: {o} → {n} check sites",
                    b.label(*d),
                    check_name(*code)
                );
                if *code >= 6000 {
                    custom.push(line);
                } else if ANCHOR_CHECKS.iter().any(|(c, _)| c == code) {
                    anchor.push(line);
                }
            }
        }
    } else {
        for (code, name) in ANCHOR_CHECKS {
            let o = old.imm_counts.get(code).copied().unwrap_or(0);
            let n = new.imm_counts.get(code).copied().unwrap_or(0);
            if n < o {
                anchor.push(format!("{name} ({code}): {o} → {n} check sites"));
            }
        }
    }
    for (id, sev, title, detail) in [
        (
            "TM-CHECK-GONE",
            Severity::High,
            "Account checks were removed",
            anchor,
        ),
        (
            "TM-ERR-GONE",
            Severity::Medium,
            "Custom error checks were removed",
            custom,
        ),
    ] {
        if !detail.is_empty() {
            findings.push(Finding {
                id,
                severity: sev,
                title: title.into(),
                detail,
            });
        }
    }
}

const KEY_DISTINCT: usize = 20;

fn key_like(k: &[u8; 32]) -> bool {
    k.iter().collect::<BTreeSet<_>>().len() >= KEY_DISTINCT
}

fn assembled_keys(p: &Program, skip: &BTreeSet<u64>) -> BTreeSet<[u8; 32]> {
    let cands: Vec<&WideLoad> = p
        .wide
        .iter()
        .filter(|w| w.slot.is_some() && w.value != 0 && !skip.contains(&w.value))
        .collect();
    let slot = |w: &WideLoad| {
        let (base, off) = w.slot.expect("filtered");
        (w.cmp, base, off)
    };
    let mut by_slot: HashMap<(bool, u8, i16), Vec<usize>> = HashMap::new();
    for (i, w) in cands.iter().enumerate() {
        by_slot.entry(slot(w)).or_default().push(i);
    }
    let mut used = vec![false; cands.len()];
    let mut keys = BTreeSet::new();
    for (a, w) in cands.iter().enumerate() {
        if used[a] {
            continue;
        }
        let (cmp, base, off) = slot(w);
        let mut parts = vec![a];
        for step in 1..4i16 {
            let Some(want_off) = off.checked_add(8 * step) else {
                break;
            };
            let Some(list) = by_slot.get(&(cmp, base, want_off)) else {
                break;
            };
            let lo = w.pc.saturating_sub(KEY_PC_WINDOW);
            let first = list.partition_point(|&i| cands[i].pc < lo);
            let hit = list[first..]
                .iter()
                .take_while(|&&i| cands[i].pc <= w.pc + KEY_PC_WINDOW)
                .find(|&&i| !used[i] && i != a);
            match hit {
                Some(&b) => parts.push(b),
                None => break,
            }
        }
        if parts.len() < 4 {
            continue;
        }
        let mut k = [0u8; 32];
        for (j, idx) in parts.iter().enumerate() {
            k[j * 8..j * 8 + 8].copy_from_slice(&cands[*idx].value.to_le_bytes());
        }
        if key_like(&k) {
            for idx in parts {
                used[idx] = true;
            }
            keys.insert(k);
        }
    }
    keys
}

const MAX_BLOB_WINDOWS: usize = 4096;

fn rodata_keys(windows: Vec<[u8; 32]>) -> (Vec<String>, usize) {
    let windows: Vec<[u8; 32]> = windows.into_iter().take(MAX_BLOB_WINDOWS).collect();
    let by_prefix: HashMap<&[u8], usize> = windows
        .iter()
        .enumerate()
        .map(|(i, w)| (&w[..31], i))
        .collect();
    let suffixes: std::collections::HashSet<&[u8]> = windows.iter().map(|w| &w[1..]).collect();
    let mut out = Vec::new();
    let mut total = 0;
    for w in &windows {
        if suffixes.contains(&w[..31]) {
            continue;
        }
        total += 1;
        if out.len() >= MAX_DETAIL {
            continue;
        }
        let mut len = 32;
        let mut cur = w;
        while let Some(&n) = by_prefix.get(&cur[1..]) {
            if len >= 32 + windows.len() {
                break;
            }
            cur = &windows[n];
            len += 1;
        }
        if len == 32 {
            out.push(name_key(w));
        } else {
            out.push(format!("{} (start of a {len}-byte blob)", name_key(w)));
        }
    }
    (out, total)
}

fn const_findings(old: &Program, new: &Program, skip: &BTreeSet<u64>, findings: &mut Vec<Finding>) {
    let set = |p: &Program| -> BTreeSet<u64> { p.flow.iter().filter_map(|f| f.constant).collect() };
    let (a, b) = (set(old), set(new));
    let gone: Vec<u64> = a
        .difference(&b)
        .filter(|v| !skip.contains(v))
        .copied()
        .collect();
    if gone.is_empty() {
        return;
    }
    let added: Vec<u64> = b
        .difference(&a)
        .filter(|v| !skip.contains(v))
        .copied()
        .collect();
    let mut detail: Vec<String> = gone
        .iter()
        .take(MAX_DETAIL)
        .map(|v| format!("- {v:#x}"))
        .collect();
    detail.extend(added.iter().take(MAX_DETAIL).map(|v| format!("+ {v:#x}")));
    findings.push(Finding {
        id: "TM-CONST-CHANGE",
        severity: Severity::Medium,
        title: format!(
            "{} 64-bit constant(s) no longer used, {} new",
            gone.len(),
            added.len()
        ),
        detail,
    });
}

const SHAPE_WINDOW: usize = 64;

fn shape(n: &str) -> &str {
    n.split_whitespace().next().unwrap_or("")
}

fn same_shape(old: &Program, a: usize, new: &Program, b: usize) -> usize {
    let mut k = 0;
    while k < SHAPE_WINDOW {
        let (Some(x), Some(y)) = (old.norm.get(a + k), new.norm.get(b + k)) else {
            break;
        };
        if shape(x) != shape(y) {
            break;
        }
        k += 1;
        if matches!(shape(x), "ja" | "exit") {
            break;
        }
    }
    k
}

fn refine(old: &Program, new: &Program, map: &mut [Option<usize>], calls: bool) {
    let mut votes: HashMap<usize, Option<usize>> = HashMap::new();
    for (i, m) in map.iter().enumerate() {
        let Some(j) = *m else { continue };
        let (a, b) = (old.flow[i], new.flow[j]);
        if a.is_call != calls || b.is_call != calls {
            continue;
        }
        let (Some(ta), Some(tb)) = (a.target, b.target) else {
            continue;
        };
        let (Some(to), Some(got)) = (line_of(&old.flow, ta), line_of(&new.flow, tb)) else {
            continue;
        };
        votes
            .entry(to)
            .and_modify(|v| {
                if *v != Some(got) {
                    *v = None
                }
            })
            .or_insert(Some(got));
    }
    for (to, got) in votes {
        let Some(got) = got else { continue };
        if map[to] == Some(got) {
            continue;
        }
        let run = same_shape(old, to, new, got);
        if run < 2 {
            continue;
        }
        for k in 0..run {
            map[to + k] = Some(got + k);
        }
    }
}

const ANCHOR: usize = 4;

fn anchored(map: &[Option<usize>], to: usize, expected: usize) -> bool {
    (1..=ANCHOR).all(|k| {
        let before = to.checked_sub(k).map(|o| map[o] == expected.checked_sub(k));
        let after = map.get(to + k).map(|m| *m == Some(expected + k));
        before.unwrap_or(true) && after.unwrap_or(true)
    })
}

fn line_of(flow: &[crate::elf::Flow], pc: usize) -> Option<usize> {
    let i = flow.partition_point(|f| f.pc < pc);
    (flow.get(i)?.pc == pc).then_some(i)
}

const MAX_DETAIL: usize = 12;

fn retarget_findings(
    old: &Program,
    new: &Program,
    td: &TextDiff<'_, '_, '_, str>,
    findings: &mut Vec<Finding>,
) {
    if old.flow.len() != old.norm.len() || new.flow.len() != new.norm.len() {
        return;
    }
    let mut map: Vec<Option<usize>> = vec![None; old.flow.len()];
    for op in td.ops() {
        if let similar::DiffOp::Equal {
            old_index,
            new_index,
            len,
        } = *op
        {
            for k in 0..len {
                if let Some(m) = map.get_mut(old_index + k) {
                    *m = Some(new_index + k);
                }
            }
        }
    }
    refine(old, new, &mut map, false);
    refine(old, new, &mut map, true);
    let line = |p: &Program, i: usize| {
        p.lines
            .get(i)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let (mut branches, mut calls) = (Vec::new(), Vec::new());
    for (i, m) in map.iter().enumerate() {
        let Some(j) = *m else { continue };
        let (a, b) = (old.flow[i], new.flow[j]);
        let (Some(ta), Some(tb)) = (a.target, b.target) else {
            continue;
        };
        let Some(to) = line_of(&old.flow, ta) else {
            continue;
        };
        let Some(expected) = map[to] else { continue };
        if !anchored(&map, to, expected) || !anchored(&map, i, j) {
            continue;
        }
        let Some(got) = line_of(&new.flow, tb) else {
            continue;
        };
        if got != expected {
            let d = format!(
                "{}  now targets {:#x}, matching code moved to {:#x}",
                line(new, j),
                new.flow[got].pc,
                new.flow[expected].pc
            );
            if a.is_call {
                calls.push(d);
            } else {
                branches.push(d);
            }
        }
    }
    for (id, sev, title, mut d) in [
        (
            "TM-BRANCH-RETARGET",
            Severity::High,
            "Unchanged branches now jump somewhere else",
            branches,
        ),
        (
            "TM-CALL-RETARGET",
            Severity::High,
            "Unchanged calls now call a different function",
            calls,
        ),
    ] {
        if d.is_empty() {
            continue;
        }
        let total = d.len();
        d.truncate(MAX_DETAIL);
        if total > MAX_DETAIL {
            d.push(format!("… and {} more", total - MAX_DETAIL));
        }
        findings.push(Finding {
            id,
            severity: sev,
            title: format!("{title} ({total})"),
            detail: d,
        });
    }
}

fn is_known(k: &[u8; 32]) -> bool {
    static IDS: std::sync::OnceLock<BTreeSet<[u8; 32]>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        KNOWN
            .iter()
            .filter_map(|(id, _)| bs58::decode(id).into_vec().ok()?.try_into().ok())
            .collect()
    })
    .contains(k)
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

    let (oh, nh) = (handlers::handlers(old), handlers::handlers(new));
    let skip: BTreeSet<u64> = oh.keys().chain(nh.keys()).copied().collect();
    let mut before = assembled_keys(old, &skip);
    before.extend(old.consts32.iter().copied());
    let fresh_inline: Vec<[u8; 32]> = assembled_keys(new, &skip)
        .difference(&before)
        .copied()
        .collect();
    let fresh_rodata: Vec<[u8; 32]> = new
        .consts32
        .difference(&before)
        .filter(|k| !fresh_inline.contains(k))
        .copied()
        .collect();
    let known: Vec<String> = fresh_inline
        .iter()
        .chain(&fresh_rodata)
        .filter(|k| is_known(k))
        .map(name_key)
        .collect();
    let mut unknown: Vec<String> = fresh_inline
        .iter()
        .filter(|k| !is_known(k))
        .map(name_key)
        .collect();
    let (blobs, blob_count) =
        rodata_keys(fresh_rodata.into_iter().filter(|k| !is_known(k)).collect());
    let total = unknown.len() + blob_count;
    unknown.extend(blobs);
    unknown.truncate(MAX_DETAIL);
    if !unknown.is_empty() {
        findings.push(Finding {
            id: "TM-KEY-ADD",
            severity: Severity::High,
            title: format!("{total} new hardcoded key(s)"),
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

    let added_ix: Vec<_> = nh
        .iter()
        .filter(|(d, _)| !oh.contains_key(d))
        .map(|(d, h)| format!("+ {}", h.label(*d)))
        .collect();
    let removed_ix: Vec<_> = oh
        .iter()
        .filter(|(d, _)| !nh.contains_key(d))
        .map(|(d, h)| format!("- {}", h.label(*d)))
        .collect();
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

    check_findings(old, new, &oh, &nh, &mut findings);

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
    retarget_findings(old, new, &td, &mut findings);
    const_findings(old, new, &skip, &mut findings);
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

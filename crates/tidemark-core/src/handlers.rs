use crate::elf::Program;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NAME_LEN: usize = 64;
const MAX_NAME_WORDS: usize = 8;
const MAX_HANDLERS: usize = 256;
const STUB_LEN: usize = 32;
const WALK_BUDGET: usize = 4_000_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handler {
    pub name: Option<String>,
    pub dispatched: bool,
    pub checks: BTreeMap<i64, usize>,
}

impl Handler {
    pub fn label(&self, disc: u64) -> String {
        self.name.clone().unwrap_or_else(|| format!("{disc:#018x}"))
    }
}

pub fn discriminator(name: &str) -> u64 {
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

fn split_digits(w: &str) -> String {
    let mut out = String::new();
    let mut prev: Option<bool> = None;
    for c in w.chars() {
        let digit = c.is_ascii_digit();
        if prev.is_some_and(|p| p != digit) {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
        prev = Some(digit);
    }
    out
}

fn name_candidates(words: &[&str]) -> [String; 2] {
    let plain: Vec<String> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
    let split: Vec<String> = words.iter().map(|w| split_digits(w)).collect();
    [plain.join("_"), split.join("_")]
}

fn logged_names(p: &Program, known: &BTreeSet<u64>) -> BTreeMap<u64, String> {
    let needle = b"Instruction: ";
    let mut out = BTreeMap::new();
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
        'prefix: for k in (1..=words.len()).rev() {
            for name in name_candidates(&words[..k]) {
                let d = discriminator(&name);
                if known.contains(&d) {
                    out.insert(d, name);
                    break 'prefix;
                }
            }
        }
        i = at;
    }
    out
}

struct Functions {
    entries: Vec<usize>,
    callees: Vec<Vec<usize>>,
    checks: Vec<BTreeMap<i64, usize>>,
}

impl Functions {
    fn new(p: &Program) -> Self {
        let mut entries: Vec<usize> = p
            .flow
            .iter()
            .filter(|f| f.is_call)
            .filter_map(|f| f.target)
            .collect();
        entries.push(0);
        entries.extend(
            p.norm
                .iter()
                .zip(p.flow.iter().skip(1))
                .filter(|(n, _)| *n == "exit")
                .map(|(_, f)| f.pc),
        );
        entries.sort_unstable();
        entries.dedup();
        let mut f = Functions {
            callees: vec![Vec::new(); entries.len()],
            checks: vec![BTreeMap::new(); entries.len()],
            entries,
        };
        for fl in p.flow.iter().filter(|f| f.is_call) {
            let (Some(t), Some(from)) = (fl.target, f.of(fl.pc)) else {
                continue;
            };
            if let Ok(to) = f.entries.binary_search(&t) {
                f.callees[from].push(to);
            }
        }
        for &(pc, code) in &p.error_codes {
            if let Some(i) = f.of(pc) {
                *f.checks[i].entry(code).or_default() += 1;
            }
        }
        f
    }

    fn of(&self, pc: usize) -> Option<usize> {
        self.entries.partition_point(|&e| e <= pc).checked_sub(1)
    }

    fn reach(
        &self,
        roots: &[usize],
        seen: &mut [bool],
        budget: &mut usize,
        out: &mut BTreeMap<i64, usize>,
    ) -> bool {
        let mut stack = roots.to_vec();
        while let Some(f) = stack.pop() {
            if std::mem::replace(&mut seen[f], true) {
                continue;
            }
            *budget = match budget.checked_sub(1 + self.callees[f].len()) {
                Some(b) => b,
                None => return false,
            };
            for (code, n) in &self.checks[f] {
                *out.entry(*code).or_default() += n;
            }
            stack.extend(&self.callees[f]);
        }
        true
    }
}

fn stub(p: &Program, funcs: &Functions, target: usize) -> (Vec<usize>, BTreeMap<i64, usize>) {
    let mut roots = Vec::new();
    let mut checks = BTreeMap::new();
    let start = p.flow.partition_point(|f| f.pc < target);
    let mut stop = p.flow.len().min(start + STUB_LEN);
    for k in start..stop {
        let f = &p.flow[k];
        if f.is_call {
            if let Some(i) = f.target.and_then(|t| funcs.entries.binary_search(&t).ok()) {
                roots.push(i);
            }
        }
        if let Some(n) = p.norm.get(k) {
            if n.starts_with("ja ") || n == "exit" {
                stop = k + 1;
                break;
            }
        }
    }
    let end = p.flow.get(stop).map_or(usize::MAX, |f| f.pc);
    for &(pc, code) in &p.error_codes {
        if pc >= target && pc < end && funcs.of(pc) == funcs.of(target) {
            *checks.entry(code).or_default() += 1;
        }
    }
    (roots, checks)
}

const TABLE_GAP: usize = 8;

fn dispatch_table(all: &[(u64, usize, usize)]) -> &[(u64, usize, usize)] {
    let mut best = &all[..0];
    let mut start = 0;
    for i in 1..=all.len() {
        if i == all.len() || all[i].2 > all[i - 1].2 + TABLE_GAP {
            if i - start > best.len() {
                best = &all[start..i];
            }
            start = i;
        }
    }
    best
}

pub fn handlers(p: &Program) -> BTreeMap<u64, Handler> {
    let mut targets: BTreeMap<u64, usize> = BTreeMap::new();
    for &(d, t, _) in dispatch_table(&p.dispatch).iter().take(MAX_HANDLERS) {
        targets.entry(d).or_insert(t);
    }
    let wide: BTreeSet<u64> = p.wide.iter().map(|w| w.value).collect();
    let names = logged_names(p, &wide);
    let mut out: BTreeMap<u64, Handler> = names
        .iter()
        .map(|(d, n)| {
            (
                *d,
                Handler {
                    name: Some(n.clone()),
                    ..Handler::default()
                },
            )
        })
        .collect();
    if targets.is_empty() {
        return out;
    }
    let funcs = Functions::new(p);
    let mut seen = vec![false; funcs.entries.len()];
    let mut budget = WALK_BUDGET;
    let mut walked = Vec::new();
    for (d, t) in targets {
        let (roots, mut checks) = stub(p, &funcs, t);
        seen.iter_mut().for_each(|s| *s = false);
        if !funcs.reach(&roots, &mut seen, &mut budget, &mut checks) {
            for h in out.values_mut() {
                h.dispatched = false;
                h.checks.clear();
            }
            return out;
        }
        walked.push((d, checks));
    }
    for (d, checks) in walked {
        let h = out.entry(d).or_default();
        h.dispatched = true;
        h.checks = checks;
    }
    out
}

use crate::{disasm, syscalls};
use anyhow::{Context, Result};
use goblin::elf::Elf;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const R_BPF_64_32: u32 = 10;
const R_BPF_64_RELATIVE: u32 = 8;
const R_BPF_64_64: u32 = 1;

#[derive(Debug, Clone, Copy)]
pub struct WideLoad {
    pub pc: usize,
    pub value: u64,
    pub slot: Option<(u8, i16)>,
    pub cmp: bool,
}

pub struct Program {
    pub sbpf_version: u8,
    pub sha256: String,
    pub size: usize,
    pub insn_count: usize,
    pub lines: Vec<String>,
    pub norm: Vec<String>,
    pub syscalls: BTreeMap<String, usize>,
    pub callx: usize,
    pub strings: BTreeSet<String>,
    pub consts32: BTreeSet<[u8; 32]>,
    pub imm_counts: BTreeMap<i64, usize>,
    pub wide: Vec<WideLoad>,
    pub rodata: Vec<u8>,
    pub security_txt: Option<String>,
    pub flow: Vec<Flow>,
    pub dispatch: Vec<(u64, usize, usize)>,
    pub error_codes: Vec<(usize, i64)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flow {
    pub pc: usize,
    pub target: Option<usize>,
    pub is_call: bool,
    pub constant: Option<u64>,
}

fn is_address(v: u64, image_end: u64) -> bool {
    v < image_end || matches!(v >> 32, 1..=4)
}

const EM_BPF: u16 = 247;
const EM_SBPF: u16 = 263;
const EF_SBPF_V2: u32 = 0x20;
pub const SUPPORTED_SBPF: [u8; 2] = [0, 1];

pub fn sbpf_version(machine: u16, flags: u32) -> Result<u8> {
    match (machine, flags) {
        (EM_BPF, 0) => Ok(0),
        (EM_BPF, EF_SBPF_V2) => Ok(2),
        (EM_SBPF, v @ 0..=3) => Ok(v as u8),
        (EM_BPF | EM_SBPF, f) => anyhow::bail!("unknown SBPF flags {f:#x}"),
        (m, _) => anyhow::bail!("not an SBPF program (e_machine {m})"),
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub const MAX_PROGRAM_BYTES: usize = 16 << 20;

pub fn load(bytes: &[u8]) -> Result<Program> {
    if bytes.len() > MAX_PROGRAM_BYTES {
        anyhow::bail!(
            "program is {} bytes; the limit is {}",
            bytes.len(),
            MAX_PROGRAM_BYTES
        );
    }
    let elf = Elf::parse(bytes).context("not a valid ELF file")?;
    let version = sbpf_version(elf.header.e_machine, elf.header.e_flags)?;
    if !SUPPORTED_SBPF.contains(&version) {
        anyhow::bail!("SBPF v{version} programs are not supported yet; Tidemark reads v0 and v1");
    }
    let sec = |name: &str| {
        elf.section_headers
            .iter()
            .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(name))
    };
    let slice = |s: &goblin::elf::SectionHeader| {
        let a = s.sh_offset as usize;
        let b = a.saturating_add(s.sh_size as usize).min(bytes.len());
        &bytes[a.min(b)..b]
    };

    let text_hdr = sec(".text").context("program has no .text section")?;
    let text = slice(text_hdr);
    let insns = disasm::decode(text);

    let mut reloc_names: HashMap<usize, String> = HashMap::new();
    let image_end = elf
        .section_headers
        .iter()
        .map(|s| s.sh_addr.saturating_add(s.sh_size))
        .max()
        .unwrap_or(0);
    let mut relocated: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for r in elf.dynrels.iter() {
        if matches!(r.r_type, R_BPF_64_RELATIVE | R_BPF_64_64) && r.r_offset >= text_hdr.sh_addr {
            relocated.insert(((r.r_offset - text_hdr.sh_addr) / 8) as usize);
        }
        if r.r_type != R_BPF_64_32 {
            continue;
        }
        let Some(sym) = elf.dynsyms.get(r.r_sym) else {
            continue;
        };
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if sym.st_value != 0 || name.is_empty() {
            continue;
        }
        if r.r_offset >= text_hdr.sh_addr {
            let pc = ((r.r_offset - text_hdr.sh_addr) / 8) as usize;
            reloc_names.insert(pc, name.to_string());
        }
    }

    let mut lines = Vec::with_capacity(insns.len());
    let mut norm = Vec::with_capacity(insns.len());
    let mut syscalls_used: BTreeMap<String, usize> = BTreeMap::new();
    let mut callx = 0;
    let mut flow = Vec::with_capacity(insns.len());
    let mut imm_counts: BTreeMap<i64, usize> = BTreeMap::new();
    let mut wide = Vec::new();
    let mut error_codes = Vec::new();
    for i in &insns {
        if matches!(i.op, 0xb7 | 0xb4 | 0x62 | 0x6a | 0x72 | 0x7a) {
            *imm_counts.entry(i.imm).or_default() += 1;
            if is_error_code(i.imm) {
                error_codes.push((i.pc, i.imm));
            }
        }
        if i.wide {
            wide.push(WideLoad {
                pc: i.pc,
                value: i.imm as u64,
                slot: None,
                cmp: false,
            });
        }
        let mut sc: Option<String> = None;
        if i.op == 0x85 {
            sc = reloc_names
                .get(&i.pc)
                .cloned()
                .or_else(|| syscalls::by_hash(i.imm as u32).map(String::from));
            if let Some(n) = &sc {
                *syscalls_used.entry(n.clone()).or_default() += 1;
            }
        }
        if i.op == 0x8d {
            callx += 1;
        }
        let rel = |d: i64| {
            let t = i.pc as i64 + 1 + d;
            (t >= 0).then_some(t as usize)
        };
        let mut f = Flow {
            pc: i.pc,
            ..Flow::default()
        };
        if i.op & 7 == 5 && !matches!(i.op, 0x85 | 0x8d | 0x95) {
            f.target = rel(i.off as i64);
        } else if i.op == 0x85 && i.src == 1 && sc.is_none() {
            f.target = rel(i.imm);
            f.is_call = true;
        } else if i.wide && !relocated.contains(&i.pc) && !is_address(i.imm as u64, image_end) {
            f.constant = Some(i.imm as u64);
        }
        let (r, mut n) = disasm::render(i, sc.as_deref());
        if let Some(c) = f.constant {
            n = format!("lddw r{}, {c:#x}", i.dst);
        }
        flow.push(f);
        lines.push(format!("{:6x}  {r}", i.pc));
        norm.push(n);
    }

    let by_pc: HashMap<usize, usize> = insns.iter().enumerate().map(|(n, i)| (i.pc, n)).collect();
    let mut dispatch = Vec::new();
    for w in wide.iter_mut() {
        let Some(&n) = by_pc.get(&w.pc) else { continue };
        if let Some(t) = dispatch_target(&insns, n) {
            dispatch.push((w.value, t, w.pc));
        }
        if let Some(slot) = stored_to(&insns, n) {
            w.slot = Some(slot);
        } else if let Some(slot) = compared_with(&insns, n) {
            w.slot = Some(slot);
            w.cmp = true;
        }
    }

    let mut strings = BTreeSet::new();
    let mut consts32 = BTreeSet::new();
    let mut rodata = Vec::new();
    for name in [".rodata", ".data.rel.ro"] {
        if let Some(h) = sec(name) {
            let data = slice(h);
            extract_strings(data, &mut strings);
            extract_consts(data, &mut consts32);
            rodata.extend_from_slice(data);
        }
    }
    let security_txt = sec(".security.txt").map(|h| {
        String::from_utf8_lossy(slice(h))
            .replace('\0', "\n")
            .trim()
            .to_string()
    });

    Ok(Program {
        sha256: sha256_hex(bytes),
        size: bytes.len(),
        insn_count: insns.len(),
        lines,
        norm,
        syscalls: syscalls_used,
        callx,
        strings,
        consts32,
        imm_counts,
        wide,
        rodata,
        security_txt,
        sbpf_version: version,
        flow,
        dispatch,
        error_codes,
    })
}

const SLOT_SCAN: usize = 32;

fn writes(i: &disasm::Insn, reg: u8) -> bool {
    match i.op & 7 {
        0 | 1 | 4 | 7 => i.dst == reg,
        5 => matches!(i.op, 0x85 | 0x8d) && reg <= 5,
        _ => false,
    }
}

fn stored_to(insns: &[disasm::Insn], n: usize) -> Option<(u8, i16)> {
    let reg = insns[n].dst;
    for j in insns.iter().skip(n + 1).take(SLOT_SCAN) {
        if j.op == 0x7b && j.src == reg {
            return Some((j.dst, j.off));
        }
        if writes(j, reg) {
            return None;
        }
    }
    None
}

fn compared_with(insns: &[disasm::Insn], n: usize) -> Option<(u8, i16)> {
    let reg = insns[n].dst;
    for k in n + 1..insns.len().min(n + 1 + SLOT_SCAN) {
        let j = &insns[k];
        if matches!(j.op, 0x1d | 0x5d) && (j.dst == reg || j.src == reg) {
            let other = if j.dst == reg { j.src } else { j.dst };
            let lo = k.saturating_sub(SLOT_SCAN);
            let m = (lo..k).rev().find(|&m| writes(&insns[m], other))?;
            let l = &insns[m];
            return (l.op == 0x79).then_some((l.src, l.off));
        }
        if writes(j, reg) {
            return None;
        }
    }
    None
}

pub fn is_error_code(v: i64) -> bool {
    matches!(v, 2000..=3999 | 6000..=6999)
}

fn dispatch_target(insns: &[disasm::Insn], n: usize) -> Option<usize> {
    let reg = insns[n].dst;
    let k = (n + 1..insns.len().min(n + 4))
        .find(|&k| insns[k].op == 0x1d && (insns[k].dst == reg || insns[k].src == reg))?;
    let j = &insns[k];
    let other = if j.dst == reg { j.src } else { j.dst };
    let m = (k.saturating_sub(8)..k)
        .rev()
        .find(|&m| m != n && writes(&insns[m], other))?;
    let l = &insns[m];
    if l.op != 0x79 || l.off != 0 {
        return None;
    }
    let t = j.pc as i64 + 1 + j.off as i64;
    (t >= 0).then_some(t as usize)
}

fn extract_strings(data: &[u8], out: &mut BTreeSet<String>) {
    let mut cur = Vec::new();
    let flush = |cur: &mut Vec<u8>, out: &mut BTreeSet<String>| {
        if cur.len() >= 8 {
            out.insert(String::from_utf8_lossy(cur).to_string());
        }
        cur.clear();
    };
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            flush(&mut cur, out);
        }
    }
    flush(&mut cur, out);
}

fn extract_consts(data: &[u8], out: &mut BTreeSet<[u8; 32]>) {
    if data.len() < 32 {
        return;
    }
    let mut counts = [0u8; 256];
    let (mut distinct, mut printable) = (0usize, 0usize);
    let mut add = |b: u8, d: i8, distinct: &mut usize, printable: &mut usize| {
        let c = &mut counts[b as usize];
        if d > 0 {
            *distinct += (*c == 0) as usize;
            *c += 1;
        } else {
            *c -= 1;
            *distinct -= (*c == 0) as usize;
        }
        if (0x20..0x7f).contains(&b) {
            *printable = (*printable as isize + d as isize) as usize;
        }
    };
    for &b in &data[..32] {
        add(b, 1, &mut distinct, &mut printable);
    }
    for i in 0..=data.len() - 32 {
        if i > 0 {
            add(data[i - 1], -1, &mut distinct, &mut printable);
            add(data[i + 31], 1, &mut distinct, &mut printable);
        }
        if distinct >= 24 && printable < 28 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&data[i..i + 32]);
            out.insert(k);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_insns<const N: usize>() -> Vec<disasm::Insn> {
        (0..N)
            .map(|pc| {
                let i = disasm::Insn {
                    pc,
                    op: kani::any(),
                    dst: kani::any(),
                    src: kani::any(),
                    off: kani::any(),
                    imm: kani::any(),
                    wide: kani::any(),
                };
                kani::assume(i.dst < 16 && i.src < 16);
                i
            })
            .collect()
    }

    #[kani::proof]
    #[kani::unwind(7)]
    fn slot_scans_stay_in_bounds() {
        let insns = any_insns::<6>();
        let n: usize = kani::any();
        kani::assume(n < insns.len());
        let _ = stored_to(&insns, n);
        let _ = compared_with(&insns, n);
        if let Some(t) = dispatch_target(&insns, n) {
            assert!(t <= insns.len() + (i16::MAX as usize) + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = op;
        b[1] = dst | (src << 4);
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..].copy_from_slice(&imm.to_le_bytes());
        b
    }

    fn lddw(dst: u8, v: u64) -> Vec<u8> {
        let mut b = ins(0x18, dst, 0, 0, v as u32 as i32).to_vec();
        b.extend(ins(0, 0, 0, 0, (v >> 32) as u32 as i32));
        b
    }

    fn code(parts: &[Vec<u8>]) -> Vec<disasm::Insn> {
        disasm::decode(&parts.concat())
    }

    #[test]
    fn store_far_from_its_lddw_is_found() {
        let mut parts = vec![lddw(3, 0x1122_3344_5566_7788)];
        for _ in 0..20 {
            parts.push(ins(0xbf, 4, 5, 0, 0).to_vec());
        }
        parts.push(ins(0x7b, 10, 3, -40, 0).to_vec());
        assert_eq!(stored_to(&code(&parts), 0), Some((10, -40)));
    }

    #[test]
    fn overwritten_register_is_not_a_store() {
        let parts = vec![
            lddw(3, 0x1122_3344_5566_7788),
            ins(0xb7, 3, 0, 0, 1).to_vec(),
            ins(0x7b, 10, 3, -40, 0).to_vec(),
        ];
        assert_eq!(stored_to(&code(&parts), 0), None);
    }

    #[test]
    fn compared_limb_takes_the_loaded_slot() {
        let parts = vec![
            ins(0x79, 0, 2, 16, 0).to_vec(),
            lddw(7, 0x1122_3344_5566_7788),
            ins(0x5d, 0, 7, 9, 0).to_vec(),
        ];
        assert_eq!(compared_with(&code(&parts), 1), Some((2, 16)));
    }

    fn naive_consts(data: &[u8]) -> BTreeSet<[u8; 32]> {
        data.windows(32)
            .filter(|w| {
                let distinct = w.iter().collect::<BTreeSet<_>>().len();
                let printable = w.iter().filter(|b| (0x20..0x7f).contains(*b)).count();
                distinct >= 24 && printable < 28
            })
            .map(|w| w.try_into().unwrap())
            .collect()
    }

    #[test]
    fn rodata_window_matches_naive_scan() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..2000 {
            let alphabet = [8u64, 24, 32, 96, 256][round % 5];
            let len = 30 + round % 50;
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (0x10 + x % alphabet) as u8
                })
                .collect();
            let mut fast = BTreeSet::new();
            extract_consts(&data, &mut fast);
            assert_eq!(fast, naive_consts(&data), "round {round}");
        }
    }

    #[test]
    fn rodata_key_at_odd_offset_is_found() {
        let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0xa5);
        let mut data = b"abc".to_vec();
        data.extend_from_slice(&key);
        data.extend_from_slice(b"xyz");
        let mut out = BTreeSet::new();
        extract_consts(&data, &mut out);
        assert!(out.contains(&key));
    }
}

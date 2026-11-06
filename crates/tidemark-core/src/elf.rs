use crate::{disasm, syscalls};
use anyhow::{Context, Result};
use goblin::elf::Elf;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const R_BPF_64_32: u32 = 10;

pub struct Program {
    pub sha256: String,
    pub size: usize,
    pub insn_count: usize,
    pub lines: Vec<String>,
    pub norm: Vec<String>,
    pub syscalls: BTreeMap<String, usize>,
    pub callx: usize,
    pub strings: BTreeSet<String>,
    pub consts32: BTreeSet<[u8; 32]>,
    pub security_txt: Option<String>,
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn load(bytes: &[u8]) -> Result<Program> {
    let elf = Elf::parse(bytes).context("not a valid ELF file")?;
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
    for r in elf.dynrels.iter() {
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
    for i in &insns {
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
        let (r, n) = disasm::render(i, sc.as_deref());
        lines.push(format!("{:6x}  {r}", i.pc));
        norm.push(n);
    }

    let mut strings = BTreeSet::new();
    let mut consts32 = BTreeSet::new();
    for name in [".rodata", ".data.rel.ro"] {
        if let Some(h) = sec(name) {
            let data = slice(h);
            extract_strings(data, &mut strings);
            extract_consts(data, &mut consts32);
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
        security_txt,
    })
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
    let mut i = 0;
    while i + 32 <= data.len() {
        let w = &data[i..i + 32];
        let distinct = w.iter().collect::<BTreeSet<_>>().len();
        let printable = w.iter().filter(|b| (0x20..0x7f).contains(*b)).count();
        if distinct >= 24 && printable < 28 {
            let mut k = [0u8; 32];
            k.copy_from_slice(w);
            out.insert(k);
        }
        i += 8;
    }
}

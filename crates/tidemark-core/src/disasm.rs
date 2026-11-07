#[derive(Debug, Clone)]
pub struct Insn {
    pub pc: usize,
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i64,
    pub wide: bool,
    pub ver: u8,
}

pub fn decode(text: &[u8]) -> Vec<Insn> {
    decode_for(text, 0)
}

const V2_MEMORY: [(u8, u8); 12] = [
    (0x2c, 0x71),
    (0x3c, 0x69),
    (0x8c, 0x61),
    (0x9c, 0x79),
    (0x27, 0x72),
    (0x37, 0x6a),
    (0x87, 0x62),
    (0x97, 0x7a),
    (0x2f, 0x73),
    (0x3f, 0x6b),
    (0x8f, 0x63),
    (0x9f, 0x7b),
];

const HOR64: u8 = 0xf7;

pub fn decode_for(text: &[u8], ver: u8) -> Vec<Insn> {
    let mut out: Vec<Insn> = Vec::with_capacity(text.len() / 8);
    let mut i = 0;
    while let Some((mut insn, step)) = decode_at(text, i, ver != 2) {
        insn.ver = ver;
        if ver == 2 {
            if let Some(&(_, v0)) = V2_MEMORY.iter().find(|(v2, _)| *v2 == insn.op) {
                insn.op = v0;
            }
            if insn.op == HOR64 {
                if let Some(prev) = out.last_mut().filter(|p| {
                    matches!(p.op, 0xb4 | 0xb7) && p.dst == insn.dst && p.pc + 1 == insn.pc
                }) {
                    prev.op = 0x18;
                    prev.imm = (((insn.imm as u64) << 32) | (prev.imm as u32 as u64)) as i64;
                    prev.wide = true;
                    i += step;
                    continue;
                }
            }
        }
        out.push(insn);
        i += step;
    }
    out
}

#[cfg(kani)]
fn decode_one(text: &[u8], i: usize) -> Option<(Insn, usize)> {
    decode_at(text, i, true)
}

fn decode_at(text: &[u8], i: usize, lddw: bool) -> Option<(Insn, usize)> {
    let b = text.get(i..i.checked_add(8)?)?;
    let op = b[0];
    let mut imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]) as i64;
    let hi = (lddw && op == 0x18)
        .then(|| text.get(i + 12..i + 16))
        .flatten();
    if let Some(h) = hi {
        let hi = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as u64;
        imm = ((hi << 32) | (imm as u32 as u64)) as i64;
    }
    let insn = Insn {
        pc: i / 8,
        op,
        dst: b[1] & 0x0f,
        src: b[1] >> 4,
        off: i16::from_le_bytes([b[2], b[3]]),
        imm,
        wide: hi.is_some(),
        ver: 0,
    };
    Some((insn, if hi.is_some() { 16 } else { 8 }))
}

const ALU: [&str; 14] = [
    "add", "sub", "mul", "div", "or", "and", "lsh", "rsh", "neg", "mod", "xor", "mov", "arsh",
    "end",
];
const JMP: [&str; 14] = [
    "ja", "jeq", "jgt", "jge", "jset", "jne", "jsgt", "jsge", "call", "exit", "jlt", "jle", "jslt",
    "jsle",
];

const PQR: [&str; 8] = [
    "pqr?", "uhmul", "udiv", "urem", "lmul", "shmul", "sdiv", "srem",
];

pub fn is_jump32(i: &Insn) -> bool {
    i.ver >= 3 && i.op & 7 == 6
}

pub fn is_branch_op(i: &Insn) -> bool {
    (i.op & 7 == 5 && !matches!(i.op, 0x85 | 0x8d | 0x95)) || is_jump32(i)
}

fn size(op: u8) -> &'static str {
    match (op >> 3) & 3 {
        0 => "w",
        1 => "h",
        2 => "b",
        _ => "dw",
    }
}

pub fn render(i: &Insn, syscall: Option<&str>) -> (String, String) {
    let class = i.op & 7;
    let x = i.op & 0x08 != 0;
    let code = (i.op >> 4) as usize;
    let rhs = if x {
        format!("r{}", i.src)
    } else {
        format!("{}", i.imm)
    };
    if i.ver == 2 && i.op == HOR64 {
        let s = format!("hor64 r{}, {}", i.dst, i.imm);
        return (s.clone(), s);
    }
    if class == 6 && i.ver == 2 {
        let w = if i.op & 0x10 != 0 { "64" } else { "32" };
        let name = PQR[(i.op >> 5) as usize];
        let s = format!("{name}{w} r{}, {rhs}", i.dst);
        return (s.clone(), s);
    }
    match class {
        4 | 7 => {
            let w = if class == 7 { "64" } else { "32" };
            let name = ALU.get(code).copied().unwrap_or("alu?");
            let s = if name == "neg" {
                format!("neg{w} r{}", i.dst)
            } else {
                format!("{name}{w} r{}, {rhs}", i.dst)
            };
            (s.clone(), s)
        }
        5 | 6 if class == 5 || is_jump32(i) => {
            let w = if class == 6 { "32" } else { "" };
            if i.op == 0x95 {
                return ("exit".into(), "exit".into());
            }
            if i.op == 0x85 {
                return match syscall {
                    Some(n) => (format!("call {n}"), format!("call {n}")),
                    None => (format!("call {:#x}", i.imm as u32), "call <fn>".into()),
                };
            }
            if i.op == 0x8d {
                let r = match i.ver {
                    2 => i.src as i64,
                    3.. => i.dst as i64,
                    _ if i.imm != 0 => i.imm,
                    _ => i.src as i64,
                };
                return (format!("callx r{r}"), format!("callx r{r}"));
            }
            let name = JMP.get(code).copied().unwrap_or("jmp?");
            let target = i.pc as i64 + 1 + i.off as i64;
            if name == "ja" {
                return (format!("ja {target:#x}"), "ja <l>".into());
            }
            (
                format!("{name}{w} r{}, {rhs}, {target:#x}", i.dst),
                format!("{name}{w} r{}, {rhs}, <l>", i.dst),
            )
        }
        1 => {
            let s = format!("ldx{} r{}, [r{}{:+}]", size(i.op), i.dst, i.src, i.off);
            (s.clone(), s)
        }
        2 => {
            let s = format!("st{} [r{}{:+}], {}", size(i.op), i.dst, i.off, i.imm);
            (s.clone(), s)
        }
        3 => {
            let s = format!("stx{} [r{}{:+}], r{}", size(i.op), i.dst, i.off, i.src);
            (s.clone(), s)
        }
        0 if i.wide => (
            format!("lddw r{}, {:#x}", i.dst, i.imm),
            format!("lddw r{}, <addr>", i.dst),
        ),
        _ => {
            let s = format!(
                ".byte {:#04x} r{} r{} {} {}",
                i.op, i.dst, i.src, i.off, i.imm
            );
            (s.clone(), s)
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn decode_step_stays_in_bounds() {
        let bytes: [u8; 24] = kani::any();
        let (len, i): (usize, usize) = (kani::any(), kani::any());
        kani::assume(len <= bytes.len() && i <= len);
        let text = &bytes[..len];
        match decode_one(text, i) {
            Some((insn, step)) => {
                assert!(i + 8 <= len);
                assert!(step == 8 || step == 16);
                assert!(i + step <= len);
                assert_eq!(insn.wide, step == 16);
                assert_eq!(insn.pc, i / 8);
                assert!(insn.dst < 16 && insn.src < 16);
            }
            None => assert!(i + 8 > len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = op;
        b[1] = dst | (src << 4);
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    #[test]
    fn v2_constant_pairs_become_one_wide_load() {
        let text = [
            word(0xb4, 3, 0, 0, 0x5678_9abcu32 as i32),
            word(HOR64, 3, 0, 0, 0x1234),
        ]
        .concat();
        let insns = decode_for(&text, 2);
        assert_eq!(insns.len(), 1);
        assert!(insns[0].wide);
        assert_eq!(insns[0].imm as u64, 0x1234_5678_9abc);
        assert_eq!(render(&insns[0], None).0, "lddw r3, 0x123456789abc");
    }

    #[test]
    fn v2_memory_classes_map_to_v0_opcodes() {
        let text = [word(0x9c, 1, 2, 8, 0), word(0x9f, 10, 1, -8, 0)].concat();
        let r: Vec<String> = decode_for(&text, 2)
            .iter()
            .map(|i| render(i, None).0)
            .collect();
        assert_eq!(r, ["ldxdw r1, [r2+8]", "stxdw [r10-8], r1"]);
    }

    #[test]
    fn v2_lddw_opcode_is_not_wide() {
        let text = [word(0x18, 1, 0, 0, 7), word(0x95, 0, 0, 0, 0)].concat();
        assert_eq!(decode_for(&text, 2).len(), 2);
    }

    #[test]
    fn v3_jump32_is_a_branch() {
        let text = [word(0x16, 2, 0, 3, 9)].concat();
        let i = &decode_for(&text, 3)[0];
        assert!(is_branch_op(i));
        assert_eq!(render(i, None).0, "jeq32 r2, 9, 0x4");
        assert!(!is_branch_op(&decode_for(&text, 2)[0]));
    }

    #[test]
    fn callx_register_depends_on_version() {
        let text = [word(0x8d, 4, 6, 0, 0)].concat();
        assert_eq!(render(&decode_for(&text, 2)[0], None).0, "callx r6");
        assert_eq!(render(&decode_for(&text, 3)[0], None).0, "callx r4");
    }

    #[test]
    fn render_handles_every_opcode() {
        for op in 0..=255u8 {
            for wide in [false, true] {
                for (off, imm) in [(0, 0), (i16::MIN, i64::MIN), (i16::MAX, i64::MAX), (-1, -1)] {
                    let i = Insn {
                        pc: 1 << 20,
                        op,
                        dst: 15,
                        src: 15,
                        off,
                        imm,
                        wide,
                        ver: 0,
                    };
                    for ver in 0..=3 {
                        let i = Insn { ver, ..i.clone() };
                        let _ = render(&i, None);
                        let _ = render(&i, Some("sol_log_"));
                    }
                }
            }
        }
    }
}

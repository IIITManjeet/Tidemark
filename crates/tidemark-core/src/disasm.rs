#[derive(Debug, Clone)]
pub struct Insn {
    pub pc: usize,
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i64,
    pub wide: bool,
}

pub fn decode(text: &[u8]) -> Vec<Insn> {
    let mut out = Vec::with_capacity(text.len() / 8);
    let mut i = 0;
    while let Some((insn, step)) = decode_one(text, i) {
        out.push(insn);
        i += step;
    }
    out
}

fn decode_one(text: &[u8], i: usize) -> Option<(Insn, usize)> {
    let b = text.get(i..i.checked_add(8)?)?;
    let op = b[0];
    let mut imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]) as i64;
    let hi = (op == 0x18).then(|| text.get(i + 12..i + 16)).flatten();
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
        5 => {
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
                let r = if i.imm != 0 { i.imm } else { i.src as i64 };
                return (format!("callx r{r}"), format!("callx r{r}"));
            }
            let name = JMP.get(code).copied().unwrap_or("jmp?");
            let target = i.pc as i64 + 1 + i.off as i64;
            if name == "ja" {
                return (format!("ja {target:#x}"), "ja <l>".into());
            }
            (
                format!("{name} r{}, {rhs}, {target:#x}", i.dst),
                format!("{name} r{}, {rhs}, <l>", i.dst),
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
                    };
                    let _ = render(&i, None);
                    let _ = render(&i, Some("sol_log_"));
                }
            }
        }
    }
}

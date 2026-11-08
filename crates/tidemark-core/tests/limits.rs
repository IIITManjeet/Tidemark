use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tidemark_core::diff::compare;
use tidemark_core::elf::{Program, WideLoad};

fn program(norm: Vec<String>) -> Program {
    Program {
        sbpf_version: 0,
        sha256: "00".repeat(32),
        size: norm.len() * 8,
        insn_count: norm.len(),
        lines: norm.clone(),
        norm,
        syscalls: BTreeMap::new(),
        callx: 0,
        strings: BTreeSet::new(),
        consts32: BTreeSet::new(),
        imm_counts: BTreeMap::new(),
        wide: Vec::new(),
        rodata: Vec::new(),
        security_txt: None,
        flow: Vec::new(),
        dispatch: Vec::new(),
        error_codes: Vec::new(),
    }
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let r = f();
    (r, t.elapsed())
}

#[test]
fn long_camel_case_log_name_is_cheap() {
    let a = program(vec!["exit".into()]);
    let mut b = program(vec!["exit".into()]);
    b.rodata.extend_from_slice(b"Instruction: ");
    b.rodata
        .extend(std::iter::repeat_n(*b"Ab", 32 * 1024).flatten());
    let (_, t) = timed(|| compare(&a, &b));
    assert!(t < Duration::from_secs(2), "took {t:?}");
}

#[test]
fn many_stack_constants_are_cheap() {
    let a = program(vec!["exit".into()]);
    let mut b = program(vec!["exit".into()]);
    for i in 0..40_000u64 {
        b.wide.push(WideLoad {
            pc: i as usize * 2,
            value: 0x9a8b_7c6d_5e4f_3021 ^ (i << 8),
            slot: Some((10, -64 + 8 * (i % 3) as i16)),
            cmp: false,
        });
    }
    let (_, t) = timed(|| compare(&a, &b));
    assert!(t < Duration::from_secs(3), "took {t:?}");
}

#[test]
fn diff_of_unrelated_large_programs_is_bounded() {
    let vocab = [
        "mov64 r1, r2",
        "add64 r1, 1",
        "ja <l>",
        "exit",
        "ldxdw r1, [r2+0]",
        "call <fn>",
    ];
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut gen = |n: usize| {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                vocab[(x % vocab.len() as u64) as usize].to_string()
            })
            .collect::<Vec<_>>()
    };
    let a = program(gen(60_000));
    let b = program(gen(60_000));
    let (r, t) = timed(|| compare(&a, &b));
    assert!(t < Duration::from_secs(30), "took {t:?}");
    assert!(r.changed_instructions > 0);
}

#[test]
fn huge_random_rodata_is_cheap() {
    let a = program(vec!["exit".into()]);
    let mut b = program(vec!["exit".into()]);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let blob: Vec<u8> = (0..200_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    for i in 0..blob.len() - 32 {
        b.consts32.insert(blob[i..i + 32].try_into().unwrap());
    }
    let (r, t) = timed(|| compare(&a, &b));
    assert!(t < Duration::from_secs(3), "took {t:?}");
    let f = r.findings.iter().find(|f| f.id == "TM-KEY-ADD").unwrap();
    assert!(f.detail.len() <= 12);
}

#[test]
fn wide_call_graph_with_many_handlers_is_cheap() {
    let n = 200_000;
    let mut p = program(vec!["mov64 r0, 0".into(); n]);
    p.flow = (0..n)
        .map(|pc| tidemark_core::elf::Flow {
            pc,
            ..Default::default()
        })
        .collect();
    for pc in 1000..n - 1 {
        p.flow[pc].target = Some(pc + 1);
        p.flow[pc].is_call = true;
    }
    for h in 0..256u64 {
        p.flow[h as usize].target = Some(1000);
        p.flow[h as usize].is_call = true;
        p.dispatch.push((0x1000 + h, h as usize, h as usize));
    }
    let (_, t) = timed(|| compare(&p, &p));
    assert!(t < Duration::from_secs(5), "took {t:?}");
}

#[test]
fn the_same_pair_always_gets_the_same_verdict() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sbpf");
    let a = tidemark_core::elf::load(&std::fs::read(dir.join("demo_vault_v1_sbpfv2.so")).unwrap())
        .unwrap();
    let b = tidemark_core::elf::load(&std::fs::read(dir.join("demo_vault_v2_sbpfv3.so")).unwrap())
        .unwrap();
    let first = tidemark_core::verdict_hash(&compare(&a, &b));
    for _ in 0..8 {
        assert_eq!(tidemark_core::verdict_hash(&compare(&a, &b)), first);
    }
}

use std::process::Command;

fn run(isolate: bool, json: &std::path::Path) -> (i32, String) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/");
    let mut c = Command::new(env!("CARGO_BIN_EXE_tidemark"));
    c.arg("diff")
        .arg(format!("{root}demo_vault_v1.so"))
        .arg(format!("{root}demo_vault_v2.so"))
        .arg("--json")
        .arg(json);
    if isolate {
        c.arg("--isolate");
    }
    let out = c.output().expect("run tidemark");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let hash = stdout
        .lines()
        .find(|l| l.starts_with("verdict hash"))
        .expect("verdict hash line")
        .to_string();
    (out.status.code().expect("exit code"), hash)
}

#[test]
fn isolated_review_matches_in_process_review() {
    let dir = std::env::temp_dir().join(format!("tidemark-isolate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (pa, pb) = (dir.join("plain.json"), dir.join("isolated.json"));
    let (code_a, hash_a) = run(false, &pa);
    let (code_b, hash_b) = run(true, &pb);
    assert_eq!((code_a, code_b), (2, 2));
    assert_eq!(hash_a, hash_b);
    assert_eq!(std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn isolated_runner_failure_is_an_error() {
    let dir = std::env::temp_dir().join(format!("tidemark-isolate-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.so");
    std::fs::write(&bad, b"not an elf").unwrap();
    let code = Command::new(env!("CARGO_BIN_EXE_tidemark"))
        .arg("diff")
        .arg(&bad)
        .arg(&bad)
        .arg("--isolate")
        .output()
        .unwrap()
        .status
        .code();
    assert_eq!(code, Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

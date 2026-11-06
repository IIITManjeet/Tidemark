use std::process::Command;

fn diff(args: &[&str]) -> i32 {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/");
    Command::new(env!("CARGO_BIN_EXE_tidemark"))
        .arg("diff")
        .arg(format!("{root}demo_vault_v1.so"))
        .arg(format!("{root}demo_vault_v2.so"))
        .args(args)
        .output()
        .expect("run tidemark")
        .status
        .code()
        .expect("exit code")
}

#[test]
fn default_gate_fails_on_high() {
    assert_eq!(diff(&[]), 2);
}

#[test]
fn stricter_and_looser_gates() {
    assert_eq!(diff(&["--fail-on", "medium"]), 2);
    assert_eq!(diff(&["--fail-on", "critical"]), 0);
}

#[test]
fn unknown_gate_is_an_error_not_a_pass() {
    assert_eq!(diff(&["--fail-on", "severe"]), 1);
}

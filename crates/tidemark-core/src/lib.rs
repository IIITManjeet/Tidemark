pub mod diff;
pub mod disasm;
pub mod elf;
pub mod syscalls;

pub fn report_hash(report: &diff::Report) -> String {
    let v = serde_json::to_value(report).expect("report serializes");
    canonical_hash(&v)
}

pub fn canonical_hash(v: &serde_json::Value) -> String {
    elf::sha256_hex(&serde_json::to_vec(v).expect("value serializes"))
}

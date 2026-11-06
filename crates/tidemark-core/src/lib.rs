pub mod diff;
pub mod disasm;
pub mod elf;
pub mod ledger;
pub mod rpc;
pub mod submit;
pub mod syscalls;

pub fn report_hash(report: &diff::Report) -> String {
    let v = serde_json::to_value(report).expect("report serializes");
    canonical_hash(&v)
}

pub fn canonical_hash(v: &serde_json::Value) -> String {
    elf::sha256_hex(&serde_json::to_vec(v).expect("value serializes"))
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

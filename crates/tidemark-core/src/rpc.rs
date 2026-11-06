use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};

pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const PROGRAMDATA_HEADER: usize = 45;

pub struct Deployed {
    pub elf: Vec<u8>,
    pub last_deploy_slot: u64,
    pub upgrade_authority: Option<String>,
    pub programdata: String,
}

fn account(rpc: &str, key: &str) -> Result<(Vec<u8>, String)> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[key,{"encoding":"base64"}]});
    let v: Value = ureq::post(rpc).send_json(body)?.into_json()?;
    let val = &v["result"]["value"];
    if val.is_null() {
        bail!("account {key} not found");
    }
    let data = val["data"][0].as_str().context("unexpected RPC response")?;
    let owner = val["owner"].as_str().unwrap_or_default().to_string();
    Ok((
        base64::engine::general_purpose::STANDARD.decode(data)?,
        owner,
    ))
}

pub fn fetch(rpc: &str, program_id: &str) -> Result<Deployed> {
    let (prog, owner) = account(rpc, program_id)?;
    if owner != UPGRADEABLE_LOADER {
        bail!("{program_id} is not owned by the upgradeable loader (owner {owner}); it cannot be upgraded");
    }
    if prog.len() < 36 {
        bail!("unexpected program account layout");
    }
    let pd = bs58::encode(&prog[4..36]).into_string();
    let (data, _) = account(rpc, &pd)?;
    if data.len() < PROGRAMDATA_HEADER {
        bail!("unexpected ProgramData layout");
    }
    let slot = u64::from_le_bytes(data[4..12].try_into()?);
    let upgrade_authority = (data[12] == 1).then(|| bs58::encode(&data[13..45]).into_string());
    let raw = &data[PROGRAMDATA_HEADER..];
    let elf = raw[..elf_len(raw)?].to_vec();
    Ok(Deployed {
        elf,
        last_deploy_slot: slot,
        upgrade_authority,
        programdata: pd,
    })
}

pub fn elf_len(raw: &[u8]) -> Result<usize> {
    if raw.len() < 64 || &raw[..4] != b"\x7fELF" {
        bail!("program data does not start with an ELF header");
    }
    let u64_at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().expect("8 bytes")) as usize;
    let u16_at = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]) as usize;
    let (phoff, shoff) = (u64_at(0x20), u64_at(0x28));
    let (phentsize, phnum) = (u16_at(0x36), u16_at(0x38));
    let (shentsize, shnum) = (u16_at(0x3a), u16_at(0x3c));
    let mut end = shoff.saturating_add(shentsize.saturating_mul(shnum));
    end = end.max(phoff.saturating_add(phentsize.saturating_mul(phnum)));
    for i in 0..shnum {
        let Some(h) = shoff.checked_add(i.saturating_mul(shentsize)) else {
            break;
        };
        if h.saturating_add(0x28) > raw.len() {
            break;
        }
        let kind = u32::from_le_bytes(raw[h + 4..h + 8].try_into().expect("4 bytes"));
        if kind != 8 {
            end = end.max(u64_at(h + 0x18).saturating_add(u64_at(h + 0x20)));
        }
    }
    if end > raw.len() {
        bail!("ELF header points past the end of program data");
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_len_matches_file_size_with_padding() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        for f in ["demo_vault_v1.so", "demo_vault_v2.so", "tidemark_ledger.so"] {
            let bytes = std::fs::read(dir.join(f)).unwrap();
            let mut padded = bytes.clone();
            padded.extend(std::iter::repeat_n(0u8, 4096));
            assert_eq!(elf_len(&padded).unwrap(), bytes.len(), "{f}");
        }
    }

    #[test]
    fn rejects_non_elf() {
        assert!(elf_len(&[0u8; 128]).is_err());
    }
}

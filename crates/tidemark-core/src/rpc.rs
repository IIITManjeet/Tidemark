use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const PROGRAMDATA_HEADER: usize = 45;

pub struct Deployed {
    pub elf: Vec<u8>,
    pub last_deploy_slot: u64,
    pub upgrade_authority: Option<String>,
    pub programdata: String,
}

pub const MAX_RESPONSE_BYTES: u64 = 64 << 20;

pub fn call(url: &str, method: &str, params: Value) -> Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build();
    let resp = agent
        .post(url)
        .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("RPC response is larger than {MAX_RESPONSE_BYTES} bytes");
    }
    let v: Value = serde_json::from_slice(&body).context("RPC returned invalid JSON")?;
    if let Some(e) = v.get("error") {
        bail!("RPC error: {e}");
    }
    Ok(v["result"].clone())
}

fn account(rpc: &str, key: &str) -> Result<(Vec<u8>, String)> {
    let r = call(
        rpc,
        "getAccountInfo",
        json!([key, {"encoding": "base64", "commitment": "confirmed"}]),
    )?;
    let val = &r["value"];
    if val.is_null() {
        bail!("account {key} not found");
    }
    let data = val["data"][0].as_str().context("unexpected RPC response")?;
    let owner = val["owner"]
        .as_str()
        .context("RPC response has no owner")?
        .to_string();
    Ok((
        base64::engine::general_purpose::STANDARD.decode(data)?,
        owner,
    ))
}

pub fn parse_program_account(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 36 {
        bail!("program account is too short");
    }
    let tag = u32::from_le_bytes(data[..4].try_into()?);
    if tag != 2 {
        bail!("not an upgradeable program account (loader state {tag})");
    }
    Ok(data[4..36].try_into()?)
}

pub struct ProgramData<'a> {
    pub slot: u64,
    pub authority: Option<[u8; 32]>,
    pub elf: &'a [u8],
}

pub fn parse_programdata(data: &[u8]) -> Result<ProgramData<'_>> {
    if data.len() < PROGRAMDATA_HEADER {
        bail!("ProgramData account is too short");
    }
    let tag = u32::from_le_bytes(data[..4].try_into()?);
    if tag != 3 {
        bail!("not a ProgramData account (loader state {tag})");
    }
    let slot = u64::from_le_bytes(data[4..12].try_into()?);
    let authority = match data[12] {
        0 => None,
        1 => Some(data[13..45].try_into()?),
        t => bail!("invalid upgrade authority tag {t}"),
    };
    Ok(ProgramData {
        slot,
        authority,
        elf: &data[PROGRAMDATA_HEADER..],
    })
}

pub fn fetch(rpc: &str, program_id: &str) -> Result<Deployed> {
    let (prog, owner) = account(rpc, program_id)?;
    if owner != UPGRADEABLE_LOADER {
        bail!("{program_id} is not owned by the upgradeable loader (owner {owner}); it cannot be upgraded");
    }
    let pd = bs58::encode(parse_program_account(&prog)?).into_string();
    let (data, pd_owner) = account(rpc, &pd)?;
    if pd_owner != UPGRADEABLE_LOADER {
        bail!("ProgramData {pd} is not owned by the upgradeable loader");
    }
    let ProgramData {
        slot,
        authority,
        elf: raw,
    } = parse_programdata(&data)?;
    if raw.iter().all(|b| *b == 0) {
        bail!("program {program_id} has been closed");
    }
    let elf = raw[..elf_len(raw)?].to_vec();
    Ok(Deployed {
        elf,
        last_deploy_slot: slot,
        upgrade_authority: authority.map(|a| bs58::encode(a).into_string()),
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
    fn loader_tags_are_checked() {
        let mut prog = vec![0u8; 36];
        prog[0] = 2;
        prog[4..36].copy_from_slice(&[7u8; 32]);
        assert_eq!(parse_program_account(&prog).unwrap(), [7u8; 32]);
        prog[0] = 3;
        assert!(parse_program_account(&prog).is_err());
        assert!(parse_program_account(&prog[..20]).is_err());

        let mut pd = vec![0u8; 64];
        pd[0] = 3;
        pd[4] = 9;
        pd[12] = 1;
        pd[13..45].copy_from_slice(&[5u8; 32]);
        let p = parse_programdata(&pd).unwrap();
        assert_eq!((p.slot, p.authority, p.elf.len()), (9, Some([5u8; 32]), 19));
        pd[12] = 0;
        assert_eq!(parse_programdata(&pd).unwrap().authority, None);
        pd[12] = 2;
        assert!(parse_programdata(&pd).is_err());
        pd[12] = 0;
        pd[0] = 1;
        assert!(parse_programdata(&pd).is_err());
    }

    #[test]
    fn rejects_non_elf() {
        assert!(elf_len(&[0u8; 128]).is_err());
    }
}

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
    let mut elf = data[PROGRAMDATA_HEADER..].to_vec();
    while elf.last() == Some(&0) {
        elf.pop();
    }
    Ok(Deployed {
        elf,
        last_deploy_slot: slot,
        upgrade_authority,
        programdata: pd,
    })
}

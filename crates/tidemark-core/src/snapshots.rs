use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

fn folder(dir: &Path, program: &str) -> Result<PathBuf> {
    crate::submit::decode_pubkey(program)
        .with_context(|| format!("{program:?} is not a program id"))?;
    Ok(dir.join(program))
}

pub fn path_for(dir: &Path, program: &str, slot: u64) -> Result<PathBuf> {
    Ok(folder(dir, program)?.join(format!("{slot}.so")))
}

pub fn store(dir: &Path, program: &str, slot: u64, elf: &[u8]) -> Result<bool> {
    let p = path_for(dir, program, slot)?;
    if p.exists() {
        return Ok(false);
    }
    let f = folder(dir, program)?;
    std::fs::create_dir_all(&f).with_context(|| format!("creating {}", f.display()))?;
    let tmp = p.with_extension("so.part");
    std::fs::write(&tmp, elf)?;
    std::fs::rename(&tmp, &p)?;
    Ok(true)
}

pub fn slots(dir: &Path, program: &str) -> Result<Vec<u64>> {
    let f = folder(dir, program)?;
    if !f.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<u64> = std::fs::read_dir(&f)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".so")?.parse().ok()
        })
        .collect();
    out.sort_unstable();
    Ok(out)
}

pub fn previous(dir: &Path, program: &str, slot: u64) -> Result<Option<u64>> {
    Ok(slots(dir, program)?.into_iter().filter(|s| *s < slot).max())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3";

    #[test]
    fn ids_that_are_not_program_keys_are_refused() {
        let d = tmp("ids");
        for bad in ["../x", "C:/x", "/etc", "abc"] {
            assert!(store(&d, bad, 1, b"x").is_err(), "{bad}");
        }
        assert!(!d.join("..").join("x").join("1.so").exists());
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tidemark-snap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn stores_each_version_once_and_finds_the_previous_one() {
        let d = tmp("order");
        assert!(store(&d, P, 100, b"v1").unwrap());
        assert!(!store(&d, P, 100, b"v1").unwrap());
        assert!(store(&d, P, 250, b"v2").unwrap());
        assert!(store(&d, P, 90, b"v0").unwrap());
        assert_eq!(slots(&d, P).unwrap(), vec![90, 100, 250]);
        assert_eq!(previous(&d, P, 250).unwrap(), Some(100));
        assert_eq!(previous(&d, P, 90).unwrap(), None);
        assert_eq!(std::fs::read(path_for(&d, P, 250).unwrap()).unwrap(), b"v2");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_program_has_no_snapshots() {
        let d = tmp("empty");
        assert!(slots(&d, P).unwrap().is_empty());
        assert_eq!(previous(&d, P, 5).unwrap(), None);
    }

    #[test]
    fn stray_files_are_ignored() {
        let d = tmp("stray");
        store(&d, P, 7, b"x").unwrap();
        std::fs::write(d.join(P).join("notes.txt"), b"hi").unwrap();
        std::fs::write(d.join(P).join("8.so.part"), b"half").unwrap();
        assert_eq!(slots(&d, P).unwrap(), vec![7]);
        let _ = std::fs::remove_dir_all(&d);
    }
}

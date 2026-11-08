use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tidemark_core::{diff, elf};

const WALL_CLOCK: Duration = Duration::from_secs(120);
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn lock_down() -> Result<()> {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, RulesetStatus, ABI};
    use rlimit::{setrlimit, Resource};

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))?
        .create()?
        .restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        let _ = writeln!(
            std::io::stderr(),
            "note: Landlock is unavailable on this kernel; continuing with resource limits only"
        );
    }
    for (res, limit) in [
        (Resource::AS, 2u64 << 30),
        (Resource::CPU, 60),
        (Resource::NOFILE, 16),
        (Resource::FSIZE, 0),
        (Resource::NPROC, 0),
    ] {
        setrlimit(res, limit, limit).with_context(|| format!("cannot set {res:?} limit"))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn lock_down() -> Result<()> {
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0u8; 8];
    r.read_exact(&mut len)?;
    let len = u64::from_le_bytes(len);
    if len > MAX_OUTPUT {
        bail!("input of {len} bytes is too large");
    }
    let mut buf = Vec::new();
    r.take(len).read_to_end(&mut buf)?;
    if buf.len() as u64 != len {
        bail!("input ended early");
    }
    Ok(buf)
}

fn write_frame(w: &mut impl Write, b: &[u8]) -> std::io::Result<()> {
    w.write_all(&(b.len() as u64).to_le_bytes())?;
    w.write_all(b)
}

pub fn child() -> Result<()> {
    lock_down()?;
    let mut stdin = std::io::stdin().lock();
    let (a, b) = (read_frame(&mut stdin)?, read_frame(&mut stdin)?);
    let r = diff::compare(&elf::load(&a)?, &elf::load(&b)?);
    let e = tidemark_core::cache::entry(&r);
    let mut out = std::io::stdout().lock();
    out.write_all(serde_json::to_string(&e)?.as_bytes())?;
    out.flush()?;
    Ok(())
}

pub fn review(a: &[u8], b: &[u8]) -> Result<Value> {
    if !cfg!(target_os = "linux") {
        let _ = writeln!(
            std::io::stderr(),
            "note: --isolate on this OS uses a separate process with a cleared environment and a timeout; OS-level limits are Linux-only"
        );
    }
    let exe = std::env::current_exe().context("cannot locate the tidemark executable")?;
    let mut child = Command::new(exe)
        .arg("__review")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start the isolated runner")?;
    let mut stdin = child.stdin.take().context("no stdin")?;
    let mut stdout = child.stdout.take().context("no stdout")?;
    let mut stderr = child.stderr.take().context("no stderr")?;
    let (a, b) = (a.to_vec(), b.to_vec());
    std::thread::spawn(move || {
        let _ = write_frame(&mut stdin, &a).and_then(|_| write_frame(&mut stdin, &b));
    });
    let out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = (&mut stdout).take(MAX_OUTPUT).read_to_end(&mut v);
        v
    });
    let err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > WALL_CLOCK {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "isolated runner timed out after {}s and was killed",
                WALL_CLOCK.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = out.join().unwrap_or_default();
    let err = err.join().unwrap_or_default();
    if !status.success() {
        bail!(
            "isolated runner failed ({status}): {}",
            String::from_utf8_lossy(&err).trim()
        );
    }
    let note = String::from_utf8_lossy(&err);
    if !note.trim().is_empty() {
        let _ = writeln!(std::io::stderr(), "{}", note.trim());
    }
    serde_json::from_slice(&out).context("isolated runner returned an invalid report")
}

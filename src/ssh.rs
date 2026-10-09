//! Load SSH keys into an agent, with passphrases from sealkeep.
//!
//! An agent such as gcr holds a key with a passphrase only in memory. After a reboot it
//! is empty until someone types the passphrase, and each `git push` of an AI agent fails
//! with `Permission denied (publickey)`. `ssh-load` (also the last step of `unlock`) adds
//! each key of the config to its agent. It runs `ssh-add` with sealkeep as the
//! `SSH_ASKPASS` program, so the passphrase goes from the store to `ssh-add` and is never
//! shown.
//!
//! The askpass step prints a passphrase, so it answers only when two checks pass: its
//! parent process is `ssh-add`, and the one-use token in its environment names a file
//! that `ssh-load` wrote for this run and that the step removes. The file holds the
//! name of the passphrase secret; the step reads the value from the store.

use crate::config::{Config, SshKey};
use crate::names::SecretRef;
use crate::store::Stores;
use anyhow::{Context, Result, bail};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const ASKPASS_ENV: &str = "SEALKEEP_ASKPASS_TOKEN";

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => directories::BaseDirs::new()
            .map(|d| d.home_dir().join(rest))
            .unwrap_or_else(|| PathBuf::from(p)),
        None => PathBuf::from(p),
    }
}

fn fingerprint(key: &Path) -> Result<String> {
    let pubkey = PathBuf::from(format!("{}.pub", key.display()));
    let src = if pubkey.exists() {
        pubkey
    } else {
        key.to_path_buf()
    };
    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(&src)
        .stdin(Stdio::null())
        .output()
        .context("run ssh-keygen")?;
    if !out.status.success() {
        bail!("ssh-keygen cannot read {}", src.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .nth(1)
        .map(str::to_string)
        .context("no fingerprint in the ssh-keygen output")
}

fn agent_has(agent: &str, fp: &str) -> bool {
    Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", agent)
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(fp))
        .unwrap_or(false)
}

fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir)
        .join("sealkeep")
}

fn random_token() -> Result<String> {
    let mut buf = [0u8; 24];
    let mut f = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    std::io::Read::read_exact(&mut f, &mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Add each SSH key of the config to its agent. Returns report lines.
pub fn load(cfg: &Config) -> Result<Vec<String>> {
    let stores = Stores::from_config(cfg);
    let bin = std::env::current_exe().context("find the sealkeep binary")?;
    let mut lines = Vec::new();
    for k in &cfg.ssh_keys {
        let path = expand(&k.path);
        let agent = match &k.agent {
            Some(a) => a.clone(),
            None => std::env::var("SSH_AUTH_SOCK")
                .context("no agent in the config and no $SSH_AUTH_SOCK")?,
        };
        let fp = match fingerprint(&path) {
            Ok(f) => f,
            Err(e) => {
                lines.push(format!("{}: ERROR {e:#}", k.path));
                continue;
            }
        };
        if agent_has(&agent, &fp) {
            lines.push(format!("{}: already in the agent", k.path));
            continue;
        }
        match add_one(&stores, &bin, &path, &agent, k) {
            Ok(()) if agent_has(&agent, &fp) => lines.push(format!("{}: added to {agent}", k.path)),
            Ok(()) => lines.push(format!(
                "{}: ERROR ssh-add ended, but the key is not in the agent",
                k.path
            )),
            Err(e) => lines.push(format!("{}: ERROR {e:#}", k.path)),
        }
    }
    Ok(lines)
}

fn add_one(stores: &Stores, bin: &Path, path: &Path, agent: &str, k: &SshKey) -> Result<()> {
    let mut cmd = Command::new("ssh-add");
    cmd.arg(path)
        .env("SSH_AUTH_SOCK", agent)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // A one-use token: the file holds the name of the passphrase secret, only the user
    // can read it, and the askpass step removes it.
    let mut token_file = None;
    if let Some(name) = &k.passphrase {
        // Fail here, before ssh-add, when the passphrase is not stored.
        let r = SecretRef::parse(name)?;
        stores.resolve(std::slice::from_ref(&r))?;
        let token = random_token()?;
        let dir = runtime_dir();
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("askpass-{token}"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&file)?;
        f.write_all(name.as_bytes())?;
        token_file = Some(file);
        cmd.env("SSH_ASKPASS", bin)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env(
                "DISPLAY",
                std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into()),
            )
            .env(ASKPASS_ENV, &token);
    }
    let out = cmd.output().context("run ssh-add");
    if let Some(f) = token_file {
        let _ = std::fs::remove_file(f);
    }
    let out = out?;
    if !out.status.success() {
        bail!(
            "ssh-add failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
    }
    crate::record(
        "ssh_load",
        k.passphrase.iter().cloned().collect(),
        Some(format!("ssh-add {}", k.path)),
    )
}

/// The name of the parent process.
fn parent_name() -> Option<String> {
    #[cfg(unix)]
    {
        let ppid = unsafe { libc::getppid() };
        if let Ok(exe) = std::fs::read_link(format!("/proc/{ppid}/exe")) {
            return exe.file_name().map(|n| n.to_string_lossy().into_owned());
        }
        let out = Command::new("ps")
            .args(["-o", "comm=", "-p", &ppid.to_string()])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return Path::new(&s)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
    }
    #[allow(unreachable_code)]
    None
}

/// The askpass step. Runs when `SEALKEEP_ASKPASS_TOKEN` is set. Prints the passphrase
/// for `ssh-add`, or nothing.
pub fn askpass(token: &str) -> i32 {
    if parent_name().as_deref() != Some("ssh-add") {
        eprintln!("sealkeep: the askpass step answers ssh-add only");
        return 1;
    }
    if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return 1;
    }
    let file = runtime_dir().join(format!("askpass-{token}"));
    let name = match std::fs::read_to_string(&file) {
        Ok(n) => n,
        Err(_) => return 1,
    };
    let _ = std::fs::remove_file(&file);
    let value = SecretRef::parse(name.trim()).and_then(|r| {
        let stores = Stores::from_config(&Config::load()?);
        Ok(stores.resolve(std::slice::from_ref(&r))?.remove(0).value)
    });
    match value {
        Ok(v) => {
            println!("{v}");
            0
        }
        Err(e) => {
            eprintln!("sealkeep: {e:#}");
            1
        }
    }
}

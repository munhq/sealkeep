//! Run the CLI of a vendor for a store.
//!
//! A value never goes on the command line, where `ps` and shell history show it. It goes
//! to the CLI through stdin, or through a temporary file that only the user can read and
//! that is removed after the call. Prompts are off, so a CLI that needs a sign-in fails
//! with its message.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// The first line of stderr, for an error message.
    pub fn err_line(&self) -> String {
        self.stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect()
    }

    pub fn ok(self, what: &str) -> Result<Output> {
        if self.status != 0 {
            bail!("{what} failed (exit {}): {}", self.status, self.err_line());
        }
        Ok(self)
    }
}

/// Run `prog args`, with `stdin` when given, and `env` added.
pub fn run(
    prog: &str,
    args: &[String],
    stdin: Option<&[u8]>,
    env: &[(&str, &str)],
) -> Result<Output> {
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("run `{prog}` (is it installed and on PATH?)"))?;
    if let Some(input) = stdin {
        let mut w = child.stdin.take().expect("stdin is piped");
        let input = input.to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&input);
        });
    }
    let out = child.wait_with_output()?;
    Ok(Output {
        status: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// A file that only the user can read, removed when it is dropped.
pub struct SecretFile {
    pub path: PathBuf,
}

impl SecretFile {
    pub fn new(content: &[u8]) -> Result<Self> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|d| d.is_dir())
            .unwrap_or_else(std::env::temp_dir)
            .join("sealkeep");
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = dir.join(format!(
            "value-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        let file = Self { path };
        f.write_all(content)?;
        f.sync_all()?;
        Ok(file)
    }

    pub fn display(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An ID for a vendor that allows only `[A-Za-z0-9-]` (and `_` when `underscore`) and
/// at most `max` characters: the name with `/` as `--` and other characters as `-`, cut
/// to fit, and 8 hex characters of its SHA-256, so two names never get the same ID. The
/// real name goes into a tag.
pub fn safe_id(name: &str, underscore: bool, max: usize) -> String {
    let base: String = name
        .replace('/', "--")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || (underscore && c == '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let hash = Sha256::digest(name.as_bytes());
    let short: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let room = max.saturating_sub(4 + 1 + short.len());
    let base: String = base.chars().take(room).collect();
    format!("sk--{base}-{short}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_safe_and_distinct() {
        let a = safe_id("personal/app.x/dev/API_KEY", false, 127);
        let b = safe_id("personal/app-x/dev/API_KEY", false, 127);
        assert_ne!(a, b);
        assert!(
            a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{a}"
        );
        assert!(a.starts_with("sk--personal--app-x--dev--API-KEY-"), "{a}");
        let c = safe_id("personal/app/API_KEY", true, 255);
        assert!(c.contains("API_KEY"), "{c}");
        let long = "a/".repeat(100) + "KEY";
        let d = safe_id(&long, false, 127);
        assert_eq!(d.len(), 127, "{d}");
        assert_ne!(d, safe_id(&("b/".to_string() + &long), false, 127));
    }

    #[test]
    fn secret_file_is_removed() {
        let f = SecretFile::new(b"v").unwrap();
        let p = f.path.clone();
        assert!(p.exists());
        drop(f);
        assert!(!p.exists());
    }
}

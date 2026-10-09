//! The local audit log: one JSON line for each use of a secret. It holds names, stores
//! and the command, and never a value.
//!
//! Path: `$SEALKEEP_AUDIT_LOG`, else `audit.jsonl` in the data folder of the OS
//! (`~/.local/share/sealkeep/audit.jsonl` on Linux).

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write as _;
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SEALKEEP_AUDIT_LOG") {
        return Ok(PathBuf::from(p));
    }
    let dirs = directories::ProjectDirs::from("", "", "sealkeep")
        .context("cannot find the home folder for the audit log")?;
    Ok(dirs.data_local_dir().join("audit.jsonl"))
}

#[derive(Serialize)]
pub struct Event<'a> {
    pub at: String,
    /// `run`, `mcp_run`, `get`, `set`, `remove`, `import`.
    pub action: &'a str,
    pub secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Append one event. A failure to write the log stops the action: a secret use that
/// cannot be logged does not happen.
pub fn record(event: &Event) -> Result<()> {
    let p = path()?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&p)
        .with_context(|| format!("open the audit log {}", p.display()))?;
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    f.write_all(&line)
        .with_context(|| format!("write the audit log {}", p.display()))?;
    Ok(())
}

/// The command as one line for the log, cut to 300 characters.
pub fn command_line(argv: &[String]) -> String {
    let s = argv.join(" ");
    if s.chars().count() > 300 {
        let mut t: String = s.chars().take(300).collect();
        t.push('…');
        t
    } else {
        s
    }
}

pub fn cwd() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string())
}

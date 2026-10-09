//! Install sealkeep into the AI clients on this machine: the skill, the MCP server and
//! the guard hook.
//!
//! | Client      | Skill                          | MCP                 | Hook                                   |
//! |-------------|--------------------------------|---------------------|----------------------------------------|
//! | Claude Code | `<config>/skills/sealkeep`     | `claude mcp add`    | `<config>/settings.json`, PreToolUse   |
//! | Codex       | `$CODEX_HOME/skills/sealkeep`  | `codex mcp add`     | `$CODEX_HOME/hooks.json`, PreToolUse   |
//! | Cursor      | `~/.cursor/skills/sealkeep`    | `~/.cursor/mcp.json`| `~/.cursor/hooks.json`, beforeShellExecution |
//!
//! Claude Code gets each config folder: `$CLAUDE_CONFIG_DIR`, `~/.claude`, and each
//! `~/.claude-*` folder that Claude Code has used. Each JSON file is backed up to
//! `<file>.bak-<unix time>` before a change.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SKILL: &str = include_str!("../plugin/skills/sealkeep/SKILL.md");
const MARK: &str = "sealkeep guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ClientId {
    Claude,
    Codex,
    Cursor,
}

#[derive(Debug, Clone, Copy)]
pub struct Parts {
    pub skills: bool,
    pub mcp: bool,
    pub hooks: bool,
}

pub struct Ctx {
    pub dry_run: bool,
    pub bin: String,
    pub parts: Parts,
}

fn home() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .context("cannot find the home folder")
}

/// The absolute path of this binary, so hooks work with a short PATH.
pub fn bin_path() -> Result<String> {
    let p = std::env::current_exe().context("find the sealkeep binary")?;
    let p = p.canonicalize().unwrap_or(p);
    Ok(p.display().to_string())
}

/// The Claude Code config folders on this machine.
pub fn claude_dirs() -> Result<Vec<PathBuf>> {
    let home = home()?;
    let mut dirs = Vec::new();
    if let Some(d) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        dirs.push(PathBuf::from(d));
    }
    let default = home.join(".claude");
    if default.is_dir() {
        dirs.push(default);
    }
    if let Ok(rd) = std::fs::read_dir(&home) {
        let mut extra: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".claude-"))
                    && p.is_dir()
                    && (p.join("projects").is_dir()
                        || p.join("history.jsonl").is_file()
                        || p.join(".credentials.json").is_file())
            })
            .collect();
        extra.sort();
        dirs.extend(extra);
    }
    let mut seen = HashSet::new();
    dirs.retain(|d| seen.insert(d.canonicalize().unwrap_or_else(|_| d.clone())));
    Ok(dirs)
}

fn codex_home() -> Result<PathBuf> {
    match std::env::var_os("CODEX_HOME") {
        Some(d) => Ok(PathBuf::from(d)),
        None => Ok(home()?.join(".codex")),
    }
}

fn on_path(prog: &str) -> bool {
    Command::new(prog)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// The clients that exist on this machine.
pub fn detect() -> Result<Vec<ClientId>> {
    let mut out = Vec::new();
    if !claude_dirs()?.is_empty() || on_path("claude") {
        out.push(ClientId::Claude);
    }
    if codex_home()?.is_dir() || on_path("codex") {
        out.push(ClientId::Codex);
    }
    if home()?.join(".cursor").is_dir() {
        out.push(ClientId::Cursor);
    }
    Ok(out)
}

// ── files ────────────────────────────────────────────────────────────────────

fn backup(path: &Path) -> Result<()> {
    if path.exists() {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak = PathBuf::from(format!("{}.bak-{secs}", path.display()));
        std::fs::copy(path, &bak).with_context(|| format!("back up {}", path.display()))?;
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(json!({})),
        Ok(t) => serde_json::from_str(&t).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Change a JSON file with `f`. `f` returns `false` when no change is needed.
fn edit_json(ctx: &Ctx, path: &Path, f: impl FnOnce(&mut Value) -> Result<bool>) -> Result<bool> {
    // A config file that is a link to a shared file keeps its link: the write goes to
    // the target.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let path = resolved.as_path();
    let mut v = read_json(path)?;
    if !v.is_object() {
        bail!("{} is not a JSON object", path.display());
    }
    if !f(&mut v)? {
        return Ok(false);
    }
    if ctx.dry_run {
        return Ok(true);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    backup(path)?;
    let tmp = PathBuf::from(format!("{}.sealkeep-tmp", path.display()));
    std::fs::write(&tmp, serde_json::to_string_pretty(&v)? + "\n")?;
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn write_skill(ctx: &Ctx, skills_dir: &Path) -> Result<String> {
    let dir = skills_dir.join("sealkeep");
    let file = dir.join("SKILL.md");
    if std::fs::read_to_string(&file).is_ok_and(|t| t == SKILL) {
        return Ok(format!("skill is current in {}", dir.display()));
    }
    if !ctx.dry_run {
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        std::fs::write(&file, SKILL).with_context(|| format!("write {}", file.display()))?;
    }
    let verb = if ctx.dry_run { "would write" } else { "wrote" };
    Ok(format!("{verb} the skill to {}", dir.display()))
}

fn guard_command(ctx: &Ctx, client: &str) -> String {
    format!("{} guard --client {client}", shell_quote(&ctx.bin))
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Claude Code and Codex: a PreToolUse group with a matcher.
fn add_pretool_hook(ctx: &Ctx, path: &Path, matcher: &str, client: &str) -> Result<String> {
    let cmd = guard_command(ctx, client);
    let changed = edit_json(ctx, path, |v| {
        if v.to_string().contains(MARK) {
            return Ok(false);
        }
        let hooks = v
            .as_object_mut()
            .expect("checked")
            .entry("hooks")
            .or_insert_with(|| json!({}));
        let list = hooks
            .as_object_mut()
            .context("`hooks` is not an object")?
            .entry("PreToolUse")
            .or_insert_with(|| json!([]));
        list.as_array_mut()
            .context("`hooks.PreToolUse` is not a list")?
            .push(json!({"matcher": matcher, "hooks": [{"type": "command", "command": cmd, "timeout": 10}]}));
        Ok(true)
    })?;
    Ok(if changed {
        let verb = if ctx.dry_run { "would add" } else { "added" };
        format!("{verb} the guard hook to {}", path.display())
    } else {
        format!("the guard hook is already in {}", path.display())
    })
}

fn remove_hooks(ctx: &Ctx, path: &Path, event: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    edit_json(ctx, path, |v| {
        let Some(list) = v
            .pointer_mut(&format!("/hooks/{event}"))
            .and_then(Value::as_array_mut)
        else {
            return Ok(false);
        };
        let before = list.len();
        list.retain(|g| !g.to_string().contains(MARK));
        Ok(list.len() != before)
    })
}

// ── clients ──────────────────────────────────────────────────────────────────

fn claude_mcp(ctx: &Ctx, dir: &Path, add: bool) -> Result<String> {
    if !on_path("claude") {
        return Ok("the `claude` CLI is not on PATH, so the MCP server is not registered".into());
    }
    let mut base = Command::new("claude");
    // `~/.claude` is the default folder, and its user config is `~/.claude.json`.
    if dir == home()?.join(".claude") {
        base.env_remove("CLAUDE_CONFIG_DIR");
    } else {
        base.env("CLAUDE_CONFIG_DIR", dir);
    }
    let exists = {
        let mut c = clone_cmd(&base);
        c.args(["mcp", "get", "sealkeep"]);
        c.output().map(|o| o.status.success()).unwrap_or(false)
    };
    if add && exists {
        return Ok("the MCP server is already registered".into());
    }
    if !add && !exists {
        return Ok("no MCP server to remove".into());
    }
    if ctx.dry_run {
        return Ok(if add {
            "would register the MCP server"
        } else {
            "would remove the MCP server"
        }
        .into());
    }
    let mut c = clone_cmd(&base);
    if add {
        c.args([
            "mcp", "add", "--scope", "user", "sealkeep", "--", &ctx.bin, "mcp",
        ]);
    } else {
        c.args(["mcp", "remove", "--scope", "user", "sealkeep"]);
    }
    let out = c.output().context("run `claude mcp`")?;
    if !out.status.success() {
        bail!(
            "`claude mcp` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(if add {
        "registered the MCP server"
    } else {
        "removed the MCP server"
    }
    .into())
}

fn clone_cmd(c: &Command) -> Command {
    let mut n = Command::new(c.get_program());
    for (k, v) in c.get_envs() {
        match v {
            Some(v) => n.env(k, v),
            None => n.env_remove(k),
        };
    }
    n.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    n
}

fn codex_mcp(ctx: &Ctx, add: bool) -> Result<String> {
    if !on_path("codex") {
        return Ok("the `codex` CLI is not on PATH, so the MCP server is not registered".into());
    }
    let cfg = std::fs::read_to_string(codex_home()?.join("config.toml")).unwrap_or_default();
    let exists = cfg.contains("[mcp_servers.sealkeep]");
    if add == exists {
        return Ok(if add {
            "the MCP server is already registered"
        } else {
            "no MCP server to remove"
        }
        .into());
    }
    if ctx.dry_run {
        return Ok(if add {
            "would register the MCP server"
        } else {
            "would remove the MCP server"
        }
        .into());
    }
    let mut c = Command::new("codex");
    if add {
        c.args(["mcp", "add", "sealkeep", "--", &ctx.bin, "mcp"]);
    } else {
        c.args(["mcp", "remove", "sealkeep"]);
    }
    let out = c.output().context("run `codex mcp`")?;
    if !out.status.success() {
        bail!(
            "`codex mcp` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(if add {
        "registered the MCP server"
    } else {
        "removed the MCP server"
    }
    .into())
}

fn cursor_mcp(ctx: &Ctx, add: bool) -> Result<String> {
    let path = home()?.join(".cursor").join("mcp.json");
    let bin = ctx.bin.clone();
    let changed = edit_json(ctx, &path, |v| {
        let servers = v
            .as_object_mut()
            .expect("checked")
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        let servers = servers
            .as_object_mut()
            .context("`mcpServers` is not an object")?;
        if add {
            if servers.contains_key("sealkeep") {
                return Ok(false);
            }
            servers.insert("sealkeep".into(), json!({"command": bin, "args": ["mcp"]}));
            Ok(true)
        } else {
            Ok(servers.remove("sealkeep").is_some())
        }
    })?;
    Ok(match (add, changed) {
        (true, true) if ctx.dry_run => {
            format!("would register the MCP server in {}", path.display())
        }
        (true, true) => format!("registered the MCP server in {}", path.display()),
        (true, false) => "the MCP server is already registered".into(),
        (false, true) => format!("removed the MCP server from {}", path.display()),
        (false, false) => "no MCP server to remove".into(),
    })
}

fn cursor_hook(ctx: &Ctx, add: bool) -> Result<String> {
    let path = home()?.join(".cursor").join("hooks.json");
    if !add {
        let changed = remove_hooks(ctx, &path, "beforeShellExecution")?;
        return Ok(if changed {
            format!("removed the guard hook from {}", path.display())
        } else {
            "no guard hook to remove".into()
        });
    }
    let cmd = guard_command(ctx, "cursor");
    let changed = edit_json(ctx, &path, |v| {
        if v.to_string().contains(MARK) {
            return Ok(false);
        }
        let o = v.as_object_mut().expect("checked");
        o.entry("version").or_insert(json!(1));
        let hooks = o.entry("hooks").or_insert_with(|| json!({}));
        hooks
            .as_object_mut()
            .context("`hooks` is not an object")?
            .entry("beforeShellExecution")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .context("`hooks.beforeShellExecution` is not a list")?
            .push(json!({"command": cmd}));
        Ok(true)
    })?;
    Ok(if changed {
        format!("added the guard hook to {}", path.display())
    } else {
        format!("the guard hook is already in {}", path.display())
    })
}

fn remove_skill(ctx: &Ctx, skills_dir: &Path) -> Result<String> {
    let dir = skills_dir.join("sealkeep");
    let file = dir.join("SKILL.md");
    if !file.exists() {
        return Ok("no skill to remove".into());
    }
    if !ctx.dry_run {
        std::fs::remove_file(&file)?;
        let _ = std::fs::remove_dir(&dir);
    }
    Ok(format!("removed the skill from {}", dir.display()))
}

/// Install (`add = true`) or uninstall each part into each client. Returns report lines.
pub fn apply(ctx: &Ctx, clients: &[ClientId], add: bool) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut push = |label: String, r: Result<String>| match r {
        Ok(s) => lines.push(format!("{label}: {s}")),
        Err(e) => lines.push(format!("{label}: ERROR {e:#}")),
    };
    let mut skill_dirs_done = HashSet::new();
    for c in clients {
        match c {
            ClientId::Claude => {
                for dir in claude_dirs()? {
                    let label = format!("Claude Code {}", dir.display());
                    if ctx.parts.skills {
                        let skills = dir.join("skills");
                        let key = skills.canonicalize().unwrap_or_else(|_| skills.clone());
                        if skill_dirs_done.insert(key) {
                            push(
                                label.clone(),
                                if add {
                                    write_skill(ctx, &skills)
                                } else {
                                    remove_skill(ctx, &skills)
                                },
                            );
                        }
                    }
                    if ctx.parts.mcp {
                        push(label.clone(), claude_mcp(ctx, &dir, add));
                    }
                    if ctx.parts.hooks {
                        let settings = dir.join("settings.json");
                        let r = if add {
                            add_pretool_hook(ctx, &settings, "Bash|Read|Grep", "claude")
                        } else {
                            remove_hooks(ctx, &settings, "PreToolUse").map(|c| {
                                if c {
                                    format!("removed the guard hook from {}", settings.display())
                                } else {
                                    "no guard hook to remove".into()
                                }
                            })
                        };
                        push(label.clone(), r);
                    }
                }
            }
            ClientId::Codex => {
                let home = codex_home()?;
                let label = "Codex".to_string();
                if ctx.parts.skills {
                    push(
                        label.clone(),
                        if add {
                            write_skill(ctx, &home.join("skills"))
                        } else {
                            remove_skill(ctx, &home.join("skills"))
                        },
                    );
                }
                if ctx.parts.mcp {
                    push(label.clone(), codex_mcp(ctx, add));
                }
                if ctx.parts.hooks {
                    let path = home.join("hooks.json");
                    let r = if add {
                        add_pretool_hook(ctx, &path, "", "codex")
                            .map(|s| s + " (approve it one time in Codex with /hooks)")
                    } else {
                        remove_hooks(ctx, &path, "PreToolUse").map(|c| {
                            if c {
                                format!("removed the guard hook from {}", path.display())
                            } else {
                                "no guard hook to remove".into()
                            }
                        })
                    };
                    push(label.clone(), r);
                }
            }
            ClientId::Cursor => {
                let label = "Cursor".to_string();
                if ctx.parts.skills {
                    let skills = home()?.join(".cursor").join("skills");
                    push(
                        label.clone(),
                        if add {
                            write_skill(ctx, &skills)
                        } else {
                            remove_skill(ctx, &skills)
                        },
                    );
                }
                if ctx.parts.mcp {
                    push(label.clone(), cursor_mcp(ctx, add));
                }
                if ctx.parts.hooks {
                    push(label.clone(), cursor_hook(ctx, add));
                }
            }
        }
    }
    Ok(lines)
}

/// One line for each client for `doctor`.
pub fn status() -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for dir in claude_dirs()? {
        let skill = dir.join("skills/sealkeep/SKILL.md");
        let skill = match std::fs::read_to_string(&skill) {
            Ok(t) if t == SKILL => "current",
            Ok(_) => "old (run `sealkeep install`)",
            Err(_) => "missing",
        };
        let hook = read_json(&dir.join("settings.json"))
            .map(|v| v.to_string().contains(MARK))
            .unwrap_or(false);
        lines.push(format!(
            "Claude Code {}: skill {skill}, hook {}",
            dir.display(),
            if hook { "on" } else { "missing" }
        ));
    }
    let codex = codex_home()?;
    if codex.is_dir() {
        let hook = read_json(&codex.join("hooks.json"))
            .map(|v| v.to_string().contains(MARK))
            .unwrap_or(false);
        let mcp = std::fs::read_to_string(codex.join("config.toml"))
            .unwrap_or_default()
            .contains("[mcp_servers.sealkeep]");
        lines.push(format!(
            "Codex {}: skill {}, MCP {}, hook {}",
            codex.display(),
            if codex.join("skills/sealkeep/SKILL.md").exists() {
                "present"
            } else {
                "missing"
            },
            if mcp { "on" } else { "missing" },
            if hook { "on" } else { "missing" }
        ));
    }
    let cursor = home()?.join(".cursor");
    if cursor.is_dir() {
        let mcp = read_json(&cursor.join("mcp.json"))
            .map(|v| v.pointer("/mcpServers/sealkeep").is_some())
            .unwrap_or(false);
        let hook = read_json(&cursor.join("hooks.json"))
            .map(|v| v.to_string().contains(MARK))
            .unwrap_or(false);
        lines.push(format!(
            "Cursor: MCP {}, hook {}",
            if mcp { "on" } else { "missing" },
            if hook { "on" } else { "missing" }
        ));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx {
            dry_run: false,
            bin: "/opt/bin/sealkeep".into(),
            parts: Parts {
                skills: true,
                mcp: true,
                hooks: true,
            },
        }
    }

    #[test]
    fn hook_is_added_once_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other"}]}]}}"#).unwrap();
        let c = ctx();
        add_pretool_hook(&c, &path, "Bash|Read|Grep", "claude").unwrap();
        add_pretool_hook(&c, &path, "Bash|Read|Grep", "claude").unwrap();
        let v = read_json(&path).unwrap();
        let list = v.pointer("/hooks/PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[1].pointer("/hooks/0/command").unwrap(),
            "/opt/bin/sealkeep guard --client claude"
        );
        assert!(remove_hooks(&c, &path, "PreToolUse").unwrap());
        let v = read_json(&path).unwrap();
        assert_eq!(
            v.pointer("/hooks/PreToolUse")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let backups = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".bak-")
            })
            .count();
        assert!(backups >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_config_keeps_its_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("shared.json");
        std::fs::write(&target, "{}").unwrap();
        let link = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        add_pretool_hook(&ctx(), &link, "Bash", "claude").unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(std::fs::read_to_string(&target).unwrap().contains(MARK));
    }

    #[test]
    fn dry_run_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut c = ctx();
        c.dry_run = true;
        let msg = add_pretool_hook(&c, &path, "Bash", "claude").unwrap();
        assert!(msg.contains("would add"));
        assert!(!path.exists());
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/usr/bin/sealkeep"), "/usr/bin/sealkeep");
        assert_eq!(shell_quote("/Users/a b/sealkeep"), "'/Users/a b/sealkeep'");
    }
}

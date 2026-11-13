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

use crate::config::Config;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SKILL: &str = include_str!("../plugin/skills/sealkeep/SKILL.md");
const MARK: &str = "sealkeep guard";

/// The `permissions.deny` rules of Claude Code for paths and commands that print a
/// secret value outside sealkeep. Claude Code checks the Read rules on the path, so a
/// shell trick does not change the result. `.env.example` and the other template names
/// stay readable. The Bash rules are a second layer: the guard hook parses the command,
/// including flags before a verb and `bash -c`.
const DENY_RULES: &[&str] = &[
    "Read(**/.kube/**)",
    "Read(**/.aws/**)",
    "Read(**/.config/gcloud/**)",
    "Read(**/.azure/**)",
    "Read(**/.kube/config)",
    "Read(**/kubeconfig)",
    "Read(**/*.kubeconfig)",
    "Read(**/.aws/credentials)",
    "Read(**/.docker/config.json)",
    "Read(**/.netrc)",
    "Read(**/.npmrc)",
    "Read(**/.pypirc)",
    "Read(**/.git-credentials)",
    "Read(**/.vault-token)",
    "Read(**/.envrc)",
    "Read(**/.pgpass)",
    "Read(**/.my.cnf)",
    "Read(**/.mongorc.js)",
    "Read(**/*.kdbx)",
    "Read(**/.password-store/**)",
    "Read(**/.gnupg/**)",
    "Read(**/.config/sops/**)",
    "Read(**/.config/age/**)",
    "Read(**/.config/helm/repositories.yaml)",
    "Read(**/.config/terraform/credentials.tfrc.json)",
    "Read(**/.terraform.d/credentials.tfrc.json)",
    "Read(**/.config/pulumi/credentials.json)",
    "Read(**/.config/rclone/rclone.conf)",
    "Read(**/.config/argocd/config)",
    "Read(**/.config/glab-cli/config.yml)",
    "Read(**/.config/git/credentials)",
    "Read(**/.m2/**)",
    "Read(**/.gradle/gradle.properties)",
    "Read(**/.nuget/**)",
    "Read(**/.gem/credentials)",
    "Read(**/.condarc)",
    "Read(**/.yarnrc.yml)",
    "Read(**/.bash_history)",
    "Read(**/.zsh_history)",
    "Read(**/.local/share/fish/fish_history)",
    "Read(**/.python_history)",
    "Read(**/.node_repl_history)",
    "Read(**/.psql_history)",
    "Read(**/.mysql_history)",
    "Read(**/.config/google-chrome/**)",
    "Read(**/.config/chromium/**)",
    "Read(**/.config/BraveSoftware/**)",
    "Read(**/.config/microsoft-edge/**)",
    "Read(**/.mozilla/firefox/**)",
    "Read(**/Library/Safari/**)",
    "Read(**/Login Data)",
    "Read(**/logins.json)",
    "Read(**/key4.db)",
    "Read(**/key3.db)",
    "Read(**/cookies.sqlite)",
    "Read(**/signons.sqlite)",
    "Read(**/k3s.yaml)",
    "Read(**/admin.conf)",
    "Read(**/kubelet.conf)",
    "Read(**/.ssh/id_rsa)",
    "Read(**/.ssh/id_dsa)",
    "Read(**/.ssh/id_ecdsa)",
    "Read(**/.ssh/id_ed25519)",
    "Read(**/*.tfstate)",
    "Read(**/*.tfstate.backup)",
    "Bash(kubectl get secret:*)",
    "Bash(kubectl get secrets:*)",
    "Bash(kubectl edit secret:*)",
    "Bash(kubectl view-secret:*)",
    "Bash(kubectl config view --raw:*)",
    "Bash(kubectl create token:*)",
    "Bash(vault kv get:*)",
    "Bash(vault kv export:*)",
    "Bash(vault read:*)",
    "Bash(ansible-vault view:*)",
    "Bash(ansible-vault decrypt:*)",
    "Bash(sops -d:*)",
    "Bash(sops decrypt:*)",
    "Bash(env)",
    "Bash(printenv:*)",
    "Bash(set)",
    "Bash(export)",
    "Bash(export -p)",
    "Bash(declare)",
    "Bash(declare -p:*)",
    "Bash(declare -x)",
    "Bash(secret-tool lookup:*)",
    "Bash(secret-tool search:*)",
    "Bash(keyring get:*)",
    "Bash(security find-generic-password -w:*)",
    "Bash(security find-generic-password -g:*)",
    "Bash(security find-internet-password -w:*)",
    "Bash(security dump-keychain:*)",
    "Bash(security export:*)",
    "Bash(gcloud auth print-access-token:*)",
    "Bash(gcloud auth print-identity-token:*)",
    "Bash(aws configure get aws_secret_access_key:*)",
    "Bash(aws configure get aws_session_token:*)",
    "Bash(aws sts get-session-token:*)",
    "Bash(aws sts assume-role:*)",
    "Bash(aws sso get-role-credentials:*)",
    "Bash(az account get-access-token:*)",
    "Bash(gh auth token:*)",
    "Bash(gh auth status --show-token:*)",
    "Bash(git credential fill:*)",
    "Bash(git credential-manager get:*)",
    "Bash(terraform state pull:*)",
    "Bash(terraform state show:*)",
    "Bash(terraform output -json:*)",
    "Bash(terraform output -raw:*)",
    "Bash(terraform show -json:*)",
    "Bash(helm get values:*)",
    "Bash(helm get manifest:*)",
    "Bash(helm get all:*)",
    "Bash(helm secrets view:*)",
    "Bash(helm secrets dec:*)",
    "Bash(docker compose config:*)",
    "Bash(docker-compose config:*)",
    "Bash(docker inspect:*)",
    "Bash(docker history:*)",
    "Bash(podman inspect:*)",
    "Bash(podman history:*)",
    "Bash(pulumi stack output --show-secrets:*)",
    "Bash(ansible-inventory --list:*)",
    "Bash(ansible-inventory --host:*)",
    "Bash(ansible-inventory --yaml:*)",
    "Bash(ansible-inventory)",
];

/// The `.env` rules, which follow `guard.block_dotenv`.
const DOTENV_DENY_RULES: &[&str] = &[
    "Read(**/.env)",
    "Read(**/.env.local)",
    "Read(**/.env.development)",
    "Read(**/.env.production)",
    "Read(**/.env.staging)",
    "Read(**/.env.test)",
    "Read(**/*.env)",
];

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

// ── the machine host ─────────────────────────────────────────────────────────
//
// One host on the loopback address serves each local server once for the machine,
// and each client holds one URL in the place of a stdio command. The host of the
// kit `@munhq/mcp-kit` reads its servers from `~/.config/mcp-kit/host.json`, and
// this install writes the entry of sealkeep into it.

/// The port of the machine host, and the name of this server in its list.
const HOST_PORT: u16 = 7717;
const SERVER: &str = "sealkeep";

/// The URL that serves this server on the machine host.
fn host_url() -> String {
    format!("http://127.0.0.1:{HOST_PORT}/{SERVER}")
}

/// The file that lists the servers of the machine host.
fn host_config() -> Result<PathBuf> {
    Ok(home()?.join(".config").join("mcp-kit").join("host.json"))
}

/// The unit of the machine host: a service of the user on Linux.
fn host_unit() -> Result<PathBuf> {
    Ok(home()?
        .join(".config")
        .join("systemd")
        .join("user")
        .join("mcp-kit-host.service"))
}

/// Does this machine have the machine host? A client gets the URL only when it does,
/// so no client points at a server that no process serves.
fn host_present() -> bool {
    host_unit().map(|p| p.exists()).unwrap_or(false) || on_path("mcp-kit-host")
}

/// Run a program for its effect only, and report whether it exited with 0.
fn quiet(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Keep the machine file to the user: it lists the commands of the host.
fn restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        if let Some(dir) = path.parent() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Add this binary to the server list of the machine host, so the host starts one
/// `sealkeep mcp` for every client. It also reports whether the file changed.
fn register_with_host(ctx: &Ctx) -> Result<(String, bool)> {
    let path = host_config()?;
    let bin = ctx.bin.clone();
    let changed = edit_json(ctx, &path, |v| {
        let obj = v.as_object_mut().expect("checked");
        obj.entry("port").or_insert_with(|| json!(HOST_PORT));
        obj.entry("host").or_insert_with(|| json!("127.0.0.1"));
        let list = obj
            .entry("servers")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .context("`servers` is not a list")?;
        let entry = json!({"name": SERVER, "command": bin, "args": ["mcp"]});
        match list
            .iter_mut()
            .find(|s| s.get("name").and_then(|n| n.as_str()) == Some(SERVER))
        {
            Some(slot) if *slot == entry => Ok(false),
            Some(slot) => {
                *slot = entry;
                Ok(true)
            }
            None => {
                list.push(entry);
                Ok(true)
            }
        }
    })?;
    if changed && !ctx.dry_run {
        restrict(&path)?;
    }
    Ok(match (ctx.dry_run, changed) {
        (false, true) => (format!("added the server to {}", path.display()), true),
        (true, true) => (format!("would add the server to {}", path.display()), true),
        _ => ("the server is already in the machine host".into(), false),
    })
}

/// Remove this server from the list of the machine host, so the host starts no
/// process for it.
fn unregister_with_host(ctx: &Ctx) -> Result<String> {
    let path = host_config()?;
    let changed = edit_json(ctx, &path, |v| {
        let Some(list) = v.get_mut("servers").and_then(|s| s.as_array_mut()) else {
            return Ok(false);
        };
        let before = list.len();
        list.retain(|s| s.get("name").and_then(|n| n.as_str()) != Some(SERVER));
        Ok(list.len() != before)
    })?;
    if changed && !ctx.dry_run {
        restart_host();
    }
    Ok(match (ctx.dry_run, changed) {
        (false, true) => format!("removed the server from {}", path.display()),
        (true, true) => format!("would remove the server from {}", path.display()),
        _ => "the server is not in the machine host".into(),
    })
}

/// Restart a host that runs, so it reads the server list again.
fn restart_host() {
    if quiet(
        "systemctl",
        &["--user", "is-active", "mcp-kit-host.service"],
    ) {
        let _ = quiet("systemctl", &["--user", "restart", "mcp-kit-host.service"]);
    }
}

/// One line that says the state of the machine host, and of this server in its list.
fn host_line() -> Result<String> {
    if !host_present() {
        return Ok(format!(
            "Machine host: missing, so each client starts its own copy; run `mcp-kit-host install`, then `sealkeep install`, to serve it at {}",
            host_url()
        ));
    }
    let listed = read_json(&host_config()?)
        .map(|v| v.to_string().contains(&format!("\"{SERVER}\"")))
        .unwrap_or(false);
    Ok(if listed {
        format!("Machine host: {SERVER} is listed at {}", host_url())
    } else {
        format!(
            "Machine host: {SERVER} is not listed; run `sealkeep install` to serve it at {}",
            host_url()
        )
    })
}

/// Give the machine host the new list, and say where the clients find the server.
/// A restart is needed only when the list changed, because it ends every session.
fn run_host(ctx: &Ctx, changed: bool) -> Result<String> {
    if host_unit()?.exists() {
        if !ctx.dry_run {
            let _ = quiet("systemctl", &["--user", "daemon-reload"]);
            let _ = quiet(
                "systemctl",
                &["--user", "enable", "--now", "mcp-kit-host.service"],
            );
            if changed {
                restart_host();
            }
        }
        return Ok(format!("the machine host serves it at {}", host_url()));
    }
    if on_path("mcp-kit-host") {
        if changed && !ctx.dry_run {
            let _ = quiet("mcp-kit-host", &["install"]);
        }
        return Ok(format!("the machine host serves it at {}", host_url()));
    }
    Ok(format!(
        "the machine host is not installed, so a client keeps the stdio command; run `mcp-kit-host install`, then `sealkeep install`, to serve it at {}",
        host_url()
    ))
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

/// Claude Code: a PostToolUse group that replaces a stored secret value in a tool result.
fn add_posttool_hook(ctx: &Ctx, path: &Path, matcher: &str) -> Result<String> {
    let cmd = format!("{} --after", guard_command(ctx, "claude"));
    let changed = edit_json(ctx, path, |v| {
        let hooks = v
            .as_object_mut()
            .expect("checked")
            .entry("hooks")
            .or_insert_with(|| json!({}));
        let list = hooks
            .as_object_mut()
            .context("`hooks` is not an object")?
            .entry("PostToolUse")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .context("`hooks.PostToolUse` is not a list")?;
        if list.iter().any(|g| g.to_string().contains(MARK)) {
            return Ok(false);
        }
        list.push(json!({"matcher": matcher, "hooks": [{"type": "command", "command": cmd, "timeout": 10}]}));
        Ok(true)
    })?;
    Ok(if changed {
        let verb = if ctx.dry_run { "would add" } else { "added" };
        format!("{verb} the output guard to {}", path.display())
    } else {
        format!("the output guard is already in {}", path.display())
    })
}

/// Claude Code: `permissions.deny` rules for the credential files and the commands that
/// read another secret store, plus the `.env` rules when `block_dotenv` is on.
fn add_deny_rules(ctx: &Ctx, path: &Path, block_dotenv: bool) -> Result<String> {
    let changed = edit_json(ctx, path, |v| {
        let list = v
            .as_object_mut()
            .expect("checked")
            .entry("permissions")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("`permissions` is not an object")?
            .entry("deny")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .context("`permissions.deny` is not a list")?;
        let mut changed = false;
        let extra: &[&str] = if block_dotenv { DOTENV_DENY_RULES } else { &[] };
        for rule in DENY_RULES.iter().chain(extra.iter()) {
            if !list.iter().any(|r| r.as_str() == Some(rule)) {
                list.push(json!(rule));
                changed = true;
            }
        }
        Ok(changed)
    })?;
    Ok(if changed {
        let verb = if ctx.dry_run { "would add" } else { "added" };
        format!("{verb} the deny rules to {}", path.display())
    } else {
        format!("the deny rules are already in {}", path.display())
    })
}

fn remove_deny_rules(ctx: &Ctx, path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    edit_json(ctx, path, |v| {
        let Some(list) = v
            .pointer_mut("/permissions/deny")
            .and_then(Value::as_array_mut)
        else {
            return Ok(false);
        };
        let before = list.len();
        list.retain(|r| {
            !r.as_str()
                .is_some_and(|r| DENY_RULES.contains(&r) || DOTENV_DENY_RULES.contains(&r))
        });
        Ok(list.len() != before)
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
    let url = if host_present() {
        Some(host_url())
    } else {
        None
    };
    let listed = {
        let mut c = clone_cmd(&base);
        c.args(["mcp", "get", "sealkeep"]);
        c.output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    };
    // An entry of an older install is a stdio command, and it is not this entry.
    let exists = match (&url, &listed) {
        (Some(url), Some(text)) => text.contains(url.as_str()),
        (None, Some(_)) => true,
        _ => false,
    };
    if add && exists {
        return Ok("the MCP server is already registered".into());
    }
    if !add && listed.is_none() {
        return Ok("no MCP server to remove".into());
    }
    if ctx.dry_run {
        return Ok(match (add, &url) {
            (true, Some(url)) => format!("would register the MCP server at {url}"),
            (true, None) => "would register the MCP server".into(),
            (false, _) => "would remove the MCP server".into(),
        });
    }
    let mut c = clone_cmd(&base);
    if add {
        match &url {
            Some(url) => {
                // The name is taken by the stdio entry, so the old one goes first.
                let mut old = clone_cmd(&base);
                old.args(["mcp", "remove", "--scope", "user", "sealkeep"]);
                let _ = old.output();
                c.args([
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "--transport",
                    "http",
                    "sealkeep",
                    url,
                ]);
            }
            None => {
                c.args([
                    "mcp", "add", "--scope", "user", "sealkeep", "--", &ctx.bin, "mcp",
                ]);
            }
        }
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
    Ok(match (add, &url) {
        (true, Some(url)) => format!("registered the MCP server at {url}"),
        (true, None) => "registered the MCP server".into(),
        (false, _) => "removed the MCP server".into(),
    })
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
    let listed = cfg.contains("[mcp_servers.sealkeep]");
    let url = if host_present() {
        Some(host_url())
    } else {
        None
    };
    // An entry of an older install is a stdio command, and it is not this entry.
    let exists = match (&url, add) {
        (_, false) => listed,
        (Some(url), true) => cfg.contains(url.as_str()),
        (None, true) => listed,
    };
    if add && exists {
        return Ok("the MCP server is already registered".into());
    }
    if !add && !exists {
        return Ok("no MCP server to remove".into());
    }
    if ctx.dry_run {
        return Ok(match (add, &url) {
            (true, Some(url)) => format!("would register the MCP server at {url}"),
            (true, None) => "would register the MCP server".into(),
            (false, _) => "would remove the MCP server".into(),
        });
    }
    let mut c = Command::new("codex");
    if add {
        match &url {
            Some(url) => {
                // The name is taken by the stdio entry, so the old one goes first.
                let _ = Command::new("codex")
                    .args(["mcp", "remove", "sealkeep"])
                    .output();
                c.args(["mcp", "add", "sealkeep", "--url", url]);
            }
            None => {
                c.args(["mcp", "add", "sealkeep", "--", &ctx.bin, "mcp"]);
            }
        }
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
    Ok(match (add, &url) {
        (true, Some(url)) => format!("registered the MCP server at {url}"),
        (true, None) => "registered the MCP server".into(),
        (false, _) => "removed the MCP server".into(),
    })
}

fn cursor_mcp(ctx: &Ctx, add: bool) -> Result<String> {
    let path = home()?.join(".cursor").join("mcp.json");
    let bin = ctx.bin.clone();
    let url = if host_present() {
        Some(host_url())
    } else {
        None
    };
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
            let entry = match &url {
                Some(url) => json!({"url": url}),
                None => json!({"command": bin, "args": ["mcp"]}),
            };
            if servers.get("sealkeep") == Some(&entry) {
                return Ok(false);
            }
            servers.insert("sealkeep".into(), entry);
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
    // The machine host starts this server once for every client, and it reads its
    // server list from the machine file.
    if ctx.parts.mcp {
        let outcome = if add {
            register_with_host(ctx)
        } else {
            unregister_with_host(ctx).map(|line| (line, false))
        };
        let changed = matches!(&outcome, Ok((_, true)));
        push("machine host".into(), outcome.map(|(line, _)| line));
        if add {
            push("machine host".into(), run_host(ctx, changed));
        }
    }
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
                        if add {
                            push(
                                label.clone(),
                                add_posttool_hook(ctx, &settings, "Bash|Read|Grep"),
                            );
                            let block_dotenv =
                                Config::load().unwrap_or_default().guard.block_dotenv;
                            push(label.clone(), add_deny_rules(ctx, &settings, block_dotenv));
                        } else {
                            let post = remove_hooks(ctx, &settings, "PostToolUse");
                            let deny = remove_deny_rules(ctx, &settings);
                            push(
                                label.clone(),
                                post.and_then(|p| deny.map(|d| (p, d))).map(|(p, d)| {
                                    if p || d {
                                        format!(
                                            "removed the output guard and the deny rules from {}",
                                            settings.display()
                                        )
                                    } else {
                                        "no output guard or deny rules to remove".into()
                                    }
                                }),
                            );
                        }
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
    lines.push(host_line()?);
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

    #[test]
    fn the_host_url_is_one_loopback_address() {
        assert_eq!(host_url(), "http://127.0.0.1:7717/sealkeep");
    }

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

    #[test]
    fn output_guard_and_deny_rules_are_added_once_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"permissions":{"deny":["Bash(rm -rf *)"]},"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"other"}]}]}}"#,
        )
        .unwrap();
        let c = ctx();
        for _ in 0..2 {
            add_posttool_hook(&c, &path, "Bash|Read|Grep").unwrap();
            add_deny_rules(&c, &path, true).unwrap();
        }
        let v = read_json(&path).unwrap();
        let post = v.pointer("/hooks/PostToolUse").unwrap().as_array().unwrap();
        assert_eq!(post.len(), 2);
        assert_eq!(
            post[1].pointer("/hooks/0/command").unwrap(),
            "/opt/bin/sealkeep guard --client claude --after"
        );
        let deny = v.pointer("/permissions/deny").unwrap().as_array().unwrap();
        assert_eq!(deny.len(), 1 + DENY_RULES.len() + DOTENV_DENY_RULES.len());
        assert_eq!(deny[0], "Bash(rm -rf *)");

        assert!(remove_hooks(&c, &path, "PostToolUse").unwrap());
        assert!(remove_deny_rules(&c, &path).unwrap());
        let v = read_json(&path).unwrap();
        assert_eq!(
            v.pointer("/hooks/PostToolUse")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            v.pointer("/permissions/deny").unwrap(),
            &json!(["Bash(rm -rf *)"])
        );
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

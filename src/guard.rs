//! The pre-tool hook. It refuses a tool call that would put a secret value into the
//! context of the agent:
//!
//! 1. `sealkeep get`, which prints a value.
//! 2. A direct read of the sealkeep keyring entries (`secret-tool lookup service sealkeep`,
//!    `security find-generic-password -s sealkeep -w`, `keyring get sealkeep …`).
//! 3. A read of a `.env` file (`cat .env`, `source .env`, the Read tool on `.env`), when
//!    `guard.block_dotenv` is on. `.env.example`, `.env.sample`, `.env.template` and
//!    `.env.dist` stay readable.
//! 4. An environment dump (`env`, `printenv`, `set`, `/proc/*/environ`, `ps e`) and a
//!    keyring read that is not sealkeep (`secret-tool`, `security -w`, `keyring get`, the
//!    Secret Service over D-Bus).
//! 5. A read of a Kubernetes Secret (`kubectl get secret`, `kubectl edit secret`,
//!    `kubectl view-secret`, `kubectl config view --raw`, `kubectl create token`,
//!    `kubectl get --raw …/secrets/…`).
//! 6. A printed token (`gcloud auth print-access-token`, `aws sts get-session-token`,
//!    `gh auth token`, `git credential fill` and the like).
//! 7. A tool that resolves a secret and prints it (`terraform state pull`,
//!    `helm get values`, `docker compose config`, `ansible-inventory --list`).
//! 8. A read of Vault or another secret store (`vault kv get`, `vault read`,
//!    `ansible-vault view`, `sops -d`, `aws secretsmanager get-secret-value` and the
//!    CLIs of the other stores that sealkeep supports).
//! 9. A credential file: a kubeconfig, `~/.aws`, the cloud token files, the browser
//!    password stores, the shell history, an SSH private key, a Terraform state file and
//!    the like.
//! 10. The command after `--` in `sealkeep run` and `kubectl exec`.
//! 11. Each command prefix in `guard.deny` of the config.
//!
//! Input: the JSON of the hook on stdin. Claude Code and Codex send
//! `{"tool_name", "tool_input": {"command" | "file_path" | "path"}}`; Cursor sends
//! `{"command"}`. Output: Claude Code and Codex get exit code 2 and the reason on stderr;
//! Cursor gets `{"permission": "deny", …}` on stdout.

use crate::config::Config;
use crate::redact::Redactor;
use crate::store;
use serde_json::Value;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Client {
    Claude,
    Codex,
    Cursor,
}

const ADVICE: &str = "Use `sealkeep run NAME -- <command>` to give the command the secret without the value. Run `sealkeep list` to see the names.";

/// The advice for a read that goes around sealkeep to another secret store. The person
/// puts the value in sealkeep one time; the agent then uses the name.
const STORE_ADVICE: &str = "If the value exists only in Kubernetes, Vault or another secret store, ask the person to put it in sealkeep first (`sealkeep set personal/<project>/prod/KEY`), then run the command with `sealkeep run NAME -- <command>`. Do not read the store directly.";

const CREDENTIAL_ADVICE: &str = "If the command needs a value from this file, put it in sealkeep (`sealkeep set personal/<project>/prod/KEY`) and use `sealkeep run NAME -- <command>`.";

/// Programs that print or load the file they are given.
const FILE_READERS: &[&str] = &[
    "cat", "tac", "less", "more", "head", "tail", "bat", "batcat", "grep", "egrep", "fgrep", "rg",
    "ag", "sed", "awk", "gawk", "cut", "sort", "uniq", "strings", "xxd", "od", "hexdump", "base64",
    "nl", "source", ".", "cp", "jq", "yq", "diff", "column", "tee", "dotenv", "envsubst", "vim",
    "vi", "nano", "view", "code", "python", "python3", "node", "ruby", "perl", "dd", "sqlite3",
];

const SAFE_DOTENV_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".tmpl"];

/// Check one hook input. `Some(reason)` refuses the call.
pub fn check(input: &Value, cfg: &Config) -> Option<String> {
    let tool_input = input.get("tool_input").unwrap_or(input);
    if let Some(cmd) = command_of(tool_input) {
        return check_command(&cmd, cfg);
    }
    for key in ["file_path", "path", "notebook_path"] {
        if let Some(p) = tool_input.get(key).and_then(Value::as_str)
            && let Some(kind) = path_kind(p, cfg)
        {
            return Some(format!(
                "sealkeep guard: `{p}` is {}. {}",
                kind.what(),
                kind.advice()
            ));
        }
    }
    None
}

/// How long the post-tool hook may spend to read the secret values of the stores.
const LOAD_BUDGET: Duration = Duration::from_secs(4);

/// The text of a tool result: each string in `tool_response`, joined by line breaks.
fn response_text(response: &Value) -> String {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut parts = Vec::new();
    walk(response, &mut parts);
    parts.join("\n")
}

/// The same JSON with each string redacted, so the shape of the result stays the one the
/// tool made.
fn redact_json(v: &Value, redactor: &Redactor) -> Value {
    match v {
        Value::String(s) => Value::String(redactor.redact_str(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| redact_json(x, redactor)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), redact_json(x, redactor)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The `(name, value)` of each secret in the stores of the config. Each store loads in its
/// own thread. A store that does not answer within `LOAD_BUDGET` adds nothing, so the hook
/// ends before its time limit.
pub fn load_values(cfg: &Config) -> Vec<(String, String)> {
    let (tx, rx) = mpsc::channel();
    for sc in &cfg.stores {
        let sc = sc.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let s = store::open(&sc);
            let Ok(list) = s.list() else { return };
            for info in list {
                if let Ok(Some(value)) = s.get(&info.name) {
                    let _ = tx.send((info.name, value));
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + LOAD_BUDGET;
    let mut out = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(pair) => out.push(pair),
            Err(_) => break,
        }
    }
    out
}

/// Check the result of a finished tool call. When it holds the value of a stored secret,
/// the answer is the PostToolUse output of Claude Code: the result with each value
/// replaced by `[sealkeep:NAME]`, and a note that names the secrets. It never holds a
/// value.
pub fn check_output(input: &Value, redactor: &Redactor) -> Option<Value> {
    let response = input.get("tool_response")?;
    let names = redactor.names_in(response_text(response).as_bytes());
    if names.is_empty() {
        return None;
    }
    let shown = names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": redact_json(response, redactor),
            "additionalContext": format!(
                "sealkeep guard: the output of this tool call held the value of {shown}, and sealkeep replaced it. Do not ask for the value again. {ADVICE}"
            ),
        }
    }))
}

fn command_of(v: &Value) -> Option<String> {
    match v.get("command")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => {
            let argv: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            Some(argv.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" "))
        }
        _ => None,
    }
}

/// Quote one word for a shell line, so `segments` and `words` give it back unchanged.
fn quote(w: &str) -> String {
    if !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c))
    {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish"];

/// The command after a `--`, as one shell line. `sealkeep run` and `kubectl exec` both
/// put the real command there.
fn after_dashdash(args: &[&str]) -> Option<String> {
    let i = args.iter().position(|a| *a == "--")?;
    Some(
        args[i + 1..]
            .iter()
            .map(|a| quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Remove the body of each quoted heredoc (`<<'EOF'` or `<<"EOF"`). The shell does not
/// expand or run that text, so a word such as `cat .env` in it is data. The body of an
/// unquoted heredoc stays, because the shell expands `$(…)` and backticks in it.
fn strip_quoted_heredocs(cmd: &str) -> String {
    let mut out = Vec::new();
    let mut lines = cmd.lines();
    while let Some(line) = lines.next() {
        out.push(line);
        let Some(pos) = line.find("<<") else { continue };
        let rest = line[pos + 2..].trim_start_matches('-').trim_start();
        let delim = if let Some(r) = rest.strip_prefix('\'') {
            r.split('\'').next()
        } else if let Some(r) = rest.strip_prefix('"') {
            r.split('"').next()
        } else {
            None
        };
        let Some(delim) = delim.filter(|d| !d.is_empty()) else {
            continue;
        };
        for body in lines.by_ref() {
            if body.trim() == delim {
                out.push(body);
                break;
            }
        }
    }
    out.join("\n")
}

pub fn check_command(cmd: &str, cfg: &Config) -> Option<String> {
    let stripped = strip_quoted_heredocs(cmd);
    let cmd = stripped.as_str();
    // A shell runs `$(…)` and `` `…` `` also inside double quotes.
    for sub in substitutions(cmd) {
        if let Some(r) = check_command(&sub, cfg) {
            return Some(r);
        }
    }
    for seg in segments(cmd) {
        let words = words(&seg);
        // `env` is also a wrapper, so check the bare form before it is stripped.
        if words.first().is_some_and(|w| basename(w) == "env") {
            let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();
            let split = args
                .iter()
                .position(|a| *a == "-S" || *a == "--split-string")
                .and_then(|i| args.get(i + 1).copied())
                .or_else(|| args.iter().find_map(|a| a.strip_prefix("--split-string=")));
            if let Some(script) = split
                && let Some(r) = check_command(script, cfg)
            {
                return Some(r);
            }
            if let Some(what) = env_dump(&args) {
                return Some(format!(
                    "sealkeep guard: {what} would put a secret value into the context. {ADVICE}"
                ));
            }
        }
        let words = strip_prefixes(&words);
        if words.is_empty() {
            continue;
        }
        let prog = basename(&words[0]);
        let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();

        // `bash -c "<script>"`: check the script.
        if SHELLS.contains(&prog.as_str())
            && let Some(i) = args
                .iter()
                .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
            && let Some(script) = args.get(i + 1)
            && let Some(r) = check_command(script, cfg)
        {
            return Some(r);
        }

        if seg.contains("SEALKEEP_ASKPASS_TOKEN") {
            return Some(format!(
                "sealkeep guard: SEALKEEP_ASKPASS_TOKEN is for ssh-add only. {ADVICE}"
            ));
        }
        // `kubectl get secret`, `vault kv get` and the CLIs of the other stores print a
        // value without sealkeep. Check these before the generic rules, so the agent gets
        // the advice that names the store.
        if let Some(what) = secret_store_read(&prog, &args) {
            return Some(format!(
                "sealkeep guard: {what} would put a secret value into the context. {STORE_ADVICE}"
            ));
        }
        // `sealkeep run NAME -- <command>` is the safe way to give a command a value.
        // `kubectl exec POD -- <command>` runs in the pod. The command after `--` still
        // must not read another store or a credential file.
        if (prog == "sealkeep" && args.first() == Some(&"run")
            || matches!(prog.as_str(), "kubectl" | "oc"))
            && let Some(inner) = after_dashdash(&args)
            && let Some(r) = check_command(&inner, cfg)
        {
            return Some(r);
        }
        if prog == "sealkeep" && args.first() == Some(&"get") {
            return Some(format!(
                "sealkeep guard: `sealkeep get` prints a secret value. {ADVICE}"
            ));
        }
        if FILE_READERS.contains(&prog.as_str())
            && let Some((p, kind)) = args.iter().find_map(|a| path_kind(a, cfg).map(|k| (*a, k)))
        {
            return Some(format!(
                "sealkeep guard: `{p}` is {}. {}",
                kind.what(),
                kind.advice()
            ));
        }
        let redirect = args.iter().enumerate().find_map(|(i, a)| {
            let p = if *a == "<" {
                args.get(i + 1).copied()
            } else {
                a.strip_prefix('<')
            }?;
            path_kind(p, cfg).map(|k| (p, k))
        });
        if let Some((p, kind)) = redirect {
            return Some(format!(
                "sealkeep guard: this reads `{p}`, which is {}. {}",
                kind.what(),
                kind.advice()
            ));
        }
        let line = words.join(" ");
        for d in &cfg.guard.deny {
            let d = d.trim();
            if !d.is_empty() && (line == d || line.starts_with(&format!("{d} "))) {
                return Some(format!(
                    "sealkeep guard: `{d}` is in guard.deny of the sealkeep config. {ADVICE}"
                ));
            }
        }
    }
    None
}

/// `.env`, `.env.local`, `prod.env`, but not `.env.example`.
pub fn is_dotenv_path(p: &str) -> bool {
    let p = p.trim_matches(|c| c == '"' || c == '\'');
    let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
    let is_env = name == ".env" || name.starts_with(".env.") || name.ends_with(".env");
    is_env && !SAFE_DOTENV_SUFFIXES.iter().any(|s| name.ends_with(s))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Dotenv,
    Credential,
}

impl PathKind {
    fn what(self) -> &'static str {
        match self {
            PathKind::Dotenv => "a .env file, and its values would go into the context",
            PathKind::Credential => {
                "a file or folder that holds a credential, and its values would go into the context"
            }
        }
    }

    fn advice(self) -> &'static str {
        match self {
            PathKind::Dotenv => ADVICE,
            PathKind::Credential => CREDENTIAL_ADVICE,
        }
    }
}

fn path_kind(p: &str, cfg: &Config) -> Option<PathKind> {
    if cfg.guard.block_dotenv && is_dotenv_path(p) {
        return Some(PathKind::Dotenv);
    }
    credential_path(p).then_some(PathKind::Credential)
}

/// A file that holds a credential, or a folder that a recursive read would walk. These
/// are the common places that an agent can reach with its user account and that
/// sealkeep is meant to replace. The patterns match a full path or its tail, so `~`,
/// `/home/<user>` and a relative path all work.
fn credential_path(p: &str) -> bool {
    let p = p
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches('<');
    let norm = p.replace('\\', "/");
    let s = format!("/{}", norm.trim_matches('/'));
    let name = s.rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        return false;
    }
    const EXACT: &[&str] = &[
        "/.netrc",
        "/_netrc",
        "/.npmrc",
        "/.yarnrc.yml",
        "/.pypirc",
        "/.condarc",
        "/.git-credentials",
        "/.vault-token",
        "/.envrc",
        "/.pgpass",
        "/.my.cnf",
        "/.mongorc.js",
        "/.kube/config",
        "/.aws/credentials",
        "/.config/gcloud/application_default_credentials.json",
        "/.config/gcloud/credentials.db",
        "/.config/gcloud/access_tokens.db",
        "/.azure/accessTokens.json",
        "/.azure/msal_token_cache.json",
        "/.docker/config.json",
        "/.config/containers/auth.json",
        "/.config/gh/hosts.yml",
        "/.config/git/credentials",
        "/.config/sops/age/keys.txt",
        "/.config/age/keys.txt",
        "/.config/helm/repositories.yaml",
        "/.config/terraform/credentials.tfrc.json",
        "/.terraform.d/credentials.tfrc.json",
        "/.config/pulumi/credentials.json",
        "/.config/rclone/rclone.conf",
        "/.config/argocd/config",
        "/.config/glab-cli/config.yml",
        "/.m2/settings.xml",
        "/.gradle/gradle.properties",
        "/.nuget/NuGet/NuGet.Config",
        "/.gem/credentials",
        "/.cargo/credentials",
        "/.cargo/credentials.toml",
        "/.bash_history",
        "/.zsh_history",
        "/.local/share/fish/fish_history",
        "/.python_history",
        "/.node_repl_history",
        "/.psql_history",
        "/.mysql_history",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/controller-manager.conf",
        "/etc/kubernetes/scheduler.conf",
        "/etc/kubernetes/kubelet.conf",
        "/etc/rancher/k3s/k3s.yaml",
        "/var/lib/kubelet/kubeconfig",
        "/var/lib/kubelet/config.yaml",
    ];
    if EXACT.iter().any(|x| s.ends_with(x)) {
        return true;
    }
    // KeePass databases and private key rings.
    if name.ends_with(".kdbx") {
        return true;
    }
    if s.contains("/.password-store/") || s == "/.password-store" {
        return true;
    }
    if s.contains("/.gnupg/") || s == "/.gnupg" {
        return true;
    }
    // The credential stores of the browsers. The parent folder keeps a project file
    // named `Cookies` from matching.
    const BROWSER_DIRS: &[&str] = &[
        "/google-chrome/",
        "/chromium/",
        "/Brave-Browser/",
        "/microsoft-edge/",
        "/firefox/",
        "/Safari/",
        "/Application Support/Google/Chrome/",
        "/Application Support/Firefox/",
    ];
    const BROWSER_FILES: &[&str] = &[
        "Login Data",
        "Cookies",
        "Local State",
        "logins.json",
        "key4.db",
        "key3.db",
        "cookies.sqlite",
        "signons.sqlite",
    ];
    if BROWSER_DIRS.iter().any(|d| s.contains(d)) && BROWSER_FILES.contains(&name) {
        return true;
    }
    const BROWSER_ROOTS: &[&str] = &[
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/.config/BraveSoftware/",
        "/.config/microsoft-edge/",
        "/.mozilla/firefox/",
        "/Library/Safari/",
        "/Application Support/Google/Chrome/",
        "/Application Support/Firefox/",
    ];
    if BROWSER_ROOTS.iter().any(|d| s.contains(d)) {
        return true;
    }
    // A kubeconfig can have any name in $KUBECONFIG; these are the usual names.
    if name == "kubeconfig" || name.ends_with(".kubeconfig") {
        return true;
    }
    // A kubeconfig with a name of its own (`~/.kube/ovh-gra1.yaml`), and the other files
    // in the folder. `ls` is still allowed; a read of the content is not.
    if s.contains("/.kube/") {
        return true;
    }
    // Terraform state holds variable values, including tokens.
    if name.ends_with(".tfstate") || name.ends_with(".tfstate.backup") {
        return true;
    }
    // A private SSH key, whatever its name. The public files stay readable.
    if s.contains("/.ssh/") {
        let public = name.ends_with(".pub")
            || matches!(
                name,
                "known_hosts" | "known_hosts.old" | "config" | "authorized_keys"
            );
        if !public {
            return true;
        }
    }
    // `~/.aws/config` can hold keys too, and the SSO and CLI caches hold tokens.
    if s.contains("/.aws/") {
        return true;
    }
    // The token caches of the cloud CLIs.
    if s.contains("/.config/gcloud/") || s.contains("/.azure/") {
        return true;
    }
    // The token that Kubernetes mounts into a pod, and the environment of a process.
    if s.contains("/var/run/secrets/") || s.contains("/run/secrets/") || s == "/var/run/secrets" {
        return true;
    }
    if s.contains("/proc/") && matches!(name, "environ" | "cmdline") {
        return true;
    }
    // A directory that a recursive `grep`, `rg` or Read would walk.
    const DIRS: &[&str] = &[
        "/.kube",
        "/.aws",
        "/.config/gcloud",
        "/.azure",
        "/.docker",
        "/.ssh",
        "/.config/gh",
        "/.config/git",
        "/.config/sops",
        "/.config/age",
        "/.config/helm",
        "/.config/terraform",
        "/.terraform.d",
        "/.config/pulumi",
        "/.config/rclone",
        "/.config/argocd",
        "/.config/glab-cli",
        "/.m2",
        "/.gradle",
        "/.nuget",
        "/.gem",
        "/.password-store",
        "/.gnupg",
        "/.config/google-chrome",
        "/.config/chromium",
        "/.config/BraveSoftware",
        "/.config/microsoft-edge",
        "/.mozilla/firefox",
        "/Library/Safari",
        "/etc/kubernetes",
        "/etc/rancher/k3s",
        "/var/lib/kubelet",
    ];
    DIRS.iter().any(|d| s == *d || s.ends_with(d))
}

/// The command is one that prints a value from a secret store without sealkeep. The
/// rules are narrow on purpose: `kubectl get pods`, `vault kv list` and `vault kv put`
/// stay allowed.
fn secret_store_read(prog: &str, args: &[&str]) -> Option<&'static str> {
    match prog {
        "kubectl" | "oc" => kubectl_secret_read(args),
        "k3s" | "microk8s" if args.first() == Some(&"kubectl") => kubectl_secret_read(&args[1..]),
        "vault" | "bao" => vault_secret_read(args),
        "env" => env_dump(args),
        "printenv" => Some("`printenv`"),
        "set" if args.is_empty() => Some("`set` with no arguments"),
        "export" if args.is_empty() || has(args, "-p") => Some("`export -p`"),
        "declare" | "typeset" if declare_dump(args) => Some("`declare -p`"),
        "ps" => ps_env(args),
        "secret-tool" if matches!(args.first(), Some(&"lookup") | Some(&"search")) => {
            Some("`secret-tool lookup`")
        }
        "security" => security_read(args),
        "keyring" if args.first() == Some(&"get") => Some("`keyring get`"),
        "gdbus" | "busctl" | "dbus-send"
            if args.iter().any(|a| a.contains("org.freedesktop.secrets")) =>
        {
            Some("a D-Bus call to the OS keyring")
        }
        "ansible-vault" if has_any(args, &["view", "decrypt"]) => {
            Some("`ansible-vault view` or `ansible-vault decrypt`")
        }
        "sops"
            if has_any(
                args,
                &["-d", "--decrypt", "decrypt", "exec-env", "exec-file"],
            ) =>
        {
            Some("`sops` with decryption")
        }
        "aws" => aws_secret_read(args),
        "gcloud" if has(args, "secrets") && has(args, "versions") && has(args, "access") => {
            Some("`gcloud secrets versions access`")
        }
        "gcloud"
            if has(args, "auth")
                && has_any(args, &["print-access-token", "print-identity-token"]) =>
        {
            Some("`gcloud auth print-access-token`")
        }
        "az" if has(args, "keyvault")
            && has(args, "secret")
            && has_any(args, &["show", "download"]) =>
        {
            Some("`az keyvault secret show`")
        }
        "az" if has(args, "account") && has(args, "get-access-token") => {
            Some("`az account get-access-token`")
        }
        "gh" if has(args, "auth")
            && (has(args, "token")
                || args
                    .iter()
                    .any(|a| *a == "--show-token" || a.starts_with("--show-token="))) =>
        {
            Some("`gh auth token`")
        }
        "git"
            if args.first() == Some(&"credential")
                && matches!(args.get(1), Some(&"fill") | Some(&"get")) =>
        {
            Some("`git credential fill`")
        }
        "git"
            if matches!(
                args.first(),
                Some(&"credential-manager") | Some(&"credential-manager-core")
            ) && args.get(1) == Some(&"get") =>
        {
            Some("`git credential-manager get`")
        }
        "npm" | "yarn" | "pnpm"
            if has(args, "config")
                && has(args, "get")
                && args.iter().any(|a| {
                    a.contains("_authToken")
                        || a.contains("_auth")
                        || a.eq_ignore_ascii_case("npmAuthToken")
                        || a.eq_ignore_ascii_case("npmAuthIdent")
                }) =>
        {
            Some("a package-manager token read")
        }
        "terraform" | "tofu" => terraform_secret_read(args),
        "helm" => helm_secret_read(args),
        "docker" | "docker-compose" | "podman" => container_secret_read(prog, args),
        "pulumi" if has(args, "stack") && has(args, "output") && has(args, "--show-secrets") => {
            Some("`pulumi stack output --show-secrets`")
        }
        "ansible-inventory"
            if args.is_empty()
                || has(args, "--list")
                || has(args, "--host")
                || has(args, "--yaml") =>
        {
            Some("`ansible-inventory --list`")
        }
        "op" if has(args, "read") && !has(args, "item") => Some("`op read`"),
        "op" if has(args, "item")
            && has(args, "get")
            && args
                .iter()
                .any(|a| *a == "--reveal" || a.starts_with("--reveal=")) =>
        {
            Some("`op item get --reveal`")
        }
        "bw" => {
            let i = args.iter().position(|a| *a == "get")?;
            let what = args[i + 1..].iter().find(|a| !a.starts_with('-'))?;
            matches!(*what, "password" | "item" | "notes" | "totp").then_some("`bw get`")
        }
        "bws" if has(args, "secret") && has_any(args, &["get", "list"]) => {
            Some("`bws secret get` or `bws secret list`")
        }
        "pass" | "gopass" | "lpass" if has(args, "show") => Some("a password-manager read"),
        "rbw" if has(args, "get") => Some("`rbw get`"),
        "keepassxc-cli" if has(args, "show") => Some("`keepassxc-cli show`"),
        _ => None,
    }
}

fn kubectl_secret_read(args: &[&str]) -> Option<&'static str> {
    if args.first() == Some(&"view-secret") {
        return Some("`kubectl view-secret`");
    }
    if args.windows(2).any(|w| w[0] == "create" && w[1] == "token") {
        return Some("`kubectl create token` (the token can read Secrets)");
    }
    if args.first() == Some(&"config")
        && args.get(1) == Some(&"view")
        && args.iter().any(|a| {
            matches!(*a, "--raw" | "--flatten")
                || a.starts_with("--raw=")
                || a.starts_with("--flatten=")
        })
    {
        return Some("`kubectl config view --raw` (the kubeconfig holds certificates and tokens)");
    }
    // A path under the pod's service-account mount holds a token, whichever verb is
    // used (`exec`, `cp`, `debug`).
    if args
        .iter()
        .any(|a| a.contains("/var/run/secrets") || a.contains("/run/secrets/"))
    {
        return Some("a read of a pod's service-account token");
    }
    if has(args, "exec")
        && let Some(i) = args.iter().position(|a| *a == "--")
        && let Some(first) = args[i + 1..].iter().find(|a| !a.starts_with('-'))
        && matches!(*first, "env" | "printenv")
    {
        return Some("`kubectl exec … -- env`");
    }
    let i = args.iter().position(|a| matches!(*a, "get" | "edit"))?;
    let rest = &args[i + 1..];
    let raw = rest.iter().any(|a| {
        a.strip_prefix("--raw=")
            .is_some_and(|p| p.contains("/secrets"))
    }) || rest
        .windows(2)
        .any(|w| w[0] == "--raw" && w[1].contains("/secrets"));
    if raw || rest.iter().any(|a| is_secret_resource(a)) {
        Some(if args[i] == "edit" {
            "`kubectl edit secret`"
        } else {
            "`kubectl get secret`"
        })
    } else {
        None
    }
}

/// `secret`, `secrets`, `sec`, `secrets/name`, `pods,secrets` and `secrets.v1.core`.
fn is_secret_resource(a: &str) -> bool {
    let a = a.trim_matches(|c| c == '"' || c == '\'');
    if a.starts_with('-') {
        return false;
    }
    a.split(',').any(|part| {
        let first = part.split(['/', '.']).next().unwrap_or(part);
        matches!(
            first.to_ascii_lowercase().as_str(),
            "secret" | "secrets" | "sec"
        )
    })
}

fn vault_secret_read(args: &[&str]) -> Option<&'static str> {
    let tokens: Vec<&str> = args.iter().copied().take_while(|a| *a != "--").collect();
    if tokens
        .windows(2)
        .any(|w| w[0] == "kv" && matches!(w[1], "get" | "export"))
    {
        return Some("`vault kv get`");
    }
    // `vault read` is the command, not the word in `vault policy read`.
    if let Some(i) = tokens.iter().position(|a| *a == "read")
        && (i == 0 || tokens[i - 1].starts_with('-'))
    {
        return Some("`vault read`");
    }
    None
}

fn aws_secret_read(args: &[&str]) -> Option<&'static str> {
    if has(args, "secretsmanager") && has_any(args, &["get-secret-value", "batch-get-secret-value"])
    {
        return Some("`aws secretsmanager get-secret-value`");
    }
    if has(args, "ssm")
        && has_any(args, &["get-parameter", "get-parameters"])
        && args
            .iter()
            .any(|a| *a == "--with-decryption" || a.starts_with("--with-decryption="))
    {
        return Some("`aws ssm get-parameter --with-decryption`");
    }
    if has(args, "configure")
        && has(args, "get")
        && has_any(args, &["aws_secret_access_key", "aws_session_token"])
    {
        return Some("`aws configure get` with the secret key");
    }
    if has(args, "sts")
        && has_any(
            args,
            &[
                "get-session-token",
                "get-federation-token",
                "assume-role",
                "assume-role-with-saml",
                "assume-role-with-web-identity",
            ],
        )
    {
        return Some("`aws sts` with the temporary credentials");
    }
    if has(args, "sso") && has(args, "get-role-credentials") {
        return Some("`aws sso get-role-credentials`");
    }
    None
}

/// `env` prints the environment when no command follows. Flags and `VAR=value`
/// assignments are not a command.
fn env_dump(args: &[&str]) -> Option<&'static str> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a.starts_with('-') {
            i += if matches!(a, "-u" | "--unset" | "-C" | "--chdir") {
                2
            } else {
                1
            };
        } else if is_assignment(a) {
            i += 1;
        } else {
            return None;
        }
    }
    Some("`env` with no command prints the environment")
}

fn is_assignment(w: &str) -> bool {
    w.contains('=')
        && w.split('=').next().is_some_and(|k| {
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

fn declare_dump(args: &[&str]) -> bool {
    args.is_empty()
        || args.iter().any(|a| a.starts_with("-p") || *a == "--print")
        || (args.len() == 1 && args[0] == "-x")
}

fn ps_env(args: &[&str]) -> Option<&'static str> {
    let dump = args.iter().any(|a| {
        matches!(*a, "e" | "ew" | "eww" | "auxe" | "axue")
            || *a == "-E"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains("aux") && a.ends_with('e'))
    });
    dump.then_some("`ps` with the environment")
}

fn security_read(args: &[&str]) -> Option<&'static str> {
    if matches!(
        args.first(),
        Some(&"find-generic-password") | Some(&"find-internet-password")
    ) && args.iter().any(|a| *a == "-w" || *a == "-g")
    {
        return Some("`security find-*-password -w`");
    }
    if matches!(args.first(), Some(&"dump-keychain") | Some(&"export")) {
        return Some("`security dump-keychain`");
    }
    None
}

fn terraform_secret_read(args: &[&str]) -> Option<&'static str> {
    if has(args, "state") && has_any(args, &["pull", "show"]) {
        return Some("`terraform state pull` or `terraform state show`");
    }
    if has(args, "output") && has_any(args, &["-json", "--json", "-raw", "--raw"]) {
        return Some("`terraform output -json`");
    }
    if has(args, "show") && has_any(args, &["-json", "--json"]) {
        return Some("`terraform show -json`");
    }
    None
}

fn helm_secret_read(args: &[&str]) -> Option<&'static str> {
    if has(args, "get") && has_any(args, &["values", "manifest", "all"]) {
        return Some("`helm get values` or `helm get manifest`");
    }
    if has(args, "secrets") && has_any(args, &["view", "dec", "decrypt"]) {
        return Some("`helm secrets view` or `helm secrets dec`");
    }
    None
}

fn container_secret_read(prog: &str, args: &[&str]) -> Option<&'static str> {
    if prog == "docker-compose" && has(args, "config") {
        return Some("`docker-compose config` (it resolves and prints the environment)");
    }
    if has(args, "compose") && has(args, "config") {
        return Some("`docker compose config` (it resolves and prints the environment)");
    }
    if has(args, "inspect") {
        return Some("`docker inspect` (it prints the container environment)");
    }
    if has(args, "history") {
        return Some("`docker history` (build arguments and commands can hold secrets)");
    }
    if has(args, "exec")
        && let Some(i) = args.iter().position(|a| *a == "--")
        && let Some(first) = args[i + 1..].iter().find(|a| !a.starts_with('-'))
        && matches!(*first, "env" | "printenv")
    {
        return Some("`docker exec … -- env`");
    }
    None
}

fn has(args: &[&str], needle: &str) -> bool {
    args.contains(&needle)
}

fn has_any(args: &[&str], needles: &[&str]) -> bool {
    args.iter().any(|a| needles.contains(a))
}

/// Run the same checks on a command that is about to be executed without a shell, as
/// the MCP server does. Returns the refusal that `check` would give the hook.
pub fn check_argv(argv: &[String], cfg: &Config) -> Option<String> {
    let cmd = argv.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ");
    check_command(&cmd, cfg)
}

/// Commands that the built-in rules must refuse, and ordinary commands that must stay
/// allowed. `sealkeep doctor` and `sealkeep guard --check` run this, so a binary that
/// lost a rule (or a future edit that breaks one) fails loudly.
pub fn self_test(cfg: &Config) -> Vec<(String, bool)> {
    let deny = [
        (
            "refuse `kubectl get secret`",
            "kubectl -n cert-manager get secret cloudflare-api-token -o jsonpath='{.data.api-token}'",
        ),
        (
            "refuse `kubectl get` with the flags before the resource",
            "kubectl -n cert-manager get -o yaml secret cloudflare-api-token",
        ),
        (
            "refuse `kubectl get --raw` of a Secret",
            "kubectl get --raw /api/v1/namespaces/cert-manager/secrets/cloudflare-api-token",
        ),
        (
            "refuse `kubectl edit secret`",
            "kubectl edit secret cloudflare-api-token",
        ),
        (
            "refuse `kubectl config view --raw`",
            "kubectl config view --raw",
        ),
        (
            "refuse `kubectl create token`",
            "kubectl -n vault create token sealkeep --duration 10m",
        ),
        ("refuse `vault kv get`", "vault kv get secret/cloudflare"),
        ("refuse `vault read`", "vault read secret/cloudflare"),
        (
            "refuse `ansible-vault view`",
            "ansible-vault view group_vars/all/vault.yml",
        ),
        ("refuse `sops -d`", "sops -d secrets.yaml"),
        (
            "refuse `aws secretsmanager get-secret-value`",
            "aws secretsmanager get-secret-value --secret-id x",
        ),
        (
            "refuse `gcloud secrets versions access`",
            "gcloud secrets versions access latest --secret x",
        ),
        (
            "refuse `az keyvault secret show`",
            "az keyvault secret show --vault-name x --name y",
        ),
        ("refuse `op read`", "op read op://vault/item/password"),
        ("refuse `bw get password`", "bw get password item"),
        ("refuse a kubeconfig read", "cat ~/.kube/config"),
        (
            "refuse `sealkeep run -- kubectl get secret`",
            "sealkeep run -- kubectl get secret x",
        ),
        ("refuse bare `env`", "env"),
        ("refuse `env VAR=1`", "env FOO=bar"),
        ("refuse `printenv`", "printenv"),
        ("refuse `set`", "set"),
        ("refuse `export -p`", "export -p"),
        ("refuse `declare -p`", "declare -p API_KEY"),
        ("refuse `/proc/self/environ`", "cat /proc/self/environ"),
        ("refuse `ps e`", "ps e"),
        ("refuse `ps auxe`", "ps auxe"),
        (
            "refuse `secret-tool` for another service",
            "secret-tool lookup service cloudflare username adi",
        ),
        (
            "refuse `security find-generic-password -w` for another service",
            "security find-generic-password -s cloudflare -a adi -w",
        ),
        (
            "refuse `security dump-keychain`",
            "security dump-keychain -d",
        ),
        (
            "refuse a D-Bus call to the keyring",
            "gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets",
        ),
        (
            "refuse `gcloud auth print-access-token`",
            "gcloud auth print-access-token",
        ),
        (
            "refuse `aws configure get` of the secret key",
            "aws configure get aws_secret_access_key",
        ),
        (
            "refuse `aws sts get-session-token`",
            "aws sts get-session-token",
        ),
        (
            "refuse `az account get-access-token`",
            "az account get-access-token",
        ),
        ("refuse `gh auth token`", "gh auth token"),
        ("refuse `git credential fill`", "git credential fill"),
        ("refuse `terraform state pull`", "terraform state pull"),
        ("refuse `terraform output -json`", "terraform output -json"),
        (
            "refuse `helm get values`",
            "helm get values release -n prod",
        ),
        ("refuse `docker compose config`", "docker compose config"),
        ("refuse `docker inspect`", "docker inspect app"),
        (
            "refuse `pulumi stack output --show-secrets`",
            "pulumi stack output --show-secrets",
        ),
        (
            "refuse `ansible-inventory --list`",
            "ansible-inventory --list",
        ),
        ("refuse `~/.envrc`", "cat ~/.envrc"),
        ("refuse `~/.pgpass`", "cat ~/.pgpass"),
        (
            "refuse a browser password store",
            "cat ~/.config/google-chrome/Default/Login\\ Data",
        ),
        ("refuse shell history", "cat ~/.bash_history"),
    ];
    let allow = [
        ("allow `kubectl get pods`", "kubectl get pods"),
        ("allow `vault kv list`", "vault kv list secret/"),
        (
            "allow `sealkeep run` with a command",
            "sealkeep run API_KEY -- curl -sS https://example.com",
        ),
        ("allow an ordinary file", "cat README.md"),
        ("allow `env FOO=bar cmd`", "env FOO=bar kubectl get pods"),
        ("allow `set -e`", "set -e; true"),
        ("allow `export FOO=bar`", "export FOO=bar"),
        ("allow `ps -ef`", "ps -ef"),
        ("allow `ps aux`", "ps aux"),
        (
            "allow `aws sts get-caller-identity`",
            "aws sts get-caller-identity",
        ),
        ("allow `gcloud auth list`", "gcloud auth list"),
        ("allow `helm list`", "helm list"),
        ("allow `docker ps`", "docker ps"),
        ("allow `terraform output`", "terraform output"),
        (
            "allow `ansible-inventory --graph`",
            "ansible-inventory --graph",
        ),
    ];
    let mut out = Vec::new();
    for (what, cmd) in deny {
        out.push((format!("{what}: {cmd}"), check_command(cmd, cfg).is_some()));
    }
    if cfg.guard.block_dotenv {
        out.push((
            "refuse a .env read: cat .env".to_string(),
            check_command("cat .env", cfg).is_some(),
        ));
    }
    for (what, cmd) in allow {
        out.push((format!("{what}: {cmd}"), check_command(cmd, cfg).is_none()));
    }
    out
}

/// Split a shell command into simple commands at `;`, `&&`, `||`, `|`, `&`, line breaks,
/// `$(`, `(`, `)` and backticks. Text in quotes is kept as one piece.
fn segments(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' && i + 1 < chars.len() {
                    i += 1;
                    cur.push(chars[i]);
                }
            }
            None => match c {
                '\\' if i + 1 < chars.len() => {
                    cur.push(c);
                    i += 1;
                    cur.push(chars[i]);
                }
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                ';' | '|' | '&' | '\n' | '`' | '(' | ')' => {
                    out.push(std::mem::take(&mut cur));
                }
                '$' if chars.get(i + 1) == Some(&'(') => {
                    out.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            },
        }
        i += 1;
    }
    out.push(cur);
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The text of each `$(…)` and `` `…` `` in a command, at any quote level.
fn substitutions(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && chars.get(i + 1) == Some(&'(') {
            let start = i + 2;
            let mut depth = 1;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let end = if depth == 0 { j - 1 } else { j };
            out.push(chars[start..end].iter().collect());
            i = start;
            continue;
        }
        if chars[i] == '`'
            && let Some(len) = chars[i + 1..].iter().position(|c| *c == '`')
        {
            out.push(chars[i + 1..i + 1 + len].iter().collect());
            i += len + 2;
            continue;
        }
        i += 1;
    }
    out
}

/// Split one simple command into words, and remove the quotes.
fn words(seg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has = false;
    let mut chars = seg.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            Some(_) => cur.push(c),
            None if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has = true;
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                has = true;
            }
            None if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            None => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Remove `VAR=value`, `sudo`, `env`, `command`, `exec`, `time`, `nohup` and `xargs` from
/// the start of a command, so the real program is the first word.
fn strip_prefixes(words: &[String]) -> Vec<String> {
    let mut i = 0;
    while i < words.len() {
        let name = basename(&words[i]);
        if is_assignment(&words[i]) {
            i += 1;
            continue;
        }
        // `env`, `sudo` and `xargs` take flags, and some of those take a value. Skip
        // both, so the real program is the first word.
        let value_flags: &[&str] = match name.as_str() {
            "env" => &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
            "sudo" => &[
                "-u",
                "--user",
                "-g",
                "--group",
                "-p",
                "--prompt",
                "-C",
                "--close-from",
                "-D",
                "--chdir",
                "-h",
                "--host",
                "-r",
                "--role",
                "-t",
                "--type",
                "-U",
                "--other-user",
            ],
            "xargs" => &[
                "-n",
                "--max-args",
                "-I",
                "--replace",
                "-P",
                "--max-procs",
                "-L",
                "--max-lines",
                "-s",
                "--max-chars",
                "-E",
                "--eof",
                "-a",
                "--arg-file",
                "-d",
                "--delimiter",
            ],
            _ => &[],
        };
        if !value_flags.is_empty() {
            i += 1;
            while i < words.len() {
                let a = &words[i];
                if is_assignment(a) {
                    i += 1;
                } else if a.starts_with('-') {
                    i += if value_flags.contains(&a.as_str()) {
                        2
                    } else {
                        1
                    };
                } else {
                    break;
                }
            }
            continue;
        }
        let wrapper = matches!(
            name.as_str(),
            "command" | "exec" | "time" | "nohup" | "doas"
        );
        if wrapper {
            i += 1;
        } else {
            break;
        }
    }
    words[i..].to_vec()
}

fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

/// Write the refusal in the format of the client. Returns the exit code of the hook.
pub fn respond(client: Client, reason: Option<String>) -> i32 {
    match (client, reason) {
        (_, None) => 0,
        (Client::Cursor, Some(r)) => {
            println!(
                "{}",
                serde_json::json!({"permission": "deny", "userMessage": r, "agentMessage": r})
            );
            0
        }
        (_, Some(r)) => {
            eprintln!("{r}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> Config {
        Config::default()
    }

    fn denied(cmd: &str) -> bool {
        check_command(cmd, &cfg()).is_some()
    }

    #[test]
    fn sealkeep_get_is_refused_in_every_position() {
        assert!(denied("sealkeep get OPENROUTER_KEY"));
        assert!(denied("echo hi && sealkeep get X"));
        assert!(denied("FOO=1 sealkeep get X"));
        assert!(denied(
            "curl -H \"x: $(sealkeep get X)\" https://example.com"
        ));
        assert!(denied("/usr/local/bin/sealkeep get X | cat"));
        assert!(denied("echo \"`sealkeep get X`\""));
        assert!(!denied("sealkeep run X -- curl https://example.com"));
        assert!(!denied("sealkeep list"));
        assert!(denied("SEALKEEP_ASKPASS_TOKEN=ab sealkeep"));
        assert!(denied("export SEALKEEP_ASKPASS_TOKEN=ab; sealkeep"));
    }

    #[test]
    fn quoted_heredocs_are_data() {
        assert!(!denied(
            "python3 - <<'EOF'\nx = \"refuses `cat .env`\"\nEOF\necho done"
        ));
        assert!(!denied(
            "cat > notes.md <<\"END\"\nrun `sealkeep get X` never\nEND"
        ));
        // Unquoted: the shell runs the substitution.
        assert!(denied("cat <<EOF\n$(cat .env)\nEOF"));
        // A command after the heredoc is still checked.
        assert!(denied("python3 - <<'EOF'\nprint(1)\nEOF\ncat .env"));
    }

    #[test]
    fn keyring_reads() {
        assert!(denied("secret-tool lookup service sealkeep username X"));
        assert!(denied("secret-tool lookup service other username X"));
        assert!(denied("secret-tool search --all service other"));
        assert!(denied("security find-generic-password -s sealkeep -a X -w"));
        assert!(denied("security find-generic-password -s other -a X -w"));
        assert!(!denied("security find-generic-password -s sealkeep -a X"));
        assert!(denied("security dump-keychain -d"));
        assert!(denied("security export -t private-keys"));
        assert!(denied("keyring get sealkeep X"));
        assert!(denied("keyring get other X"));
        assert!(denied(
            "gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets"
        ));
        assert!(!denied(
            "gdbus call --session --dest org.freedesktop.portal.Desktop"
        ));
    }

    #[test]
    fn dotenv_reads() {
        assert!(denied("cat .env"));
        assert!(denied("cat ../app/.env.local"));
        assert!(denied("source ./.env"));
        assert!(denied(". .env"));
        assert!(denied("grep KEY prod.env"));
        assert!(denied("set -a; . ./.env; set +a"));
        assert!(denied("while read l; do echo $l; done <.env"));
        assert!(denied("while read l; do echo $l; done < .env"));
        assert!(denied("bash -lc 'cat .env'"));
        assert!(!denied("cat .env.example"));
        assert!(!denied("cp .env.example .env.sample"));
        assert!(!denied("ls -la"));
        assert!(!denied("echo '.env is ignored' | grep env"));
        let mut c = cfg();
        c.guard.block_dotenv = false;
        assert!(check_command("cat .env", &c).is_none());
    }

    #[test]
    fn environment_and_token_dumps() {
        assert!(denied("env"));
        assert!(denied("env FOO=bar"));
        assert!(denied("env -0"));
        assert!(denied("printenv"));
        assert!(denied("printenv GITHUB_TOKEN"));
        assert!(denied("set"));
        assert!(denied("export"));
        assert!(denied("export -p"));
        assert!(denied("declare"));
        assert!(denied("declare -p"));
        assert!(denied("declare -px"));
        assert!(denied("declare -x"));
        assert!(denied("typeset -p"));
        assert!(denied("ps e"));
        assert!(denied("ps eww"));
        assert!(denied("ps auxe"));
        assert!(denied("ps -auxe"));
        assert!(denied("cat /proc/self/environ"));
        assert!(denied("cat /proc/1/environ"));
        assert!(denied("tr '\\0' '\\n' < /proc/self/environ"));
        assert!(denied("strings /proc/1/cmdline"));
        assert!(denied("dd if=/proc/self/environ"));
        assert!(denied(
            "sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'select * from logins'"
        ));

        assert!(!denied("env FOO=bar kubectl get pods"));
        assert!(!denied("set -e; true"));
        assert!(!denied("export FOO=bar"));
        assert!(!denied("declare -x FOO"));
        assert!(!denied("ps -ef"));
        assert!(!denied("ps aux"));
        assert!(!denied("ps -eo pid,cmd"));
        assert!(!denied("cat /proc/cpuinfo"));

        assert!(denied("env -u FOO kubectl get secret x"));
        assert!(denied("env -S 'kubectl get secret x'"));
        assert!(denied("sudo -u root kubectl get secret x"));
        assert!(denied("xargs -n1 kubectl get secret"));
        assert!(!denied("env -u FOO kubectl get pods"));
        assert!(!denied("sudo -u root kubectl get pods"));
        assert!(!denied("xargs -n1 echo"));

        assert!(denied("gcloud auth print-access-token"));
        assert!(denied("gcloud auth application-default print-access-token"));
        assert!(denied("gcloud auth print-identity-token"));
        assert!(denied("aws configure get aws_secret_access_key"));
        assert!(denied("aws configure get aws_session_token"));
        assert!(denied("aws sts get-session-token"));
        assert!(denied("aws sts assume-role --role-arn x"));
        assert!(denied("aws sso get-role-credentials"));
        assert!(denied("az account get-access-token"));
        assert!(denied("gh auth token"));
        assert!(denied("gh auth status --show-token"));
        assert!(denied("git credential fill"));
        assert!(denied("git credential-manager get"));
        assert!(denied("npm config get //registry.npmjs.org/:_authToken"));
        assert!(denied("yarn config get npmAuthToken"));
        assert!(denied("pnpm config get //registry.npmjs.org/:_authToken"));

        assert!(!denied("gcloud auth list"));
        assert!(!denied("aws configure get region"));
        assert!(!denied("aws sts get-caller-identity"));
        assert!(!denied("aws sso login"));
        assert!(!denied("az account show"));
        assert!(!denied("gh auth status"));
        assert!(!denied("git credential approve"));
        assert!(!denied("npm config get registry"));
    }

    #[test]
    fn terraform_helm_docker_and_inventory() {
        assert!(denied("terraform state pull"));
        assert!(denied("terraform state show aws_instance.x"));
        assert!(denied("terraform output -json"));
        assert!(denied("terraform output -raw db_password"));
        assert!(denied("terraform show -json"));
        assert!(denied("tofu state pull"));
        assert!(denied("tofu output -json"));
        assert!(denied("helm get values release"));
        assert!(denied("helm get manifest release"));
        assert!(denied("helm get all release"));
        assert!(denied("helm secrets view secrets.yaml"));
        assert!(denied("helm secrets dec secrets.yaml"));
        assert!(denied("docker compose config"));
        assert!(denied("docker-compose config"));
        assert!(denied("docker inspect app"));
        assert!(denied("podman inspect app"));
        assert!(denied("docker history app"));
        assert!(denied("docker exec app -- env"));
        assert!(denied("podman exec app -- printenv"));
        assert!(denied("pulumi stack output --show-secrets"));
        assert!(denied("ansible-inventory --list"));
        assert!(denied("ansible-inventory --host web1"));
        assert!(denied("ansible-inventory"));
        assert!(denied("ansible-inventory --yaml"));

        assert!(!denied("terraform state list"));
        assert!(!denied("terraform output"));
        assert!(!denied("terraform show"));
        assert!(!denied("helm list"));
        assert!(!denied("helm get notes release"));
        assert!(!denied("docker ps"));
        assert!(!denied("docker compose ps"));
        assert!(!denied("docker exec app -- ls /tmp"));
        assert!(!denied("pulumi stack output"));
        assert!(!denied("ansible-inventory --graph"));
    }

    #[test]
    fn deny_list() {
        let mut c = cfg();
        c.guard.deny = vec!["vault kv get".into()];
        assert!(check_command("vault kv get secret/x", &c).is_some());
        assert!(check_command("vault kv list secret/", &c).is_none());
    }

    #[test]
    fn kubernetes_secret_reads_are_refused() {
        assert!(denied("kubectl get secret"));
        assert!(denied(
            "kubectl -n cert-manager get secret cloudflare-api-token -o jsonpath='{.data.api-token}'"
        ));
        assert!(denied(
            "kubectl -n cert-manager get -o yaml secret cloudflare-api-token"
        ));
        assert!(denied("kubectl get secrets -A"));
        assert!(denied("kubectl get sec foo"));
        assert!(denied("kubectl get SECRET foo"));
        assert!(denied("kubectl get secret/foo"));
        assert!(denied("kubectl get pods,secrets"));
        assert!(denied("kubectl get secrets.v1.core foo"));
        assert!(denied(
            "kubectl get --raw /api/v1/namespaces/cert-manager/secrets/cloudflare-api-token"
        ));
        assert!(denied(
            "kubectl get --raw=/api/v1/namespaces/cert-manager/secrets/cloudflare-api-token"
        ));
        assert!(denied("kubectl edit secret cloudflare-api-token"));
        assert!(denied("kubectl view-secret cloudflare-api-token"));
        assert!(denied("kubectl config view --raw"));
        assert!(denied(
            "kubectl exec pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        ));
        assert!(denied("kubectl exec pod -- vault kv get secret/x"));
        assert!(denied("kubectl exec pod -- env"));
        assert!(denied(
            "kubectl debug pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        ));
        assert!(denied("/usr/bin/kubectl get secret x"));
        assert!(denied("oc get secret x"));
        assert!(denied("k3s kubectl get secret x"));
        assert!(denied("kubectl get secret x | base64 -d"));

        assert!(!denied("kubectl get pods"));
        assert!(!denied("kubectl get all"));
        assert!(!denied("kubectl describe secret x"));
        assert!(!denied("kubectl edit deployment x"));
        assert!(!denied("kubectl config view"));
        assert!(!denied("kubectl exec pod -- ls /tmp"));
        assert!(denied(
            "kubectl -n vault create token sealkeep --duration 10m"
        ));
    }

    #[test]
    fn other_store_reads_are_refused() {
        assert!(denied("vault kv get secret/cloudflare"));
        assert!(denied("vault kv export secret/cloudflare"));
        assert!(denied("vault read secret/cloudflare"));
        assert!(denied("bao kv get secret/cloudflare"));
        assert!(denied("ansible-vault view group_vars/all/vault.yml"));
        assert!(denied("ansible-vault decrypt group_vars/all/vault.yml"));
        assert!(denied("sops -d secrets.yaml"));
        assert!(denied("sops --decrypt secrets.yaml"));
        assert!(denied("sops exec-env secrets.yaml 'env'"));
        assert!(denied(
            "aws secretsmanager get-secret-value --secret-id cloudflare"
        ));
        assert!(denied(
            "gcloud secrets versions access latest --secret cloudflare"
        ));
        assert!(denied("az keyvault secret show --vault-name x --name y"));
        assert!(denied("op read op://vault/item/password"));
        assert!(denied("op item get item --reveal"));
        assert!(denied("bw get password item"));
        assert!(denied("bw get item item"));
        assert!(denied("bws secret get x"));
        assert!(denied("pass show cloudflare"));
        assert!(denied("rbw get cloudflare"));

        assert!(!denied("vault kv put secret/x KEY=value"));
        assert!(!denied("vault kv list secret/"));
        assert!(!denied("vault policy read default"));
        assert!(!denied("vault status"));
        assert!(!denied("ansible-vault encrypt group_vars/all/vault.yml"));
        assert!(!denied("sops -e secrets.yaml"));
        assert!(!denied("aws s3 ls"));
        assert!(!denied("aws ssm get-parameter --name x"));
        assert!(!denied("gcloud secrets list"));
        assert!(!denied("az keyvault secret list --vault-name x"));
        assert!(!denied("op item get item"));
        assert!(!denied("bw get username item"));
    }

    #[test]
    fn credential_files_are_refused() {
        assert!(denied("cat ~/.kube/config"));
        assert!(denied("cat /home/user/.kube/config"));
        assert!(denied("cat /home/user/.kube/ovh-gra1.yaml"));
        assert!(denied("grep token ~/.aws/credentials"));
        assert!(denied("head ~/.docker/config.json"));
        assert!(denied("cat ~/.ssh/id_ed25519"));
        assert!(denied("cat ~/.ssh/deploy_key"));
        assert!(denied("cat ~/.aws/config"));
        assert!(denied("cat terraform.tfstate"));
        assert!(denied("cat prod.tfstate.backup"));
        assert!(denied("cat .npmrc"));
        assert!(denied("cat ~/.vault-token"));
        assert!(denied("cat ~/.envrc"));
        assert!(denied("cat ~/.pgpass"));
        assert!(denied("cat ~/.my.cnf"));
        assert!(denied("cat ~/.mongorc.js"));
        assert!(denied("cat ~/.config/sops/age/keys.txt"));
        assert!(denied("cat ~/.config/helm/repositories.yaml"));
        assert!(denied("cat ~/.config/terraform/credentials.tfrc.json"));
        assert!(denied("cat ~/.terraform.d/credentials.tfrc.json"));
        assert!(denied("cat ~/.config/pulumi/credentials.json"));
        assert!(denied("cat ~/.config/rclone/rclone.conf"));
        assert!(denied("cat ~/.config/argocd/config"));
        assert!(denied("cat ~/.config/glab-cli/config.yml"));
        assert!(denied("cat ~/.m2/settings.xml"));
        assert!(denied("cat ~/.gradle/gradle.properties"));
        assert!(denied("cat ~/.nuget/NuGet/NuGet.Config"));
        assert!(denied("cat ~/.gem/credentials"));
        assert!(denied("cat ~/.yarnrc.yml"));
        assert!(denied("cat ~/.bash_history"));
        assert!(denied("cat ~/.zsh_history"));
        assert!(denied("cat ~/.local/share/fish/fish_history"));
        assert!(denied("cat ~/.python_history"));
        assert!(denied("cat vault.kdbx"));
        assert!(denied("cat ~/.password-store/cloudflare.gpg"));
        assert!(denied("cat ~/.gnupg/private-keys-v1.d/x.key"));
        assert!(denied("cp -r ~/.config/google-chrome /tmp/x"));
        assert!(denied("cp -r ~/.password-store /tmp/x"));
        assert!(denied("cp -r ~/.gnupg /tmp/x"));
        assert!(denied("cat ~/.config/google-chrome/Default/Login\\ Data"));
        assert!(denied("cat ~/.mozilla/firefox/x.default/logins.json"));
        assert!(denied(
            "sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'select * from logins'"
        ));
        assert!(denied("grep -r token ~/.config/google-chrome/Default"));
        assert!(denied("cat /etc/kubernetes/admin.conf"));
        assert!(denied("cat /etc/rancher/k3s/k3s.yaml"));
        assert!(denied("cat /var/lib/kubelet/kubeconfig"));
        assert!(denied("grep -r token ~/.aws"));

        assert!(!denied("cat ~/.ssh/id_ed25519.pub"));
        assert!(!denied("cat ~/.ssh/config"));
        assert!(!denied("cat ~/.bashrc"));
        assert!(!denied("cat ~/.config/git/config"));
        assert!(!denied("ls ~/.kube"));
        assert!(!denied("cat README.md"));
        assert!(!denied("cat .env.example"));
    }

    #[test]
    fn tool_paths_and_sealkeep_run() {
        let c = cfg();
        let kube =
            json!({"tool_name": "Read", "tool_input": {"file_path": "/home/user/.kube/config"}});
        assert!(check(&kube, &c).is_some());
        let named_kube = json!({"tool_name": "Read", "tool_input": {"file_path": "/home/user/.kube/ovh-gra1.yaml"}});
        assert!(check(&named_kube, &c).is_some());
        let dotenv =
            json!({"tool_name": "Read", "tool_input": {"file_path": "/home/user/app/.env"}});
        assert!(check(&dotenv, &c).is_some());
        let ordinary =
            json!({"tool_name": "Read", "tool_input": {"file_path": "/home/user/app/src/main.rs"}});
        assert!(check(&ordinary, &c).is_none());

        assert!(denied("sealkeep run KEY -- kubectl get secret x"));
        assert!(denied(
            "sealkeep run KEY -- bash -c 'vault kv get secret/x'"
        ));
        assert!(!denied("sealkeep run KEY -- kubectl get pods"));
        assert!(!denied(
            "sealkeep run API_KEY -- sh -c 'curl -H \"Authorization: Bearer $API_KEY\" https://example.com'"
        ));

        let argv = vec![
            "kubectl".to_string(),
            "get".to_string(),
            "secret".to_string(),
            "x".to_string(),
        ];
        assert!(check_argv(&argv, &c).is_some());
        let argv = vec!["kubectl".to_string(), "get".to_string(), "pods".to_string()];
        assert!(check_argv(&argv, &c).is_none());
    }

    #[test]
    fn the_built_in_rules_pass_their_own_test() {
        for (what, ok) in self_test(&cfg()) {
            assert!(ok, "{what}");
        }
    }

    #[test]
    fn output_with_a_stored_value_is_redacted_in_shape() {
        let value = "sk-test-0123456789abcdef";
        let r = Redactor::new([("shared/acme/prod/API_KEY", value)]);
        let input = json!({"tool_response": {
            "stdout": format!("A=1\nAPI_KEY={value}"),
            "file": {"content": [format!("x {value} y"), "clean"]},
            "code": 0
        }});
        let out = check_output(&input, &r).unwrap();
        let h = &out["hookSpecificOutput"];
        let shown = h["updatedToolOutput"].to_string();
        assert!(!shown.contains(value));
        assert_eq!(h["updatedToolOutput"]["code"], 0);
        assert_eq!(
            h["updatedToolOutput"]["file"]["content"][0],
            "x [sealkeep:shared/acme/prod/API_KEY] y"
        );
        assert!(
            h["additionalContext"]
                .as_str()
                .unwrap()
                .contains("shared/acme/prod/API_KEY")
        );
        assert!(!out.to_string().contains(value));

        let clean = json!({"tool_response": {"stdout": "hello"}});
        assert!(check_output(&clean, &r).is_none());
        assert!(check_output(&json!({"tool_name": "Bash"}), &r).is_none());
    }

    #[test]
    fn hook_inputs() {
        let c = cfg();
        let claude = json!({"tool_name": "Bash", "tool_input": {"command": "cat .env"}});
        assert!(check(&claude, &c).is_some());
        let read = json!({"tool_name": "Read", "tool_input": {"file_path": "/home/user/code/example/.env"}});
        assert!(check(&read, &c).is_some());
        let codex = json!({"tool_input": {"command": ["bash", "-lc", "sealkeep get X"]}});
        assert!(check(&codex, &c).is_some());
        let cursor = json!({"command": "cat .env", "cwd": "/tmp"});
        assert!(check(&cursor, &c).is_some());
        let quoted =
            json!({"tool_input": {"command": ["bash", "-c", "echo 'it'\\''s'; cat .env"]}});
        assert!(check(&quoted, &c).is_some());
        assert_eq!(words("echo 'it'\\''s'"), vec!["echo", "it's"]);
        let ok = json!({"tool_name": "Read", "tool_input": {"file_path": "src/main.rs"}});
        assert!(check(&ok, &c).is_none());
    }
}

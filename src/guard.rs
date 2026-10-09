//! The pre-tool hook. It refuses a tool call that would put a secret value into the
//! context of the agent:
//!
//! 1. `sealkeep get`, which prints a value.
//! 2. A direct read of the sealkeep keyring entries (`secret-tool lookup service sealkeep`,
//!    `security find-generic-password -s sealkeep -w`, `keyring get sealkeep …`).
//! 3. A read of a `.env` file (`cat .env`, `source .env`, the Read tool on `.env`), when
//!    `guard.block_dotenv` is on. `.env.example`, `.env.sample`, `.env.template` and
//!    `.env.dist` stay readable.
//! 4. Each command prefix in `guard.deny` of the config.
//!
//! Input: the JSON of the hook on stdin. Claude Code and Codex send
//! `{"tool_name", "tool_input": {"command" | "file_path" | "path"}}`; Cursor sends
//! `{"command"}`. Output: Claude Code and Codex get exit code 2 and the reason on stderr;
//! Cursor gets `{"permission": "deny", …}` on stdout.

use crate::config::{Config, DEFAULT_KEYRING_SERVICE};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Client {
    Claude,
    Codex,
    Cursor,
}

const ADVICE: &str = "Use `sealkeep run NAME -- <command>` to give the command the secret without the value. Run `sealkeep list` to see the names.";

/// Programs that print or load the file they are given.
const FILE_READERS: &[&str] = &[
    "cat", "tac", "less", "more", "head", "tail", "bat", "batcat", "grep", "egrep", "fgrep", "rg",
    "ag", "sed", "awk", "gawk", "cut", "sort", "uniq", "strings", "xxd", "od", "hexdump", "base64",
    "nl", "source", ".", "cp", "jq", "yq", "diff", "column", "tee", "dotenv", "envsubst", "vim",
    "vi", "nano", "view", "code", "python", "python3", "node", "ruby", "perl",
];

const SAFE_DOTENV_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".tmpl"];

/// Check one hook input. `Some(reason)` refuses the call.
pub fn check(input: &Value, cfg: &Config) -> Option<String> {
    let tool_input = input.get("tool_input").unwrap_or(input);
    if let Some(cmd) = command_of(tool_input) {
        return check_command(&cmd, cfg);
    }
    if cfg.guard.block_dotenv {
        for key in ["file_path", "path", "notebook_path"] {
            if let Some(p) = tool_input.get(key).and_then(Value::as_str)
                && is_dotenv_path(p)
            {
                return Some(format!(
                    "sealkeep guard: `{p}` is a .env file, and its values would go into the context. {ADVICE}"
                ));
            }
        }
    }
    None
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

pub fn check_command(cmd: &str, cfg: &Config) -> Option<String> {
    // A shell runs `$(…)` and `` `…` `` also inside double quotes.
    for sub in substitutions(cmd) {
        if let Some(r) = check_command(&sub, cfg) {
            return Some(r);
        }
    }
    for seg in segments(cmd) {
        let words = words(&seg);
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
        if prog == "sealkeep" && args.first() == Some(&"get") {
            return Some(format!(
                "sealkeep guard: `sealkeep get` prints a secret value. {ADVICE}"
            ));
        }
        if prog == "secret-tool"
            && matches!(args.first(), Some(&"lookup") | Some(&"search"))
            && mentions_sealkeep_service(&args)
        {
            return Some(format!(
                "sealkeep guard: this reads a sealkeep value from the keyring. {ADVICE}"
            ));
        }
        if prog == "security"
            && matches!(
                args.first(),
                Some(&"find-generic-password") | Some(&"find-internet-password")
            )
            && args.iter().any(|a| *a == "-w" || *a == "-g")
            && mentions_sealkeep_service(&args)
        {
            return Some(format!(
                "sealkeep guard: this reads a sealkeep value from the Keychain. {ADVICE}"
            ));
        }
        if prog == "keyring"
            && args.first() == Some(&"get")
            && args.get(1) == Some(&DEFAULT_KEYRING_SERVICE)
        {
            return Some(format!(
                "sealkeep guard: this reads a sealkeep value from the keyring. {ADVICE}"
            ));
        }
        if cfg.guard.block_dotenv
            && FILE_READERS.contains(&prog.as_str())
            && let Some(p) = args.iter().find(|a| is_dotenv_path(a))
        {
            return Some(format!(
                "sealkeep guard: `{p}` is a .env file, and its values would go into the context. {ADVICE}"
            ));
        }
        let redirect = args.iter().enumerate().any(|(i, a)| {
            (a.starts_with('<') && a.len() > 1 && is_dotenv_path(a.trim_start_matches('<')))
                || (*a == "<" && args.get(i + 1).is_some_and(|n| is_dotenv_path(n)))
        });
        if cfg.guard.block_dotenv && redirect {
            return Some(format!(
                "sealkeep guard: this reads a .env file into the command. {ADVICE}"
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

fn mentions_sealkeep_service(args: &[&str]) -> bool {
    args.contains(&DEFAULT_KEYRING_SERVICE)
}

/// `.env`, `.env.local`, `prod.env`, but not `.env.example`.
pub fn is_dotenv_path(p: &str) -> bool {
    let p = p.trim_matches(|c| c == '"' || c == '\'');
    let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
    let is_env = name == ".env" || name.starts_with(".env.") || name.ends_with(".env");
    is_env && !SAFE_DOTENV_SUFFIXES.iter().any(|s| name.ends_with(s))
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
        let w = &words[i];
        let assignment = w.contains('=')
            && w.split('=').next().is_some_and(|k| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
        let wrapper = matches!(
            basename(w).as_str(),
            "sudo" | "env" | "command" | "exec" | "time" | "nohup" | "xargs" | "doas"
        );
        if assignment || wrapper {
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
    fn keyring_reads() {
        assert!(denied("secret-tool lookup service sealkeep username X"));
        assert!(!denied("secret-tool lookup service other username X"));
        assert!(denied("security find-generic-password -s sealkeep -a X -w"));
        assert!(!denied("security find-generic-password -s sealkeep -a X"));
        assert!(denied("keyring get sealkeep X"));
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
    fn deny_list() {
        let mut c = cfg();
        c.guard.deny = vec!["vault kv get".into()];
        assert!(check_command("vault kv get secret/x", &c).is_some());
        assert!(check_command("vault kv list secret/", &c).is_none());
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

//! End-to-end tests of the binary. Run with `cargo test --features test-store`: the
//! keyring is then a file in a temporary folder.

#![cfg(all(feature = "test-store", unix))]

use assert_cmd::Command;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

const SECRET: &str = "sk-test-0123456789abcdef";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("sealkeep").unwrap();
        c.env("SEALKEEP_TEST_KEYRING_FILE", self.path("keyring.ron"))
            .env("SEALKEEP_CONFIG", self.path("config.toml"))
            .env("SEALKEEP_AUDIT_LOG", self.path("audit.jsonl"))
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .current_dir(self.dir.path());
        c
    }

    fn set(&self, name: &str, value: &str) {
        self.cmd()
            .args(["set", name, "--stdin", "-d", "a test key"])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.path("audit.jsonl")).unwrap_or_default()
    }
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn set_list_and_run_with_redaction() {
    let env = Env::new();
    env.set("API_KEY", SECRET);

    let out = env.cmd().args(["list", "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["secrets"][0]["name"], "API_KEY");
    assert_eq!(v["secrets"][0]["description"], "a test key");
    assert!(!stdout(&out).contains(SECRET));

    let out = env
        .cmd()
        .args([
            "run",
            "API_KEY",
            "--",
            "sh",
            "-c",
            "echo raw=$API_KEY; printf %s \"$API_KEY\" | base64; echo err=$API_KEY >&2; exit 7",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    let o = stdout(&out);
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(o.contains("raw=[sealkeep:API_KEY]"), "{o}");
    assert_eq!(o.matches("[sealkeep:API_KEY]").count(), 2, "{o}");
    assert!(e.contains("err=[sealkeep:API_KEY]"), "{e}");
    assert!(!o.contains(SECRET) && !e.contains(SECRET));

    let audit = env.audit();
    assert!(audit.contains("\"action\":\"run\""));
    assert!(audit.contains("local:API_KEY"));
    assert!(!audit.contains(SECRET));
}

#[test]
fn env_mapping_and_missing_names() {
    let env = Env::new();
    env.set("GH_PAT", SECRET);
    let out = env
        .cmd()
        .args([
            "run",
            "-e",
            "GITHUB_TOKEN=local:GH_PAT",
            "--",
            "sh",
            "-c",
            "test \"$GITHUB_TOKEN\" = \"$EXPECT\" && echo same",
        ])
        .env("EXPECT", SECRET)
        .output()
        .unwrap();
    assert!(stdout(&out).contains("same"), "{out:?}");

    env.cmd()
        .args(["run", "NOT_THERE", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no store has a secret `NOT_THERE`",
        ));
}

#[test]
fn get_refuses_without_a_terminal() {
    let env = Env::new();
    env.set("API_KEY", SECRET);
    let out = env.cmd().args(["get", "API_KEY"]).output().unwrap();
    assert!(!out.status.success());
    assert!(!stdout(&out).contains(SECRET));
    assert!(String::from_utf8_lossy(&out.stderr).contains("only at a terminal"));
}

#[test]
fn dotenv_file_is_redacted_and_removed() {
    let env = Env::new();
    env.set("ADMIN_PASSWORD", SECRET);
    let out = env
        .cmd()
        .args([
            "run",
            "--dotenv",
            "ADMIN_PASSWORD",
            "--",
            "sh",
            "-c",
            "cat \"$0\"; echo path=$0",
            "{dotenv}",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let o = stdout(&out);
    assert!(
        o.contains("ADMIN_PASSWORD='[sealkeep:ADMIN_PASSWORD]'"),
        "{o}"
    );
    let path = o.lines().find_map(|l| l.strip_prefix("path=")).unwrap();
    assert!(!Path::new(path).exists(), "the dotenv file was not removed");

    env.cmd()
        .args(["run", "--dotenv", "ADMIN_PASSWORD", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("{dotenv}"));
}

#[test]
fn import_into_a_folder_prints_names_only() {
    let env = Env::new();
    std::fs::write(
        env.path("app.env"),
        format!("OPENROUTER_API_KEY={SECRET}\nlower_case=x1234\nEMPTY=\nDB_URL=\"postgres://u:p@h/db\"\n"),
    )
    .unwrap();
    let out = env
        .cmd()
        .args(["import", "app.env", "--to", "personal/example-app/dev"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("Stored 3 secrets"), "{e}");
    assert!(e.contains("personal/example-app/dev/OPENROUTER_API_KEY"));
    assert!(e.contains("personal/example-app/dev/LOWER_CASE"));
    assert!(e.contains("skipped EMPTY"));
    assert!(!e.contains(SECRET) && !stdout(&out).contains(SECRET));

    // A second import of the same file changes nothing.
    let out = env
        .cmd()
        .args(["import", "app.env", "--to", "personal/example-app/dev"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("Stored 0 secrets (3 were the same)"));

    let out = env
        .cmd()
        .args(["list", "personal/example-app"])
        .output()
        .unwrap();
    assert!(stdout(&out).contains("personal/example-app/dev/DB_URL"));
}

#[test]
fn shared_values_are_stored_once_with_aliases() {
    let env = Env::new();
    std::fs::write(
        env.path("a.env"),
        format!("STRIPE_KEY={SECRET}\nPORT=3000\n"),
    )
    .unwrap();
    std::fs::write(env.path("b.env"), format!("STRIPE_SECRET={SECRET}\n")).unwrap();
    for (file, folder, key) in [
        ("a.env", "personal/app-a/dev", "STRIPE_KEY"),
        ("b.env", "personal/app-b/dev", "STRIPE_SECRET"),
    ] {
        env.cmd()
            .args([
                "import",
                file,
                "--to",
                folder,
                "--map",
                &format!("{key}=shared/stripe/test/SECRET_KEY"),
            ])
            .assert()
            .success();
    }
    let out = env.cmd().args(["list", "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"shared/stripe/test/SECRET_KEY"),
        "{names:?}"
    );
    assert!(
        names.contains(&"personal/app-a/dev/STRIPE_KEY"),
        "{names:?}"
    );
    assert!(
        names.contains(&"personal/app-b/dev/STRIPE_SECRET"),
        "{names:?}"
    );
    // One stored value, two aliases.
    let stored = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["store"] == "local")
        .count();
    assert_eq!(stored, 2, "{v}");

    // A folder run gives the alias value under the alias key.
    let out = env
        .cmd()
        .args([
            "run",
            "--all",
            "personal/app-a/dev",
            "--",
            "sh",
            "-c",
            "echo k=$STRIPE_KEY p=$PORT",
        ])
        .output()
        .unwrap();
    assert_eq!(
        stdout(&out).trim(),
        "k=[sealkeep:personal/app-a/dev/STRIPE_KEY] p=3000",
        "{out:?}"
    );

    // A different value for the shared name is refused.
    std::fs::write(env.path("c.env"), "STRIPE_KEY=sk-other-value-123\n").unwrap();
    env.cmd()
        .args([
            "import",
            "c.env",
            "--to",
            "personal/app-c/dev",
            "--map",
            "STRIPE_KEY=shared/stripe/test/SECRET_KEY",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already has a different value"));
}

#[test]
fn folder_runs_refuse_two_secrets_for_one_variable() {
    let env = Env::new();
    env.set("personal/app/dev/DATABASE_URL", SECRET);
    env.set(
        "personal/app/prod/DATABASE_URL",
        "postgres://prod-value-123",
    );
    env.cmd()
        .args(["run", "--all", "personal/app", "--recursive", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("both set DATABASE_URL"));
    // Without --recursive, a folder is one level, as a .env file is.
    env.cmd()
        .args(["run", "--all", "personal/app", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("has no secret"));
    let out = env
        .cmd()
        .args([
            "run",
            "--all",
            "personal/app/dev",
            "--",
            "sh",
            "-c",
            "echo $DATABASE_URL",
        ])
        .output()
        .unwrap();
    assert_eq!(
        stdout(&out).trim(),
        "[sealkeep:personal/app/dev/DATABASE_URL]"
    );
}

#[test]
fn ini_files_keep_their_sections() {
    let env = Env::new();
    std::fs::write(
        env.path("ovh.conf"),
        format!("[default]\nendpoint=ovh-eu\n\n[ovh-eu]\napplication_key={SECRET}\napplication_secret=as-0123456789\n"),
    )
    .unwrap();
    let out = env
        .cmd()
        .args(["import", "ovh.conf", "--to", "work/ovh"])
        .output()
        .unwrap();
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("work/ovh/default/ENDPOINT"), "{e}");
    assert!(e.contains("work/ovh/ovh-eu/APPLICATION_KEY"), "{e}");
    assert!(!e.contains(SECRET));
}

#[test]
fn set_from_file_and_scan() {
    let env = Env::new();
    std::fs::write(env.path("gh-token"), format!("{SECRET}\n")).unwrap();
    env.cmd()
        .args(["set", "personal/github/PAT", "--from-file", "gh-token"])
        .assert()
        .success();
    let out = env
        .cmd()
        .args([
            "run",
            "personal/github/PAT",
            "--",
            "sh",
            "-c",
            "printf %s \"$PAT\" | wc -c",
        ])
        .output()
        .unwrap();
    assert_eq!(stdout(&out).trim(), SECRET.len().to_string());

    std::fs::create_dir_all(env.path("proj")).unwrap();
    std::fs::write(env.path("proj/.env"), format!("A_KEY={SECRET}\nPORT=1\n")).unwrap();
    std::fs::write(env.path("other.env"), format!("B_TOKEN={SECRET}\n")).unwrap();
    let out = env.cmd().args(["scan", ".", "--json"]).output().unwrap();
    let text = stdout(&out);
    assert!(!text.contains(SECRET), "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["groups"].as_array().unwrap().len(), 1, "{v}");
    assert!(v["other_files"].to_string().contains("gh-token"), "{v}");
}

#[test]
fn mv_keeps_the_value_and_moves_aliases() {
    let env = Env::new();
    env.set("personal/x/OLD_KEY", SECRET);
    env.cmd()
        .args([
            "alias",
            "add",
            "personal/app/dev/OLD_KEY",
            "personal/x/OLD_KEY",
        ])
        .assert()
        .success();
    env.cmd()
        .args(["mv", "personal/x/OLD_KEY", "shared/x/NEW_KEY"])
        .assert()
        .success();
    let out = env
        .cmd()
        .args([
            "run",
            "personal/app/dev/OLD_KEY",
            "--",
            "sh",
            "-c",
            "test \"$OLD_KEY\" = \"$EXPECT\" && echo same",
        ])
        .env("EXPECT", SECRET)
        .output()
        .unwrap();
    assert_eq!(stdout(&out).trim(), "same", "{out:?}");
    env.cmd()
        .args(["run", "personal/x/OLD_KEY", "--", "true"])
        .assert()
        .failure();
}

#[test]
fn rm_removes_from_the_store_and_the_index() {
    let env = Env::new();
    env.set("API_KEY", SECRET);
    env.cmd().args(["rm", "API_KEY"]).assert().success();
    let out = env.cmd().args(["list", "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["secrets"].as_array().unwrap().len(), 0);
    env.cmd().args(["rm", "API_KEY"]).assert().failure();
}

#[test]
fn guard_hook_formats() {
    let env = Env::new();
    env.cmd()
        .args(["guard", "--client", "claude"])
        .write_stdin(
            json!({"tool_name": "Bash", "tool_input": {"command": "sealkeep get API_KEY"}})
                .to_string(),
        )
        .assert()
        .code(2)
        .stderr(predicates::str::contains("sealkeep run"));
    env.cmd()
        .args(["guard", "--client", "claude"])
        .write_stdin(json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}).to_string())
        .assert()
        .code(0);
    let out = env
        .cmd()
        .args(["guard", "--client", "cursor"])
        .write_stdin(json!({"command": "cat .env"}).to_string())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "deny");
}

#[test]
fn store_and_alias_config_commands() {
    let env = Env::new();
    env.cmd()
        .args([
            "store",
            "add-vault",
            "vault",
            "--address",
            "http://127.0.0.1:{port}",
            "--auth",
            "token",
            "--port-forward",
            "kubectl -n vault port-forward svc/vault {port}:8200",
        ])
        .assert()
        .success();
    let cfg = std::fs::read_to_string(env.path("config.toml")).unwrap();
    assert!(cfg.contains("kind = \"vault\""), "{cfg}");
    assert!(cfg.contains("kind = \"keyring\""), "{cfg}");
    env.cmd()
        .args([
            "store",
            "add-vault",
            "bad",
            "--address",
            "http://vault.example:8200",
            "--auth",
            "token",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("https"));
    env.cmd()
        .args(["store", "remove", "vault"])
        .assert()
        .success();

    env.cmd()
        .args(["alias", "add", "personal/app/dev/X_KEY", "shared/x/X_KEY"])
        .assert()
        .success();
    env.cmd()
        .args(["alias", "add", "shared/x/X_KEY", "shared/y/Y_KEY"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("also an alias"));
    env.cmd()
        .args(["alias", "rm", "personal/app/dev/X_KEY"])
        .assert()
        .success();
}

// ── MCP ─────────────────────────────────────────────────────────────────────

#[test]
fn mcp_lists_and_runs_with_redaction() {
    let env = Env::new();
    env.set("API_KEY", SECRET);
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("sealkeep"))
        .arg("mcp")
        .env("SEALKEEP_TEST_KEYRING_FILE", env.path("keyring.ron"))
        .env("SEALKEEP_CONFIG", env.path("config.toml"))
        .env("SEALKEEP_AUDIT_LOG", env.path("audit.jsonl"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut send = |v: Value| {
        stdin.write_all(format!("{v}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    };
    let mut recv = || -> Value {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };

    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}),
    );
    let init = recv();
    assert_eq!(init["result"]["serverInfo"]["name"], "sealkeep", "{init}");
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = recv();
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"list_secrets") && names.contains(&"run_with_secrets"),
        "{tools}"
    );
    assert!(!names.iter().any(|n| n.contains("get")), "{names:?}");

    send(
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "run_with_secrets",
        "arguments": {"command": ["sh", "-c", "echo k=$API_KEY; exit 3"], "secrets": ["API_KEY"]}}}),
    );
    let r = recv();
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["stdout"], "k=[sealkeep:API_KEY]\n");
    assert!(!r.to_string().contains(SECRET));

    send(
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
        "name": "list_secrets", "arguments": {}}}),
    );
    let r = recv();
    assert!(r.to_string().contains("API_KEY"));
    assert!(!r.to_string().contains(SECRET));

    drop(stdin);
    let _ = child.wait();
    assert!(env.audit().contains("\"action\":\"mcp_run\""));
}

// ── Vault KV v2, against a local fake ───────────────────────────────────────

#[derive(Default)]
struct KvSecret {
    data: serde_json::Map<String, Value>,
    version: u64,
    custom: serde_json::Map<String, Value>,
}

fn serve_fake_vault(state: Arc<Mutex<std::collections::BTreeMap<String, KvSecret>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let state = state.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let (mut len, mut token) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("x-vault-token:") {
                        token = h["x-vault-token:".len()..].trim().to_string();
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (status, reply) = if token != "test-token" {
                    (403, json!({"errors": ["permission denied"]}))
                } else {
                    vault_route(&mut state.lock().unwrap(), &method, &path, &body)
                };
                let text = reply.to_string();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

fn vault_route(
    st: &mut std::collections::BTreeMap<String, KvSecret>,
    method: &str,
    path: &str,
    body: &Value,
) -> (u16, Value) {
    if path == "/v1/auth/token/lookup-self" {
        return (200, json!({"data": {"policies": ["sealkeep"]}}));
    }
    if let Some(p) = path.strip_prefix("/v1/agent/metadata/") {
        if let Some(prefix) = p.strip_suffix("?list=true") {
            let prefix = prefix.trim_end_matches('/');
            let mut keys = std::collections::BTreeSet::new();
            for k in st.keys() {
                let rest = if prefix.is_empty() {
                    Some(k.as_str())
                } else {
                    k.strip_prefix(&format!("{prefix}/"))
                };
                if let Some(rest) = rest {
                    match rest.split_once('/') {
                        Some((dir, _)) => keys.insert(format!("{dir}/")),
                        None => keys.insert(rest.to_string()),
                    };
                }
            }
            if keys.is_empty() {
                return (404, json!({"errors": []}));
            }
            return (200, json!({"data": {"keys": keys}}));
        }
        return match (method, st.get_mut(p)) {
            ("GET", Some(s)) => (
                200,
                json!({"data": {"custom_metadata": s.custom, "updated_time": "2026-10-09T00:00:00Z"}}),
            ),
            ("GET", None) => (404, json!({"errors": []})),
            ("POST", Some(s)) => {
                s.custom = body["custom_metadata"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                (204, Value::Null)
            }
            _ => (400, json!({"errors": ["no secret"]})),
        };
    }
    if let Some(p) = path.strip_prefix("/v1/agent/data/") {
        return match method {
            "GET" => match st.get(p) {
                Some(s) => (
                    200,
                    json!({"data": {"data": s.data, "metadata": {"version": s.version}}}),
                ),
                None => (404, json!({"errors": []})),
            },
            "POST" => {
                let e = st.entry(p.to_string()).or_default();
                if body["options"]["cas"].as_u64() != Some(e.version) {
                    return (
                        400,
                        json!({"errors": ["check-and-set parameter did not match the current version"]}),
                    );
                }
                e.data = body["data"].as_object().cloned().unwrap_or_default();
                e.version += 1;
                (200, json!({"data": {"version": e.version}}))
            }
            _ => (405, json!({"errors": []})),
        };
    }
    (404, json!({"errors": ["no route"]}))
}

#[test]
fn sync_to_vault_and_run_from_it() {
    let env = Env::new();
    let state = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let url = serve_fake_vault(state.clone());
    env.set("shared/stripe/test/SECRET_KEY", SECRET);
    env.set("personal/app/dev/DATABASE_URL", "postgres://u:p@h/app-dev");
    env.set("BARE_KEY", "bare-value-123");
    env.cmd()
        .args(["set", "personal/ssh/NO_DESC_PASSPHRASE", "--stdin"])
        .write_stdin("passphrase-with-no-description")
        .assert()
        .success();
    env.cmd()
        .args([
            "store",
            "add-vault",
            "vault",
            "--address",
            &url,
            "--auth",
            "token",
        ])
        .assert()
        .success();

    let out = env
        .cmd()
        .args(["sync", "--from", "local", "--to", "vault"])
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{e}");
    assert!(e.contains("Copied 3 secrets"), "{e}");
    assert!(e.contains("skipped BARE_KEY (Vault needs a folder)"), "{e}");
    assert!(!e.contains(SECRET));
    {
        let st = state.lock().unwrap();
        assert_eq!(st["shared/stripe/test"].data["SECRET_KEY"], SECRET);
        assert!(st["shared/stripe/test"].custom.contains_key("SECRET_KEY"));
    }

    let out = env
        .cmd()
        .args(["sync", "--from", "local", "--to", "vault"])
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("Copied 0 secrets from local to vault; 3 were the same")
    );

    let out = env
        .cmd()
        .args(["list", "--store", "vault", "--json"])
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["secrets"].as_array().unwrap().len(), 3, "{v}");
    let no_desc = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "personal/ssh/NO_DESC_PASSPHRASE")
        .unwrap();
    assert!(no_desc.get("description").is_none(), "{no_desc}");

    let out = env
        .cmd()
        .args([
            "run",
            "vault:shared/stripe/test/SECRET_KEY",
            "--",
            "sh",
            "-c",
            "echo $SECRET_KEY",
        ])
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    assert_eq!(
        stdout(&out).trim(),
        "[sealkeep:shared/stripe/test/SECRET_KEY]",
        "{out:?}"
    );

    // With two stores, `set` writes to both.
    let out = env
        .cmd()
        .args(["set", "shared/new/X_KEY", "--stdin"])
        .write_stdin("value-in-both-stores")
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Stored shared/new/X_KEY in local, vault"),
        "{out:?}"
    );
    assert_eq!(
        state.lock().unwrap()["shared/new"].data["X_KEY"],
        "value-in-both-stores"
    );
    // A bare name has no folder, so it goes to the keyring only.
    let out = env
        .cmd()
        .args(["set", "BARE_TWO", "--stdin"])
        .write_stdin("bare-value-456")
        .env("VAULT_TOKEN", "test-token")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Stored BARE_TWO in local."),
        "{out:?}"
    );

    env.cmd()
        .args(["list", "--store", "vault"])
        .env("VAULT_TOKEN", "wrong")
        .assert()
        .failure()
        .stderr(predicates::str::contains("permission denied"));
}

// ── SSH keys ────────────────────────────────────────────────────────────────

#[test]
fn ssh_load_adds_a_key_with_its_passphrase_and_askpass_answers_ssh_add_only() {
    let env = Env::new();
    let key = env.path("id_test");
    let pass = "correct horse battery staple 42";
    let ok = std::process::Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            pass,
            "-C",
            "sealkeep-test",
            "-f",
        ])
        .arg(&key)
        .status()
        .unwrap();
    assert!(ok.success());
    let sock = env.path("agent.sock");
    let mut agent = std::process::Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&sock)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    env.set("personal/ssh/TEST_PASSPHRASE", pass);
    env.cmd()
        .args([
            "ssh-add",
            key.to_str().unwrap(),
            "--passphrase",
            "personal/ssh/TEST_PASSPHRASE",
            "--agent",
        ])
        .arg(&sock)
        .assert()
        .success();
    let out = env.cmd().arg("ssh-load").output().unwrap();
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{e}");
    assert!(e.contains("added to"), "{e}");
    let listed = std::process::Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&listed.stdout).contains("sealkeep-test"));

    // A second run finds the key in the agent.
    let out = env.cmd().arg("ssh-load").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("already in the agent"));

    // The askpass step does not answer a process that is not ssh-add.
    let out = env
        .cmd()
        .env("SEALKEEP_ASKPASS_TOKEN", "a".repeat(48))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!stdout(&out).contains(pass));
    assert!(!env.audit().contains(pass));

    let _ = agent.kill();
    let _ = agent.wait();
}

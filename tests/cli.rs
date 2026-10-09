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
fn import_prints_names_only() {
    let env = Env::new();
    std::fs::write(
        env.path("app.env"),
        format!("OPENROUTER_API_KEY={SECRET}\nlower_case=x1234\nEMPTY=\nDB_URL=\"postgres://u:p@h/db\"\n"),
    )
    .unwrap();
    let out = env
        .cmd()
        .args(["import", "app.env", "--prefix", "APP_"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("Imported 2 secrets"), "{e}");
    assert!(e.contains("local:APP_OPENROUTER_API_KEY"));
    assert!(e.contains("skipped lower_case"));
    assert!(!e.contains(SECRET) && !stdout(&out).contains(SECRET));
    let out = env.cmd().args(["list"]).output().unwrap();
    assert!(stdout(&out).contains("APP_DB_URL"));
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
fn store_config_commands() {
    let env = Env::new();
    env.cmd()
        .args([
            "store",
            "add-proxium",
            "team",
            "--url",
            "https://proxium.example",
            "--project",
            "acme",
        ])
        .assert()
        .success();
    let cfg = std::fs::read_to_string(env.path("config.toml")).unwrap();
    assert!(cfg.contains("kind = \"proxium\""), "{cfg}");
    assert!(cfg.contains("kind = \"keyring\""), "{cfg}");
    env.cmd()
        .args([
            "store",
            "add-proxium",
            "bad",
            "--url",
            "http://proxium.example",
            "--project",
            "acme",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("https"));
    env.cmd()
        .args(["store", "remove", "team"])
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

// ── Proxium, against a local fake ──────────────────────────────────────────

#[derive(Default)]
struct Fake {
    approved_after: usize,
    polls: usize,
    reveals: Vec<(String, String)>,
}

fn serve_fake(state: Arc<Mutex<Fake>>) -> String {
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
                let mut len = 0;
                let mut auth = String::new();
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
                    if lower.starts_with("authorization:") {
                        auth = h["authorization:".len()..].trim().to_string();
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (status, reply) = route(&state, &method, &path, &auth, &body);
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

fn route(state: &Mutex<Fake>, method: &str, path: &str, auth: &str, body: &Value) -> (u16, Value) {
    let mut st = state.lock().unwrap();
    match (method, path) {
        ("POST", "/api/auth/device/code") => {
            assert_eq!(body["client_id"], "proxium-cli");
            (
                200,
                json!({"device_code": "dc", "user_code": "ABCD1234", "verification_uri": "http://x/device",
                         "verification_uri_complete": "http://x/device?user_code=ABCD1234", "expires_in": 60, "interval": 1}),
            )
        }
        ("POST", "/api/auth/device/token") => {
            st.polls += 1;
            if st.polls <= st.approved_after {
                (
                    400,
                    json!({"error": "authorization_pending", "error_description": "wait"}),
                )
            } else {
                (
                    200,
                    json!({"access_token": "session-1", "token_type": "Bearer", "expires_in": 600}),
                )
            }
        }
        ("GET", "/api/auth/token") => {
            if auth == "Bearer session-1" {
                (200, json!({"token": "jwt-1"}))
            } else {
                (401, json!({"error": "unauthorized"}))
            }
        }
        _ if auth != "Bearer jwt-1" => (
            401,
            json!({"error": {"code": "unauthenticated", "message": "no"}}),
        ),
        ("GET", "/api/teams/acme/secrets") => (
            200,
            json!({"secrets": [
            {"name": "STRIPE_KEY", "description": "test mode", "version": 1, "updated_at": "2026-10-09T00:00:00Z", "updated_by": "u"}]}),
        ),
        ("POST", "/api/teams/acme/secrets/STRIPE_KEY/reveal") => {
            st.reveals.push((
                "STRIPE_KEY".into(),
                body["purpose"].as_str().unwrap_or("").into(),
            ));
            (
                200,
                json!({"name": "STRIPE_KEY", "value": SECRET, "version": 1}),
            )
        }
        ("POST", p) if p.ends_with("/reveal") => (
            404,
            json!({"error": {"code": "not_found", "message": "no"}}),
        ),
        _ => (
            404,
            json!({"error": {"code": "not_found", "message": path}}),
        ),
    }
}

#[test]
fn proxium_login_list_and_run() {
    let env = Env::new();
    let state = Arc::new(Mutex::new(Fake {
        approved_after: 1,
        ..Default::default()
    }));
    let url = serve_fake(state.clone());
    env.cmd()
        .args([
            "store",
            "add-proxium",
            "team",
            "--url",
            &url,
            "--project",
            "acme",
        ])
        .assert()
        .success();

    env.cmd()
        .args(["run", "team:STRIPE_KEY", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("sealkeep login team"));

    let out = env
        .cmd()
        .args(["login", "team", "--no-browser"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("ABCD1234"));
    assert_eq!(state.lock().unwrap().polls, 2);

    let out = env.cmd().args(["list"]).output().unwrap();
    assert!(stdout(&out).contains("STRIPE_KEY"), "{out:?}");

    // A bare name falls through the empty local store to the Proxium store.
    let out = env
        .cmd()
        .args(["run", "STRIPE_KEY", "--", "sh", "-c", "echo v=$STRIPE_KEY"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out).trim(), "v=[sealkeep:STRIPE_KEY]", "{out:?}");
    let reveals = state.lock().unwrap().reveals.clone();
    assert_eq!(reveals.len(), 1);
    assert!(reveals[0].1.starts_with("run: sh -c"), "{reveals:?}");

    env.cmd().args(["logout", "team"]).assert().success();
    env.cmd()
        .args(["list", "--store", "team"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not signed in"));
}

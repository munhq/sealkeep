//! A HashiCorp Vault (or OpenBao) KV v2 mount as a store.
//!
//! Layout: the folder of a name is one KV secret and the key is one field of it, so
//! `shared/stripe/test/SECRET_KEY` is the field `SECRET_KEY` of `<mount>/shared/stripe/test`.
//! The `custom_metadata` of each secret lists its keys with their descriptions, so
//! `list` reads metadata only and no value.
//!
//! Auth: a token (`$VAULT_TOKEN` or the keyring entry `vault-token:<store>`), or a
//! Kubernetes ServiceAccount JWT from `jwt_command` that Vault exchanges for a token that
//! lives for the TTL of its role. `port_forward` reaches a Vault that has no address
//! outside its cluster, through the Kubernetes API that the kubeconfig already reaches.

use super::{SecretInfo, Store, keyring};
use crate::config::{DEFAULT_KEYRING_SERVICE, StoreConfig, VaultAuth};
use crate::names;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use ureq::Agent;

/// The custom_metadata value of a key with no description.
const NO_DESCRIPTION: &str = "-";

pub struct VaultStore {
    name: String,
    address: String,
    mount: String,
    auth: VaultAuth,
    role: Option<String>,
    k8s_auth_mount: String,
    jwt_command: Vec<String>,
    port_forward: Vec<String>,
    agent: Agent,
    conn: Mutex<Option<Conn>>,
}

struct Conn {
    base: String,
    token: String,
    _forward: Option<Forward>,
}

/// The port-forward process. It stops when the store is dropped.
struct Forward(Child);

impl Drop for Forward {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The `custom_metadata` of a secret and its `updated_time`.
type Meta = (Map<String, Value>, Option<String>);

fn reply_error(status: u16, body: &str) -> anyhow::Error {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let errs: Vec<&str> = v
        .get("errors")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if errs.is_empty() {
        anyhow!("Vault answered HTTP {status}")
    } else {
        anyhow!("Vault answered HTTP {status}: {}", errs.join("; "))
    }
}

fn free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").context("find a free local port")?;
    Ok(l.local_addr()?.port())
}

impl VaultStore {
    pub fn new(cfg: StoreConfig) -> Self {
        let StoreConfig::Vault {
            name,
            address,
            mount,
            auth,
            role,
            k8s_auth_mount,
            jwt_command,
            port_forward,
        } = cfg
        else {
            unreachable!("VaultStore::new takes a vault config");
        };
        let agent = Agent::new_with_config(
            Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .http_status_as_error(false)
                .user_agent(concat!("sealkeep/", env!("CARGO_PKG_VERSION")))
                .build(),
        );
        Self {
            name,
            address,
            mount,
            auth,
            role,
            k8s_auth_mount,
            jwt_command,
            port_forward,
            agent,
            conn: Mutex::new(None),
        }
    }

    pub fn token_user(store: &str) -> String {
        format!("vault-token:{store}")
    }

    fn start_forward(&self) -> Result<(u16, Option<Forward>)> {
        if self.port_forward.is_empty() {
            return Ok((0, None));
        }
        let port = free_port()?;
        let args: Vec<String> = self
            .port_forward
            .iter()
            .map(|a| a.replace("{port}", &port.to_string()))
            .collect();
        let child = Command::new(&args[0])
            .args(&args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("start the port forward `{}`", args[0]))?;
        let mut fwd = Forward(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok((port, Some(fwd)));
            }
            if let Some(st) = fwd.0.try_wait()? {
                bail!(
                    "the port forward stopped ({st}); run it by hand to see why: {}",
                    args.join(" ")
                );
            }
            if Instant::now() >= deadline {
                bail!("the port forward did not open port {port} in 20 s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn login(&self, base: &str) -> Result<String> {
        match self.auth {
            VaultAuth::Token => {
                if let Ok(t) = std::env::var("VAULT_TOKEN")
                    && !t.is_empty()
                {
                    return Ok(t);
                }
                keyring::read(DEFAULT_KEYRING_SERVICE, &Self::token_user(&self.name))?
                    .with_context(|| {
                        format!(
                            "store `{}` has no token: set $VAULT_TOKEN, or run `sealkeep store token {}`",
                            self.name, self.name
                        )
                    })
            }
            VaultAuth::Kubernetes => {
                let out = Command::new(&self.jwt_command[0])
                    .args(&self.jwt_command[1..])
                    .stdin(Stdio::null())
                    .output()
                    .with_context(|| format!("run `{}`", self.jwt_command[0]))?;
                if !out.status.success() {
                    bail!(
                        "the jwt_command failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                let jwt = String::from_utf8(out.stdout)?.trim().to_string();
                let mut resp = self
                    .agent
                    .post(format!("{base}/v1/auth/{}/login", self.k8s_auth_mount))
                    .send_json(json!({ "role": self.role, "jwt": jwt }))
                    .with_context(|| format!("reach Vault at {base}"))?;
                let status = resp.status().as_u16();
                let body = resp.body_mut().read_to_string().unwrap_or_default();
                if status != 200 {
                    return Err(reply_error(status, &body)).context("Kubernetes login to Vault");
                }
                let v: Value = serde_json::from_str(&body)?;
                v.pointer("/auth/client_token")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .context("the Vault login reply has no client_token")
            }
        }
    }

    /// Call Vault. Opens the port forward and signs in on the first call.
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| anyhow!("vault connection lock"))?;
        if guard.is_none() {
            let (port, fwd) = self.start_forward()?;
            let base = self
                .address
                .replace("{port}", &port.to_string())
                .trim_end_matches('/')
                .to_string();
            let token = self.login(&base)?;
            *guard = Some(Conn {
                base,
                token,
                _forward: fwd,
            });
        }
        let conn = guard.as_ref().expect("set above");
        let url = format!("{}/v1/{path}", conn.base);
        let token = conn.token.as_str();
        let mut resp = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("X-Vault-Token", token).call(),
            ("POST", Some(b)) => self
                .agent
                .post(&url)
                .header("X-Vault-Token", token)
                .send_json(b),
            ("POST", None) => self
                .agent
                .post(&url)
                .header("X-Vault-Token", token)
                .send_empty(),
            (m, _) => bail!("method {m} is not used"),
        }
        .with_context(|| format!("reach Vault at {}", conn.base))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if status >= 400 && status != 404 {
            return Err(reply_error(status, &text)).with_context(|| format!("{method} {path}"));
        }
        let v = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        Ok((status, v))
    }

    fn folder_of(name: &str) -> Result<&str> {
        let f = names::folder_of(name);
        if f.is_empty() {
            bail!(
                "`{name}`: a Vault store needs a folder in the name, for example personal/app/{name}"
            );
        }
        Ok(f)
    }

    /// The fields of a folder and its current version (0 when the folder is new).
    fn read_folder(&self, folder: &str) -> Result<(Map<String, Value>, u64)> {
        let (status, v) = self.call("GET", &format!("{}/data/{folder}", self.mount), None)?;
        if status == 404 {
            let version = v
                .pointer("/data/metadata/version")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            return Ok((Map::new(), version));
        }
        let data = v
            .pointer("/data/data")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let version = v
            .pointer("/data/metadata/version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Ok((data, version))
    }

    fn write_folder(&self, folder: &str, data: Map<String, Value>, cas: u64) -> Result<()> {
        self.call(
            "POST",
            &format!("{}/data/{folder}", self.mount),
            Some(json!({ "options": { "cas": cas }, "data": data })),
        )?;
        Ok(())
    }

    fn read_meta(&self, folder: &str) -> Result<Option<Meta>> {
        let (status, v) = self.call("GET", &format!("{}/metadata/{folder}", self.mount), None)?;
        if status == 404 {
            return Ok(None);
        }
        let custom = v
            .pointer("/data/custom_metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let updated = v
            .pointer("/data/updated_time")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Some((custom, updated)))
    }

    fn write_meta(&self, folder: &str, custom: Map<String, Value>) -> Result<()> {
        self.call(
            "POST",
            &format!("{}/metadata/{folder}", self.mount),
            Some(json!({ "custom_metadata": custom })),
        )?;
        Ok(())
    }

    /// Every secret path under `prefix` (recursive LIST).
    fn walk(&self, prefix: &str, out: &mut Vec<String>) -> Result<()> {
        let path = if prefix.is_empty() {
            format!("{}/metadata/?list=true", self.mount)
        } else {
            format!("{}/metadata/{prefix}/?list=true", self.mount)
        };
        let (status, v) = self.call("GET", &path, None)?;
        if status == 404 {
            return Ok(());
        }
        let keys: Vec<String> = v
            .pointer("/data/keys")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        for k in keys {
            let full = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}/{k}")
            };
            match full.strip_suffix('/') {
                Some(dir) => self.walk(dir, out)?,
                None => out.push(full),
            }
        }
        Ok(())
    }
}

impl Store for VaultStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vault"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let mut folders = Vec::new();
        self.walk("", &mut folders)?;
        let mut out = Vec::new();
        for folder in folders {
            let Some((custom, updated)) = self.read_meta(&folder)? else {
                continue;
            };
            for (key, desc) in custom {
                if !names::valid_key(&key) {
                    continue;
                }
                let d = desc.as_str().unwrap_or("").to_string();
                let d = if d == NO_DESCRIPTION {
                    String::new()
                } else {
                    d
                };
                out.push(SecretInfo {
                    store: self.name.clone(),
                    name: format!("{folder}/{key}"),
                    description: (!d.is_empty()).then_some(d),
                    updated_at: updated.clone(),
                    alias_of: None,
                });
            }
        }
        Ok(out)
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let folder = match Self::folder_of(name) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let (data, _) = self.read_folder(folder)?;
        Ok(data
            .get(names::key_of(name))
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()> {
        let folder = Self::folder_of(name)?;
        let key = names::key_of(name);
        let (mut data, version) = self.read_folder(folder)?;
        data.insert(key.to_string(), json!(value));
        self.write_folder(folder, data, version)?;
        let mut custom = self.read_meta(folder)?.map(|m| m.0).unwrap_or_default();
        let keep = custom
            .get(key)
            .and_then(Value::as_str)
            .filter(|d| *d != NO_DESCRIPTION)
            .unwrap_or("")
            .to_string();
        let desc: String = description.unwrap_or(&keep).chars().take(500).collect();
        // Vault refuses an empty custom_metadata value, so no description is `-`.
        let desc = if desc.trim().is_empty() {
            NO_DESCRIPTION.to_string()
        } else {
            desc
        };
        custom.insert(key.to_string(), json!(desc));
        self.write_meta(folder, custom)
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let folder = Self::folder_of(name)?;
        let key = names::key_of(name);
        let (mut data, version) = self.read_folder(folder)?;
        let had = data.remove(key).is_some();
        if had {
            self.write_folder(folder, data, version)?;
        }
        if let Some((mut custom, _)) = self.read_meta(folder)?
            && custom.remove(key).is_some()
        {
            self.write_meta(folder, custom)?;
            return Ok(true);
        }
        Ok(had)
    }

    fn status(&self) -> Result<String> {
        let (_, v) = self.call("GET", "auth/token/lookup-self", None)?;
        let policies: Vec<String> = v
            .pointer("/data/policies")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let n = self.list()?.len();
        let base = self
            .conn
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.base.clone()))
            .unwrap_or_default();
        Ok(format!(
            "{base} mount `{}`, policies {}, {n} secrets",
            self.mount,
            policies.join(",")
        ))
    }
}

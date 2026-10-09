//! The config file: the stores, the order in which a name is looked up, the aliases and
//! the guard rules. It holds names only, never a value.
//!
//! ```toml
//! [[store]]
//! name = "local"
//! kind = "keyring"
//!
//! [[store]]
//! name = "vault"
//! kind = "vault"
//! address = "http://127.0.0.1:{port}"
//! mount = "agent"
//! auth = "kubernetes"
//! role = "sealkeep"
//! jwt_command = ["kubectl", "-n", "vault", "create", "token", "sealkeep", "--duration", "10m"]
//! port_forward = ["kubectl", "-n", "vault", "port-forward", "svc/vault", "{port}:8200"]
//!
//! [aliases]
//! "personal/example-app/dev/STRIPE_SECRET_KEY" = "shared/stripe/test/SECRET_KEY"
//!
//! [guard]
//! block_dotenv = true
//! ```
//!
//! With no file, sealkeep has one keyring store named `local`.

use crate::names;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const DEFAULT_KEYRING_SERVICE: &str = "sealkeep";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "store")]
    pub stores: Vec<StoreConfig>,
    /// `alias name -> target name`. A project folder can name a shared secret, so the
    /// value is stored one time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, String>,
    #[serde(default)]
    pub guard: GuardConfig,
    /// SSH keys that `ssh-load` (and `unlock`) adds to an agent.
    #[serde(default, rename = "ssh_key", skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<SshKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshKey {
    /// The private key file. `~/` is the home folder.
    pub path: String,
    /// The secret that holds its passphrase. Absent for a key with no passphrase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    /// The agent socket. Default: `$SSH_AUTH_SOCK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Refuse shell commands and file reads that print a `.env` file.
    #[serde(default = "yes")]
    pub block_dotenv: bool,
    /// More command prefixes to refuse, for example `vault kv get`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            block_dotenv: true,
            deny: Vec::new(),
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VaultAuth {
    /// A token in `$VAULT_TOKEN`, else in the keyring entry `vault-token:<store>`.
    Token,
    /// A Kubernetes ServiceAccount JWT from `jwt_command`, exchanged at
    /// `auth/<k8s_auth_mount>/login` for a short-lived Vault token.
    Kubernetes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum StoreConfig {
    Keyring {
        name: String,
        /// The service name of the keyring entries.
        #[serde(default = "default_service")]
        service: String,
    },
    Vault {
        name: String,
        /// The Vault address. `{port}` is the local port of `port_forward`.
        address: String,
        /// The KV v2 mount.
        mount: String,
        auth: VaultAuth,
        /// The role for Kubernetes auth.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        #[serde(default = "default_k8s_mount")]
        k8s_auth_mount: String,
        /// A command that prints a ServiceAccount JWT, for Kubernetes auth.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        jwt_command: Vec<String>,
        /// A command that forwards a local port to Vault while sealkeep runs. `{port}`
        /// is a free local port that sealkeep chooses.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        port_forward: Vec<String>,
    },
    /// AWS Secrets Manager through the `aws` CLI. One JSON secret for each folder,
    /// named `<prefix><folder>`.
    Aws {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        #[serde(default = "default_aws_prefix")]
        prefix: String,
        /// Another endpoint, for example a LocalStack test server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_url: Option<String>,
    },
    /// Google Secret Manager through the `gcloud` CLI. One secret for each name.
    Gcp { name: String, project: String },
    /// Azure Key Vault through the `az` CLI. One secret for each name.
    Azure { name: String, vault: String },
    /// 1Password through the `op` CLI. One item for each folder, one field for each key.
    Onepassword { name: String, vault: String },
    /// Bitwarden or Vaultwarden through the `bw` CLI. One item for each folder, one
    /// hidden field for each key. `bw` must be unlocked (`$BW_SESSION`).
    Bitwarden { name: String },
}

fn default_aws_prefix() -> String {
    "sealkeep/".to_string()
}

fn default_service() -> String {
    DEFAULT_KEYRING_SERVICE.to_string()
}

fn default_k8s_mount() -> String {
    "kubernetes".to_string()
}

impl StoreConfig {
    pub fn name(&self) -> &str {
        match self {
            StoreConfig::Keyring { name, .. }
            | StoreConfig::Vault { name, .. }
            | StoreConfig::Aws { name, .. }
            | StoreConfig::Gcp { name, .. }
            | StoreConfig::Azure { name, .. }
            | StoreConfig::Onepassword { name, .. }
            | StoreConfig::Bitwarden { name } => name,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stores: vec![StoreConfig::Keyring {
                name: "local".into(),
                service: default_service(),
            }],
            aliases: BTreeMap::new(),
            guard: GuardConfig::default(),
            ssh_keys: Vec::new(),
        }
    }
}

/// `$SEALKEEP_CONFIG`, else the config folder of the OS (`~/.config/sealkeep/config.toml`
/// on Linux, `~/Library/Application Support/sealkeep/config.toml` on macOS).
pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SEALKEEP_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let dirs = directories::ProjectDirs::from("", "", "sealkeep")
        .context("cannot find the home folder for the config file")?;
    Ok(dirs.config_dir().join("config.toml"))
}

impl Config {
    pub fn load() -> Result<Self> {
        let p = path()?;
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
        };
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse {}", p.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        self.validate()?;
        let p = path()?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self)?;
        let tmp = p.with_extension("toml.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &p).with_context(|| format!("write {}", p.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.stores.is_empty() {
            bail!("the config has no store");
        }
        let mut seen = std::collections::HashSet::new();
        for s in &self.stores {
            let n = s.name();
            if n.is_empty()
                || !n
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            {
                bail!("store name `{n}`: use a-z, 0-9 and -");
            }
            if !seen.insert(n) {
                bail!("two stores have the name `{n}`");
            }
            if let StoreConfig::Vault {
                address,
                mount,
                auth,
                role,
                jwt_command,
                port_forward,
                ..
            } = s
            {
                let local = address.starts_with("http://127.0.0.1")
                    || address.starts_with("http://localhost");
                if !(address.starts_with("https://") || local) {
                    bail!("store `{n}`: the Vault address must use https, or be a local port");
                }
                if address.contains("{port}") && port_forward.is_empty() {
                    bail!("store `{n}`: the address has {{port}}, so it needs port_forward");
                }
                if !port_forward.is_empty() && !port_forward.iter().any(|a| a.contains("{port}")) {
                    bail!("store `{n}`: port_forward needs the argument {{port}}");
                }
                if mount.is_empty() || mount.contains('/') {
                    bail!("store `{n}`: the mount is one path segment, for example `agent`");
                }
                if *auth == VaultAuth::Kubernetes && (role.is_none() || jwt_command.is_empty()) {
                    bail!("store `{n}`: Kubernetes auth needs `role` and `jwt_command`");
                }
            }
        }
        for k in &self.ssh_keys {
            if let Some(p) = &k.passphrase {
                names::check(p).with_context(|| format!("ssh_key `{}`", k.path))?;
            }
        }
        for (alias, target) in &self.aliases {
            names::check(alias).with_context(|| format!("alias `{alias}`"))?;
            names::check(target).with_context(|| format!("alias target `{target}`"))?;
            if self.aliases.contains_key(target) {
                bail!("alias `{alias}` points to `{target}`, which is also an alias");
            }
        }
        Ok(())
    }

    pub fn store(&self, name: &str) -> Result<&StoreConfig> {
        self.stores
            .iter()
            .find(|s| s.name() == name)
            .with_context(|| format!("no store named `{name}` (run `sealkeep store list`)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_both_kinds_and_aliases() {
        let cfg: Config = toml::from_str(
            r#"
            [[store]]
            name = "local"
            kind = "keyring"

            [[store]]
            name = "vault"
            kind = "vault"
            address = "http://127.0.0.1:{port}"
            mount = "agent"
            auth = "kubernetes"
            role = "sealkeep"
            jwt_command = ["kubectl", "create", "token", "sealkeep"]
            port_forward = ["kubectl", "port-forward", "svc/vault", "{port}:8200"]

            [aliases]
            "personal/example-app/dev/STRIPE_SECRET_KEY" = "shared/stripe/test/SECRET_KEY"
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.stores.len(), 2);
        assert_eq!(cfg.aliases.len(), 1);
        assert!(cfg.guard.block_dotenv);
    }

    #[test]
    fn rejects_bad_vault_and_alias_chains() {
        let mut cfg = Config::default();
        cfg.stores.push(StoreConfig::Vault {
            name: "vault".into(),
            address: "http://vault.example:8200".into(),
            mount: "agent".into(),
            auth: VaultAuth::Token,
            role: None,
            k8s_auth_mount: "kubernetes".into(),
            jwt_command: vec![],
            port_forward: vec![],
        });
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.aliases.insert("a/B".into(), "c/D".into());
        cfg.aliases.insert("c/D".into(), "e/F".into());
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.stores.push(cfg.stores[0].clone());
        assert!(cfg.validate().is_err());
    }
}

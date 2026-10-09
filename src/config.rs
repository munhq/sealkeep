//! The config file: which stores exist, and the order in which a bare name is looked up.
//!
//! ```toml
//! [[store]]
//! name = "local"
//! kind = "keyring"
//!
//! [[store]]
//! name = "team"
//! kind = "proxium"
//! url = "https://proxium.tech"
//! project = "acme"
//!
//! [guard]
//! block_dotenv = true
//! ```
//!
//! With no file, sealkeep has one keyring store named `local`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_KEYRING_SERVICE: &str = "sealkeep";
pub const DEFAULT_PROXIUM_CLIENT_ID: &str = "proxium-cli";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "store")]
    pub stores: Vec<StoreConfig>,
    #[serde(default)]
    pub guard: GuardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Refuse shell commands and file reads that print a `.env` file.
    #[serde(default = "yes")]
    pub block_dotenv: bool,
    /// More command prefixes to refuse, for example `vault kv get`.
    #[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum StoreConfig {
    Keyring {
        name: String,
        /// The service name of the keyring entries.
        #[serde(default = "default_service")]
        service: String,
    },
    Proxium {
        name: String,
        /// The Proxium origin, for example `https://proxium.tech`.
        url: String,
        /// The project slug.
        project: String,
        #[serde(default = "default_client_id")]
        client_id: String,
    },
}

fn default_service() -> String {
    DEFAULT_KEYRING_SERVICE.to_string()
}

fn default_client_id() -> String {
    DEFAULT_PROXIUM_CLIENT_ID.to_string()
}

impl StoreConfig {
    pub fn name(&self) -> &str {
        match self {
            StoreConfig::Keyring { name, .. } | StoreConfig::Proxium { name, .. } => name,
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
            guard: GuardConfig::default(),
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
            if let StoreConfig::Proxium { url, project, .. } = s {
                if !(url.starts_with("https://")
                    || url.starts_with("http://localhost")
                    || url.starts_with("http://127.0.0.1"))
                {
                    bail!("store `{n}`: the Proxium URL must use https");
                }
                if project.is_empty() {
                    bail!("store `{n}`: the project is empty");
                }
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
    fn parse_both_kinds() {
        let cfg: Config = toml::from_str(
            r#"
            [[store]]
            name = "local"
            kind = "keyring"

            [[store]]
            name = "team"
            kind = "proxium"
            url = "https://proxium.example"
            project = "acme"
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.stores.len(), 2);
        assert!(cfg.guard.block_dotenv);
        match &cfg.stores[1] {
            StoreConfig::Proxium { client_id, .. } => assert_eq!(client_id, "proxium-cli"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_plain_http_and_duplicates() {
        let mut cfg = Config::default();
        cfg.stores.push(StoreConfig::Proxium {
            name: "team".into(),
            url: "http://proxium.example".into(),
            project: "acme".into(),
            client_id: "proxium-cli".into(),
        });
        assert!(cfg.validate().is_err());
        let mut cfg = Config::default();
        cfg.stores.push(cfg.stores[0].clone());
        assert!(cfg.validate().is_err());
    }
}

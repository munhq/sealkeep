//! The secret stores. Each store keeps values under names; sealkeep reads a value only
//! to inject it into a command, and never prints it unless a person asks at a terminal.

pub mod keyring;
pub mod proxium;

use crate::config::{Config, StoreConfig};
use crate::names::SecretRef;
use anyhow::{Context, Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SecretInfo {
    pub store: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

pub trait Store {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    fn list(&self) -> Result<Vec<SecretInfo>>;
    /// The value, or `None` when the store has no secret of this name. `purpose` goes
    /// to the audit log of the store when it has one.
    fn get(&self, name: &str, purpose: &str) -> Result<Option<String>>;
    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()>;
    /// `true` when a secret was removed.
    fn remove(&self, name: &str) -> Result<bool>;
    /// One line for `doctor`. An error means the store cannot be used now.
    fn status(&self) -> Result<String>;
}

pub fn open(cfg: &StoreConfig) -> Box<dyn Store> {
    match cfg {
        StoreConfig::Keyring { name, service } => {
            Box::new(keyring::KeyringStore::new(name.clone(), service.clone()))
        }
        StoreConfig::Proxium {
            name,
            url,
            project,
            client_id,
        } => Box::new(proxium::ProxiumStore::new(
            name.clone(),
            url.clone(),
            project.clone(),
            client_id.clone(),
        )),
    }
}

pub struct Stores {
    pub stores: Vec<Box<dyn Store>>,
}

/// A resolved secret. `value` lives only in memory, for the run that needs it.
pub struct Resolved {
    pub reference: SecretRef,
    pub store: String,
    pub value: String,
}

impl Stores {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            stores: cfg.stores.iter().map(open).collect(),
        }
    }

    pub fn by_name(&self, name: &str) -> Result<&dyn Store> {
        self.stores
            .iter()
            .find(|s| s.name() == name)
            .map(|s| s.as_ref())
            .with_context(|| format!("no store named `{name}` (run `sealkeep store list`)"))
    }

    /// The store for a write: the named one, else the first in the config.
    pub fn for_write(&self, name: Option<&str>) -> Result<&dyn Store> {
        match name {
            Some(n) => self.by_name(n),
            None => self
                .stores
                .first()
                .map(|s| s.as_ref())
                .context("the config has no store"),
        }
    }

    /// Find each secret. A bare name is looked up in the stores in config order.
    pub fn resolve(&self, refs: &[SecretRef], purpose: &str) -> Result<Vec<Resolved>> {
        let mut out = Vec::with_capacity(refs.len());
        for r in refs {
            out.push(self.resolve_one(r, purpose)?);
        }
        Ok(out)
    }

    fn resolve_one(&self, r: &SecretRef, purpose: &str) -> Result<Resolved> {
        if let Some(store) = &r.store {
            let s = self.by_name(store)?;
            return match s.get(&r.name, purpose)? {
                Some(value) => Ok(Resolved {
                    reference: r.clone(),
                    store: s.name().to_string(),
                    value,
                }),
                None => bail!("store `{store}` has no secret `{}`", r.name),
            };
        }
        let mut errors = Vec::new();
        for s in &self.stores {
            match s.get(&r.name, purpose) {
                Ok(Some(value)) => {
                    return Ok(Resolved {
                        reference: r.clone(),
                        store: s.name().to_string(),
                        value,
                    });
                }
                Ok(None) => {}
                Err(e) => errors.push(format!("{}: {e:#}", s.name())),
            }
        }
        if errors.is_empty() {
            bail!(
                "no store has a secret `{}` (run `sealkeep list` to see the names)",
                r.name
            );
        }
        bail!(
            "no store gave the secret `{}`; errors: {}",
            r.name,
            errors.join("; ")
        )
    }

    /// The names in every store. A store that fails adds an error line.
    pub fn list_all(&self) -> (Vec<SecretInfo>, Vec<String>) {
        let mut all = Vec::new();
        let mut errors = Vec::new();
        for s in &self.stores {
            match s.list() {
                Ok(mut l) => all.append(&mut l),
                Err(e) => errors.push(format!("{}: {e:#}", s.name())),
            }
        }
        (all, errors)
    }
}

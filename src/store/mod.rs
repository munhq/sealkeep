//! The secret stores. Each store keeps values under names; sealkeep reads a value only
//! to inject it into a command, and never prints it unless a person asks at a terminal.

pub mod keyring;
pub mod vault;

use crate::config::{Config, StoreConfig};
use crate::names::{self, Binding, SecretRef};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize)]
pub struct SecretInfo {
    pub store: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// For an alias: the name it points to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
}

pub trait Store {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    fn list(&self) -> Result<Vec<SecretInfo>>;
    /// The value, or `None` when the store has no secret of this name.
    fn get(&self, name: &str) -> Result<Option<String>>;
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
        StoreConfig::Vault { .. } => Box::new(vault::VaultStore::new(cfg.clone())),
    }
}

pub struct Stores {
    pub stores: Vec<Box<dyn Store>>,
    pub aliases: BTreeMap<String, String>,
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
            aliases: cfg.aliases.clone(),
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

    /// Find each secret. An alias resolves to its target. A name with no store is looked
    /// up in the stores in config order.
    pub fn resolve(&self, refs: &[SecretRef]) -> Result<Vec<Resolved>> {
        refs.iter().map(|r| self.resolve_one(r)).collect()
    }

    fn resolve_one(&self, r: &SecretRef) -> Result<Resolved> {
        let target = self.aliases.get(&r.name).cloned();
        let lookup = target.as_deref().unwrap_or(&r.name);
        if let Some(store) = &r.store {
            let s = self.by_name(store)?;
            return match s.get(lookup)? {
                Some(value) => Ok(Resolved {
                    reference: r.clone(),
                    store: s.name().to_string(),
                    value,
                }),
                None => bail!("store `{store}` has no secret `{lookup}`"),
            };
        }
        let mut errors = Vec::new();
        for s in &self.stores {
            match s.get(lookup) {
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
        let shown = match &target {
            Some(t) => format!("`{}` (an alias of `{t}`)", r.name),
            None => format!("`{}`", r.name),
        };
        if errors.is_empty() {
            bail!("no store has a secret {shown} (run `sealkeep list` to see the names)");
        }
        bail!(
            "no store gave the secret {shown}; errors: {}",
            errors.join("; ")
        )
    }

    /// The names in every store and the aliases. A store that fails adds an error line.
    pub fn list_all(&self) -> (Vec<SecretInfo>, Vec<String>) {
        let mut all = Vec::new();
        let mut errors = Vec::new();
        for s in &self.stores {
            match s.list() {
                Ok(mut l) => all.append(&mut l),
                Err(e) => errors.push(format!("{}: {e:#}", s.name())),
            }
        }
        for (alias, target) in &self.aliases {
            all.push(SecretInfo {
                store: "alias".into(),
                name: alias.clone(),
                description: None,
                updated_at: None,
                alias_of: Some(target.clone()),
            });
        }
        (all, errors)
    }

    /// One binding for each secret in `folder` and below, by the key of its name. Two
    /// secrets with the same key are an error, because one variable cannot hold both.
    pub fn folder_bindings(&self, folder: &str, store: Option<&str>) -> Result<Vec<Binding>> {
        names::check_prefix(folder)?;
        let (items, errors) = match store {
            Some(s) => (self.by_name(s)?.list()?, Vec::new()),
            None => self.list_all(),
        };
        if !errors.is_empty() {
            bail!("cannot list every store: {}", errors.join("; "));
        }
        let mut by_key: HashMap<String, String> = HashMap::new();
        let mut out = Vec::new();
        for i in items.iter().filter(|i| names::under(&i.name, folder)) {
            let key = names::key_of(&i.name).to_string();
            match by_key.get(&key) {
                Some(n) if n == &i.name => continue,
                Some(n) => bail!(
                    "`{n}` and `{}` both set {key}; name a deeper folder, or use -e for one of them",
                    i.name
                ),
                None => {}
            }
            by_key.insert(key.clone(), i.name.clone());
            out.push(Binding {
                var: key,
                secret: SecretRef {
                    store: store.map(str::to_string),
                    name: i.name.clone(),
                },
            });
        }
        if out.is_empty() {
            bail!("the folder `{folder}` has no secret (run `sealkeep list {folder}`)");
        }
        Ok(out)
    }
}

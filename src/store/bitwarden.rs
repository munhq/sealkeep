//! Bitwarden (or a self-hosted Vaultwarden) through the `bw` CLI.
//!
//! One Secure Note for each folder, named `sealkeep:<folder>`, with one hidden custom
//! field for each key. `bw create item` and `bw edit item` read the base64-encoded item
//! JSON from stdin, so no value is in the arguments of the command. `bw` must be
//! unlocked: `export BW_SESSION=$(bw unlock --raw)`.
//!
//! The Secrets Manager CLI (`bws`) takes a value only as a command argument, which the
//! process list shows, so this store uses the password manager CLI.

use super::cli;
use super::{SecretInfo, Store};
use crate::names;
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

pub struct BwStore {
    pub name: String,
}

const PREFIX: &str = "sealkeep:";
/// The type of a hidden custom field.
const HIDDEN: u64 = 1;

impl BwStore {
    fn bw(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<cli::Output> {
        let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        a.push("--nointeraction".into());
        let out = cli::run("bw", &a, stdin, &[])?;
        if out.status != 0
            && (out.stderr.contains("Vault is locked") || out.stderr.contains("not logged in"))
        {
            bail!("bw is locked: run `export BW_SESSION=$(bw unlock --raw)`, then try again");
        }
        Ok(out)
    }

    fn items(&self) -> Result<Vec<Value>> {
        let out = self
            .bw(&["list", "items", "--search", PREFIX], None)?
            .ok("bw list items")?;
        let v: Value = serde_json::from_str(&out.stdout).context("parse the bw output")?;
        Ok(v.as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i["name"].as_str().is_some_and(|n| n.starts_with(PREFIX)))
            .collect())
    }

    fn item(&self, folder: &str) -> Result<Option<Value>> {
        let want = format!("{PREFIX}{folder}");
        Ok(self
            .items()?
            .into_iter()
            .find(|i| i["name"].as_str() == Some(want.as_str())))
    }

    fn encode(item: &Value) -> Result<Vec<u8>> {
        Ok(STANDARD.encode(serde_json::to_vec(item)?).into_bytes())
    }
}

impl Store for BwStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "bitwarden"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let mut list = Vec::new();
        for it in self.items()? {
            let Some(folder) = it["name"].as_str().and_then(|n| n.strip_prefix(PREFIX)) else {
                continue;
            };
            if !names::valid_prefix(folder) {
                continue;
            }
            for f in it["fields"].as_array().cloned().unwrap_or_default() {
                let Some(key) = f["name"].as_str() else {
                    continue;
                };
                if names::valid_key(key) {
                    list.push(SecretInfo {
                        store: self.name.clone(),
                        name: format!("{folder}/{key}"),
                        description: None,
                        updated_at: it["revisionDate"].as_str().map(str::to_string),
                        alias_of: None,
                    });
                }
            }
        }
        Ok(list)
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let folder = names::folder_of(name);
        if folder.is_empty() {
            return Ok(None);
        }
        let key = names::key_of(name);
        Ok(self.item(folder)?.and_then(|it| {
            it["fields"]
                .as_array()?
                .iter()
                .find(|f| f["name"].as_str() == Some(key))
                .and_then(|f| f["value"].as_str())
                .map(str::to_string)
        }))
    }

    fn set(&self, name: &str, value: &str, _description: Option<&str>) -> Result<()> {
        let folder = names::folder_of(name);
        if folder.is_empty() {
            bail!("`{name}`: the bitwarden store needs a folder in the name");
        }
        let key = names::key_of(name);
        match self.item(folder)? {
            Some(mut it) => {
                let id = it["id"].as_str().context("the item has no id")?.to_string();
                if !it["fields"].is_array() {
                    it["fields"] = json!([]);
                }
                let fields = it["fields"].as_array_mut().expect("checked");
                match fields.iter_mut().find(|f| f["name"].as_str() == Some(key)) {
                    Some(f) => f["value"] = json!(value),
                    None => fields.push(json!({ "name": key, "value": value, "type": HIDDEN })),
                }
                self.bw(&["edit", "item", &id], Some(&Self::encode(&it)?))?
                    .ok(&format!("bw edit item {folder}"))?;
            }
            None => {
                let it = json!({
                    "type": 2,
                    "name": format!("{PREFIX}{folder}"),
                    "notes": "Managed by sealkeep: one hidden field for each key.",
                    "secureNote": { "type": 0 },
                    "fields": [{ "name": key, "value": value, "type": HIDDEN }],
                    "favorite": false,
                    "reprompt": 0,
                });
                self.bw(&["create", "item"], Some(&Self::encode(&it)?))?
                    .ok(&format!("bw create item {folder}"))?;
            }
        }
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let folder = names::folder_of(name);
        let Some(mut it) = self.item(folder)? else {
            return Ok(false);
        };
        let id = it["id"].as_str().context("the item has no id")?.to_string();
        let key = names::key_of(name);
        let Some(fields) = it["fields"].as_array_mut() else {
            return Ok(false);
        };
        let before = fields.len();
        fields.retain(|f| f["name"].as_str() != Some(key));
        if fields.len() == before {
            return Ok(false);
        }
        self.bw(&["edit", "item", &id], Some(&Self::encode(&it)?))?
            .ok(&format!("bw edit item {folder}"))?;
        Ok(true)
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!("Bitwarden, {n} secrets"))
    }
}

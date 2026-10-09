//! 1Password through the `op` CLI (2.23 or later).
//!
//! One item for each folder: a Secure Note whose title is the folder, with the tag
//! `sealkeep`, and one concealed field for each key in the section `sealkeep`. A new
//! item goes to `op item create -` as a JSON template on stdin; a change goes to
//! `op item edit <id>` as the whole item JSON on stdin. Neither puts a value in the
//! arguments of the command.

use super::cli;
use super::{SecretInfo, Store};
use crate::names;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

pub struct OpStore {
    pub name: String,
    pub vault: String,
}

const TAG: &str = "sealkeep";
const SECTION: &str = "sealkeep";

impl OpStore {
    fn op(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<cli::Output> {
        let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        a.extend(["--vault".into(), self.vault.clone()]);
        cli::run("op", &a, stdin, &[])
    }

    /// The item of a folder, or `None`.
    fn item(&self, folder: &str) -> Result<Option<Value>> {
        let out = self.op(&["item", "get", folder, "--format", "json"], None)?;
        if out.status != 0 {
            if out.stderr.contains("isn't an item") || out.stderr.contains("not found") {
                return Ok(None);
            }
            bail!("op item get {folder} failed: {}", out.err_line());
        }
        let v: Value = serde_json::from_str(&out.stdout).context("parse the op output")?;
        if v["title"].as_str() != Some(folder) {
            return Ok(None);
        }
        Ok(Some(v))
    }

    fn ours(field: &Value) -> bool {
        field["section"]["id"].as_str() == Some(SECTION)
    }

    fn field_index(item: &Value, key: &str) -> Option<usize> {
        item["fields"]
            .as_array()?
            .iter()
            .position(|f| Self::ours(f) && f["label"].as_str() == Some(key))
    }

    fn field(key: &str, value: &str) -> Value {
        json!({
            "id": format!("sk_{key}"),
            "section": { "id": SECTION, "label": SECTION },
            "type": "CONCEALED",
            "label": key,
            "value": value,
        })
    }
}

impl Store for OpStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "1password"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let out = self
            .op(&["item", "list", "--tags", TAG, "--format", "json"], None)?
            .ok("op item list")?;
        let items: Value = serde_json::from_str(&out.stdout).context("parse the op output")?;
        let mut list = Vec::new();
        for it in items.as_array().cloned().unwrap_or_default() {
            let Some(folder) = it["title"].as_str() else {
                continue;
            };
            if !names::valid_prefix(folder) {
                continue;
            }
            let Some(item) = self.item(folder)? else {
                continue;
            };
            for f in item["fields"].as_array().cloned().unwrap_or_default() {
                let Some(key) = f["label"].as_str() else {
                    continue;
                };
                if Self::ours(&f) && names::valid_key(key) {
                    list.push(SecretInfo {
                        store: self.name.clone(),
                        name: format!("{folder}/{key}"),
                        description: None,
                        updated_at: it["updated_at"].as_str().map(str::to_string),
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
        let Some(item) = self.item(folder)? else {
            return Ok(None);
        };
        let Some(i) = Self::field_index(&item, names::key_of(name)) else {
            return Ok(None);
        };
        Ok(item["fields"][i]["value"].as_str().map(str::to_string))
    }

    fn set(&self, name: &str, value: &str, _description: Option<&str>) -> Result<()> {
        let folder = names::folder_of(name);
        if folder.is_empty() {
            bail!("`{name}`: the 1password store needs a folder in the name");
        }
        let key = names::key_of(name);
        match self.item(folder)? {
            Some(mut item) => {
                let id = item["id"]
                    .as_str()
                    .context("the item has no id")?
                    .to_string();
                match Self::field_index(&item, key) {
                    Some(i) => item["fields"][i]["value"] = json!(value),
                    None => {
                        if !item["fields"].is_array() {
                            item["fields"] = json!([]);
                        }
                        item["fields"]
                            .as_array_mut()
                            .expect("checked")
                            .push(Self::field(key, value));
                        let has_section = item["sections"]
                            .as_array()
                            .is_some_and(|s| s.iter().any(|x| x["id"] == SECTION));
                        if !has_section {
                            if !item["sections"].is_array() {
                                item["sections"] = json!([]);
                            }
                            item["sections"]
                                .as_array_mut()
                                .expect("checked")
                                .push(json!({ "id": SECTION, "label": SECTION }));
                        }
                    }
                }
                let body = serde_json::to_vec(&item)?;
                self.op(&["item", "edit", &id], Some(&body))?
                    .ok(&format!("op item edit {folder}"))?;
            }
            None => {
                let template = json!({
                    "title": folder,
                    "category": "SECURE_NOTE",
                    "tags": [TAG],
                    "sections": [{ "id": SECTION, "label": SECTION }],
                    "fields": [
                        {
                            "id": "notesPlain",
                            "type": "STRING",
                            "purpose": "NOTES",
                            "label": "notesPlain",
                            "value": "Managed by sealkeep: one concealed field for each key.",
                        },
                        Self::field(key, value),
                    ],
                });
                let body = serde_json::to_vec(&template)?;
                self.op(&["item", "create", "-"], Some(&body))?
                    .ok(&format!("op item create {folder}"))?;
            }
        }
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let folder = names::folder_of(name);
        let Some(mut item) = self.item(folder)? else {
            return Ok(false);
        };
        let Some(i) = Self::field_index(&item, names::key_of(name)) else {
            return Ok(false);
        };
        let id = item["id"]
            .as_str()
            .context("the item has no id")?
            .to_string();
        item["fields"].as_array_mut().expect("checked").remove(i);
        // 1Password keeps the earlier versions of the item.
        let body = serde_json::to_vec(&item)?;
        self.op(&["item", "edit", &id], Some(&body))?
            .ok(&format!("op item edit {folder}"))?;
        Ok(true)
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!("1Password vault `{}`, {n} secrets", self.vault))
    }
}

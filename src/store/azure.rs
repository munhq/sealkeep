//! Azure Key Vault through the `az` CLI.
//!
//! One secret for each name. A secret name allows `[0-9a-zA-Z-]` and 127 characters
//! only, so the name comes from `cli::safe_id`, and the tags `sealkeep-name` and
//! `sealkeep-description` hold the name and its description. A value goes to `az` in a
//! file that only the user can read (`--file`).
//!
//! `rm` deletes a secret, which Key Vault keeps in its soft-delete state. A later `set`
//! of the same name recovers it first, because Key Vault refuses a new secret with the
//! name of a deleted one.

use super::cli::{self, SecretFile};
use super::{SecretInfo, Store};
use crate::names;
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub struct AzureStore {
    pub name: String,
    pub vault: String,
}

const NAME_TAG: &str = "sealkeep-name";
const DESC_TAG: &str = "sealkeep-description";

impl AzureStore {
    fn az(&self, args: &[&str]) -> Result<cli::Output> {
        let mut a: Vec<String> = vec!["keyvault".into(), "secret".into()];
        a.extend(args.iter().map(|s| s.to_string()));
        a.extend([
            "--vault-name".into(),
            self.vault.clone(),
            "--only-show-errors".into(),
        ]);
        cli::run("az", &a, None, &[])
    }

    fn id(name: &str) -> String {
        cli::safe_id(name, false, 127)
    }

    fn not_found(out: &cli::Output) -> bool {
        out.stderr.contains("SecretNotFound") || out.stderr.contains("was not found")
    }

    fn put(&self, id: &str, file: &SecretFile, name: &str, desc: &str) -> Result<cli::Output> {
        let name_tag = format!("{NAME_TAG}={name}");
        let desc_tag = format!("{DESC_TAG}={desc}");
        let path = file.display();
        self.az(&[
            "set",
            "--name",
            id,
            "--file",
            &path,
            "--encoding",
            "utf-8",
            "--tags",
            &name_tag,
            &desc_tag,
            "--output",
            "none",
        ])
    }
}

impl Store for AzureStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "azure"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let out = self
            .az(&["list", "--output", "json"])?
            .ok("az keyvault secret list")?;
        let v: Value = serde_json::from_str(&out.stdout).context("parse the az output")?;
        let mut list = Vec::new();
        for s in v.as_array().cloned().unwrap_or_default() {
            let tags = &s["tags"];
            let Some(name) = tags[NAME_TAG].as_str() else {
                continue;
            };
            if !names::valid(name) {
                continue;
            }
            let d = tags[DESC_TAG].as_str().unwrap_or("");
            list.push(SecretInfo {
                store: self.name.clone(),
                name: name.to_string(),
                description: (!d.is_empty() && d != "-").then(|| d.to_string()),
                updated_at: s["attributes"]["updated"].as_str().map(str::to_string),
                alias_of: None,
            });
        }
        Ok(list)
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let id = Self::id(name);
        let out = self.az(&["show", "--name", &id, "--output", "json"])?;
        if out.status != 0 {
            if Self::not_found(&out) {
                return Ok(None);
            }
            bail!("az keyvault secret show {id} failed: {}", out.err_line());
        }
        let v: Value = serde_json::from_str(&out.stdout)?;
        Ok(v["value"].as_str().map(str::to_string))
    }

    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()> {
        let id = Self::id(name);
        let desc: String = description
            .filter(|d| !d.trim().is_empty())
            .unwrap_or("-")
            .chars()
            .take(250)
            .collect();
        let file = SecretFile::new(value.as_bytes())?;
        let out = self.put(&id, &file, name, &desc)?;
        if out.status == 0 {
            return Ok(());
        }
        if !out.stderr.contains("ObjectIsDeletedButRecoverable")
            && !out.stderr.contains("deleted but recoverable")
        {
            bail!("az keyvault secret set {id} failed: {}", out.err_line());
        }
        self.az(&["recover", "--name", &id, "--output", "none"])?
            .ok(&format!("az keyvault secret recover {id}"))?;
        // The recovery finishes in the background; try the write again for up to 30 s.
        let mut last = String::new();
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let out = self.put(&id, &file, name, &desc)?;
            if out.status == 0 {
                return Ok(());
            }
            last = out.err_line();
        }
        bail!("az keyvault secret set {id} failed after the recovery: {last}")
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let id = Self::id(name);
        let out = self.az(&["delete", "--name", &id, "--output", "none"])?;
        if out.status != 0 {
            if Self::not_found(&out) {
                return Ok(false);
            }
            bail!("az keyvault secret delete {id} failed: {}", out.err_line());
        }
        Ok(true)
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!("Azure Key Vault `{}`, {n} secrets", self.vault))
    }
}

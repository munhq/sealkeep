//! AWS Secrets Manager through the `aws` CLI.
//!
//! Layout: one secret for each folder, named `<prefix><folder>`, that holds a JSON object
//! of the keys: `shared/stripe/test/SECRET_KEY` is the field `SECRET_KEY` of the secret
//! `sealkeep/shared/stripe/test`. The JSON goes to the CLI as `file://` of a file that
//! only the user can read.

use super::cli::{self, SecretFile};
use super::{SecretInfo, Store};
use crate::names;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

pub struct AwsStore {
    pub name: String,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub prefix: String,
    pub endpoint_url: Option<String>,
}

impl AwsStore {
    fn aws(&self, args: &[&str]) -> Result<cli::Output> {
        let mut a: Vec<String> = vec!["secretsmanager".into()];
        a.extend(args.iter().map(|s| s.to_string()));
        if let Some(r) = &self.region {
            a.extend(["--region".into(), r.clone()]);
        }
        if let Some(p) = &self.profile {
            a.extend(["--profile".into(), p.clone()]);
        }
        if let Some(e) = &self.endpoint_url {
            a.extend(["--endpoint-url".into(), e.clone()]);
        }
        a.extend(["--output".into(), "json".into()]);
        cli::run("aws", &a, None, &[("AWS_PAGER", "")])
    }

    fn secret_id(&self, folder: &str) -> String {
        format!("{}{folder}", self.prefix)
    }

    /// The fields of a folder, or `None` when its secret does not exist.
    fn read(&self, folder: &str) -> Result<Option<Map<String, Value>>> {
        let id = self.secret_id(folder);
        let out = self.aws(&["get-secret-value", "--secret-id", &id])?;
        if out.status != 0 {
            if out.stderr.contains("ResourceNotFoundException") {
                return Ok(None);
            }
            bail!("aws get-secret-value {id} failed: {}", out.err_line());
        }
        let v: Value = serde_json::from_str(&out.stdout).context("parse the aws output")?;
        let s = v["SecretString"].as_str().unwrap_or("{}");
        let data: Value = serde_json::from_str(s).unwrap_or(Value::Object(Map::new()));
        Ok(Some(data.as_object().cloned().unwrap_or_default()))
    }

    fn write(&self, folder: &str, data: &Map<String, Value>, exists: bool) -> Result<()> {
        let id = self.secret_id(folder);
        let file = SecretFile::new(serde_json::to_string(data)?.as_bytes())?;
        let arg = format!("file://{}", file.display());
        let out = if exists {
            self.aws(&[
                "put-secret-value",
                "--secret-id",
                &id,
                "--secret-string",
                &arg,
            ])?
        } else {
            self.aws(&[
                "create-secret",
                "--name",
                &id,
                "--description",
                "sealkeep folder",
                "--secret-string",
                &arg,
            ])?
        };
        out.ok(&format!("aws write {id}"))?;
        Ok(())
    }
}

impl Store for AwsStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "aws"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let filter = format!("Key=name,Values={}", self.prefix);
        let mut out_list = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut args = vec!["list-secrets", "--filters", filter.as_str()];
            if let Some(t) = &token {
                args.extend(["--next-token", t.as_str()]);
            }
            let out = self.aws(&args)?.ok("aws list-secrets")?;
            let v: Value = serde_json::from_str(&out.stdout)?;
            for s in v["SecretList"].as_array().cloned().unwrap_or_default() {
                let Some(full) = s["Name"].as_str() else {
                    continue;
                };
                let Some(folder) = full.strip_prefix(&self.prefix) else {
                    continue;
                };
                if !names::valid_prefix(folder) {
                    continue;
                }
                let updated = s["LastChangedDate"].as_str().map(str::to_string);
                for key in self.read(folder)?.unwrap_or_default().keys() {
                    if names::valid_key(key) {
                        out_list.push(SecretInfo {
                            store: self.name.clone(),
                            name: format!("{folder}/{key}"),
                            description: None,
                            updated_at: updated.clone(),
                            alias_of: None,
                        });
                    }
                }
            }
            token = v["NextToken"].as_str().map(str::to_string);
            if token.is_none() {
                break;
            }
        }
        Ok(out_list)
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let folder = names::folder_of(name);
        if folder.is_empty() {
            return Ok(None);
        }
        Ok(self.read(folder)?.and_then(|d| {
            d.get(names::key_of(name))
                .and_then(Value::as_str)
                .map(str::to_string)
        }))
    }

    fn set(&self, name: &str, value: &str, _description: Option<&str>) -> Result<()> {
        let folder = names::folder_of(name);
        if folder.is_empty() {
            bail!("`{name}`: the aws store needs a folder in the name");
        }
        let existing = self.read(folder)?;
        let exists = existing.is_some();
        let mut data = existing.unwrap_or_default();
        data.insert(names::key_of(name).to_string(), Value::from(value));
        self.write(folder, &data, exists)
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let folder = names::folder_of(name);
        let Some(mut data) = self.read(folder)? else {
            return Ok(false);
        };
        if data.remove(names::key_of(name)).is_none() {
            return Ok(false);
        }
        // An empty folder stays as a secret with `{}`; AWS keeps the old versions.
        self.write(folder, &data, true)?;
        Ok(true)
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!(
            "AWS Secrets Manager, prefix `{}`{}, {n} secrets",
            self.prefix,
            self.region
                .as_deref()
                .map(|r| format!(", region {r}"))
                .unwrap_or_default()
        ))
    }
}

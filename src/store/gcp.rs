//! Google Secret Manager through the `gcloud` CLI.
//!
//! One secret for each name. A secret ID allows `[A-Za-z0-9_-]` only, so the ID comes
//! from `cli::safe_id`, and the annotations `sealkeep-name` and `sealkeep-description`
//! hold the name and its description. A value goes to `gcloud` on stdin
//! (`--data-file=-`).

use super::cli;
use super::{SecretInfo, Store};
use crate::names;
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub struct GcpStore {
    pub name: String,
    pub project: String,
}

const NAME_KEY: &str = "sealkeep-name";
const DESC_KEY: &str = "sealkeep-description";

impl GcpStore {
    fn gcloud(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<cli::Output> {
        let mut a: Vec<String> = vec!["secrets".into()];
        a.extend(args.iter().map(|s| s.to_string()));
        a.extend([format!("--project={}", self.project), "--quiet".into()]);
        cli::run("gcloud", &a, stdin, &[])
    }

    fn id(name: &str) -> String {
        cli::safe_id(name, true, 255)
    }

    /// `--update-annotations` in the `^;^` form, so a value can hold a comma.
    fn annotations(name: &str, description: Option<&str>) -> String {
        let mut s = format!("^;^{NAME_KEY}={name}");
        if let Some(d) = description {
            let d: String = d.replace(';', ",").chars().take(500).collect();
            s.push_str(&format!(";{DESC_KEY}={d}"));
        }
        s
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let out = self.gcloud(&["describe", id, "--format=json"], None)?;
        if out.status == 0 {
            return Ok(true);
        }
        if out.stderr.contains("NOT_FOUND") || out.stderr.contains("not found") {
            return Ok(false);
        }
        bail!("gcloud secrets describe {id} failed: {}", out.err_line())
    }
}

impl Store for GcpStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "gcp"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let out = self
            .gcloud(&["list", "--format=json"], None)?
            .ok("gcloud secrets list")?;
        let v: Value = serde_json::from_str(&out.stdout).context("parse the gcloud output")?;
        let mut list = Vec::new();
        for s in v.as_array().cloned().unwrap_or_default() {
            let ann = &s["annotations"];
            let Some(name) = ann[NAME_KEY].as_str() else {
                continue;
            };
            if !names::valid(name) {
                continue;
            }
            list.push(SecretInfo {
                store: self.name.clone(),
                name: name.to_string(),
                description: ann[DESC_KEY].as_str().map(str::to_string),
                updated_at: s["createTime"].as_str().map(str::to_string),
                alias_of: None,
            });
        }
        Ok(list)
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        let id = Self::id(name);
        let out = self.gcloud(
            &["versions", "access", "latest", &format!("--secret={id}")],
            None,
        )?;
        if out.status != 0 {
            if out.stderr.contains("NOT_FOUND") || out.stderr.contains("not found") {
                return Ok(None);
            }
            bail!(
                "gcloud secrets versions access {id} failed: {}",
                out.err_line()
            );
        }
        Ok(Some(out.stdout))
    }

    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()> {
        let id = Self::id(name);
        let ann = Self::annotations(name, description);
        if self.exists(&id)? {
            self.gcloud(
                &["versions", "add", &id, "--data-file=-"],
                Some(value.as_bytes()),
            )?
            .ok(&format!("gcloud secrets versions add {id}"))?;
            if description.is_some() {
                self.gcloud(
                    &["update", &id, &format!("--update-annotations={ann}")],
                    None,
                )?
                .ok(&format!("gcloud secrets update {id}"))?;
            }
        } else {
            self.gcloud(
                &[
                    "create",
                    &id,
                    "--replication-policy=automatic",
                    "--data-file=-",
                    &format!("--annotations={ann}"),
                ],
                Some(value.as_bytes()),
            )?
            .ok(&format!("gcloud secrets create {id}"))?;
        }
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let id = Self::id(name);
        if !self.exists(&id)? {
            return Ok(false);
        }
        self.gcloud(&["delete", &id], None)?
            .ok(&format!("gcloud secrets delete {id}"))?;
        Ok(true)
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!(
            "Google Secret Manager, project `{}`, {n} secrets",
            self.project
        ))
    }
}

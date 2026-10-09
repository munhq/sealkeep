//! A Proxium project as a store.
//!
//! Proxium seals each value with the data key of the project and logs each reveal with
//! the person and the purpose. sealkeep signs in with the device flow of RFC 8628 and
//! keeps the session token in the OS keyring. For each call it exchanges the session
//! for a JWT that is valid for 15 minutes.
//!
//! API (Proxium `/api/teams/{project}/secrets`):
//! - `GET    …/secrets`                 the names
//! - `PUT    …/secrets/{name}`          write a value (owners)
//! - `DELETE …/secrets/{name}`          remove (owners)
//! - `POST   …/secrets/{name}/reveal`   the value, logged with the purpose

use super::{SecretInfo, Store, keyring};
use crate::config::DEFAULT_KEYRING_SERVICE;
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use ureq::Agent;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub struct ProxiumStore {
    name: String,
    url: String,
    project: String,
    client_id: String,
    agent: Agent,
}

#[derive(Deserialize)]
struct ListReply {
    secrets: Vec<ListItem>,
}

#[derive(Deserialize)]
struct ListItem {
    name: String,
    description: Option<String>,
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct RevealReply {
    value: String,
}

#[derive(Deserialize)]
struct TokenReply {
    token: String,
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

fn agent() -> Agent {
    let cfg = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(concat!("sealkeep/", env!("CARGO_PKG_VERSION")))
        .build();
    Agent::new_with_config(cfg)
}

/// The error text of a Proxium reply: `{"error": {"code", "message"}}` or
/// `{"error": "...", "error_description": "..."}`.
fn reply_error(status: u16, body: &str) -> anyhow::Error {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let code = v
        .pointer("/error/code")
        .or_else(|| v.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let msg = v
        .pointer("/error/message")
        .or_else(|| v.get("error_description"))
        .or_else(|| v.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if code.is_empty() && msg.is_empty() {
        anyhow!("HTTP {status}")
    } else {
        anyhow!("HTTP {status} {code}: {msg}")
    }
}

impl ProxiumStore {
    pub fn new(name: String, url: String, project: String, client_id: String) -> Self {
        Self {
            name,
            url: url.trim_end_matches('/').to_string(),
            project,
            client_id,
            agent: agent(),
        }
    }

    fn session_user(&self) -> String {
        format!("proxium-session:{}", self.name)
    }

    fn session(&self) -> Result<String> {
        keyring::read(DEFAULT_KEYRING_SERVICE, &self.session_user())?.with_context(|| {
            format!(
                "store `{}` is not signed in (run `sealkeep login {}`)",
                self.name, self.name
            )
        })
    }

    /// A JWT for the gateway, from the session.
    fn jwt(&self) -> Result<String> {
        let session = self.session()?;
        let mut resp = self
            .agent
            .get(format!("{}/api/auth/token", self.url))
            .header("Authorization", format!("Bearer {session}"))
            .call()
            .with_context(|| format!("reach {}", self.url))?;
        let status = resp.status().as_u16();
        if status == 401 {
            bail!(
                "the session of store `{}` has expired (run `sealkeep login {}`)",
                self.name,
                self.name
            );
        }
        if status != 200 {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(reply_error(status, &body)).context("get a token from Proxium");
        }
        Ok(resp.body_mut().read_json::<TokenReply>()?.token)
    }

    fn secrets_url(&self) -> String {
        format!("{}/api/teams/{}/secrets", self.url, self.project)
    }

    /// Sign in with the device flow and keep the session in the keyring.
    pub fn login(&self, open_browser: bool) -> Result<()> {
        let mut resp = self
            .agent
            .post(format!("{}/api/auth/device/code", self.url))
            .send_json(json!({ "client_id": self.client_id }))
            .with_context(|| format!("reach {}", self.url))?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(reply_error(status, &body)).context("start the device sign-in");
        }
        let code: DeviceCode = resp.body_mut().read_json()?;
        let link = code
            .verification_uri_complete
            .clone()
            .unwrap_or_else(|| code.verification_uri.clone());
        eprintln!("Open {link}");
        eprintln!(
            "Make sure that the page shows the code {}, then approve it.",
            code.user_code
        );
        if open_browser && webbrowser::open(&link).is_err() {
            eprintln!("(The browser did not open. Open the link yourself.)");
        }
        let mut interval = Duration::from_secs(code.interval.unwrap_or(5).max(1));
        let deadline = Instant::now() + Duration::from_secs(code.expires_in);
        loop {
            if Instant::now() >= deadline {
                bail!(
                    "the code expired before it was approved; run `sealkeep login {}` again",
                    self.name
                );
            }
            std::thread::sleep(interval);
            let mut resp = self
                .agent
                .post(format!("{}/api/auth/device/token", self.url))
                .send_json(json!({
                    "grant_type": DEVICE_GRANT,
                    "device_code": code.device_code,
                    "client_id": self.client_id,
                }))?;
            let status = resp.status().as_u16();
            let body: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
            if status == 200 {
                let token = body
                    .get("access_token")
                    .and_then(Value::as_str)
                    .context("the device token reply has no access_token")?;
                keyring::write(DEFAULT_KEYRING_SERVICE, &self.session_user(), token)?;
                break;
            }
            match body.get("error").and_then(Value::as_str) {
                Some("authorization_pending") => {}
                Some("slow_down") => interval += Duration::from_secs(5),
                Some("access_denied") => bail!("the sign-in was denied"),
                Some("expired_token") => {
                    bail!("the code expired; run `sealkeep login {}` again", self.name)
                }
                _ => {
                    return Err(reply_error(status, &body.to_string()))
                        .context("finish the device sign-in");
                }
            }
        }
        // Check that the session works for this project.
        self.list()
            .context("signed in, but the project secrets are not readable")?;
        Ok(())
    }

    pub fn logout(&self) -> Result<bool> {
        keyring::delete(DEFAULT_KEYRING_SERVICE, &self.session_user())
    }
}

impl Store for ProxiumStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "proxium"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        let jwt = self.jwt()?;
        let mut resp = self
            .agent
            .get(self.secrets_url())
            .header("Authorization", format!("Bearer {jwt}"))
            .call()?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(reply_error(status, &body)).context("list the project secrets");
        }
        let reply: ListReply = resp.body_mut().read_json()?;
        Ok(reply
            .secrets
            .into_iter()
            .map(|s| SecretInfo {
                store: self.name.clone(),
                name: s.name,
                description: s.description,
                updated_at: s.updated_at,
            })
            .collect())
    }

    fn get(&self, name: &str, purpose: &str) -> Result<Option<String>> {
        let jwt = self.jwt()?;
        let purpose: String = purpose.chars().take(200).collect();
        let mut resp = self
            .agent
            .post(format!("{}/{name}/reveal", self.secrets_url()))
            .header("Authorization", format!("Bearer {jwt}"))
            .send_json(json!({ "purpose": purpose }))?;
        let status = resp.status().as_u16();
        match status {
            200 => Ok(Some(resp.body_mut().read_json::<RevealReply>()?.value)),
            404 => Ok(None),
            _ => {
                let body = resp.body_mut().read_to_string().unwrap_or_default();
                Err(reply_error(status, &body)).with_context(|| format!("reveal `{name}`"))
            }
        }
    }

    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()> {
        let jwt = self.jwt()?;
        let mut body = json!({ "value": value });
        if let Some(d) = description {
            body["description"] = json!(d);
        }
        let mut resp = self
            .agent
            .put(format!("{}/{name}", self.secrets_url()))
            .header("Authorization", format!("Bearer {jwt}"))
            .send_json(body)?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(reply_error(status, &body)).with_context(|| format!("write `{name}`"));
        }
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let jwt = self.jwt()?;
        let mut resp = self
            .agent
            .delete(format!("{}/{name}", self.secrets_url()))
            .header("Authorization", format!("Bearer {jwt}"))
            .call()?;
        let status = resp.status().as_u16();
        match status {
            200 | 204 => Ok(true),
            404 => Ok(false),
            _ => {
                let body = resp.body_mut().read_to_string().unwrap_or_default();
                Err(reply_error(status, &body)).with_context(|| format!("remove `{name}`"))
            }
        }
    }

    fn status(&self) -> Result<String> {
        let n = self.list()?.len();
        Ok(format!(
            "{} project `{}`, {n} secrets",
            self.url, self.project
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_shapes() {
        let e = reply_error(403, r#"{"error":{"code":"forbidden","message":"no"}}"#);
        assert_eq!(e.to_string(), "HTTP 403 forbidden: no");
        let e = reply_error(
            400,
            r#"{"error":"invalid_grant","error_description":"bad"}"#,
        );
        assert_eq!(e.to_string(), "HTTP 400 invalid_grant: bad");
        assert_eq!(reply_error(502, "<html>").to_string(), "HTTP 502");
    }
}

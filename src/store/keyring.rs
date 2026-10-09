//! The OS keyring: Keychain on macOS, the Secret Service (GNOME Keyring, KWallet) on
//! Linux and BSD, and the Credential Manager on Windows.
//!
//! Each secret is one entry with the service name of the store and the secret name as
//! the user. The platform stores cannot list entries in the same way, so the store keeps
//! an index entry (user `__index__`) with the names and descriptions.
//!
//! A locked keyring asks the person to unlock it on the desktop and waits. Each call
//! has a time limit (`SEALKEEP_KEYRING_TIMEOUT` seconds, default 30), so an agent gets
//! an error that says what to do. `sealkeep unlock` waits longer for the person.

use super::{SecretInfo, Store};
use anyhow::{Context, Result, anyhow};
use keyring_core::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const INDEX_USER: &str = "__index__";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// 0 means: read `SEALKEEP_KEYRING_TIMEOUT`.
static TIMEOUT_SECS: AtomicU64 = AtomicU64::new(0);

/// Wait up to `secs` for each keyring call from now on.
pub fn set_timeout(secs: u64) {
    TIMEOUT_SECS.store(secs.max(1), Ordering::Relaxed);
}

fn timeout() -> Duration {
    let set = TIMEOUT_SECS.load(Ordering::Relaxed);
    let secs = if set > 0 {
        set
    } else {
        std::env::var("SEALKEEP_KEYRING_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
    };
    Duration::from_secs(secs)
}

/// Run one keyring call with the time limit.
fn bounded<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    init()?;
    let limit = timeout();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => Err(anyhow!(
            "the OS keyring did not answer in {} s. It is probably locked and waits for an unlock on the desktop. Run `sealkeep unlock` at the desktop, then try again",
            limit.as_secs()
        )),
    }
}

static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

#[cfg(feature = "test-store")]
static SAMPLE: OnceLock<std::sync::Arc<keyring_core::sample::Store>> = OnceLock::new();

/// Set the platform store as the default keyring store, one time per process.
pub fn init() -> Result<()> {
    INIT.get_or_init(|| platform_store().map_err(|e| format!("{e:#}")))
        .clone()
        .map_err(|e| anyhow!("the OS keyring is not available: {e}"))
}

fn platform_store() -> Result<()> {
    #[cfg(feature = "test-store")]
    if let Some(path) = std::env::var_os("SEALKEEP_TEST_KEYRING_FILE") {
        let path = path.to_string_lossy().into_owned();
        let store = keyring_core::sample::Store::new_with_backing(&path)?;
        let _ = SAMPLE.set(store.clone());
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let store = zbus_secret_service_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// The sample store of the tests writes its file only on request.
fn persist() -> Result<()> {
    #[cfg(feature = "test-store")]
    if let Some(s) = SAMPLE.get() {
        s.save()?;
    }
    Ok(())
}

/// Read one entry. `None` when it does not exist.
pub fn read(service: &str, user: &str) -> Result<Option<String>> {
    let (service, user) = (service.to_string(), user.to_string());
    bounded(move || {
        let entry = Entry::new(&service, &user)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read keyring entry {service}/{user}")),
        }
    })
}

pub fn write(service: &str, user: &str, value: &str) -> Result<()> {
    let (service, user, value) = (service.to_string(), user.to_string(), value.to_string());
    bounded(move || {
        Entry::new(&service, &user)?
            .set_password(&value)
            .with_context(|| format!("write keyring entry {service}/{user}"))?;
        persist()
    })
}

/// `true` when an entry was deleted.
pub fn delete(service: &str, user: &str) -> Result<bool> {
    let (service, user) = (service.to_string(), user.to_string());
    bounded(move || {
        let r = match Entry::new(&service, &user)?.delete_credential() {
            Ok(()) => true,
            Err(KeyringError::NoEntry) => false,
            Err(e) => {
                return Err(e).with_context(|| format!("delete keyring entry {service}/{user}"));
            }
        };
        persist()?;
        Ok(r)
    })
}

/// Whether the default collection of the Secret Service is locked. `None` on macOS and
/// Windows, where the login keychain is unlocked with the session.
pub fn default_locked() -> Result<Option<bool>> {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        #[cfg(feature = "test-store")]
        if std::env::var_os("SEALKEEP_TEST_KEYRING_FILE").is_some() {
            return Ok(Some(false));
        }
        use secret_service::EncryptionType;
        use secret_service::blocking::SecretService;
        let ss = SecretService::connect(EncryptionType::Plain)
            .context("connect to the Secret Service on the session bus")?;
        let c = ss
            .get_default_collection()
            .context("find the default keyring collection")?;
        Ok(Some(c.is_locked()?))
    }
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    Ok(None)
}

/// Unlock GNOME Keyring with the login password, for a session that has no desktop to
/// show the unlock prompt.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn unlock_gnome_keyring(password: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("gnome-keyring-daemon");
    cmd.arg("--unlock")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if std::env::var_os("GNOME_KEYRING_CONTROL").is_none()
        && let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
    {
        let control = std::path::Path::new(&rt).join("keyring");
        if control.join("control").exists() {
            cmd.env("GNOME_KEYRING_CONTROL", control);
        }
    }
    let mut child = cmd.spawn().context("start gnome-keyring-daemon --unlock")?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(password.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "gnome-keyring-daemon --unlock failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    #[serde(default)]
    secrets: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

pub struct KeyringStore {
    name: String,
    service: String,
}

impl KeyringStore {
    pub fn new(name: String, service: String) -> Self {
        Self { name, service }
    }

    fn index(&self) -> Result<Index> {
        match read(&self.service, INDEX_USER)? {
            Some(text) => {
                serde_json::from_str(&text).context("the keyring index is not valid JSON")
            }
            None => Ok(Index::default()),
        }
    }

    fn save_index(&self, index: &Index) -> Result<()> {
        write(&self.service, INDEX_USER, &serde_json::to_string(index)?)
    }
}

impl Store for KeyringStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "keyring"
    }

    fn list(&self) -> Result<Vec<SecretInfo>> {
        Ok(self
            .index()?
            .secrets
            .into_iter()
            .map(|(name, e)| SecretInfo {
                store: self.name.clone(),
                name,
                description: e.description,
                updated_at: e.updated_at,
                alias_of: None,
            })
            .collect())
    }

    fn get(&self, name: &str) -> Result<Option<String>> {
        read(&self.service, name)
    }

    fn set(&self, name: &str, value: &str, description: Option<&str>) -> Result<()> {
        write(&self.service, name, value)?;
        let mut index = self.index()?;
        let e = index.secrets.entry(name.to_string()).or_default();
        if let Some(d) = description {
            e.description = Some(d.to_string());
        }
        e.updated_at = Some(crate::audit::now());
        self.save_index(&index)
    }

    fn remove(&self, name: &str) -> Result<bool> {
        let deleted = delete(&self.service, name)?;
        let mut index = self.index()?;
        let listed = index.secrets.remove(name).is_some();
        if listed {
            self.save_index(&index)?;
        }
        Ok(deleted || listed)
    }

    fn status(&self) -> Result<String> {
        if default_locked()? == Some(true) {
            anyhow::bail!("the keyring is locked (run `sealkeep unlock`)");
        }
        let n = self.index()?.secrets.len();
        Ok(format!("keyring service `{}`, {n} secrets", self.service))
    }
}

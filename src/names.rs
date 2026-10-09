//! Secret names.
//!
//! A name is a path of lower-case folders and a key: `shared/stripe/test/SECRET_KEY`,
//! `personal/example-app/prod/DATABASE_URL`, or a bare `API_KEY`. The key is the default
//! environment variable that `run` sets, so it follows the rules of a portable
//! environment variable name. A folder groups the secrets of one owner, project and
//! environment, and `run --all <folder>` gives a command all of them.

use anyhow::{Result, bail};

pub const MAX_NAME: usize = 200;
pub const MAX_KEY: usize = 64;

/// `^[A-Z][A-Z0-9_]{0,63}$`
pub fn valid_key(key: &str) -> bool {
    let b = key.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_KEY
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^[a-z0-9][a-z0-9._-]*$`, at most 64 bytes.
pub fn valid_folder(seg: &str) -> bool {
    let b = seg.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// A folder path: `shared/stripe/test`, with no leading or trailing `/`.
pub fn valid_prefix(p: &str) -> bool {
    !p.is_empty() && p.len() <= MAX_NAME && p.split('/').all(valid_folder)
}

/// `folder/…/KEY` or `KEY`.
pub fn valid(name: &str) -> bool {
    if name.len() > MAX_NAME {
        return false;
    }
    match name.rsplit_once('/') {
        Some((prefix, key)) => valid_prefix(prefix) && valid_key(key),
        None => valid_key(name),
    }
}

pub fn check(name: &str) -> Result<()> {
    if !valid(name) {
        bail!(
            "`{name}` is not a valid secret name: use lower-case folders and an upper-case key, for example shared/stripe/test/SECRET_KEY"
        );
    }
    Ok(())
}

pub fn check_prefix(prefix: &str) -> Result<()> {
    if !valid_prefix(prefix) {
        bail!("`{prefix}` is not a valid folder: use a-z, 0-9, `.`, `_` and `-`, separated by `/`");
    }
    Ok(())
}

/// The key of a name: the part after the last `/`.
pub fn key_of(name: &str) -> &str {
    name.rsplit_once('/').map(|(_, k)| k).unwrap_or(name)
}

/// The folder of a name, or `""` for a bare key.
pub fn folder_of(name: &str) -> &str {
    name.rsplit_once('/').map(|(f, _)| f).unwrap_or("")
}

/// Whether `name` is in the folder `prefix` or in a folder below it.
pub fn under(name: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    name.len() > prefix.len() + 1
        && name.starts_with(prefix)
        && name.as_bytes()[prefix.len()] == b'/'
}

/// A reference to a secret on the command line: `NAME` or `STORE:NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub store: Option<String>,
    pub name: String,
}

impl SecretRef {
    pub fn parse(s: &str) -> Result<Self> {
        let (store, name) = match s.split_once(':') {
            Some((store, name)) if !store.is_empty() => (Some(store.to_string()), name),
            Some(_) => bail!("`{s}`: the store name before `:` is empty"),
            None => (None, s),
        };
        check(name)?;
        Ok(Self {
            store,
            name: name.to_string(),
        })
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.store {
            Some(s) => write!(f, "{s}:{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// One `--env VAR=REF` mapping, or a bare `REF` that sets the variable named by its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub var: String,
    pub secret: SecretRef,
}

impl Binding {
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((var, r)) = s.split_once('=') {
            if !valid_env_var(var) {
                bail!("`{var}` is not a valid environment variable name");
            }
            return Ok(Self {
                var: var.to_string(),
                secret: SecretRef::parse(r)?,
            });
        }
        let secret = SecretRef::parse(s)?;
        Ok(Self {
            var: key_of(&secret.name).to_string(),
            secret,
        })
    }
}

pub fn valid_env_var(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid("OPENROUTER_API_KEY"));
        assert!(valid("shared/stripe/test/SECRET_KEY"));
        assert!(valid("personal/example-app/prod/DATABASE_URL"));
        assert!(valid("acme/ovh/APPLICATION_KEY"));
        assert!(!valid(""));
        assert!(!valid("lower"));
        assert!(!valid("Shared/stripe/KEY"));
        assert!(!valid("shared//KEY"));
        assert!(!valid("/KEY"));
        assert!(!valid("shared/stripe/"));
        assert!(!valid("shared/stripe/key"));
        assert!(!valid(&"A".repeat(65)));
    }

    #[test]
    fn parts() {
        assert_eq!(key_of("shared/stripe/test/SECRET_KEY"), "SECRET_KEY");
        assert_eq!(
            folder_of("shared/stripe/test/SECRET_KEY"),
            "shared/stripe/test"
        );
        assert_eq!(key_of("API_KEY"), "API_KEY");
        assert_eq!(folder_of("API_KEY"), "");
        assert!(under("shared/stripe/test/SECRET_KEY", "shared/stripe"));
        assert!(under(
            "shared/stripe/test/SECRET_KEY",
            "shared/stripe/test/"
        ));
        assert!(!under("shared/stripe-old/KEY", "shared/stripe"));
        assert!(!under("shared/stripe", "shared/stripe"));
    }

    #[test]
    fn refs() {
        let r = SecretRef::parse("vault:shared/stripe/test/SECRET_KEY").unwrap();
        assert_eq!(r.store.as_deref(), Some("vault"));
        assert_eq!(r.name, "shared/stripe/test/SECRET_KEY");
        assert!(SecretRef::parse(":X").is_err());
        assert!(SecretRef::parse("local:bad").is_err());
    }

    #[test]
    fn bindings() {
        let b = Binding::parse("GITHUB_TOKEN=local:personal/github/PAT").unwrap();
        assert_eq!(b.var, "GITHUB_TOKEN");
        assert_eq!(b.secret.name, "personal/github/PAT");
        let b = Binding::parse("shared/stripe/test/SECRET_KEY").unwrap();
        assert_eq!(b.var, "SECRET_KEY");
        assert!(Binding::parse("1X=API_KEY").is_err());
    }
}

//! Secret names. A name is also the default environment variable that `run` sets, so
//! it follows the rules of a portable environment variable name.

use anyhow::{Result, bail};

pub const MAX_NAME: usize = 64;

/// `^[A-Z][A-Z0-9_]{0,63}$`. Proxium checks the same rule on its side.
pub fn valid(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

pub fn check(name: &str) -> Result<()> {
    if !valid(name) {
        bail!(
            "`{name}` is not a valid secret name: use A-Z, 0-9 and _, start with a letter, at most {MAX_NAME} characters"
        );
    }
    Ok(())
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

/// One `--env VAR=REF` mapping, or a bare `REF` that sets the variable of the same name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub var: String,
    pub secret: SecretRef,
}

impl Binding {
    pub fn parse(s: &str) -> Result<Self> {
        match s.split_once('=') {
            Some((var, r)) => {
                if !valid_env_var(var) {
                    bail!("`{var}` is not a valid environment variable name");
                }
                Ok(Self {
                    var: var.to_string(),
                    secret: SecretRef::parse(r)?,
                })
            }
            None => {
                let secret = SecretRef::parse(s)?;
                Ok(Self {
                    var: secret.name.clone(),
                    secret,
                })
            }
        }
    }
}

fn valid_env_var(v: &str) -> bool {
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
        assert!(valid("A"));
        assert!(!valid(""));
        assert!(!valid("lower"));
        assert!(!valid("1ABC"));
        assert!(!valid("A-B"));
        assert!(!valid(&"A".repeat(65)));
        assert!(valid(&"A".repeat(64)));
    }

    #[test]
    fn refs() {
        let r = SecretRef::parse("team:STRIPE_KEY").unwrap();
        assert_eq!(r.store.as_deref(), Some("team"));
        assert_eq!(r.name, "STRIPE_KEY");
        assert!(SecretRef::parse(":X").is_err());
        assert!(SecretRef::parse("team:bad").is_err());
    }

    #[test]
    fn bindings() {
        let b = Binding::parse("GITHUB_TOKEN=local:GH_PAT").unwrap();
        assert_eq!(b.var, "GITHUB_TOKEN");
        assert_eq!(b.secret.name, "GH_PAT");
        let b = Binding::parse("GH_PAT").unwrap();
        assert_eq!(b.var, "GH_PAT");
        assert!(Binding::parse("1X=GH_PAT").is_err());
    }
}

//! Find the secrets on a machine without showing them.
//!
//! `scan` walks folders and reads each dotenv file in memory. It prints the path, the key
//! names, a class for each key (`secret` or `config`), and a group number for each value
//! that occurs in more than one place. It never prints a value or a hash of one. Other
//! files that often hold one credential (token files, keys, `ovh.conf`, AWS credentials)
//! are listed by path only.

use crate::guard::is_dotenv_path;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    ".cache",
    ".npm",
    ".cargo",
    ".rustup",
    "vendor",
    ".next",
    "dist",
    "build",
    "venv",
    ".venv",
    "site-packages",
    ".pnpm-store",
    ".terraform",
    "__pycache__",
    ".gradle",
    "Trash",
];

#[derive(Debug, Serialize)]
pub struct KeyReport {
    pub key: String,
    /// `secret`, `config` or `empty`.
    pub class: &'static str,
    /// The same value is in each place with this group number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub keys: Vec<KeyReport>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub dotenv_files: Vec<FileReport>,
    /// Files that often hold a credential, by path only.
    pub other_files: Vec<String>,
    /// Group number -> the places (`path:KEY`) that hold the same value.
    pub groups: Vec<Vec<String>>,
}

pub struct Options {
    pub max_depth: usize,
    pub exclude: Vec<String>,
}

/// The class of one entry, from its key and its value.
fn class(key: &str, value: &str) -> &'static str {
    if value.is_empty() {
        "empty"
    } else if crate::redact::secret_key_name(key) || crate::redact::url_with_password(value) {
        "secret"
    } else {
        "config"
    }
}

fn other_candidate(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let ext = Path::new(&n)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let looks_like_code = matches!(
        ext,
        "rs" | "ts"
            | "tsx"
            | "js"
            | "mjs"
            | "go"
            | "py"
            | "md"
            | "sol"
            | "sh"
            | "html"
            | "svg"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "lock"
            | "j2"
    );
    if looks_like_code {
        return false;
    }
    n.contains("token")
        || n.contains("secret")
        || n.contains("credential")
        || n.contains("password")
        || n.contains("apikey")
        || n.contains("api_key")
        || ext == "pem"
        || ext == "key"
        || n == "ovh.conf"
        || n == ".ovhrc"
        || n == ".netrc"
        || n == ".pgpass"
        || ext == "tfvars"
        || n == "credentials"
}

fn walk(
    dir: &Path,
    depth: usize,
    opts: &Options,
    dotenv: &mut Vec<PathBuf>,
    other: &mut Vec<PathBuf>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if depth == 0 || SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            let p = path.to_string_lossy();
            if opts.exclude.iter().any(|x| p.contains(x.as_str())) {
                continue;
            }
            walk(&path, depth - 1, opts, dotenv, other);
        } else if ft.is_file() {
            let p = path.to_string_lossy();
            if opts.exclude.iter().any(|x| p.contains(x.as_str())) {
                continue;
            }
            if is_dotenv_path(&name) {
                dotenv.push(path);
            } else if other_candidate(&name) {
                other.push(path);
            }
        }
    }
}

pub fn scan(roots: &[PathBuf], opts: &Options) -> Result<Report> {
    let mut dotenv = Vec::new();
    let mut other = Vec::new();
    for r in roots {
        if r.is_file() {
            dotenv.push(r.clone());
        } else {
            walk(r, opts.max_depth, opts, &mut dotenv, &mut other);
        }
    }
    dotenv.sort();
    other.sort();

    // value -> places. The values stay in this map and are dropped at the end.
    let mut by_value: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut files: Vec<FileReport> = Vec::new();
    for (fi, path) in dotenv.iter().enumerate() {
        let mut rep = FileReport {
            path: path.display().to_string(),
            error: None,
            keys: Vec::new(),
        };
        match dotenvy::from_path_iter(path) {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((key, value)) => {
                            let c = class(&key, &value);
                            if !value.is_empty() {
                                by_value
                                    .entry(value)
                                    .or_default()
                                    .push((fi, rep.keys.len()));
                            }
                            rep.keys.push(KeyReport {
                                key,
                                class: c,
                                group: None,
                            });
                        }
                        Err(e) => {
                            rep.error = Some(format!("{e}"));
                            break;
                        }
                    }
                }
            }
            Err(e) => rep.error = Some(format!("{e}")),
        }
        files.push(rep);
    }

    let mut groups: Vec<Vec<(usize, usize)>> = by_value
        .into_values()
        .filter(|places| places.len() > 1)
        .collect();
    groups.sort();
    let mut named = Vec::new();
    for (gi, places) in groups.iter().enumerate() {
        let mut members = Vec::new();
        for (fi, ki) in places {
            files[*fi].keys[*ki].group = Some(gi + 1);
            members.push(format!("{}:{}", files[*fi].path, files[*fi].keys[*ki].key));
        }
        named.push(members);
    }
    Ok(Report {
        dotenv_files: files,
        other_files: other.iter().map(|p| p.display().to_string()).collect(),
        groups: named,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(class("STRIPE_SECRET_KEY", "sk_test_x"), "secret");
        assert_eq!(class("DATABASE_URL", "postgres://u:p@h/db"), "secret");
        assert_eq!(class("DATABASE_URL", "postgres://h/db"), "config");
        assert_eq!(class("PORT", "3000"), "config");
        assert_eq!(class("API_KEY", ""), "empty");
    }

    #[test]
    fn groups_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b/node_modules");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join(".env"), "STRIPE_KEY=sk_same\nPORT=3000\n").unwrap();
        std::fs::write(dir.path().join("b.env"), "STRIPE_SECRET=sk_same\nOTHER=x\n").unwrap();
        std::fs::write(b.join(".env"), "HIDDEN=sk_same\n").unwrap();
        std::fs::write(dir.path().join(".env.example"), "A=sk_same\n").unwrap();
        std::fs::write(dir.path().join("gh-token"), "t").unwrap();
        let r = scan(
            &[dir.path().to_path_buf()],
            &Options {
                max_depth: 5,
                exclude: vec![],
            },
        )
        .unwrap();
        assert_eq!(r.dotenv_files.len(), 2);
        assert_eq!(r.groups.len(), 1);
        assert_eq!(r.groups[0].len(), 2);
        assert_eq!(r.other_files.len(), 1);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("sk_same"));
        assert!(!json.contains("3000"));
    }
}

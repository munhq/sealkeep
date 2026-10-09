//! `import`: copy the entries of a dotenv or INI file into a folder. It prints names only.
//!
//! A dotenv key `stripe_secret_key` becomes `<folder>/STRIPE_SECRET_KEY`. An INI key
//! becomes `<folder>/<section>/<KEY>`, so `ovh.conf` and AWS `credentials` keep their
//! profiles apart. `--map KEY=NAME` stores the value of KEY at NAME (a shared folder)
//! and makes `<folder>/KEY` an alias of it, so the value is stored one time.

use crate::config::Config;
use crate::names;
use crate::store::Stores;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Dotenv,
    Ini,
}

#[derive(clap::Args)]
pub struct ImportArgs {
    pub file: PathBuf,
    /// The folder for the entries, for example personal/example-app/dev.
    #[arg(long)]
    pub to: String,
    #[arg(long)]
    pub store: Option<String>,
    /// The file format. Default: INI for `.ini`, `.conf` and `credentials`, else dotenv.
    #[arg(long, value_enum)]
    pub format: Option<Format>,
    /// Only these keys (comma-separated, as in the file).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Leave out these keys (comma-separated, as in the file).
    #[arg(long, value_delimiter = ',')]
    pub skip: Vec<String>,
    /// Store KEY at NAME and make <folder>/KEY an alias of NAME.
    #[arg(long, value_name = "KEY=NAME")]
    pub map: Vec<String>,
    /// Replace a mapped NAME that already has a different value.
    #[arg(long)]
    pub force: bool,
    /// The description for each imported secret.
    #[arg(short, long)]
    pub description: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
}

/// `stripe-secret.key` -> `STRIPE_SECRET_KEY`. `None` when no valid key results.
pub fn key_name(raw: &str) -> Option<String> {
    let k: String = raw
        .trim()
        .chars()
        .map(|c| match c {
            'a'..='z' => c.to_ascii_uppercase(),
            'A'..='Z' | '0'..='9' | '_' => c,
            '-' | '.' | ' ' => '_',
            _ => '\0',
        })
        .collect();
    (!k.contains('\0') && names::valid_key(&k)).then_some(k)
}

/// `Default Profile` -> `default-profile`.
fn folder_name(raw: &str) -> Option<String> {
    let f: String = raw
        .trim()
        .chars()
        .map(|c| match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            ' ' => '-',
            _ => '\0',
        })
        .collect();
    (!f.contains('\0') && names::valid_folder(&f)).then_some(f)
}

/// The entries of an INI file as `(section, key, value)`. Lines that start with `#` or
/// `;` are comments. A value can be in single or double quotes.
pub fn parse_ini(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_string();
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            out.push((section.clone(), k.trim().to_string(), v.to_string()));
        }
    }
    out
}

fn detect(path: &Path) -> Format {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.ends_with(".ini") || name.ends_with(".conf") || name == "credentials" {
        Format::Ini
    } else {
        Format::Dotenv
    }
}

/// `(raw key, target name, value)`.
type Entry = (String, String, String);

/// The entries of the file, and the keys that have no valid name.
fn entries(path: &Path, format: Format, folder: &str) -> Result<(Vec<Entry>, Vec<String>)> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    match format {
        Format::Dotenv => {
            let iter = dotenvy::from_path_iter(path)
                .with_context(|| format!("read {}", path.display()))?;
            for item in iter {
                let (k, v) = item.with_context(|| format!("parse {}", path.display()))?;
                match key_name(&k) {
                    Some(key) => out.push((k, format!("{folder}/{key}"), v)),
                    None => skipped.push(format!("{k} (no valid name)")),
                }
            }
        }
        Format::Ini => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            for (section, k, v) in parse_ini(&text) {
                let raw = if section.is_empty() {
                    k.clone()
                } else {
                    format!("{section}.{k}")
                };
                let target = match (section.is_empty(), folder_name(&section), key_name(&k)) {
                    (true, _, Some(key)) => format!("{folder}/{key}"),
                    (false, Some(sec), Some(key)) => format!("{folder}/{sec}/{key}"),
                    _ => {
                        skipped.push(format!("{raw} (no valid name)"));
                        continue;
                    }
                };
                out.push((raw, target, v));
            }
        }
    }
    Ok((out, skipped))
}

pub fn run(args: ImportArgs) -> Result<i32> {
    let folder = args.to.trim_end_matches('/').to_string();
    names::check_prefix(&folder)?;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for m in &args.map {
        let (k, n) = m
            .split_once('=')
            .with_context(|| format!("--map needs KEY=NAME, got `{m}`"))?;
        names::check(n)?;
        map.insert(k.to_string(), n.to_string());
    }
    let format = args.format.unwrap_or_else(|| detect(&args.file));
    let (items, mut skipped) = entries(&args.file, format, &folder)?;

    let mut cfg = Config::load()?;
    let stores = Stores::from_config(&cfg);
    let s = stores.for_write(args.store.as_deref())?;
    let desc = args.description.clone().unwrap_or_else(|| {
        let f = args
            .file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("imported from {f}")
    });

    let mut stored = Vec::new();
    let mut aliased = Vec::new();
    let mut unchanged = Vec::new();
    for (raw, target, value) in items {
        if !args.only.is_empty() && !args.only.contains(&raw) {
            continue;
        }
        if args.skip.contains(&raw) {
            skipped.push(format!("{raw} (--skip)"));
            continue;
        }
        if value.is_empty() {
            skipped.push(format!("{raw} (empty)"));
            continue;
        }
        if cfg.aliases.contains_key(&target) && !map.contains_key(&raw) {
            skipped.push(format!("{raw} ({target} is an alias; use --map)"));
            continue;
        }
        match map.get(&raw) {
            Some(shared) => {
                match s.get(shared)? {
                    Some(existing) if existing == value => unchanged.push(shared.clone()),
                    Some(_) if !args.force => bail!(
                        "`{shared}` already has a different value than {raw} of {}; check which one is current, then use --force to replace it",
                        args.file.display()
                    ),
                    _ => {
                        if !args.dry_run {
                            s.set(shared, &value, Some(&desc))?;
                        }
                        stored.push(shared.clone());
                    }
                }
                if !args.dry_run {
                    cfg.aliases.insert(target.clone(), shared.clone());
                }
                aliased.push(format!("{target} -> {shared}"));
            }
            None => {
                if s.get(&target)?.as_deref() == Some(value.as_str()) {
                    unchanged.push(target);
                    continue;
                }
                if !args.dry_run {
                    s.set(&target, &value, Some(&desc))?;
                }
                stored.push(target);
            }
        }
    }
    if !args.dry_run && !aliased.is_empty() {
        cfg.save()?;
    }
    if !args.dry_run && !stored.is_empty() {
        crate::record(
            "import",
            stored.iter().map(|n| format!("{}:{n}", s.name())).collect(),
            Some(args.file.display().to_string()),
        )?;
    }
    let verb = if args.dry_run {
        "Would store"
    } else {
        "Stored"
    };
    eprintln!(
        "{verb} {} secrets in {} ({} were the same):",
        stored.len(),
        s.name(),
        unchanged.len()
    );
    for n in &stored {
        eprintln!("  {n}");
    }
    for a in &aliased {
        eprintln!("  alias {a}");
    }
    for k in &skipped {
        eprintln!("  skipped {k}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names() {
        assert_eq!(
            key_name("stripe_secret_key").as_deref(),
            Some("STRIPE_SECRET_KEY")
        );
        assert_eq!(
            key_name("aws-access.key").as_deref(),
            Some("AWS_ACCESS_KEY")
        );
        assert_eq!(key_name("1abc"), None);
        assert_eq!(key_name("a$b"), None);
    }

    #[test]
    fn ini() {
        let e = parse_ini(
            "; comment\n[default]\nendpoint=ovh-eu\n\n[ovh-eu]\napplication_key = \"abc\"\n# x\nconsumer_key='def'\n",
        );
        assert_eq!(e.len(), 3);
        assert_eq!(
            e[1],
            ("ovh-eu".into(), "application_key".into(), "abc".into())
        );
        assert_eq!(e[2].2, "def");
        assert_eq!(
            folder_name("Default Profile").as_deref(),
            Some("default-profile")
        );
    }
}

//! sealkeep: give AI agents the use of your secrets without the values.

mod audit;
mod config;
mod dotenv;
mod guard;
mod import;
mod install;
mod mcp;
mod names;
mod redact;
mod run;
mod scan;
mod ssh;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::{Config, StoreConfig, VaultAuth};
use names::Binding;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use store::Stores;

#[derive(Parser)]
#[command(
    name = "sealkeep",
    version,
    about = "Give AI agents the use of your secrets without the values",
    long_about = "sealkeep keeps secrets in the OS keyring, with Vault as a replica. `sealkeep run` gives \
secrets to a command and redacts them from its output, so an AI agent can use a secret that it never sees.\n\n\
Names: <scope>/<project>/<env>/<KEY>, for example shared/stripe/test/SECRET_KEY."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the secret names (in FOLDER, when given), their store and description. Never a value.
    List {
        folder: Option<String>,
        #[arg(long)]
        store: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Store a secret. The value comes from a hidden prompt, from stdin (--stdin) or from a file (--from-file).
    Set {
        name: String,
        #[arg(long)]
        store: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        /// Read the value from stdin (one trailing line break is removed).
        #[arg(long, conflicts_with = "from_file")]
        stdin: bool,
        /// Read the value from a file (one trailing line break is removed).
        #[arg(long)]
        from_file: Option<PathBuf>,
    },
    /// Rename a secret in its store. Aliases to the old name follow it.
    Mv {
        old: String,
        new: String,
        #[arg(long)]
        store: Option<String>,
    },
    /// Remove a secret.
    Rm {
        name: String,
        #[arg(long)]
        store: Option<String>,
    },
    /// Print a value. Works only when stdin and stdout are a terminal, so an agent cannot use it.
    Get {
        name: String,
        #[arg(long)]
        store: Option<String>,
    },
    /// Run a command with secrets in its environment, and redact them from its output.
    #[command(
        after_help = "Examples:\n  sealkeep run shared/openrouter/API_KEY -- sh -c 'curl -H \"Authorization: Bearer $API_KEY\" https://openrouter.ai/api/v1/key'\n  sealkeep run --all personal/example-app/dev -- npm run dev\n  sealkeep run -e GITHUB_TOKEN=personal/github/PAT -- gh api user\n  sealkeep run --dotenv ADMIN_PASSWORD=personal/example-app/dev/ADMIN_PASSWORD -- npx @playwright/mcp@latest --secrets {dotenv}"
    )]
    Run {
        /// Every secret in FOLDER, each in the variable named by its key.
        #[arg(long = "all", value_name = "FOLDER")]
        all: Vec<String>,
        /// With --all: also the secrets in the subfolders.
        #[arg(long)]
        recursive: bool,
        /// Read --all folders from this store only.
        #[arg(long)]
        store: Option<String>,
        /// Set VAR to the secret NAME (or STORE:NAME).
        #[arg(short = 'e', long = "env", value_name = "VAR=NAME")]
        env: Vec<String>,
        /// Put the secret in a temporary dotenv file; {dotenv} in the command becomes its path.
        #[arg(long, value_name = "[VAR=]NAME")]
        dotenv: Vec<String>,
        /// Secrets for the variables named by their keys.
        #[arg(value_name = "NAME")]
        secrets: Vec<String>,
        /// The command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Copy the entries of a dotenv or INI file into a folder. Prints the names only.
    Import(import::ImportArgs),
    /// Find the dotenv files and credential files under folders. Prints paths, key names
    /// and groups of keys with the same value. Never a value.
    Scan {
        roots: Vec<PathBuf>,
        #[arg(long, default_value_t = 6)]
        max_depth: usize,
        /// Leave out paths that contain this text.
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Copy the secrets of one store to another (for example the keyring to Vault).
    Sync {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// Only this folder and below.
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage aliases: a name in a project folder that points to a shared secret.
    Alias {
        #[command(subcommand)]
        cmd: AliasCmd,
    },
    /// Manage the stores in the config file.
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Serve the MCP tools on stdio.
    Mcp,
    /// The pre-tool hook for AI clients (reads the hook JSON on stdin).
    Guard {
        #[arg(long, value_enum, default_value = "claude")]
        client: guard::Client,
    },
    /// Install the skill, the MCP server and the guard hook into the AI clients.
    Install {
        /// Only these clients. Default: each client that is on this machine.
        #[arg(long, value_enum, value_delimiter = ',')]
        client: Vec<install::ClientId>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        no_skills: bool,
        #[arg(long)]
        no_mcp: bool,
        #[arg(long)]
        no_hooks: bool,
    },
    /// Remove what `install` added.
    Uninstall {
        #[arg(long, value_enum, value_delimiter = ',')]
        client: Vec<install::ClientId>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Unlock the OS keyring: with the login password at a terminal (GNOME Keyring with no
    /// desktop), or with the prompt on the desktop.
    Unlock {
        /// Read the password from stdin.
        #[arg(long)]
        stdin: bool,
    },
    /// Add the SSH keys of the config to their agents, with passphrases from sealkeep.
    SshLoad,
    /// Add an SSH key to the config of `ssh-load`.
    SshAdd {
        /// The private key file, for example ~/.ssh/id_ed25519.
        path: String,
        /// The secret that holds its passphrase.
        #[arg(long)]
        passphrase: Option<String>,
        /// The agent socket. Default: $SSH_AUTH_SOCK when `ssh-load` runs.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Check the config, the stores and the clients.
    Doctor,
    /// Show the last entries of the local audit log.
    Audit {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
}

#[derive(Subcommand)]
enum AliasCmd {
    /// Make NAME point to TARGET.
    Add { name: String, target: String },
    /// Remove an alias. The target stays.
    Rm { name: String },
    /// Show the aliases.
    List,
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Show the stores, in lookup order.
    List,
    /// Add an OS keyring store.
    AddKeyring {
        name: String,
        #[arg(long, default_value = config::DEFAULT_KEYRING_SERVICE)]
        service: String,
    },
    /// Add a Vault KV v2 mount as a store.
    AddVault {
        name: String,
        /// The address; `{port}` is the local port of --port-forward.
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "agent")]
        mount: String,
        #[arg(long, value_enum, default_value = "kubernetes")]
        auth: AuthArg,
        #[arg(long)]
        role: Option<String>,
        #[arg(long, default_value = "kubernetes")]
        k8s_auth_mount: String,
        /// The command that prints a ServiceAccount JWT, as one shell-split string.
        #[arg(long)]
        jwt_command: Option<String>,
        /// The command that forwards {port} to Vault, as one shell-split string.
        #[arg(long)]
        port_forward: Option<String>,
    },
    /// Add AWS Secrets Manager as a store (uses the `aws` CLI and its sign-in).
    AddAws {
        name: String,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, default_value = "sealkeep/")]
        prefix: String,
        #[arg(long)]
        endpoint_url: Option<String>,
    },
    /// Add Google Secret Manager as a store (uses the `gcloud` CLI and its sign-in).
    AddGcp {
        name: String,
        #[arg(long)]
        project: String,
    },
    /// Add Azure Key Vault as a store (uses the `az` CLI and its sign-in).
    AddAzure {
        name: String,
        #[arg(long)]
        vault: String,
    },
    /// Add a 1Password vault as a store (uses the `op` CLI, 2.23 or later, and its sign-in).
    #[command(name = "add-1password")]
    AddOnepassword {
        name: String,
        #[arg(long)]
        vault: String,
    },
    /// Add Bitwarden or Vaultwarden as a store (uses the `bw` CLI; export BW_SESSION).
    AddBitwarden { name: String },
    /// Store the Vault token of a store (token auth) in the keyring. Reads stdin or a prompt.
    Token { store: String },
    /// Remove a store from the config. Its secrets stay where they are.
    Remove { name: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum AuthArg {
    Token,
    Kubernetes,
}

fn main() {
    // sealkeep runs as the SSH_ASKPASS program of `ssh-load`.
    if let Ok(token) = std::env::var(ssh::ASKPASS_ENV) {
        std::process::exit(ssh::askpass(&token));
    }
    let cli = Cli::parse();
    match dispatch(cli.cmd) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sealkeep: {e:#}");
            std::process::exit(1);
        }
    }
}

fn dispatch(cmd: Cmd) -> Result<i32> {
    match cmd {
        Cmd::List {
            folder,
            store,
            json,
        } => list(folder.as_deref(), store, json),
        Cmd::Set {
            name,
            store,
            description,
            stdin,
            from_file,
        } => set(
            &name,
            store.as_deref(),
            description.as_deref(),
            stdin,
            from_file.as_deref(),
        ),
        Cmd::Mv { old, new, store } => mv(&old, &new, store.as_deref()),
        Cmd::Rm { name, store } => rm(&name, store.as_deref()),
        Cmd::Get { name, store } => get(&name, store.as_deref()),
        Cmd::Run {
            all,
            recursive,
            store,
            env,
            dotenv,
            secrets,
            command,
        } => run_cmd(all, recursive, store, env, dotenv, secrets, command),
        Cmd::Import(args) => import::run(args),
        Cmd::Scan {
            roots,
            max_depth,
            exclude,
            json,
        } => scan_cmd(roots, max_depth, exclude, json),
        Cmd::Sync {
            from,
            to,
            folder,
            dry_run,
        } => sync(&from, &to, folder.as_deref(), dry_run),
        Cmd::Alias { cmd } => alias_cmd(cmd),
        Cmd::Store { cmd } => store_cmd(cmd),
        Cmd::Mcp => mcp::serve().map(|_| 0),
        Cmd::Guard { client } => Ok(guard_cmd(client)),
        Cmd::Install {
            client,
            dry_run,
            no_skills,
            no_mcp,
            no_hooks,
        } => install_cmd(
            client,
            dry_run,
            install::Parts {
                skills: !no_skills,
                mcp: !no_mcp,
                hooks: !no_hooks,
            },
            true,
        ),
        Cmd::Uninstall { client, dry_run } => install_cmd(
            client,
            dry_run,
            install::Parts {
                skills: true,
                mcp: true,
                hooks: true,
            },
            false,
        ),
        Cmd::Unlock { stdin } => unlock(stdin),
        Cmd::SshLoad => ssh_load(),
        Cmd::SshAdd {
            path,
            passphrase,
            agent,
        } => {
            let mut cfg = Config::load()?;
            cfg.ssh_keys.retain(|k| k.path != path);
            cfg.ssh_keys.push(config::SshKey {
                path: path.clone(),
                passphrase,
                agent,
            });
            cfg.save()?;
            eprintln!("Added {path} to the keys of ssh-load.");
            Ok(0)
        }
        Cmd::Doctor => doctor(),
        Cmd::Audit { tail } => audit_tail(tail),
    }
}

pub fn stores() -> Result<Stores> {
    Ok(Stores::from_config(&Config::load()?))
}

fn list(folder: Option<&str>, store: Option<String>, as_json: bool) -> Result<i32> {
    if let Some(f) = folder {
        names::check_prefix(f.trim_end_matches('/'))?;
    }
    let stores = stores()?;
    let (mut items, errors) = match &store {
        Some(s) => (stores.by_name(s)?.list()?, Vec::new()),
        None => stores.list_all(),
    };
    if let Some(f) = folder {
        items.retain(|i| names::under(&i.name, f));
    }
    items.sort_by(|a, b| a.name.cmp(&b.name).then(a.store.cmp(&b.store)));
    if as_json {
        let v = serde_json::json!({"secrets": items, "errors": errors});
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        let w = items.iter().map(|i| i.name.len()).max().unwrap_or(4).max(4);
        let sw = items
            .iter()
            .map(|i| i.store.len())
            .max()
            .unwrap_or(5)
            .max(5);
        println!("{:w$}  {:sw$}  DESCRIPTION", "NAME", "STORE");
        for i in &items {
            let d = match &i.alias_of {
                Some(t) => format!("-> {t}"),
                None => i.description.clone().unwrap_or_default(),
            };
            println!("{:w$}  {:sw$}  {d}", i.name, i.store);
        }
        for e in &errors {
            eprintln!("sealkeep: store {e}");
        }
    }
    Ok(if errors.is_empty() { 0 } else { 1 })
}

/// Remove one trailing line break.
pub fn trim_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

fn read_value(name: &str, from_stdin: bool, from_file: Option<&std::path::Path>) -> Result<String> {
    let value = if let Some(p) = from_file {
        trim_newline(std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?)
    } else if from_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        trim_newline(s)
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("stdin is not a terminal; use --stdin or --from-file");
        }
        let a = rpassword::prompt_password(format!("Value for {name}: "))?;
        let b = rpassword::prompt_password("The same value again: ")?;
        if a != b {
            bail!("the two values are different");
        }
        a
    };
    if value.is_empty() {
        bail!("the value is empty");
    }
    if value.len() < redact::MIN_REDACT_LEN {
        eprintln!(
            "sealkeep: the value is shorter than {} characters, so `run` cannot redact it from output",
            redact::MIN_REDACT_LEN
        );
    }
    Ok(value)
}

pub fn record(action: &'static str, secrets: Vec<String>, command: Option<String>) -> Result<()> {
    audit::record(&audit::Event {
        at: audit::now(),
        action,
        secrets,
        command,
        cwd: audit::cwd(),
        exit_code: None,
    })
}

fn set(
    name: &str,
    store: Option<&str>,
    description: Option<&str>,
    from_stdin: bool,
    from_file: Option<&std::path::Path>,
) -> Result<i32> {
    names::check(name)?;
    let cfg = Config::load()?;
    if cfg.aliases.contains_key(name) {
        bail!("`{name}` is an alias; set its target, or run `sealkeep alias rm {name}` first");
    }
    let stores = Stores::from_config(&cfg);
    let targets = stores.write_targets(store, name)?;
    let value = read_value(name, from_stdin, from_file)?;
    let mut done = Vec::new();
    let mut failed = false;
    for s in targets {
        match s.set(name, &value, description) {
            Ok(()) => done.push(s.name().to_string()),
            Err(e) => {
                failed = true;
                eprintln!("sealkeep: store {}: {e:#}", s.name());
            }
        }
    }
    if !done.is_empty() {
        record(
            "set",
            done.iter().map(|s| format!("{s}:{name}")).collect(),
            None,
        )?;
        eprintln!("Stored {name} in {}.", done.join(", "));
    }
    Ok(if failed { 1 } else { 0 })
}

fn mv(old: &str, new: &str, store: Option<&str>) -> Result<i32> {
    names::check(old)?;
    names::check(new)?;
    let mut cfg = Config::load()?;
    if let Some(target) = cfg.aliases.remove(old) {
        cfg.aliases.insert(new.to_string(), target.clone());
        cfg.save()?;
        eprintln!("Moved the alias {old} -> {target} to {new}.");
        return Ok(0);
    }
    let stores = Stores::from_config(&cfg);
    let candidates: Vec<&dyn store::Store> = match store {
        Some(s) => vec![stores.by_name(s)?],
        None => stores.stores.iter().map(|s| s.as_ref()).collect(),
    };
    let mut moved_in = Vec::new();
    for s in candidates {
        let Some(value) = s.get(old)? else { continue };
        if s.get(new)?.is_some() {
            bail!("`{new}` already exists in {}", s.name());
        }
        let desc = s
            .list()?
            .into_iter()
            .find(|i| i.name == old)
            .and_then(|i| i.description);
        s.set(new, &value, desc.as_deref())?;
        s.remove(old)?;
        moved_in.push(s.name().to_string());
    }
    if moved_in.is_empty() {
        bail!("no store has a secret `{old}`");
    }
    let mut follow = 0;
    for t in cfg.aliases.values_mut() {
        if t == old {
            *t = new.to_string();
            follow += 1;
        }
    }
    if follow > 0 {
        cfg.save()?;
    }
    record(
        "move",
        moved_in
            .iter()
            .flat_map(|s| [format!("{s}:{old}"), format!("{s}:{new}")])
            .collect(),
        None,
    )?;
    eprintln!(
        "Moved {old} to {new} in {} ({follow} aliases follow it).",
        moved_in.join(", ")
    );
    Ok(0)
}

fn rm(name: &str, store: Option<&str>) -> Result<i32> {
    names::check(name)?;
    let stores = stores()?;
    let targets: Vec<&dyn store::Store> = match store {
        Some(s) => vec![stores.by_name(s)?],
        None => stores.stores.iter().map(|s| s.as_ref()).collect(),
    };
    let mut removed = Vec::new();
    for s in targets {
        if s.remove(name)? {
            removed.push(format!("{}:{name}", s.name()));
        }
    }
    if removed.is_empty() {
        bail!("no store has a secret `{name}`");
    }
    record("remove", removed.clone(), None)?;
    eprintln!("Removed {}.", removed.join(", "));
    Ok(0)
}

fn get(name: &str, store: Option<&str>) -> Result<i32> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        bail!(
            "`get` prints a value, so it works only at a terminal. Use `sealkeep run {name} -- <command>`"
        );
    }
    names::check(name)?;
    let r = names::SecretRef {
        store: store.map(str::to_string),
        name: name.to_string(),
    };
    let stores = stores()?;
    let v = stores.resolve(std::slice::from_ref(&r))?.remove(0);
    record("get", vec![format!("{}:{name}", v.store)], None)?;
    println!("{}", v.value);
    Ok(0)
}

fn run_cmd(
    all: Vec<String>,
    recursive: bool,
    store: Option<String>,
    env: Vec<String>,
    dotenv: Vec<String>,
    secrets: Vec<String>,
    command: Vec<String>,
) -> Result<i32> {
    let stores = stores()?;
    // Folders first, then single names, so a single name can replace one folder entry.
    let mut bindings: Vec<Binding> = Vec::new();
    for f in &all {
        for b in stores.folder_bindings(f.trim_end_matches('/'), store.as_deref(), recursive)? {
            bindings.retain(|x| x.var != b.var);
            bindings.push(b);
        }
    }
    let mut single: Vec<Binding> = secrets
        .iter()
        .map(|s| Binding::parse(s))
        .collect::<Result<_>>()?;
    for e in &env {
        if !e.contains('=') {
            bail!("-e needs VAR=NAME, got `{e}`");
        }
        single.push(Binding::parse(e)?);
    }
    for b in single {
        bindings.retain(|x| x.var != b.var);
        bindings.push(b);
    }
    let dotenv: Vec<Binding> = dotenv
        .iter()
        .map(|s| Binding::parse(s))
        .collect::<Result<_>>()?;
    let prepared = run::prepare(
        &stores,
        run::RunSpec {
            argv: command,
            env: bindings,
            dotenv,
            cwd: None,
            action: "run",
        },
    )?;
    prepared.run_streamed()
}

fn scan_cmd(
    roots: Vec<PathBuf>,
    max_depth: usize,
    exclude: Vec<String>,
    json: bool,
) -> Result<i32> {
    let roots = if roots.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        roots
    };
    let report = scan::scan(&roots, &scan::Options { max_depth, exclude })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }
    for f in &report.dotenv_files {
        println!("{}", f.path);
        if let Some(e) = &f.error {
            println!("  (not read: {e})");
        }
        for b in &f.bad_lines {
            println!(
                "  line {}: does not parse ({}); the text is not shown",
                b.line, b.reason
            );
        }
        for k in &f.keys {
            let kind = k.kind.map(|x| format!(" ({x})")).unwrap_or_default();
            match k.group {
                Some(g) => println!("  {:40} {:6}{kind} same value: group {g}", k.key, k.class),
                None => println!("  {:40} {}{kind}", k.key, k.class),
            }
        }
    }
    if !report.groups.is_empty() {
        println!("\nGroups of keys with the same value:");
        for (i, g) in report.groups.iter().enumerate() {
            println!("  group {}: {}", i + 1, g.join(", "));
        }
    }
    if !report.other_files.is_empty() {
        println!("\nOther files that can hold a credential (not read):");
        for p in &report.other_files {
            println!("  {p}");
        }
    }
    Ok(0)
}

fn sync(from: &str, to: &str, folder: Option<&str>, dry_run: bool) -> Result<i32> {
    if from == to {
        bail!("--from and --to name the same store");
    }
    if let Some(f) = folder {
        names::check_prefix(f)?;
    }
    let stores = stores()?;
    let src = stores.by_name(from)?;
    let dst = stores.by_name(to)?;
    let mut items = src.list()?;
    if let Some(f) = folder {
        items.retain(|i| names::under(&i.name, f));
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let (mut copied, mut same, mut skipped) = (Vec::new(), 0usize, Vec::new());
    for i in &items {
        if names::folder_of(&i.name).is_empty() && dst.needs_folder() {
            skipped.push(format!(
                "{} (the {} store needs a folder)",
                i.name,
                dst.kind()
            ));
            continue;
        }
        let Some(value) = src.get(&i.name)? else {
            skipped.push(format!("{} (listed, but has no value)", i.name));
            continue;
        };
        if dst.get(&i.name)?.as_deref() == Some(value.as_str()) {
            same += 1;
            continue;
        }
        if !dry_run {
            dst.set(&i.name, &value, i.description.as_deref())?;
        }
        copied.push(i.name.clone());
    }
    if !dry_run && !copied.is_empty() {
        record(
            "sync",
            copied.iter().map(|n| format!("{to}:{n}")).collect(),
            Some(format!("from {from}")),
        )?;
    }
    let verb = if dry_run { "Would copy" } else { "Copied" };
    eprintln!(
        "{verb} {} secrets from {from} to {to}; {same} were the same.",
        copied.len()
    );
    for n in &copied {
        eprintln!("  {n}");
    }
    for s in &skipped {
        eprintln!("  skipped {s}");
    }
    Ok(0)
}

fn alias_cmd(cmd: AliasCmd) -> Result<i32> {
    let mut cfg = Config::load()?;
    match cmd {
        AliasCmd::List => {
            for (a, t) in &cfg.aliases {
                println!("{a} -> {t}");
            }
            return Ok(0);
        }
        AliasCmd::Add { name, target } => {
            names::check(&name)?;
            names::check(&target)?;
            cfg.aliases.insert(name.clone(), target.clone());
            cfg.save()?;
            eprintln!("{name} -> {target}");
        }
        AliasCmd::Rm { name } => {
            if cfg.aliases.remove(&name).is_none() {
                bail!("no alias `{name}`");
            }
            cfg.save()?;
            eprintln!("Removed the alias {name}.");
        }
    }
    Ok(0)
}

fn split_command(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

fn store_cmd(cmd: StoreCmd) -> Result<i32> {
    let mut cfg = Config::load()?;
    match cmd {
        StoreCmd::List => {
            for s in &cfg.stores {
                match s {
                    StoreConfig::Keyring { name, service } => {
                        println!("{name}  keyring  service={service}")
                    }
                    StoreConfig::Vault {
                        name,
                        address,
                        mount,
                        auth,
                        ..
                    } => println!("{name}  vault  {address} mount={mount} auth={auth:?}"),
                    StoreConfig::Aws {
                        name,
                        region,
                        prefix,
                        ..
                    } => println!(
                        "{name}  aws  prefix={prefix} region={}",
                        region.as_deref().unwrap_or("(default)")
                    ),
                    StoreConfig::Gcp { name, project } => {
                        println!("{name}  gcp  project={project}")
                    }
                    StoreConfig::Azure { name, vault } => println!("{name}  azure  vault={vault}"),
                    StoreConfig::Onepassword { name, vault } => {
                        println!("{name}  1password  vault={vault}")
                    }
                    StoreConfig::Bitwarden { name } => println!("{name}  bitwarden"),
                }
            }
            eprintln!("(config: {})", config::path()?.display());
            return Ok(0);
        }
        StoreCmd::AddKeyring { name, service } => {
            cfg.stores.push(StoreConfig::Keyring { name, service })
        }
        StoreCmd::AddVault {
            name,
            address,
            mount,
            auth,
            role,
            k8s_auth_mount,
            jwt_command,
            port_forward,
        } => cfg.stores.push(StoreConfig::Vault {
            name,
            address,
            mount,
            auth: match auth {
                AuthArg::Token => VaultAuth::Token,
                AuthArg::Kubernetes => VaultAuth::Kubernetes,
            },
            role,
            k8s_auth_mount,
            jwt_command: jwt_command
                .as_deref()
                .map(split_command)
                .unwrap_or_default(),
            port_forward: port_forward
                .as_deref()
                .map(split_command)
                .unwrap_or_default(),
        }),
        StoreCmd::AddAws {
            name,
            region,
            profile,
            prefix,
            endpoint_url,
        } => cfg.stores.push(StoreConfig::Aws {
            name,
            region,
            profile,
            prefix,
            endpoint_url,
        }),
        StoreCmd::AddGcp { name, project } => cfg.stores.push(StoreConfig::Gcp { name, project }),
        StoreCmd::AddAzure { name, vault } => cfg.stores.push(StoreConfig::Azure { name, vault }),
        StoreCmd::AddOnepassword { name, vault } => {
            cfg.stores.push(StoreConfig::Onepassword { name, vault })
        }
        StoreCmd::AddBitwarden { name } => cfg.stores.push(StoreConfig::Bitwarden { name }),
        StoreCmd::Token { store } => {
            match cfg.store(&store)? {
                StoreConfig::Vault { .. } => {}
                _ => bail!("store `{store}` is not a Vault store"),
            }
            let token = read_value("the Vault token", !std::io::stdin().is_terminal(), None)?;
            store::keyring::write(
                config::DEFAULT_KEYRING_SERVICE,
                &store::vault::VaultStore::token_user(&store),
                &token,
            )?;
            eprintln!("Stored the token of `{store}` in the keyring.");
            return Ok(0);
        }
        StoreCmd::Remove { name } => {
            let before = cfg.stores.len();
            cfg.stores.retain(|s| s.name() != name);
            if cfg.stores.len() == before {
                bail!("no store named `{name}`");
            }
        }
    }
    cfg.save()?;
    eprintln!("Saved {}.", config::path()?.display());
    Ok(0)
}

fn guard_cmd(client: guard::Client) -> i32 {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return 0;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&input) else {
        return 0;
    };
    // A config that does not parse keeps the default rules on.
    let cfg = Config::load().unwrap_or_default();
    guard::respond(client, guard::check(&v, &cfg))
}

fn install_cmd(
    clients: Vec<install::ClientId>,
    dry_run: bool,
    parts: install::Parts,
    add: bool,
) -> Result<i32> {
    let clients = if clients.is_empty() {
        install::detect()?
    } else {
        clients
    };
    if clients.is_empty() {
        bail!("no AI client found (Claude Code, Codex, Cursor); name one with --client");
    }
    let ctx = install::Ctx {
        dry_run,
        bin: install::bin_path()?,
        parts,
    };
    let lines = install::apply(&ctx, &clients, add)?;
    let mut failed = false;
    for l in &lines {
        failed |= l.contains(": ERROR ");
        println!("{l}");
    }
    if dry_run {
        println!("(dry run: nothing changed)");
    }
    Ok(if failed { 1 } else { 0 })
}

fn unlock(from_stdin: bool) -> Result<i32> {
    // The password is read only for GNOME Keyring; macOS and Windows unlock with the session.
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    let _ = from_stdin;
    match store::keyring::default_locked()? {
        None => {
            eprintln!("The login keychain opens with your session; there is nothing to unlock.");
            return Ok(0);
        }
        Some(false) => {
            eprintln!("The keyring is unlocked.");
            return ssh_load();
        }
        Some(true) => {}
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if (from_stdin || std::io::stdin().is_terminal())
        && std::process::Command::new("gnome-keyring-daemon")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    {
        let pw = if from_stdin {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            trim_newline(s)
        } else {
            rpassword::prompt_password(
                "Password of the login keyring (a new keyring gets this password): ",
            )?
        };
        store::keyring::unlock_gnome_keyring(&pw)?;
        if store::keyring::default_locked()? == Some(false) {
            eprintln!("The keyring is unlocked.");
            return ssh_load();
        }
        bail!("the keyring is still locked; check the password");
    }
    // A desktop session shows the unlock prompt of the keyring.
    store::keyring::set_timeout(300);
    eprintln!("Approve the unlock prompt of the keyring on the desktop.");
    let cfg = Config::load()?;
    if let Some(StoreConfig::Keyring { name, service }) = cfg
        .stores
        .iter()
        .find(|s| matches!(s, StoreConfig::Keyring { .. }))
    {
        let n = store::keyring::KeyringStore::new(name.clone(), service.clone());
        store::Store::set(&n, "SEALKEEP_UNLOCK_CHECK", "unlock-check", None)?;
        store::Store::remove(&n, "SEALKEEP_UNLOCK_CHECK")?;
    }
    eprintln!("The keyring is unlocked.");
    Ok(0)
}

fn ssh_load() -> Result<i32> {
    let cfg = Config::load()?;
    if cfg.ssh_keys.is_empty() {
        eprintln!("No SSH keys in the config (add one with `sealkeep ssh-add`).");
        return Ok(0);
    }
    let lines = ssh::load(&cfg)?;
    let failed = lines.iter().any(|l| l.contains(": ERROR"));
    for l in lines {
        eprintln!("{l}");
    }
    Ok(if failed { 1 } else { 0 })
}

fn doctor() -> Result<i32> {
    let mut bad = false;
    println!("binary: {}", install::bin_path()?);
    println!("config: {}", config::path()?.display());
    println!("audit log: {}", audit::path()?.display());
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            println!("config ERROR: {e:#}");
            return Ok(1);
        }
    };
    for s in Stores::from_config(&cfg).stores {
        match s.status() {
            Ok(line) => println!("store {} ({}): ok, {line}", s.name(), s.kind()),
            Err(e) => {
                bad = true;
                println!("store {} ({}): ERROR {e:#}", s.name(), s.kind());
            }
        }
    }
    println!("aliases: {}", cfg.aliases.len());
    println!(
        "guard: block .env reads {}, {} more deny prefixes",
        if cfg.guard.block_dotenv { "on" } else { "off" },
        cfg.guard.deny.len()
    );
    for l in install::status()? {
        println!("{l}");
    }
    Ok(if bad { 1 } else { 0 })
}

fn audit_tail(n: usize) -> Result<i32> {
    let p = audit::path()?;
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("No audit log yet ({}).", p.display());
            return Ok(0);
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
    };
    let lines: Vec<&str> = text.lines().collect();
    for l in &lines[lines.len().saturating_sub(n)..] {
        println!("{l}");
    }
    Ok(0)
}

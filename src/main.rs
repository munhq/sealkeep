//! sealkeep: give AI agents the use of your secrets without the values.

mod audit;
mod config;
mod guard;
mod install;
mod mcp;
mod names;
mod redact;
mod run;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::{Config, StoreConfig};
use names::Binding;
use std::io::{IsTerminal, Read};
use store::Stores;

#[derive(Parser)]
#[command(
    name = "sealkeep",
    version,
    about = "Give AI agents the use of your secrets without the values",
    long_about = "sealkeep keeps secrets in the OS keyring or in a Proxium project. `sealkeep run` gives \
secrets to a command and redacts them from its output, so an AI agent can use a secret that it never sees."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the secret names, their store and description. Never a value.
    List {
        #[arg(long)]
        store: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Store a secret. The value comes from a hidden prompt, or from stdin with --stdin.
    Set {
        name: String,
        #[arg(long)]
        store: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        /// Read the value from stdin (one trailing line break is removed).
        #[arg(long)]
        stdin: bool,
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
        after_help = "Examples:\n  sealkeep run OPENROUTER_API_KEY -- sh -c 'curl -H \"Authorization: Bearer $OPENROUTER_API_KEY\" https://openrouter.ai/api/v1/key'\n  sealkeep run -e GITHUB_TOKEN=GH_PAT -- gh api user\n  sealkeep run --dotenv ADMIN_PASSWORD -- npx @playwright/mcp@latest --secrets {dotenv}"
    )]
    Run {
        /// Set VAR to the secret NAME (or STORE:NAME).
        #[arg(short = 'e', long = "env", value_name = "VAR=NAME")]
        env: Vec<String>,
        /// Put the secret in a temporary dotenv file; {dotenv} in the command becomes its path.
        #[arg(long, value_name = "[VAR=]NAME")]
        dotenv: Vec<String>,
        /// Secrets for the variables of the same name.
        #[arg(value_name = "NAME")]
        secrets: Vec<String>,
        /// The command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Copy the entries of a dotenv file into a store. Prints the names only.
    Import {
        file: std::path::PathBuf,
        #[arg(long)]
        store: Option<String>,
        /// Only these keys (comma-separated).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Add this prefix to each name, for example APP_.
        #[arg(long, default_value = "")]
        prefix: String,
        /// The description for each imported secret.
        #[arg(short, long)]
        description: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage the stores in the config file.
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Sign in to a Proxium store (device flow).
    Login {
        store: String,
        #[arg(long)]
        no_browser: bool,
    },
    /// Remove the Proxium session of a store from the keyring.
    Logout { store: String },
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
    Unlock,
    /// Check the config, the stores and the clients.
    Doctor,
    /// Show the last entries of the local audit log.
    Audit {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
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
    /// Add a Proxium project as a store.
    AddProxium {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        project: String,
        #[arg(long, default_value = config::DEFAULT_PROXIUM_CLIENT_ID)]
        client_id: String,
    },
    /// Remove a store from the config. Its secrets stay where they are.
    Remove { name: String },
}

fn main() {
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
        Cmd::List { store, json } => list(store, json),
        Cmd::Set {
            name,
            store,
            description,
            stdin,
        } => set(&name, store.as_deref(), description.as_deref(), stdin),
        Cmd::Rm { name, store } => rm(&name, store.as_deref()),
        Cmd::Get { name, store } => get(&name, store.as_deref()),
        Cmd::Run {
            env,
            dotenv,
            secrets,
            command,
        } => run_cmd(env, dotenv, secrets, command),
        Cmd::Import {
            file,
            store,
            only,
            prefix,
            description,
            dry_run,
        } => import(
            &file,
            store.as_deref(),
            &only,
            &prefix,
            description.as_deref(),
            dry_run,
        ),
        Cmd::Store { cmd } => store_cmd(cmd),
        Cmd::Login { store, no_browser } => login(&store, !no_browser),
        Cmd::Logout { store } => logout(&store),
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
        Cmd::Unlock => unlock(),
        Cmd::Doctor => doctor(),
        Cmd::Audit { tail } => audit_tail(tail),
    }
}

fn stores() -> Result<Stores> {
    Ok(Stores::from_config(&Config::load()?))
}

fn list(store: Option<String>, as_json: bool) -> Result<i32> {
    let stores = stores()?;
    let (mut items, errors) = match &store {
        Some(s) => (stores.by_name(s)?.list()?, Vec::new()),
        None => stores.list_all(),
    };
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
            let d = i.description.as_deref().unwrap_or("");
            println!("{:w$}  {:sw$}  {d}", i.name, i.store);
        }
        for e in &errors {
            eprintln!("sealkeep: store {e}");
        }
    }
    Ok(if errors.is_empty() { 0 } else { 1 })
}

fn read_value(name: &str, from_stdin: bool) -> Result<String> {
    let value = if from_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
        s
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("stdin is not a terminal; use --stdin to read the value from stdin");
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

fn record(action: &'static str, secrets: Vec<String>, command: Option<String>) -> Result<()> {
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
) -> Result<i32> {
    names::check(name)?;
    let stores = stores()?;
    let s = stores.for_write(store)?;
    let value = read_value(name, from_stdin)?;
    s.set(name, &value, description)?;
    record("set", vec![format!("{}:{name}", s.name())], None)?;
    eprintln!("Stored {name} in {}.", s.name());
    Ok(0)
}

fn rm(name: &str, store: Option<&str>) -> Result<i32> {
    names::check(name)?;
    let stores = stores()?;
    let targets: Vec<&dyn store::Store> = match store {
        Some(s) => vec![stores.by_name(s)?],
        None => stores.stores.iter().map(|s| s.as_ref()).collect(),
    };
    for s in targets {
        if s.remove(name)? {
            record("remove", vec![format!("{}:{name}", s.name())], None)?;
            eprintln!("Removed {name} from {}.", s.name());
            return Ok(0);
        }
    }
    bail!("no store has a secret `{name}`")
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
    let v = stores
        .resolve(std::slice::from_ref(&r), "get: printed at a terminal")?
        .remove(0);
    record("get", vec![format!("{}:{name}", v.store)], None)?;
    println!("{}", v.value);
    Ok(0)
}

fn run_cmd(
    env: Vec<String>,
    dotenv: Vec<String>,
    secrets: Vec<String>,
    command: Vec<String>,
) -> Result<i32> {
    let mut bindings: Vec<Binding> = secrets
        .iter()
        .map(|s| Binding::parse(s))
        .collect::<Result<_>>()?;
    for e in &env {
        if !e.contains('=') {
            bail!("-e needs VAR=NAME, got `{e}`");
        }
        bindings.push(Binding::parse(e)?);
    }
    let dotenv: Vec<Binding> = dotenv
        .iter()
        .map(|s| Binding::parse(s))
        .collect::<Result<_>>()?;
    let prepared = run::prepare(
        &stores()?,
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

fn import(
    file: &std::path::Path,
    store: Option<&str>,
    only: &[String],
    prefix: &str,
    description: Option<&str>,
    dry_run: bool,
) -> Result<i32> {
    let stores = stores()?;
    let s = stores.for_write(store)?;
    let iter = dotenvy::from_path_iter(file).with_context(|| format!("read {}", file.display()))?;
    let desc = description.map(str::to_string).unwrap_or_else(|| {
        let f = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("imported from {f}")
    });
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    for item in iter {
        let (key, value) = item.with_context(|| format!("parse {}", file.display()))?;
        if !only.is_empty() && !only.iter().any(|o| o == &key) {
            continue;
        }
        let name = format!("{prefix}{key}");
        if !names::valid(&name) {
            skipped.push(format!("{key} (the name `{name}` is not valid)"));
            continue;
        }
        if value.is_empty() {
            skipped.push(format!("{key} (empty)"));
            continue;
        }
        if !dry_run {
            s.set(&name, &value, Some(&desc))?;
        }
        imported.push(format!("{}:{name}", s.name()));
    }
    if !dry_run && !imported.is_empty() {
        record("import", imported.clone(), Some(file.display().to_string()))?;
    }
    let verb = if dry_run { "Would import" } else { "Imported" };
    eprintln!("{verb} {} secrets into {}:", imported.len(), s.name());
    for n in &imported {
        eprintln!("  {n}");
    }
    for k in &skipped {
        eprintln!("  skipped {k}");
    }
    Ok(0)
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
                    StoreConfig::Proxium {
                        name, url, project, ..
                    } => {
                        println!("{name}  proxium  {url} project={project}")
                    }
                }
            }
            eprintln!("(config: {})", config::path()?.display());
            return Ok(0);
        }
        StoreCmd::AddKeyring { name, service } => {
            cfg.stores.push(StoreConfig::Keyring { name, service })
        }
        StoreCmd::AddProxium {
            name,
            url,
            project,
            client_id,
        } => {
            cfg.stores.push(StoreConfig::Proxium {
                name: name.clone(),
                url,
                project,
                client_id,
            });
            eprintln!("Run `sealkeep login {name}` to sign in.");
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

fn proxium_store(name: &str) -> Result<store::proxium::ProxiumStore> {
    let cfg = Config::load()?;
    match cfg.store(name)? {
        StoreConfig::Proxium {
            name,
            url,
            project,
            client_id,
        } => Ok(store::proxium::ProxiumStore::new(
            name.clone(),
            url.clone(),
            project.clone(),
            client_id.clone(),
        )),
        StoreConfig::Keyring { .. } => {
            bail!("store `{name}` is a keyring store; it needs no sign-in")
        }
    }
}

fn login(name: &str, open_browser: bool) -> Result<i32> {
    proxium_store(name)?.login(open_browser)?;
    eprintln!("Signed in. Store `{name}` is ready.");
    Ok(0)
}

fn logout(name: &str) -> Result<i32> {
    if proxium_store(name)?.logout()? {
        eprintln!("Removed the session of `{name}`.");
    } else {
        eprintln!("Store `{name}` had no session.");
    }
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

fn unlock() -> Result<i32> {
    match store::keyring::default_locked()? {
        None => {
            eprintln!("The login keychain opens with your session; there is nothing to unlock.");
            return Ok(0);
        }
        Some(false) => {
            eprintln!("The keyring is unlocked.");
            return Ok(0);
        }
        Some(true) => {}
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if std::io::stdin().is_terminal()
        && std::process::Command::new("gnome-keyring-daemon")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    {
        let pw = rpassword::prompt_password("Password of the login keyring: ")?;
        store::keyring::unlock_gnome_keyring(&pw)?;
        if store::keyring::default_locked()? == Some(false) {
            eprintln!("The keyring is unlocked.");
            return Ok(0);
        }
        bail!("the keyring is still locked; check the password");
    }
    // A desktop session shows the unlock prompt of the keyring.
    store::keyring::set_timeout(300);
    eprintln!("Approve the unlock prompt of the keyring on the desktop.");
    let cfg = Config::load()?;
    for s in &cfg.stores {
        if let StoreConfig::Keyring { name, service } = s {
            let n = store::keyring::KeyringStore::new(name.clone(), service.clone());
            store::Store::set(&n, "SEALKEEP_UNLOCK_CHECK", "unlock-check", None)?;
            store::Store::remove(&n, "SEALKEEP_UNLOCK_CHECK")?;
            break;
        }
    }
    eprintln!("The keyring is unlocked.");
    Ok(0)
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

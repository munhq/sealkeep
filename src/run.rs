//! Run a command with secrets in its environment, and redact them from its output.

use crate::audit;
use crate::names::Binding;
use crate::redact::Redactor;
use crate::store::{Resolved, Stores};
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The argument that `--dotenv` replaces with the path of the secrets file.
pub const DOTENV_PLACEHOLDER: &str = "{dotenv}";

pub struct RunSpec {
    pub argv: Vec<String>,
    /// Secrets that go into the environment of the command.
    pub env: Vec<Binding>,
    /// Secrets that go into a dotenv file, for a tool that reads its secrets from a file.
    pub dotenv: Vec<Binding>,
    pub cwd: Option<PathBuf>,
    /// The audit action and the purpose that a remote store logs.
    pub action: &'static str,
}

pub struct Prepared {
    spec: RunSpec,
    resolved_env: Vec<(String, String)>,
    dotenv: Option<DotenvFile>,
    redactor: Redactor,
    secret_names: Vec<String>,
}

/// Resolve the secrets, write the dotenv file, and build the redactor.
pub fn prepare(stores: &Stores, mut spec: RunSpec) -> Result<Prepared> {
    if spec.argv.is_empty() {
        bail!("no command to run");
    }
    let purpose = format!("{}: {}", spec.action, audit::command_line(&spec.argv));
    let env_refs: Vec<_> = spec.env.iter().map(|b| b.secret.clone()).collect();
    let file_refs: Vec<_> = spec.dotenv.iter().map(|b| b.secret.clone()).collect();
    let env_vals: Vec<Resolved> = stores.resolve(&env_refs, &purpose)?;
    let file_vals: Vec<Resolved> = stores.resolve(&file_refs, &purpose)?;

    let all: Vec<(&str, &str)> = env_vals
        .iter()
        .chain(file_vals.iter())
        .map(|r| (r.reference.name.as_str(), r.value.as_str()))
        .collect();
    let redactor = Redactor::new(all.iter().copied());

    let resolved_env = spec
        .env
        .iter()
        .zip(env_vals.iter())
        .map(|(b, r)| (b.var.clone(), r.value.clone()))
        .collect();

    let dotenv = if spec.dotenv.is_empty() {
        None
    } else {
        let pairs: Vec<(String, String)> = spec
            .dotenv
            .iter()
            .zip(file_vals.iter())
            .map(|(b, r)| (b.var.clone(), r.value.clone()))
            .collect();
        let file = DotenvFile::write(&pairs)?;
        let path = file.path.display().to_string();
        let mut used = false;
        for a in spec.argv.iter_mut() {
            if a.contains(DOTENV_PLACEHOLDER) {
                *a = a.replace(DOTENV_PLACEHOLDER, &path);
                used = true;
            }
        }
        if !used {
            bail!(
                "--dotenv needs the argument {DOTENV_PLACEHOLDER} in the command, where the file path goes"
            );
        }
        Some(file)
    };

    let secret_names = env_vals
        .iter()
        .chain(file_vals.iter())
        .map(|r| format!("{}:{}", r.store, r.reference.name))
        .collect();
    Ok(Prepared {
        spec,
        resolved_env,
        dotenv,
        redactor,
        secret_names,
    })
}

impl Prepared {
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.spec.argv[0]);
        cmd.args(&self.spec.argv[1..]);
        for (k, v) in &self.resolved_env {
            cmd.env(k, v);
        }
        if let Some(d) = &self.spec.cwd {
            cmd.current_dir(d);
        }
        cmd
    }

    fn log(&self, exit_code: Option<i32>) -> Result<()> {
        audit::record(&audit::Event {
            at: audit::now(),
            action: self.spec.action,
            secrets: self.secret_names.clone(),
            command: Some(
                self.redactor
                    .redact_str(&audit::command_line(&self.spec.argv)),
            ),
            cwd: self
                .spec
                .cwd
                .as_ref()
                .map(|p| p.display().to_string())
                .or_else(audit::cwd),
            exit_code,
        })
    }

    /// Run with the terminal: stdin is passed through, and stdout and stderr are
    /// redacted on their way to the terminal. Returns the exit code.
    pub fn run_streamed(self) -> Result<i32> {
        self.log(None)?;
        let mut child = self
            .command()
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start `{}`", self.spec.argv[0]))?;
        let out = child.stdout.take().expect("stdout is piped");
        let err = child.stderr.take().expect("stderr is piped");
        let status = std::thread::scope(|s| {
            let r = &self.redactor;
            let a = s.spawn(move || pump(r, out, std::io::stdout()));
            let b = s.spawn(move || pump(r, err, std::io::stderr()));
            let status = child.wait();
            let _ = a.join();
            let _ = b.join();
            status
        })?;
        drop(self.dotenv);
        Ok(exit_code(status))
    }

    /// Run with captured output, for the MCP tool. The output of each stream is cut at
    /// `limit` bytes, and the command is killed after `timeout`.
    pub fn run_captured(
        self,
        stdin: Option<String>,
        timeout: Duration,
        limit: usize,
    ) -> Result<Captured> {
        let mut child = self
            .command()
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start `{}`", self.spec.argv[0]))?;
        if let Some(input) = stdin {
            let mut w = child.stdin.take().expect("stdin is piped");
            std::thread::spawn(move || {
                let _ = w.write_all(input.as_bytes());
            });
        }
        let out = child.stdout.take().expect("stdout is piped");
        let err = child.stderr.take().expect("stderr is piped");
        let (tx, rx) = mpsc::channel();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send((0, read_capped(out, limit)));
        });
        std::thread::spawn(move || {
            let _ = tx2.send((1, read_capped(err, limit)));
        });
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if start.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = (Vec::new(), false);
        let mut stderr = (Vec::new(), false);
        for _ in 0..2 {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok((0, v)) => stdout = v,
                Ok((_, v)) => stderr = v,
                Err(_) => break,
            }
        }
        let code = exit_code(status);
        self.log(Some(code))?;
        let r = &self.redactor;
        Ok(Captured {
            exit_code: code,
            stdout: String::from_utf8_lossy(&r.redact_all(&stdout.0)).into_owned(),
            stderr: String::from_utf8_lossy(&r.redact_all(&stderr.0)).into_owned(),
            truncated: stdout.1 || stderr.1,
            timed_out,
        })
    }
}

pub struct Captured {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

fn pump(r: &Redactor, mut from: impl Read, mut to: impl Write) {
    let mut s = r.stream();
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let out = s.push(&buf[..n]);
                if to.write_all(&out).and_then(|_| to.flush()).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = to.write_all(&s.finish());
    let _ = to.flush();
}

/// Read to the end, and keep the first `limit` bytes. The rest is read and dropped, so
/// the command does not block on a full pipe.
fn read_capped(mut from: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = limit.saturating_sub(kept.len());
                if n > room {
                    truncated = true;
                }
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, truncated)
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(c) = status.code() {
        return c;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

/// A dotenv file that only the user can read, removed when the run ends.
struct DotenvFile {
    path: PathBuf,
}

impl DotenvFile {
    fn write(pairs: &[(String, String)]) -> Result<Self> {
        let dir = runtime_dir()?;
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = dir.join(format!(
            "secrets-{}-{}.env",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        let file = Self { path };
        for (k, v) in pairs {
            f.write_all(dotenv_line(k, v).as_bytes())?;
        }
        f.sync_all()?;
        Ok(file)
    }
}

impl Drop for DotenvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `$XDG_RUNTIME_DIR/sealkeep` (a tmpfs that only the user can read on Linux), else a
/// folder in the temp folder of the OS.
fn runtime_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        let d = PathBuf::from(d);
        if d.is_dir() {
            return Ok(d.join("sealkeep"));
        }
    }
    #[cfg(unix)]
    let user = unsafe { libc::getuid() }.to_string();
    #[cfg(not(unix))]
    let user = std::env::var("USERNAME").unwrap_or_default();
    Ok(std::env::temp_dir().join(format!("sealkeep-{user}")))
}

/// One dotenv line. A value without `'` or a line break goes in single quotes, which
/// dotenv parsers read as literal text.
fn dotenv_line(k: &str, v: &str) -> String {
    if !v.contains('\'') && !v.contains('\n') && !v.contains('\r') {
        format!("{k}='{v}'\n")
    } else {
        let escaped = v
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("{k}=\"{escaped}\"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_quoting() {
        assert_eq!(dotenv_line("A", "x y$z"), "A='x y$z'\n");
        assert_eq!(dotenv_line("A", "it's"), "A=\"it's\"\n");
        assert_eq!(dotenv_line("A", "a\"b\nc"), "A=\"a\\\"b\\nc\"\n");
    }

    #[test]
    fn dotenv_file_is_private_and_removed() {
        let file = DotenvFile::write(&[("A".into(), "v".into())]).unwrap();
        let path = file.path.clone();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A='v'\n");
        drop(file);
        assert!(!path.exists());
    }

    #[test]
    fn capped_read() {
        let (v, t) = read_capped(&b"abcdef"[..], 4);
        assert_eq!(v, b"abcd");
        assert!(t);
        let (v, t) = read_capped(&b"ab"[..], 4);
        assert_eq!(v, b"ab");
        assert!(!t);
    }
}

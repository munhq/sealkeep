//! The resident redaction agent of the post-tool hook.
//!
//! The hook used to read every store on each tool call, and the stores can take
//! seconds. The agent reads the stores one time, holds the redactor in memory and
//! answers on a Unix socket that only the same user can open. The hook sends the tool
//! result and gets the redacted result back. When the agent does not answer in 200 ms,
//! the hook starts it and uses the in-process path for that call.
//!
//! The socket is `$XDG_RUNTIME_DIR/sealkeep/agent.sock`: the folder has mode 0700 and
//! the socket has mode 0600. Each peer is checked with `SO_PEERCRED` on Linux and
//! `getpeereid` on macOS and the BSDs; a peer with another uid is refused.
//!
//! A value never goes to a disk file, to a log or to a message. The agent keeps the
//! values only in memory, tries to lock that memory with `mlockall`, and turns off core
//! dumps. The status that the agent reports holds counts, times and ages only.

use crate::config::Config;
use crate::guard;
use crate::redact::Redactor;
use crate::store;
#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long the hook waits for the agent before it uses the in-process path.
pub const HOOK_TIMEOUT: Duration = Duration::from_millis(200);

/// The agent reads the stores again after this time.
const RELOAD_EVERY: Duration = Duration::from_secs(10 * 60);

/// How long `doctor` waits for the agent status.
const STATUS_TIMEOUT: Duration = Duration::from_millis(500);

/// A reload marker stays for this time, so a burst of hooks starts one agent.
const START_MARKER_TTL: Duration = Duration::from_secs(15);

static RELOAD: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreLoad {
    pub name: String,
    pub kind: String,
    pub secrets: usize,
    pub list_ms: u64,
    pub get_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub socket: String,
    /// Unix seconds.
    pub started_at: u64,
    /// Unix seconds of the last completed load.
    pub loaded_at: u64,
    pub loading: bool,
    pub values: usize,
    /// Whether the agent could lock its memory with `mlockall`.
    pub memlock: bool,
    pub stores: Vec<StoreLoad>,
}

/// The outcome of a request to the agent from the hook.
pub enum Answer {
    /// The agent answered; the value is the hook output, or `None` for a clean result.
    Redacted(Option<serde_json::Value>),
    /// No agent socket.
    NotRunning,
    /// The agent has the socket but did not answer in time.
    Timeout,
}

struct State {
    redactor: Option<Redactor>,
    status: Status,
}

/// The folder of the socket: `$XDG_RUNTIME_DIR/sealkeep`, else a private folder in the
/// temporary folder that is named after the user id.
pub fn dir() -> std::path::PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => std::path::PathBuf::from(d).join("sealkeep"),
        _ => std::env::temp_dir().join(format!("sealkeep-{}", user_id())),
    }
}

pub fn socket_path() -> std::path::PathBuf {
    dir().join("agent.sock")
}

fn marker_path() -> std::path::PathBuf {
    dir().join("agent.start")
}

#[cfg(unix)]
fn user_id() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn user_id() -> u32 {
    0
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ask the agent to redact a tool result. `Answer::NotRunning` tells the hook to start
/// the agent; a timeout or an error from a running agent only uses the fallback.
pub fn redact(input: &serde_json::Value) -> Answer {
    match ask(
        &serde_json::json!({"cmd": "redact", "input": input}),
        HOOK_TIMEOUT,
    ) {
        Ok(reply) if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
            Answer::Redacted(reply.get("output").cloned().filter(|v| !v.is_null()))
        }
        Ok(_) => Answer::Timeout,
        Err(AskError::NotRunning) => Answer::NotRunning,
        Err(AskError::Timeout) => Answer::Timeout,
    }
}

/// Start the agent in the background when it is not up. A marker stops a burst of hook
/// calls from starting a process each.
pub fn start_background() {
    if can_connect() {
        return;
    }
    let dir = dir();
    if !prepare_dir(&dir) {
        return;
    }
    let marker = marker_path();
    if !claim_marker(&marker) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        let _ = std::fs::remove_file(&marker);
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("agent")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let _ = cmd.spawn();
}

/// Tell a running agent that the stores changed. It sends the request and does not wait for
/// the answer, so `sealkeep set` does not wait for a slow store. A missing agent is not an
/// error: the next hook starts it.
pub fn notify_reload() {
    #[cfg(unix)]
    {
        use std::io::Write;
        let Ok(mut stream) = connect() else {
            return;
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
        let _ = stream.write_all(b"{\"cmd\":\"reload\"}\n");
        let _ = stream.flush();
    }
}

/// The status of a running agent, for `doctor`. `None` when no agent answers.
pub fn status() -> Option<Status> {
    let reply = ask(&serde_json::json!({"cmd": "status"}), STATUS_TIMEOUT).ok()?;
    if reply.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    serde_json::from_value(reply.get("status")?.clone()).ok()
}

/// The lines that `sealkeep doctor` prints about the agent and the load time of each
/// store. It never holds a value.
pub fn doctor() -> Vec<String> {
    let Some(st) = status() else {
        return if can_connect() {
            vec!["agent: starting or busy (no answer in 500 ms)".to_string()]
        } else {
            vec![
                "agent: not running (the guard starts it on the first tool result; `sealkeep agent` starts it now)"
                    .to_string(),
            ]
        };
    };
    let age = now().saturating_sub(st.loaded_at);
    let mut out = Vec::new();
    if st.loading {
        out.push(format!("agent: loading (pid {})", st.pid));
    } else {
        out.push(format!(
            "agent: running (pid {}), {} values, loaded {} s ago, memory locked: {}",
            st.pid,
            st.values,
            age,
            if st.memlock { "yes" } else { "no" }
        ));
    }
    out.push(format!("agent: socket {}", st.socket));
    for s in &st.stores {
        let mut line = format!(
            "agent store {} ({}): {} secrets, list {} ms, get {} ms",
            s.name, s.kind, s.secrets, s.list_ms, s.get_ms
        );
        if let Some(e) = &s.error {
            line.push_str(&format!(", ERROR {e}"));
        }
        out.push(line);
    }
    out
}

/// Run the agent until it is stopped. It prints one line at the start and one after each
/// load, and it never prints a value.
pub fn run() -> Result<i32> {
    #[cfg(not(unix))]
    {
        bail!("the redaction agent needs a Unix socket; it is not available on this platform")
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::net::UnixListener;

        let cfg = Config::load()?;
        let dir = dir();
        if !prepare_dir(&dir) {
            bail!("cannot use the socket folder {}", dir.display());
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let md = std::fs::symlink_metadata(&dir)?;
        if !md.file_type().is_dir() {
            bail!("{} is not a folder", dir.display());
        }
        if md.uid() != unsafe { libc::geteuid() } {
            bail!("{} is not owned by this user", dir.display());
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("set the mode of {}", dir.display()))?;

        let path = dir.join("agent.sock");
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            eprintln!("sealkeep agent: already running on {}", path.display());
            let _ = std::fs::remove_file(marker_path());
            return Ok(0);
        }
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("remove the stale socket {}", path.display()))?;
        }

        // The umask closes the window before the explicit chmod below.
        let old_umask = unsafe { libc::umask(0o077) };
        let listener = UnixListener::bind(&path);
        unsafe { libc::umask(old_umask) };
        let listener = listener.with_context(|| format!("bind {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set the mode of {}", path.display()))?;
        listener.set_nonblocking(true)?;
        let _ = std::fs::remove_file(marker_path());

        install_signals();

        let started_at = now();
        let state = Arc::new(Mutex::new(State {
            redactor: None,
            status: Status {
                pid: std::process::id(),
                socket: path.display().to_string(),
                started_at,
                loaded_at: 0,
                loading: true,
                values: 0,
                memlock: false,
                stores: Vec::new(),
            },
        }));

        let (tx, rx) = mpsc::channel::<Option<mpsc::SyncSender<()>>>();
        spawn_loader(cfg, state.clone(), rx);

        eprintln!("sealkeep agent: listening on {}", path.display());
        let mut last_load = Instant::now();
        loop {
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            if RELOAD.swap(false, Ordering::SeqCst) || last_load.elapsed() >= RELOAD_EVERY {
                let _ = tx.send(None);
                last_load = Instant::now();
            }
            if !wait_readable(&listener, Duration::from_millis(250)) {
                continue;
            }
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        let tx = tx.clone();
                        std::thread::spawn(move || serve(stream, state, tx));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("sealkeep agent: accept: {e}");
                        break;
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&path);
        Ok(0)
    }
}

#[cfg(unix)]
fn install_signals() {
    extern "C" fn reload(_: libc::c_int) {
        RELOAD.store(true, Ordering::SeqCst);
    }
    extern "C" fn stop(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    unsafe {
        libc::signal(libc::SIGUSR1, reload as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

#[cfg(unix)]
fn wait_readable(listener: &std::os::unix::net::UnixListener, timeout: Duration) -> bool {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    unsafe { libc::poll(&mut fd, 1, ms) > 0 }
}

/// Answer one request of one peer. The peer must be the same user, and each request is one
/// line of JSON.
#[cfg(unix)]
fn serve(
    stream: std::os::unix::net::UnixStream,
    state: Arc<Mutex<State>>,
    reload: mpsc::Sender<Option<mpsc::SyncSender<()>>>,
) {
    use std::io::{BufRead, BufReader};
    if !peer_is_owner(&stream) {
        return;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) else {
        reply(
            &stream,
            &serde_json::json!({"ok": false, "error": "the request is not JSON"}),
        );
        return;
    };
    let answer = match req.get("cmd").and_then(|v| v.as_str()) {
        Some("redact") => {
            let input = req.get("input").cloned().unwrap_or(serde_json::Value::Null);
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            match &st.redactor {
                Some(r) => {
                    serde_json::json!({"ok": true, "output": guard::check_output(&input, r)})
                }
                None => serde_json::json!({"ok": false, "error": "the values are still loading"}),
            }
        }
        Some("status") => match state.lock() {
            Ok(st) => serde_json::json!({"ok": true, "status": st.status}),
            Err(_) => serde_json::json!({"ok": false, "error": "the agent state is poisoned"}),
        },
        Some("reload") => {
            let (done, wait) = mpsc::sync_channel(0);
            if reload.send(Some(done)).is_err() {
                serde_json::json!({"ok": false, "error": "the loader is gone"})
            } else {
                match wait.recv_timeout(Duration::from_secs(60)) {
                    Ok(()) => match state.lock() {
                        Ok(st) => serde_json::json!({"ok": true, "status": st.status}),
                        Err(_) => {
                            serde_json::json!({"ok": false, "error": "the agent state is poisoned"})
                        }
                    },
                    Err(_) => {
                        serde_json::json!({"ok": false, "error": "the reload did not finish"})
                    }
                }
            }
        }
        Some("stop") => {
            STOP.store(true, Ordering::SeqCst);
            serde_json::json!({"ok": true})
        }
        _ => serde_json::json!({"ok": false, "error": "unknown command"}),
    };
    reply(&stream, &answer);
}

#[cfg(unix)]
fn reply(stream: &std::os::unix::net::UnixStream, reply: &serde_json::Value) {
    use std::io::Write;
    let mut bytes = serde_json::to_vec(reply).unwrap_or_default();
    bytes.push(b'\n');
    let mut out = stream;
    let _ = out.write_all(&bytes);
}

#[cfg(unix)]
fn spawn_loader(
    cfg: Config,
    state: Arc<Mutex<State>>,
    rx: mpsc::Receiver<Option<mpsc::SyncSender<()>>>,
) {
    std::thread::spawn(move || {
        let mut pending: Option<mpsc::SyncSender<()>> = None;
        loop {
            let mut loaded = load(&cfg);
            if let Ok(mut st) = state.lock() {
                st.redactor = loaded.redactor.take();
                st.status.loaded_at = now();
                st.status.loading = false;
                st.status.values = loaded.values;
                st.status.memlock = loaded.memlock;
                st.status.stores = loaded.stores;
            }
            if let Some(done) = pending.take() {
                let _ = done.send(());
            }
            match rx.recv() {
                Ok(done) => pending = done,
                Err(_) => break,
            }
        }
    });
}

struct Loaded {
    redactor: Option<Redactor>,
    values: usize,
    memlock: bool,
    stores: Vec<StoreLoad>,
}

/// Read every store one time. It records the time of the list call and of all get calls
/// of each store, so `doctor` and the issue can show where the seconds go.
fn load(cfg: &Config) -> Loaded {
    // The sample keyring of the tests keeps its entries in memory, so a reload of a test
    // must read them from its file again. The real keyring stores are separate processes
    // and need no refresh.
    #[cfg(feature = "test-store")]
    let _ = crate::store::keyring::refresh();

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut stores = Vec::new();
    for sc in &cfg.stores {
        let s = store::open(sc);
        let name = s.name().to_string();
        let kind = s.kind().to_string();
        let mut stat = StoreLoad {
            name,
            kind,
            secrets: 0,
            list_ms: 0,
            get_ms: 0,
            error: None,
        };
        let t = Instant::now();
        match s.list() {
            Ok(items) => {
                stat.list_ms = t.elapsed().as_millis() as u64;
                let t = Instant::now();
                for info in items {
                    match s.get(&info.name) {
                        Ok(Some(value)) => {
                            pairs.push((info.name, value));
                            stat.secrets += 1;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            if stat.error.is_none() {
                                stat.error = Some(format!("{e:#}"));
                            }
                        }
                    }
                }
                stat.get_ms = t.elapsed().as_millis() as u64;
            }
            Err(e) => {
                stat.list_ms = t.elapsed().as_millis() as u64;
                stat.error = Some(format!("{e:#}"));
            }
        }
        stores.push(stat);
    }
    let values = pairs.len();
    let redactor = Redactor::new(pairs.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    // Lock the pages that hold the patterns, then drop the plain copies.
    let memlock = lock_memory();
    drop(pairs);
    Loaded {
        redactor: Some(redactor),
        values,
        memlock,
        stores,
    }
}

/// Best effort: lock the memory of the process and turn off core dumps. A limit of the
/// system can refuse the lock; the agent then reports `memlock: false` in `doctor`.
#[cfg(unix)]
fn lock_memory() -> bool {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        libc::mlockall(libc::MCL_CURRENT) == 0
    }
}

#[cfg(not(unix))]
fn lock_memory() -> bool {
    false
}

#[cfg(unix)]
fn prepare_dir(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let Ok(md) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !md.file_type().is_dir() || md.uid() != unsafe { libc::geteuid() } {
        return false;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).is_ok()
}

#[cfg(not(unix))]
fn prepare_dir(_dir: &std::path::Path) -> bool {
    false
}

/// The socket folder is safe to connect into only when this user owns it and no other
/// user can write to it. Without this check, another local user could make the folder
/// first (it is in the shared temporary folder when `XDG_RUNTIME_DIR` is not set), listen
/// there, and receive the tool results that the hook sends for redaction.
#[cfg(unix)]
fn dir_is_private(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(md) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    md.file_type().is_dir()
        && md.uid() == unsafe { libc::geteuid() }
        && md.permissions().mode() & 0o077 == 0
}

/// Connect to the agent socket, but only inside a private folder.
#[cfg(unix)]
fn connect() -> std::io::Result<std::os::unix::net::UnixStream> {
    if !dir_is_private(&dir()) {
        return Err(std::io::Error::other(
            "the socket folder is not private to this user",
        ));
    }
    std::os::unix::net::UnixStream::connect(socket_path())
}

#[cfg(unix)]
fn can_connect() -> bool {
    connect().is_ok()
}

#[cfg(not(unix))]
fn can_connect() -> bool {
    false
}

/// Take the start marker for at most `START_MARKER_TTL`. A stale marker can be taken.
#[cfg(unix)]
fn claim_marker(marker: &std::path::Path) -> bool {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    for _ in 0..2 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker)
        {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(marker)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_none_or(|age| age > START_MARKER_TTL);
                if stale {
                    let _ = std::fs::remove_file(marker);
                    continue;
                }
                return false;
            }
            Err(_) => return false,
        }
    }
    false
}

#[cfg(not(unix))]
fn claim_marker(_marker: &std::path::Path) -> bool {
    false
}

enum AskError {
    NotRunning,
    Timeout,
}

#[cfg(unix)]
fn ask(
    request: &serde_json::Value,
    timeout: Duration,
) -> std::result::Result<serde_json::Value, AskError> {
    use std::io::{BufRead, BufReader, Write};

    let stream = connect().map_err(|_| AskError::NotRunning)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return Err(AskError::Timeout),
    };
    let mut body = serde_json::to_vec(request).map_err(|_| AskError::Timeout)?;
    body.push(b'\n');
    if writer.write_all(&body).is_err() {
        return Err(AskError::Timeout);
    }
    let _ = writer.flush();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.is_empty() {
        return Err(AskError::Timeout);
    }
    serde_json::from_str(&line).map_err(|_| AskError::Timeout)
}

#[cfg(not(unix))]
fn ask(
    _request: &serde_json::Value,
    _timeout: Duration,
) -> std::result::Result<serde_json::Value, AskError> {
    Err(AskError::NotRunning)
}

/// The uid of the peer of a socket, or an error when the platform cannot report it. An
/// error is a refusal.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(all(
    unix,
    not(target_os = "linux"),
    not(target_os = "macos"),
    not(target_os = "freebsd"),
    not(target_os = "netbsd"),
    not(target_os = "openbsd")
))]
fn peer_uid(_stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::other(
        "this platform cannot report the uid of a socket peer",
    ))
}

#[cfg(unix)]
fn peer_is_owner(stream: &std::os::unix::net::UnixStream) -> bool {
    match peer_uid(stream) {
        Ok(uid) => same_user(uid, unsafe { libc::geteuid() }),
        Err(_) => false,
    }
}

/// The rule of the peer check, kept apart for the test.
#[cfg(unix)]
fn same_user(peer: u32, me: u32) -> bool {
    peer == me
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_that_others_can_write_is_not_private() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("sealkeep-dir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(dir_is_private(&base));
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!dir_is_private(&base));
        assert!(!dir_is_private(&base.join("missing")));
        let file = base.join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(!dir_is_private(&file));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_peer_with_another_uid_is_refused() {
        let me = 1000;
        assert!(same_user(me, me));
        assert!(!same_user(me + 1, me));
        assert!(!same_user(0, me));
    }
}

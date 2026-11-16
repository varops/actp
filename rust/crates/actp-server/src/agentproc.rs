//! Starts and stops ACP agent processes. A port of Go's `internal/agentproc`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::watch;

/// How much of an agent's stderr is kept for error messages.
pub const STDERR_TAIL: usize = 8 << 10;

/// How to start an agent. Environments are lists of `KEY=value`, like Go's.
#[derive(Clone, Debug, Default)]
pub struct Spec {
    pub command: String,
    pub args: Vec<String>,
    pub dir: PathBuf,
    /// `None` means the current process environment.
    pub base_env: Option<Vec<String>>,
    pub env: BTreeMap<String, String>,
    pub env_remove: Vec<String>,
}

/// A running agent.
pub struct Process {
    pid: u32,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    done: watch::Receiver<bool>,
    exit: Arc<Mutex<Option<i32>>>,
    stopping: tokio::sync::OnceCell<()>,
}

impl Process {
    /// Launches the agent in its own process group.
    pub fn start(spec: &Spec) -> std::io::Result<Arc<Process>> {
        let env = build_env(spec.base_env.clone(), &spec.env, &spec.env_remove);
        let path = look_path(&spec.command, &env)?;
        let mut cmd = Command::new(&path);
        cmd.args(&spec.args).current_dir(&spec.dir).env_clear();
        for kv in &env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // An agent never outlives the runtime that supervises it.
            .kill_on_drop(true);
        set_process_group(&mut cmd);
        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let exit = Arc::new(Mutex::new(None));
        let (done_tx, done_rx) = watch::channel(false);
        let tail = stderr.clone();
        let exit2 = exit.clone();
        tokio::spawn(async move {
            let copy = async {
                if let Some(p) = stderr_pipe.as_mut() {
                    let mut buf = [0u8; 4096];
                    loop {
                        match p.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                                t.extend_from_slice(&buf[..n]);
                                if t.len() > STDERR_TAIL {
                                    let cut = t.len() - STDERR_TAIL;
                                    t.drain(..cut);
                                }
                            }
                        }
                    }
                }
            };
            // Like Go's cmd.Wait, done waits for stderr to drain, but only briefly after
            // the exit: on Windows a pipe handle inherited by a sibling agent spawned at
            // the same moment can keep stderr open long after this agent exited.
            tokio::pin!(copy);
            let status = tokio::select! {
                s = child.wait() => {
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut copy).await;
                    s
                }
                _ = &mut copy => child.wait().await,
            };
            let code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
            *exit2.lock().unwrap_or_else(|e| e.into_inner()) = Some(code);
            done_tx.send_replace(true);
        });
        Ok(Arc::new(Process {
            pid,
            stdin: tokio::sync::Mutex::new(stdin),
            stdout: Mutex::new(stdout),
            stderr,
            done: done_rx,
            exit,
            stopping: tokio::sync::OnceCell::new(),
        }))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Takes the agent's stdout (once).
    pub fn take_stdout(&self) -> Option<ChildStdout> {
        self.stdout.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Writes bytes to the agent's stdin.
    pub async fn write_stdin(&self, data: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut g = self.stdin.lock().await;
        match g.as_mut() {
            Some(w) => {
                w.write_all(data).await?;
                w.flush().await
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stdin closed",
            )),
        }
    }

    /// Resolves once the process has exited.
    pub async fn wait(&self) {
        let mut d = self.done.clone();
        let _ = d.wait_for(|v| *v).await;
    }

    pub fn exited(&self) -> bool {
        *self.done.borrow()
    }

    /// The exit code, or -1 while running or when killed by a signal.
    pub fn exit_code(&self) -> i32 {
        self.exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(-1)
    }

    /// The last bytes the agent wrote to stderr.
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }

    /// Closes stdin, asks the process group to stop, and kills it after `grace`.
    pub async fn stop(&self, grace: Duration) {
        self.stopping
            .get_or_init(|| async {
                if let Ok(mut g) = self.stdin.try_lock() {
                    g.take();
                }
                if tokio::time::timeout(Duration::from_millis(200), self.wait())
                    .await
                    .is_ok()
                {
                    return;
                }
                terminate_group(self.pid).await;
                if tokio::time::timeout(grace, self.wait()).await.is_err() {
                    kill_group(self.pid).await;
                    self.wait().await;
                }
            })
            .await;
    }
}

#[cfg(unix)]
fn set_process_group(cmd: &mut Command) {
    cmd.process_group(0);
}

#[cfg(windows)]
fn set_process_group(cmd: &mut Command) {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(unix)]
async fn terminate_group(pid: u32) {
    if pid > 0 {
        // SAFETY: kill(2) with a negative pid signals the agent's process group.
        unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGTERM) };
    }
}

#[cfg(unix)]
async fn kill_group(pid: u32) {
    if pid > 0 {
        // SAFETY: as above.
        unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
    }
}

// npm-installed agents are .cmd shims; only killing the tree stops the real agent.
// taskkill runs as an async child, so stopping an agent never blocks a runtime thread.
#[cfg(windows)]
async fn terminate_group(pid: u32) {
    taskkill(&["/T", "/PID", &pid.to_string()]).await;
}

#[cfg(windows)]
async fn kill_group(pid: u32) {
    taskkill(&["/T", "/F", "/PID", &pid.to_string()]).await;
}

#[cfg(windows)]
async fn taskkill(args: &[&str]) {
    let _ = Command::new("taskkill")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// Stops a leftover process group from an earlier run. Agents lead their own
/// group, so a reused pid that leads no group is left alone.
#[cfg(unix)]
pub fn kill_group_by_pid(pid: i64) {
    if pid <= 1 || pid > i32::MAX as i64 {
        return;
    }
    let pid = pid as libc::pid_t;
    // SAFETY: getpgid and kill only take integers.
    unsafe {
        if libc::getpgid(pid) != pid {
            return;
        }
        libc::kill(-pid, libc::SIGKILL);
    }
}

/// Runs once at server start, before any agent, so a blocking taskkill is fine here.
#[cfg(windows)]
pub fn kill_group_by_pid(pid: i64) {
    if pid > 0 {
        let _ = std::process::Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Whether a process with this id exists.
#[cfg(unix)]
pub fn process_alive(pid: i64) -> bool {
    // SAFETY: signal 0 only checks for existence.
    pid > 1 && pid <= i32::MAX as i64 && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
}

#[cfg(windows)]
pub fn process_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|w| w == pid.to_string())
        })
        .unwrap_or(false)
}

fn env_key(k: &str) -> String {
    if cfg!(windows) {
        k.to_uppercase()
    } else {
        k.to_string()
    }
}

/// The current process environment as `KEY=value` entries.
pub fn os_environ() -> Vec<String> {
    std::env::vars_os()
        .map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
        .collect()
}

/// Applies removals and additions to a base environment.
pub fn build_env(
    base: Option<Vec<String>>,
    add: &BTreeMap<String, String>,
    remove: &[String],
) -> Vec<String> {
    let base = base.unwrap_or_else(os_environ);
    let mut drop: HashSet<String> = remove.iter().map(|k| env_key(k)).collect();
    drop.extend(add.keys().map(|k| env_key(k)));
    let mut out: Vec<String> = base
        .into_iter()
        .filter(|kv| !drop.contains(&env_key(kv.split('=').next().unwrap_or(""))))
        .collect();
    out.extend(add.iter().map(|(k, v)| format!("{k}={v}")));
    out
}

/// Reads a variable from an environment list (the last one wins).
pub fn getenv(env: &[String], key: &str) -> String {
    for kv in env.iter().rev() {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if env_key(k) == env_key(key) {
            return v.to_string();
        }
    }
    String::new()
}

const LIST_SEPARATOR: char = if cfg!(windows) { ';' } else { ':' };

/// Finds a command using the PATH of the given environment, not of actp itself.
pub fn look_path(command: &str, env: &[String]) -> std::io::Result<PathBuf> {
    if command.is_empty() {
        return Err(std::io::Error::other("no command"));
    }
    if command.contains(['/', '\\']) {
        return match std::fs::metadata(command) {
            Ok(_) => Ok(PathBuf::from(command)),
            Err(e) => Err(std::io::Error::new(e.kind(), format!("{command}: {e}"))),
        };
    }
    let mut exts = vec![String::new()];
    if cfg!(windows) {
        let pathext = getenv(env, "PATHEXT").to_lowercase();
        exts = pathext.split(';').map(str::to_string).collect();
        if exts.len() == 1 && exts[0].is_empty() {
            exts = vec![".com".into(), ".exe".into(), ".bat".into(), ".cmd".into()];
        }
    }
    for dir in getenv(env, "PATH").split(LIST_SEPARATOR) {
        if dir.is_empty() {
            continue;
        }
        for ext in &exts {
            let candidate = Path::new(dir).join(format!("{command}{ext}"));
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{command} was not found on the agent PATH"),
    ))
}

fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) if !m.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// The environment of the user's login shell, which has the PATH agents
/// usually need. Falls back to the current environment.
pub async fn login_shell_env() -> Vec<String> {
    if cfg!(windows) {
        return os_environ();
    }
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into());
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(shell)
            .args(["-l", "-c", "env -0"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let Ok(Ok(out)) = out else {
        return os_environ();
    };
    if !out.status.success() || out.stdout.is_empty() {
        return os_environ();
    }
    let env: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|kv| kv.contains('='))
        .map(str::to_string)
        .collect();
    if getenv(&env, "PATH").is_empty() {
        return os_environ();
    }
    env
}

/// Adds folders to the end of PATH in env, skipping ones already there.
pub fn append_path(env: Vec<String>, dirs: &[PathBuf]) -> Vec<String> {
    let mut path = getenv(&env, "PATH");
    let mut have: HashSet<String> = path.split(LIST_SEPARATOR).map(str::to_string).collect();
    for d in dirs {
        let d = d.to_string_lossy().into_owned();
        if d.is_empty() || have.contains(&d) {
            continue;
        }
        if !path.is_empty() {
            path.push(LIST_SEPARATOR);
        }
        path.push_str(&d);
        have.insert(d);
    }
    let mut add = BTreeMap::new();
    add.insert("PATH".to_string(), path);
    build_env(Some(env), &add, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_building() {
        let base = vec!["A=1".to_string(), "B=2".into(), "PATH=/bin".into()];
        let mut add = BTreeMap::new();
        add.insert("B".to_string(), "3".to_string());
        let env = build_env(Some(base.clone()), &add, &["A".to_string()]);
        assert_eq!(env, ["PATH=/bin", "B=3"]);
        assert_eq!(getenv(&env, "B"), "3");
        let env = append_path(base, &[PathBuf::from("/x"), PathBuf::from("/bin")]);
        assert_eq!(getenv(&env, "PATH"), format!("/bin{LIST_SEPARATOR}/x"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runs_and_stops() {
        let spec = Spec {
            command: "sh".into(),
            args: vec!["-c".into(), "echo oops >&2; exec sleep 30".into()],
            dir: std::env::temp_dir(),
            ..Default::default()
        };
        let p = Process::start(&spec).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let start = std::time::Instant::now();
        p.stop(Duration::from_secs(2)).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(p.exited());
        assert_eq!(p.exit_code(), -1);
        assert_eq!(p.stderr(), "oops\n");
        assert!(look_path("definitely-not-a-command-actp", &os_environ()).is_err());
    }
}

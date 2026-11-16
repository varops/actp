//! Conformance against the Go implementation: the Go and Rust `actp` binaries
//! run against each other in all four pairings (bridge × server), with the
//! scripted ACP test agent from the Go repository (`cmd/actp-testagent`) as
//! the agent. A TCP proxy between bridge and server cuts connections.
//!
//! The Go binaries come from `ACTP_GO_BIN` and `ACTP_TESTAGENT_BIN`, or are
//! built with `go build` from the repository root when those are not set.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Notify;

mod common;
use common::{bins, hash, yaml_path};

fn bin(i: Impl) -> &'static Path {
    match i {
        Impl::Go => &bins().go,
        Impl::Rust => &bins().rust,
    }
}

const TOKEN: &str = "actp_conformance_token";
const OTHER_TOKEN: &str = "actp_conformance_other";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Impl {
    Go,
    Rust,
}

/// A temporary folder with a home, a workspace and an agent store.
struct Dirs {
    root: PathBuf,
    home: PathBuf,
    site: PathBuf,
}

impl Dirs {
    fn new(name: &str) -> Dirs {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conf-{}-{name}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let site = root.join("site");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&site).unwrap();
        let root = common::canon(&root);
        let site = root.join("site");
        let home = root.join("home");
        Dirs { root, home, site }
    }

    fn envs(&self, cmd: &mut Command) {
        cmd.env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData"))
            .env_remove("ACTP_TOKEN");
    }
}

/// The server config: a scripted agent, a workspace, and two tokens.
fn server_config(d: &Dirs, port: u16, tokens_in_file: bool) -> String {
    let tokens = format!(
        "    - name: tester\n      hash: \"{}\"\n      agents: [\"*\"]\n      workspaces: [\"*\"]\n      default_workspace: site\n      map:\n        /client/repo: site\n    - name: limited\n      hash: \"{}\"\n      agents: [other]\n      workspaces: [site]\n",
        hash(TOKEN),
        hash(OTHER_TOKEN)
    );
    let (inline, file) = if tokens_in_file {
        (String::new(), format!("tokens:\n{tokens}"))
    } else {
        (format!("  tokens:\n{tokens}"), String::new())
    };
    std::fs::write(d.root.join("tokens.yaml"), file).unwrap();
    format!(
        "server:\n  name: conformance\n  listen: 127.0.0.1:{port}\n  shell_env: false\n  idle_close: 2s\n  prompt_timeout: 30s\n  log_dir: {}\n  state_dir: {}\n  tokens_file: {}\n  workspaces:\n    - name: site\n      path: {}\n  agents:\n    - id: test\n      command: {}\n      env:\n        ACTP_TESTAGENT_STORE: {}\n      max_unattended: 5s\n    - id: other\n      command: {}\n{inline}remotes_file: {}\n",
        yaml_path(&d.root.join("logs")),
        yaml_path(&d.root.join("state")),
        yaml_path(&d.root.join("tokens.yaml")),
        yaml_path(&d.site),
        yaml_path(&bins().agent),
        yaml_path(&d.root.join("store")),
        yaml_path(&bins().agent),
        yaml_path(&d.root.join("remotes.yaml")),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct ServerProc {
    // Held to keep the server running (killed on drop); signalled by the revoke test.
    #[cfg_attr(not(unix), allow(dead_code))]
    child: Child,
    port: u16,
    dirs: Dirs,
}

impl ServerProc {
    async fn start(which: Impl, name: &str, tokens_in_file: bool) -> ServerProc {
        let dirs = Dirs::new(name);
        for _ in 0..5 {
            let port = free_port();
            let config = dirs.root.join("actp.yaml");
            std::fs::write(&config, server_config(&dirs, port, tokens_in_file)).unwrap();
            let log = std::fs::File::create(dirs.root.join(format!("server-{port}.log"))).unwrap();
            let mut cmd = Command::new(bin(which));
            cmd.arg("serve")
                .arg("--config")
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .kill_on_drop(true);
            dirs.envs(&mut cmd);
            let mut child = cmd.spawn().expect("start server");
            for _ in 0..100 {
                if let Ok(r) = http_get(port, "/health", None).await
                    && r.0 == 200
                {
                    return ServerProc { child, port, dirs };
                }
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = child.kill().await;
        }
        panic!(
            "{which:?} server did not start; see {}",
            dirs.root.display()
        );
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.dirs.root.join("logs").join("audit.jsonl")).unwrap_or_default()
    }

    /// Waits for the probe at start to report the scripted agent.
    async fn wait_probed(&self) {
        for _ in 0..100 {
            let (_, _, body) = http_get(self.port, "/api/v1/agents", Some(TOKEN))
                .await
                .unwrap();
            if body.contains("\"status\":\"ready\"") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("agent never probed ready");
    }
}

/// A tiny HTTP/1.1 GET: status, headers (lowercase names), body.
async fn http_get(
    port: u16,
    path: &str,
    token: Option<&str>,
) -> std::io::Result<(u16, BTreeMap<String, String>, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf))
        .await
        .map_err(|_| std::io::Error::other("timeout"))??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no header end"))?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_lowercase(), v.to_string()))
        .collect::<BTreeMap<_, _>>();
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|t| t == "chunked")
    {
        dechunk(body)
    } else {
        body.to_string()
    };
    Ok((status, headers, body))
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = s.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.push_str(&rest[..n]);
        s = &rest[n + 2..];
    }
    out
}

/// A TCP proxy between bridge and server that can cut every connection at once.
struct DropProxy {
    port: u16,
    conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl DropProxy {
    async fn start(target: u16) -> DropProxy {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let c2 = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut down, _)) = ln.accept().await {
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", target)).await else {
                    continue;
                };
                let h = tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                });
                c2.lock().unwrap().push(h.abort_handle());
            }
        });
        DropProxy { port, conns }
    }

    /// Cuts every open connection, like a network failure.
    fn drop_all(&self) {
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

/// An ACP client driving one bridge process over stdio.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    notify: Arc<Notify>,
    next_id: i64,
}

impl Client {
    async fn start(
        which: Impl,
        server: &ServerProc,
        base_port: u16,
        agent: &str,
        token: &str,
        extra: &[&str],
    ) -> Client {
        let client_cfg = server.dirs.root.join("client.yaml");
        std::fs::write(
            &client_cfg,
            format!(
                "remotes_file: {}\n",
                yaml_path(&server.dirs.root.join("remotes.yaml"))
            ),
        )
        .unwrap();
        let mut cmd = Command::new(bin(which));
        cmd.arg("bridge")
            .arg(format!("{agent}@http://127.0.0.1:{base_port}"))
            .args([
                "--token-env",
                "ACTP_CONF_TOKEN",
                "--name",
                "conformance",
                "--config",
            ])
            .arg(&client_cfg)
            .args(extra)
            .env("ACTP_CONF_TOKEN", token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        server.dirs.envs(&mut cmd);
        let mut child = cmd.spawn().expect("start bridge");
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let stderr: Arc<Mutex<String>> = Arc::default();
        let notify = Arc::new(Notify::new());
        let (l2, n2) = (lines.clone(), notify.clone());
        let mut out = BufReader::new(child.stdout.take().unwrap()).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = out.next_line().await {
                l2.lock().unwrap().push(line);
                n2.notify_waiters();
            }
        });
        let e2 = stderr.clone();
        let mut err = child.stderr.take().unwrap();
        tokio::spawn(async move {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s).await;
            e2.lock().unwrap().push_str(&s);
        });
        Client {
            stdin: child.stdin.take(),
            child,
            lines,
            stderr,
            notify,
            next_id: 0,
        }
    }

    async fn send(&mut self, v: Value) {
        let mut line = serde_json::to_string(&v).unwrap();
        line.push('\n');
        self.stdin
            .as_mut()
            .expect("stdin open")
            .write_all(line.as_bytes())
            .await
            .unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> i64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        id
    }

    /// The first output line matching `f`, as raw text and parsed.
    async fn wait(&self, what: &str, f: impl Fn(&Value) -> bool) -> (String, Value) {
        let deadline = tokio::time::Instant::now() + WAIT;
        let mut seen = 0;
        loop {
            let notified = self.notify.notified();
            {
                let lines = self.lines.lock().unwrap();
                for l in &lines[seen..] {
                    if let Ok(v) = serde_json::from_str::<Value>(l)
                        && f(&v)
                    {
                        return (l.clone(), v);
                    }
                }
                seen = lines.len();
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                panic!(
                    "timed out waiting for {what}; got:\n{}\nstderr: {}",
                    self.lines.lock().unwrap().join("\n"),
                    self.stderr.lock().unwrap()
                );
            }
        }
    }

    async fn response(&self, id: i64) -> (String, Value) {
        self.wait(&format!("response {id}"), |v| {
            v.get("id") == Some(&json!(id)) && v.get("method").is_none()
        })
        .await
    }

    async fn call(&mut self, method: &str, params: Value) -> (String, Value) {
        let id = self.request(method, params).await;
        self.response(id).await
    }

    async fn chunk(&self, text: &str) -> Value {
        self.wait(&format!("chunk {text}"), |v| {
            v["method"] == "session/update" && chunk_text(v).contains(text)
        })
        .await
        .1
    }

    fn chunks(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["method"] == "session/update")
            .map(|v| chunk_text(&v))
            .collect()
    }

    async fn initialize(&mut self) -> String {
        let (raw, v) = self
            .call("initialize", json!({"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": true}, "terminal": true, "elicitation": {"form": {}}}, "clientInfo": {"name": "conformance <&>", "version": "1"}}))
            .await;
        assert!(v.get("error").is_none(), "initialize: {raw}");
        raw
    }

    async fn new_session(&mut self, cwd: &str) -> String {
        let (raw, v) = self
            .call("session/new", json!({"cwd": cwd, "mcpServers": []}))
            .await;
        v["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("session/new: {raw}"))
            .to_string()
    }

    async fn prompt(&mut self, sid: &str, text: &str) -> i64 {
        self.request(
            "session/prompt",
            json!({"sessionId": sid, "prompt": [{"type": "text", "text": text}]}),
        )
        .await
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    /// Waits for the bridge to exit: its exit code and stderr.
    async fn exit(&mut self) -> (i32, String) {
        let status = tokio::time::timeout(WAIT, self.child.wait())
            .await
            .expect("bridge did not exit")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        (
            status.code().unwrap_or(-1),
            self.stderr.lock().unwrap().clone(),
        )
    }
}

fn chunk_text(v: &Value) -> String {
    v["params"]["update"]["content"]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn stop_reason(v: &Value) -> &str {
    v["result"]["stopReason"].as_str().unwrap_or_default()
}

/// What every pairing must see as the `initialize` answer, byte for byte:
/// the terminal-auth hint removed and the result re-encoded with sorted keys.
const INITIALIZE_ANSWER: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"agentCapabilities":{"loadSession":true,"sessionCapabilities":{"close":{},"list":{}}},"agentInfo":{"name":"actp-testagent","version":"1.0.0"},"authMethods":[{"description":"Run `testagent login` on the agent host","id":"login","name":"Login"}],"protocolVersion":1}}"#;

// ---------------------------------------------------------------- scenarios

async fn auth_refused(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "auth", false).await;
    let mut c = Client::start(bridge, &s, s.port, "test", "actp_wrong", &[]).await;
    let (code, stderr) = c.exit().await;
    assert_eq!(
        (code, stderr.as_str()),
        (1, "actp: missing or invalid token (HTTP 401)\n")
    );

    let mut c = Client::start(bridge, &s, s.port, "test", OTHER_TOKEN, &[]).await;
    let (code, stderr) = c.exit().await;
    assert_eq!(
        (code, stderr.as_str()),
        (1, "actp: this token may not use agent test (HTTP 403)\n")
    );

    let mut c = Client::start(bridge, &s, s.port, "nope", TOKEN, &[]).await;
    let (code, stderr) = c.exit().await;
    assert_eq!(
        (code, stderr.as_str()),
        (1, "actp: no agent named nope (HTTP 404)\n")
    );
}

async fn folder_not_allowed(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "folder", false).await;
    let mut c = Client::start(bridge, &s, s.port, "test", TOKEN, &[]).await;
    assert_eq!(c.initialize().await, INITIALIZE_ANSWER);
    let (raw, _) = c
        .call(
            "session/new",
            json!({"cwd": "/somewhere/else", "mcpServers": []}),
        )
        .await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32602,"message":"cwd not allowed: /somewhere/else"},"id":2,"jsonrpc":"2.0"}"#
    );
    let (raw, _) = c
        .call(
            "session/new",
            json!({"cwd": "actp://nope", "mcpServers": []}),
        )
        .await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32602,"message":"cwd not allowed: actp://nope (unknown workspace \"nope\")"},"id":3,"jsonrpc":"2.0"}"#
    );
    let (raw, _) = c
        .call(
            "session/new",
            json!({"cwd": "actp://site/../..", "mcpServers": []}),
        )
        .await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32602,"message":"cwd not allowed: actp://site/../.. (leaves workspace \"site\")"},"id":4,"jsonrpc":"2.0"}"#
    );
    // A mapped client folder works, and the agent sees the server folder.
    let sid = c.new_session("/client/repo").await;
    c.prompt(&sid, "cwd").await;
    c.chunk(&s.dirs.site.to_string_lossy()).await;
    assert!(s.audit().contains("\"event\":\"cwd_rejected\""));
    c.close_stdin();
    assert_eq!(c.exit().await.0, 0);
}

async fn full_session(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "full", false).await;
    let mut c = Client::start(bridge, &s, s.port, "test", TOKEN, &[]).await;
    assert_eq!(c.initialize().await, INITIALIZE_ANSWER);
    let sid = c.new_session("actp://site").await;

    let id = c.prompt(&sid, "echo hello <there> & you").await;
    c.chunk("hello <there> & you").await;
    let (raw, v) = c.response(id).await;
    assert_eq!(stop_reason(&v), "end_turn", "{raw}");
    assert_eq!(
        raw,
        format!(r#"{{"id":{id},"jsonrpc":"2.0","result":{{"stopReason":"end_turn"}}}}"#)
    );

    // fs and terminal never reach the agent; other capabilities do.
    let id = c.prompt(&sid, "caps").await;
    let caps = chunk_text(&c.chunk("elicitation").await);
    assert_eq!(caps, r#"{"elicitation":{"form":{}}}"#);
    c.response(id).await;

    // A permission prompt goes to the client and the answer back to the agent.
    let id = c.prompt(&sid, "permission").await;
    let (_, req) = c
        .wait("permission request", |v| {
            v["method"] == "session/request_permission"
        })
        .await;
    c.send(json!({"jsonrpc": "2.0", "id": req["id"], "result": {"outcome": {"outcome": "selected", "optionId": "allow"}}})).await;
    c.chunk(r#""optionId":"allow""#).await;
    c.response(id).await;

    // Files stay on the agent host.
    let id = c.prompt(&sid, "fs").await;
    c.chunk("fs: error -32601").await;
    c.response(id).await;
    assert!(
        !c.lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("\"method\":\"fs/"))
    );

    // session/list shows the client's own cwd form.
    let (raw, _) = c.call("session/list", json!({"cwd": "actp://site"})).await;
    assert!(raw.contains(r#""cwd":"actp://site""#), "{raw}");

    c.close_stdin();
    let (code, stderr) = c.exit().await;
    assert_eq!(code, 0, "{stderr}");
    wait_until("link to end after the client left", || {
        s.audit().contains("client left and the turn is done")
    })
    .await;
    assert!(s.audit().contains("\"event\":\"link_unattended\""));

    // The session can be loaded on a new link and shows the earlier turns.
    let mut c2 = Client::start(bridge, &s, s.port, "test", TOKEN, &[]).await;
    c2.initialize().await;
    let (raw, v) = c2
        .call(
            "session/load",
            json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(v.get("error").is_none(), "{raw}");
    c2.chunk("hello <there> & you").await;
}

async fn drop_and_resume(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "drop", false).await;
    let proxy = DropProxy::start(s.port).await;
    let mut c = Client::start(bridge, &s, proxy.port, "test", TOKEN, &[]).await;
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "slow 20").await;
    c.chunk("chunk 3").await;
    proxy.drop_all(); // mid-turn, every TCP connection
    let (raw, v) = c.response(id).await;
    assert_eq!(stop_reason(&v), "end_turn", "{raw}");
    let want: Vec<String> = (1..=20).map(|i| format!("chunk {i}")).collect();
    assert_eq!(c.chunks(), want, "chunks lost, doubled or out of order");
    assert!(
        s.audit().contains("\"event\":\"link_resumed\""),
        "the drop did not happen"
    );

    // A second drop while the agent waits on the client: the prompt survives.
    let id = c.prompt(&sid, "permission").await;
    let (_, req) = c
        .wait("permission request", |v| {
            v["method"] == "session/request_permission"
        })
        .await;
    proxy.drop_all();
    tokio::time::sleep(Duration::from_millis(300)).await;
    c.send(json!({"jsonrpc": "2.0", "id": req["id"], "result": {"outcome": {"outcome": "selected", "optionId": "deny"}}})).await;
    c.chunk(r#""optionId":"deny""#).await;
    c.response(id).await;
    let n = c
        .lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("session/request_permission"))
        .count();
    assert_eq!(n, 1, "the permission request was delivered {n} times");

    c.close_stdin();
    assert_eq!(c.exit().await.0, 0);
}

#[cfg(unix)]
async fn token_revoke(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "revoke", true).await;
    let proxy = DropProxy::start(s.port).await;
    let mut c = Client::start(bridge, &s, proxy.port, "test", TOKEN, &[]).await;
    c.initialize().await;
    let sid = c.new_session("actp://site").await;

    // Revoke: remove the token from the tokens file and reload (SIGHUP), as
    // `actp token revoke` plus a reload does.
    std::fs::write(s.dirs.root.join("tokens.yaml"), format!("tokens:\n    - name: limited\n      hash: \"{}\"\n      agents: [other]\n      workspaces: [site]\n", hash(OTHER_TOKEN))).unwrap();
    // SAFETY: signals the server process this test started.
    unsafe { libc::kill(s.child.id().unwrap() as i32, libc::SIGHUP) };
    for _ in 0..100 {
        if http_get(s.port, "/api/v1/info", Some(TOKEN))
            .await
            .unwrap()
            .0
            == 401
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        http_get(s.port, "/api/v1/info", Some(TOKEN))
            .await
            .unwrap()
            .0,
        401,
        "token still accepted after reload"
    );

    // Like Go: the open link keeps working until its connection drops...
    let id = c.prompt(&sid, "echo still here").await;
    c.chunk("still here").await;
    c.response(id).await;
    // ...and then it cannot come back.
    let id = c.prompt(&sid, "slow 50").await;
    c.chunk("chunk 1").await;
    proxy.drop_all();
    let (raw, v) = c.response(id).await;
    assert_eq!(v["error"]["code"], -32000, "{raw}");
    assert_eq!(
        v["error"]["message"], "remote session lost: missing or invalid token (HTTP 401)",
        "{raw}"
    );
    let (code, stderr) = c.exit().await;
    assert_eq!(
        (code, stderr.as_str()),
        (
            1,
            "actp: remote session lost: missing or invalid token (HTTP 401)\n"
        )
    );
}

async fn agent_crash(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "crash", false).await;
    let mut c = Client::start(bridge, &s, s.port, "test", TOKEN, &[]).await;
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "burst-crash 300").await;
    let (raw, _) = c.response(id).await;
    assert_eq!(
        raw,
        format!(
            r#"{{"error":{{"code":-32000,"message":"remote session lost: agent test exited with code 4: testagent: crashing after a burst"}},"id":{id},"jsonrpc":"2.0"}}"#
        )
    );
    assert_eq!(c.chunks().len(), 300, "output before the exit was lost");
    let (code, stderr) = c.exit().await;
    assert_eq!(
        (code, stderr.as_str()),
        (
            1,
            "actp: remote session lost: agent test exited with code 4: testagent: crashing after a burst\n"
        )
    );
}

/// Messages whose envelope two decoders could read differently (a key in two
/// spellings) must be refused before any policy, not forwarded: otherwise the
/// server routes by one reading and the agent acts on the other.
async fn ambiguous_envelope(bridge: Impl, server: Impl) {
    let s = ServerProc::start(server, "envelope", false).await;
    let mut c = Client::start(bridge, &s, s.port, "test", TOKEN, &[]).await;
    c.initialize().await;
    // A: the server would see session/prompt, the agent session/new in "/".
    c.send(json!({"jsonrpc": "2.0", "id": 10, "method": "session/new", "Method": "session/prompt", "params": {"cwd": "/", "mcpServers": [{"name": "x", "command": "not-a-real-command", "args": [], "env": []}]}})).await;
    let (raw, _) = c.response(10).await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32600,"message":"invalid request: ambiguous JSON-RPC envelope: key \"Method\" differs from \"method\" only in case"},"id":10,"jsonrpc":"2.0"}"#
    );
    // B: the server would see a notification, the agent a request.
    c.send(json!({"jsonrpc": "2.0", "id": 11, "Id": null, "method": "session/new", "params": {"cwd": "/", "mcpServers": []}})).await;
    let (raw, _) = c.response(11).await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32600,"message":"invalid request: ambiguous JSON-RPC envelope: key \"Id\" differs from \"id\" only in case"},"id":11,"jsonrpc":"2.0"}"#
    );
    // A null id is still a request, so its cwd is checked.
    c.send(json!({"jsonrpc": "2.0", "id": null, "method": "session/new", "params": {"cwd": "/", "mcpServers": []}})).await;
    let (raw, _) = c
        .wait("null-id answer", |v| {
            v.get("id") == Some(&Value::Null) && v.get("error").is_some()
        })
        .await;
    assert_eq!(
        raw,
        r#"{"error":{"code":-32602,"message":"cwd not allowed: /"},"id":null,"jsonrpc":"2.0"}"#
    );
    // The link is still usable, and the agent never opened a session in "/".
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "echo still fine").await;
    c.response(id).await;
    let n = c
        .lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains(r#""id":10,"#) || l.contains(r#""id":11,"#))
        .count();
    assert_eq!(n, 2, "the agent answered a refused request");
    for entry in std::fs::read_dir(s.dirs.root.join("store"))
        .unwrap()
        .flatten()
    {
        let stored = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
            !stored.contains(r#""cwd":"/""#),
            "the agent opened a session in /: {stored}"
        );
    }
    assert!(s.audit().contains("\"event\":\"message_refused\""));
    c.close_stdin();
    assert_eq!(c.exit().await.0, 0);
}

async fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

macro_rules! pairings {
    ($name:ident) => {
        mod $name {
            use super::*;
            #[tokio::test(flavor = "multi_thread")]
            async fn go_bridge_go_server() {
                super::$name(Impl::Go, Impl::Go).await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn go_bridge_rust_server() {
                super::$name(Impl::Go, Impl::Rust).await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn rust_bridge_go_server() {
                super::$name(Impl::Rust, Impl::Go).await
            }
            #[tokio::test(flavor = "multi_thread")]
            async fn rust_bridge_rust_server() {
                super::$name(Impl::Rust, Impl::Rust).await
            }
        }
    };
}

pairings!(auth_refused);
pairings!(folder_not_allowed);
pairings!(full_session);
pairings!(drop_and_resume);
pairings!(agent_crash);
pairings!(ambiguous_envelope);
#[cfg(unix)]
pairings!(token_revoke);

// ------------------------------------------------- byte-level server parity

/// The same requests against a Go and a Rust server give the same status,
/// headers that matter, and body bytes.
#[tokio::test(flavor = "multi_thread")]
async fn management_endpoints_match_go() {
    let go = ServerProc::start(Impl::Go, "mgmt-go", false).await;
    let rs = ServerProc::start(Impl::Rust, "mgmt-rs", false).await;
    go.wait_probed().await;
    rs.wait_probed().await;
    let cases: &[(&str, Option<&str>)] = &[
        ("/health", None),
        ("/api/v1/info", None),
        ("/api/v1/info", Some("actp_wrong")),
        ("/api/v1/agents", Some(TOKEN)),
        ("/api/v1/agents", Some(OTHER_TOKEN)),
        ("/nope", Some(TOKEN)),
        ("/nope", None),
        ("/actp/v1/agents/test/link", Some(TOKEN)),
        ("/actp/v1/agents/nope/link", Some(TOKEN)),
        ("/actp/v1/agents/test/link", Some(OTHER_TOKEN)),
    ];
    for (path, token) in cases {
        let (gs, gh, gb) = http_get(go.port, path, *token).await.unwrap();
        let (rs_, rh, rb) = http_get(rs.port, path, *token).await.unwrap();
        assert_eq!((rs_, rb.as_str()), (gs, gb.as_str()), "{path} {token:?}");
        for h in ["content-type", "www-authenticate", "x-content-type-options"] {
            assert_eq!(rh.get(h), gh.get(h), "{path} {token:?}: header {h}");
        }
    }
    // /api/v1/info differs only in the version string.
    let (_, _, gb) = http_get(go.port, "/api/v1/info", Some(TOKEN))
        .await
        .unwrap();
    let (_, _, rb) = http_get(rs.port, "/api/v1/info", Some(TOKEN))
        .await
        .unwrap();
    let norm = |b: &str| {
        let mut v: Value = serde_json::from_str(b).unwrap();
        v["version"] = json!("X");
        v
    };
    assert_eq!(norm(&rb), norm(&gb));
    assert!(
        rb.starts_with(r#"{"name":"conformance","promptTimeoutSeconds":30,"version":"#),
        "{rb}"
    );
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn raw_link(port: u16) -> (Ws, BTreeMap<String, String>) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://127.0.0.1:{port}/actp/v1/agents/test/link")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {TOKEN}").parse().unwrap());
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", "actp.v1".parse().unwrap());
    let (ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    (ws, headers)
}

/// Reads text frames until `f` says stop; returns them.
async fn frames_until(ws: &mut Ws, f: impl Fn(&[String]) -> bool) -> Vec<String> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    while !f(&got) {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => got.push(t.as_str().to_string()),
            Ok(Some(Ok(_))) => {}
            other => panic!("socket ended early ({other:?}) after {got:?}"),
        }
    }
    got
}

/// Frames as the peer would see them, with acks (which depend on timing) removed.
fn without_acks(frames: &[String]) -> Vec<String> {
    frames
        .iter()
        .filter(|f| !f.starts_with(r#"{"t":"ack""#))
        .map(|f| {
            let v: Value = serde_json::from_str(f).unwrap();
            match v.get("ack") {
                Some(a) => f.replace(&format!(",\"ack\":{a}"), ""),
                None => f.clone(),
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_frames_match_go() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let go = ServerProc::start(Impl::Go, "wire-go", false).await;
    let rs = ServerProc::start(Impl::Rust, "wire-rs", false).await;
    let mut results = Vec::new();
    for s in [&go, &rs] {
        let (mut ws, h) = raw_link(s.port).await;
        assert_eq!(h.get("actp-link-id").map(|v| v.len()), Some(48));
        assert_eq!(h.get("actp-last-seq").map(String::as_str), Some("0"));
        assert_eq!(h.get("actp-prompt-timeout").map(String::as_str), Some("30"));
        assert_eq!(
            h.get("sec-websocket-protocol").map(String::as_str),
            Some("actp.v1")
        );
        let send = [
            r#"{"t":"msg","seq":1,"msg":{"jsonrpc":"2.0","id":"i<1>","method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"terminal":true,"zeta":{"b":1,"a":"x&y"}},"clientInfo":{"name":"<raw>","version":"1"}}}}"#,
            r#"{"t":"msg","seq":2,"msg":{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/nowhere","mcpServers":[]}}}"#,
            r#"{"t":"msg","seq":3,"msg":{"jsonrpc":"2.0","id":3,"method":"session/new","params":{"cwd":"actp://site","mcpServers":[{"name":"local","command":"npx"},{"name":"web","type":"http","url":"https://mcp.example.com/<x>"}]}}}"#,
            r#"{"t":"ping"}"#,
        ];
        for f in send {
            ws.send(Message::text(f)).await.unwrap();
        }
        let frames = frames_until(&mut ws, |got| {
            got.iter().filter(|f| f.contains(r#""t":"msg""#)).count() >= 3
                && got.iter().any(|f| f == r#"{"t":"pong"}"#)
        })
        .await;
        let mut frames = without_acks(&frames);
        frames.retain(|f| f != r#"{"t":"pong"}"#);
        // The new session's id differs per run; compare its shape.
        for f in frames.iter_mut() {
            if let Some(i) = f.find(r#""sessionId":"s-"#) {
                let end = f[i + 13..].find('"').unwrap() + i + 13;
                f.replace_range(i..end + 1, r#""sessionId":"S""#);
            }
        }
        // A frame with a gap, then garbage: both get the same error frames.
        ws.send(Message::text(
            r#"{"t":"msg","seq":9,"msg":{"jsonrpc":"2.0","method":"x"}}"#,
        ))
        .await
        .unwrap();
        let gap = frames_until(&mut ws, |got| {
            got.iter().any(|f| f.contains("sequence_gap"))
        })
        .await;
        frames.push(
            gap.into_iter()
                .find(|f| f.contains("sequence_gap"))
                .unwrap(),
        );
        results.push(frames);
    }
    assert_eq!(
        results[1], results[0],
        "Rust server frames differ from Go's"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn config_acceptance_matches_go() {
    let d = Dirs::new("config");
    let base = format!(
        "  state_dir: {}\n  log_dir: {}\n  tokens_file: {}\n",
        yaml_path(&d.root.join("state")),
        yaml_path(&d.root.join("logs")),
        yaml_path(&d.root.join("tokens.yaml"))
    );
    let cases = [
        "server:\n  name: x\n",
        "server:\n  lisen: x\n",
        "server:\n  Name: x\n",
        "server:\n  name: a\n  name: b\n",
        "server:\n  dashboard: {}\n",
        "server:\n  idle_close: 10\n",
        "server:\n  idle_close: 1.5h\n",
        "server:\n  idle_close: -1s\n",
        "server:\n  spool_limit: 8MB\n",
        "server:\n  spool_limit: 1.5GB\n",
        "server:\n  insecure_listen: yes\n",
        "server:\n  insecure_listen: True\n",
        "server:\n  tunnel:\n    mode: off\n",
        "server:\n  tunnel:\n    mode: true\n",
        "server:\n  tunnel:\n    mode: named\n",
        "server:\n  tunnel:\n    mode: quick\n    provider: cloudflare\n",
        "server:\n  agents:\n    - id: a\n      command: x\n      max_links: \"5\"\n",
        "server:\n  agents:\n    - id: a\n      command: x\n      max_links: true\n",
        "server:\n  agents:\n    - id: Bad\n      command: x\n",
        "server:\n  agents:\n    - id: a\n      preset: nope\n",
        "server:\n  agents:\n    - id: a\n      preset: claude-code\n      permissions: sometimes\n",
        "server:\n  agents:\n    - id: a\n      command: x\n      args: [1, true]\n      env: {A: 1}\n",
        "server:\n  workspaces:\n    - name: w\n      path: relative/path\n",
        "server:\n  tokens:\n    - name: t\n      hash: md5:x\n",
        "server:\n  tokens:\n    - name: t\n      hash: sha256:x\n      agents: [ghost]\n",
        "server:\n  tls_cert: /x\n",
        "server:\n  audit:\n    log_prompts: true\n",
        "version: 2\nserver:\n  name: x\n",
        "dashboard:\n  terminal: true\nserver:\n  name: x\n",
        "remotes:\n  - name: r\nserver:\n  name: x\n",
    ];
    for (i, case) in cases.iter().enumerate() {
        let body = if case.contains("server:\n") {
            case.replacen("server:\n", &format!("server:\n{base}"), 1)
        } else {
            case.to_string()
        };
        let path = d.root.join(format!("case{i}.yaml"));
        std::fs::write(
            &path,
            format!(
                "{body}remotes_file: {}\n",
                yaml_path(&d.root.join("remotes.yaml"))
            ),
        )
        .unwrap();
        let run = |which: Impl, args: &[&str]| {
            let mut cmd = std::process::Command::new(bin(which));
            cmd.args(args)
                .arg("--config")
                .arg(&path)
                .env("HOME", &d.home)
                .env("USERPROFILE", &d.home)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.status().unwrap().success()
        };
        let go_ok = run(Impl::Go, &["token", "list"]);
        let rs_ok = run(Impl::Rust, &["check-config"]);
        assert_eq!(rs_ok, go_ok, "case {i}: {case:?} (Go accepts: {go_ok})");
    }
}

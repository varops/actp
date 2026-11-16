//! End-to-end behaviour of the Rust libraries in one process: a stdio ACP
//! client → `actp_client::run` → TCP proxy → `actp_server` → the scripted
//! test agent. Ports of the Go tests in `internal/e2e`, with fast timers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actp_proto::jsonrpc::{self, Kind, Line, Message};
use actp_proto::{Endpoint, FrameConn, deliver_fn};
use actp_server::config::Config;
use actp_server::{Server, http};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

mod common;
use common::{bins, hash, yaml_path};

const TOKEN: &str = "actp_testtoken";

fn fast_wire() -> actp_proto::Options {
    actp_proto::Options {
        heartbeat_every: Duration::from_millis(50),
        dead_after: Duration::from_millis(400),
        ack_delay: Duration::from_millis(20),
        tick: Duration::from_millis(10),
        ..Default::default()
    }
}

struct Env {
    srv: Server,
    port: u16,
    proxy: Proxy,
    root: std::path::PathBuf,
    site: String,
    stop: CancellationToken,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop.cancel();
        self.proxy.drop_all();
    }
}

async fn env(adjust: impl FnOnce(&mut actp_server::config::Server)) -> Env {
    if std::env::var_os("ACTP_TEST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
    }
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "e2e-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("site")).unwrap();
    let root = common::canon(&root);
    let site = root.join("site");
    let yaml = format!(
        "server:\n  idle_close: 1s\n  prompt_timeout: 2s\n  log_dir: {}\n  state_dir: {}\n  tokens_file: {}\n  workspaces:\n    - name: site\n      path: {}\n  agents:\n    - id: test\n      command: {}\n      env:\n        ACTP_TESTAGENT_STORE: {}\n      max_unattended: 1s\n  tokens:\n    - name: tester\n      hash: \"{}\"\n      agents: [\"*\"]\n      workspaces: [\"*\"]\n      default_workspace: site\n      map:\n        /client/repo: site\n",
        yaml_path(&root.join("logs")),
        yaml_path(&root.join("state")),
        yaml_path(&root.join("tokens.yaml")),
        yaml_path(&site),
        yaml_path(&bins().agent),
        yaml_path(&root.join("store")),
        hash(TOKEN)
    );
    let mut cfg = Config::parse(&yaml).unwrap();
    adjust(cfg.server.as_mut().unwrap());
    cfg.validate().unwrap();
    let sc = cfg.server.clone().unwrap();
    let srv = Server::new(
        sc,
        actp_server::Options {
            version: "test".into(),
            base_env: Some(actp_server::agentproc::os_environ()),
            wire: fast_wire(),
            tick: Duration::from_millis(20),
            mode_reset_timeout: Duration::from_secs(1),
            held_load_timeout: Duration::from_secs(2),
            max_held_messages: 200,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let stop = CancellationToken::new();
    tokio::spawn(http::serve(
        srv.clone(),
        http::TcpAcceptor(ln),
        stop.clone(),
    ));
    let proxy = Proxy::start(port).await;
    Env {
        srv,
        port,
        proxy,
        site: site.to_string_lossy().into_owned(),
        root,
        stop,
    }
}

impl Env {
    fn bridge(&self) -> Client {
        self.bridge_with(|_| {})
    }

    fn bridge_with(&self, f: impl FnOnce(&mut actp_client::Options)) -> Client {
        let mut o = actp_client::Options {
            agent: "test".into(),
            base_url: format!("http://127.0.0.1:{}", self.proxy.port),
            token: TOKEN.into(),
            client_name: "e2e".into(),
            wire: fast_wire(),
            max_backoff: Duration::from_millis(100),
            give_up_after: Duration::from_secs(3),
            ..Default::default()
        };
        f(&mut o);
        Client::start(o)
    }

    fn audit_has(&self, event: &str) -> bool {
        std::fs::read_to_string(self.root.join("logs").join("audit.jsonl"))
            .unwrap_or_default()
            .contains(&format!("\"event\":\"{event}\""))
    }

    async fn wait_no_links(&self) {
        let srv = self.srv.clone();
        wait_until("all links to end", move || srv.links().is_empty()).await;
    }
}

async fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

type Conns = Arc<Mutex<Vec<(tokio::task::AbortHandle, Arc<AtomicBool>)>>>;

/// Forwards TCP to the server; can cut, freeze or refuse connections.
struct Proxy {
    port: u16,
    conns: Conns,
    paused: Arc<AtomicBool>,
}

impl Proxy {
    async fn start(target: u16) -> Proxy {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let conns: Conns = Arc::default();
        let paused = Arc::new(AtomicBool::new(false));
        let (c2, p2) = (conns.clone(), paused.clone());
        tokio::spawn(async move {
            while let Ok((down, _)) = ln.accept().await {
                if p2.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(up) = TcpStream::connect(("127.0.0.1", target)).await else {
                    continue;
                };
                let frozen = Arc::new(AtomicBool::new(false));
                let f2 = frozen.clone();
                let h = tokio::spawn(async move {
                    let (mut dr, mut dw) = down.into_split();
                    let (mut ur, mut uw) = up.into_split();
                    let f3 = f2.clone();
                    let a = async move {
                        let mut buf = vec![0u8; 32 << 10];
                        while let Ok(n) = dr.read(&mut buf).await {
                            if n == 0
                                || (!f2.load(Ordering::SeqCst)
                                    && uw.write_all(&buf[..n]).await.is_err())
                            {
                                break;
                            }
                        }
                    };
                    let b = async move {
                        let mut buf = vec![0u8; 32 << 10];
                        while let Ok(n) = ur.read(&mut buf).await {
                            if n == 0
                                || (!f3.load(Ordering::SeqCst)
                                    && dw.write_all(&buf[..n]).await.is_err())
                            {
                                break;
                            }
                        }
                    };
                    tokio::join!(a, b);
                });
                c2.lock().unwrap().push((h.abort_handle(), frozen));
            }
        });
        Proxy {
            port,
            conns,
            paused,
        }
    }

    /// Cuts every open connection, like a network failure.
    fn drop_all(&self) {
        for (h, _) in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }

    /// Every open connection silently swallows data from now on.
    fn freeze(&self) {
        for (_, f) in self.conns.lock().unwrap().iter() {
            f.store(true, Ordering::SeqCst);
        }
    }

    fn pause(&self, on: bool) {
        self.paused.store(on, Ordering::SeqCst);
    }
}

/// A stdio ACP client driving one in-process bridge.
struct Client {
    stdin: Option<DuplexStream>,
    msgs: Arc<Mutex<Vec<Message>>>,
    notify: Arc<Notify>,
    done: Option<tokio::task::JoinHandle<Result<(), actp_client::Error>>>,
    next_id: i64,
}

impl Client {
    fn start(o: actp_client::Options) -> Client {
        let (stdin_w, stdin_r) = tokio::io::duplex(1 << 20);
        let (stdout_w, stdout_r) = tokio::io::duplex(1 << 20);
        let done = tokio::spawn(actp_client::run(o, stdin_r, stdout_w));
        let msgs: Arc<Mutex<Vec<Message>>> = Arc::default();
        let notify = Arc::new(Notify::new());
        let (m2, n2) = (msgs.clone(), notify.clone());
        tokio::spawn(async move {
            let mut rd = jsonrpc::Reader::new(BufReader::new(stdout_r));
            while let Ok(Some(line)) = rd.read().await {
                if let Line::Message(m) = line {
                    m2.lock().unwrap().push(m);
                    n2.notify_waiters();
                }
            }
            n2.notify_waiters();
        });
        Client {
            stdin: Some(stdin_w),
            msgs,
            notify,
            done: Some(done),
            next_id: 0,
        }
    }

    async fn send_raw(&mut self, raw: &str) {
        let w = self.stdin.as_mut().unwrap();
        w.write_all(raw.as_bytes()).await.unwrap();
        w.write_all(b"\n").await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> String {
        self.next_id += 1;
        let id = self.next_id;
        self.send_raw(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        )
        .await;
        id.to_string()
    }

    async fn wait(&self, what: &str, f: impl Fn(&Message) -> bool) -> Message {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let notified = self.notify.notified();
            if let Some(m) = self.msgs.lock().unwrap().iter().find(|m| f(m)) {
                return m.clone();
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                let got: Vec<String> = self
                    .msgs
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|m| m.raw.clone())
                    .collect();
                panic!("timed out waiting for {what}; got:\n{}", got.join("\n"));
            }
        }
    }

    async fn response(&self, id: &str) -> Message {
        self.wait(&format!("response {id}"), |m| {
            m.kind() == Kind::Response && m.id_key() == id
        })
        .await
    }

    async fn call(&mut self, method: &str, params: Value) -> Message {
        let id = self.request(method, params).await;
        self.response(&id).await
    }

    async fn chunk(&self, text: &str) -> Message {
        let escaped = serde_json::to_string(text).unwrap();
        let escaped = escaped[1..escaped.len() - 1].to_string();
        self.wait(&format!("chunk {text}"), |m| {
            m.method == "session/update"
                && m.params
                    .as_deref()
                    .is_some_and(|p| p.contains(&escaped) || p.contains(text))
        })
        .await
    }

    async fn initialize(&mut self) {
        let r = self.call("initialize", json!({"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": true}, "terminal": true, "elicitation": {"form": {}}}})).await;
        assert!(r.error.is_none(), "initialize: {}", r.raw);
    }

    async fn new_session(&mut self, cwd: &str) -> String {
        let r = self
            .call("session/new", json!({"cwd": cwd, "mcpServers": []}))
            .await;
        assert!(r.error.is_none(), "session/new: {}", r.raw);
        serde_json::from_str::<Value>(r.result.as_deref().unwrap()).unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn prompt(&mut self, sid: &str, text: &str) -> String {
        self.request(
            "session/prompt",
            json!({"sessionId": sid, "prompt": [{"type": "text", "text": text}]}),
        )
        .await
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    async fn wait_exit(&mut self) -> Result<(), actp_client::Error> {
        tokio::time::timeout(Duration::from_secs(10), self.done.take().unwrap())
            .await
            .expect("bridge did not exit")
            .unwrap()
    }

    fn chunks(&self) -> Vec<String> {
        self.msgs
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.method == "session/update")
            .map(|m| serde_json::from_str::<Value>(m.params.as_deref().unwrap()).unwrap()["update"]["content"]["text"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

fn stop_reason(m: &Message) -> String {
    serde_json::from_str::<Value>(m.result.as_deref().unwrap_or("null")).unwrap()["stopReason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_turn() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "echo hello there").await;
    c.chunk("hello there").await;
    assert_eq!(stop_reason(&c.response(&id).await), "end_turn");
    c.close_stdin();
    c.wait_exit().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cwd_resolution_and_bridge_override() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("/client/repo").await;
    c.prompt(&sid, "cwd").await;
    c.chunk(&e.site).await;
    let r = c
        .call(
            "session/new",
            json!({"cwd": "/somewhere/else", "mcpServers": []}),
        )
        .await;
    let err = r.error.unwrap();
    assert_eq!(
        (err.code, err.message.as_str()),
        (
            jsonrpc::CODE_INVALID_PARAMS,
            "cwd not allowed: /somewhere/else"
        )
    );

    let mut c = e.bridge_with(|o| o.cwd = "actp://site".into());
    c.initialize().await;
    let sid = c.new_session("/anything/on/the/client").await;
    c.prompt(&sid, "cwd").await;
    c.chunk(&e.site).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_servers_are_filtered() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let r = c
        .call("session/new", json!({"cwd": "actp://site", "mcpServers": [{"name": "local", "command": "npx", "args": [], "env": []}, {"name": "web", "type": "http", "url": "https://mcp.example.com", "headers": []}]}))
        .await;
    let sid = serde_json::from_str::<Value>(r.result.as_deref().unwrap()).unwrap()["sessionId"]
        .as_str()
        .unwrap()
        .to_string();
    c.prompt(&sid, "mcp").await;
    let m = c.chunk("mcp.example.com").await;
    assert!(
        !m.raw.contains("npx"),
        "stdio MCP server reached the agent: {}",
        m.raw
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn permission_policy_auto_deny() {
    let e = env(|s| s.agents[0].permissions = "auto_deny".into()).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "permission").await;
    c.chunk(r#"\"optionId\":\"deny\""#).await;
    assert!(e.audit_has("permission_answered"));
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_drop_is_detected_and_resumed() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "slow 20").await;
    c.chunk("chunk 2").await;
    e.proxy.freeze(); // no FIN, no RST: only heartbeats can tell
    assert_eq!(stop_reason(&c.response(&id).await), "end_turn");
    let want: Vec<String> = (1..=20).map(|i| format!("chunk {i}")).collect();
    assert_eq!(c.chunks(), want);
    assert!(e.audit_has("link_resumed"), "silent drop was not detected");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_quit_finishes_the_turn() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "slow 8").await;
    c.chunk("chunk 1").await;
    c.close_stdin();
    c.wait_exit().await.unwrap();
    let srv = e.srv.clone();
    wait_until("link to be unattended", move || {
        let l = srv.links();
        l.is_empty() || l[0].state == actp_server::STATE_UNATTENDED
    })
    .await;
    e.wait_no_links().await;
    let mut c2 = e.bridge();
    c2.initialize().await;
    let r = c2
        .call(
            "session/load",
            json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(r.error.is_none(), "load: {}", r.raw);
    c2.chunk("chunk 8").await; // the turn finished while nobody was connected
}

#[tokio::test(flavor = "multi_thread")]
async fn client_quit_with_cancel_policy() {
    let e = env(|s| s.agents[0].on_client_exit = "cancel".into()).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "slow 100").await;
    c.chunk("chunk 1").await;
    c.close_stdin();
    let _ = c.wait_exit().await;
    let start = std::time::Instant::now();
    e.wait_no_links().await;
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "cancel took {:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unattended_turn_is_capped() {
    let e = env(|_| {}).await; // max_unattended: 1s
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "slow 200").await;
    c.chunk("chunk 1").await;
    c.close_stdin();
    let _ = c.wait_exit().await;
    let start = std::time::Instant::now();
    e.wait_no_links().await;
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "unattended turn ran {:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unattended_permission_is_cancelled_at_once() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "permission").await;
    c.wait("permission request", |m| {
        m.method == "session/request_permission"
    })
    .await;
    c.close_stdin();
    let _ = c.wait_exit().await;
    e.wait_no_links().await;
    let mut c2 = e.bridge();
    c2.initialize().await;
    c2.call(
        "session/load",
        json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
    )
    .await;
    c2.chunk("cancelled").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn link_limit() {
    let e = env(|s| s.agents[0].max_links = 1).await;
    let mut c = e.bridge();
    c.initialize().await;
    let mut c2 = e.bridge();
    match c2.wait_exit().await {
        Err(actp_client::Error::Status(s)) => {
            assert_eq!((s.status, s.code.as_str()), (429, "too_many_links"))
        }
        other => panic!("second bridge: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_required_is_reported() {
    let e = env(|s| {
        s.agents[0]
            .env
            .insert("ACTP_TESTAGENT_SCENARIO".into(), "auth-required".into());
    })
    .await;
    let mut c = e.bridge();
    let r = c
        .call(
            "initialize",
            json!({"protocolVersion": 1, "clientCapabilities": {}}),
        )
        .await;
    assert!(
        !r.raw.contains("terminal-auth"),
        "terminal-auth hint reached the client: {}",
        r.raw
    );
    assert!(
        c.call(
            "session/new",
            json!({"cwd": "actp://site", "mcpServers": []})
        )
        .await
        .error
        .is_some()
    );
    let tok = e.srv.authenticate(TOKEN).await.unwrap();
    assert!(
        e.srv
            .agents_body(&tok)
            .contains("\"status\":\"auth_required\"")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quick_restart_loads_the_session() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "echo before restart").await;
    c.response(&id).await;
    c.close_stdin();
    let _ = c.wait_exit().await;
    let mut c2 = e.bridge(); // no pause: the old link may still be closing
    c2.initialize().await;
    let r = c2
        .call(
            "session/load",
            json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(r.error.is_none(), "load right after restart: {}", r.raw);
    c2.chunk("before restart").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe() {
    let e = env(|_| {}).await;
    let mut agent = e.srv.config().agents[0].clone();
    assert_eq!(e.srv.probe(&agent).await.0, "ready");
    agent.command = "/nonexistent/agent".into();
    assert_eq!(e.srv.probe(&agent).await.0, "unavailable");
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_revokes_tokens() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let mut next = (*e.srv.config()).clone();
    next.tokens.clear();
    e.srv.reload(next);
    assert!(e.srv.authenticate(TOKEN).await.is_err());
    // The open link keeps working until it drops; then it cannot come back.
    let id = c.prompt(&sid, "echo still here").await;
    c.response(&id).await;
    e.proxy.drop_all();
    assert!(matches!(
        c.wait_exit().await,
        Err(actp_client::Error::Lost(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn bye_is_sent_when_the_client_leaves_during_a_reconnect() {
    let e = env(|s| s.prompt_timeout = Duration::from_secs(3600)).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    c.prompt(&sid, "permission").await;
    c.wait("permission request", |m| {
        m.method == "session/request_permission"
    })
    .await;
    e.proxy.pause(true);
    e.proxy.drop_all();
    let srv = e.srv.clone();
    wait_until("link detached", move || {
        let l = srv.links();
        l.len() == 1 && l[0].state == actp_server::STATE_DETACHED
    })
    .await;
    c.close_stdin();
    tokio::time::sleep(Duration::from_millis(300)).await;
    e.proxy.pause(false);
    c.wait_exit().await.unwrap();
    // The bye got through: the waiting prompt is cancelled and the link ends,
    // long before the one-hour prompt_timeout.
    e.wait_no_links().await;
    assert!(e.audit_has("link_unattended"));
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_exit_while_away_still_delivers_its_output() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "late-burst-crash 100").await;
    c.chunk("starting").await;
    e.proxy.freeze(); // the client goes quiet; the agent bursts and exits meanwhile
    let r = c.response(&id).await;
    assert!(
        r.error
            .as_ref()
            .is_some_and(|e| e.message.contains("exited with code 4")),
        "{}",
        r.raw
    );
    c.chunk("burst 100").await;
    assert!(
        e.audit_has("link_resumed"),
        "the bridge never came back for the output"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_explains_a_url_with_no_server() {
    let e = env(|_| {}).await;
    // Something that answers 404 without JSON.
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = ln.accept().await {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 19\r\nContent-Type: text/plain\r\n\r\n404 page not found\n").await;
        }
    });
    let mut c = e.bridge_with(|o| o.base_url = format!("http://127.0.0.1:{port}"));
    let err = c.wait_exit().await.unwrap_err().to_string();
    assert!(err.contains("no actp server answers"), "{err}");
    let mut c2 = e.bridge_with(|o| o.agent = "nope".into());
    let err = c2.wait_exit().await.unwrap_err().to_string();
    assert!(
        !err.contains("no actp server answers") && err.contains("no agent named nope"),
        "{err}"
    );
}

// ---- raw links: drop without a bye, never come back

struct RawLink {
    ep: Endpoint,
    got: Arc<Mutex<Vec<Message>>>,
    id: String,
    served: Option<tokio::task::JoinHandle<actp_proto::ServeEnd>>,
    port: u16,
    next: i64,
}

impl RawLink {
    async fn open(port: u16) -> RawLink {
        let got: Arc<Mutex<Vec<Message>>> = Arc::default();
        let g2 = got.clone();
        let ep = Endpoint::new(
            fast_wire(),
            deliver_fn(move |raw| {
                let g = g2.clone();
                async move {
                    if let Ok(m) = jsonrpc::parse(&raw) {
                        g.lock().unwrap().push(m);
                    }
                    Ok(())
                }
            }),
        );
        let mut r = RawLink {
            ep,
            got,
            id: String::new(),
            served: None,
            port,
            next: 0,
        };
        r.connect(None).await.unwrap();
        r
    }

    async fn connect(&mut self, link_id: Option<&str>) -> Result<(), u16> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = format!("ws://127.0.0.1:{}/actp/v1/agents/test/link", self.port)
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("Authorization", format!("Bearer {TOKEN}").parse().unwrap());
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", "actp.v1".parse().unwrap());
        if let Some(id) = link_id {
            req.headers_mut()
                .insert("Actp-Link-Id", id.parse().unwrap());
            req.headers_mut().insert(
                "Actp-Last-Seq",
                self.ep.last_received().to_string().parse().unwrap(),
            );
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, resp)) => {
                self.id = resp
                    .headers()
                    .get("Actp-Link-Id")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let last: i64 = resp
                    .headers()
                    .get("Actp-Last-Seq")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                let ep = self.ep.clone();
                self.served = Some(tokio::spawn(async move {
                    ep.serve(FrameConn::from_websocket(ws), last).await
                }));
                Ok(())
            }
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
            Err(e) => panic!("{e}"),
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Message {
        self.next += 1;
        let id = self.next.to_string();
        self.ep.send(
            json!({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params})
                .to_string(),
        );
        let got = self.got.clone();
        let id2 = id.clone();
        wait_until(&format!("{method} response"), move || {
            got.lock()
                .unwrap()
                .iter()
                .any(|m| m.kind() == Kind::Response && m.id_key() == id2)
        })
        .await;
        self.got
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.kind() == Kind::Response && m.id_key() == id)
            .unwrap()
            .clone()
    }

    async fn wait_for(&self, what: &str, f: impl Fn(&Message) -> bool + Send + 'static) {
        let got = self.got.clone();
        wait_until(what, move || got.lock().unwrap().iter().any(&f)).await;
    }

    async fn drop_link(&mut self) {
        self.ep
            .detach(actp_proto::frame::CLOSE_GOING_AWAY, "test drop");
        let _ = self.served.take().unwrap().await;
    }

    async fn session(&mut self) -> String {
        self.call(
            "initialize",
            json!({"protocolVersion": 1, "clientCapabilities": {}}),
        )
        .await;
        let r = self
            .call(
                "session/new",
                json!({"cwd": "actp://site", "mcpServers": []}),
            )
            .await;
        serde_json::from_str::<Value>(r.result.as_deref().unwrap()).unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn prompt(&self, sid: &str, text: &str) {
        self.ep.send(json!({"jsonrpc": "2.0", "id": "p", "method": "session/prompt", "params": {"sessionId": sid, "prompt": [{"type": "text", "text": text}]}}).to_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn detached_idle_link_closes_and_cannot_resume() {
    let e = env(|_| {}).await; // idle_close: 1s
    let mut r = RawLink::open(e.port).await;
    r.session().await;
    r.drop_link().await;
    let srv = e.srv.clone();
    wait_until("link detached", move || {
        let l = srv.links();
        l.len() == 1 && l[0].state == "detached"
    })
    .await;
    let start = std::time::Instant::now();
    e.wait_no_links().await;
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "idle link lived {:?}",
        start.elapsed()
    );
    // A late client either finds the link gone (410), or gets its missed output and then the reason.
    let id = r.id.clone();
    match r.connect(Some(&id)).await {
        Err(status) => assert_eq!(status, 410),
        Ok(()) => {
            let end = r.served.take().unwrap().await.unwrap();
            assert!(
                matches!(end, actp_proto::ServeEnd::Remote(ref re) if re.code == "link_ended"),
                "{end:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn detached_link_keeps_a_waiting_prompt_until_prompt_timeout() {
    let e = env(|_| {}).await; // idle_close 1s, prompt_timeout 2s
    let mut r = RawLink::open(e.port).await;
    let sid = r.session().await;
    r.prompt(&sid, "permission");
    r.wait_for("permission request", |m| {
        m.method == "session/request_permission"
    })
    .await;
    r.drop_link().await;
    tokio::time::sleep(Duration::from_millis(1500)).await; // past idle_close: a waiting prompt keeps the link
    assert_eq!(
        e.srv.links().len(),
        1,
        "link closed while a prompt was waiting"
    );
    e.wait_no_links().await; // ends at prompt_timeout
}

#[tokio::test(flavor = "multi_thread")]
async fn loading_a_session_held_by_a_dropped_link_takes_it_over() {
    let e = env(|_| {}).await;
    let mut old = RawLink::open(e.port).await;
    let sid = old.session().await;
    old.prompt(&sid, "slow 10");
    old.wait_for("chunk 1", |m| {
        m.method == "session/update" && m.params.as_deref().is_some_and(|p| p.contains("chunk 1"))
    })
    .await;
    old.drop_link().await; // killed hard: no bye

    let mut c = e.bridge();
    c.initialize().await;
    let r = c
        .call(
            "session/load",
            json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(
        r.error
            .as_ref()
            .is_some_and(|e| e.message.contains("session still running")),
        "first load: {}",
        r.raw
    );
    let srv = e.srv.clone();
    wait_until("old link to finish and close", move || {
        srv.links().len() == 1
    })
    .await;
    let r = c
        .call(
            "session/load",
            json!({"sessionId": sid, "cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(r.error.is_none(), "second load: {}", r.raw);
    c.chunk("chunk 10").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_close_counts_from_when_the_turn_ended() {
    let e = env(|_| {}).await; // idle_close: 1s
    let mut r = RawLink::open(e.port).await;
    let sid = r.session().await;
    r.prompt(&sid, "slow 20");
    r.wait_for("chunk 1", |m| {
        m.method == "session/update" && m.params.as_deref().is_some_and(|p| p.contains("chunk 1"))
    })
    .await;
    r.drop_link().await;
    // The turn runs about 2 s while detached, longer than idle_close.
    let srv = e.srv.clone();
    wait_until("turn to finish", move || {
        let l = srv.links();
        l.len() == 1 && !l[0].running
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let id = r.id.clone();
    r.connect(Some(&id))
        .await
        .expect("resume after the turn ended");
    r.wait_for("chunk 20", |m| {
        m.method == "session/update" && m.params.as_deref().is_some_and(|p| p.contains("chunk 20"))
    })
    .await;
    r.wait_for("prompt response", |m| {
        m.kind() == Kind::Response && m.id_key() == "\"p\""
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn server_close_ends_links_with_server_shutdown() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session("actp://site").await;
    let id = c.prompt(&sid, "echo x").await;
    c.response(&id).await;
    e.srv.close(Duration::from_secs(1)).await;
    match c.wait_exit().await {
        Err(actp_client::Error::Lost(r)) => assert_eq!(r, "server is stopping"),
        other => panic!("{other:?}"),
    }
    assert!(
        !e.srv.state_path().exists(),
        "a clean stop leaves no state file"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn link_limit_holds_under_parallel_upgrades() {
    let e = env(|s| s.agents[0].max_links = 1).await;
    let port = e.port;
    let attempts = (0..8).map(|_| async move {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = format!("ws://127.0.0.1:{port}/actp/v1/agents/test/link")
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("Authorization", format!("Bearer {TOKEN}").parse().unwrap());
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", "actp.v1".parse().unwrap());
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _)) => Ok(ws),
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
            Err(other) => panic!("dial: {other}"),
        }
    });
    let results = futures_util::future::join_all(attempts).await;
    let opened = results.iter().filter(|r| r.is_ok()).count();
    let refused = results.iter().filter(|r| matches!(r, Err(429))).count();
    assert_eq!((opened, refused), (1, 7), "max_links 1");
}

/// A workspace sub folder with agent project settings, as Claude Code reads
/// them from `.claude/settings.json`.
fn write_settings(e: &Env, dir: &str, body: &str) -> String {
    let d = std::path::Path::new(&e.site).join(dir).join(".claude");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("settings.json"), body).unwrap();
    format!("actp://site/{dir}")
}

#[tokio::test(flavor = "multi_thread")]
async fn starting_mode_reset_times_out() {
    let e = env(|_| {}).await; // mode_reset_timeout: 1s
    let cwd = write_settings(
        &e,
        "silent",
        r#"{"permissions":{"defaultMode":"bypass"},"actpTest":{"ignoreSetMode":true}}"#,
    );
    let mut c = e.bridge();
    c.initialize().await;
    let start = std::time::Instant::now();
    let r = c
        .call("session/new", json!({"cwd": cwd, "mcpServers": []}))
        .await;
    assert!(
        r.error.as_ref().is_some_and(|e| e
            .message
            .starts_with("session refused: it starts in mode bypassPermissions")),
        "{}",
        r.raw
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "refusal took {:?}",
        start.elapsed()
    );
    assert!(e.audit_has("mode_reset_failed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_wait_for_the_starting_mode_check() {
    let e = env(|_| {}).await;
    let cwd = write_settings(
        &e,
        "slow",
        r#"{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":300}}"#,
    );
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session(&cwd).await;
    // Load the session again and prompt it at once: the prompt must wait until
    // the starting mode has been switched.
    c.request(
        "session/load",
        json!({"sessionId": sid, "cwd": cwd, "mcpServers": []}),
    )
    .await;
    let id = c.prompt(&sid, "mode").await;
    c.response(&id).await;
    c.chunk("mode: default").await;
    assert!(
        !c.chunks().iter().any(|t| t == "mode: bypassPermissions"),
        "a request reached the agent in the refused mode"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn actp_ids_are_reserved() {
    let e = env(|_| {}).await;
    let mut c = e.bridge();
    c.initialize().await;
    c.send_raw(r#"{"jsonrpc":"2.0","id":"actp-7","method":"session/list","params":{}}"#)
        .await;
    let r = c.response("\"actp-7\"").await;
    let err = r.error.unwrap();
    assert_eq!(
        (err.code, err.message.as_str()),
        (
            -32600,
            "invalid request: ids starting with \"actp-\" are reserved for actp"
        )
    );
}

/// A large queue released while the first queued request makes the agent
/// write a lot must not deadlock: the queue drains off the task that reads
/// the agent, which keeps reading.
#[tokio::test(flavor = "multi_thread")]
async fn large_held_backlog_does_not_deadlock() {
    let e = env(|_| {}).await;
    let cwd = write_settings(
        &e,
        "backlog",
        r#"{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":300}}"#,
    );
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session(&cwd).await;
    let big = "x".repeat(300 << 10);
    let id = c.prompt(&sid, &format!("echo {big}")).await; // the session history now holds 300 KB
    c.response(&id).await;
    let load = json!({"sessionId": sid, "cwd": cwd, "mcpServers": []});
    let first = c.request("session/load", load.clone()).await;
    let second = c.request("session/load", load).await; // replays 300 KB while the queue drains
    let pad = "p".repeat(2 << 10);
    let mut ids = Vec::new();
    for _ in 0..150 {
        ids.push(
            c.request("session/set_title", json!({"sessionId": sid, "title": pad}))
                .await,
        );
    }
    c.response(&first).await;
    c.response(&second).await;
    for id in ids {
        c.response(&id).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn held_queue_is_bounded() {
    let e = env(|_| {}).await; // max_held_messages: 200
    let cwd = write_settings(
        &e,
        "bounded",
        r#"{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":500}}"#,
    );
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session(&cwd).await;
    c.request(
        "session/load",
        json!({"sessionId": sid, "cwd": cwd, "mcpServers": []}),
    )
    .await;
    let mut ids = Vec::new();
    for _ in 0..205 {
        ids.push(
            c.request("session/set_title", json!({"sessionId": sid, "title": "t"}))
                .await,
        );
    }
    let mut busy = 0;
    for id in ids {
        if c.response(&id)
            .await
            .error
            .is_some_and(|e| e.message.starts_with("session busy:"))
        {
            busy += 1;
        }
    }
    assert_eq!(busy, 5);
    assert!(e.audit_has("held_overflow"));
}

#[tokio::test(flavor = "multi_thread")]
async fn held_load_times_out() {
    let e = env(|_| {}).await; // held_load_timeout: 2s
    let cwd = write_settings(&e, "slowload", r#"{"actpTest":{"loadDelayMs":4000}}"#);
    let mut c = e.bridge();
    c.initialize().await;
    let sid = c.new_session(&cwd).await;
    let load = c
        .request(
            "session/load",
            json!({"sessionId": sid, "cwd": cwd, "mcpServers": []}),
        )
        .await;
    let prompt = c.prompt(&sid, "echo waiting").await;
    for id in [&load, &prompt] {
        let r = c.response(id).await;
        assert_eq!(
            r.error.map(|e| e.message).as_deref(),
            Some("session refused: the agent did not answer in time"),
            "{}",
            r.raw
        );
    }
    tokio::time::sleep(Duration::from_secs(3)).await; // the agent's late answer to the load is dropped
    let n = c
        .msgs
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.kind() == Kind::Response && m.id_key() == load)
        .count();
    assert_eq!(n, 1, "answers to the load");
    assert!(e.audit_has("load_timed_out"));
}

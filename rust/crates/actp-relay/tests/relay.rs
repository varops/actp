//! The relay end to end, in one process: a relay, two machines running
//! `actp_server` in relay mode with device certificates, and callers going
//! through the relay with the actp bridge library or plain HTTPS.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use actp_relay::{Relay, Timing};
use actp_server::relay::{RelayAcceptor, RelayOptions, Status};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "actp_relaytesttoken";
const ADMIN: &str = "actpr_admintoken";

// ---- the Go test agent ----

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn test_agent() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("ACTP_TESTAGENT_BIN").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
        let exe = if cfg!(windows) { ".exe" } else { "" };
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("relay-go-bin");
        std::fs::create_dir_all(&out).unwrap();
        let target = out.join(format!("actp-testagent{exe}"));
        let status = std::process::Command::new("go")
            .args(["build", "-o"])
            .arg(&target)
            .arg("./cmd/actp-testagent")
            .current_dir(repo_root())
            .env("CGO_ENABLED", "0")
            .status()
            .expect("building the Go test agent (set ACTP_TESTAGENT_BIN to use a prebuilt one)");
        assert!(status.success());
        target
    })
}

fn yaml_path(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

fn hash(t: &str) -> String {
    actp_relay::config::hash_token(t)
}

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "relay-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

// ---- certificates ----

struct Pki {
    dir: PathBuf,
    device_ca: Issuer<'static, KeyPair>,
}

fn ca(cn: &str) -> (CertificateParams, KeyPair, String) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = p.self_signed(&key).unwrap();
    (p, key, cert.pem())
}

impl Pki {
    fn new(dir: &Path) -> Pki {
        let (rp, rk, rpem) = ca("relay test CA");
        std::fs::write(dir.join("relay-ca.pem"), rpem).unwrap();
        let relay_ca = Issuer::new(rp, rk);
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "relay");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = p.signed_by(&key, &relay_ca).unwrap();
        std::fs::write(dir.join("relay.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("relay.key"), key.serialize_pem()).unwrap();

        let (dp, dk, dpem) = ca("device test CA");
        std::fs::write(dir.join("device-ca.pem"), dpem).unwrap();
        Pki {
            dir: dir.to_path_buf(),
            device_ca: Issuer::new(dp, dk),
        }
    }

    /// A device certificate for `cn`, signed by `issuer` (the org's device CA by default).
    fn device(&self, cn: &str, issuer: Option<&Issuer<'static, KeyPair>>) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p
            .signed_by(&key, issuer.unwrap_or(&self.device_ca))
            .unwrap();
        let (c, k) = (
            self.dir.join(format!("{cn}.pem")),
            self.dir.join(format!("{cn}.key")),
        );
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        (c, k)
    }

    fn caller_tls(&self) -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(self.dir.join("relay-ca.pem")).unwrap() {
            roots.add(c.unwrap()).unwrap();
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }
}

// ---- the relay ----

fn fast_timing() -> Timing {
    Timing {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(800),
        stream_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(10),
    }
}

struct RelayEnv {
    relay: Relay,
    port: u16,
    dir: PathBuf,
    stop: CancellationToken,
}

impl Drop for RelayEnv {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn start_relay(pki: &Pki, dir: &Path) -> RelayEnv {
    let yaml = format!(
        "listen: 127.0.0.1:0\ntls_cert: {}\ntls_key: {}\ndevice_ca: {}\nstate_dir: {}\nlog_dir: {}\nblocked_machines: [lost-laptop]\nadmin_tokens:\n  - name: dave\n    hash: {}\n",
        yaml_path(&pki.dir.join("relay.pem")),
        yaml_path(&pki.dir.join("relay.key")),
        yaml_path(&pki.dir.join("device-ca.pem")),
        yaml_path(&dir.join("state")),
        yaml_path(&dir.join("logs")),
        hash(ADMIN),
    );
    let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    let relay = Relay::with_timing(cfg, fast_timing()).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let stop = CancellationToken::new();
    {
        let (relay, stop) = (relay.clone(), stop.clone());
        tokio::spawn(async move { relay.serve(ln, tls, stop).await });
    }
    RelayEnv {
        relay,
        port,
        dir: dir.to_path_buf(),
        stop,
    }
}

impl RelayEnv {
    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("logs").join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn audit_has(&self, event: &str, f: impl Fn(&Value) -> bool) -> bool {
        self.audit().iter().any(|e| e["event"] == event && f(e))
    }
}

// ---- machines ----

struct Laptop {
    srv: actp_server::Server,
    status: tokio::sync::watch::Receiver<Status>,
    stop: CancellationToken,
}

impl Drop for Laptop {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn start_laptop(pki: &Pki, name: &str, relay_port: u16, cert: (PathBuf, PathBuf)) -> Laptop {
    let root = scratch(name);
    std::fs::create_dir_all(root.join("site")).unwrap();
    let yaml = format!(
        "server:\n  name: {name}\n  idle_close: 1s\n  log_dir: {}\n  state_dir: {}\n  tokens_file: {}\n  relay:\n    url: wss://localhost:{relay_port}\n    cert: {}\n    key: {}\n    ca: {}\n  workspaces:\n    - name: site\n      path: {}\n  agents:\n    - id: test\n      command: {}\n      env:\n        ACTP_TESTAGENT_STORE: {}\n  tokens:\n    - name: it\n      hash: \"{}\"\n      agents: [\"*\"]\n      workspaces: [\"*\"]\n      default_workspace: site\n",
        yaml_path(&root.join("logs")),
        yaml_path(&root.join("state")),
        yaml_path(&root.join("tokens.yaml")),
        yaml_path(&cert.0),
        yaml_path(&cert.1),
        yaml_path(&pki.dir.join("relay-ca.pem")),
        yaml_path(&root.join("site")),
        yaml_path(test_agent()),
        yaml_path(&root.join("store")),
        hash(TOKEN),
    );
    let cfg = actp_server::config::Config::parse(&yaml).unwrap();
    cfg.validate().unwrap();
    let sc = cfg.server.clone().unwrap();
    let relay_cfg = sc.relay.clone().unwrap();
    let srv = actp_server::Server::new(
        sc,
        actp_server::Options {
            version: "test".into(),
            base_env: Some(actp_server::agentproc::os_environ()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut opts = RelayOptions::new(
        relay_cfg.url.clone(),
        actp_server::relay::client_tls(&relay_cfg).unwrap(),
    );
    opts.ping_every = Duration::from_millis(100);
    opts.dead_after = Duration::from_millis(800);
    opts.max_backoff = Duration::from_millis(200);
    opts.dial_timeout = Duration::from_secs(3);
    let stop = CancellationToken::new();
    let acceptor = RelayAcceptor::start(srv.clone(), opts, stop.clone());
    let status = acceptor.status();
    tokio::spawn(actp_server::http::serve(
        srv.clone(),
        acceptor,
        stop.clone(),
    ));
    Laptop { srv, status, stop }
}

impl Laptop {
    async fn wait_status(&mut self, want: impl Fn(&Status) -> bool) -> Status {
        tokio::time::timeout(Duration::from_secs(10), self.status.wait_for(|s| want(s)))
            .await
            .expect("laptop status in time")
            .expect("status channel open")
            .clone()
    }

    async fn wait_connected(&mut self) {
        self.wait_status(|s| matches!(s, Status::Connected { .. }))
            .await;
    }
}

// ---- callers ----

/// One HTTPS request to the relay; returns the status and the JSON body.
async fn request(
    pki: &Pki,
    port: u16,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (u16, Value) {
    request_with(pki.caller_tls(), port, method, path, bearer, body).await
}

async fn request_with(
    tls: Arc<rustls::ClientConfig>,
    port: u16,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let mut req = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    if !bearer.is_empty() {
        req = req.header("authorization", format!("Bearer {bearer}"));
    }
    use http_body_util::BodyExt;
    let req = req
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An ACP client on the actp bridge library, through the relay to `machine`.
struct Caller {
    stdin: tokio::io::DuplexStream,
    lines: Arc<Mutex<Vec<Value>>>,
    done: tokio::task::JoinHandle<Result<(), actp_client::Error>>,
}

impl Caller {
    fn start(pki: &Pki, port: u16, machine: &str) -> Caller {
        let o = actp_client::Options {
            agent: "test".into(),
            base_url: format!("https://localhost:{port}/m/{machine}"),
            token: TOKEN.into(),
            client_name: "relay-test".into(),
            max_backoff: Duration::from_millis(100),
            give_up_after: Duration::from_secs(2),
            tls: Some(pki.caller_tls()),
            ..Default::default()
        };
        let (stdin_w, stdin_r) = tokio::io::duplex(1 << 20);
        let (stdout_w, stdout_r) = tokio::io::duplex(1 << 20);
        let done = tokio::spawn(actp_client::run(o, stdin_r, stdout_w));
        let lines: Arc<Mutex<Vec<Value>>> = Arc::default();
        let l2 = lines.clone();
        tokio::spawn(async move {
            let mut rd = BufReader::new(stdout_r).lines();
            while let Ok(Some(line)) = rd.next_line().await {
                if let Ok(v) = serde_json::from_str(&line) {
                    l2.lock().unwrap().push(v);
                }
            }
        });
        Caller {
            stdin: stdin_w,
            lines,
            done,
        }
    }

    async fn call(&mut self, id: i64, method: &str, params: Value) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(v) = self
                .lines
                .lock()
                .unwrap()
                .iter()
                .find(|v| v["id"] == json!(id))
            {
                return v.clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no answer to {method}: {:?}",
                self.lines.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---- a TCP proxy that can cut every connection ----

struct Proxy {
    port: u16,
    conns: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Proxy {
    async fn start(target: u16) -> Proxy {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let conns: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
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
        Proxy { port, conns }
    }

    fn drop_all(&self) {
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

// ---- tests ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_callers_to_the_right_machine() {
    let dir = scratch("route");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;

    // Each machine answers as itself.
    for m in ["laptop-a", "laptop-b"] {
        let (status, body) = request(
            &pki,
            env.port,
            "GET",
            &format!("/m/{m}/api/v1/info"),
            TOKEN,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["name"], m);
    }
    // The machine checks the caller's credentials, not the relay.
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        "actp_wrong",
        None,
    )
    .await;
    assert_eq!(status, 401);

    // A session through the relay reaches the agent on laptop-a only.
    let mut caller = Caller::start(&pki, env.port, "laptop-a");
    let init = caller
        .call(1, "initialize", json!({"protocolVersion": 1}))
        .await;
    assert!(init.get("result").is_some(), "{init}");
    eventually("the link on laptop-a", || a.srv.links().len() == 1).await;
    assert!(b.srv.links().is_empty());

    // Who is online, and the audit of the session.
    let (status, list) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(status, 200);
    let machines = list["machines"].as_array().unwrap();
    let online: Vec<&str> = machines
        .iter()
        .filter(|m| m["online"] == true)
        .map(|m| m["machine"].as_str().unwrap())
        .collect();
    assert_eq!(online, ["laptop-a", "laptop-b"]);
    let a_row = machines
        .iter()
        .find(|m| m["machine"] == "laptop-a")
        .unwrap();
    assert_eq!(a_row["sessions"], 1);
    assert!(a_row["last_seen"].is_string() && a_row["connected_since"].is_string());
    assert!(env.audit_has("session_open", |e| e["machine"] == "laptop-a"
        && e["agent"] == "test"
        && e["client_name"] == "relay-test"));
    assert!(env.audit_has("machine_online", |e| e["machine"] == "laptop-b"));
    // Never anything the session carried.
    let text = std::fs::read_to_string(env.dir.join("logs").join("audit.jsonl")).unwrap();
    assert!(!text.contains("protocolVersion") && !text.contains(TOKEN));

    // A machine that is not connected, and malformed addresses.
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-c/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (503, Some("machine_offline"))
    );
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/../relay/v1/machines",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = request(&pki, env.port, "GET", "/relay/v1/machines", "", None).await;
    assert_eq!(status, 401);

    drop(caller);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn machines_need_a_device_certificate_from_the_org() {
    let dir = scratch("certs");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;

    // No client certificate: the machine routes refuse.
    let (status, body) = request(&pki, env.port, "GET", "/relay/v1/connect", "", None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("device_certificate_required"))
    );
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        &format!("/relay/v1/stream/{}", "ab".repeat(32)),
        "",
        None,
    )
    .await;
    assert_eq!(status, 401);

    // A certificate from another CA never connects.
    let (rp, rk, _) = ca("rogue CA");
    let rogue = Issuer::new(rp, rk);
    let mut r = start_laptop(
        &pki,
        "laptop-a",
        env.port,
        pki.device("laptop-a", Some(&rogue)),
    )
    .await;
    let s = r
        .wait_status(|s| matches!(s, Status::Disconnected { .. }))
        .await;
    assert!(matches!(s, Status::Disconnected { .. }));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(env.relay.machines().is_empty());

    // A blocked machine is refused even with a good certificate.
    let mut lost = start_laptop(
        &pki,
        "lost-laptop",
        env.port,
        pki.device("lost-laptop", None),
    )
    .await;
    lost.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    assert!(env.audit_has("machine_refused", |e| e["machine"] == "lost-laptop"));

    // A certificate whose name is not a valid address is refused.
    let mut odd = start_laptop(&pki, "odd name", env.port, pki.device("odd name", None)).await;
    odd.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    drop((r, lost, odd));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_org_wide_stop_drops_sessions_and_refuses_new_ones() {
    let dir = scratch("stop");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;
    let mut ca_ = Caller::start(&pki, env.port, "laptop-a");
    let mut cb = Caller::start(&pki, env.port, "laptop-b");
    assert!(
        ca_.call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    assert!(
        cb.call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    eventually("both links", || {
        a.srv.links().len() == 1 && b.srv.links().len() == 1
    })
    .await;

    // Pressing needs an admin token and a reason.
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        TOKEN,
        Some(json!({"reason": "x"})),
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({"reason": "suspicious activity"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stop"]["stopped"], true);
    assert_eq!(body["stop"]["by"], "dave");

    // Every session ends, on both machines, and the machines know.
    eventually("links ended", || {
        a.srv.links().is_empty() && b.srv.links().is_empty()
    })
    .await;
    eventually("machines stopped", || {
        a.srv.org_stopped() && b.srv.org_stopped()
    })
    .await;
    let r = tokio::time::timeout(Duration::from_secs(10), ca_.done)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err(), "the bridge must lose its session: {r:?}");

    // Nobody new gets through, and the machines are still listed online.
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!((status, body["error"].as_str()), (503, Some("org_stopped")));
    let (_, list) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(list["stop"]["stopped"], true);
    assert!(
        list["machines"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["online"] == true)
    );
    assert!(env.audit_has("org_stop", |e| e["by"] == "dave"
        && e["reason"] == "suspicious activity"
        && e["sessions_dropped"] == 2));
    assert!(env.audit_has("session_closed", |e| e["reason"] == "org_stop"));

    // A machine that reconnects while the stop is on hears it in the hello.
    let mut c = start_laptop(&pki, "laptop-c", env.port, pki.device("laptop-c", None)).await;
    c.wait_connected().await;
    eventually("laptop-c stopped", || c.srv.org_stopped()).await;

    // The stop survives a relay restart.
    let cfg = env.relay.config().clone();
    let again = Relay::with_timing(cfg, fast_timing()).unwrap();
    assert!(again.stop_state().stopped);
    drop(again);

    // Releasing lets callers through again.
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/release",
        ADMIN,
        Some(json!({"reason": "all clear"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    eventually("machines released", || {
        !a.srv.org_stopped() && !c.srv.org_stopped()
    })
    .await;
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(env.audit_has("org_release", |e| e["by"] == "dave"
        && e["reason"] == "all clear"));
    drop(cb);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_reconnects_after_a_drop() {
    let dir = scratch("reconnect");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let proxy = Proxy::start(env.port).await;
    let mut a = start_laptop(&pki, "laptop-a", proxy.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200);

    // The network drops: the machine goes offline at the relay and comes back.
    proxy.drop_all();
    a.wait_status(|s| !matches!(s, Status::Connected { .. }))
        .await;
    a.wait_connected().await;
    eventually("offline then online again", || {
        env.audit_has("machine_offline", |e| e["machine"] == "laptop-a")
            && env
                .audit()
                .iter()
                .filter(|e| e["event"] == "machine_online" && e["machine"] == "laptop-a")
                .count()
                >= 2
    })
    .await;
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let m = env.relay.machines();
    assert_eq!(m.len(), 1);
    assert!(m[0].online);

    // A machine that just vanishes is noticed through the missing pings.
    drop(a);
    proxy.drop_all();
    eventually("laptop-a offline", || {
        env.relay.machines().iter().all(|m| !m.online)
    })
    .await;
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (503, Some("machine_offline"))
    );
}

/// Dials a relay WebSocket route as a machine with `cert`.
async fn dial_as(
    pki: &Pki,
    port: u16,
    cert: &(PathBuf, PathBuf),
    path: &str,
    protocol: &str,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, u16> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let tls = actp_server::relay::client_tls(&actp_server::config::Relay {
        url: String::new(),
        cert: cert.0.to_string_lossy().into_owned(),
        key: cert.1.to_string_lossy().into_owned(),
        ca: pki.dir.join("relay-ca.pem").to_string_lossy().into_owned(),
    })
    .unwrap();
    let mut req = format!("wss://localhost:{port}{path}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", protocol.parse().unwrap());
    match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        true,
        Some(tokio_tungstenite::Connector::Rustls(tls)),
    )
    .await
    {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("dial {path}: {e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_machine_asked_can_take_a_stream() {
    use actp_proto::relay::{Control, PROTOCOL_CONTROL, PROTOCOL_STREAM};
    use futures_util::StreamExt;
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::tungstenite::Message;

    let dir = scratch("steal");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let a = pki.device("laptop-a", None);
    let b = pki.device("laptop-b", None);
    let mut ctl = dial_as(&pki, env.port, &a, "/relay/v1/connect", PROTOCOL_CONTROL)
        .await
        .unwrap();
    let next = |m: Option<Result<Message, _>>| match m {
        Some(Ok(Message::Text(t))) => Control::decode(t.as_str()).unwrap(),
        other => panic!("expected a control message, got {other:?}"),
    };
    assert_eq!(
        next(ctl.next().await),
        Control::Hello {
            machine: "laptop-a".into(),
            stopped: false
        }
    );
    // The control route wants its subprotocol.
    assert_eq!(
        dial_as(&pki, env.port, &b, "/relay/v1/connect", "other")
            .await
            .err(),
        Some(400)
    );

    let port = env.port;
    let tls = pki.caller_tls();
    let caller = tokio::spawn(async move {
        request_with(tls, port, "GET", "/m/laptop-a/api/v1/info", TOKEN, None).await
    });
    let id = loop {
        match next(ctl.next().await) {
            Control::Open { stream } => break stream,
            _ => continue,
        }
    };
    // laptop-b cannot take laptop-a's stream, and trying does not use it up.
    let path = format!("/relay/v1/stream/{id}");
    assert_eq!(
        dial_as(&pki, env.port, &b, &path, PROTOCOL_STREAM)
            .await
            .err(),
        Some(404)
    );
    let ws = dial_as(&pki, env.port, &a, &path, PROTOCOL_STREAM)
        .await
        .unwrap();
    let mut io = actp_proto::wsio::WsIo::new(ws);
    let mut got = Vec::new();
    while !got.ends_with(b"\r\n\r\n") {
        got.push(io.read_u8().await.unwrap());
    }
    let head = String::from_utf8(got).unwrap();
    assert!(head.starts_with("GET /api/v1/info HTTP/1.1\r\n"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    );
    io.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"name\":\"fake\"}")
        .await
        .unwrap();
    io.flush().await.unwrap();
    let (status, body) = caller.await.unwrap();
    assert_eq!((status, body["name"].as_str()), (200, Some("fake")));
    // The same stream id cannot be taken twice.
    assert_eq!(
        dial_as(&pki, env.port, &a, &path, PROTOCOL_STREAM)
            .await
            .err(),
        Some(404)
    );
}

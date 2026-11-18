//! Helpers for the relay tests: certificates, a relay, machines in relay
//! mode, callers, and a proxy that can cut connections.

#![allow(dead_code)]

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

pub const TOKEN: &str = "actp_relaytesttoken";
pub const ADMIN: &str = "actpr_admintoken";

// ---- the Go test agent ----

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

pub fn test_agent() -> &'static Path {
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

pub fn yaml_path(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

pub fn hash(t: &str) -> String {
    actp_relay::config::hash_token(t)
}

pub fn scratch(name: &str) -> PathBuf {
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

pub struct Pki {
    pub dir: PathBuf,
    pub device_ca: Issuer<'static, KeyPair>,
    pub caller_ca: Issuer<'static, KeyPair>,
}

/// The caller certificate tests use unless they say otherwise.
pub const CALLER: &str = "it-bridge";

pub fn ca(cn: &str) -> (CertificateParams, KeyPair, String) {
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
    pub fn new(dir: &Path) -> Pki {
        let (rp, rk, rpem) = ca("relay test CA");
        std::fs::write(dir.join("relay-ca.pem"), rpem).unwrap();
        let relay_ca = Issuer::new(rp, rk);
        let key = KeyPair::generate().unwrap();
        // 127.0.0.1 too, and tests dial it: on Windows, `localhost` is
        // tried as `::1` first, where nothing listens, and every connection
        // then costs about two seconds.
        let mut p =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "relay");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = p.signed_by(&key, &relay_ca).unwrap();
        std::fs::write(dir.join("relay.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("relay.key"), key.serialize_pem()).unwrap();

        let (dp, dk, dpem) = ca("device test CA");
        std::fs::write(dir.join("device-ca.pem"), dpem).unwrap();
        let (cp, ck, cpem) = ca("caller test CA");
        std::fs::write(dir.join("caller-ca.pem"), cpem).unwrap();
        let pki = Pki {
            dir: dir.to_path_buf(),
            device_ca: Issuer::new(dp, dk),
            caller_ca: Issuer::new(cp, ck),
        };
        pki.caller(CALLER, None);
        pki
    }

    /// A caller certificate for `cn`, signed by `issuer` (the caller CA by
    /// default), written as `caller-<cn>.pem` and `.key`.
    pub fn caller(
        &self,
        cn: &str,
        issuer: Option<&Issuer<'static, KeyPair>>,
    ) -> (PathBuf, PathBuf) {
        self.caller_with(cn, issuer, |_| {})
    }

    /// [`Pki::caller`], with `edit` changing the certificate first.
    pub fn caller_with(
        &self,
        cn: &str,
        issuer: Option<&Issuer<'static, KeyPair>>,
        edit: impl FnOnce(&mut CertificateParams),
    ) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        edit(&mut p);
        let cert = p
            .signed_by(&key, issuer.unwrap_or(&self.caller_ca))
            .unwrap();
        let (c, k) = (
            self.dir.join(format!("caller-{cn}.pem")),
            self.dir.join(format!("caller-{cn}.key")),
        );
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        (c, k)
    }

    /// How a caller holding `cert` reaches `machine` through a relay.
    pub fn route_as(&self, cert: &(PathBuf, PathBuf), machine: &str) -> actp_client::RelayRoute {
        actp_client::RelayRoute::from_files(
            machine,
            &cert.0,
            &cert.1,
            Some(&self.dir.join("relay-ca.pem")),
            &self.dir.join("device-ca.pem"),
            &[],
            actp_proto::e2e::MachineName::Cn,
        )
        .unwrap()
    }

    /// [`Pki::route_as`] with the default caller certificate.
    pub fn route(&self, machine: &str) -> actp_client::RelayRoute {
        let cert = (
            self.dir.join(format!("caller-{CALLER}.pem")),
            self.dir.join(format!("caller-{CALLER}.key")),
        );
        self.route_as(&cert, machine)
    }

    /// A device certificate for `cn`, signed by `issuer` (the org's device CA by default).
    pub fn device(
        &self,
        cn: &str,
        issuer: Option<&Issuer<'static, KeyPair>>,
    ) -> (PathBuf, PathBuf) {
        self.device_with(cn, issuer, |_| {})
    }

    /// [`Pki::device`], with `edit` changing the certificate first (its
    /// serial number, its validity).
    pub fn device_with(
        &self,
        cn: &str,
        issuer: Option<&Issuer<'static, KeyPair>>,
        edit: impl FnOnce(&mut CertificateParams),
    ) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        edit(&mut p);
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

    /// A revocation list from the device CA, revoking `serials`, written to
    /// `name` in the PKI folder; `stale` makes its next update already past.
    pub fn crl(&self, name: &str, serials: &[u64], stale: bool) -> PathBuf {
        self.crl_by(&self.device_ca, name, serials, stale)
    }

    /// [`Pki::crl`] from the caller CA.
    pub fn caller_crl(&self, name: &str, serials: &[u64]) -> PathBuf {
        self.crl_by(&self.caller_ca, name, serials, false)
    }

    fn crl_by(
        &self,
        issuer: &Issuer<'static, KeyPair>,
        name: &str,
        serials: &[u64],
        stale: bool,
    ) -> PathBuf {
        use rcgen::{
            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
            SerialNumber,
        };
        let now = time::OffsetDateTime::now_utc();
        let (this, next) = if stale {
            (now - time::Duration::days(2), now - time::Duration::days(1))
        } else {
            (
                now - time::Duration::hours(1),
                now + time::Duration::days(1),
            )
        };
        let params = CertificateRevocationListParams {
            this_update: this,
            next_update: next,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: now - time::Duration::minutes(5),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(issuer).unwrap();
        let path = self.dir.join(name);
        std::fs::write(&path, crl.pem().unwrap()).unwrap();
        path
    }

    pub fn caller_tls(&self) -> Arc<rustls::ClientConfig> {
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

pub fn fast_timing() -> Timing {
    Timing {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(800),
        stream_timeout: Duration::from_secs(8),
        send_timeout: Duration::from_secs(2),
        flush_every: Duration::from_millis(200),
        tunnel_idle: None,
    }
}

pub struct RelayEnv {
    pub relay: Relay,
    pub port: u16,
    pub dir: PathBuf,
    pub stop: CancellationToken,
}

impl Drop for RelayEnv {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub async fn start_relay(pki: &Pki, dir: &Path) -> RelayEnv {
    start_relay_with(pki, dir, "").await
}

/// The test relay config, plus `extra` YAML.
pub fn relay_yaml(pki: &Pki, dir: &Path, extra: &str) -> String {
    format!(
        "listen: 127.0.0.1:0\ntls_cert: {}\ntls_key: {}\ndevice_ca: {}\ncaller_ca: {}\nstate_dir: {}\nlog_dir: {}\nblocked_machines: [lost-laptop]\nadmin_tokens:\n  - name: dave\n    hash: {}\n{extra}",
        yaml_path(&pki.dir.join("relay.pem")),
        yaml_path(&pki.dir.join("relay.key")),
        yaml_path(&pki.dir.join("device-ca.pem")),
        yaml_path(&pki.dir.join("caller-ca.pem")),
        yaml_path(&dir.join("state")),
        yaml_path(&dir.join("logs")),
        hash(ADMIN),
    )
}

pub async fn start_relay_with(pki: &Pki, dir: &Path, extra: &str) -> RelayEnv {
    start_relay_timed(pki, dir, extra, fast_timing()).await
}

/// [`start_relay_with`], with `timing`.
pub async fn start_relay_timed(pki: &Pki, dir: &Path, extra: &str, timing: Timing) -> RelayEnv {
    let yaml = relay_yaml(pki, dir, extra);
    let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    let relay = Relay::with_timing(cfg, timing).unwrap();
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
    pub fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("logs").join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn audit_has(&self, event: &str, f: impl Fn(&Value) -> bool) -> bool {
        self.audit().iter().any(|e| e["event"] == event && f(e))
    }
}

// ---- machines ----

pub struct Laptop {
    pub root: PathBuf,
    pub srv: actp_server::Server,
    pub status: tokio::sync::watch::Receiver<Status>,
    pub stop: CancellationToken,
}

impl Drop for Laptop {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub async fn start_laptop(
    pki: &Pki,
    name: &str,
    relay_port: u16,
    cert: (PathBuf, PathBuf),
) -> Laptop {
    let tokens = format!(
        "  tokens:\n    - name: it\n      hash: \"{}\"\n      agents: [\"*\"]\n      workspaces: [\"*\"]\n      default_workspace: site\n",
        hash(TOKEN)
    );
    start_laptop_with(pki, name, relay_port, cert, &tokens).await
}

/// A machine in relay mode with `auth` (a `tokens:` or `org:` block, indented
/// under `server:`) deciding who gets in.
pub async fn start_laptop_with(
    pki: &Pki,
    name: &str,
    relay_port: u16,
    cert: (PathBuf, PathBuf),
    auth: &str,
) -> Laptop {
    start_laptop_full(pki, name, relay_port, cert, auth, None, |_| {}).await
}

/// [`start_laptop_with`], with a papers verifier for org mode.
pub async fn start_laptop_verified(
    pki: &Pki,
    name: &str,
    relay_port: u16,
    cert: (PathBuf, PathBuf),
    auth: &str,
    verifier: Option<Arc<dyn actp_server::org::PapersVerifier>>,
) -> Laptop {
    start_laptop_full(pki, name, relay_port, cert, auth, verifier, |_| {}).await
}

/// [`start_laptop_with`], with a papers verifier and `adjust` changing the
/// relay options.
pub async fn start_laptop_full(
    pki: &Pki,
    name: &str,
    relay_port: u16,
    cert: (PathBuf, PathBuf),
    auth: &str,
    verifier: Option<Arc<dyn actp_server::org::PapersVerifier>>,
    adjust: impl FnOnce(&mut RelayOptions),
) -> Laptop {
    // ACTP_TEST_LOG=<filter> (for example `warn` or `actp_server=debug`)
    // shows the machines' and the relay's logs.
    if let Ok(filter) = std::env::var("ACTP_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(filter)
            .try_init();
    }
    let root = scratch(name);
    std::fs::create_dir_all(root.join("site")).unwrap();
    let yaml = format!(
        "server:\n  name: {name}\n  idle_close: 5s\n  log_dir: {}\n  state_dir: {}\n  tokens_file: {}\n  relay:\n    url: wss://127.0.0.1:{relay_port}\n    cert: {}\n    key: {}\n    ca: {}\n  workspaces:\n    - name: site\n      path: {}\n  agents:\n    - id: test\n      command: {}\n      env:\n        ACTP_TESTAGENT_STORE: {}\n{auth}",
        yaml_path(&root.join("logs")),
        yaml_path(&root.join("state")),
        yaml_path(&root.join("tokens.yaml")),
        yaml_path(&cert.0),
        yaml_path(&cert.1),
        yaml_path(&pki.dir.join("relay-ca.pem")),
        yaml_path(&root.join("site")),
        yaml_path(test_agent()),
        yaml_path(&root.join("store")),
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
            papers_verifier: verifier,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut opts = RelayOptions::new(
        relay_cfg.url.clone(),
        actp_server::relay::client_tls(&relay_cfg).unwrap(),
        actp_server::relay::stream_tls(&relay_cfg).unwrap(),
    );
    opts.ping_every = Duration::from_millis(100);
    opts.dead_after = Duration::from_millis(800);
    opts.max_backoff = Duration::from_millis(200);
    opts.dial_timeout = Duration::from_secs(6);
    adjust(&mut opts);
    let stop = CancellationToken::new();
    let acceptor = RelayAcceptor::start(srv.clone(), opts, stop.clone());
    let status = acceptor.status();
    tokio::spawn(actp_server::http::serve(
        srv.clone(),
        acceptor,
        stop.clone(),
    ));
    Laptop {
        root,
        srv,
        status,
        stop,
    }
}

impl Laptop {
    pub async fn wait_status(&mut self, want: impl Fn(&Status) -> bool) -> Status {
        tokio::time::timeout(Duration::from_secs(10), self.status.wait_for(|s| want(s)))
            .await
            .expect("laptop status in time")
            .expect("status channel open")
            .clone()
    }

    /// The machine's own audit log.
    pub fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.join("logs").join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub async fn wait_connected(&mut self) {
        self.wait_status(|s| matches!(s, Status::Connected { .. }))
            .await;
    }
}

// ---- callers ----

/// One HTTPS request to the relay; returns the status and the JSON body.
pub async fn request(
    pki: &Pki,
    port: u16,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (u16, Value) {
    // `/m/<machine>/<path>` is shorthand for `<path>` on that machine,
    // through a tunnel with the default caller certificate.
    if let Some(rest) = path.strip_prefix("/m/") {
        let (machine, inner) = rest.split_once('/').unwrap_or((rest, ""));
        let inner = format!("/{inner}");
        return match tunnel_request(
            &pki.route(machine),
            port,
            machine,
            method,
            &inner,
            bearer,
            body,
        )
        .await
        {
            Ok(r) => r,
            Err(Refused::Relay(status, body)) => (status, body),
            Err(Refused::Tls(e)) => panic!("TLS to {machine} failed: {e}"),
        };
    }
    request_with(pki.caller_tls(), port, method, path, bearer, body).await
}

/// Why a tunnel request got no answer from the machine.
#[derive(Debug)]
pub enum Refused {
    /// The relay refused the tunnel: its status and JSON body.
    Relay(u16, Value),
    /// The end-to-end TLS failed: the machine was not the machine asked
    /// for, or the bytes were changed on the way.
    Tls(String),
}

/// The end-to-end TLS stream of a caller's tunnel.
pub type TunnelTls = tokio_rustls::client::TlsStream<
    actp_proto::wsio::WsIo<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
>;

/// A tunnel to `machine` through the relay at `port`, and TLS to the
/// machine inside it.
pub async fn open_tunnel(
    route: &actp_client::RelayRoute,
    port: u16,
    machine: &str,
) -> Result<TunnelTls, Refused> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("wss://127.0.0.1:{port}/relay/v1/tunnel/{machine}")
        .into_client_request()
        .unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        actp_proto::relay::PROTOCOL_TUNNEL.parse().unwrap(),
    );
    let ws = match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        true,
        Some(tokio_tungstenite::Connector::Rustls(
            route.relay_tls.clone(),
        )),
    )
    .await
    {
        Ok((ws, _)) => ws,
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
            let body = r
                .body()
                .as_deref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(Value::Null);
            return Err(Refused::Relay(r.status().as_u16(), body));
        }
        Err(e) => return Err(Refused::Tls(format!("the relay: {e}"))),
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(match &route.reload {
            Some(reload) => reload().map_err(Refused::Tls)?,
            None => route.machine_tls.clone(),
        })
        .connect(
            actp_proto::e2e::server_name(),
            actp_proto::wsio::WsIo::new(ws),
        ),
    )
    .await
    .map_err(|_| Refused::Tls("timed out".into()))?
    .map_err(|e| Refused::Tls(e.to_string()))
}

/// One request to `path` on `machine`, through the relay at `port`, over
/// TLS end to end to the machine.
pub async fn tunnel_request(
    route: &actp_client::RelayRoute,
    port: u16,
    machine: &str,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> Result<(u16, Value), Refused> {
    let tls = open_tunnel(route, port, machine).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| Refused::Tls(e.to_string()))?;
    tokio::spawn(conn);
    let mut req = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "machine.actp.invalid");
    if !bearer.is_empty() {
        req = req.header("authorization", format!("Bearer {bearer}"));
    }
    use http_body_util::BodyExt;
    let req = req
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .map_err(|_| Refused::Tls("no answer".into()))?
        .map_err(|e| Refused::Tls(e.to_string()))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| Refused::Tls(e.to_string()))?
        .to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

pub async fn request_with(
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
pub struct Caller {
    pub stdin: tokio::io::DuplexStream,
    pub lines: Arc<Mutex<Vec<Value>>>,
    pub done: tokio::task::JoinHandle<Result<(), actp_client::Error>>,
}

impl Caller {
    pub fn start(pki: &Pki, port: u16, machine: &str) -> Caller {
        Self::start_with(pki, port, machine, |_| {})
    }

    pub fn start_with(
        pki: &Pki,
        port: u16,
        machine: &str,
        adjust: impl FnOnce(&mut actp_client::Options),
    ) -> Caller {
        let mut o = actp_client::Options {
            agent: "test".into(),
            base_url: format!("https://127.0.0.1:{port}"),
            token: TOKEN.into(),
            client_name: "relay-test".into(),
            max_backoff: Duration::from_millis(100),
            give_up_after: Duration::from_secs(2),
            relay: Some(pki.route(machine)),
            ..Default::default()
        };
        adjust(&mut o);
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

    pub async fn call(&mut self, id: i64, method: &str, params: Value) -> Value {
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

pub async fn eventually(what: &str, f: impl Fn() -> bool) {
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

pub struct Proxy {
    pub port: u16,
    pub conns: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Proxy {
    pub async fn start(target: u16) -> Proxy {
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

    pub fn drop_all(&self) {
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

/// Whether `needle` occurs in `hay`.
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Records every byte read through it.
pub struct Recorder<T> {
    io: T,
    pub seen: Arc<Mutex<Vec<u8>>>,
}

impl<T> Recorder<T> {
    pub fn new(io: T) -> Self {
        Recorder {
            io,
            seen: Arc::default(),
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Recorder<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut self.io).poll_read(cx, buf);
        let new = buf.filled()[before..].to_vec();
        self.seen.lock().unwrap().extend_from_slice(&new);
        r
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Recorder<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

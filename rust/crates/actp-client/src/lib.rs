//! `actp <agent>@<server>` as a library: a local stdio ACP agent that forwards
//! everything to an agent on an actp server, reconnects after drops and
//! catches up without losing or repeating a message. A port of Go's
//! `internal/bridge`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actp_proto::conn::websocket_config;
use actp_proto::frame::{
    CLOSE_NORMAL, ERR_AGENT_EXITED, HEADER_CLIENT_NAME, HEADER_LAST_SEQ, HEADER_LINK_ID, T_BYE,
    VERSIONS,
};
use actp_proto::gojson;
use actp_proto::jsonrpc::{self, Kind, Line, Message};
use actp_proto::{Endpoint, Frame, FrameConn, RemoteError, ServeEnd, api, deliver_fn};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_util::sync::CancellationToken;

/// One `--map FROM=TO` rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    pub from: String,
    pub to: String,
}

/// How to reach the remote agent.
#[derive(Clone)]
pub struct Options {
    pub agent: String,
    /// `http(s)://host[:port][/prefix]` (or `ws(s)://`).
    pub base_url: String,
    pub token: String,
    pub client_name: String,
    /// Replaces every cwd the client sends, for example `actp://website`.
    pub cwd: String,
    /// Rewrite cwd values that start with `from`.
    pub maps: Vec<Map>,
    pub wire: actp_proto::Options,
    /// Stop reconnecting after this long (10 min of awake time).
    pub give_up_after: Duration,
    /// Longest wait between reconnects (30 s).
    pub max_backoff: Duration,
    /// TLS for `https://` servers. `None` uses the OS trust store.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Fetches the credential before every connection, for credentials that
    /// expire, such as signed papers in org mode. When set, `token` is not
    /// used. An error, or no answer within 15 s, counts as a failed
    /// connection attempt. Its error text is shown to the client and logged,
    /// so it must not carry credentials.
    pub token_source: Option<TokenSource>,
    /// Reach the machine through an actp relay, encrypted end to end. With
    /// this set, `base_url` is the relay (`https://relay.example.com`) and
    /// `tls` is not used.
    pub relay: Option<RelayRoute>,
}

/// How to reach a machine through a relay (docs/relay.md).
#[derive(Clone)]
pub struct RelayRoute {
    /// The machine's address at the relay.
    pub machine: String,
    /// TLS to the relay: the roots for the relay's certificate, and the
    /// caller certificate the relay asks for.
    pub relay_tls: Arc<rustls::ClientConfig>,
    /// TLS to the machine, end to end inside the relayed stream:
    /// [`actp_proto::e2e::client_config`] for this machine.
    pub machine_tls: Arc<rustls::ClientConfig>,
    /// Builds `machine_tls` afresh before every connection, so revocation
    /// lists that change on disk are read again ([`RelayRoute::from_files`]
    /// sets it). An error fails that connection attempt.
    pub reload: Option<MachineTls>,
    /// Whom this caller acts for, sent as `X-Actp-On-Behalf-Of`: the relay
    /// records it with the session and the machine with the link. Nobody
    /// checks it; it is for tracing. Must pass
    /// [`actp_proto::relay::valid_on_behalf_of`].
    pub on_behalf_of: Option<String>,
}

/// See [`RelayRoute::reload`].
pub type MachineTls = Arc<dyn Fn() -> Result<Arc<rustls::ClientConfig>, String> + Send + Sync>;

impl RelayRoute {
    /// A route from PEM files: the caller certificate and key the relay
    /// asks for, the roots for the relay's own certificate (`None`: the OS
    /// store), the org's device roots and revocation lists (PEM or DER) for
    /// the machine's certificate, and which name in it is the address. The
    /// device roots and lists are read again before every connection.
    ///
    /// Without revocation lists a revoked machine certificate is accepted:
    /// revoking a machine at the relay does not protect a caller from a
    /// relay that is itself compromised. Pass the lists the relay uses.
    pub fn from_files(
        machine: &str,
        caller_cert: &std::path::Path,
        caller_key: &std::path::Path,
        relay_ca: Option<&std::path::Path>,
        device_ca: &std::path::Path,
        device_crls: &[std::path::PathBuf],
        which: actp_proto::e2e::MachineName,
    ) -> Result<RelayRoute, String> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
        let certs = |p: &std::path::Path| -> Result<Vec<CertificateDer<'static>>, String> {
            let v: Vec<_> = CertificateDer::pem_file_iter(p)
                .and_then(|i| i.collect::<Result<_, _>>())
                .map_err(|e| format!("{}: {e}", p.display()))?;
            if v.is_empty() {
                return Err(format!("{}: no certificate in the file", p.display()));
            }
            Ok(v)
        };
        let key = PrivateKeyDer::from_pem_file(caller_key)
            .map_err(|e| format!("{}: {e}", caller_key.display()))?;
        let mut roots = rustls::RootCertStore::empty();
        match relay_ca {
            Some(p) => {
                for c in certs(p)? {
                    roots.add(c).map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            None => {
                for c in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(c);
                }
            }
        }
        // TLS 1.3 only: the caller certificate is not sent in the clear.
        let relay_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs(caller_cert)?, key)
        .map_err(|e| format!("{}: {e}", caller_cert.display()))?;
        let (machine_name, device_ca, device_crls) = (
            machine.to_string(),
            device_ca.to_path_buf(),
            device_crls.to_vec(),
        );
        let reload: MachineTls = Arc::new(move || {
            let mut crls = Vec::new();
            for p in &device_crls {
                let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                if bytes.starts_with(b"-----BEGIN") {
                    for c in CertificateRevocationListDer::pem_slice_iter(&bytes) {
                        crls.push(c.map_err(|e| format!("{}: {e}", p.display()))?);
                    }
                } else {
                    crls.push(CertificateRevocationListDer::from(bytes));
                }
            }
            actp_proto::e2e::client_config(&certs(&device_ca)?, &crls, which, &machine_name)
        });
        Ok(RelayRoute {
            machine: machine.to_string(),
            relay_tls: Arc::new(relay_tls),
            machine_tls: reload()?,
            reload: Some(reload),
            on_behalf_of: None,
        })
    }
}

/// See [`Options::token_source`].
pub type TokenSource = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

impl Default for Options {
    fn default() -> Self {
        Options {
            agent: String::new(),
            base_url: String::new(),
            token: String::new(),
            client_name: String::new(),
            cwd: String::new(),
            maps: Vec::new(),
            wire: actp_proto::Options::default(),
            give_up_after: Duration::from_secs(600),
            max_backoff: Duration::from_secs(30),
            tls: None,
            token_source: None,
            relay: None,
        }
    }
}

/// A failed upgrade with an HTTP status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl StatusError {
    /// Errors that will not go away by retrying.
    pub fn permanent(&self) -> bool {
        matches!(self.status, 401 | 403 | 404 | 409 | 410 | 426)
    }
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "HTTP {}", self.status)
        } else {
            write!(f, "{} (HTTP {})", self.message, self.status)
        }
    }
}

/// Why the bridge stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The remote session is gone; the bridge should exit 1.
    Lost(String),
    /// The server refused the link.
    Status(StatusError),
    /// Anything else (a bad URL, the network).
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Lost(r) => write!(f, "remote session lost: {r}"),
            Error::Status(s) => s.fmt(f),
            Error::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

type Out = jsonrpc::Writer<Box<dyn AsyncWrite + Unpin + Send>>;

struct Bridge {
    opts: Options,
    out: Arc<Out>,
    ep: Endpoint,
    /// Client request ids waiting for an answer.
    pending: Arc<Mutex<HashMap<String, String>>>,
    link_id: Mutex<String>,
    tls: Arc<rustls::ClientConfig>,
}

enum Reconnect {
    ClientGone,
    Failed(Error),
}

/// Bridges `stdin`/`stdout` to the remote agent until the client closes stdin
/// (`Ok`) or the remote session is lost (`Err(Error::Lost)`) or never opened.
pub async fn run<R, W>(opts: Options, stdin: R, stdout: W) -> Result<(), Error>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let out: Arc<Out> = Arc::new(jsonrpc::Writer::new(Box::new(stdout)));
    let pending: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    let (o2, p2) = (out.clone(), pending.clone());
    let ep = Endpoint::new(
        opts.wire.clone(),
        deliver_fn(move |raw| {
            let (out, pending) = (o2.clone(), p2.clone());
            async move { to_client(&out, &pending, raw).await }
        }),
    );
    let tls = match (&opts.tls, &opts.relay) {
        (Some(t), _) => t.clone(),
        // Through a relay the route's own TLS is used; no OS store needed.
        (None, Some(route)) => route.relay_tls.clone(),
        (None, None) => default_tls().map_err(Error::Other)?,
    };
    let b = Arc::new(Bridge {
        opts,
        out,
        ep,
        pending,
        link_id: Mutex::new(String::new()),
        tls,
    });

    // Open the link before reading the client, so a bad URL or token fails fast.
    let (mut conn, mut peer_last) = b.dial().await?;

    let client_gone = CancellationToken::new();
    {
        let b = b.clone();
        let gone = client_gone.clone();
        tokio::spawn(async move {
            b.read_client(stdin).await;
            gone.cancel();
        });
    }

    loop {
        let ep = b.ep.clone();
        let mut served = tokio::spawn(async move { ep.serve(conn, peer_last).await });
        let end = tokio::select! {
            r = &mut served => r.unwrap_or_else(|e| ServeEnd::Closed(e.to_string())),
            _ = client_gone.cancelled() => {
                b.say_bye(Some(served)).await;
                return Ok(());
            }
        };
        if let ServeEnd::Remote(re) = &end
            && re.fatal()
        {
            return Err(b.lost(&remote_reason(re)).await);
        }
        tracing::info!(reason = %end, "connection dropped, reconnecting");
        match b.reconnect(&client_gone).await {
            Ok((c, last)) => {
                conn = c;
                peer_last = last;
            }
            Err(Reconnect::ClientGone) => {
                b.say_bye(None).await;
                return Ok(());
            }
            Err(Reconnect::Failed(e)) => return Err(b.lost(&e.to_string()).await),
        }
    }
}

fn remote_reason(re: &RemoteError) -> String {
    if re.code == ERR_AGENT_EXITED
        && let Some(data) = re.data.as_deref()
    {
        let mut errs = Vec::new();
        let stderr = gojson::object(data)
            .ok()
            .flatten()
            .and_then(|d| d.string("stderr", &mut errs))
            .unwrap_or_default();
        if !stderr.trim().is_empty() {
            return format!("{}: {}", re.message, last_line(&stderr));
        }
    }
    re.message.clone()
}

fn last_line(s: &str) -> &str {
    let s = s.trim_end_matches(['\r', '\n']);
    s.rsplit('\n').next().unwrap_or(s)
}

fn jitter(d: Duration) -> Duration {
    use rand::Rng;
    let n = d.as_nanos().max(1) as u64;
    d / 2 + Duration::from_nanos(rand::rng().random_range(0..n))
}

/// Delivers one message from the server to the client.
async fn to_client(
    out: &Out,
    pending: &Mutex<HashMap<String, String>>,
    raw: String,
) -> Result<(), String> {
    if let Ok(m) = jsonrpc::parse(&raw)
        && m.kind() == Kind::Response
    {
        pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&m.id_key());
    }
    out.write_raw(&raw).await.map_err(|e| e.to_string())
}

impl Bridge {
    /// Retries with backoff until it gets through, the client leaves, or it is
    /// time to give up. Time asleep does not count: the monotonic clock stops during sleep.
    async fn reconnect(
        &self,
        client_gone: &CancellationToken,
    ) -> Result<(FrameConn, i64), Reconnect> {
        let start = Instant::now();
        let mut delay = Duration::from_millis(500);
        loop {
            tokio::select! {
                _ = client_gone.cancelled() => return Err(Reconnect::ClientGone),
                _ = tokio::time::sleep(jitter(delay)) => {}
            }
            // A dial in progress is cancelled as soon as the client leaves.
            let r = tokio::select! {
                _ = client_gone.cancelled() => return Err(Reconnect::ClientGone),
                r = self.dial() => r,
            };
            match r {
                Ok(c) => {
                    tracing::info!("reconnected");
                    return Ok(c);
                }
                Err(Error::Status(se)) if se.permanent() => {
                    return Err(Reconnect::Failed(Error::Status(se)));
                }
                Err(e) => {
                    if start.elapsed() > self.opts.give_up_after {
                        return Err(Reconnect::Failed(Error::Other(format!(
                            "server unreachable for {}: {e}",
                            go_duration(self.opts.give_up_after)
                        ))));
                    }
                    delay = (delay * 2).min(self.opts.max_backoff);
                }
            }
        }
    }

    /// Tells the server the client has left (design 3.1), then lets the socket close.
    async fn say_bye(&self, served: Option<tokio::task::JoinHandle<ServeEnd>>) {
        if self.ep.attached() {
            self.ep.send_control(Frame::of(T_BYE));
            if let Some(h) = served
                && tokio::time::timeout(Duration::from_secs(3), h)
                    .await
                    .is_err()
            {
                self.ep.detach(CLOSE_NORMAL, "bye");
            }
            return;
        }
        // Not connected right now: try for a few seconds, so the server does not
        // keep prompts waiting for a client that is gone.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, self.dial()).await {
                Err(_) => return,
                Ok(Err(Error::Status(se))) if se.permanent() => return,
                Ok(Err(_)) => {
                    tokio::time::sleep_until(
                        deadline.min(tokio::time::Instant::now() + Duration::from_millis(200)),
                    )
                    .await;
                }
                Ok(Ok((conn, last))) => {
                    let ep = self.ep.clone();
                    let h = tokio::spawn(async move { ep.serve(conn, last).await });
                    self.ep.send_control(Frame::of(T_BYE));
                    let _ = tokio::time::timeout_at(deadline, h).await;
                    return;
                }
            }
        }
    }

    /// Answers everything the client is waiting on, so it is not left hanging.
    async fn lost(&self, reason: &str) -> Error {
        let ids: Vec<String> =
            std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()))
                .into_values()
                .collect();
        let err = Error::Lost(reason.to_string());
        let msg = err.to_string();
        for id in ids {
            let _ = self
                .out
                .write(&jsonrpc::new_error(&id, jsonrpc::CODE_SERVER_ERROR, &msg))
                .await;
        }
        err
    }

    /// Forwards the client's messages until stdin closes.
    async fn read_client<R: AsyncRead + Unpin>(&self, stdin: R) {
        let mut rd = jsonrpc::Reader::new(BufReader::new(stdin));
        loop {
            match rd.read().await {
                Ok(Some(Line::Message(mut m))) => {
                    if m.kind() == Kind::Request {
                        m = self.rewrite(m);
                        self.pending
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(m.id_key(), m.id.clone().unwrap_or_default());
                    }
                    self.ep.send(m.raw);
                }
                Ok(Some(Line::Invalid(line, _))) => {
                    tracing::warn!(line = %line, "client sent a line that is not JSON-RPC")
                }
                Ok(None) | Err(_) => return,
            }
        }
    }

    /// Drops client capabilities that cannot work remotely and applies --cwd/--map.
    fn rewrite(&self, m: Message) -> Message {
        let Ok(mut p) = gojson::decode_raw_map(m.params.as_deref()) else {
            return m;
        };
        let mut changed = false;
        if m.method == "initialize" {
            if let Ok(mut caps) = gojson::decode_raw_map(
                p.as_ref()
                    .and_then(|pm| pm.get("clientCapabilities"))
                    .map(String::as_str),
            ) {
                if let Some(c) = caps.as_mut() {
                    c.remove("fs");
                    c.remove("terminal");
                }
                if let Some(pm) = p.as_mut() {
                    pm.insert("clientCapabilities".into(), gojson::encode_raw_map(&caps));
                    changed = true;
                }
            }
        } else if [
            "session/new",
            "session/load",
            "session/resume",
            "session/fork",
            "session/options",
            "session/list",
        ]
        .contains(&m.method.as_str())
        {
            let cwd = gojson::string_or_empty(
                p.as_ref().and_then(|pm| pm.get("cwd")).map(String::as_str),
            );
            if !(cwd.is_empty() && m.method == "session/list") {
                let new_cwd = map_cwd(&self.opts.cwd, &self.opts.maps, &cwd);
                if new_cwd != cwd {
                    // Go writes into the params map; with `params: null` it would panic here.
                    p.get_or_insert_default()
                        .insert("cwd".into(), gojson::string(&new_cwd));
                    changed = true;
                }
                // --map applies to additional folders too; --cwd only replaces cwd.
                let dirs = p
                    .as_ref()
                    .and_then(|pm| pm.get("additionalDirectories"))
                    .and_then(|raw| serde_json::from_str::<Vec<Option<String>>>(raw).ok());
                if let Some(dirs) = dirs.filter(|d| !d.is_empty() && !self.opts.maps.is_empty()) {
                    let mapped: Vec<String> = dirs
                        .into_iter()
                        .map(|d| {
                            let d = d.unwrap_or_default();
                            let m2 = map_cwd("", &self.opts.maps, &d);
                            changed |= m2 != d;
                            m2
                        })
                        .collect();
                    let enc = gojson::GoValue::Arr(
                        mapped.into_iter().map(gojson::GoValue::Str).collect(),
                    )
                    .encode();
                    p.get_or_insert_default()
                        .insert("additionalDirectories".into(), enc);
                }
            }
        }
        if !changed {
            return m;
        }
        m.with_params(&jsonrpc::encode_params(&p)).unwrap_or(m)
    }

    async fn dial(&self) -> Result<(FrameConn, i64), Error> {
        let base = match &self.opts.relay {
            Some(_) => TUNNEL_BASE,
            None => self.opts.base_url.as_str(),
        };
        let target = link_url(base, &self.opts.agent).map_err(Error::Other)?;
        // What to name in errors: through a relay, the machine and the relay.
        let reached = match &self.opts.relay {
            Some(route) => format!("{} through {}", route.machine, self.opts.base_url),
            None => target.clone(),
        };
        let mut req = target
            .as_str()
            .into_client_request()
            .map_err(|e| Error::Other(e.to_string()))?;
        let hv = |v: &str| HeaderValue::from_str(v).map_err(|e| Error::Other(e.to_string()));
        let link_id = self
            .link_id
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let token = match &self.opts.token_source {
            Some(source) => tokio::time::timeout(Duration::from_secs(15), source())
                .await
                .map_err(|_| Error::Other("getting credentials: timed out".into()))?
                .map_err(|e| Error::Other(format!("getting credentials: {e}")))?,
            None => self.opts.token.clone(),
        };
        {
            let h = req.headers_mut();
            h.insert("Authorization", hv(&format!("Bearer {token}"))?);
            h.insert("Sec-WebSocket-Protocol", hv(&VERSIONS.join(", "))?);
            if !self.opts.client_name.is_empty() {
                h.insert(HEADER_CLIENT_NAME, hv(&self.opts.client_name)?);
            }
            if !link_id.is_empty() {
                h.insert(HEADER_LINK_ID, hv(&link_id)?);
                h.insert(HEADER_LAST_SEQ, hv(&self.ep.last_received().to_string())?);
            }
        }
        let connect = async {
            match &self.opts.relay {
                None => tokio_tungstenite::connect_async_tls_with_config(
                    req,
                    Some(websocket_config()),
                    true,
                    Some(Connector::Rustls(self.tls.clone())),
                )
                .await
                .map(|(ws, resp)| (FrameConn::from_websocket(ws), resp)),
                Some(route) => {
                    let tls = match self.tunnel(route).await {
                        Ok(tls) => tls,
                        Err(e) => return Ok(Err(e)),
                    };
                    tokio_tungstenite::client_async_with_config(req, tls, Some(websocket_config()))
                        .await
                        .map(|(ws, resp)| (FrameConn::from_websocket(ws), resp))
                }
            }
            .map(Ok)
        };
        let (conn, resp) = match tokio::time::timeout(Duration::from_secs(15), connect).await {
            Ok(Ok(Err(e))) => return Err(e),
            Err(_) => {
                return Err(Error::Other(format!(
                    "failed to WebSocket dial {reached}: timed out"
                )));
            }
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
                let status = resp.status().as_u16();
                let (code, mut message) =
                    api::decode_error_body(resp.body().as_deref().unwrap_or_default());
                // An actp server always explains a 404; a bare one means something else answered.
                if status == 404 && code.is_empty() {
                    message = no_server_hint(&self.opts.base_url);
                }
                return Err(Error::Status(StatusError {
                    status,
                    code,
                    message,
                }));
            }
            Ok(Err(e)) => {
                return Err(Error::Other(format!(
                    "failed to WebSocket dial {reached}: {e}"
                )));
            }
            Ok(Ok(Ok(x))) => x,
        };
        if let Some(id) = resp
            .headers()
            .get(HEADER_LINK_ID)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
        {
            *self.link_id.lock().unwrap_or_else(|p| p.into_inner()) = id.to_string();
        }
        let last = resp
            .headers()
            .get(HEADER_LAST_SEQ)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        Ok((conn, last))
    }

    /// A tunnel through the relay to the machine, and TLS to the machine
    /// inside it: the relay checks the caller certificate and carries bytes
    /// it cannot read.
    async fn tunnel(
        &self,
        route: &RelayRoute,
    ) -> Result<
        tokio_rustls::client::TlsStream<
            actp_proto::wsio::WsIo<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        >,
        Error,
    > {
        let url = tunnel_url(&self.opts.base_url, &route.machine).map_err(Error::Other)?;
        let mut req = url
            .as_str()
            .into_client_request()
            .map_err(|e| Error::Other(e.to_string()))?;
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(actp_proto::relay::PROTOCOL_TUNNEL),
        );
        if let Some(who) = &route.on_behalf_of {
            if !actp_proto::relay::valid_on_behalf_of(who) {
                return Err(Error::Other(
                    "on_behalf_of must be 1 to 256 bytes, without control, invisible or direction-changing characters or surrounding space".into(),
                ));
            }
            req.headers_mut().insert(
                actp_proto::relay::HEADER_ON_BEHALF_OF,
                HeaderValue::from_bytes(who.as_bytes()).map_err(|e| Error::Other(e.to_string()))?,
            );
        }
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(1 << 20))
            .max_frame_size(Some(1 << 20));
        let ws = match tokio_tungstenite::connect_async_tls_with_config(
            req,
            Some(config),
            true,
            Some(Connector::Rustls(route.relay_tls.clone())),
        )
        .await
        {
            Ok((ws, _)) => ws,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                let (code, message) =
                    api::decode_error_body(resp.body().as_deref().unwrap_or_default());
                return Err(Error::Status(StatusError {
                    status: resp.status().as_u16(),
                    code,
                    message,
                }));
            }
            Err(e) => {
                return Err(Error::Other(format!(
                    "failed to reach the relay at {url}: {e}"
                )));
            }
        };
        let machine_tls = match &route.reload {
            Some(reload) => reload().map_err(Error::Other)?,
            None => route.machine_tls.clone(),
        };
        let tls = tokio_rustls::TlsConnector::from(machine_tls)
            .connect(
                actp_proto::e2e::server_name(),
                actp_proto::wsio::WsIo::new(ws),
            )
            .await
            .map_err(|e| {
                Error::Other(format!(
                    "TLS to machine {} through the relay failed: {e}",
                    route.machine
                ))
            })?;
        if tls.get_ref().1.alpn_protocol() != Some(actp_proto::e2e::ALPN) {
            return Err(Error::Other(format!(
                "machine {} did not agree on the actp protocol",
                route.machine
            )));
        }
        Ok(tls)
    }
}

/// The relay's tunnel URL for `machine`: `wss://relay/relay/v1/tunnel/<machine>`.
pub fn tunnel_url(relay: &str, machine: &str) -> Result<String, String> {
    if !actp_proto::relay::valid_machine_name(machine) {
        return Err(format!("{machine:?} is not a valid machine address"));
    }
    let relay = relay.strip_suffix('/').unwrap_or(relay);
    let Some((scheme, rest)) = relay.split_once("://") else {
        return Err("the relay URL needs a scheme (https://)".into());
    };
    if rest.contains(['/', '?', '#']) {
        return Err("the relay URL is the relay's address only, with no path".into());
    }
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => "wss",
        other => return Err(format!("a relay is reached over https, not \"{other}\"")),
    };
    Ok(format!(
        "{scheme}://{rest}{}{}",
        actp_proto::relay::PATH_TUNNEL,
        path_escape(machine)
    ))
}

/// The base URL of the machine inside a tunnel: requests go to the machine
/// over the end-to-end TLS, so the host is only a placeholder.
const TUNNEL_BASE: &str = "http://machine.actp.invalid";

/// Rewrites a cwd with `--cwd` (always) or the longest matching `--map`.
pub fn map_cwd(cwd_override: &str, maps: &[Map], cwd: &str) -> String {
    if !cwd_override.is_empty() {
        return cwd_override.to_string();
    }
    let norm = cwd.replace('\\', "/");
    let trimmed = |s: &str| {
        let s = s.replace('\\', "/");
        s.strip_suffix('/').map(str::to_string).unwrap_or(s)
    };
    let mut best: Option<usize> = None;
    for (i, mp) in maps.iter().enumerate() {
        let from = trimmed(&mp.from);
        // Go compares this normalized length with the raw length of the best
        // map so far; kept as is (listed in the PR notes).
        if (norm == from || norm.starts_with(&format!("{from}/")))
            && best.is_none_or(|b| from.len() > maps[b].from.len())
        {
            best = Some(i);
        }
    }
    let Some(b) = best else {
        return cwd.to_string();
    };
    let mp = &maps[b];
    let after = norm
        .strip_prefix(trimmed(&mp.from).as_str())
        .unwrap_or(&norm);
    let rest = after.strip_prefix('/').unwrap_or(after);
    if rest.is_empty() {
        return mp.to.clone();
    }
    format!("{}/{rest}", mp.to.strip_suffix('/').unwrap_or(&mp.to))
}

/// Go's `url.PathEscape`.
fn path_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b',' | b':' | b'=' | b'@'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The WebSocket URL of an agent's link endpoint.
pub fn link_url(base: &str, agent: &str) -> Result<String, String> {
    let base = base.strip_suffix('/').unwrap_or(base);
    let Some((scheme, rest)) = base.split_once("://") else {
        return Err("unsupported URL scheme \"\"".into());
    };
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => return Err(format!("unsupported URL scheme \"{other}\"")),
    };
    let (auth_path, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let mut out = format!(
        "{scheme}://{auth_path}/actp/v1/agents/{}/link",
        path_escape(agent)
    );
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    Ok(out)
}

/// Explains a URL where no actp server answers. Quick tunnel addresses change
/// whenever the server restarts, which is the usual cause.
pub fn no_server_hint(base: &str) -> String {
    let host = base
        .split_once("://")
        .map_or(base, |(_, r)| r)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host
        .rsplit_once(':')
        .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(h, _)| h);
    let mut msg = format!("no actp server answers at {base}");
    if host.ends_with(".trycloudflare.com") {
        msg.push_str(". Quick tunnel addresses change every time the server restarts: copy the current URL from the server's dashboard and update this remote");
    } else {
        msg.push_str(". Check the URL, and that the server is running");
    }
    msg
}

/// TLS with the OS trust store and the ring crypto provider.
pub fn default_tls() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Go's `time.Duration.String`, as error messages show durations.
pub fn go_duration(d: Duration) -> String {
    if d.is_zero() {
        return "0s".into();
    }
    if d < Duration::from_secs(1) {
        return format!("{}ms", gojson::format_float(d.as_secs_f64() * 1000.0));
    }
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let frac = d.subsec_nanos();
    let s = if frac > 0 {
        format!("{s}.{}", format!("{frac:09}").trim_end_matches('0'))
    } else {
        s.to_string()
    };
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_urls() {
        assert_eq!(
            link_url("https://agents.example.com/", "claude").unwrap(),
            "wss://agents.example.com/actp/v1/agents/claude/link"
        );
        assert_eq!(
            link_url("http://127.0.0.1:7860/prefix", "a b").unwrap(),
            "ws://127.0.0.1:7860/prefix/actp/v1/agents/a%20b/link"
        );
        assert!(link_url("ftp://x", "a").is_err());
    }

    #[test]
    fn cwd_maps() {
        let maps = vec![
            Map {
                from: "/client".into(),
                to: "actp://a".into(),
            },
            Map {
                from: "/client/repo/".into(),
                to: "actp://site/".into(),
            },
        ];
        assert_eq!(map_cwd("", &maps, "/client/repo/src"), "actp://site/src");
        assert_eq!(map_cwd("", &maps, "/client/repo"), "actp://site/");
        assert_eq!(map_cwd("", &maps, "/client/x"), "actp://a/x");
        assert_eq!(map_cwd("", &maps, "/elsewhere"), "/elsewhere");
        assert_eq!(map_cwd("actp://w", &maps, "/elsewhere"), "actp://w");
    }

    #[test]
    fn hints_and_durations() {
        assert!(no_server_hint("https://abc.trycloudflare.com").contains("Quick tunnel"));
        assert!(no_server_hint("http://127.0.0.1:9").ends_with("that the server is running"));
        assert_eq!(go_duration(Duration::from_secs(600)), "10m0s");
        assert_eq!(go_duration(Duration::from_secs(3)), "3s");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(
            StatusError {
                status: 401,
                code: "unauthorized".into(),
                message: "missing or invalid token".into()
            }
            .to_string(),
            "missing or invalid token (HTTP 401)"
        );
    }
}

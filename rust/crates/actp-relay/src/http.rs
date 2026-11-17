//! The relay's HTTP surface.
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /health` | anyone | liveness |
//! | `GET /relay/v1/connect` | a machine (device certificate) | the control WebSocket |
//! | `GET /relay/v1/stream/<id>` | the machine asked for it | a caller's stream |
//! | `GET /relay/v1/tunnel/<address>` | a caller (caller certificate) | a byte tunnel to the machine, carrying the caller's TLS to it |
//! | `GET /relay/v1/issuer/<path>` | a machine (device certificate) | a configured question to the identity service ([`crate::issuer`]) |
//! | `GET /relay/v1/machines` | admin token | who is online, last seen |
//! | `GET /relay/v1/stop` | admin token | the org-wide stop |
//! | `POST /relay/v1/stop`, `POST /relay/v1/release` | admin token | press, release (`{"reason": …}`) |
//!
//! Caller and management routes are rate limited per IP address. The relay
//! never reads what a tunnel carries: the caller's TLS ends at the machine
//! ([`actp_proto::e2e`]).

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use actp_proto::api;
use actp_proto::relay::{
    Control, PATH_CONNECT, PATH_ISSUER, PATH_STREAM, PATH_TUNNEL, PROTOCOL_CONTROL,
    PROTOCOL_STREAM, PROTOCOL_TUNNEL, valid_machine_name, valid_stream_id,
};
use actp_proto::wsio::WsIo;
use base64::Engine;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_util::sync::CancellationToken;

use crate::{Refusal, Relay};

/// A caller's stream, opened by a machine.
pub type Stream = WsIo<TokioIo<Upgraded>>;

type Body = BoxBody<Bytes, hyper::Error>;
type Resp = Response<Body>;

/// Who is on the other end of a TLS connection.
pub(crate) struct Peer {
    pub remote: SocketAddr,
    /// The machine named by a verified device certificate; `None` without one.
    pub machine: Option<Result<String, String>>,
    /// The caller named by a verified caller certificate; `None` without one.
    pub caller: Option<Result<String, String>>,
    /// That certificate's chain, leaf first, checked again on every request.
    pub chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    /// The connection's place under the connection limits, kept for as long
    /// as the connection (or a session it became) lives. `None` for a
    /// machine that proved itself.
    pub held: Option<Arc<crate::Held>>,
}

pub(crate) async fn serve_connection<S>(
    relay: Relay,
    io: S,
    peer: Peer,
    shutdown: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer = Arc::new(peer);
    let svc = hyper::service::service_fn(move |req| {
        let (relay, peer, shutdown) = (relay.clone(), peer.clone(), shutdown.clone());
        async move { Ok::<_, Infallible>(handle(&relay, &peer, req, shutdown).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades();
    let _ = conn.await;
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed()
}

fn json_resp(status: StatusCode, body: String) -> Resp {
    let mut r = Response::new(full(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

fn error(status: StatusCode, code: &str, message: &str) -> Resp {
    json_resp(status, api::error_body(code, message))
}

async fn handle(
    relay: &Relay,
    peer: &Peer,
    req: Request<Incoming>,
    shutdown: CancellationToken,
) -> Resp {
    let path = req.uri().path().to_string();
    if path == PATH_CONNECT {
        return machine_control(relay, peer, req, shutdown);
    }
    if let Some(id) = path.strip_prefix(PATH_STREAM) {
        return machine_stream(relay, peer, req, id.to_string());
    }
    if let Some(rest) = path.strip_prefix(PATH_ISSUER)
        && (rest.is_empty() || rest.starts_with('/'))
    {
        return issuer(relay, peer, req, rest).await;
    }
    // Everything else is open to anyone on the network: rate limited.
    if !relay.callers().allow(peer.remote.ip()) {
        relay.refusal(
            "caller_rate_limited",
            [("remote", json!(peer.remote.ip().to_string()))],
        );
        let mut r = error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests from this address",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return r;
    }
    if path == "/health" {
        return json_resp(StatusCode::OK, api::health());
    }
    let admin_route = matches!(
        path.as_str(),
        "/relay/v1/machines" | "/relay/v1/stop" | "/relay/v1/release"
    );
    if admin_route {
        return admin(relay, peer, req, &path).await;
    }
    match path.strip_prefix(PATH_TUNNEL) {
        Some(machine) => tunnel(relay, peer, req, machine).await,
        None => error(StatusCode::NOT_FOUND, "not_found", "no such route"),
    }
}

// ---- machines ----

/// The verified machine of a connection, or the response refusing it.
fn machine_of(relay: &Relay, peer: &Peer, route: &str) -> Result<String, Box<Resp>> {
    match &peer.machine {
        None => Err(Box::new(error(
            StatusCode::UNAUTHORIZED,
            "device_certificate_required",
            "this route needs the machine's device certificate",
        ))),
        Some(Err(why)) => {
            relay.refusal(
                "machine_refused",
                [
                    ("remote", json!(peer.remote.to_string())),
                    ("route", json!(route)),
                    ("reason", json!(why)),
                ],
            );
            Err(Box::new(error(
                StatusCode::FORBIDDEN,
                "bad_device_certificate",
                why,
            )))
        }
        Some(Ok(m)) if relay.blocked(m) => {
            relay.refusal(
                "machine_refused",
                [
                    ("machine", json!(m)),
                    ("remote", json!(peer.remote.to_string())),
                    ("route", json!(route)),
                    ("reason", json!("blocked")),
                ],
            );
            Err(Box::new(error(
                StatusCode::FORBIDDEN,
                "machine_blocked",
                "this machine is blocked at the relay",
            )))
        } // Checked again on every request: the certificate may have expired,
        // or been revoked by a reload, since the handshake.
        Some(Ok(m)) if !relay.chain_valid(&peer.chain) => {
            relay.refusal(
                "machine_refused",
                [
                    ("machine", json!(m)),
                    ("remote", json!(peer.remote.to_string())),
                    ("route", json!(route)),
                    ("reason", json!("certificate_invalid")),
                ],
            );
            Err(Box::new(error(
                StatusCode::FORBIDDEN,
                "bad_device_certificate",
                "the device certificate is no longer valid",
            )))
        }
        Some(Ok(m)) => Ok(m.clone()),
    }
}

/// Checks a WebSocket upgrade request for `protocol` and builds the 101.
fn ws_accept(req: &Request<Incoming>, protocol: &str) -> Result<Resp, Box<Resp>> {
    let h = req.headers();
    let bad = |msg: &str| Box::new(error(StatusCode::BAD_REQUEST, "bad_request", msg));
    if req.method() != Method::GET {
        return Err(bad("a WebSocket upgrade must be a GET"));
    }
    let has = |name: header::HeaderName, token: &str| {
        h.get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    };
    if !has(header::UPGRADE, "websocket") || !has(header::CONNECTION, "upgrade") {
        return Err(bad("a WebSocket upgrade is required"));
    }
    if h.get(header::SEC_WEBSOCKET_VERSION).map(|v| v.as_bytes()) != Some(b"13") {
        return Err(bad("WebSocket version 13 is required"));
    }
    let keys: Vec<_> = h.get_all(header::SEC_WEBSOCKET_KEY).iter().collect();
    let key = match keys.as_slice() {
        [k] => k.to_str().unwrap_or("").trim().to_string(),
        _ => return Err(bad("one Sec-WebSocket-Key is required")),
    };
    if base64::engine::general_purpose::STANDARD
        .decode(&key)
        .map(|v| v.len())
        != Ok(16)
    {
        return Err(bad("invalid Sec-WebSocket-Key"));
    }
    if !has(header::SEC_WEBSOCKET_PROTOCOL, protocol) {
        return Err(bad(&format!("the {protocol} subprotocol is required")));
    }
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let rh = r.headers_mut();
    rh.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    rh.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    rh.insert(
        header::SEC_WEBSOCKET_ACCEPT,
        HeaderValue::from_str(&derive_accept_key(key.as_bytes()))
            .expect("base64 is a header value"),
    );
    rh.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_str(protocol).expect("protocol is a header value"),
    );
    Ok(r)
}

fn ws_config(max: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

fn machine_control(
    relay: &Relay,
    peer: &Peer,
    mut req: Request<Incoming>,
    shutdown: CancellationToken,
) -> Resp {
    let machine = match machine_of(relay, peer, "connect") {
        Ok(m) => m,
        Err(r) => return *r,
    };
    let resp = match ws_accept(&req, PROTOCOL_CONTROL) {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    let relay = relay.clone();
    let remote = peer.remote;
    let chain = peer.chain.clone();
    tokio::spawn(async move {
        let Ok(up) = on_upgrade.await else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(
            TokioIo::new(up),
            Role::Server,
            Some(ws_config(64 << 10)),
        )
        .await;
        run_control(relay, machine, remote, chain, ws, shutdown).await;
    });
    resp
}

async fn run_control(
    relay: Relay,
    machine: String,
    remote: SocketAddr,
    chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    mut ws: WebSocketStream<TokioIo<Upgraded>>,
    shutdown: CancellationToken,
) {
    let Some((id, mut rx, cut, stopped)) = relay.machine_connected(&machine, remote, chain) else {
        // Blocked, or its certificate stopped being valid, since the request.
        let _ = ws.close(None).await;
        return;
    };
    tracing::info!(machine = %machine, %remote, "machine online");
    let (mut sink, mut stream) = ws.split();
    let timing = relay.timing().clone();
    // Every write has a deadline, so a machine that stops reading cannot
    // hold this task (and its cut-off) forever.
    let send_timeout = timing.send_timeout;
    let mut send = async |m: Message| -> bool {
        matches!(
            tokio::time::timeout(send_timeout, sink.send(m)).await,
            Ok(Ok(()))
        )
    };
    let hello = Control::Hello {
        machine: machine.clone(),
        stopped,
    };
    let mut why: String = "closed".into();
    if !send(Message::text(hello.encode())).await {
        relay.machine_disconnected(&machine, id, "send failed");
        return;
    }
    let mut last_heard = Instant::now();
    let mut last_marked = Instant::now();
    let mut ping = tokio::time::interval(timing.ping_every);
    ping.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => { why = "relay stopping".into(); break; }
            _ = cut.cancelled() => {
                why = cut.why().into();
                let code = if why == "replaced" {
                    actp_proto::frame::CLOSE_REPLACED
                } else {
                    actp_proto::frame::CLOSE_GOING_AWAY
                };
                let _ = send(Message::Close(Some(CloseFrame {
                    code: CloseCode::from(code),
                    reason: cut.why().into(),
                }))).await;
                break;
            }
            m = rx.recv() => {
                let Some(m) = m else { break };
                if !send(Message::text(m.encode())).await {
                    why = "send failed".into();
                    break;
                }
            }
            _ = ping.tick() => {
                if last_heard.elapsed() >= timing.dead_after {
                    why = "silent".into();
                    break;
                }
                if !send(Message::Ping(Bytes::new())).await {
                    why = "send failed".into();
                    break;
                }
            }
            m = stream.next() => match m {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => { why = "connection error".into(); break; }
                Some(Ok(_)) => {
                    last_heard = Instant::now();
                    if last_marked.elapsed() >= Duration::from_secs(5) {
                        last_marked = Instant::now();
                        relay.machine_seen(&machine);
                    }
                }
            },
        }
    }
    tracing::info!(machine = %machine, reason = %why, "machine offline");
    relay.machine_disconnected(&machine, id, &why);
}

fn machine_stream(relay: &Relay, peer: &Peer, mut req: Request<Incoming>, id: String) -> Resp {
    let machine = match machine_of(relay, peer, "stream") {
        Ok(m) => m,
        Err(r) => return *r,
    };
    if !valid_stream_id(&id) {
        return error(StatusCode::NOT_FOUND, "unknown_stream", "no such stream");
    }
    let resp = match ws_accept(&req, PROTOCOL_STREAM) {
        Ok(r) => r,
        Err(r) => return *r,
    };
    // Only the machine the stream was asked of can take it.
    let Some(tx) = relay.take_pending(&machine, &id) else {
        return error(StatusCode::NOT_FOUND, "unknown_stream", "no such stream");
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let Ok(up) = on_upgrade.await else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(
            TokioIo::new(up),
            Role::Server,
            Some(ws_config(1 << 20)),
        )
        .await;
        let _ = tx.send(WsIo::new(ws));
    });
    resp
}

// ---- the issuer pass-through ----

/// `GET /relay/v1/issuer/<path>?<query>`: a machine's question to the
/// identity service, forwarded with the relay's own credentials there.
async fn issuer(relay: &Relay, peer: &Peer, req: Request<Incoming>, path: &str) -> Resp {
    let machine = match machine_of(relay, peer, "issuer") {
        Ok(m) => m,
        Err(r) => return *r,
    };
    let Some(issuer) = relay.issuer() else {
        return error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no issuer is configured",
        );
    };
    if req.method() != Method::GET {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "only GET is forwarded",
        );
    }
    let refuse = |status: StatusCode, code: &'static str, msg: &str| {
        // The machine and why, never the path's query (it names people).
        relay.refusal(
            "issuer_refused",
            [("machine", json!(machine)), ("reason", json!(code))],
        );
        let mut r = error(status, code, msg);
        if matches!(
            code,
            "issuer_rate_limited" | "issuer_busy" | "issuer_unavailable"
        ) {
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        r
    };
    match issuer.ask(&machine, path, req.uri().query()).await {
        Ok((status, body)) => {
            // Who asked which question, never its query (it names people).
            relay.audit().event(
                "issuer_asked",
                [
                    ("machine", json!(machine)),
                    ("path", json!(path)),
                    ("status", json!(status.as_u16())),
                ],
            );
            let mut r = Response::new(full(body));
            *r.status_mut() = status;
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(crate::issuer::Refusal::NotForwarded) => refuse(
            StatusCode::NOT_FOUND,
            "issuer_path_not_forwarded",
            "this path is not forwarded to the issuer",
        ),
        Err(crate::issuer::Refusal::QueryTooLong) => refuse(
            StatusCode::URI_TOO_LONG,
            "issuer_query_too_long",
            "the query is too long",
        ),
        Err(crate::issuer::Refusal::RateLimited) => refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "issuer_rate_limited",
            "this machine asks the issuer too often",
        ),
        Err(crate::issuer::Refusal::Busy) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "issuer_busy",
            "too many questions to the issuer in flight",
        ),
        Err(crate::issuer::Refusal::Unavailable) => refuse(
            StatusCode::BAD_GATEWAY,
            "issuer_unavailable",
            "the issuer could not be asked",
        ),
    }
}

// ---- callers ----

/// The verified caller of a connection, or the response refusing it.
fn caller_of(relay: &Relay, peer: &Peer) -> Result<String, Box<Resp>> {
    let refuse = |status, code: &str, why: &str, caller: Option<&str>| {
        relay.refusal(
            "caller_refused",
            [
                ("caller", json!(caller)),
                ("remote", json!(peer.remote.to_string())),
                ("reason", json!(code)),
            ],
        );
        Box::new(error(status, code, why))
    };
    match &peer.caller {
        None => Err(refuse(
            StatusCode::UNAUTHORIZED,
            "caller_certificate_required",
            "a tunnel needs a caller certificate",
            None,
        )),
        Some(Err(why)) => Err(refuse(
            StatusCode::FORBIDDEN,
            "bad_caller_certificate",
            why,
            None,
        )),
        Some(Ok(c)) if relay.caller_blocked(c) => Err(refuse(
            StatusCode::FORBIDDEN,
            "caller_blocked",
            "this caller is blocked at the relay",
            Some(c),
        )),
        // Checked again on every request: the certificate may have expired,
        // or been revoked by a reload, since the handshake.
        Some(Ok(c)) if !relay.caller_chain_valid(&peer.chain) => Err(refuse(
            StatusCode::FORBIDDEN,
            "bad_caller_certificate",
            "the caller certificate is no longer valid",
            Some(c),
        )),
        Some(Ok(c)) => Ok(c.clone()),
    }
}

/// Ends a session in the relay's table when dropped, however the tunnel ends.
struct SessionEnd {
    relay: Relay,
    session: u64,
}

impl Drop for SessionEnd {
    fn drop(&mut self) {
        self.relay.session_ended(self.session);
    }
}

/// `GET /relay/v1/tunnel/<machine>`: a caller's byte tunnel to a machine.
/// The relay checks the caller's certificate, routes by the address, asks
/// the machine for a stream, and joins the two. What flows through is the
/// caller's TLS to the machine, which the relay can neither read nor change
/// without the connection failing.
async fn tunnel(relay: &Relay, peer: &Peer, mut req: Request<Incoming>, raw_machine: &str) -> Resp {
    let caller = match caller_of(relay, peer) {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let machine = match percent_encoding::percent_decode_str(raw_machine).decode_utf8() {
        Ok(m) if valid_machine_name(&m) => m.into_owned(),
        _ => {
            return error(
                StatusCode::NOT_FOUND,
                "unknown_machine",
                "not a machine address",
            );
        }
    };
    let resp = match ws_accept(&req, PROTOCOL_TUNNEL) {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let remote = peer.remote.to_string();
    let refuse = |reason: Refusal| {
        let (status, code, msg) = match reason {
            Refusal::Stopped => (
                StatusCode::SERVICE_UNAVAILABLE,
                "org_stopped",
                "the organization-wide stop is on",
            ),
            Refusal::Offline => (
                StatusCode::SERVICE_UNAVAILABLE,
                "machine_offline",
                "the machine is not connected to the relay",
            ),
            Refusal::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "machine_busy",
                "too many callers are connected to this machine",
            ),
            Refusal::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "machine_timeout",
                "the machine did not answer in time",
            ),
            Refusal::CallerBusy => (
                StatusCode::TOO_MANY_REQUESTS,
                "caller_busy",
                "this caller has as many streams to this machine as it may",
            ),
            Refusal::Cut("org_stop") => (
                StatusCode::SERVICE_UNAVAILABLE,
                "org_stopped",
                "the organization-wide stop is on",
            ),
            Refusal::Cut(why @ ("caller_blocked" | "caller_certificate_invalid")) => (
                StatusCode::FORBIDDEN,
                why,
                "this caller was cut off while the machine was being asked",
            ),
            Refusal::Cut(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "machine_offline",
                "the machine went offline while it was being asked",
            ),
        };
        relay.refusal(
            "caller_refused",
            [
                ("caller", json!(caller)),
                ("machine", json!(machine)),
                ("remote", json!(remote)),
                ("reason", json!(code)),
            ],
        );
        let mut r = error(status, code, msg);
        if reason != Refusal::Timeout {
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        }
        r
    };
    // The session is registered, and the stop checked, before the machine
    // is asked; a stop pressed while it answers cuts the session at once.
    let (session, cut) = match relay.session_started(&machine, &caller, &peer.chain) {
        Ok(s) => s,
        Err(r) => return refuse(r),
    };
    let ended = SessionEnd {
        relay: relay.clone(),
        session,
    };
    // The 101 waits for the machine's stream, so a caller is told in plain
    // HTTP why it cannot have a tunnel; a cut meanwhile (the stop, the
    // machine gone, the caller revoked) answers at once, and is checked
    // once more before the 101.
    let (stream, slot) = tokio::select! {
        opened = relay.open_stream(&machine) => match opened {
            Ok(s) => s,
            Err(r) => return refuse(r),
        },
        _ = cut.cancelled() => return refuse(Refusal::Cut(cut.why())),
    };
    if cut.is_cut() {
        return refuse(Refusal::Cut(cut.why()));
    }
    relay.audit().event(
        "session_open",
        [
            ("session", json!(session)),
            ("machine", json!(machine)),
            ("caller", json!(caller)),
            ("remote", json!(remote)),
        ],
    );
    let on_upgrade = hyper::upgrade::on(&mut req);
    let relay = relay.clone();
    let held = peer.held.clone();
    tokio::spawn(async move {
        let _held = held;
        let _ended = ended;
        let started = Instant::now();
        let (to_machine, to_caller) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let reason = match on_upgrade.await {
            Ok(up) => {
                let ws = WebSocketStream::from_raw_socket(
                    TokioIo::new(up),
                    Role::Server,
                    Some(ws_config(1 << 20)),
                )
                .await;
                let mut a = Counting {
                    io: WsIo::new(ws),
                    read: to_machine.clone(),
                };
                let mut b = Counting {
                    io: stream,
                    read: to_caller.clone(),
                };
                tokio::select! {
                    _ = cut.cancelled() => cut.why(),
                    r = tokio::io::copy_bidirectional(&mut a, &mut b) => {
                        if r.is_ok() { "closed" } else { "error" }
                    }
                }
            }
            Err(_) => "upgrade_failed",
        };
        drop(slot);
        relay.audit().event(
            "session_closed",
            [
                ("session", json!(session)),
                ("machine", json!(machine)),
                ("caller", json!(caller)),
                ("seconds", json!(started.elapsed().as_secs())),
                (
                    "bytes_to_machine",
                    json!(to_machine.load(Ordering::Relaxed)),
                ),
                ("bytes_to_caller", json!(to_caller.load(Ordering::Relaxed))),
                ("reason", json!(reason)),
            ],
        );
    });
    resp
}

/// Counts the bytes read through it.
struct Counting<T> {
    io: T,
    read: Arc<AtomicU64>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counting<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        self.read.fetch_add(n, Ordering::Relaxed);
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counting<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// ---- admin ----

async fn admin(relay: &Relay, peer: &Peer, req: Request<Incoming>, path: &str) -> Resp {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    let Some(by) = relay.admin(presented) else {
        relay.refusal(
            "admin_refused",
            [
                ("remote", json!(peer.remote.to_string())),
                ("route", json!(path)),
            ],
        );
        let mut r = error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid admin token",
        );
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"actp-relay\""),
        );
        return r;
    };
    match (req.method().clone(), path) {
        (Method::GET, "/relay/v1/machines") => {
            json_resp(StatusCode::OK, relay.machines_json().to_string())
        }
        (Method::GET, "/relay/v1/stop") => json_resp(
            StatusCode::OK,
            json!({ "stop": relay.stop_state() }).to_string(),
        ),
        (Method::POST, "/relay/v1/stop" | "/relay/v1/release") => {
            let body = match Limited::new(req.into_body(), 16 << 10).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "bad_request",
                        "the body is too large",
                    );
                }
            };
            let reason = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
                .map(|r| r.trim().to_string())
                .unwrap_or_default();
            if reason.is_empty() || reason.len() > 1000 {
                return error(
                    StatusCode::BAD_REQUEST,
                    "reason_required",
                    "say why: {\"reason\": \"…\"} (up to 1000 bytes)",
                );
            }
            if path == "/relay/v1/stop" {
                let s = relay.stop(&by, &reason);
                if s.saved {
                    json_resp(StatusCode::OK, json!({ "stop": s.stop }).to_string())
                } else {
                    // The stop holds now, but a restart would lose it.
                    json_resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "error": "stop_not_saved",
                            "message": "the stop is on, but stop.json could not be written: a restart before the relay manages to write it would lose the stop",
                            "stop": s.stop,
                        })
                        .to_string(),
                    )
                }
            } else {
                match relay.release(&by, &reason) {
                    Ok(s) => json_resp(StatusCode::OK, json!({ "stop": s }).to_string()),
                    Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, "not_released", &e),
                }
            }
        }
        _ => {
            let mut r = error(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
            );
            let allow = if path == "/relay/v1/machines" {
                "GET"
            } else if path == "/relay/v1/stop" {
                "GET, POST"
            } else {
                "POST"
            };
            r.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static(allow));
            r
        }
    }
}

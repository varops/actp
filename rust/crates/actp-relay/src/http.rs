//! The relay's HTTP surface.
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /health` | anyone | liveness |
//! | `GET /relay/v1/connect` | a machine (device certificate) | the control WebSocket |
//! | `GET /relay/v1/stream/<id>` | the machine asked for it | a caller's stream |
//! | `* /m/<address>/<path>` | callers | forwarded to the machine as `<path>` |
//! | `GET /relay/v1/machines` | admin token | who is online, last seen |
//! | `GET /relay/v1/stop` | admin token | the org-wide stop |
//! | `POST /relay/v1/stop`, `POST /relay/v1/release` | admin token | press, release (`{"reason": …}`) |
//!
//! Caller and management routes are rate limited per IP address.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use actp_proto::api;
use actp_proto::frame::{HEADER_CLIENT_NAME, HEADER_LINK_ID};
use actp_proto::relay::{
    Control, PATH_CONNECT, PATH_MACHINE, PATH_STREAM, PROTOCOL_CONTROL, PROTOCOL_STREAM,
    valid_machine_name, valid_stream_id,
};
use actp_proto::wsio::WsIo;
use base64::Engine;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
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
    if path == "/health" {
        return json_resp(StatusCode::OK, api::health());
    }
    if path == PATH_CONNECT {
        return machine_control(relay, peer, req, shutdown);
    }
    if let Some(id) = path.strip_prefix(PATH_STREAM) {
        return machine_stream(relay, peer, req, id.to_string());
    }
    let admin_route = matches!(
        path.as_str(),
        "/relay/v1/machines" | "/relay/v1/stop" | "/relay/v1/release"
    );
    if !admin_route && !path.starts_with(PATH_MACHINE) {
        return error(StatusCode::NOT_FOUND, "not_found", "no such route");
    }
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
    if admin_route {
        return admin(relay, peer, req, &path).await;
    }
    let rest = path[PATH_MACHINE.len()..].to_string();
    caller(relay, peer, req, &rest).await
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
        run_control(relay, machine, remote, ws, shutdown).await;
    });
    resp
}

async fn run_control(
    relay: Relay,
    machine: String,
    remote: SocketAddr,
    ws: WebSocketStream<TokioIo<Upgraded>>,
    shutdown: CancellationToken,
) {
    let (id, mut rx, cut, stopped) = relay.machine_connected(&machine, remote);
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

// ---- callers ----

/// Splits `<address>/<path>` after `/m/`: the decoded address and the path
/// to forward (with the query).
fn split_target(rest: &str, uri: &Uri) -> Option<(String, String)> {
    let (raw_machine, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let machine = percent_encoding::percent_decode_str(raw_machine)
        .decode_utf8()
        .ok()?
        .into_owned();
    if !valid_machine_name(&machine) {
        return None;
    }
    let mut target = path.to_string();
    if let Some(q) = uri.query() {
        target.push('?');
        target.push_str(q);
    }
    Some((machine, target))
}

/// Headers that belong to one hop and are not forwarded.
const HOP: &[&str] = &[
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
];

fn forwarded_headers(h: &HeaderMap, upgrade: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in h {
        let name = k.as_str();
        if HOP.contains(&name) {
            continue;
        }
        if !upgrade && (k == header::CONNECTION || k == header::UPGRADE) {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

/// The forwarded path as the machine routes it: each segment
/// percent-decoded, no query, at most 128 characters. For the audit.
fn route_of(target: &str) -> String {
    let path = target.split('?').next().unwrap_or("");
    let decoded: Vec<String> = path
        .split('/')
        .map(|s| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned()
        })
        .collect();
    decoded.join("/").chars().take(128).collect()
}

/// The agent id of an ACTP link route, for the audit.
fn agent_of(route: &str) -> Option<String> {
    let s: Vec<&str> = route.trim_start_matches('/').split('/').collect();
    match s.as_slice() {
        ["actp", "v1", "agents", id, "link"] => Some(id.chars().take(64).collect()),
        _ => None,
    }
}

fn short(s: &str) -> String {
    s.chars().take(8).collect()
}

fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(128).collect())
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

async fn caller(relay: &Relay, peer: &Peer, mut req: Request<Incoming>, rest: &str) -> Resp {
    let Some((machine, target)) = split_target(rest, req.uri()) else {
        return error(
            StatusCode::NOT_FOUND,
            "unknown_machine",
            "not a machine address",
        );
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
        };
        relay.refusal(
            "caller_refused",
            [
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
    let (stream, slot) = match relay.open_stream(&machine).await {
        Ok(s) => s,
        Err(r) => return refuse(r),
    };
    let upgrade = is_upgrade(req.headers());
    let caller_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let mut fwd = Request::new(body);
    *fwd.method_mut() = parts.method.clone();
    *fwd.uri_mut() = match target.parse() {
        Ok(u) => u,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request", "bad path"),
    };
    *fwd.headers_mut() = forwarded_headers(&parts.headers, upgrade);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(x) => x,
        Err(_) => return refuse(Refusal::Timeout),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let timing = relay.timing().clone();
    let mut resp =
        match tokio::time::timeout(timing.response_timeout, sender.send_request(fwd)).await {
            Ok(Ok(r)) => r,
            _ => return refuse(Refusal::Timeout),
        };
    let status = resp.status();
    let route = route_of(&target);
    let agent = agent_of(&route);
    let resumed = parts.headers.contains_key(HEADER_LINK_ID);
    let link = header_str(resp.headers(), HEADER_LINK_ID).map(|l| short(&l));
    let client_name = header_str(&parts.headers, HEADER_CLIENT_NAME);

    if status != StatusCode::SWITCHING_PROTOCOLS || caller_upgrade.is_none() {
        relay.audit().event(
            "caller_answered",
            [
                ("machine", json!(machine)),
                ("remote", json!(remote)),
                ("route", json!(route)),
                ("status", json!(status.as_u16())),
            ],
        );
        if status == StatusCode::SWITCHING_PROTOCOLS {
            // The caller asked for no upgrade: a machine has no business switching.
            return error(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                "the machine switched protocols unasked",
            );
        }
        // The slot is held until the answer has been sent.
        let (rparts, rbody) = resp.into_parts();
        let body = rbody.map_frame(move |f| {
            let _ = &slot;
            f
        });
        return Response::from_parts(rparts, body.boxed());
    }

    // A link: register the session (refused if the stop came meanwhile) and
    // pipe the two upgraded connections into each other.
    let Some((session, cut)) = relay.session_started(&machine) else {
        return refuse(Refusal::Stopped);
    };
    relay.audit().event(
        "session_open",
        [
            ("session", json!(session)),
            ("machine", json!(machine)),
            ("remote", json!(remote)),
            ("agent", json!(agent)),
            ("link", json!(link)),
            ("resumed", json!(resumed)),
            ("client_name", json!(client_name)),
        ],
    );
    let machine_upgrade = hyper::upgrade::on(&mut resp);
    let (rparts, _) = resp.into_parts();
    let mut out = Response::from_parts(rparts, full(Bytes::new()));
    strip_hop(out.headers_mut());
    let relay2 = relay.clone();
    let caller_upgrade = caller_upgrade.expect("checked above");
    tokio::spawn(async move {
        let started = Instant::now();
        let (to_machine, to_caller) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let reason = match (caller_upgrade.await, machine_upgrade.await) {
            (Ok(a), Ok(b)) => {
                let mut a = Counting {
                    io: TokioIo::new(a),
                    read: to_machine.clone(),
                };
                let mut b = Counting {
                    io: TokioIo::new(b),
                    read: to_caller.clone(),
                };
                tokio::select! {
                    _ = cut.cancelled() => cut.why(),
                    r = tokio::io::copy_bidirectional(&mut a, &mut b) => {
                        if r.is_ok() { "closed" } else { "error" }
                    }
                }
            }
            _ => "upgrade_failed",
        };
        drop(slot);
        relay2.session_ended(session);
        relay2.audit().event(
            "session_closed",
            [
                ("session", json!(session)),
                ("machine", json!(machine)),
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
    out
}

fn strip_hop(h: &mut HeaderMap) {
    for name in HOP {
        h.remove(HeaderName::from_static(name));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_caller_targets() {
        let u: Uri = "/m/C02X/actp/v1/agents/a/link?x=1".parse().unwrap();
        assert_eq!(
            split_target("C02X/actp/v1/agents/a/link", &u),
            Some(("C02X".into(), "/actp/v1/agents/a/link?x=1".into()))
        );
        let u: Uri = "/m/a%3Ab".parse().unwrap();
        assert_eq!(split_target("a%3Ab", &u), Some(("a:b".into(), "/".into())));
        let u: Uri = "/m/..".parse().unwrap();
        assert_eq!(split_target("..", &u), None);
        assert_eq!(split_target("a%2Fb/x", &u), None);
        assert_eq!(split_target("%2e%2e/x", &u), None);
        assert_eq!(split_target("", &u), None);
    }

    #[test]
    fn audits_routes_as_the_machine_sees_them() {
        assert_eq!(
            agent_of(&route_of("/actp/v1/agents/claude/link?q")),
            Some("claude".into())
        );
        assert_eq!(
            agent_of(&route_of("/actp/v1/%61gents/cl%61ude/link")),
            Some("claude".into())
        );
        assert_eq!(agent_of(&route_of("/api/v1/agents")), None);
        assert_eq!(route_of("/api/v1/info?token=x"), "/api/v1/info");
    }
}

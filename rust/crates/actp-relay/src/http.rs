//! The relay's HTTP surface.
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /health` | anyone | liveness |
//! | `GET /relay/v1/connect` | a machine (device certificate) | the control WebSocket |
//! | `GET /relay/v1/stream/<id>` | the machine asked for it | a caller's stream |
//! | `GET /relay/v1/tunnel/<address>` | a caller (caller certificate) | a byte tunnel to the machine, carrying the caller's TLS to it |
//! | `GET /relay/v1/issuer/<path>` | a machine (device certificate) | a configured question to the identity service ([`crate::issuer`]) |
//! | `GET /relay/v1/machines` | admin token, operator (`machines`) | who is online, last seen |
//! | `GET /relay/v1/audit` | admin token, operator (`audit`) | the relay's half of the audit, newest first ([`crate::audit::query`]) |
//! | `GET /relay/v1/stop` | admin token, any operator | the org-wide stop |
//! | `POST /relay/v1/stop`, `POST /relay/v1/release` | admin token, operator (`stop`, `release`) | press, release (`{"reason": …}`; an operator names the person in `X-Actp-On-Behalf-Of`) |
//! | `POST /relay/v1/rekey/challenge`, `POST /relay/v1/rekey` | a machine, on its pinned key | key continuity: a nonce, then the next certificate with the pinned key's signature ([`crate::Relay::rekey`]) |
//! | `POST /relay/v1/repin` | admin token | forget or set a machine's pinned key (`{"machine": …, "reason": …, "key"?: …}`) |
//!
//! An operator is a caller certificate the configuration gives a role
//! (`operators`); a request with an `Authorization` header is an admin's
//! and is judged by its token alone.
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
    Control, HEADER_ON_BEHALF_OF, OpenedBy, PATH_CONNECT, PATH_ISSUER, PATH_REKEY,
    PATH_REKEY_CHALLENGE, PATH_STREAM, PATH_TUNNEL, PROTOCOL_CONTROL, PROTOCOL_STREAM,
    PROTOCOL_TUNNEL, valid_machine_name, valid_on_behalf_of, valid_stream_id,
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

use crate::config::Permission;
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
    if path == PATH_REKEY_CHALLENGE || path == PATH_REKEY {
        return rekey(relay, peer, req, &path).await;
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
    let management_route = matches!(
        path.as_str(),
        "/relay/v1/machines"
            | "/relay/v1/audit"
            | "/relay/v1/stop"
            | "/relay/v1/release"
            | "/relay/v1/repin"
    );
    if management_route {
        return management(relay, peer, req, &path).await;
    }
    match path.strip_prefix(PATH_TUNNEL) {
        Some(machine) => tunnel(relay, peer, req, machine).await,
        None => error(StatusCode::NOT_FOUND, "not_found", "no such route"),
    }
}

// ---- machines ----

/// Key continuity: `POST /relay/v1/rekey/challenge` for a nonce, then
/// `POST /relay/v1/rekey` with the next certificate and the pinned key's
/// signature over it ([`Relay::rekey`]). Machines only, on the pinned key.
async fn rekey(relay: &Relay, peer: &Peer, req: Request<Incoming>, path: &str) -> Resp {
    let machine = match machine_of(relay, peer, "rekey") {
        Ok(m) => m,
        Err(r) => return *r,
    };
    if req.method() != Method::POST {
        let mut r = error(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "POST only",
        );
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return r;
    }
    if path == PATH_REKEY_CHALLENGE {
        return match relay.rekey_challenge(&machine) {
            Ok(nonce) => json_resp(
                StatusCode::OK,
                serde_json::to_string(&actp_proto::relay::RekeyChallenge { nonce })
                    .expect("encodes"),
            ),
            Err(why) => error(
                StatusCode::TOO_MANY_REQUESTS,
                why,
                "too many open challenges",
            ),
        };
    }
    let body = match Limited::new(req.into_body(), 64 << 10).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "the body is too large",
            );
        }
    };
    let Ok(ask) = serde_json::from_slice::<actp_proto::relay::RekeyRequest>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "not a continuity request",
        );
    };
    match relay.rekey(&machine, &peer.chain[0], ask) {
        Ok(new_key) => json_resp(
            StatusCode::OK,
            json!({ "machine": machine, "key": new_key }).to_string(),
        ),
        Err("rekey_not_saved") => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "rekey_not_saved",
            "the relay could not record the new key: the old one stays pinned, try again later",
        ),
        Err(why) => {
            relay.refusal(
                "machine_refused",
                [
                    ("machine", json!(machine)),
                    ("remote", json!(peer.remote.to_string())),
                    ("route", json!("rekey")),
                    ("reason", json!(why)),
                ],
            );
            error(
                StatusCode::FORBIDDEN,
                why,
                "the next certificate was not taken: see the reason",
            )
        }
    }
}

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
        Some(Ok(m)) => match relay.check_key(m, &peer.chain[0]) {
            Ok(()) => Ok(m.clone()),
            // Recorded by check_key, once a minute per machine.
            Err("key_changed") => Err(Box::new(error(
                StatusCode::FORBIDDEN,
                "machine_key_changed",
                "this machine's certificate has a key the relay has not seen for it: an admin must re-pin it",
            ))),
            Err(why) => {
                relay.refusal(
                    "machine_refused",
                    [
                        ("machine", json!(m)),
                        ("remote", json!(peer.remote.to_string())),
                        ("route", json!(route)),
                        ("reason", json!(why)),
                    ],
                );
                Err(Box::new(error(
                    StatusCode::FORBIDDEN,
                    "bad_device_certificate",
                    "the relay cannot read this device certificate's key",
                )))
            }
        },
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

/// `X-Actp-On-Behalf-Of`, when sent: whom a caller says it acts for.
fn on_behalf_of(req: &Request<Incoming>) -> Result<Option<String>, Box<Resp>> {
    let mut values = req.headers().get_all(HEADER_ON_BEHALF_OF).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => match std::str::from_utf8(v.as_bytes()) {
            Ok(v) if valid_on_behalf_of(v) => Ok(Some(v.to_string())),
            _ => Err(Box::new(error(
                StatusCode::BAD_REQUEST,
                "bad_on_behalf_of",
                "X-Actp-On-Behalf-Of must be 1 to 256 bytes of UTF-8, without control, invisible or direction-changing characters or surrounding space",
            ))),
        },
        (Some(_), Some(_)) => Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "bad_on_behalf_of",
            "X-Actp-On-Behalf-Of may be sent once",
        ))),
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
    // Whom the caller says it acts for: recorded and passed on, not checked.
    let on_behalf_of = match on_behalf_of(&req) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let resp = match ws_accept(&req, PROTOCOL_TUNNEL) {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let remote = peer.remote.to_string();
    let opened_by = OpenedBy {
        caller: caller.clone(),
        caller_certificate: crate::fingerprint(&peer.chain[0]),
        on_behalf_of: on_behalf_of.clone(),
    };
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
        opened = relay.open_stream(&machine, opened_by.clone()) => match opened {
            Ok(s) => s,
            Err(r) => return refuse(r),
        },
        _ = cut.cancelled() => return refuse(Refusal::Cut(cut.why())),
    };
    if cut.is_cut() {
        return refuse(Refusal::Cut(cut.why()));
    }
    match &on_behalf_of {
        Some(who) => relay.audit().event(
            "session_open",
            [
                ("session", json!(session)),
                ("machine", json!(machine)),
                ("caller", json!(caller)),
                ("caller_certificate", json!(opened_by.caller_certificate)),
                ("on_behalf_of", json!(who)),
                ("remote", json!(remote)),
            ],
        ),
        None => relay.audit().event(
            "session_open",
            [
                ("session", json!(session)),
                ("machine", json!(machine)),
                ("caller", json!(caller)),
                ("caller_certificate", json!(opened_by.caller_certificate)),
                ("remote", json!(remote)),
            ],
        ),
    }
    let opened_at = crate::audit::rfc3339(std::time::SystemTime::now());
    let on_upgrade = hyper::upgrade::on(&mut req);
    let relay = relay.clone();
    let held = peer.held.clone();
    tokio::spawn(async move {
        let _held = held;
        let _ended = ended;
        let started = Instant::now();
        let (to_machine, to_caller) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let idle_after = relay
            .timing()
            .tunnel_idle
            .unwrap_or(Duration::from_secs(relay.config().tunnel_idle_seconds));
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
                    _ = idle(&to_machine, &to_caller, idle_after) => "idle",
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
                ("on_behalf_of", json!(on_behalf_of)),
                ("opened_at", json!(opened_at)),
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

/// Returns once neither counter has moved for `limit`.
async fn idle(a: &AtomicU64, b: &AtomicU64, limit: Duration) {
    let tick = (limit / 10).clamp(Duration::from_millis(100), Duration::from_secs(10));
    let total = || a.load(Ordering::Relaxed) + b.load(Ordering::Relaxed);
    let (mut last, mut since) = (total(), Instant::now());
    loop {
        tokio::time::sleep(tick).await;
        let now = total();
        if now != last {
            (last, since) = (now, Instant::now());
        } else if since.elapsed() >= limit {
            return;
        }
    }
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

// ---- management ----

/// Who is asking the management API.
enum Who {
    /// An admin token, by its name.
    Admin(String),
    /// An operator, by its caller certificate.
    Operator {
        caller: String,
        certificate: String,
        may: Vec<Permission>,
    },
}

/// What a management route needs of an operator.
enum Need {
    /// One permission.
    One(Permission),
    /// Any operator.
    Any,
    /// Only an admin token.
    Admin,
}

/// Who is asking: an admin token when an `Authorization` header is sent
/// (and nothing else is then considered), otherwise an operator's caller
/// certificate. Everyone else, a machine included, is refused.
fn who(relay: &Relay, peer: &Peer, req: &Request<Incoming>, path: &str) -> Result<Who, Box<Resp>> {
    let unauthorized = |message: &str| {
        relay.refusal(
            "admin_refused",
            [
                ("remote", json!(peer.remote.to_string())),
                ("route", json!(path)),
            ],
        );
        let mut r = error(StatusCode::UNAUTHORIZED, "unauthorized", message);
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"actp-relay\""),
        );
        Box::new(r)
    };
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        let presented = v
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or("");
        return match relay.admin(presented) {
            Some(name) => Ok(Who::Admin(name)),
            None => Err(unauthorized("missing or invalid admin token")),
        };
    }
    if peer.caller.is_none() {
        return Err(unauthorized(
            "an admin token or an operator's caller certificate is required",
        ));
    }
    // The certificate is checked as for a tunnel: valid now, not blocked.
    let caller = caller_of(relay, peer)?;
    let may = relay.config().operator(&caller).to_vec();
    if may.is_empty() {
        return Err(operator_refused(
            relay,
            peer,
            path,
            &caller,
            "not_an_operator",
            "this caller has no role at the relay",
        ));
    }
    Ok(Who::Operator {
        caller,
        certificate: crate::fingerprint(&peer.chain[0]),
        may,
    })
}

fn operator_refused(
    relay: &Relay,
    peer: &Peer,
    path: &str,
    caller: &str,
    code: &str,
    message: &str,
) -> Box<Resp> {
    relay.refusal(
        "operator_refused",
        [
            ("caller", json!(caller)),
            ("remote", json!(peer.remote.to_string())),
            ("route", json!(path)),
            ("reason", json!(code)),
        ],
    );
    Box::new(error(StatusCode::FORBIDDEN, code, message))
}

/// The query string's `name=value` pairs, percent-decoded (`+` is a plus).
fn query_pairs(req: &Request<Incoming>) -> Result<Vec<(String, String)>, Box<Resp>> {
    let bad = |m: &str| Box::new(error(StatusCode::BAD_REQUEST, "bad_query", m));
    let q = req.uri().query().unwrap_or("");
    if q.len() > 16 << 10 {
        return Err(bad("the query is too long"));
    }
    let mut out = Vec::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let dec = |x: &str| {
            percent_encoding::percent_decode_str(x)
                .decode_utf8()
                .map(|c| c.into_owned())
                .map_err(|_| bad("the query is not UTF-8"))
        };
        out.push((dec(k)?, dec(v)?));
    }
    Ok(out)
}

async fn management(relay: &Relay, peer: &Peer, req: Request<Incoming>, path: &str) -> Resp {
    let who = match who(relay, peer, &req, path) {
        Ok(w) => w,
        Err(r) => return *r,
    };
    let method = req.method().clone();
    let need = match (&method, path) {
        (&Method::GET, "/relay/v1/machines") => Need::One(Permission::Machines),
        (&Method::GET, "/relay/v1/audit") => Need::One(Permission::Audit),
        (&Method::GET, "/relay/v1/stop") => Need::Any,
        (&Method::POST, "/relay/v1/stop") => Need::One(Permission::Stop),
        (&Method::POST, "/relay/v1/release") => Need::One(Permission::Release),
        (&Method::POST, "/relay/v1/repin") => Need::Admin,
        _ => {
            let mut r = error(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
            );
            let allow = match path {
                "/relay/v1/machines" | "/relay/v1/audit" => "GET",
                "/relay/v1/stop" => "GET, POST",
                _ => "POST", // release, repin
            };
            r.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static(allow));
            return r;
        }
    };
    if let Who::Operator { caller, may, .. } = &who {
        let ok = match need {
            Need::One(p) => may.contains(&p),
            Need::Any => true,
            Need::Admin => false,
        };
        if !ok {
            return *operator_refused(
                relay,
                peer,
                path,
                caller,
                "operator_not_permitted",
                "this operator may not do that here",
            );
        }
    }
    let obo = match on_behalf_of(&req) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match (method, path) {
        (Method::GET, "/relay/v1/machines") => machines(relay, &req),
        (Method::GET, "/relay/v1/audit") => audit(relay, &req).await,
        (Method::GET, "/relay/v1/stop") => json_resp(
            StatusCode::OK,
            json!({ "stop": relay.stop_state() }).to_string(),
        ),
        (Method::POST, "/relay/v1/repin") => {
            let Who::Admin(by) = who else {
                unreachable!("repin is for admins only, checked above")
            };
            repin(relay, req, &by).await
        }
        (Method::POST, _) => {
            let actor = match who {
                Who::Admin(name) => crate::Actor {
                    on_behalf_of: obo,
                    ..crate::Actor::admin(&name)
                },
                Who::Operator {
                    caller,
                    certificate,
                    ..
                } => {
                    // A caller certificate names a program (the IT app),
                    // not a person: who pressed it must be said.
                    let Some(person) = obo else {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "on_behalf_of_required",
                            "say whom you press or release the stop for: X-Actp-On-Behalf-Of",
                        );
                    };
                    crate::Actor {
                        name: caller,
                        kind: crate::ActorKind::Operator,
                        certificate: Some(certificate),
                        on_behalf_of: Some(person),
                    }
                }
            };
            stop_or_release(relay, req, path, &actor).await
        }
        _ => unreachable!("every other method was answered above"),
    }
}

/// `GET /relay/v1/machines[?machine=…][&online=true|false]`.
fn machines(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let pairs = match query_pairs(req) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let mut names = std::collections::HashSet::new();
    let mut online = None;
    for (k, v) in pairs {
        match (k.as_str(), v.as_str()) {
            ("machine", m) if valid_machine_name(m) && names.len() < 1000 => {
                names.insert(m.to_string());
            }
            ("online", "true") => online = Some(true),
            ("online", "false") => online = Some(false),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "bad_query",
                    "the query takes machine=<address> (up to 1000) and online=true|false",
                );
            }
        }
    }
    json_resp(
        StatusCode::OK,
        relay
            .machines_json(|m| {
                (names.is_empty() || names.contains(&m.machine))
                    && online.is_none_or(|o| o == m.online)
            })
            .to_string(),
    )
}

/// `GET /relay/v1/audit?kind=…&machine=…&caller=…&on_behalf_of=…&since=…&before=…&limit=…`.
async fn audit(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let pairs = match query_pairs(req) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let bad = |m: &str| error(StatusCode::BAD_REQUEST, "bad_query", m);
    let mut q = crate::audit::Query {
        limit: 100,
        ..Default::default()
    };
    let mut seen = std::collections::HashSet::new();
    for (k, v) in pairs {
        if k != "kind" && !seen.insert(k.clone()) {
            return bad(&format!("{k} may be given once"));
        }
        match k.as_str() {
            "kind" => {
                for part in v.split(',') {
                    match crate::audit::Kind::parse(part) {
                        Some(kind) if !q.kinds.contains(&kind) => q.kinds.push(kind),
                        Some(_) => {}
                        None => return bad("kind is sessions, stops or machines"),
                    }
                }
            }
            "machine" if valid_machine_name(&v) => q.machine = Some(v),
            "caller" if valid_machine_name(&v) => q.caller = Some(v),
            "on_behalf_of" if valid_on_behalf_of(&v) => q.on_behalf_of = Some(v),
            "since" | "before" => match crate::audit::parse_rfc3339(&v) {
                Some(t) if k == "since" => q.since = Some(t),
                Some(t) => q.before = Some(t),
                None => return bad(&format!("{k} is an RFC 3339 time in UTC")),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) if (1..=1000).contains(&n) => q.limit = n,
                _ => return bad("limit is 1 to 1000"),
            },
            "machine" | "caller" | "on_behalf_of" => {
                return bad(&format!("{k} is not a valid name"));
            }
            _ => {
                return bad(
                    "the query takes kind, machine, caller, on_behalf_of, since, before and limit",
                );
            }
        }
    }
    match relay.audit_page(q).await {
        None => {
            let mut r = error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_busy",
                "other audit queries are running; try again shortly",
            );
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            r
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "could not read the audit log");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_unreadable",
                "the audit log could not be read",
            )
        }
        Some(Ok(p)) => json_resp(
            StatusCode::OK,
            json!({ "events": p.events, "more": p.more, "next_before": p.next_before }).to_string(),
        ),
    }
}

async fn repin(relay: &Relay, req: Request<Incoming>, by: &str) -> Resp {
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
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let (machine, reason) = (field("machine"), field("reason"));
    if !valid_machine_name(&machine) || reason.is_empty() || reason.len() > 1000 {
        return error(
            StatusCode::BAD_REQUEST,
            "machine_and_reason_required",
            "say which machine and why: {\"machine\": \"…\", \"reason\": \"…\"}",
        );
    }
    // Optionally the new key itself, so nothing else can be pinned
    // first: the SHA-256 of its public key, as lowercase hex.
    let key = match v.get("key") {
        None | Some(serde_json::Value::Null) => None,
        Some(k) => match k.as_str() {
            Some(k)
                if k.len() == 64 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                Some(k.to_string())
            }
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "bad_key",
                    "key is the SHA-256 of the certificate's public key, 64 lowercase hex characters",
                );
            }
        },
    };
    let was = relay.repin(by, &machine, key.as_deref(), &reason);
    json_resp(
        StatusCode::OK,
        json!({ "machine": machine, "was_pinned": was }).to_string(),
    )
}

async fn stop_or_release(
    relay: &Relay,
    req: Request<Incoming>,
    path: &str,
    who: &crate::Actor,
) -> Resp {
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
        let s = relay.stop_as(who, &reason);
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
        match relay.release_as(who, &reason) {
            Ok(s) => json_resp(StatusCode::OK, json!({ "stop": s }).to_string()),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, "not_released", &e),
        }
    }
}

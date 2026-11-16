//! The HTTP and WebSocket transport of the server (api/openapi.yaml).
//!
//! Requests reach the server core from any byte stream: [`serve`] takes an
//! [`Acceptor`] (a TCP listener, TLS on top of one, or later a relay that
//! hands over streams multiplexed on an outbound connection), and
//! [`serve_connection`] serves one stream. Routing, status codes and bodies
//! follow the Go server, including Go's `ServeMux` answers for unknown paths.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use actp_proto::conn::websocket_config;
use actp_proto::frame::{
    HEADER_CLIENT_NAME, HEADER_LAST_SEQ, HEADER_LINK_ID, HEADER_PROMPT_TIMEOUT, VERSIONS,
};
use actp_proto::{FrameConn, api};
use base64::Engine;
use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming as Body;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_util::sync::CancellationToken;

use crate::server::{LinkRequest, Rejection, Server};

type Resp = Response<Full<Bytes>>;

/// A byte stream that carries HTTP/1.1 to the server.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A stream being set up (for example a TLS handshake), run off the accept loop.
pub type Connecting = Pin<Box<dyn Future<Output = io::Result<Box<dyn Io>>> + Send>>;

/// Where connections come from. Listening on TCP is one implementation; a
/// relay client that dials out and receives streams is another.
pub trait Acceptor: Send + 'static {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connecting>> + Send + '_>>;
}

/// Plain TCP.
pub struct TcpAcceptor(pub TcpListener);

impl Acceptor for TcpAcceptor {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connecting>> + Send + '_>> {
        Box::pin(async move {
            let (tcp, _) = self.0.accept().await?;
            let _ = tcp.set_nodelay(true);
            Ok(Box::pin(async move { Ok(Box::new(tcp) as Box<dyn Io>) }) as Connecting)
        })
    }
}

/// TLS on top of TCP, with any rustls server configuration.
pub struct TlsAcceptor {
    pub tcp: TcpListener,
    pub tls: tokio_rustls::TlsAcceptor,
}

impl Acceptor for TlsAcceptor {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connecting>> + Send + '_>> {
        Box::pin(async move {
            let (tcp, _) = self.tcp.accept().await?;
            let _ = tcp.set_nodelay(true);
            let tls = self.tls.clone();
            Ok(Box::pin(async move {
                let s = tokio::time::timeout(Duration::from_secs(10), tls.accept(tcp))
                    .await
                    .map_err(|_| io::Error::other("TLS handshake timed out"))??;
                Ok(Box::new(s) as Box<dyn Io>)
            }) as Connecting)
        })
    }
}

/// A rustls server configuration from PEM files (`tls_cert`, `tls_key`).
pub fn tls_config_from_pem(cert: &str, key: &str) -> io::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(io::Error::other)?
        .collect::<Result<_, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(io::Error::other)?;
    Ok(Arc::new(cfg))
}

/// Serves connections from `acceptor` until `shutdown` is cancelled.
pub async fn serve(
    server: Server,
    mut acceptor: impl Acceptor,
    shutdown: CancellationToken,
) -> io::Result<()> {
    loop {
        let connecting = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            c = acceptor.accept() => c,
        };
        match connecting {
            Ok(c) => {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Ok(io) = c.await {
                        serve_connection(server, io).await;
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serves HTTP/1.1, including link upgrades, on one byte stream.
pub async fn serve_connection(
    server: Server,
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) {
    let svc = hyper::service::service_fn(move |req| {
        let server = server.clone();
        async move { Ok::<_, Infallible>(handle(&server, req).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades();
    let _ = conn.await;
}

fn json(status: StatusCode, body: String) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

fn error(status: StatusCode, code: &str, message: &str) -> Resp {
    json(status, api::error_body(code, message))
}

/// Go's `http.Error`: plain text with a newline.
fn plain(status: StatusCode, body: &str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(format!("{body}\n"))));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// Go's `path.Clean` on a URL path, keeping a trailing slash like `ServeMux`.
fn clean_url_path(p: &str) -> String {
    let p = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = format!("/{}", parts.join("/"));
    if p.ends_with('/') && out != "/" {
        out.push('/');
    }
    out
}

enum Route {
    Health,
    Info,
    Agents,
    Link(String),
}

fn route(segments: &[String]) -> Option<Route> {
    let s: Vec<&str> = segments.iter().map(String::as_str).collect();
    match s.as_slice() {
        ["health"] => Some(Route::Health),
        ["api", "v1", "info"] => Some(Route::Info),
        ["api", "v1", "agents"] => Some(Route::Agents),
        ["actp", "v1", "agents", id, "link"] if !id.is_empty() => Some(Route::Link(id.to_string())),
        _ => None,
    }
}

/// Handles one request: auth (everything but `/health`), routing, handlers.
pub async fn handle(server: &Server, mut req: Request<Body>) -> Resp {
    let raw_path = req.uri().path().to_string();
    let decoded = percent_encoding::percent_decode_str(&raw_path)
        .decode_utf8_lossy()
        .into_owned();

    // No exception for local connections: a tunnel makes remote traffic look local.
    let token = if decoded == "/health" {
        None
    } else {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match presented.and_then(|p| server.authenticate(p.trim())) {
            Some(t) => Some(t),
            None => {
                let mut r = error(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "missing or invalid token",
                );
                r.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"actp\""),
                );
                return r;
            }
        }
    };

    let clean = clean_url_path(&decoded);
    if clean != decoded && req.method() != Method::CONNECT {
        let mut loc = clean.clone();
        if let Some(q) = req.uri().query() {
            loc = format!("{loc}?{q}");
        }
        let mut r = Response::new(Full::new(Bytes::new()));
        *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
        if let Ok(v) = HeaderValue::from_str(&loc) {
            r.headers_mut().insert(header::LOCATION, v);
        }
        return r;
    }
    let segments: Vec<String> = raw_path
        .trim_start_matches('/')
        .split('/')
        .map(|s| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned()
        })
        .collect();
    let Some(route) = route(&segments) else {
        return plain(StatusCode::NOT_FOUND, "404 page not found");
    };
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let mut r = plain(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }
    match route {
        Route::Health => json(StatusCode::OK, api::health()),
        Route::Info => json(StatusCode::OK, server.info_body()),
        Route::Agents => json(
            StatusCode::OK,
            server.agents_body(token.as_ref().expect("authenticated")),
        ),
        Route::Link(agent_id) => {
            open_link(server, token.expect("authenticated"), agent_id, &mut req).await
        }
    }
}

/// One header value for an optional parameter, like the generated Go wrapper:
/// more than one is a 400.
fn single_header(h: &HeaderMap, name: &str) -> Result<Option<String>, Box<Resp>> {
    let values: Vec<_> = h.get_all(name).iter().collect();
    match values.len() {
        0 => Ok(None),
        1 => Ok(Some(
            String::from_utf8_lossy(values[0].as_bytes()).into_owned(),
        )),
        n => Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &format!("Expected one value for {name}, got {n}"),
        ))),
    }
}

fn rejection(r: Rejection) -> Resp {
    let mut resp = error(
        StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        r.code,
        &r.message,
    );
    if let Some(s) = r.retry_after {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(s));
    }
    resp
}

fn has_token(h: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
    h.get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

async fn open_link(
    server: &Server,
    tok: crate::config::Token,
    agent_id: String,
    req: &mut Request<Body>,
) -> Resp {
    let h = req.headers().clone();
    let protocols = match single_header(&h, "Sec-WebSocket-Protocol") {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let client_name = match single_header(&h, HEADER_CLIENT_NAME) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let link_id = match single_header(&h, HEADER_LINK_ID) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let last_seq = match single_header(&h, HEADER_LAST_SEQ) {
        Ok(None) => None,
        Ok(Some(v)) => match v.parse::<i64>() {
            Ok(n) => Some(n),
            Err(_) => {
                let msg = format!(
                    "Invalid format for parameter Actp-Last-Seq: error binding string parameter: strconv.ParseInt: parsing \"{v}\": invalid syntax"
                );
                return error(StatusCode::BAD_REQUEST, "bad_request", &msg);
            }
        },
        Err(r) => return *r,
    };
    if let Err(r) = server.check_agent(&tok, &agent_id) {
        return rejection(r);
    }
    let upgrade = h
        .get(header::UPGRADE)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return error(
            StatusCode::UPGRADE_REQUIRED,
            "upgrade_required",
            "the link endpoint needs a WebSocket upgrade",
        );
    }
    let offered: Vec<String> = protocols
        .iter()
        .flat_map(|p| p.split(','))
        .map(|v| v.trim().to_string())
        .collect();
    if !offered.iter().any(|v| VERSIONS.contains(&v.as_str())) {
        return error(
            StatusCode::UPGRADE_REQUIRED,
            "no_common_version",
            &format!("supported wire versions: {}", VERSIONS.join(", ")),
        );
    }

    let lreq = LinkRequest {
        agent_id,
        client_name,
        link_id,
        last_seq,
    };
    let pending = match server.open_link(&tok, &lreq).await {
        Ok(p) => p,
        Err(r) => return rejection(r),
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(pending.link_id()) {
        headers.insert(HEADER_LINK_ID, v);
    }
    headers.insert(HEADER_LAST_SEQ, HeaderValue::from(pending.last_received()));
    headers.insert(
        HEADER_PROMPT_TIMEOUT,
        HeaderValue::from(server.config().prompt_timeout.as_secs()),
    );

    // The WebSocket handshake checks, in the order coder/websocket makes them.
    let fail = |status: StatusCode, msg: String, extra: &[(&'static str, &'static str)]| {
        let mut r = plain(status, &msg);
        for (k, v) in headers.iter() {
            r.headers_mut().insert(k.clone(), v.clone());
        }
        for (k, v) in extra {
            r.headers_mut().insert(*k, HeaderValue::from_static(v));
        }
        r
    };
    let failure = if !has_token(&h, header::CONNECTION, "upgrade") {
        let got = h
            .get(header::CONNECTION)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default();
        Some(fail(
            StatusCode::UPGRADE_REQUIRED,
            format!(
                "WebSocket protocol violation: Connection header \"{got}\" does not contain Upgrade"
            ),
            &[("connection", "Upgrade"), ("upgrade", "websocket")],
        ))
    } else if req.method() != Method::GET {
        Some(fail(
            StatusCode::METHOD_NOT_ALLOWED,
            format!(
                "WebSocket protocol violation: handshake request method is not GET but \"{}\"",
                req.method()
            ),
            &[],
        ))
    } else if h.get(header::SEC_WEBSOCKET_VERSION).map(|v| v.as_bytes()) != Some(b"13") {
        let got = h
            .get(header::SEC_WEBSOCKET_VERSION)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default();
        Some(fail(
            StatusCode::BAD_REQUEST,
            format!("unsupported WebSocket protocol version (only 13 is supported): \"{got}\""),
            &[("sec-websocket-version", "13")],
        ))
    } else {
        let keys: Vec<_> = h.get_all(header::SEC_WEBSOCKET_KEY).iter().collect();
        let key = keys
            .first()
            .map(|k| String::from_utf8_lossy(k.as_bytes()).trim().to_string())
            .unwrap_or_default();
        if keys.is_empty() {
            Some(fail(
                StatusCode::BAD_REQUEST,
                "WebSocket protocol violation: missing Sec-WebSocket-Key".into(),
                &[],
            ))
        } else if keys.len() > 1 {
            Some(fail(
                StatusCode::BAD_REQUEST,
                "WebSocket protocol violation: multiple Sec-WebSocket-Key headers".into(),
                &[],
            ))
        } else if base64::engine::general_purpose::STANDARD
            .decode(&key)
            .map(|v| v.len())
            != Ok(16)
        {
            Some(fail(
                StatusCode::BAD_REQUEST,
                format!(
                    "WebSocket protocol violation: invalid Sec-WebSocket-Key \"{key}\", must be a 16 byte base64 encoded string"
                ),
                &[],
            ))
        } else {
            None
        }
    };
    if let Some(r) = failure {
        pending.abandon().await;
        return r;
    }

    let key = h
        .get(header::SEC_WEBSOCKET_KEY)
        .map(|k| String::from_utf8_lossy(k.as_bytes()).trim().to_string())
        .unwrap_or_default();
    let selected = VERSIONS
        .iter()
        .find_map(|sp| offered.iter().find(|cp| cp.eq_ignore_ascii_case(sp)))
        .cloned();
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *resp.headers_mut() = headers;
    resp.headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    if let Ok(v) = HeaderValue::from_str(&derive_accept_key(key.as_bytes())) {
        resp.headers_mut().insert(header::SEC_WEBSOCKET_ACCEPT, v);
    }
    if let Some(p) = selected.and_then(|p| HeaderValue::from_str(&p).ok()) {
        resp.headers_mut().insert(header::SEC_WEBSOCKET_PROTOCOL, p);
    }
    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(up) => {
                let ws = WebSocketStream::from_raw_socket(
                    TokioIo::new(up),
                    Role::Server,
                    Some(websocket_config()),
                )
                .await;
                pending.serve(FrameConn::from_websocket(ws)).await;
            }
            Err(_) => pending.abandon().await,
        }
    });
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_paths_like_servemux() {
        for (a, b) in [
            ("/health", "/health"),
            ("//health", "/health"),
            ("/api/v1/../v1/info", "/api/v1/info"),
            ("/a/", "/a/"),
            ("/", "/"),
            ("", "/"),
        ] {
            assert_eq!(clean_url_path(a), b, "{a}");
        }
    }
}

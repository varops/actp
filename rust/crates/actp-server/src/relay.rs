//! Relay mode (docs/relay.md): the machine dials out to one relay instead of
//! listening, and serves the callers the relay routes to it.
//!
//! [`RelayAcceptor`] keeps a control WebSocket open to the relay, with the
//! machine's device certificate, and reconnects with backoff when it drops.
//! For every caller the relay announces, it dials a data WebSocket, answers
//! the caller's end-to-end TLS on it with the device certificate
//! ([`actp_proto::e2e`]), and hands the result to [`crate::http::serve`] as
//! one more connection, so everything past the transport (authentication,
//! links, confinement) is the same as when the server listens. The relay
//! carries the caller's TLS and cannot read it. The relay's org-wide stop reaches
//! [`Server::set_org_stopped`].

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use actp_proto::relay::{
    Control, PATH_CONNECT, PATH_STREAM, PROTOCOL_CONTROL, PROTOCOL_STREAM, valid_stream_id,
};
use actp_proto::wsio::WsIo;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::http::{Acceptor, Connecting, Io};
use crate::server::Server;

/// How to reach the relay.
#[derive(Clone)]
pub struct RelayOptions {
    /// `wss://host[:port]`.
    pub url: String,
    /// TLS with the device certificate as the client certificate.
    pub tls: Arc<rustls::ClientConfig>,
    /// The end-to-end TLS callers open inside each relayed stream: the
    /// device certificate again, as the server ([`stream_tls`]).
    pub e2e: Arc<rustls::ServerConfig>,
    /// Longest wait between reconnects (30 s).
    pub max_backoff: Duration,
    /// How often the machine pings the relay (20 s).
    pub ping_every: Duration,
    /// The control connection is dead after this long without a message (60 s).
    pub dead_after: Duration,
    /// Callers served at once through the relay (64). Further streams the
    /// relay asks for are not dialed.
    pub max_streams: usize,
    /// How long dialing one data stream may take (10 s).
    pub dial_timeout: Duration,
}

impl RelayOptions {
    pub fn new(
        url: impl Into<String>,
        tls: Arc<rustls::ClientConfig>,
        e2e: Arc<rustls::ServerConfig>,
    ) -> Self {
        RelayOptions {
            url: url.into(),
            tls,
            e2e,
            max_backoff: Duration::from_secs(30),
            ping_every: Duration::from_secs(20),
            dead_after: Duration::from_secs(60),
            max_streams: 64,
            dial_timeout: Duration::from_secs(10),
        }
    }
}

/// The state of the control connection, for a status display and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Connecting,
    /// Connected; the relay knows this machine by `machine`.
    Connected {
        machine: String,
    },
    /// Not connected; the last error.
    Disconnected {
        error: String,
    },
}

/// Connections from the relay, for [`crate::http::serve`].
pub struct RelayAcceptor {
    rx: mpsc::Receiver<Connecting>,
    status: watch::Receiver<Status>,
}

impl RelayAcceptor {
    /// Starts the control connection. It runs until `shutdown` is cancelled.
    pub fn start(server: Server, opts: RelayOptions, shutdown: CancellationToken) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let (status_tx, status) = watch::channel(Status::Connecting);
        tokio::spawn(control_loop(server, opts, tx, status_tx, shutdown));
        RelayAcceptor { rx, status }
    }

    /// Follows the state of the control connection.
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
}

impl Acceptor for RelayAcceptor {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connecting>> + Send + '_>> {
        Box::pin(async move {
            match self.rx.recv().await {
                Some(c) => Ok(c),
                // The control loop ended (shutdown): no more connections.
                None => std::future::pending().await,
            }
        })
    }
}

/// TLS for the relay from the config: the device certificate as the client
/// certificate, and the configured roots (or the OS store) for the relay.
pub fn client_tls(relay: &config::Relay) -> io::Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let (certs, key) = device_chain(relay)?;
    let mut roots = rustls::RootCertStore::empty();
    if relay.ca.is_empty() {
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
    } else {
        for c in CertificateDer::pem_file_iter(&relay.ca)
            .map_err(|e| io::Error::other(format!("relay ca {}: {e}", relay.ca)))?
        {
            let c = c.map_err(|e| io::Error::other(format!("relay ca {}: {e}", relay.ca)))?;
            roots.add(c).map_err(io::Error::other)?;
        }
    }
    // TLS 1.3 only, as at the relay: the device certificate is not sent in
    // the clear.
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)
    .map_err(io::Error::other)?;
    Ok(Arc::new(cfg))
}

fn device_chain(
    relay: &config::Relay,
) -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&relay.cert)
        .map_err(|e| io::Error::other(format!("relay cert {}: {e}", relay.cert)))?
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::other(format!("relay cert {}: {e}", relay.cert)))?;
    if certs.is_empty() {
        return Err(io::Error::other(format!(
            "relay cert {}: no certificate in the file",
            relay.cert
        )));
    }
    let key = PrivateKeyDer::from_pem_file(&relay.key)
        .map_err(|e| io::Error::other(format!("relay key {}: {e}", relay.key)))?;
    Ok((certs, key))
}

/// The end-to-end TLS the machine answers callers with, inside relayed
/// streams: its device certificate as the server certificate.
pub fn stream_tls(relay: &config::Relay) -> io::Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = device_chain(relay)?;
    actp_proto::e2e::server_config(certs, key).map_err(io::Error::other)
}

fn join_url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

async fn dial(
    opts: &RelayOptions,
    path: &str,
    protocol: &str,
    max_message: usize,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    let url = join_url(&opts.url, path);
    if !url.starts_with("wss://") {
        return Err("the relay url must start with wss://".into());
    }
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|e| e.to_string())?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str(protocol).map_err(|e| e.to_string())?,
    );
    let cfg = WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        req,
        Some(cfg),
        true,
        Some(Connector::Rustls(opts.tls.clone())),
    );
    match tokio::time::timeout(opts.dial_timeout, connect).await {
        Err(_) => Err("timed out".into()),
        Ok(Err(tungstenite::Error::Http(resp))) => Err(format!("HTTP {}", resp.status())),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok((ws, resp))) => {
            let chosen = resp
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok());
            if chosen != Some(protocol) {
                return Err(format!("the relay did not accept protocol {protocol}"));
            }
            Ok(ws)
        }
    }
}

async fn control_loop(
    server: Server,
    opts: RelayOptions,
    tx: mpsc::Sender<Connecting>,
    status: watch::Sender<Status>,
    shutdown: CancellationToken,
) {
    let streams = Arc::new(Semaphore::new(opts.max_streams));
    let mut backoff = Duration::from_secs(1);
    loop {
        let _ = status.send(Status::Connecting);
        let started = Instant::now();
        let dialed = tokio::select! {
            _ = shutdown.cancelled() => return,
            d = dial(&opts, PATH_CONNECT, PROTOCOL_CONTROL, 64 << 10) => d,
        };
        let error = match dialed {
            Ok(ws) => {
                tracing::info!(relay = %opts.url, "connected to the relay");
                let e = run_control(&server, &opts, ws, &tx, &status, &streams, &shutdown).await;
                if shutdown.is_cancelled() {
                    return;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    backoff = Duration::from_secs(1);
                }
                e
            }
            Err(e) => e,
        };
        tracing::warn!(relay = %opts.url, error = %error, retry_in = ?backoff, "relay connection down");
        let _ = status.send(Status::Disconnected { error });
        let wait = jitter(backoff);
        backoff = (backoff * 2).min(opts.max_backoff);
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// `d` give or take a fifth, so a fleet does not reconnect in step.
fn jitter(d: Duration) -> Duration {
    use rand::Rng;
    let f: f64 = rand::rng().random_range(0.8..1.2);
    d.mul_f64(f)
}

/// Serves one control connection; returns why it ended.
async fn run_control(
    server: &Server,
    opts: &RelayOptions,
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    tx: &mpsc::Sender<Connecting>,
    status: &watch::Sender<Status>,
    streams: &Arc<Semaphore>,
    shutdown: &CancellationToken,
) -> String {
    let (mut sink, mut stream) = ws.split();
    let mut last_heard = Instant::now();
    let mut next_ping = Instant::now() + opts.ping_every;
    let mut hello = false;
    loop {
        let deadline = (last_heard + opts.dead_after).min(next_ping);
        let msg = tokio::select! {
            _ = shutdown.cancelled() => {
                let _ = sink.send(Message::Close(None)).await;
                return "shutting down".into();
            }
            _ = tokio::time::sleep_until(deadline) => {
                if last_heard.elapsed() >= opts.dead_after {
                    return "the relay stopped answering".into();
                }
                if let Err(e) = sink.send(Message::Ping(Default::default())).await {
                    return e.to_string();
                }
                next_ping = Instant::now() + opts.ping_every;
                continue;
            }
            m = stream.next() => m,
        };
        let text = match msg {
            None => return "the relay closed the connection".into(),
            Some(Err(e)) => return e.to_string(),
            Some(Ok(m)) => {
                last_heard = Instant::now();
                match m {
                    Message::Text(t) => t,
                    Message::Close(_) => return "the relay closed the connection".into(),
                    _ => continue,
                }
            }
        };
        let Some(control) = Control::decode(text.as_str()) else {
            tracing::debug!("ignoring an unknown relay message");
            continue;
        };
        match control {
            Control::Hello { machine, stopped } => {
                if !actp_proto::relay::valid_machine_name(&machine) {
                    return "the relay sent a malformed machine address".into();
                }
                hello = true;
                tracing::info!(machine = %machine, stopped, "the relay knows this machine");
                server.set_relay_machine(&machine);
                if let Some(org) = &server.config().org {
                    if org.machine != machine {
                        tracing::error!(relay_says = %machine, configured = %org.machine, "the relay knows this machine by another address than org machine: all papers are refused until they agree");
                    }
                }
                server.set_org_stopped(stopped).await;
                let _ = status.send(Status::Connected { machine });
            }
            _ if !hello => return "the relay did not say hello first".into(),
            Control::Stop => {
                server.set_org_stopped(true).await;
            }
            Control::Release => {
                server.set_org_stopped(false).await;
            }
            Control::Open { stream: id } => {
                if !valid_stream_id(&id) {
                    tracing::warn!("the relay sent a malformed stream id");
                    continue;
                }
                let Ok(permit) = streams.clone().try_acquire_owned() else {
                    tracing::warn!("too many relayed callers at once; not opening another");
                    continue;
                };
                let opts = opts.clone();
                let connecting: Connecting = Box::pin(async move {
                    let path = format!("{PATH_STREAM}{id}");
                    let ws = dial(&opts, &path, PROTOCOL_STREAM, 1 << 20)
                        .await
                        .map_err(|e| {
                            tracing::warn!(error = %e, "could not open a relayed stream");
                            io::Error::other(e)
                        })?;
                    // The caller's TLS, end to end: nothing but a caller
                    // that completes it (and so checked this machine's
                    // certificate) reaches the server.
                    let accept =
                        tokio_rustls::TlsAcceptor::from(opts.e2e.clone()).accept(WsIo::new(ws));
                    let tls = match tokio::time::timeout(opts.dial_timeout, accept).await {
                        Ok(Ok(tls))
                            if tls.get_ref().1.alpn_protocol() == Some(actp_proto::e2e::ALPN) =>
                        {
                            tls
                        }
                        Ok(Ok(_)) => {
                            tracing::warn!("a relayed caller did not ask for the actp protocol");
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "the caller did not ask for the actp protocol",
                            ));
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "a relayed caller's TLS failed");
                            return Err(e);
                        }
                        Err(_) => {
                            tracing::warn!("a relayed caller's TLS did not complete in time");
                            return Err(io::Error::from(io::ErrorKind::TimedOut));
                        }
                    };
                    Ok(Box::new(Held {
                        io: tls,
                        _permit: permit,
                    }) as Box<dyn Io>)
                });
                if tx.try_send(connecting).is_err() {
                    tracing::warn!("relayed streams are arriving faster than they are served");
                }
            }
        }
    }
}

/// A stream that holds its place under [`RelayOptions::max_streams`] until dropped.
struct Held<T> {
    io: T,
    _permit: OwnedSemaphorePermit,
}

impl<T: AsyncRead + Unpin> AsyncRead for Held<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Held<T> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_urls() {
        assert_eq!(
            join_url("wss://relay.example.com/", PATH_CONNECT),
            "wss://relay.example.com/relay/v1/connect"
        );
    }
}

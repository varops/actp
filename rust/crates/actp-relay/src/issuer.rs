//! The issuer pass-through (docs/relay.md): machines ask the organization's
//! identity service a few configured questions through the relay, because
//! laptops cannot reach it themselves.
//!
//! `GET /relay/v1/issuer/<path>?<query>` from a machine (device certificate
//! only) is forwarded to the configured issuer as `GET <url><path>?<query>`
//! with the configured headers (the relay's own credentials there), and the
//! status and body come back. Nothing else from the machine is forwarded,
//! and nothing else of the answer comes back.
//!
//! The relay carries the answers and cannot be trusted with them: what a
//! machine asks this way must be answered with something it can check
//! itself, such as a signed answer bound to a nonce it chose. The relay
//! limits how often each machine may ask, and how many questions are in
//! flight, so one machine cannot spend the issuer's capacity.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::config;
use crate::limit::RateLimiter;

/// The largest answer passed back.
pub const MAX_ANSWER: usize = 64 << 10;
/// The longest query passed on.
pub const MAX_QUERY: usize = 2048;
/// Questions in flight to the issuer at once, all machines together.
pub const MAX_IN_FLIGHT: usize = 32;
/// Questions in flight from one machine at once.
pub const MAX_IN_FLIGHT_PER_MACHINE: usize = 2;
/// The header the relay sets on every question, naming the machine that
/// asked (from its certificate), whatever else is configured or sent.
pub const MACHINE_HEADER: &str = "x-relay-machine";

/// The limits on questions, kept across reloads so a reload neither resets
/// a machine's allowance nor opens more slots.
pub struct Limits {
    per_machine: RateLimiter<String>,
    in_flight: Arc<tokio::sync::Semaphore>,
    open: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl Limits {
    pub fn new(rate: config::Rate) -> Arc<Limits> {
        Arc::new(Limits {
            per_machine: RateLimiter::new(rate.per_second, rate.burst),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
            open: Default::default(),
        })
    }

    pub fn set_rate(&self, rate: config::Rate) {
        self.per_machine.set_rate(rate.per_second, rate.burst);
    }

    fn open(self: &Arc<Self>, machine: &str) -> Option<Open> {
        let mut m = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let n = m.entry(machine.to_string()).or_default();
        if *n >= MAX_IN_FLIGHT_PER_MACHINE {
            return None;
        }
        *n += 1;
        Some(Open {
            limits: self.clone(),
            machine: machine.to_string(),
        })
    }
}

/// One of a machine's open questions.
struct Open {
    limits: Arc<Limits>,
    machine: String,
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut m = self.limits.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.machine) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.machine);
            }
        }
    }
}

/// The configured issuer, ready to forward to.
pub struct Issuer {
    scheme_https: bool,
    /// As in the URL (with brackets for IPv6), for the Host header.
    host: String,
    /// To connect to and to check the certificate against (no brackets).
    connect_host: String,
    port: u16,
    prefix: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    headers: Vec<(HeaderName, HeaderValue)>,
    paths: Vec<String>,
    timeout: Duration,
    limits: Arc<Limits>,
}

/// Why a question was not answered by the issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The path is not one the configuration forwards.
    NotForwarded,
    /// The query is too long.
    QueryTooLong,
    /// This machine asked too often.
    RateLimited,
    /// Too many questions in flight.
    Busy,
    /// The issuer could not be reached, timed out, or answered too much.
    Unavailable,
}

fn bad(what: &str) -> io::Error {
    io::Error::other(format!("issuer: {what}"))
}

impl Issuer {
    /// The issuer from its section, under `limits` (kept by the relay
    /// across reloads).
    pub fn from_config(cfg: &config::Issuer, limits: Arc<Limits>) -> io::Result<Issuer> {
        let uri: Uri = cfg.url.parse().map_err(|e| bad(&format!("url: {e}")))?;
        let host = uri
            .host()
            .ok_or_else(|| bad("url needs a host"))?
            .to_string();
        let connect_host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let https = match uri.scheme_str() {
            Some("https") => true,
            // Plain http only to a loopback address, by number: a name could
            // resolve elsewhere and send the credentials in the clear.
            Some("http") if is_loopback_ip(&connect_host) => false,
            _ => {
                return Err(bad(
                    "url must be https:// (http:// only to a loopback address such as 127.0.0.1)",
                ));
            }
        };
        if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
            return Err(bad("url must not carry a user name or password"));
        }
        if uri.query().is_some() {
            return Err(bad("url must not carry a query"));
        }
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let prefix = uri.path().trim_end_matches('/').to_string();
        let tls = if https {
            let Some(ca) = &cfg.ca else {
                return Err(bad(
                    "an https url needs ca, the roots for the issuer's certificate",
                ));
            };
            use rustls_pki_types::CertificateDer;
            use rustls_pki_types::pem::PemObject;
            let mut roots = rustls::RootCertStore::empty();
            for c in CertificateDer::pem_file_iter(ca).map_err(|e| bad(&format!("ca: {e}")))? {
                roots
                    .add(c.map_err(|e| bad(&format!("ca: {e}")))?)
                    .map_err(|e| bad(&format!("ca: {e}")))?;
            }
            if roots.is_empty() {
                return Err(bad("ca: no certificate in the file"));
            }
            let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(Arc::new(tls))
        } else {
            None
        };
        let mut headers = Vec::new();
        for (name, value) in &cfg.headers {
            let name: HeaderName = name
                .parse()
                .map_err(|_| bad(&format!("header name {name:?}")))?;
            if name.as_str() == MACHINE_HEADER {
                return Err(bad(&format!("header {name} is set by the relay")));
            }
            // `env:NAME` and `file:/path` keep a secret out of the config
            // file; a file is read again on every reload, so a secret can be
            // rotated without a restart (an environment variable cannot).
            let value = if let Some(var) = value.strip_prefix("env:") {
                std::env::var(var).map_err(|_| bad(&format!("header {name}: {var} is not set")))?
            } else if let Some(path) = value.strip_prefix("file:") {
                std::fs::read_to_string(path)
                    .map_err(|e| bad(&format!("header {name}: {path}: {e}")))?
                    .trim()
                    .to_string()
            } else {
                value.clone()
            };
            let mut value =
                HeaderValue::from_str(&value).map_err(|_| bad(&format!("header {name}")))?;
            value.set_sensitive(true);
            headers.push((name, value));
        }
        Ok(Issuer {
            scheme_https: https,
            host,
            connect_host,
            port,
            prefix,
            tls,
            headers,
            paths: cfg.paths.clone(),
            timeout: Duration::from_secs(cfg.timeout_seconds),
            limits,
        })
    }

    /// Forwards `path?query` for `machine`; the issuer's status and body.
    pub async fn ask(
        &self,
        machine: &str,
        path: &str,
        query: Option<&str>,
    ) -> Result<(StatusCode, Bytes), Refusal> {
        // Every request counts against the machine's allowance, refused
        // ones too, so no machine can fill the audit with refusals.
        if !self.limits.per_machine.allow_key(machine.to_string()) {
            return Err(Refusal::RateLimited);
        }
        if !self.paths.iter().any(|p| p == path) {
            return Err(Refusal::NotForwarded);
        }
        if query.is_some_and(|q| q.len() > MAX_QUERY) {
            return Err(Refusal::QueryTooLong);
        }
        let Some(_open) = self.limits.open(machine) else {
            return Err(Refusal::Busy);
        };
        let Ok(_permit) = self.limits.in_flight.try_acquire() else {
            return Err(Refusal::Busy);
        };
        let target = match query {
            Some(q) => format!("{}{path}?{q}", self.prefix),
            None => format!("{}{path}", self.prefix),
        };
        match tokio::time::timeout(self.timeout, self.send(&target, machine)).await {
            // Only final answers: an informational or made-up status could
            // confuse the machine's HTTP client.
            Ok(Ok((status, _))) if !(200..=599).contains(&status.as_u16()) => {
                tracing::warn!(%status, "the issuer answered with an odd status");
                Err(Refusal::Unavailable)
            }
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(e)) => {
                // Not the target: its query names a person.
                tracing::warn!(error = %e, "the issuer could not be asked");
                Err(Refusal::Unavailable)
            }
            Err(_) => {
                tracing::warn!("the issuer did not answer in time");
                Err(Refusal::Unavailable)
            }
        }
    }

    async fn send(&self, target: &str, machine: &str) -> io::Result<(StatusCode, Bytes)> {
        let tcp = TcpStream::connect((self.connect_host.as_str(), self.port)).await?;
        let _ = tcp.set_nodelay(true);
        let mut req = Request::get(target)
            .header(http::header::HOST, self.authority())
            .header(http::header::ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        for (n, v) in &self.headers {
            req.headers_mut().insert(n.clone(), v.clone());
        }
        // Who asked, from its certificate: the issuer can log and limit per
        // machine, though the credentials are the relay's.
        req.headers_mut().insert(
            HeaderName::from_static(MACHINE_HEADER),
            HeaderValue::from_str(machine).map_err(io::Error::other)?,
        );
        let resp = match &self.tls {
            Some(tls) => {
                let name = rustls_pki_types::ServerName::try_from(self.connect_host.clone())
                    .map_err(io::Error::other)?;
                let stream = tokio_rustls::TlsConnector::from(tls.clone())
                    .connect(name, tcp)
                    .await?;
                send_on(TokioIo::new(stream), req).await?
            }
            None => send_on(TokioIo::new(tcp), req).await?,
        };
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| io::Error::other(format!("the answer: {e}")))?
            .to_bytes();
        Ok((status, body))
    }

    fn authority(&self) -> String {
        let default = if self.scheme_https { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

async fn send_on<T>(
    io: TokioIo<T>,
    req: Request<Empty<Bytes>>,
) -> io::Result<http::Response<hyper::body::Incoming>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.map_err(io::Error::other)
}

fn is_loopback_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

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

/// The configured issuer, ready to forward to.
pub struct Issuer {
    scheme_https: bool,
    host: String,
    port: u16,
    prefix: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    headers: Vec<(HeaderName, HeaderValue)>,
    paths: Vec<String>,
    timeout: Duration,
    per_machine: RateLimiter<String>,
    in_flight: tokio::sync::Semaphore,
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
    pub fn from_config(cfg: &config::Issuer) -> io::Result<Issuer> {
        let uri: Uri = cfg.url.parse().map_err(|e| bad(&format!("url: {e}")))?;
        let host = uri
            .host()
            .ok_or_else(|| bad("url needs a host"))?
            .to_string();
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") if is_loopback(&host) => false,
            _ => return Err(bad("url must be https:// (http:// on loopback only)")),
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
            // `env:NAME` keeps a secret out of the file.
            let value = match value.strip_prefix("env:") {
                Some(var) => std::env::var(var)
                    .map_err(|_| bad(&format!("header {name}: {var} is not set")))?,
                None => value.clone(),
            };
            let mut value =
                HeaderValue::from_str(&value).map_err(|_| bad(&format!("header {name}")))?;
            value.set_sensitive(true);
            headers.push((name, value));
        }
        Ok(Issuer {
            scheme_https: https,
            host,
            port,
            prefix,
            tls,
            headers,
            paths: cfg.paths.clone(),
            timeout: Duration::from_secs(cfg.timeout_seconds),
            per_machine: RateLimiter::new(cfg.rate.per_second, cfg.rate.burst),
            in_flight: tokio::sync::Semaphore::new(MAX_IN_FLIGHT),
        })
    }

    /// Forwards `path?query` for `machine`; the issuer's status and body.
    pub async fn ask(
        &self,
        machine: &str,
        path: &str,
        query: Option<&str>,
    ) -> Result<(StatusCode, Bytes), Refusal> {
        if !self.paths.iter().any(|p| p == path) {
            return Err(Refusal::NotForwarded);
        }
        if query.is_some_and(|q| q.len() > MAX_QUERY) {
            return Err(Refusal::QueryTooLong);
        }
        if !self.per_machine.allow_key(machine.to_string()) {
            return Err(Refusal::RateLimited);
        }
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return Err(Refusal::Busy);
        };
        let target = match query {
            Some(q) => format!("{}{path}?{q}", self.prefix),
            None => format!("{}{path}", self.prefix),
        };
        match tokio::time::timeout(self.timeout, self.send(&target)).await {
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

    async fn send(&self, target: &str) -> io::Result<(StatusCode, Bytes)> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let _ = tcp.set_nodelay(true);
        let mut req = Request::get(target)
            .header(http::header::HOST, self.authority())
            .header(http::header::ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        for (n, v) in &self.headers {
            req.headers_mut().insert(n.clone(), v.clone());
        }
        let resp = match &self.tls {
            Some(tls) => {
                let name = rustls_pki_types::ServerName::try_from(self.host.clone())
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

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

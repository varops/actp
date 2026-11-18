//! The relay's management API, as an operator or an admin (docs/relay.md,
//! "Operators"): who is online, the relay's half of the audit, and the
//! org-wide stop.
//!
//! An operator is a caller whose certificate the relay's configuration
//! gives a role; it reaches the API with the same TLS it opens tunnels with
//! ([`RelayRoute::relay_tls`]). A program acting for a person (an IT app)
//! names the person with [`RelayOps::on_behalf_of`]; the relay requires it
//! of an operator for the stop and its release, and records it.

use std::sync::Arc;
use std::time::Duration;

use actp_proto::api;
use http_body_util::{BodyExt, Full, Limited};
use serde::{Deserialize, Serialize};

use crate::{Error, RelayRoute, StatusError};

/// The org-wide stop, as the relay records it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Stop {
    pub stopped: bool,
    /// Who pressed or released it last: an admin token's name, or an
    /// operator's caller name.
    pub by: String,
    /// `admin`, `operator`, or `relay`.
    pub by_kind: String,
    /// The person an operator acted for.
    pub on_behalf_of: Option<String>,
    pub reason: String,
    /// RFC 3339.
    pub at: String,
}

/// A machine the relay has seen.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Machine {
    /// Its address: the name in its device certificate.
    pub machine: String,
    pub online: bool,
    /// While online, since when (RFC 3339).
    pub connected_since: Option<String>,
    pub first_seen: String,
    /// Now, while online; otherwise when it was last heard from (to within
    /// about a minute, and as of the relay's last save before a restart).
    pub last_seen: String,
    /// Callers connected to it now.
    pub sessions: u64,
    /// The key its name is pinned to (SHA-256 of the public key, hex).
    pub key: Option<String>,
    pub key_until: Option<String>,
}

/// `GET /relay/v1/machines`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Machines {
    pub stop: Stop,
    pub machines: Vec<Machine>,
}

/// Which machines to list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachinesQuery {
    /// Only these (up to 1000); empty: all.
    pub machines: Vec<String>,
    /// Only those online (`Some(true)`) or offline (`Some(false)`).
    pub online: Option<bool>,
}

/// Which kind of audit events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// `session_open`, `session_closed`: who connected to which machine,
    /// when and for how long.
    Sessions,
    /// `org_stop`, `org_release` (and whether the stop was saved).
    Stops,
    /// Machines coming and going, and changes to their pinned keys.
    Machines,
}

impl AuditKind {
    fn as_str(self) -> &'static str {
        match self {
            AuditKind::Sessions => "sessions",
            AuditKind::Stops => "stops",
            AuditKind::Machines => "machines",
        }
    }
}

/// `GET /relay/v1/audit`: every field narrows the answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Empty: every kind.
    pub kinds: Vec<AuditKind>,
    /// Only events naming exactly this machine, caller, or person (events
    /// without the field, such as the stop's for `machine`, are left out).
    pub machine: Option<String>,
    pub caller: Option<String>,
    pub on_behalf_of: Option<String>,
    /// RFC 3339, at or after.
    pub since: Option<String>,
    /// RFC 3339, before: the previous page's [`AuditPage::next_before`].
    pub before: Option<String>,
    /// 1 to 1000; the relay's default is 100.
    pub limit: Option<usize>,
}

/// One audit event: `event` and `time` (RFC 3339, microseconds, unique),
/// and its fields (docs/relay.md, "Audit").
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event: String,
    pub time: String,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// One page of the audit, newest first.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    /// Older events match too: ask again with `before` = `next_before`.
    pub more: bool,
    pub next_before: Option<String>,
}

/// A client for the relay's management API.
#[derive(Clone)]
pub struct RelayOps {
    host: String,
    port: u16,
    authority: String,
    tls: Arc<rustls::ClientConfig>,
    bearer: Option<String>,
    on_behalf_of: Option<String>,
    timeout: Duration,
}

/// Answers over this are refused (a list of 20 000 machines is about 6 MB).
const MAX_BODY: usize = 64 << 20;

impl RelayOps {
    /// The relay at `relay` (`https://host[:port]`), reached with `tls`: a
    /// caller certificate the relay names an operator.
    pub fn new(relay: &str, tls: Arc<rustls::ClientConfig>) -> Result<RelayOps, String> {
        let relay = relay.strip_suffix('/').unwrap_or(relay);
        let Some((scheme, rest)) = relay.split_once("://") else {
            return Err("the relay URL needs a scheme (https://)".into());
        };
        if !matches!(scheme.to_ascii_lowercase().as_str(), "https" | "wss") {
            return Err(format!("a relay is reached over https, not \"{scheme}\""));
        }
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err("the relay URL is the relay's address only, with no path".into());
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !p.contains(']') => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("{p:?} is not a port"))?,
            ),
            _ => (rest.to_string(), 443),
        };
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .map(str::to_string)
            .unwrap_or(host);
        rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| format!("{host:?} is not a host name"))?;
        Ok(RelayOps {
            host,
            port,
            authority: rest.to_string(),
            tls,
            bearer: None,
            on_behalf_of: None,
            timeout: Duration::from_secs(30),
        })
    }

    /// [`RelayOps::new`] with a route's caller certificate and person.
    pub fn from_route(relay: &str, route: &RelayRoute) -> Result<RelayOps, String> {
        let mut ops = RelayOps::new(relay, route.relay_tls.clone())?;
        ops.on_behalf_of = route.on_behalf_of.clone();
        Ok(ops)
    }

    /// Whom the requests are for, sent as `X-Actp-On-Behalf-Of`: required
    /// of an operator for the stop and its release, recorded with them.
    pub fn on_behalf_of(mut self, who: Option<String>) -> RelayOps {
        self.on_behalf_of = who;
        self
    }

    /// Asks as an admin, with this token, instead of the certificate.
    pub fn admin_token(mut self, token: Option<String>) -> RelayOps {
        self.bearer = token;
        self
    }

    /// How long one request may take (30 s).
    pub fn timeout(mut self, d: Duration) -> RelayOps {
        self.timeout = d;
        self
    }

    /// Who is online, and when each machine was last seen.
    pub async fn machines(&self, q: &MachinesQuery) -> Result<Machines, Error> {
        let mut query = Vec::new();
        for m in &q.machines {
            query.push(("machine", m.as_str()));
        }
        if let Some(o) = q.online {
            query.push(("online", if o { "true" } else { "false" }));
        }
        self.call("GET", "/relay/v1/machines", &query, None).await
    }

    /// One page of the relay's audit, newest first.
    pub async fn audit(&self, q: &AuditQuery) -> Result<AuditPage, Error> {
        let kinds = q
            .kinds
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let limit = q.limit.map(|l| l.to_string());
        let mut query = Vec::new();
        if !kinds.is_empty() {
            query.push(("kind", kinds.as_str()));
        }
        for (k, v) in [
            ("machine", &q.machine),
            ("caller", &q.caller),
            ("on_behalf_of", &q.on_behalf_of),
            ("since", &q.since),
            ("before", &q.before),
            ("limit", &limit),
        ] {
            if let Some(v) = v {
                query.push((k, v.as_str()));
            }
        }
        self.call("GET", "/relay/v1/audit", &query, None).await
    }

    /// The org-wide stop as it is now.
    pub async fn stop_state(&self) -> Result<Stop, Error> {
        Ok(self
            .call::<StopAnswer>("GET", "/relay/v1/stop", &[], None)
            .await?
            .stop)
    }

    /// Presses the org-wide stop: every session ends, and no caller gets
    /// through until it is released. `stop_not_saved` (HTTP 500) means the
    /// stop holds but a restart of the relay would lose it.
    pub async fn stop(&self, reason: &str) -> Result<Stop, Error> {
        let body = serde_json::json!({ "reason": reason }).to_string();
        Ok(self
            .call::<StopAnswer>("POST", "/relay/v1/stop", &[], Some(body))
            .await?
            .stop)
    }

    /// Releases the org-wide stop.
    pub async fn release(&self, reason: &str) -> Result<Stop, Error> {
        let body = serde_json::json!({ "reason": reason }).to_string();
        Ok(self
            .call::<StopAnswer>("POST", "/relay/v1/release", &[], Some(body))
            .await?
            .stop)
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<T, Error> {
        match tokio::time::timeout(self.timeout, self.send(method, path, query, body)).await {
            Ok(r) => r,
            Err(_) => Err(Error::Other(format!(
                "the relay did not answer {path} in time"
            ))),
        }
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<T, Error> {
        let other = |what: &str, e: &dyn std::fmt::Display| {
            Error::Other(format!("{what} the relay at {}: {e}", self.authority))
        };
        let mut uri = path.to_string();
        for (i, (k, v)) in query.iter().enumerate() {
            uri.push(if i == 0 { '?' } else { '&' });
            uri.push_str(&escape(k));
            uri.push('=');
            uri.push_str(&escape(v));
        }
        let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| other("could not reach", &e))?;
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|e| other("bad host name for", &e))?;
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| other("TLS failed with", &e))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| other("HTTP failed with", &e))?;
        tokio::spawn(conn);
        let mut req = http::Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::HOST, &self.authority);
        if let Some(t) = &self.bearer {
            req = req.header(http::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(who) = &self.on_behalf_of {
            if !actp_proto::relay::valid_on_behalf_of(who) {
                return Err(Error::Other(
                    "on_behalf_of must be 1 to 256 bytes, without control, invisible or direction-changing characters or surrounding space".into(),
                ));
            }
            req = req.header(actp_proto::relay::HEADER_ON_BEHALF_OF, who.as_bytes());
        }
        if body.is_some() {
            req = req.header(http::header::CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(bytes_of(body.unwrap_or_default())))
            .map_err(|e| Error::Other(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| other("no answer from", &e))?;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| other("could not read the answer of", &e))?
            .to_bytes();
        if !(200..300).contains(&status) {
            let (code, message) = api::decode_error_body(&bytes);
            return Err(Error::Status(StatusError {
                status,
                code,
                message,
            }));
        }
        serde_json::from_slice(&bytes).map_err(|e| other("unexpected answer from", &e))
    }
}

#[derive(Deserialize)]
struct StopAnswer {
    stop: Stop,
}

fn bytes_of(s: String) -> hyper::body::Bytes {
    hyper::body::Bytes::from(s)
}

/// Percent-encodes everything but the unreserved characters, `+` included.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls() -> Arc<rustls::ClientConfig> {
        crate::default_tls().unwrap()
    }

    #[test]
    fn relay_urls() {
        let o = RelayOps::new("https://relay.example.com", tls()).unwrap();
        assert_eq!((o.host.as_str(), o.port), ("relay.example.com", 443));
        let o = RelayOps::new("https://relay.example.com:8443/", tls()).unwrap();
        assert_eq!((o.host.as_str(), o.port), ("relay.example.com", 8443));
        assert_eq!(o.authority, "relay.example.com:8443");
        let o = RelayOps::new("wss://[::1]:9443", tls()).unwrap();
        assert_eq!((o.host.as_str(), o.port), ("::1", 9443));
        for bad in [
            "relay.example.com",
            "http://relay.example.com",
            "https://relay.example.com/relay",
            "https://user@relay.example.com",
            "https://relay.example.com:x",
            "https://",
        ] {
            assert!(RelayOps::new(bad, tls()).is_err(), "{bad}");
        }
    }

    #[test]
    fn escapes_query_values() {
        assert_eq!(escape("dana+it@example.com"), "dana%2Bit%40example.com");
        assert_eq!(
            escape("2026-11-18T10:00:00.000001Z"),
            "2026-11-18T10%3A00%3A00.000001Z"
        );
        assert_eq!(escape("Dana Ö"), "Dana%20%C3%96");
    }
}

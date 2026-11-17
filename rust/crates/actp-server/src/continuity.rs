//! Key continuity (docs/relay.md): moving the relay's pin for this machine
//! to a new device key, with the old key's proof.
//!
//! The relay pins each machine name to the key it first saw. When the MDM
//! issues a renewed certificate with a new key, it puts it next to the
//! current one as `<cert>.next` and `<key>.next`. While connected, the
//! machine notices them, asks the relay for a nonce, and posts the new
//! certificate with the current key's signature over it, its own address
//! and the nonce. The relay moves the pin only with that proof. Then the
//! machine installs the new files (keeping the old ones as `<cert>.prev`
//! and `<key>.prev`) and reconnects with them.
//!
//! Without `.next` files, or once the current certificate has expired,
//! nothing here helps: an admin re-pins the machine at the relay.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use actp_proto::relay::{PATH_REKEY, PATH_REKEY_CHALLENGE, RekeyChallenge, RekeyRequest};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::relay::{Status, client_tls, device_chain, stream_tls};

/// The TLS the machine speaks with: to the relay, and end to end to callers.
pub(crate) struct Identity {
    pub tls: Arc<rustls::ClientConfig>,
    pub e2e: Arc<rustls::ServerConfig>,
}

pub(crate) type Shared = Arc<RwLock<Identity>>;

/// Where the next certificate and key are put: `<cert>.next`, `<key>.next`.
pub fn next_files(relay: &config::Relay) -> config::Relay {
    config::Relay {
        cert: format!("{}.next", relay.cert),
        key: format!("{}.next", relay.key),
        ..relay.clone()
    }
}

/// Looks for a next certificate every `every` while connected, and moves
/// to it. On success, swaps `identity` and wakes `reconnect`.
pub(crate) async fn run(
    relay: config::Relay,
    identity: Shared,
    status: watch::Receiver<Status>,
    reconnect: Arc<Notify>,
    every: Duration,
    shutdown: CancellationToken,
) {
    let next = next_files(&relay);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(every) => {}
        }
        if !std::path::Path::new(&next.cert).exists() || !std::path::Path::new(&next.key).exists() {
            continue;
        }
        let Status::Connected { machine } = status.borrow().clone() else {
            continue;
        };
        match move_to_next(&relay, &next, &machine, &identity).await {
            Ok(()) => {
                tracing::info!(machine = %machine, "moved to the next device certificate; reconnecting");
                reconnect.notify_one();
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not move to the next device certificate");
            }
        }
    }
}

async fn move_to_next(
    relay: &config::Relay,
    next: &config::Relay,
    machine: &str,
    identity: &Shared,
) -> Result<(), String> {
    use base64::engine::general_purpose::STANDARD as B64;
    // Both next files must load, and make working TLS, before anything is
    // asked: a broken pair must never become the pin.
    let (next_chain, _) = device_chain(next).map_err(|e| e.to_string())?;
    let new = Identity {
        tls: client_tls(next).map_err(|e| e.to_string())?,
        e2e: stream_tls(next).map_err(|e| e.to_string())?,
    };
    let (_, current_key) = device_chain(relay).map_err(|e| e.to_string())?;
    let current = identity
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .tls
        .clone();
    let (status, body) = post(
        &relay.url,
        current.clone(),
        PATH_REKEY_CHALLENGE,
        Vec::new(),
    )
    .await?;
    if status != 200 {
        return Err(format!(
            "the relay refused a nonce: HTTP {status} {}",
            code(&body)
        ));
    }
    let challenge: RekeyChallenge =
        serde_json::from_slice(&body).map_err(|_| "the relay's nonce is malformed".to_string())?;
    let message =
        actp_proto::relay::rekey_message(machine, &challenge.nonce, next_chain[0].as_ref());
    let (scheme, signature) = actp_proto::relay::rekey_sign(&current_key, &message)?;
    let ask = RekeyRequest {
        certificates: next_chain.iter().map(|c| B64.encode(c.as_ref())).collect(),
        nonce: challenge.nonce,
        scheme,
        signature: B64.encode(signature),
    };
    let body = serde_json::to_vec(&ask).expect("encodes");
    let (status, answer) = post(&relay.url, current, PATH_REKEY, body).await?;
    // The same key needs no proof: the pin holds for it already.
    if status != 200 && code(&answer) != "rekey_same_key" {
        return Err(format!(
            "the relay refused the next certificate: HTTP {status} {}",
            code(&answer)
        ));
    }
    install(relay, next).map_err(|e| format!("installing the next certificate: {e}"))?;
    *identity.write().unwrap_or_else(|p| p.into_inner()) = new;
    Ok(())
}

/// The relay's error code in a refusal, if it gave one.
fn code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_default()
}

/// Keeps the current files as `.prev` and moves the next ones in place,
/// the key first.
fn install(relay: &config::Relay, next: &config::Relay) -> io::Result<()> {
    std::fs::copy(&relay.key, format!("{}.prev", relay.key))?;
    std::fs::copy(&relay.cert, format!("{}.prev", relay.cert))?;
    std::fs::rename(&next.key, &relay.key)?;
    std::fs::rename(&next.cert, &relay.cert)?;
    Ok(())
}

/// One `POST` to the relay at `base` (`wss://host[:port]`) with `tls`:
/// the status and up to 64 KiB of the answer.
async fn post(
    base: &str,
    tls: Arc<rustls::ClientConfig>,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    let uri: http::Uri = base.parse().map_err(|e| format!("the relay url: {e}"))?;
    if uri.scheme_str() != Some("wss") {
        return Err("the relay url must start with wss://".into());
    }
    let host = uri.host().ok_or("the relay url has no host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let connect_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let ask = async {
        let tcp = tokio::net::TcpStream::connect((connect_host.as_str(), port))
            .await
            .map_err(|e| e.to_string())?;
        let name = rustls::pki_types::ServerName::try_from(connect_host.clone())
            .map_err(|e| e.to_string())?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let authority = match uri.port_u16() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let req = http::Request::post(path)
            .header(http::header::HOST, authority)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), 64 << 10)
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok::<_, String>((status, bytes.to_vec()))
    };
    tokio::time::timeout(Duration::from_secs(10), ask)
        .await
        .map_err(|_| "the relay did not answer in time".to_string())?
}

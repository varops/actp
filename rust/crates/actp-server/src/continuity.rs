//! Key continuity (docs/relay.md): moving the relay's pin for this machine
//! to a new device key, with the old key's proof.
//!
//! The relay pins each machine name to the key it first saw. When the MDM
//! issues a renewed certificate with a new key, it puts it next to the
//! current one as `<cert>.next` and `<key>.next`. While connected, the
//! machine reads that pair once, checks it, and stages its exact bytes
//! beside the current files (which also shows the folder is writable). It
//! then asks the relay for a nonce, and posts the new certificate with the
//! current key's signature over it, its own address and the nonce. The relay
//! moves the pin only with that proof, and saves it before answering. The
//! machine then switches to the new identity in memory and reconnects, and
//! only then puts the staged files in place.
//!
//! If anything goes wrong after the relay moved the pin (the answer was
//! lost, the files could not be put in place, the machine restarted), the
//! relay refuses the old key at the next connection. The machine then tries
//! the `.next` pair, and keeps it if the relay takes it. The same path takes
//! up a key an admin re-pinned the machine to. Without a `.next` pair, or
//! once the current certificate has expired, an admin re-pins the machine.

use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use actp_proto::relay::{PATH_REKEY, PATH_REKEY_CHALLENGE, RekeyChallenge, RekeyRequest};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::relay::{Status, client_tls_with};

/// The TLS the machine speaks with: to the relay, and end to end to callers;
/// and the certificate and key it is made of, when known, which sign the
/// proof for the next one.
pub(crate) struct Identity {
    pub tls: Arc<rustls::ClientConfig>,
    pub e2e: Arc<rustls::ServerConfig>,
    pub pair: Option<Arc<Pair>>,
}

pub(crate) type Shared = Arc<RwLock<Identity>>;

/// Bumped every time the identity changes, so the control connection made
/// with an older one reconnects.
pub(crate) type Generation = Arc<watch::Sender<u64>>;

/// Where the next certificate and key are put: `<cert>.next`, `<key>.next`.
pub fn next_files(relay: &config::Relay) -> config::Relay {
    config::Relay {
        cert: format!("{}.next", relay.cert),
        key: format!("{}.next", relay.key),
        ..relay.clone()
    }
}

/// A device certificate and key, read once: their exact bytes, and what
/// they parse to.
pub(crate) struct Pair {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Pair {
    /// Reads and checks the pair at `files`' paths: a certificate chain, a
    /// key, and the key is the certificate's (it signs, the certificate
    /// verifies).
    pub(crate) fn read(files: &config::Relay) -> Result<Pair, String> {
        use rustls::pki_types::pem::PemObject;
        let cert_pem = std::fs::read(&files.cert).map_err(|e| format!("{}: {e}", files.cert))?;
        let key_pem = std::fs::read(&files.key).map_err(|e| format!("{}: {e}", files.key))?;
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{}: {e}", files.cert))?;
        if chain.is_empty() {
            return Err(format!("{}: no certificate in the file", files.cert));
        }
        let key =
            PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| format!("{}: {e}", files.key))?;
        let probe = actp_proto::relay::rekey_message("probe", "probe", chain[0].as_ref());
        let (scheme, sig) = actp_proto::relay::rekey_sign(&key, &probe)?;
        if !actp_proto::relay::rekey_verify(chain[0].as_ref(), scheme, &probe, &sig) {
            return Err(format!("{} is not the key of {}", files.key, files.cert));
        }
        Ok(Pair {
            cert_pem,
            key_pem,
            chain,
            key,
        })
    }

    /// The identity this pair makes, with `relay`'s roots for the relay.
    pub(crate) fn identity(self: &Arc<Self>, relay: &config::Relay) -> Result<Identity, String> {
        Ok(Identity {
            tls: client_tls_with(relay, self.chain.clone(), self.key.clone_key())
                .map_err(|e| e.to_string())?,
            e2e: actp_proto::e2e::server_config(self.chain.clone(), self.key.clone_key())
                .map_err(|e| e.to_string())?,
            pair: Some(self.clone()),
        })
    }

    /// Whether `other` holds the same certificate and key.
    fn same_as(&self, other: &Pair) -> bool {
        self.cert_pem == other.cert_pem && self.key_pem == other.key_pem
    }

    /// Writes the pair's exact bytes next to the current files as
    /// `.staged`, synced, the key readable by its owner only.
    fn stage(&self, relay: &config::Relay) -> io::Result<()> {
        write_synced(&format!("{}.staged", relay.cert), &self.cert_pem, false)?;
        write_synced(&format!("{}.staged", relay.key), &self.key_pem, true)
    }
}

fn write_synced(path: &str, data: &[u8], private: bool) -> io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Puts the staged files in place (key, then certificate), and removes the
/// `.next` pair if it still holds the bytes that were staged. The old key
/// is not kept.
fn commit(relay: &config::Relay, pair: &Pair) -> io::Result<()> {
    // If the certificate cannot follow the key, the old key goes back: a
    // key without its certificate would stop the machine from starting.
    let old_key = std::fs::read(&relay.key)?;
    std::fs::rename(format!("{}.staged", relay.key), &relay.key)?;
    if let Err(e) = std::fs::rename(format!("{}.staged", relay.cert), &relay.cert) {
        let _ = write_synced(&format!("{}.staged", relay.key), &old_key, true)
            .and_then(|()| std::fs::rename(format!("{}.staged", relay.key), &relay.key));
        return Err(e);
    }
    let next = next_files(relay);
    if std::fs::read(&next.cert).ok().as_deref() == Some(&pair.cert_pem[..])
        && std::fs::read(&next.key).ok().as_deref() == Some(&pair.key_pem[..])
    {
        let _ = std::fs::remove_file(&next.key);
        let _ = std::fs::remove_file(&next.cert);
    }
    Ok(())
}

fn unstage(relay: &config::Relay) {
    let _ = std::fs::remove_file(format!("{}.staged", relay.key));
    let _ = std::fs::remove_file(format!("{}.staged", relay.cert));
}

const NOT_IN_PLACE: &str = "the next device certificate could not be put in place; this machine uses it until it restarts, and takes it up again from the .next files then";

/// Stages and commits `pair` as the machine's files, after the relay took
/// it. Errors are logged: the identity in memory is the new one already.
pub(crate) fn install(relay: &config::Relay, pair: &Pair) {
    if let Err(e) = pair.stage(relay).and_then(|()| commit(relay, pair)) {
        unstage(relay);
        tracing::error!(error = %e, "{NOT_IN_PLACE}");
    }
}

/// At start, before the device certificate is used: repairs the one state
/// a swap cut short leaves (the `.next` key in place, the old certificate
/// not yet replaced) by putting the `.next` certificate in place too. In any
/// other state the files are left alone, so the old key, the only one that
/// can prove a move, is never lost to a file that was only unreadable.
pub fn repair(relay: &config::Relay) {
    if Pair::read(relay).is_ok() {
        return;
    }
    let next = next_files(relay);
    let (Ok(key), Ok(next_key), Ok(next_cert)) = (
        std::fs::read(&relay.key),
        std::fs::read(&next.key),
        std::fs::read(&next.cert),
    ) else {
        return;
    };
    if key != next_key || std::fs::read(&relay.cert).ok().as_deref() == Some(&next_cert[..]) {
        return;
    }
    let Some(pair) = next_pair(relay) else {
        return;
    };
    tracing::warn!(
        "a device certificate swap was cut short; putting the next certificate in place"
    );
    let done = write_synced(&format!("{}.staged", relay.cert), &pair.cert_pem, false)
        .and_then(|()| std::fs::rename(format!("{}.staged", relay.cert), &relay.cert));
    match done {
        Ok(()) => {
            let _ = std::fs::remove_file(&next.key);
            let _ = std::fs::remove_file(&next.cert);
        }
        Err(e) => {
            unstage(relay);
            tracing::error!(error = %e, "{NOT_IN_PLACE}");
        }
    }
}

/// The `.next` pair, when there is one that reads and checks.
pub(crate) fn next_pair(relay: &config::Relay) -> Option<Arc<Pair>> {
    let next = next_files(relay);
    if !Path::new(&next.cert).exists() || !Path::new(&next.key).exists() {
        return None;
    }
    match Pair::read(&next) {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            tracing::warn!(error = %e, "the next device certificate cannot be used");
            None
        }
    }
}

/// Switches to `identity` and has the control connection reconnect.
pub(crate) fn switch(shared: &Shared, generation: &Generation, identity: Identity) {
    *shared.write().unwrap_or_else(|p| p.into_inner()) = identity;
    generation.send_modify(|g| *g += 1);
}

/// Looks for a next certificate every `every` while connected, and moves
/// to it with the current key's proof.
pub(crate) async fn run(
    relay: config::Relay,
    identity: Shared,
    generation: Generation,
    status: watch::Receiver<Status>,
    every: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(every) => {}
        }
        let Status::Connected { machine } = status.borrow().clone() else {
            continue;
        };
        let Some(pair) = next_pair(&relay) else {
            continue;
        };
        // Already the identity in use (its files were not put in place, or
        // the MDM delivered them again): only the files, no relay, no
        // reconnect.
        let current = identity
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .pair
            .clone();
        if current.is_some_and(|c| c.same_as(&pair)) {
            install(&relay, &pair);
            continue;
        }
        match move_to(&relay, &pair, &machine, &identity).await {
            Ok(new) => {
                tracing::info!(machine = %machine, "the relay took the next device certificate; reconnecting with it");
                switch(&identity, &generation, new);
                if let Err(e) = commit(&relay, &pair) {
                    unstage(&relay);
                    tracing::error!(error = %e, "{NOT_IN_PLACE}");
                }
            }
            Err(e) => {
                unstage(&relay);
                tracing::warn!(error = %e, "could not move to the next device certificate");
            }
        }
    }
}

/// Stages `pair`, proves it to the relay with the current key, and returns
/// the identity it makes once the relay took it. The staged files are left
/// for [`commit`].
async fn move_to(
    relay: &config::Relay,
    pair: &Arc<Pair>,
    machine: &str,
    identity: &Shared,
) -> Result<Identity, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    let new = pair.identity(relay)?;
    // Nothing is asked unless the files can be put in place afterwards.
    pair.stage(relay)
        .map_err(|e| format!("cannot stage the next certificate beside the current one: {e}"))?;
    // Signed with the key in use, which is not always the one on disk.
    let (tls, current) = {
        let id = identity.read().unwrap_or_else(|p| p.into_inner());
        (id.tls.clone(), id.pair.clone())
    };
    let current = match current {
        Some(c) => c,
        None => Arc::new(Pair::read(relay)?),
    };
    let (status, body) = post(&relay.url, tls.clone(), PATH_REKEY_CHALLENGE, Vec::new()).await?;
    if status != 200 {
        return Err(format!(
            "the relay refused a nonce: HTTP {status} {}",
            code(&body)
        ));
    }
    let challenge: RekeyChallenge =
        serde_json::from_slice(&body).map_err(|_| "the relay's nonce is malformed".to_string())?;
    // Only what the relay gives: the signed message stays unambiguous.
    if challenge.nonce.len() != 64
        || !challenge
            .nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("the relay's nonce is malformed".into());
    }
    let message =
        actp_proto::relay::rekey_message(machine, &challenge.nonce, pair.chain[0].as_ref());
    let (scheme, signature) = actp_proto::relay::rekey_sign(&current.key, &message)?;
    let ask = RekeyRequest {
        certificates: pair.chain.iter().map(|c| B64.encode(c.as_ref())).collect(),
        nonce: challenge.nonce,
        scheme,
        signature: B64.encode(signature),
    };
    let body = serde_json::to_vec(&ask).expect("encodes");
    let (status, answer) = post(&relay.url, tls, PATH_REKEY, body).await?;
    // The same key needs no proof: the pin holds for it already.
    if status != 200 && code(&answer) != "rekey_same_key" {
        return Err(format!(
            "the relay refused the next certificate: HTTP {status} {}",
            code(&answer)
        ));
    }
    Ok(new)
}

/// The relay's error code in a refusal, if it gave one.
fn code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_default()
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

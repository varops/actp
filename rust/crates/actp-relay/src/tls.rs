//! TLS for the relay: its own certificate, and client certificates of two
//! kinds, each from its own roots. Machines log in with the org's device
//! certificates (`device_ca`), callers with caller certificates
//! (`caller_ca`). The handshake accepts either; every route then checks the
//! certificate again against the one kind it serves, so a device
//! certificate never opens a tunnel and a caller certificate never logs in
//! as a machine.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime};

pub use actp_proto::e2e::machine_name;

use crate::config::Config;

fn err(what: &Path, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{}: {e}", what.display()))
}

fn certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let v: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|e| err(path, e))?
        .collect::<Result<_, _>>()
        .map_err(|e| err(path, e))?;
    if v.is_empty() {
        return Err(err(path, "no certificate in the file"));
    }
    Ok(v)
}

fn crls(path: &Path) -> io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let bytes = std::fs::read(path).map_err(|e| err(path, e))?;
    if bytes.starts_with(b"-----BEGIN") {
        CertificateRevocationListDer::pem_slice_iter(&bytes)
            .collect::<Result<_, _>>()
            .map_err(|e| err(path, e))
    } else {
        Ok(vec![CertificateRevocationListDer::from(bytes)])
    }
}

/// The relay's TLS setup: the rustls configuration, and one verifier per
/// kind of client certificate, kept so certificates can be checked again
/// during a connection (expiry, a new revocation list).
#[derive(Clone)]
pub struct Setup {
    pub config: Arc<rustls::ServerConfig>,
    pub devices: Arc<dyn ClientCertVerifier>,
    pub callers: Arc<dyn ClientCertVerifier>,
}

fn valid(verifier: &Arc<dyn ClientCertVerifier>, chain: &[CertificateDer<'static>]) -> bool {
    match chain.split_first() {
        Some((leaf, rest)) => verifier
            .verify_client_cert(leaf, rest, UnixTime::now())
            .is_ok(),
        None => false,
    }
}

impl Setup {
    /// Whether a chain (leaf first) is a valid device certificate now:
    /// signed by the device roots, in its validity period, not revoked.
    pub fn still_valid(&self, chain: &[CertificateDer<'static>]) -> bool {
        valid(&self.devices, chain)
    }

    /// The same for a caller certificate, against the caller roots.
    pub fn caller_valid(&self, chain: &[CertificateDer<'static>]) -> bool {
        valid(&self.callers, chain)
    }
}

/// A client certificate verifier. `handshake` is the one TLS uses for
/// every connection: it takes no certificate too (`/health`, the
/// management API), and a certificate whose issuer has no revocation list
/// (a caller's, when only devices have lists), because every route checks
/// the certificate again with the strict verifier of its own kind.
fn verifier(
    roots: &[CertificateDer<'static>],
    crls: Vec<CertificateRevocationListDer<'static>>,
    what: &Path,
    handshake: bool,
) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut store = rustls::RootCertStore::empty();
    for c in roots {
        store.add(c.clone()).map_err(|e| err(what, e))?;
    }
    let mut builder = WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider);
    if handshake {
        builder = builder.allow_unauthenticated();
    }
    if !crls.is_empty() {
        if handshake {
            builder = builder.allow_unknown_revocation_status();
        }
        // Revocation is checked for the end certificate only (the lists
        // MDM tools publish are the issuing CA's), and a list past its
        // next-update time no longer counts, so a stale list fails closed.
        builder = builder
            .with_crls(crls)
            .only_check_end_entity_revocation()
            .enforce_revocation_expiration();
    }
    builder.build().map_err(io::Error::other)
}

/// The relay's TLS setup from its config.
pub fn server_config(cfg: &Config) -> io::Result<Setup> {
    let device_roots = certs(&cfg.device_ca)?;
    let caller_roots = certs(&cfg.caller_ca)?;
    // One root for both kinds would let a laptop open tunnels to other
    // laptops, or a caller log in as a machine.
    if device_roots.iter().any(|d| caller_roots.contains(d)) {
        return Err(err(
            &cfg.caller_ca,
            "caller_ca shares a root with device_ca; use roots that sign only caller certificates",
        ));
    }
    let mut device_crls = Vec::new();
    for p in &cfg.device_crls {
        device_crls.extend(crls(p)?);
    }
    let mut caller_crls = Vec::new();
    for p in &cfg.caller_crls {
        caller_crls.extend(crls(p)?);
    }
    let devices = verifier(&device_roots, device_crls.clone(), &cfg.device_ca, false)?;
    let callers = verifier(&caller_roots, caller_crls.clone(), &cfg.caller_ca, false)?;
    // The handshake takes either kind (or none: /health); the routes decide.
    let all_roots: Vec<_> = device_roots.into_iter().chain(caller_roots).collect();
    let all_crls: Vec<_> = device_crls.into_iter().chain(caller_crls).collect();
    let handshake = verifier(&all_roots, all_crls, &cfg.device_ca, true)?;
    let key = PrivateKeyDer::from_pem_file(&cfg.tls_key).map_err(|e| err(&cfg.tls_key, e))?;
    let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_client_cert_verifier(handshake)
    .with_single_cert(certs(&cfg.tls_cert)?, key)
    .map_err(io::Error::other)?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    // No session resumption: a resumed session would bring back a client
    // certificate without checking it against today's roots and lists.
    sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    sc.send_tls13_tickets = 0;
    Ok(Setup {
        config: Arc::new(sc),
        devices,
        callers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MachineName;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    fn cert(edit: impl FnOnce(&mut CertificateParams)) -> CertificateDer<'static> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        edit(&mut p);
        p.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn reads_exactly_one_name_of_the_chosen_kind() {
        let cn = cert(|p| p.distinguished_name.push(DnType::CommonName, "C02XK1"));
        assert_eq!(machine_name(&cn, MachineName::Cn).unwrap(), "C02XK1");
        assert!(machine_name(&cn, MachineName::Dns).is_err());

        let none = cert(|_| {});
        assert!(
            machine_name(&none, MachineName::Cn)
                .unwrap_err()
                .contains("no common name")
        );

        let bad = cert(|p| p.distinguished_name.push(DnType::CommonName, "Dana's Mac"));
        assert!(
            machine_name(&bad, MachineName::Cn)
                .unwrap_err()
                .contains("not a valid")
        );

        let dns = cert(|p| {
            p.subject_alt_names = vec![SanType::DnsName(
                "dana-mbp.corp.example".try_into().unwrap(),
            )]
        });
        assert_eq!(
            machine_name(&dns, MachineName::Dns).unwrap(),
            "dana-mbp.corp.example"
        );
        let two = cert(|p| {
            p.subject_alt_names = vec![
                SanType::DnsName("a.example".try_into().unwrap()),
                SanType::DnsName("b.example".try_into().unwrap()),
            ]
        });
        assert!(
            machine_name(&two, MachineName::Dns)
                .unwrap_err()
                .contains("more than one")
        );

        let urn = cert(|p| {
            p.subject_alt_names = vec![SanType::URI("urn:device:1234".try_into().unwrap())]
        });
        assert_eq!(
            machine_name(&urn, MachineName::Uri).unwrap(),
            "urn:device:1234"
        );
        // A URI with a path cannot be an address.
        let spiffe = cert(|p| {
            p.subject_alt_names = vec![SanType::URI("spiffe://acme/dev/1".try_into().unwrap())]
        });
        assert!(machine_name(&spiffe, MachineName::Uri).is_err());
    }
}

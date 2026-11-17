//! TLS for the relay: its own certificate, and device certificates from the
//! org's roots, asked of every client but required only on the machine
//! routes. Callers need no client certificate: the machine checks their
//! papers itself.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::{Config, MachineName};

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

/// The relay's TLS setup: the rustls configuration, and the device
/// certificate verifier inside it, kept so certificates can be checked
/// again during a connection (expiry, a new revocation list).
#[derive(Clone)]
pub struct Setup {
    pub config: Arc<rustls::ServerConfig>,
    pub verifier: Arc<dyn ClientCertVerifier>,
}

impl Setup {
    /// Whether a device certificate chain (leaf first) is valid now: signed
    /// by the configured roots, in its validity period, not revoked.
    pub fn still_valid(&self, chain: &[CertificateDer<'static>]) -> bool {
        match chain.split_first() {
            Some((leaf, rest)) => self
                .verifier
                .verify_client_cert(leaf, rest, UnixTime::now())
                .is_ok(),
            None => false,
        }
    }
}

/// The relay's TLS setup from its config.
pub fn server_config(cfg: &Config) -> io::Result<Setup> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in certs(&cfg.device_ca)? {
        roots.add(c).map_err(|e| err(&cfg.device_ca, e))?;
    }
    let mut all_crls = Vec::new();
    for p in &cfg.device_crls {
        all_crls.extend(crls(p)?);
    }
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .allow_unauthenticated();
    if !all_crls.is_empty() {
        // Revocation is checked for the device certificate only (the lists
        // MDM tools publish are the issuing CA's), and a list past its
        // next-update time no longer counts, so a stale list fails closed.
        builder = builder
            .with_crls(all_crls)
            .only_check_end_entity_revocation()
            .enforce_revocation_expiration();
    }
    let verifier = builder.build().map_err(io::Error::other)?;
    let kept = verifier.clone();
    let key = PrivateKeyDer::from_pem_file(&cfg.tls_key).map_err(|e| err(&cfg.tls_key, e))?;
    let mut sc = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(&cfg.tls_cert)?, key)
        .map_err(io::Error::other)?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    // No session resumption: a resumed session would bring back a device
    // certificate without checking it against today's roots and lists.
    sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    sc.send_tls13_tickets = 0;
    Ok(Setup {
        config: Arc::new(sc),
        verifier: kept,
    })
}

/// The machine address in a verified device certificate, or why there is none.
/// rustls has already checked the chain, the dates, the key usage and the
/// revocation lists; this only reads the name.
pub fn machine_name(cert: &CertificateDer<'_>, which: MachineName) -> Result<String, String> {
    let (_, x) = X509Certificate::from_der(cert.as_ref())
        .map_err(|e| format!("unreadable certificate: {e}"))?;
    let names: Vec<String> = match which {
        MachineName::Cn => x
            .subject()
            .iter_common_name()
            .map(|a| {
                a.as_str()
                    .map(str::to_string)
                    .map_err(|_| "the common name is not a string".to_string())
            })
            .collect::<Result<_, _>>()?,
        MachineName::Dns | MachineName::Uri => {
            let san = x
                .subject_alternative_name()
                .map_err(|e| format!("unreadable subject alternative names: {e}"))?;
            san.map(|s| {
                s.value
                    .general_names
                    .iter()
                    .filter_map(|g| match (which, g) {
                        (MachineName::Dns, GeneralName::DNSName(n)) => Some(n.to_string()),
                        (MachineName::Uri, GeneralName::URI(n)) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
        }
    };
    let what = match which {
        MachineName::Cn => "common name",
        MachineName::Dns => "DNS name",
        MachineName::Uri => "URI",
    };
    match names.as_slice() {
        [] => Err(format!("the certificate has no {what}")),
        [one] if actp_proto::relay::valid_machine_name(one) => Ok(one.clone()),
        [one] => Err(format!(
            "the certificate's {what} {one:?} is not a valid machine address"
        )),
        _ => Err(format!("the certificate has more than one {what}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

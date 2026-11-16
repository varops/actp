//! TLS for the relay: its own certificate, and device certificates from the
//! org's roots, asked of every client but required only on the machine
//! routes. Callers need no client certificate: the machine checks their
//! papers itself.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
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

/// The relay's rustls configuration from its config.
pub fn server_config(cfg: &Config) -> io::Result<Arc<rustls::ServerConfig>> {
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
    let key = PrivateKeyDer::from_pem_file(&cfg.tls_key).map_err(|e| err(&cfg.tls_key, e))?;
    let mut sc = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(&cfg.tls_cert)?, key)
        .map_err(io::Error::other)?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(sc))
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

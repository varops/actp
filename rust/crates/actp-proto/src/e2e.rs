//! End-to-end TLS between a caller and a machine, through the relay
//! (docs/relay.md).
//!
//! The relay carries a caller's bytes to the machine and back, and nothing
//! it carries can be read or changed on the way. Inside the relayed stream
//! the caller opens TLS 1.3 straight to the machine:
//!
//! - The machine answers with its device certificate ([`server_config`]),
//!   the one it logs in to the relay with.
//! - The caller checks that certificate against the organization's device
//!   roots, and checks that it names exactly the machine the caller asked
//!   for ([`client_config`]). A relay that sends the caller anywhere else,
//!   or answers itself, fails the handshake.
//!
//! Credentials (actp tokens, signed papers) travel inside that TLS, so the
//! relay never sees them.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::relay::valid_machine_name;

/// ALPN of the end-to-end TLS. A machine answers nothing else, so a stream
/// that is not this protocol fails the handshake.
pub const ALPN: &[u8] = b"actp-e2e.v1";

/// The server name the caller sends. Machine addresses are not always DNS
/// names, so the name is fixed and the machine is checked in the
/// certificate instead ([`client_config`]).
pub const SERVER_NAME: &str = "machine.actp.invalid";

/// Which name in a device certificate is the machine's address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineName {
    /// The subject's common name (the default; MDM tools usually put the
    /// serial number or the computer name here).
    #[default]
    Cn,
    /// The one DNS name in the subject alternative names.
    Dns,
    /// The one URI in the subject alternative names.
    Uri,
}

/// The machine address in a device certificate, or why there is none. Only
/// reads the name; the chain, dates, key usage and revocation are checked
/// elsewhere.
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
        [one] if valid_machine_name(one) => Ok(one.clone()),
        [one] => Err(format!(
            "the certificate's {what} {one:?} is not a valid machine address"
        )),
        _ => Err(format!("the certificate has more than one {what}")),
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The machine's side: TLS 1.3 with its device certificate (leaf first,
/// then intermediates), [`ALPN`] only, no client certificate (callers prove
/// themselves inside, with tokens or papers), no session resumption.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
    let mut sc = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    sc.alpn_protocols = vec![ALPN.to_vec()];
    sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    sc.send_tls13_tickets = 0;
    Ok(Arc::new(sc))
}

/// The caller's side, for one machine: TLS 1.3, [`ALPN`] only, and a
/// certificate check that accepts exactly a device certificate under
/// `device_roots`, not revoked by `device_crls` (end entity only; a list
/// past its next-update time fails closed, as at the relay), whose
/// `which` name is `machine`.
pub fn client_config(
    device_roots: &[CertificateDer<'_>],
    device_crls: &[CertificateRevocationListDer<'_>],
    which: MachineName,
    machine: &str,
) -> Result<Arc<rustls::ClientConfig>, String> {
    if !valid_machine_name(machine) {
        return Err(format!("{machine:?} is not a valid machine address"));
    }
    let roots = device_roots
        .iter()
        .map(|c| {
            webpki::anchor_from_trusted_cert(c)
                .map(|a| a.to_owned())
                .map_err(|e| format!("a device root: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if roots.is_empty() {
        return Err("no device roots".into());
    }
    let crls = device_crls
        .iter()
        .map(|c| {
            webpki::OwnedCertRevocationList::from_der(c.as_ref())
                .map_err(|e| format!("a device revocation list: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provider = provider();
    let verifier = Arc::new(MachineVerifier {
        roots,
        crls,
        which,
        machine: machine.to_string(),
        algorithms: provider.signature_verification_algorithms,
    });
    let mut cc = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];
    cc.resumption = rustls::client::Resumption::disabled();
    cc.enable_sni = false;
    Ok(Arc::new(cc))
}

/// The server name to connect with under [`client_config`].
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("a valid DNS name")
}

#[derive(Debug)]
struct MachineVerifier {
    roots: Vec<TrustAnchor<'static>>,
    crls: Vec<webpki::OwnedCertRevocationList>,
    which: MachineName,
    machine: String,
    algorithms: WebPkiSupportedAlgorithms,
}

fn invalid(e: CertificateError) -> rustls::Error {
    rustls::Error::InvalidCertificate(e)
}

impl ServerCertVerifier for MachineVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| invalid(CertificateError::BadEncoding))?;
        let crls: Vec<webpki::CertRevocationList<'_>> = self
            .crls
            .iter()
            .map(|c| webpki::CertRevocationList::from(c.clone()))
            .collect();
        let crl_refs: Vec<&webpki::CertRevocationList<'_>> = crls.iter().collect();
        let revocation = match crl_refs.is_empty() {
            true => None,
            false => Some(
                webpki::RevocationOptionsBuilder::new(&crl_refs)
                    .map_err(|_| invalid(CertificateError::BadEncoding))?
                    .with_depth(webpki::RevocationCheckDepth::EndEntity)
                    .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                    .build(),
            ),
        };
        // Device certificates are client certificates (they log machines
        // in to the relay), so they are checked for client use: the same
        // certificates the relay accepts as machines.
        cert.verify_for_usage(
            self.algorithms.all,
            &self.roots,
            intermediates,
            now,
            webpki::KeyUsage::client_auth(),
            revocation,
            None,
        )
        .map_err(|e| {
            invalid(match e {
                webpki::Error::CertExpired { .. } => CertificateError::Expired,
                webpki::Error::CertNotValidYet { .. } => CertificateError::NotValidYet,
                webpki::Error::CertRevoked => CertificateError::Revoked,
                webpki::Error::UnknownIssuer => CertificateError::UnknownIssuer,
                _ => CertificateError::ApplicationVerificationFailure,
            })
        })?;
        match machine_name(end_entity, self.which) {
            Ok(name) if name == self.machine => Ok(ServerCertVerified::assertion()),
            _ => Err(invalid(CertificateError::NotValidForName)),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Only TLS 1.3 is offered.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

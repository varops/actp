//! `actp-relay.yaml`. Unknown keys are refused.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The relay's configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the relay listens (machines and callers alike), for example `0.0.0.0:443`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The relay's own certificate (PEM, leaf first) and key.
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    /// The roots that sign the org's device certificates (PEM). Only machines
    /// with a certificate from these roots can connect.
    pub device_ca: PathBuf,
    /// Certificate revocation lists for device certificates (PEM or DER files).
    #[serde(default)]
    pub device_crls: Vec<PathBuf>,
    /// Which name in the device certificate is the machine's address.
    #[serde(default)]
    pub machine_name: MachineName,
    /// Addresses refused even with a valid certificate (a lost laptop before
    /// its certificate is revoked).
    #[serde(default)]
    pub blocked_machines: Vec<String>,
    /// The roots that sign caller certificates (PEM): the IT client and
    /// anything else allowed to open tunnels to machines. Must not share a
    /// root with `device_ca`.
    pub caller_ca: PathBuf,
    /// Certificate revocation lists for caller certificates.
    #[serde(default)]
    pub caller_crls: Vec<PathBuf>,
    /// Which name in a caller certificate names the caller (in the audit).
    #[serde(default)]
    pub caller_name: MachineName,
    /// Callers refused even with a valid certificate.
    #[serde(default)]
    pub blocked_callers: Vec<String>,
    /// The org-wide stop and who was seen when.
    pub state_dir: PathBuf,
    /// `audit.jsonl` goes here.
    pub log_dir: PathBuf,
    /// Tokens for the management API (`/relay/v1/machines`, the stop). Each
    /// has a name, recorded with every stop and release, and a SHA-256 hash.
    #[serde(default)]
    pub admin_tokens: Vec<AdminToken>,
    /// Callers with a role at the relay itself, by the name in their caller
    /// certificate: who may see who is online, read the audit, and press or
    /// release the org-wide stop. None by default: a caller certificate
    /// opens tunnels and nothing else.
    #[serde(default)]
    pub operators: Vec<Operator>,
    /// Callers served at once per machine, waiting ones included.
    #[serde(default = "default_max_streams")]
    pub max_streams_per_machine: usize,
    /// Streams one caller (by its certificate name) may have to one machine
    /// at once, so a stolen caller certificate cannot hold all of them.
    #[serde(default = "default_max_streams_per_caller")]
    pub max_streams_per_caller: usize,
    /// Requests per caller IP address to machines and the management API.
    #[serde(default)]
    pub caller_rate: Rate,
    /// `audit.jsonl` is rotated at this size (100 MB); ten old files are kept.
    #[serde(default = "default_audit_max_mb")]
    pub audit_max_mb: u64,
    /// Connections the relay holds at once (20000), and per IP address
    /// (1000: an office behind one NAT address counts as one).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// Off (0) by default: a machine moves its pin to a new key by key
    /// continuity, with the old key's signature, or an admin re-pins it.
    /// Set, how close to its expiry (days) a machine's pinned certificate
    /// must be for a newer certificate with a new key to be taken as its
    /// renewal without that proof (at most 90; warned about at start).
    #[serde(default = "default_key_renewal_days")]
    pub machine_key_renewal_days: u64,
    /// Device connections held at once per machine, before any becomes a
    /// stream (64).
    #[serde(default = "default_max_connections_per_machine")]
    pub max_connections_per_machine: usize,
    /// A tunnel that carries nothing either way for this long is cut (600 s,
    /// at least 60): a peer gone quiet without closing. Live sessions
    /// carry heartbeats, and the machine closes idle HTTP connections itself.
    #[serde(default = "default_tunnel_idle_seconds")]
    pub tunnel_idle_seconds: u64,
    /// The issuer pass-through: questions machines may ask the identity
    /// service through the relay. Off when absent.
    #[serde(default)]
    pub issuer: Option<Issuer>,
}

/// The identity service machines may ask through the relay.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// `https://host[:port][/prefix]` (`http://` on loopback only).
    pub url: String,
    /// Roots for its certificate (PEM); required for `https://`.
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// Sent with every forwarded question: the relay's own credentials
    /// there. A value `env:NAME` is read from that environment variable.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// The only paths forwarded, exactly (no query).
    pub paths: Vec<String>,
    /// Questions per machine (1 a second, 10 at once by default).
    #[serde(default = "default_issuer_rate")]
    pub rate: Rate,
    /// How long one question may take (5 s).
    #[serde(default = "default_issuer_timeout")]
    pub timeout_seconds: u64,
}

impl std::fmt::Debug for Issuer {
    // Header values can be secrets: their names only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("url", &self.url)
            .field("ca", &self.ca)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("paths", &self.paths)
            .field("rate", &self.rate)
            .field("timeout_seconds", &self.timeout_seconds)
            .finish()
    }
}

fn default_key_renewal_days() -> u64 {
    0
}

fn default_max_connections_per_machine() -> usize {
    64
}

fn default_tunnel_idle_seconds() -> u64 {
    600
}

fn default_issuer_rate() -> Rate {
    Rate {
        per_second: 1,
        burst: 10,
    }
}

fn default_issuer_timeout() -> u64 {
    5
}

fn default_max_connections() -> usize {
    20_000
}

fn default_max_connections_per_ip() -> usize {
    1_000
}

/// A rate: so many per second on average, up to `burst` at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    pub per_second: u32,
    pub burst: u32,
}

impl Default for Rate {
    fn default() -> Self {
        Rate {
            per_second: 20,
            burst: 60,
        }
    }
}

fn default_audit_max_mb() -> u64 {
    100
}

fn default_listen() -> String {
    "0.0.0.0:443".into()
}

fn default_max_streams() -> usize {
    32
}

fn default_max_streams_per_caller() -> usize {
    8
}

/// Which certificate name identifies a machine (and a caller).
pub use actp_proto::e2e::MachineName;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminToken {
    pub name: String,
    /// `sha256:<hex>` of the token.
    pub hash: String,
}

/// A caller with a role at the relay ([`Config::operators`]).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    /// The caller's name, as `caller_name` reads it from its certificate.
    pub caller: String,
    /// What it may do; at least one.
    pub may: Vec<Permission>,
    /// When set, only these certificates (SHA-256 of the DER, as
    /// `sha256:<hex>`) count as this operator: another certificate with the
    /// same name, from any root in `caller_ca`, does not. Empty: any valid
    /// caller certificate with the name.
    #[serde(default)]
    pub certificates: Vec<String>,
}

/// What an operator may do at the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// `GET /relay/v1/machines`: who is online, and when each was last seen.
    Machines,
    /// `GET /relay/v1/audit`: the relay's half of the audit.
    Audit,
    /// `POST /relay/v1/stop`: press the org-wide stop.
    Stop,
    /// `POST /relay/v1/release`: release it.
    Release,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Machines => "machines",
            Permission::Audit => "audit",
            Permission::Stop => "stop",
            Permission::Release => "release",
        }
    }
}

impl Config {
    /// The operator entry for the caller named `caller`.
    pub fn operator_entry(&self, caller: &str) -> Option<&Operator> {
        self.operators.iter().find(|o| o.caller == caller)
    }

    /// What the caller named `caller` may do at the relay; empty when it is
    /// not an operator.
    pub fn operator(&self, caller: &str) -> &[Permission] {
        self.operators
            .iter()
            .find(|o| o.caller == caller)
            .map(|o| o.may.as_slice())
            .unwrap_or(&[])
    }

    pub fn audit_max_bytes(&self) -> u64 {
        self.audit_max_mb.saturating_mul(1 << 20)
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let cfg = Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg: Config = serde_norway::from_str(text).map_err(|e| e.to_string())?;
        // hash_token writes lowercase hex; tools such as Get-FileHash write
        // uppercase. Both mean the same token.
        for t in &mut cfg.admin_tokens {
            t.hash = t.hash.to_ascii_lowercase();
        }
        for o in &mut cfg.operators {
            for c in &mut o.certificates {
                *c = c.to_ascii_lowercase();
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut errs = Vec::new();
        let mut names = std::collections::HashSet::new();
        for t in &self.admin_tokens {
            if t.name.is_empty() {
                errs.push("every admin token needs a name".to_string());
            } else if !names.insert(&t.name) {
                errs.push(format!("admin token {:?} is defined twice", t.name));
            }
            if !valid_hash(&t.hash) {
                errs.push(format!(
                    "admin token {:?}: hash must be sha256:<64 hex digits>",
                    t.name
                ));
            }
        }
        if self.caller_rate.per_second == 0 || self.caller_rate.burst == 0 {
            errs.push("caller_rate per_second and burst must be at least 1".into());
        }
        if self.max_connections == 0 || self.max_connections_per_ip == 0 {
            errs.push("max_connections and max_connections_per_ip must be at least 1".into());
        }
        if self.audit_max_mb == 0 {
            errs.push("audit_max_mb must be at least 1".into());
        }
        if self.max_streams_per_machine == 0 || self.max_streams_per_caller == 0 {
            errs.push(
                "max_streams_per_machine and max_streams_per_caller must be at least 1".into(),
            );
        }
        // Longer would leave a name open to a new key most of the time.
        if self.machine_key_renewal_days > 90 {
            errs.push("machine_key_renewal_days must be at most 90".into());
        }
        if self.max_connections_per_machine == 0 {
            errs.push("max_connections_per_machine must be at least 1".into());
        }
        // Below a minute, a session between heartbeats could be cut.
        if self.tunnel_idle_seconds < 60 {
            errs.push("tunnel_idle_seconds must be at least 60".into());
        }
        if let Some(i) = &self.issuer {
            if i.paths.is_empty() {
                errs.push("issuer.paths must name at least one path".into());
            }
            for p in &i.paths {
                let ok = p.starts_with('/')
                    && p.len() <= 256
                    && !p.contains("//")
                    && !p.split('/').any(|seg| seg == ".." || seg == ".")
                    && p.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.')
                    });
                if !ok {
                    errs.push(format!(
                        "issuer path {p:?} must start with / and hold only letters, digits, /, -, _ and ."
                    ));
                }
            }
            if i.rate.per_second == 0 || i.rate.burst == 0 {
                errs.push("issuer.rate per_second and burst must be at least 1".into());
            }
            if i.timeout_seconds == 0 || i.timeout_seconds > 30 {
                errs.push("issuer.timeout_seconds must be 1 to 30".into());
            }
        }
        let mut ops = std::collections::HashSet::new();
        for o in &self.operators {
            if !actp_proto::relay::valid_machine_name(&o.caller) {
                errs.push(format!(
                    "operator {:?} is not a valid caller name",
                    o.caller
                ));
            } else if !ops.insert(&o.caller) {
                errs.push(format!("operator {:?} is listed twice", o.caller));
            }
            for c in &o.certificates {
                if !valid_hash(c) {
                    errs.push(format!(
                        "operator {:?}: certificates are sha256:<64 lowercase hex digits>",
                        o.caller
                    ));
                }
            }
            if o.may.is_empty() {
                errs.push(format!(
                    "operator {:?}: may must name at least one of machines, audit, stop, release",
                    o.caller
                ));
            }
        }
        for c in &self.blocked_callers {
            if !actp_proto::relay::valid_machine_name(c) {
                errs.push(format!("blocked caller {c:?} is not a valid caller name"));
            }
        }
        for m in &self.blocked_machines {
            if !actp_proto::relay::valid_machine_name(m) {
                errs.push(format!(
                    "blocked machine {m:?} is not a valid machine address"
                ));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

fn valid_hash(h: &str) -> bool {
    // Lowercase, as hash_token writes it: an uppercase hash would never match.
    h.strip_prefix("sha256:")
        .is_some_and(|x| x.len() == 64 && x.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// `sha256:<hex>` of a token, as the config stores it.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    )
}

/// A new admin token: `actpr_` and 32 random bytes in base64url.
pub fn generate_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    format!(
        "actpr_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "tls_cert: r.pem\ntls_key: r.key\ndevice_ca: ca.pem\ncaller_ca: callers.pem\nstate_dir: s\nlog_dir: l\n";

    #[test]
    fn defaults_and_strictness() {
        let c = Config::parse(BASE).unwrap();
        assert_eq!(c.listen, "0.0.0.0:443");
        assert_eq!(c.machine_name, MachineName::Cn);
        assert_eq!(c.max_streams_per_machine, 32);
        assert!(Config::parse(&format!("{BASE}lisen: x\n")).is_err());
        assert!(Config::parse(&format!("{BASE}machine_name: serial\n")).is_err());
        assert!(Config::parse("listen: x\n").is_err());
        // Callers need their own roots.
        assert!(Config::parse(&BASE.replace("caller_ca: callers.pem\n", "")).is_err());
        assert!(Config::parse(&format!("{BASE}blocked_callers: [\"a/b\"]\n")).is_err());
        assert_eq!(
            Config::parse(&format!("{BASE}caller_name: uri\n"))
                .unwrap()
                .caller_name,
            MachineName::Uri
        );
        let t = generate_token();
        let ok = format!(
            "{BASE}admin_tokens:\n  - name: dave\n    hash: {}\n",
            hash_token(&t)
        );
        assert!(Config::parse(&ok).is_ok());
        let twice = format!(
            "{BASE}admin_tokens:\n  - name: dave\n    hash: {h}\n  - name: dave\n    hash: {h}\n",
            h = hash_token(&t)
        );
        assert!(Config::parse(&twice).is_err());
        assert!(
            Config::parse(&format!(
                "{BASE}admin_tokens:\n  - name: x\n    hash: sha256:00\n"
            ))
            .is_err()
        );
        assert!(Config::parse(&format!("{BASE}blocked_machines: [\"a/b\"]\n")).is_err());
    }

    #[test]
    fn operators() {
        let c = Config::parse(&format!(
            "{BASE}operators:\n  - caller: it-bridge\n    may: [machines, audit, stop, release]\n  - caller: manager\n    may: [machines]\n"
        ))
        .unwrap();
        assert_eq!(c.operator("it-bridge").len(), 4);
        assert_eq!(c.operator("manager"), &[Permission::Machines]);
        // Not listed: nothing. Names are compared exactly.
        assert!(c.operator("IT-bridge").is_empty());
        assert!(c.operator("").is_empty());
        assert!(
            Config::parse(BASE)
                .unwrap()
                .operator("it-bridge")
                .is_empty()
        );
        for bad in [
            "operators:\n  - caller: a\n    may: []\n",
            "operators:\n  - caller: a\n",
            "operators:\n  - caller: a\n    may: [everything]\n",
            "operators:\n  - caller: a/b\n    may: [audit]\n",
            "operators:\n  - caller: a\n    may: [audit]\n  - caller: a\n    may: [stop]\n",
            "operators:\n  - caller: a\n    may: [audit]\n    role: admin\n",
            "operators:\n  - caller: a\n    may: [audit]\n    certificates: [abc]\n",
        ] {
            assert!(Config::parse(&format!("{BASE}{bad}")).is_err(), "{bad}");
        }
    }
}

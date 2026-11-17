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

impl Config {
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
}

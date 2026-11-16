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
    /// Requests per caller IP address to machines and the management API.
    #[serde(default)]
    pub caller_rate: Rate,
    /// `audit.jsonl` is rotated at this size (100 MB); ten old files are kept.
    #[serde(default = "default_audit_max_mb")]
    pub audit_max_mb: u64,
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

/// Which certificate name identifies a machine.
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
        let cfg: Config = serde_norway::from_str(text).map_err(|e| e.to_string())?;
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
        if self.audit_max_mb == 0 {
            errs.push("audit_max_mb must be at least 1".into());
        }
        if self.max_streams_per_machine == 0 {
            errs.push("max_streams_per_machine must be at least 1".into());
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
    h.strip_prefix("sha256:")
        .is_some_and(|x| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit()))
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

    const BASE: &str =
        "tls_cert: r.pem\ntls_key: r.key\ndevice_ca: ca.pem\nstate_dir: s\nlog_dir: l\n";

    #[test]
    fn defaults_and_strictness() {
        let c = Config::parse(BASE).unwrap();
        assert_eq!(c.listen, "0.0.0.0:443");
        assert_eq!(c.machine_name, MachineName::Cn);
        assert_eq!(c.max_streams_per_machine, 32);
        assert!(Config::parse(&format!("{BASE}lisen: x\n")).is_err());
        assert!(Config::parse(&format!("{BASE}machine_name: serial\n")).is_err());
        assert!(Config::parse("listen: x\n").is_err());
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

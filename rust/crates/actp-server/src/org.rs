//! Org mode (docs/relay.md): callers present signed papers from the
//! organization's identity service instead of actp tokens, and this machine
//! checks them itself. Nothing on the way, the relay included, vouches for
//! a caller.
//!
//! Checking the papers is split in two:
//!
//! - A [`PapersVerifier`], supplied by the program that embeds the server,
//!   knows the issuer: its keys and signature format, freshness, and whether
//!   the person is still who the papers say (revocation). It answers with the
//!   [`Caller`] the papers describe, or a refusal. actp ships no verifier for
//!   any real issuer; [`testing::SharedSecret`] is for tests.
//! - actp then checks, whatever the verifier: that the papers name this
//!   machine (`org.machine`), and that they grant `org.require_grant` as
//!   exactly `true`.
//!
//! The caller gets `org.access` under the name `papers:<caller id>`, so only
//! the same person can resume a link, and link limits count per person.

use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value};

use crate::auth::Refused;
use crate::config::{Org, Token};

/// Who the papers say the caller is, as the verifier read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The person's stable id at the issuer.
    pub id: String,
    /// The machine the papers are meant for (its relay address).
    pub machine: String,
    /// What the papers grant: name → value.
    pub grants: Map<String, Value>,
}

pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<Caller, Refused>> + Send + 'a>>;

/// Checks papers against their issuer. `machine` is this machine's address;
/// a verifier for an issuer that binds papers to a machine checks it too.
///
/// `verify` must return its future at once and do the work inside it, without
/// blocking: the time limit covers the future only. A verifier that asks its
/// issuer online should cache answers or limit its requests, since anyone who
/// can reach the machine can present papers.
///
/// Refuse on anything doubtful: a bad signature, expired papers, an issuer
/// that cannot be asked whether the papers still hold. Refusal codes are
/// written to the audit log, so they must not carry the papers themselves.
/// Set [`Refused::principal`] only once the papers are known to be genuine.
pub trait PapersVerifier: Send + Sync + 'static {
    fn verify<'a>(&'a self, papers: &'a str, machine: &'a str) -> VerifyFuture<'a>;
}

/// The token name of a caller who came in with papers.
pub fn token_name(caller_id: &str) -> String {
    format!("papers:{caller_id}")
}

/// Papers larger than this are refused before the verifier sees them.
pub const MAX_PAPERS: usize = 32 << 10;

/// How long a verifier may take before the papers count as not checked.
pub const VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether a caller id is fit for a token name and the audit log: 1 to 256
/// characters of letters, digits and `.`, `_`, `-`, `@`, `+`, `:`, `=`.
pub fn valid_caller_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b'+' | b':' | b'=')
        })
}

/// The access a caller presenting `papers` gets in org mode, or why not.
pub async fn authenticate(
    verifier: Option<&dyn PapersVerifier>,
    org: &Org,
    papers: &str,
    timeout: std::time::Duration,
) -> Result<Token, Refused> {
    let Some(verifier) = verifier else {
        return Err(Refused::new("no_papers_verifier"));
    };
    // A validated config never has these empty; refuse rather than let an
    // empty value match a verifier's empty answer.
    if org.machine.is_empty() || org.require_grant.is_empty() {
        return Err(Refused::new("org_misconfigured"));
    }
    if papers.is_empty() || papers.len() > MAX_PAPERS {
        return Err(Refused::new("papers_malformed"));
    }
    let caller = match tokio::time::timeout(timeout, verifier.verify(papers, &org.machine)).await {
        Err(_) => return Err(Refused::temporary("verifier_timeout")),
        Ok(Err(mut r)) => {
            // The verifier's word about who it was, only if fit to log.
            if r.principal.as_deref().is_some_and(|p| !valid_caller_id(p)) {
                r.principal = None;
            }
            return Err(r);
        }
        Ok(Ok(c)) => c,
    };
    if !valid_caller_id(&caller.id) {
        return Err(Refused::new("papers_malformed"));
    }
    let refuse = |code: &'static str| Refused {
        principal: Some(caller.id.clone()),
        ..Refused::new(code)
    };
    if caller.machine.is_empty() || caller.machine != org.machine {
        return Err(refuse("papers_other_machine"));
    }
    if caller.grants.get(&org.require_grant) != Some(&Value::Bool(true)) {
        return Err(refuse("papers_no_grant"));
    }
    Ok(Token {
        name: token_name(&caller.id),
        hash: String::new(),
        ..org.access.clone()
    })
}

/// A verifier for tests and examples only, behind the `testing` feature.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256};

    use super::{Caller, PapersVerifier, VerifyFuture};
    use crate::auth::Refused;

    /// Papers signed with a shared secret (HMAC-SHA256):
    /// `base64url(json).hex(mac)`, where the JSON names the caller, the
    /// machine, the grants and an expiry in Unix seconds. **For tests only**:
    /// anyone who can verify these papers can also issue them.
    pub struct SharedSecret {
        secret: Vec<u8>,
        /// While set, every check fails as if the issuer could not be asked.
        pub unavailable: AtomicBool,
    }

    fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        inner.update(k.map(|b| b ^ 0x36));
        inner.update(msg);
        let mut outer = Sha256::new();
        outer.update(k.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    impl SharedSecret {
        pub fn new(secret: &[u8]) -> Self {
            SharedSecret {
                secret: secret.to_vec(),
                unavailable: AtomicBool::new(false),
            }
        }

        /// Signs papers for `caller` on `machine`, valid for `ttl`.
        pub fn issue(&self, caller: &str, machine: &str, grants: Value, ttl: Duration) -> String {
            self.sign(&json!({
                "caller": caller,
                "machine": machine,
                "grants": grants,
                "expires": now() + ttl.as_secs(),
            }))
        }

        /// Signs any body, for tests of malformed papers.
        pub fn sign(&self, body: &Value) -> String {
            let raw = body.to_string();
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(&raw),
                hex::encode(hmac(&self.secret, raw.as_bytes()))
            )
        }

        fn check(&self, papers: &str) -> Result<Caller, Refused> {
            let (body, mac) = papers
                .split_once('.')
                .ok_or(Refused::new("papers_malformed"))?;
            let raw = URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Refused::new("papers_malformed"))?;
            let mac = hex::decode(mac).map_err(|_| Refused::new("papers_malformed"))?;
            let want = hmac(&self.secret, &raw);
            if mac.len() != want.len()
                || mac.iter().zip(want).fold(0u8, |d, (a, b)| d | (a ^ b)) != 0
            {
                return Err(Refused::new("papers_signature"));
            }
            let v: Value =
                serde_json::from_slice(&raw).map_err(|_| Refused::new("papers_malformed"))?;
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let (Some(id), Some(machine), Some(expires)) = (
                s("caller"),
                s("machine"),
                v.get("expires").and_then(Value::as_u64),
            ) else {
                return Err(Refused::new("papers_malformed"));
            };
            if now() >= expires {
                return Err(Refused {
                    principal: Some(id),
                    ..Refused::new("papers_expired")
                });
            }
            let grants: Map<String, Value> = match v.get("grants") {
                Some(Value::Object(m)) => m.clone(),
                None | Some(Value::Null) => Map::new(),
                Some(_) => return Err(Refused::new("papers_malformed")),
            };
            Ok(Caller {
                id,
                machine,
                grants,
            })
        }
    }

    impl PapersVerifier for SharedSecret {
        fn verify<'a>(&'a self, papers: &'a str, _machine: &'a str) -> VerifyFuture<'a> {
            let r = if self.unavailable.load(Ordering::SeqCst) {
                Err(Refused::temporary("issuer_unavailable"))
            } else {
                self.check(papers)
            };
            Box::pin(async move { r })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use std::sync::Arc;

    use super::testing::SharedSecret;
    use super::*;

    fn org() -> Org {
        Org {
            machine: "laptop-a".into(),
            require_grant: "machines.operate".into(),
            access: Token {
                agents: vec!["*".into()],
                max_links: 8,
                ..Default::default()
            },
        }
    }

    async fn check(v: &SharedSecret, papers: &str) -> Result<Token, Refused> {
        authenticate(Some(v), &org(), papers, VERIFY_TIMEOUT).await
    }

    fn org_config(dir: &std::path::Path) -> crate::config::Server {
        let yaml = format!(
            "server:\n  log_dir: '{d}/logs'\n  state_dir: '{d}/state'\n  tokens_file: '{d}/tokens.yaml'\n  workspaces:\n    - name: it\n      path: '{d}'\n  agents:\n    - id: a\n      command: x\n  org:\n    machine: laptop-a\n    require_grant: machines.operate\n    access:\n      agents: [a]\n",
            d = dir.display()
        );
        let c = crate::config::Config::parse(&yaml).unwrap();
        c.validate().unwrap();
        c.server.unwrap()
    }

    #[tokio::test]
    async fn org_mode_needs_a_verifier_at_start_and_on_reload() {
        let dir = std::env::temp_dir().join(format!("actp-org-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let opts = || crate::Options {
            base_env: Some(Vec::new()),
            read_only: true,
            ..Default::default()
        };
        let sc = org_config(&dir);
        assert!(crate::Server::new(sc.clone(), opts()).await.is_err());

        // A server in token mode, reloaded into org mode without a verifier,
        // keeps its old config.
        let mut tokens = sc.clone();
        tokens.org = None;
        let srv = crate::Server::new(tokens, opts()).await.unwrap();
        srv.reload(sc.clone());
        assert!(srv.config().org.is_none());

        // With a verifier it starts, and refuses papers while the relay
        // knows it by another name.
        let v = Arc::new(SharedSecret::new(b"k"));
        let srv = crate::Server::new(
            sc,
            crate::Options {
                papers_verifier: Some(v.clone()),
                ..opts()
            },
        )
        .await
        .unwrap();
        let p = v.issue(
            "dave",
            "laptop-a",
            json!({"machines.operate": true}),
            Duration::from_secs(60),
        );
        assert!(srv.authenticate(&p).await.is_ok());
        srv.set_relay_machine("laptop-b");
        assert_eq!(
            srv.authenticate(&p).await.unwrap_err().code,
            "org_machine_mismatch"
        );
        srv.set_relay_machine("laptop-a");
        assert!(srv.authenticate(&p).await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A verifier that never answers.
    struct Hangs;

    impl PapersVerifier for Hangs {
        fn verify<'a>(&'a self, _: &'a str, _: &'a str) -> VerifyFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_verifier_that_hangs_is_a_temporary_refusal() {
        let r = authenticate(Some(&Hangs), &org(), "papers", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!((r.code, r.temporary), ("verifier_timeout", true));
    }

    #[tokio::test]
    async fn checks_machine_and_grant_whatever_the_verifier() {
        let v = SharedSecret::new(b"secret");
        let ok = v.issue(
            "dave",
            "laptop-a",
            json!({"machines.operate": true}),
            Duration::from_secs(60),
        );
        let t = check(&v, &ok).await.unwrap();
        assert_eq!(
            (t.name.as_str(), t.agents.as_slice()),
            ("papers:dave", &["*".to_string()][..])
        );

        for (papers, want) in [
            (
                v.issue(
                    "dave",
                    "laptop-b",
                    json!({"machines.operate": true}),
                    Duration::from_secs(60),
                ),
                "papers_other_machine",
            ),
            (
                v.issue("dave", "laptop-a", json!({}), Duration::from_secs(60)),
                "papers_no_grant",
            ),
            (
                v.issue(
                    "dave",
                    "laptop-a",
                    json!({"machines.operate": "yes"}),
                    Duration::from_secs(60),
                ),
                "papers_no_grant",
            ),
            (
                v.issue(
                    "dave",
                    "laptop-a",
                    json!({"machines.operate": true}),
                    Duration::ZERO,
                ),
                "papers_expired",
            ),
            (
                SharedSecret::new(b"other").issue(
                    "dave",
                    "laptop-a",
                    json!({"machines.operate": true}),
                    Duration::from_secs(60),
                ),
                "papers_signature",
            ),
            (
                v.issue(
                    "",
                    "laptop-a",
                    json!({"machines.operate": true}),
                    Duration::from_secs(60),
                ),
                "papers_malformed",
            ),
            (
                v.issue(
                    "a\nb",
                    "laptop-a",
                    json!({"machines.operate": true}),
                    Duration::from_secs(60),
                ),
                "papers_malformed",
            ),
            ("x".repeat(MAX_PAPERS + 1), "papers_malformed"),
            ("not.papers".into(), "papers_malformed"),
        ] {
            assert_eq!(check(&v, &papers).await.unwrap_err().code, want, "{papers}");
        }
        let r = check(
            &v,
            &v.issue("dave", "laptop-b", json!({}), Duration::from_secs(60)),
        )
        .await;
        assert_eq!(r.unwrap_err().principal.as_deref(), Some("dave"));
        for (id, machine) in [
            ("dave\u{202e}", "laptop-a"),
            ("da ve", "laptop-a"),
            ("dave", ""),
        ] {
            let p = v.issue(
                id,
                machine,
                json!({"machines.operate": true}),
                Duration::from_secs(60),
            );
            assert!(check(&v, &p).await.is_err(), "{id:?} on {machine:?}");
        }
        v.unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let r = check(&v, &ok).await.unwrap_err();
        assert_eq!((r.code, r.temporary), ("issuer_unavailable", true));
        assert_eq!(
            authenticate(None, &org(), &ok, VERIFY_TIMEOUT)
                .await
                .unwrap_err()
                .code,
            "no_papers_verifier"
        );
    }
}

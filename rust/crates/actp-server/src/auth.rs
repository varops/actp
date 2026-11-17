//! Who a bearer token belongs to. Pluggable, so other token formats can be
//! accepted next to, or instead of, actp's own hashed tokens. Org mode
//! ([`crate::org`]) accepts signed caller papers instead of tokens.

use std::future::Future;
use std::pin::Pin;

use crate::config::{self, Token};

/// A refused credential: a stable code for the audit log and, when the
/// credential was genuine enough to say, whose it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub principal: Option<String>,
    /// The credential could not be checked just now (an issuer that cannot
    /// be reached, a timeout). The caller is told to try again (503) rather
    /// than that it was refused (401), so a bridge keeps its session.
    pub temporary: bool,
}

impl Refused {
    pub fn new(code: &'static str) -> Self {
        Refused {
            code,
            principal: None,
            temporary: false,
        }
    }

    /// A refusal that may go away on its own; see [`Refused::temporary`].
    pub fn temporary(code: &'static str) -> Self {
        Refused {
            temporary: true,
            ..Refused::new(code)
        }
    }
}

/// The code for an unknown actp token. Not audited, like the Go server.
pub const INVALID_TOKEN: &str = "invalid_token";

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = Result<Token, Refused>> + Send + 'a>>;

/// Maps a presented bearer token to the token policy it stands for: the agents,
/// workspaces, limits and rewrites that apply. An error refuses the request (401).
///
/// The returned token's `name` identifies the holder: a link can only be
/// resumed by a request that authenticates to the same name.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate<'a>(&'a self, cfg: &'a config::Server, presented: &'a str) -> AuthFuture<'a>;
}

/// actp's own tokens: SHA-256 hashes in the config and the tokens file,
/// compared in constant time.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigTokens;

impl Authenticator for ConfigTokens {
    fn authenticate<'a>(&'a self, cfg: &'a config::Server, presented: &'a str) -> AuthFuture<'a> {
        let found = find_token(cfg, presented).cloned();
        Box::pin(async move { found.ok_or(Refused::new(INVALID_TOKEN)) })
    }
}

/// The token entry matching a presented token. Every entry is compared, so
/// timing does not reveal which one matched; the last match wins, like Go.
pub fn find_token<'a>(cfg: &'a config::Server, presented: &str) -> Option<&'a Token> {
    if presented.is_empty() {
        return None;
    }
    let want = config::hash_token(presented);
    let mut found = None;
    for t in &cfg.tokens {
        if constant_time_eq(t.hash.as_bytes(), want.as_bytes()) {
            found = Some(t);
        }
    }
    found
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_tokens() {
        let s = config::Server {
            tokens: vec![
                Token {
                    name: "a".into(),
                    hash: "sha256:00".into(),
                    ..Default::default()
                },
                Token {
                    name: "b".into(),
                    hash: config::hash_token("actp_x"),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(find_token(&s, "actp_x").map(|t| t.name.as_str()), Some("b"));
        assert!(find_token(&s, "actp_wrong").is_none());
        assert!(find_token(&s, "").is_none());
    }
}

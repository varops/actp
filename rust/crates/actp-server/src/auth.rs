//! Who a bearer token belongs to. Pluggable, so a later build can accept
//! tokens signed by another authority (for example an organization's
//! identity service) next to, or instead of, actp's own hashed tokens.

use crate::config::{self, Token};

/// Maps a presented bearer token to the token policy it stands for: the agents,
/// workspaces, limits and rewrites that apply. `None` refuses the request (401).
///
/// The returned token's `name` identifies the holder: a link can only be
/// resumed by a request that authenticates to the same name.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, cfg: &config::Server, presented: &str) -> Option<Token>;
}

/// actp's own tokens: SHA-256 hashes in the config and the tokens file,
/// compared in constant time.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigTokens;

impl Authenticator for ConfigTokens {
    fn authenticate(&self, cfg: &config::Server, presented: &str) -> Option<Token> {
        find_token(cfg, presented).cloned()
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

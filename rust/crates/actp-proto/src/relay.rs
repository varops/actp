//! The relay protocol (docs/relay.md).
//!
//! A machine keeps one control WebSocket open to the relay
//! ([`PATH_CONNECT`]). The relay sends [`Control`] messages on it as JSON
//! text frames. Both machine WebSockets are made over TLS with the
//! machine's device certificate.
//!
//! A caller opens a tunnel WebSocket to the relay ([`PATH_TUNNEL`] + the
//! machine's address) over TLS with its own caller certificate. The relay
//! sends the machine [`Control::Open`] with a fresh stream id, the machine
//! dials a data WebSocket ([`PATH_STREAM`] + id), and the relay joins the
//! two. Both carry bytes ([`crate::wsio`]): the caller's TLS straight to
//! the machine ([`crate::e2e`]), which the relay cannot read.

use serde::{Deserialize, Serialize};

/// The machine's control connection.
pub const PATH_CONNECT: &str = "/relay/v1/connect";
/// A data stream: this prefix plus the stream id from [`Control::Open`].
pub const PATH_STREAM: &str = "/relay/v1/stream/";
/// A caller's tunnel to a machine: this prefix plus the machine's address.
pub const PATH_TUNNEL: &str = "/relay/v1/tunnel/";

/// WebSocket subprotocols of the two machine connections and the caller's
/// tunnel.
pub const PROTOCOL_CONTROL: &str = "actp-relay.v2";
pub const PROTOCOL_STREAM: &str = "actp-relay-stream.v2";
pub const PROTOCOL_TUNNEL: &str = "actp-relay-tunnel.v1";

/// Length of a stream id: 32 random bytes as lowercase hex.
pub const STREAM_ID_LEN: usize = 64;

/// A message from the relay to a machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// First message on every control connection: the address the relay
    /// knows this machine by, and whether the org-wide stop is on.
    Hello { machine: String, stopped: bool },
    /// A caller is waiting: dial [`PATH_STREAM`] + `stream`, and answer the
    /// caller's TLS on it ([`crate::e2e::server_config`]).
    Open { stream: String },
    /// The org-wide stop was pressed: end every session, refuse new ones.
    Stop,
    /// The org-wide stop was released.
    Release,
}

impl Control {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("control messages encode")
    }

    /// `None` for anything this version does not know, so a newer relay can
    /// add messages without breaking older machines.
    pub fn decode(s: &str) -> Option<Control> {
        serde_json::from_str(s).ok()
    }
}

/// Whether `id` has the shape of a stream id.
pub fn valid_stream_id(id: &str) -> bool {
    id.len() == STREAM_ID_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `name` can be a machine address at the relay: 1 to 253 bytes of
/// letters, digits and `.`, `-`, `_`, `@`, `:`, `+`, `~`, not `.` or `..`.
/// Addresses are compared exactly, so the set stays free of anything that
/// URL decoding, path cleaning or case folding could change.
pub fn valid_machine_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name != "."
        && name != ".."
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@' | b':' | b'+' | b'~')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip() {
        for c in [
            Control::Hello {
                machine: "C02XK1".into(),
                stopped: true,
            },
            Control::Open {
                stream: "ab".repeat(32),
            },
            Control::Stop,
            Control::Release,
        ] {
            assert_eq!(Control::decode(&c.encode()), Some(c));
        }
        assert_eq!(Control::Stop.encode(), r#"{"type":"stop"}"#);
        assert_eq!(Control::decode(r#"{"type":"later"}"#), None);
    }

    #[test]
    fn names_and_ids() {
        assert!(valid_machine_name("C02XK1ABJG5H"));
        assert!(valid_machine_name("dana-mbp.corp.example.com"));
        for bad in [
            "", ".", "..", "a/b", "a b", "a%2fb", "a\\b", "é", "a?b", "a#b",
        ] {
            assert!(!valid_machine_name(bad), "{bad}");
        }
        assert!(!valid_machine_name(&"a".repeat(254)));
        assert!(valid_stream_id(&"0f".repeat(32)));
        assert!(!valid_stream_id(&"0F".repeat(32)));
        assert!(!valid_stream_id("00"));
    }
}

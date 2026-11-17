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
/// A machine's question to the identity service, through the relay: this
/// prefix plus the issuer's path (docs/relay.md, the issuer pass-through).
pub const PATH_ISSUER: &str = "/relay/v1/issuer";

/// WebSocket subprotocols of the two machine connections and the caller's
/// tunnel.
pub const PROTOCOL_CONTROL: &str = "actp-relay.v2";
pub const PROTOCOL_STREAM: &str = "actp-relay-stream.v2";
pub const PROTOCOL_TUNNEL: &str = "actp-relay-tunnel.v1";

/// Length of a stream id: 32 random bytes as lowercase hex.
pub const STREAM_ID_LEN: usize = 64;

/// A tunnel request header: the person the caller acts for, as the caller
/// says. The relay records it with the session and passes it to the
/// machine; nobody checks it ([`valid_on_behalf_of`]).
pub const HEADER_ON_BEHALF_OF: &str = "x-actp-on-behalf-of";
/// The longest [`HEADER_ON_BEHALF_OF`], in bytes.
pub const MAX_ON_BEHALF_OF: usize = 256;

/// Who opened a relayed stream, as the relay saw it: the caller's name and
/// certificate, which it checked, and whom the caller said it acts for,
/// which it did not. The machine records it with the link; it cannot check
/// it, and a relay could lie, so it is for tracing, never for deciding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedBy {
    /// The caller's name from its certificate.
    pub caller: String,
    /// SHA-256 of the caller's certificate, as lowercase hex.
    pub caller_certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

impl OpenedBy {
    /// Whether every field has the shape the relay gives it.
    pub fn valid(&self) -> bool {
        valid_machine_name(&self.caller)
            && self.caller_certificate.len() == 64
            && self
                .caller_certificate
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && self.on_behalf_of.as_deref().is_none_or(valid_on_behalf_of)
    }
}

/// Whether `v` can be an [`HEADER_ON_BEHALF_OF`] value: 1 to
/// [`MAX_ON_BEHALF_OF`] bytes of UTF-8, no space at either end, and nothing
/// that would show a reader something other than what is there: no control
/// characters, line separators, invisible or direction-changing
/// characters. An email address or a directory id, typically.
pub fn valid_on_behalf_of(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_ON_BEHALF_OF
        && v.trim() == v
        && !v.chars().any(|c| c.is_control() || hidden(c))
}

/// Format characters (Unicode Cf: invisible, joining, direction-changing),
/// the line and paragraph separators, fillers and variation selectors.
fn hidden(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890 | 0x0891
        | 0x08E2 | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F | 0x200B..=0x200F
        | 0x2028..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF)
}

/// A message from the relay to a machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// First message on every control connection: the address the relay
    /// knows this machine by, and whether the org-wide stop is on.
    Hello { machine: String, stopped: bool },
    /// A caller is waiting: dial [`PATH_STREAM`] + `stream`, and answer the
    /// caller's TLS on it ([`crate::e2e::server_config`]). `opened_by` says
    /// who, as the relay saw it (absent from older relays).
    Open {
        stream: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        opened_by: Option<OpenedBy>,
    },
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
                opened_by: None,
            },
            Control::Open {
                stream: "ab".repeat(32),
                opened_by: Some(OpenedBy {
                    caller: "it-bridge".into(),
                    caller_certificate: "0f".repeat(32),
                    on_behalf_of: Some("carol@acme.com".into()),
                }),
            },
            Control::Stop,
            Control::Release,
        ] {
            assert_eq!(Control::decode(&c.encode()), Some(c));
        }
        assert_eq!(Control::Stop.encode(), r#"{"type":"stop"}"#);
        assert_eq!(Control::decode(r#"{"type":"later"}"#), None);
        // An older relay's Open, and a newer relay's to an older machine.
        assert_eq!(
            Control::decode(&format!(
                r#"{{"type":"open","stream":"{}"}}"#,
                "ab".repeat(32)
            )),
            Some(Control::Open {
                stream: "ab".repeat(32),
                opened_by: None
            })
        );
    }

    #[test]
    fn on_behalf_of_values() {
        for good in [
            "carol@acme.com",
            "eun_usr_dana",
            "Zoë Ångström",
            &"a".repeat(256),
        ] {
            assert!(valid_on_behalf_of(good), "{good}");
        }
        for bad in [
            "",
            " carol",
            "carol ",
            "a\nb",
            "a\u{7f}b",
            "a\tb",
            &"a".repeat(257),
            // Shown as something else: reversed, invisible, a new line.
            "carol\u{202e}moc.emca",
            "car\u{200b}ol",
            "carol\u{2028}x",
            "\u{feff}carol",
            "carol\u{2066}x",
            "carol\u{e0041}",
            "carol\u{fe0f}",
        ] {
            assert!(!valid_on_behalf_of(bad), "{bad:?}");
        }
        let ok = OpenedBy {
            caller: "it-bridge".into(),
            caller_certificate: "0f".repeat(32),
            on_behalf_of: None,
        };
        assert!(ok.valid());
        for bad in [
            OpenedBy {
                caller: "a b".into(),
                ..ok.clone()
            },
            OpenedBy {
                caller_certificate: "0F".repeat(32),
                ..ok.clone()
            },
            OpenedBy {
                caller_certificate: "0f".into(),
                ..ok.clone()
            },
            OpenedBy {
                on_behalf_of: Some(" x".into()),
                ..ok.clone()
            },
        ] {
            assert!(!bad.valid(), "{bad:?}");
        }
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

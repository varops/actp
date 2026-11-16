//! The `actp.v1` envelope (docs/wire.md section 4): one JSON object per
//! WebSocket text frame, encoded exactly like Go's `json.Marshal(wire.Frame)`.

use crate::gojson::{self, DecodeError};

/// Wire versions, newest first. A server and bridge pick the newest they share.
pub const VERSIONS: &[&str] = &["actp.v1"];

/// Headers on the link upgrade request and response.
pub const HEADER_LINK_ID: &str = "Actp-Link-Id";
pub const HEADER_LAST_SEQ: &str = "Actp-Last-Seq";
pub const HEADER_CLIENT_NAME: &str = "Actp-Client-Name";
pub const HEADER_PROMPT_TIMEOUT: &str = "Actp-Prompt-Timeout";

/// WebSocket close codes.
pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_GOING_AWAY: u16 = 1001;
pub const CLOSE_REPLACED: u16 = 4001;
pub const CLOSE_LINK_ENDED: u16 = 4002;
pub const CLOSE_PROTOCOL_ERROR: u16 = 4003;
pub const CLOSE_DEAD: u16 = 4004;

/// Frame types.
pub const T_MSG: &str = "msg";
pub const T_ACK: &str = "ack";
pub const T_PING: &str = "ping";
pub const T_PONG: &str = "pong";
pub const T_BYE: &str = "bye";
pub const T_ERROR: &str = "error";

/// Error codes sent in error frames.
pub const ERR_AGENT_EXITED: &str = "agent_exited";
pub const ERR_SPOOL_FULL: &str = "spool_full";
pub const ERR_SERVER_SHUTDOWN: &str = "server_shutdown";
pub const ERR_ENDED_BY_ADMIN: &str = "ended_by_admin";
pub const ERR_LINK_ENDED: &str = "link_ended";
pub const ERR_SEQUENCE_GAP: &str = "sequence_gap";
pub const ERR_PROTOCOL: &str = "protocol_error";

/// Largest frame either side accepts.
pub const MAX_FRAME: usize = 16 << 20;

/// One WebSocket text frame. Empty strings, zero numbers and `None` are left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub t: String,
    pub seq: i64,
    pub ack: i64,
    /// One raw ACP JSON-RPC message.
    pub msg: Option<String>,
    pub code: String,
    pub message: String,
    pub data: Option<String>,
}

impl Frame {
    pub fn of(t: &str) -> Frame {
        Frame {
            t: t.to_string(),
            ..Default::default()
        }
    }

    pub fn ack(ack: i64) -> Frame {
        Frame {
            t: T_ACK.into(),
            ack,
            ..Default::default()
        }
    }

    pub fn msg(seq: i64, ack: i64, msg: String) -> Frame {
        Frame {
            t: T_MSG.into(),
            seq,
            ack,
            msg: Some(msg),
            ..Default::default()
        }
    }

    pub fn error(code: &str, message: impl Into<String>, data: Option<String>) -> Frame {
        Frame {
            t: T_ERROR.into(),
            code: code.into(),
            message: message.into(),
            data,
            ..Default::default()
        }
    }

    /// Encodes like Go: fields in declaration order, `omitempty`, HTML-escaped.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(32 + self.msg.as_ref().map_or(0, |m| m.len()));
        out.push_str("{\"t\":");
        gojson::push_string(&mut out, &self.t);
        if self.seq != 0 {
            out.push_str(",\"seq\":");
            out.push_str(&self.seq.to_string());
        }
        if self.ack != 0 {
            out.push_str(",\"ack\":");
            out.push_str(&self.ack.to_string());
        }
        if let Some(m) = self.msg.as_deref().filter(|m| !m.is_empty()) {
            out.push_str(",\"msg\":");
            out.push_str(&gojson::compact(m, true));
        }
        if !self.code.is_empty() {
            out.push_str(",\"code\":");
            gojson::push_string(&mut out, &self.code);
        }
        if !self.message.is_empty() {
            out.push_str(",\"message\":");
            gojson::push_string(&mut out, &self.message);
        }
        if let Some(d) = self.data.as_deref().filter(|d| !d.is_empty()) {
            out.push_str(",\"data\":");
            out.push_str(&gojson::compact(d, true));
        }
        out.push('}');
        out
    }

    /// Decodes like Go's `json.Unmarshal` into `wire.Frame`: unknown fields are
    /// ignored, field names match case-insensitively, a wrong type is an error.
    pub fn decode(text: &str) -> Result<Frame, DecodeError> {
        let mut f = Frame::default();
        let Some(e) = gojson::object(text)? else {
            return Ok(f);
        };
        let mut errs = Vec::new();
        if let Some(t) = e.string("t", &mut errs) {
            f.t = t;
        }
        if let Some(v) = e.int("seq", &mut errs) {
            f.seq = v;
        }
        if let Some(v) = e.int("ack", &mut errs) {
            f.ack = v;
        }
        f.msg = e.raw("msg").map(str::to_string);
        if let Some(v) = e.string("code", &mut errs) {
            f.code = v;
        }
        if let Some(v) = e.string("message", &mut errs) {
            f.message = v;
        }
        f.data = e.raw("data").map(str::to_string);
        match errs.into_iter().next() {
            Some(err) => Err(err),
            None => Ok(f),
        }
    }
}

/// An error frame received from the other side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteError {
    pub code: String,
    pub message: String,
    pub data: Option<String>,
}

impl RemoteError {
    /// Whether the link has ended, as opposed to only this socket.
    pub fn fatal(&self) -> bool {
        self.code != ERR_SEQUENCE_GAP && self.code != ERR_PROTOCOL
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RemoteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_go() {
        assert_eq!(
            Frame::msg(42, 17, r#"{"jsonrpc":"2.0","method":"a<b"}"#.into()).encode(),
            format!(
                r#"{{"t":"msg","seq":42,"ack":17,"msg":{{"jsonrpc":"2.0","method":"a{}b"}}}}"#,
                crate::gojson::tests::LT
            )
        );
        assert_eq!(
            Frame::msg(1, 0, "{}".into()).encode(),
            r#"{"t":"msg","seq":1,"msg":{}}"#
        );
        assert_eq!(Frame::ack(0).encode(), r#"{"t":"ack"}"#);
        assert_eq!(Frame::of(T_PONG).encode(), r#"{"t":"pong"}"#);
        assert_eq!(
            Frame::error(
                ERR_AGENT_EXITED,
                "agent x exited with code 3",
                Some(r#"{"exitCode":3,"stderr":"boom\n"}"#.into())
            )
            .encode(),
            r#"{"t":"error","code":"agent_exited","message":"agent x exited with code 3","data":{"exitCode":3,"stderr":"boom\n"}}"#
        );
    }

    #[test]
    fn decodes_like_go() {
        let f = Frame::decode(r#"{"t":"msg","seq":3,"ack":2,"msg":{"a":1},"extra":true}"#).unwrap();
        assert_eq!(
            (f.t.as_str(), f.seq, f.ack, f.msg.as_deref()),
            ("msg", 3, 2, Some(r#"{"a":1}"#))
        );
        assert_eq!(
            Frame::decode(r#"{"T":"ack","ACK":5}"#).unwrap(),
            Frame::ack(5)
        );
        assert_eq!(Frame::decode("null").unwrap(), Frame::default());
        assert!(Frame::decode(r#"{"t":"msg","seq":"1"}"#).is_err());
        assert!(Frame::decode(r#"{"t":"msg","seq":1.5}"#).is_err());
        assert!(Frame::decode("[]").is_err());
        assert!(Frame::decode("{").is_err());
    }
}

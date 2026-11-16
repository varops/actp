//! Reads, writes and inspects newline-delimited JSON-RPC 2.0 messages without
//! decoding fields actp does not need, so unknown fields survive. A port of
//! `internal/jsonrpc`.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::gojson::{self, DecodeError, GoValue, RawMap};

pub const CODE_PARSE_ERROR: i64 = -32700;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_INTERNAL_ERROR: i64 = -32603;
pub const CODE_SERVER_ERROR: i64 = -32000;
pub const CODE_CANCELLED: i64 = -32800;

/// The shape of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Request,
    Notification,
    Response,
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<String>,
}

/// One JSON-RPC message with its header fields peeked. `raw` is the compact message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub raw: String,
    /// The compact id; `None` when absent (or `null` on a request).
    pub id: Option<String>,
    pub method: String,
    pub params: Option<String>,
    pub result: Option<String>,
    pub error: Option<RpcError>,
}

/// Peeks a raw message, keeping its bytes (compacted) as they are.
pub fn parse(raw: &str) -> Result<Message, DecodeError> {
    let entries = gojson::object(raw)?;
    let mut errs = Vec::new();
    let (mut id, mut method, mut params, mut result, mut error) =
        (None, String::new(), None, None, None);
    if let Some(e) = &entries {
        id = e.raw("id").map(str::to_string);
        method = e.string("method", &mut errs).unwrap_or_default();
        params = e.raw("params").map(str::to_string);
        result = e.raw("result").map(str::to_string);
        for v in e.all("error") {
            match gojson::kind(v) {
                gojson::Kind::Null => error = None,
                gojson::Kind::Object => {
                    let mut cur: RpcError = error.take().unwrap_or_default();
                    if let Ok(Some(fields)) = gojson::object(v) {
                        if let Some(c) = fields.int("code", &mut errs) {
                            cur.code = c;
                        }
                        if let Some(m) = fields.string("message", &mut errs) {
                            cur.message = m;
                        }
                        if let Some(d) = fields.raw("data") {
                            cur.data = Some(d.to_string());
                        }
                    }
                    error = Some(cur);
                }
                _ => errs.push(DecodeError("cannot unmarshal into an error object".into())),
            }
        }
    }
    if let Some(e) = errs.into_iter().next() {
        return Err(e);
    }
    let mut m = Message {
        raw: gojson::compact(raw.trim(), false),
        id: None,
        method,
        params,
        result,
        error,
    };
    match id.as_deref() {
        Some("null") if m.method.is_empty() => m.id = Some("null".into()),
        Some("null") | None => {}
        Some(other) => m.id = Some(gojson::compact(other, false)),
    }
    if m.method.is_empty() && m.id.is_none() {
        return Err(DecodeError(
            "not a JSON-RPC message: no method and no id".into(),
        ));
    }
    Ok(m)
}

impl Message {
    pub fn kind(&self) -> Kind {
        match (self.method.is_empty(), self.id.is_some()) {
            (false, true) => Kind::Request,
            (false, false) => Kind::Notification,
            _ => Kind::Response,
        }
    }

    /// A map key for the message id.
    pub fn id_key(&self) -> String {
        self.id.clone().unwrap_or_default()
    }

    /// A copy of the message with new params (an encoded JSON value).
    pub fn with_params(&self, params: &str) -> Result<Message, DecodeError> {
        self.with_field("params", params)
    }

    /// A copy of the message with a new result (an encoded JSON value).
    pub fn with_result(&self, result: &str) -> Result<Message, DecodeError> {
        self.with_field("result", result)
    }

    /// Like Go's `withField`: re-encodes the message as a map with sorted keys.
    fn with_field(&self, key: &str, value: &str) -> Result<Message, DecodeError> {
        let mut obj = gojson::decode_raw_map(Some(&self.raw))?;
        obj.get_or_insert_default()
            .insert(key.to_string(), value.to_string());
        parse(&gojson::encode_raw_map(&obj))
    }
}

/// Encodes params the way `WithParams(map[string]json.RawMessage)` does.
pub fn encode_params(p: &RawMap) -> String {
    gojson::encode_raw_map(p)
}

fn build(v: GoValue) -> Message {
    parse(&v.encode()).expect("built messages are valid")
}

/// A request. `id` is an encoded JSON id; an empty one encodes as `null`.
pub fn new_request(id: &str, method: &str, params: GoValue) -> Message {
    build(gojson::map([
        ("jsonrpc", gojson::s("2.0")),
        ("id", GoValue::Raw(id.to_string())),
        ("method", gojson::s(method)),
        ("params", params),
    ]))
}

pub fn new_notification(method: &str, params: GoValue) -> Message {
    build(gojson::map([
        ("jsonrpc", gojson::s("2.0")),
        ("method", gojson::s(method)),
        ("params", params),
    ]))
}

pub fn new_result(id: &str, result: GoValue) -> Message {
    build(gojson::map([
        ("jsonrpc", gojson::s("2.0")),
        ("id", GoValue::Raw(id.to_string())),
        ("result", result),
    ]))
}

pub fn new_error(id: &str, code: i64, message: &str) -> Message {
    build(gojson::map([
        ("jsonrpc", gojson::s("2.0")),
        ("id", GoValue::Raw(id.to_string())),
        (
            "error",
            gojson::map([
                ("code", GoValue::Int(code)),
                ("message", gojson::s(message)),
            ]),
        ),
    ]))
}

/// One line read from a stream.
#[derive(Debug)]
pub enum Line {
    Message(Message),
    /// A non-empty line that is not JSON-RPC; callers log and skip it.
    Invalid(String, DecodeError),
}

/// Reads one message per line.
pub struct Reader<R> {
    r: R,
    buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> Reader<R> {
    pub fn new(r: R) -> Self {
        Reader {
            r,
            buf: Vec::with_capacity(64 << 10),
        }
    }

    /// The next non-empty line, `Ok(None)` at the end of the stream.
    pub async fn read(&mut self) -> std::io::Result<Option<Line>> {
        loop {
            self.buf.clear();
            let n = self.r.read_until(b'\n', &mut self.buf).await?;
            let text = String::from_utf8_lossy(&self.buf);
            let trimmed = text.trim_matches(char::is_whitespace);
            if !trimmed.is_empty() {
                return Ok(Some(match parse(trimmed) {
                    Ok(m) => Line::Message(m),
                    Err(e) => Line::Invalid(
                        trimmed.to_string(),
                        DecodeError(format!("invalid message: {e}")),
                    ),
                }));
            }
            if n == 0 {
                return Ok(None);
            }
        }
    }
}

/// Writes one message per line. Safe for concurrent use.
pub struct Writer<W> {
    w: Mutex<W>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(w: W) -> Self {
        Writer { w: Mutex::new(w) }
    }

    pub async fn write(&self, m: &Message) -> std::io::Result<()> {
        self.write_raw(&m.raw).await
    }

    /// Writes an already compact JSON message and a newline.
    pub async fn write_raw(&self, raw: &str) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(raw.len() + 1);
        buf.extend_from_slice(raw.as_bytes());
        buf.push(b'\n');
        let mut w = self.w.lock().await;
        w.write_all(&buf).await?;
        w.flush().await
    }

    /// Takes the writer back, for example to close it.
    pub fn into_inner(self) -> W {
        self.w.into_inner()
    }

    /// Runs `f` on the writer if nobody is writing right now.
    pub fn try_with<T>(&self, f: impl FnOnce(&mut W) -> T) -> Option<T> {
        self.w.try_lock().ok().map(|mut g| f(&mut g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
                .unwrap()
                .kind(),
            Kind::Request
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","method":"session/update","params":{}}"#)
                .unwrap()
                .kind(),
            Kind::Notification
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":"a","result":{}}"#)
                .unwrap()
                .kind(),
            Kind::Response
        );
        let null_id =
            parse(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}"#).unwrap();
        assert_eq!(null_id.kind(), Kind::Response);
        assert_eq!(null_id.id.as_deref(), Some("null"));
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":null,"method":"m"}"#)
                .unwrap()
                .kind(),
            Kind::Notification
        );
        assert!(parse(r#"{"jsonrpc":"2.0"}"#).is_err());
        assert!(parse(r#"{"method":5,"id":1}"#).is_err());
        assert!(parse("[1]").is_err());
        assert!(parse("not json").is_err());
        let e =
            parse(r#"{"id":2,"error":{"code":-32602,"message":"bad","data":{"x":1}}}"#).unwrap();
        assert_eq!(
            e.error,
            Some(RpcError {
                code: -32602,
                message: "bad".into(),
                data: Some(r#"{"x":1}"#.into())
            })
        );
    }

    #[test]
    fn raw_is_compacted_and_ids_too() {
        let m = parse(r#" { "id" : [ 1 , 2 ] , "method" : "x" } "#).unwrap();
        assert_eq!(m.raw, r#"{"id":[1,2],"method":"x"}"#);
        assert_eq!(m.id_key(), "[1,2]");
    }

    #[test]
    fn with_params_keeps_unknown_fields_and_sorts() {
        let m = parse(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":1},"zz":{"b":"<"}}"#)
            .unwrap();
        let out = m.with_params(r#"{"cwd":"/w"}"#).unwrap();
        assert_eq!(
            out.raw,
            format!(
                r#"{{"id":1,"jsonrpc":"2.0","method":"x","params":{{"cwd":"/w"}},"zz":{{"b":"{}"}}}}"#,
                crate::gojson::tests::LT
            )
        );
    }

    #[test]
    fn builders_match_go() {
        assert_eq!(
            new_error("7", CODE_INVALID_PARAMS, "cwd not allowed: /x").raw,
            r#"{"error":{"code":-32602,"message":"cwd not allowed: /x"},"id":7,"jsonrpc":"2.0"}"#
        );
        assert_eq!(
            new_result(
                r#""a""#,
                gojson::map([(
                    "outcome",
                    gojson::map([
                        ("outcome", gojson::s("selected")),
                        ("optionId", gojson::s("allow"))
                    ])
                )])
            )
            .raw,
            r#"{"id":"a","jsonrpc":"2.0","result":{"outcome":{"optionId":"allow","outcome":"selected"}}}"#
        );
        assert_eq!(
            new_notification(
                "session/cancel",
                gojson::map([("sessionId", gojson::s("s1"))])
            )
            .raw,
            r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}"#
        );
        assert_eq!(
            new_request(r#""actp-1""#, "session/close", gojson::map([])).raw,
            r#"{"id":"actp-1","jsonrpc":"2.0","method":"session/close","params":{}}"#
        );
    }

    #[tokio::test]
    async fn reader_and_writer() {
        let input =
            b"{\"jsonrpc\":\"2.0\",\"method\":\"a\"}\n\n  \nnot json\n{\"id\":1,\"result\":null}"
                .to_vec();
        let mut r = Reader::new(&input[..]);
        assert!(matches!(r.read().await.unwrap(), Some(Line::Message(m)) if m.method == "a"));
        assert!(matches!(r.read().await.unwrap(), Some(Line::Invalid(l, _)) if l == "not json"));
        assert!(
            matches!(r.read().await.unwrap(), Some(Line::Message(m)) if m.kind() == Kind::Response)
        );
        assert!(r.read().await.unwrap().is_none());

        let w = Writer::new(Vec::new());
        w.write_raw("{}").await.unwrap();
        w.write(&new_result("1", GoValue::Null)).await.unwrap();
        assert_eq!(
            String::from_utf8(w.into_inner()).unwrap(),
            "{}\n{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":null}\n"
        );
    }
}

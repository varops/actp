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
    // An id key makes a message with a method a request, even with a null id:
    // that is how agents (for example the ACP TypeScript SDK) read it.
    if let Some(id) = id.as_deref() {
        m.id = Some(gojson::compact(id, false));
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

/// The JSON-RPC fields actp routes and rewrites by.
const ENVELOPE_KEYS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// A message whose envelope two JSON decoders can read differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ambiguous {
    pub reason: String,
    /// The message's id when it has exactly one non-null `"id"` key.
    pub id: Option<String>,
    /// Whether a method key is present in any spelling.
    pub request: bool,
}

impl std::fmt::Display for Ambiguous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ambiguous JSON-RPC envelope: {}", self.reason)
    }
}

impl std::error::Error for Ambiguous {}

/// Refuses a message that Go-style decoding (case-insensitive keys, last one
/// wins) and a peer's exact-key decoding could read differently: a key that
/// differs from an envelope field only in case, or an envelope field given
/// twice. Messages that are not JSON objects are left to [`parse`].
pub fn check_envelope(raw: &str) -> Result<(), Ambiguous> {
    if gojson::kind(raw) != gojson::Kind::Object {
        return Ok(());
    }
    let Ok(Some(entries)) = gojson::object(raw) else {
        return Ok(());
    };
    let mut a = Ambiguous {
        reason: String::new(),
        id: None,
        request: false,
    };
    let mut seen = [0usize; ENVELOPE_KEYS.len()];
    let mut ids = Vec::new();
    for (key, val) in &entries.0 {
        for (i, name) in ENVELOPE_KEYS.iter().enumerate() {
            if !gojson::field_matches(key, name) {
                continue;
            }
            if *name == "method" {
                a.request = true;
            }
            if key != name {
                if a.reason.is_empty() {
                    a.reason = format!("key {key:?} differs from {name:?} only in case");
                }
            } else {
                seen[i] += 1;
                if *name == "id" {
                    ids.push(val.get());
                }
                if seen[i] == 2 && a.reason.is_empty() {
                    a.reason = format!("key {name:?} appears more than once");
                }
            }
        }
    }
    if a.reason.is_empty() {
        return Ok(());
    }
    if let [id] = ids.as_slice()
        && gojson::kind(id) != gojson::Kind::Null
    {
        a.id = Some(gojson::compact(id, false));
    }
    Err(a)
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
        // An id key, even null, makes a request: agents read it that way.
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":null,"method":"m"}"#)
                .unwrap()
                .kind(),
            Kind::Request
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
    fn envelope_ambiguity_is_refused() {
        for ok in [
            r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/","Cwd":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"session/update","params":{},"_meta":{"id":1}}"#,
            "[1,2]",
            "not json",
        ] {
            assert_eq!(check_envelope(ok), Ok(()), "{ok}");
        }
        let refused: &[(&str, Option<&str>, bool)] = &[
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"session/new","Method":"session/prompt","params":{}}"#,
                Some("1"),
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","id":7,"Id":null,"method":"session/new","params":{}}"#,
                Some("7"),
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"x","Params":{}}"#,
                Some("1"),
                true,
            ),
            (r#"{"jsonrpc":"2.0","ID":1,"method":"x"}"#, None, true),
            (r#"{"JSONRPC":"2.0","id":1,"method":"x"}"#, Some("1"), true),
            (r#"{"jsonrpc":"2.0","id":1,"Result":{}}"#, Some("1"), false),
            (r#"{"jsonrpc":"2.0","id":1,"ERROR":{}}"#, Some("1"), false),
            (
                r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}"#,
                None,
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"x","method":"y"}"#,
                Some("1"),
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{},"params":{}}"#,
                Some("1"),
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"x","\u0050arams":{}}"#,
                Some("1"),
                true,
            ),
            (
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"param\u{17f}\":{}}",
                Some("1"),
                true,
            ),
        ];
        for (raw, id, request) in refused {
            let a = check_envelope(raw).expect_err(raw);
            assert_eq!((a.id.as_deref(), a.request), (*id, *request), "{raw}");
        }
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

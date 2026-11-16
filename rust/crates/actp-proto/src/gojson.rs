//! JSON the way Go's `encoding/json` reads and writes it.
//!
//! actp passes ACP messages through as raw bytes and only re-encodes what it
//! rewrites. To stay byte-for-byte compatible with the Go implementation, the
//! re-encoding follows `encoding/json`: object keys of maps are sorted, strings
//! escape `<`, `>`, `&`, U+2028 and U+2029, raw values are compacted with the
//! same HTML escaping, and numbers decoded as `any` are formatted as float64.
//! Decoding follows Go too: struct fields match keys case-insensitively, the
//! last duplicate wins, `null` leaves a field alone, and a value of the wrong
//! type is an error.

use std::collections::BTreeMap;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` as a JSON string, escaped like Go's `json.Marshal`.
pub fn push_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' => push_u00(out, c as u8),
            c if (c as u32) < 0x20 => push_u00(out, c as u8),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_u00(out: &mut String, b: u8) {
    out.push_str("\\u00");
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0xf) as usize] as char);
}

/// A JSON string encoded like Go's `json.Marshal(s)`.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    push_string(&mut out, s);
    out
}

/// Removes insignificant whitespace from valid JSON, like Go's `json.Compact`.
/// With `escape_html`, `<`, `>`, `&`, U+2028 and U+2029 are escaped as well,
/// which is what `json.Marshal` does to a `json.RawMessage`.
pub fn compact(raw: &str, escape_html: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_str = false;
    let mut escaped = false;
    for c in raw.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            if escape_html {
                match c {
                    '<' | '>' | '&' => {
                        push_u00(&mut out, c as u8);
                        continue;
                    }
                    '\u{2028}' => {
                        out.push_str("\\u2028");
                        continue;
                    }
                    '\u{2029}' => {
                        out.push_str("\\u2029");
                        continue;
                    }
                    _ => {}
                }
            }
            out.push(c);
            continue;
        }
        match c {
            ' ' | '\t' | '\n' | '\r' => {}
            '"' => {
                in_str = true;
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// A value to encode the way Go's `json.Marshal` encodes `map[string]any`
/// trees: maps with sorted keys, raw values compacted with HTML escaping.
#[derive(Clone, Debug, PartialEq)]
pub enum GoValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<GoValue>),
    Map(BTreeMap<String, GoValue>),
    /// A `json.RawMessage`. An empty one encodes as `null`, like a nil RawMessage.
    Raw(String),
}

impl GoValue {
    pub fn encode(&self) -> String {
        let mut out = String::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut String) {
        match self {
            GoValue::Null => out.push_str("null"),
            GoValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            GoValue::Int(i) => out.push_str(&i.to_string()),
            GoValue::Str(s) => push_string(out, s),
            GoValue::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.encode_into(out);
                }
                out.push(']');
            }
            GoValue::Map(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    push_string(out, k);
                    out.push(':');
                    v.encode_into(out);
                }
                out.push('}');
            }
            GoValue::Raw(r) => {
                if r.is_empty() {
                    out.push_str("null");
                } else {
                    out.push_str(&compact(r, true));
                }
            }
        }
    }
}

/// Builds a `GoValue::Map` from pairs.
pub fn map<const N: usize>(pairs: [(&str, GoValue); N]) -> GoValue {
    GoValue::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn s(v: impl Into<String>) -> GoValue {
    GoValue::Str(v.into())
}

/// A Go `map[string]json.RawMessage`: `None` is a nil map.
pub type RawMap = Option<BTreeMap<String, String>>;

/// Encodes a raw map like `json.Marshal(map[string]json.RawMessage)`.
pub fn encode_raw_map(m: &RawMap) -> String {
    match m {
        None => "null".to_string(),
        Some(m) => {
            let mut out = String::from("{");
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_string(&mut out, k);
                out.push(':');
                GoValue::Raw(v.clone()).encode_into(&mut out);
            }
            out.push('}');
            out
        }
    }
}

/// Encodes a list of raw maps like `json.Marshal([]map[string]json.RawMessage)`.
/// `None` is a nil slice (`null`).
pub fn encode_raw_maps(list: &Option<Vec<RawMap>>) -> String {
    match list {
        None => "null".to_string(),
        Some(list) => {
            let mut out = String::from("[");
            for (i, m) in list.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&encode_raw_map(m));
            }
            out.push(']');
            out
        }
    }
}

/// The error Go's decoder reports; actp only cares that there was one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

/// The members of a JSON object, in order, duplicates included.
pub struct Entries(pub Vec<(String, Box<RawValue>)>);

impl<'de> serde::Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Entries, A::Error> {
                let mut v = Vec::new();
                while let Some((k, val)) = a.next_entry::<String, Box<RawValue>>()? {
                    v.push((k, val));
                }
                Ok(Entries(v))
            }
        }
        d.deserialize_map(V)
    }
}

/// What a raw JSON value is, by its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

pub fn kind(raw: &str) -> Kind {
    match raw.trim_start().as_bytes().first() {
        Some(b'n') => Kind::Null,
        Some(b't') | Some(b'f') => Kind::Bool,
        Some(b'"') => Kind::String,
        Some(b'[') => Kind::Array,
        Some(b'{') => Kind::Object,
        _ => Kind::Number,
    }
}

/// Checks that `raw` is one valid JSON value (whitespace around it allowed).
pub fn valid(raw: &str) -> bool {
    serde_json::from_str::<&RawValue>(raw).is_ok()
}

/// The members of an object, for struct-style decoding. `Ok(None)` is `null`
/// (Go leaves the struct alone), an error is any other non-object or bad JSON.
pub fn object(raw: &str) -> Result<Option<Entries>, DecodeError> {
    if raw.trim().is_empty() {
        return Err(DecodeError("unexpected end of JSON input".into()));
    }
    if kind(raw) == Kind::Null {
        return if valid(raw) {
            Ok(None)
        } else {
            Err(DecodeError("invalid JSON".into()))
        };
    }
    if kind(raw) != Kind::Object {
        return if valid(raw) {
            Err(DecodeError("cannot unmarshal into an object".into()))
        } else {
            Err(DecodeError("invalid JSON".into()))
        };
    }
    serde_json::from_str::<Entries>(raw)
        .map(Some)
        .map_err(|e| DecodeError(e.to_string()))
}

/// Go's field-name match: exact or case-insensitive.
pub fn field_matches(key: &str, name: &str) -> bool {
    key == name || key.eq_ignore_ascii_case(name) || key.to_lowercase() == name.to_lowercase()
}

impl Entries {
    /// Every value whose key matches the Go field `name`, in order.
    pub fn all<'a, 'n>(&'a self, name: &'n str) -> impl Iterator<Item = &'a str> + use<'a, 'n> {
        self.0
            .iter()
            .filter(move |(k, _)| field_matches(k, name))
            .map(|(_, v)| v.get())
    }

    /// The raw value Go would leave in a `json.RawMessage` field (the last one).
    pub fn raw<'a>(&'a self, name: &str) -> Option<&'a str> {
        self.all(name).last()
    }

    /// Decodes a string field. Errors are type errors; the value is what Go keeps.
    pub fn string(&self, name: &str, errs: &mut Vec<DecodeError>) -> Option<String> {
        let mut out = None;
        for raw in self.all(name) {
            match decode_string(raw) {
                Ok(Some(v)) => out = Some(v),
                Ok(None) => {}
                Err(e) => errs.push(e),
            }
        }
        out
    }

    /// Decodes an integer field (Go `int`/`int64`).
    pub fn int(&self, name: &str, errs: &mut Vec<DecodeError>) -> Option<i64> {
        let mut out = None;
        for raw in self.all(name) {
            match decode_int(raw) {
                Ok(Some(v)) => out = Some(v),
                Ok(None) => {}
                Err(e) => errs.push(e),
            }
        }
        out
    }
}

/// Decodes a Go `string`: `Ok(None)` for null (no change), an error for any other type.
pub fn decode_string(raw: &str) -> Result<Option<String>, DecodeError> {
    match kind(raw) {
        Kind::Null => Ok(None),
        Kind::String => serde_json::from_str::<String>(raw)
            .map(Some)
            .map_err(|e| DecodeError(e.to_string())),
        _ => Err(DecodeError(format!("cannot unmarshal {raw} into a string"))),
    }
}

/// Decodes a Go `int64`: only integer literals in range, `Ok(None)` for null.
pub fn decode_int(raw: &str) -> Result<Option<i64>, DecodeError> {
    let t = raw.trim();
    match kind(t) {
        Kind::Null => Ok(None),
        Kind::Number => t
            .parse::<i64>()
            .map(Some)
            .map_err(|_| DecodeError(format!("cannot unmarshal number {t} into an integer"))),
        _ => Err(DecodeError(format!("cannot unmarshal {t} into an integer"))),
    }
}

/// `json.Unmarshal(raw, &s)` for a string variable that starts empty: the
/// string, or "" for anything else. A nil/absent raw value is also "".
pub fn string_or_empty(raw: Option<&str>) -> String {
    raw.and_then(|r| decode_string(r).ok().flatten())
        .unwrap_or_default()
}

/// `json.Unmarshal(raw, &m)` into a `map[string]json.RawMessage` that starts nil.
/// `Err` when Go would fail (then `m` stays nil); `Ok(None)` for `null`.
pub fn decode_raw_map(raw: Option<&str>) -> Result<RawMap, DecodeError> {
    let Some(raw) = raw else {
        return Err(DecodeError("unexpected end of JSON input".into()));
    };
    let Some(entries) = object(raw)? else {
        return Ok(None);
    };
    let mut m = BTreeMap::new();
    for (k, v) in entries.0 {
        m.insert(k, v.get().to_string());
    }
    Ok(Some(m))
}

/// `json.Unmarshal(raw, &list)` into a `[]map[string]json.RawMessage` that starts nil.
pub fn decode_raw_maps(raw: Option<&str>) -> Result<Option<Vec<RawMap>>, DecodeError> {
    let Some(raw) = raw else {
        return Err(DecodeError("unexpected end of JSON input".into()));
    };
    match kind(raw) {
        Kind::Null if valid(raw) => Ok(None),
        Kind::Array => {
            let items: Vec<Box<RawValue>> =
                serde_json::from_str(raw).map_err(|e| DecodeError(e.to_string()))?;
            let mut out = Vec::with_capacity(items.len());
            let mut err = None;
            for it in items {
                match decode_raw_map(Some(it.get())) {
                    Ok(m) => out.push(m),
                    Err(e) => {
                        err.get_or_insert(e);
                        out.push(None);
                    }
                }
            }
            match err {
                Some(e) => Err(e),
                None => Ok(Some(out)),
            }
        }
        _ => Err(DecodeError(
            "cannot unmarshal into a list of objects".into(),
        )),
    }
}

/// Encodes a decoded `any` value the way Go re-encodes `map[string]any`:
/// sorted keys, numbers as float64.
pub fn encode_any(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_float(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => push_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_any(it, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_string(out, k);
                out.push(':');
                encode_any(&m[k], out);
            }
            out.push('}');
        }
    }
}

/// Formats a float64 like `encoding/json`.
pub fn format_float(f: f64) -> String {
    let abs = f.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let e = format!("{f:e}");
        let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
        let exp: i32 = exp.parse().unwrap_or(0);
        if exp < 0 {
            format!("{mant}e-{}", -exp)
        } else {
            format!("{mant}e+{exp:02}")
        }
    } else {
        format!("{f}")
    }
}

/// Decodes into a `serde_json::Value` the way Go decodes into `any`: the
/// caller formats numbers back as float64 with [`encode_any`].
pub fn decode_any(raw: &str) -> Option<serde_json::Value> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const LT: &str = concat!("\\", "u", "003c");
    pub(crate) const GT: &str = concat!("\\", "u", "003e");
    pub(crate) const AMP: &str = concat!("\\", "u", "0026");

    #[test]
    fn strings_escape_like_go() {
        assert_eq!(string("a<b>&c"), format!("\"a{LT}b{GT}{AMP}c\""));
        assert_eq!(
            string("\u{1}\u{8}\u{c}\n\r\t\"\\"),
            r#""\u0001\b\f\n\r\t\"\\""#
        );
        assert_eq!(string("\u{2028}\u{2029}é"), "\"\\u2028\\u2029é\"");
        assert_eq!(string("\u{7f}"), "\"\u{7f}\"");
    }

    #[test]
    fn compact_like_go() {
        assert_eq!(
            compact(" { \"a\" : [1, 2] , \"b\":\"x y\" } ", false),
            r#"{"a":[1,2],"b":"x y"}"#
        );
        assert_eq!(
            compact(r#"{"a":"<\"&>"}"#, true),
            format!(r#"{{"a":"{LT}\"{AMP}{GT}"}}"#)
        );
        assert_eq!(compact(r#"{"a":"<"}"#, false), r#"{"a":"<"}"#);
    }

    #[test]
    fn maps_sort_keys() {
        let v = map([
            ("jsonrpc", s("2.0")),
            ("id", GoValue::Raw("1".into())),
            (
                "error",
                map([("message", s("m")), ("code", GoValue::Int(-32602))]),
            ),
        ]);
        assert_eq!(
            v.encode(),
            r#"{"error":{"code":-32602,"message":"m"},"id":1,"jsonrpc":"2.0"}"#
        );
        assert_eq!(GoValue::Raw(String::new()).encode(), "null");
    }

    #[test]
    fn floats_like_go() {
        assert_eq!(format_float(1.0), "1");
        assert_eq!(format_float(0.5), "0.5");
        assert_eq!(format_float(1e21), "1e+21");
        assert_eq!(format_float(1.5e-7), "1.5e-7");
        assert_eq!(format_float(123456789.0), "123456789");
        assert_eq!(format_float(-2e-10), "-2e-10");
        assert_eq!(format_float(1e100), "1e+100");
    }

    #[test]
    fn struct_fields_fold_and_last_wins() {
        let e = object(r#"{"ID":1,"id":"x","Method":"a","method":null}"#)
            .unwrap()
            .unwrap();
        let mut errs = vec![];
        assert_eq!(e.string("method", &mut errs), Some("a".into()));
        assert!(errs.is_empty());
        assert_eq!(e.raw("id"), Some(r#""x""#));
        assert_eq!(e.int("id", &mut errs), Some(1));
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn ints_are_strict() {
        assert_eq!(decode_int("12"), Ok(Some(12)));
        assert_eq!(decode_int("null"), Ok(None));
        assert!(decode_int("1.0").is_err());
        assert!(decode_int("1e2").is_err());
        assert!(decode_int("\"1\"").is_err());
        assert!(decode_int("99999999999999999999").is_err());
    }

    #[test]
    fn raw_maps() {
        assert_eq!(decode_raw_map(Some("null")), Ok(None));
        assert!(decode_raw_map(Some("[1]")).is_err());
        assert!(decode_raw_map(None).is_err());
        let m = decode_raw_map(Some(r#"{"b":1,"a":{"x" : 2},"b":3}"#)).unwrap();
        assert_eq!(encode_raw_map(&m), r#"{"a":{"x":2},"b":3}"#);
        assert_eq!(
            encode_raw_maps(&decode_raw_maps(Some("null")).unwrap()),
            "null"
        );
        assert!(decode_raw_maps(Some(r#"[{"a":1},2]"#)).is_err());
        assert_eq!(
            encode_raw_maps(&decode_raw_maps(Some(r#"[{"b":1,"a":2},null]"#)).unwrap()),
            r#"[{"a":2,"b":1},null]"#
        );
    }
}

//! The HTTP message shapes of `api/openapi.yaml`, encoded exactly like the Go
//! server's `json.NewEncoder(w).Encode(v)` (fields in the generated order,
//! optional fields left out, a trailing newline).

use crate::gojson::{self, push_string};

/// `GET /health`.
pub fn health() -> String {
    "{\"ok\":true}\n".to_string()
}

/// The error body every non-2xx JSON response carries.
pub fn error_body(code: &str, message: &str) -> String {
    let mut out = String::from("{\"error\":");
    push_string(&mut out, code);
    out.push_str(",\"message\":");
    push_string(&mut out, message);
    out.push_str("}\n");
    out
}

/// `GET /api/v1/info`.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub name: Option<String>,
    pub prompt_timeout_seconds: i64,
    pub public_url: Option<String>,
    pub version: String,
    pub wire_versions: Vec<String>,
}

impl Info {
    pub fn encode(&self) -> String {
        let mut out = String::from("{");
        if let Some(n) = &self.name {
            out.push_str("\"name\":");
            push_string(&mut out, n);
            out.push(',');
        }
        out.push_str("\"promptTimeoutSeconds\":");
        out.push_str(&self.prompt_timeout_seconds.to_string());
        if let Some(u) = &self.public_url {
            out.push_str(",\"publicUrl\":");
            push_string(&mut out, u);
        }
        out.push_str(",\"version\":");
        push_string(&mut out, &self.version);
        out.push_str(",\"wireVersions\":[");
        for (i, v) in self.wire_versions.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_string(&mut out, v);
        }
        out.push_str("]}\n");
        out
    }
}

/// `agentInfo` as the agent reported it in `initialize`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentInfo {
    pub name: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
}

impl AgentInfo {
    /// Decodes like Go into `*api.AgentInfo`: `None` for null or a non-object,
    /// fields of the wrong type left out.
    pub fn decode(raw: Option<&str>) -> Option<AgentInfo> {
        let e = gojson::object(raw?).ok()??;
        let mut errs = Vec::new();
        Some(AgentInfo {
            name: e.string("name", &mut errs),
            title: e.string("title", &mut errs),
            version: e.string("version", &mut errs),
        })
    }

    pub fn encode_into(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        for (k, v) in [
            ("name", &self.name),
            ("title", &self.title),
            ("version", &self.version),
        ] {
            if let Some(v) = v {
                if !first {
                    out.push(',');
                }
                first = false;
                push_string(out, k);
                out.push(':');
                push_string(out, v);
            }
        }
        out.push('}');
    }
}

/// One workspace a token may use.
#[derive(Clone, Debug, Default)]
pub struct Workspace {
    pub default: bool,
    pub name: String,
}

/// One entry of `GET /api/v1/agents`.
#[derive(Clone, Debug, Default)]
pub struct Agent {
    /// A decoded `map[string]any`, re-encoded with float64 numbers like Go.
    pub agent_capabilities: Option<serde_json::Map<String, serde_json::Value>>,
    pub agent_info: Option<AgentInfo>,
    pub auth_hint: Option<String>,
    pub description: Option<String>,
    pub error: Option<String>,
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub workspaces: Vec<Workspace>,
}

impl Agent {
    fn encode_into(&self, out: &mut String) {
        out.push('{');
        if let Some(c) = &self.agent_capabilities {
            out.push_str("\"agentCapabilities\":");
            gojson::encode_any(&serde_json::Value::Object(c.clone()), out);
            out.push(',');
        }
        if let Some(i) = &self.agent_info {
            out.push_str("\"agentInfo\":");
            i.encode_into(out);
            out.push(',');
        }
        for (k, v) in [
            ("authHint", &self.auth_hint),
            ("description", &self.description),
            ("error", &self.error),
        ] {
            if let Some(v) = v {
                push_string(out, k);
                out.push(':');
                push_string(out, v);
                out.push(',');
            }
        }
        out.push_str("\"id\":");
        push_string(out, &self.id);
        if let Some(n) = &self.name {
            out.push_str(",\"name\":");
            push_string(out, n);
        }
        out.push_str(",\"status\":");
        push_string(out, &self.status);
        out.push_str(",\"workspaces\":[");
        for (i, w) in self.workspaces.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            if w.default {
                out.push_str("\"default\":true,");
            }
            out.push_str("\"name\":");
            push_string(out, &w.name);
            out.push('}');
        }
        out.push_str("]}");
    }
}

/// `GET /api/v1/agents`.
pub fn agent_list(agents: &[Agent]) -> String {
    let mut out = String::from("{\"agents\":[");
    for (i, a) in agents.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        a.encode_into(&mut out);
    }
    out.push_str("]}\n");
    out
}

/// The `{"error": ..., "message": ...}` body of a failed upgrade, read the way
/// the Go bridge reads it: the first JSON value, fields of the wrong type left empty.
pub fn decode_error_body(body: &[u8]) -> (String, String) {
    let body = &body[..body.len().min(64 << 10)];
    let mut it =
        serde_json::Deserializer::from_slice(body).into_iter::<Box<serde_json::value::RawValue>>();
    let Some(Ok(first)) = it.next() else {
        return (String::new(), String::new());
    };
    let Ok(Some(e)) = gojson::object(first.get()) else {
        return (String::new(), String::new());
    };
    let mut errs = Vec::new();
    (
        e.string("error", &mut errs).unwrap_or_default(),
        e.string("message", &mut errs).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_match_go() {
        assert_eq!(
            error_body("unauthorized", "missing or invalid token"),
            "{\"error\":\"unauthorized\",\"message\":\"missing or invalid token\"}\n"
        );
        let info = Info {
            name: None,
            prompt_timeout_seconds: 86400,
            public_url: None,
            version: "dev".into(),
            wire_versions: vec!["actp.v1".into()],
        };
        assert_eq!(
            info.encode(),
            "{\"promptTimeoutSeconds\":86400,\"version\":\"dev\",\"wireVersions\":[\"actp.v1\"]}\n"
        );
        let caps: serde_json::Value = serde_json::json!({"loadSession": true, "promptCapabilities": {"image": false}, "n": 3});
        let a = Agent {
            agent_capabilities: caps.as_object().cloned(),
            agent_info: Some(AgentInfo {
                name: Some("x".into()),
                title: None,
                version: Some("1".into()),
            }),
            id: "test".into(),
            name: Some("test".into()),
            status: "ready".into(),
            workspaces: vec![
                Workspace {
                    default: true,
                    name: "site".into(),
                },
                Workspace {
                    default: false,
                    name: "b".into(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            agent_list(&[a]),
            "{\"agents\":[{\"agentCapabilities\":{\"loadSession\":true,\"n\":3,\"promptCapabilities\":{\"image\":false}},\"agentInfo\":{\"name\":\"x\",\"version\":\"1\"},\"id\":\"test\",\"name\":\"test\",\"status\":\"ready\",\"workspaces\":[{\"default\":true,\"name\":\"site\"},{\"name\":\"b\"}]}]}\n"
        );
        assert_eq!(agent_list(&[]), "{\"agents\":[]}\n");
    }

    #[test]
    fn error_bodies() {
        assert_eq!(
            decode_error_body(b"{\"error\":\"x\",\"message\":\"y\"}\n"),
            ("x".into(), "y".into())
        );
        assert_eq!(
            decode_error_body(b"404 page not found\n"),
            (String::new(), String::new())
        );
        assert_eq!(
            decode_error_body(b"{\"error\":1,\"message\":\"y\"} trailing"),
            (String::new(), "y".into())
        );
    }
}

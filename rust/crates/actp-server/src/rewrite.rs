//! The rewrites of design 3.3: working folders, client capabilities, terminal
//! login hints and MCP servers. A port of Go's `internal/server/rewrite.go`.

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use actp_proto::gojson::{self, RawMap};

use crate::config::{self, Server, Token};

/// The cwd form that names a workspace: `actp://<workspace>/<sub/path>`.
pub const WORKSPACE_SCHEME: &str = "actp://";

const SEP: &str = std::path::MAIN_SEPARATOR_STR;

/// Maps a client cwd to a folder on this machine. The error is the message
/// the client gets (`cwd not allowed: ...`).
pub fn resolve_cwd(s: &Server, tok: &Token, cwd: &str) -> Result<String, String> {
    let allowed: Vec<String> = tok.allowed_workspaces(s);
    let in_workspace = |name: &str, sub: &str| -> Result<String, String> {
        let ws = s
            .workspace(name)
            .filter(|_| allowed.iter().any(|a| a == name));
        let Some(ws) = ws else {
            return Err(format!(
                "cwd not allowed: {cwd} (unknown workspace {})",
                config::quote(name)
            ));
        };
        let root = real_path(&ws.path);
        let target = real_path(&join(&root, &from_slash(sub)));
        if !within(&target, &root) {
            return Err(format!(
                "cwd not allowed: {cwd} (leaves workspace {})",
                config::quote(name)
            ));
        }
        Ok(target)
    };

    if let Some(rest) = cwd.strip_prefix(WORKSPACE_SCHEME) {
        let (name, sub) = rest.split_once('/').unwrap_or((rest, ""));
        return in_workspace(name, sub);
    }
    if Path::new(cwd).is_absolute() {
        let target = real_path(cwd);
        for w in &s.workspaces {
            if allowed.iter().any(|a| a == &w.name) && within(&target, &real_path(&w.path)) {
                return Ok(target);
            }
        }
    }
    // Longest matching prefix wins, so nested mappings behave.
    let clean_cwd = to_slash(&clean(cwd));
    let mut keys: Vec<&String> = tok.map.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for from in keys {
        let f = to_slash(&clean(from));
        let f = f.strip_suffix('/').unwrap_or(&f);
        if clean_cwd == f || clean_cwd.starts_with(&format!("{f}/")) {
            let after = &clean_cwd[f.len()..];
            let rest = after.strip_prefix('/').unwrap_or(after);
            return in_workspace(&tok.map[from], rest);
        }
    }
    if tok.cwd_fallback && !tok.default_workspace.is_empty() {
        return in_workspace(&tok.default_workspace, "");
    }
    Err(format!("cwd not allowed: {cwd}"))
}

/// Go's `filepath.Clean`: lexical, `.` for an empty path.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let path = Path::new(p);
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts: Vec<String> = Vec::new();
    for c in path.components() {
        match c {
            Component::Prefix(pre) => prefix = pre.as_os_str().to_string_lossy().into_owned(),
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|l| l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..".into());
                }
            }
            Component::Normal(n) => parts.push(n.to_string_lossy().into_owned()),
        }
    }
    let mut out = prefix;
    if rooted {
        out.push_str(SEP);
    }
    out.push_str(&parts.join(SEP));
    if out.is_empty() { ".".into() } else { out }
}

/// Go's `filepath.Join`: concatenates, then cleans.
fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => clean(b),
        (false, true) => clean(a),
        (false, false) => clean(&format!("{a}{SEP}{b}")),
    }
}

fn from_slash(p: &str) -> String {
    if cfg!(windows) {
        p.replace('/', "\\")
    } else {
        p.to_string()
    }
}

fn to_slash(p: &str) -> String {
    if cfg!(windows) {
        p.replace('\\', "/")
    } else {
        p.to_string()
    }
}

/// Resolves symlinks like Go's `filepath.EvalSymlinks`, without Windows' `\\?\` prefix.
fn eval_symlinks(p: &str) -> Option<String> {
    let r = std::fs::canonicalize(p).ok()?;
    let s = r.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return Some(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return Some(rest.to_string());
        }
    }
    Some(s)
}

/// Cleans a path and resolves symlinks for the part that exists.
pub fn real_path(p: &str) -> String {
    let p = clean(p);
    if let Some(r) = eval_symlinks(&p) {
        return r;
    }
    // Resolve the nearest existing parent, keep the rest as written.
    let mut dir = PathBuf::from(&p);
    let mut rest = PathBuf::new();
    loop {
        let Some(parent) = dir.parent().map(Path::to_path_buf) else {
            return p;
        };
        let base = dir.file_name().map(PathBuf::from).unwrap_or_default();
        rest = base.join(&rest);
        if parent.as_os_str().is_empty() || parent == dir {
            return p;
        }
        dir = parent;
        if let Some(r) = eval_symlinks(&dir.to_string_lossy()) {
            let rest_s = rest.to_string_lossy();
            let rest_s = rest_s.trim_end_matches(['/', '\\']);
            return join(&r, rest_s);
        }
    }
}

/// Whether `path` is `root` or inside it.
pub fn within(path: &str, root: &str) -> bool {
    let p: Vec<String> = Path::new(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let r: Vec<String> = Path::new(root)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if r.len() > p.len() {
        return false;
    }
    r.iter().zip(&p).all(|(a, b)| {
        if cfg!(windows) {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    })
}

/// Session methods that create, load or re-target a session, or resolve options
/// for a folder: they need an allowed cwd (design 3.3). `session/list` may omit it.
pub fn session_cwd_required(method: &str) -> bool {
    matches!(
        method,
        "session/new" | "session/load" | "session/resume" | "session/fork" | "session/options"
    )
}

/// Session methods that take no folders, MCP servers or session options, so
/// they pass through as they are.
fn session_plain(method: &str) -> bool {
    matches!(
        method,
        "session/prompt"
            | "session/cancel"
            | "session/close"
            | "session/set_mode"
            | "session/set_model"
            | "session/set_config_option"
            | "session/status"
            | "session/set_title"
            | "session/delete"
            | "session/archive"
            | "session/unarchive"
    )
}

/// The params actp checks on session requests.
const POLICY_FIELDS: [&str; 4] = ["cwd", "additionalDirectories", "mcpServers", "_meta"];

/// The first policy field carried by a session method actp does not know: such
/// a message could create or re-target a session past the checks, so it is
/// refused instead of forwarded (default deny).
pub fn unchecked_session_field(method: &str, p: &RawMap) -> Option<&'static str> {
    if !method.starts_with("session/")
        || session_plain(method)
        || session_cwd_required(method)
        || method == "session/list"
    {
        return None;
    }
    let p = p.as_ref()?;
    POLICY_FIELDS.into_iter().find(|f| p.contains_key(*f))
}

pub fn unchecked_session_message(method: &str, field: &str) -> String {
    format!(
        "invalid request: actp does not know {method} and cannot check its {}",
        config::quote(field)
    )
}

/// Applies the cwd rules to every entry of `additionalDirectories`, without the
/// token's `cwd_fallback`: an unknown folder must not silently become the
/// default workspace. `null` stays `null`. The result is encoded JSON.
pub fn resolve_additional_directories(
    s: &Server,
    tok: &Token,
    raw: &str,
) -> Result<String, String> {
    if gojson::kind(raw) == gojson::Kind::Null {
        return Ok(raw.to_string());
    }
    let list_err = || "additionalDirectories must be a list of folders".to_string();
    if gojson::kind(raw) != gojson::Kind::Array {
        return Err(list_err());
    }
    let items: Vec<Box<serde_json::value::RawValue>> =
        serde_json::from_str(raw).map_err(|_| list_err())?;
    let mut dirs = Vec::with_capacity(items.len());
    for it in &items {
        dirs.push(
            gojson::decode_string(it.get())
                .map_err(|_| list_err())?
                .unwrap_or_default(),
        );
    }
    let strict = Token {
        cwd_fallback: false,
        ..tok.clone()
    };
    let mut out = Vec::with_capacity(dirs.len());
    for d in dirs {
        match resolve_cwd(s, &strict, &d) {
            Ok(r) => out.push(gojson::GoValue::Str(r)),
            Err(e) => {
                return Err(format!(
                    "additional directory not allowed: {}",
                    e.strip_prefix("cwd not allowed: ").unwrap_or(&e)
                ));
            }
        }
    }
    Ok(gojson::GoValue::Arr(out).encode())
}

/// Keeps only the allow-listed top-level keys of a session request's `_meta`
/// (agent setting `keep_session_meta`, empty by default). Agents read `_meta` as
/// options (Claude's adapter takes SDK options and MCP servers from it), so by
/// default it is dropped. `None` means: drop `_meta`.
pub fn keep_meta_keys(raw: &str, keep: &[String]) -> Option<String> {
    if keep.is_empty() {
        return None;
    }
    let meta = gojson::decode_raw_map(Some(raw)).ok()??;
    let kept: std::collections::BTreeMap<String, String> = keep
        .iter()
        .filter_map(|k| meta.get(k).map(|v| (k.clone(), v.clone())))
        .collect();
    if kept.is_empty() {
        return None;
    }
    Some(gojson::encode_raw_map(&Some(kept)))
}

/// Removes `fs` and `terminal` from `initialize` params. `None` when the
/// params are not an object (or missing), like Go's error.
pub fn strip_client_capabilities(params: Option<&str>) -> Option<String> {
    let mut p = gojson::decode_raw_map(params).ok()?;
    if let Some(m) = p.as_mut()
        && let Some(raw) = m.get("clientCapabilities").cloned()
        && let Ok(mut caps) = gojson::decode_raw_map(Some(&raw))
    {
        if let Some(c) = caps.as_mut() {
            c.remove("fs");
            c.remove("terminal");
        }
        m.insert("clientCapabilities".into(), gojson::encode_raw_map(&caps));
    }
    Some(gojson::encode_raw_map(&p))
}

/// Removes terminal-login hints from an `initialize` result, because the
/// client would run that login on its own machine.
pub fn strip_terminal_auth(result: Option<&str>) -> Option<String> {
    let Ok(mut r) = gojson::decode_raw_map(result) else {
        return None;
    };
    let m = r.as_mut()?;
    let mut changed = false;
    if let Some(raw) = m.get("authMethods").cloned()
        && let Ok(mut methods) = gojson::decode_raw_maps(Some(&raw))
    {
        for mm in methods.iter_mut().flatten() {
            if drop_meta_key(mm, "terminal-auth") {
                changed = true;
            }
        }
        m.insert("authMethods".into(), gojson::encode_raw_maps(&methods));
    }
    if let Some(raw) = m.get("agentCapabilities").cloned()
        && let Ok(mut caps) = gojson::decode_raw_map(Some(&raw))
        && drop_meta_key(&mut caps, "terminal-auth")
    {
        m.insert("agentCapabilities".into(), gojson::encode_raw_map(&caps));
        changed = true;
    }
    if !changed {
        return None;
    }
    Some(gojson::encode_raw_map(&r))
}

fn drop_meta_key(obj: &mut RawMap, key: &str) -> bool {
    let Some(o) = obj.as_mut() else {
        return false;
    };
    let Some(raw) = o.get("_meta").cloned() else {
        return false;
    };
    let Ok(Some(mut meta)) = gojson::decode_raw_map(Some(&raw)) else {
        return false;
    };
    if meta.remove(key).is_none() {
        return false;
    }
    if meta.is_empty() {
        o.remove("_meta");
    } else {
        o.insert("_meta".into(), gojson::encode_raw_map(&Some(meta)));
    }
    true
}

/// Applies a token's MCP policy: the kept entries (encoded) and a short
/// description of each dropped one. `None` leaves the value as it was.
pub fn filter_mcp_servers(policy: &str, servers: &str) -> (Option<String>, Vec<String>) {
    if servers.is_empty() {
        return (None, Vec::new());
    }
    let Ok(list) = gojson::decode_raw_maps(Some(servers)) else {
        return (None, Vec::new());
    };
    let mut kept: Vec<RawMap> = Vec::new();
    let mut dropped = Vec::new();
    for entry in list.unwrap_or_default() {
        let field = |k: &str| {
            gojson::string_or_empty(entry.as_ref().and_then(|m| m.get(k)).map(String::as_str))
        };
        let name = field("name");
        let mut typ = field("type");
        if typ.is_empty() {
            typ = "stdio".into();
        }
        if policy == "all" {
            kept.push(entry);
        } else if policy == "none" {
            dropped.push(format!("{name} (mcp_servers: none)"));
        } else if typ == "stdio" {
            dropped.push(format!(
                "{name} (stdio would run a command on the agent host)"
            ));
        } else if is_loopback_url(&field("url")) {
            dropped.push(format!(
                "{name} (localhost means the agent host, not the client)"
            ));
        } else {
            kept.push(entry);
        }
    }
    (Some(gojson::encode_raw_maps(&Some(kept))), dropped)
}

/// The host of a URL the way Go's `url.Parse(raw).Hostname()` finds it.
fn url_hostname(raw: &str) -> String {
    let mut rest = raw;
    // An optional scheme: a letter, then letters, digits, + - . up to ':'.
    if let Some(i) = rest.find(':') {
        let scheme = &rest[..i];
        if !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
        {
            rest = &rest[i + 1..];
        }
    }
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let Some(auth) = rest.strip_prefix("//") else {
        return String::new();
    };
    let auth = auth.split('/').next().unwrap_or("");
    let host_port = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let mut host = host_port;
    if let Some(colon) = host_port.rfind(':') {
        let port = &host_port[colon + 1..];
        if port.bytes().all(|b| b.is_ascii_digit()) {
            host = &host_port[..colon];
        }
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    host.to_string()
}

/// Whether a URL points at this machine.
pub fn is_loopback_url(raw: &str) -> bool {
    let host = url_hostname(raw);
    let lower = host.to_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
        Err(_) => false,
    }
}

/// Where agents start when the token has no workspace.
pub fn home_dir() -> PathBuf {
    config::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn setup() -> (PathBuf, Server, Token) {
        let root = std::env::temp_dir().join(format!("actp-rw-{}-{}", std::process::id(), {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        }));
        let root = PathBuf::from(real_path(&root.to_string_lossy()));
        let site = root.join("site");
        std::fs::create_dir_all(site.join("sub")).unwrap();
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let s = Server {
            workspaces: vec![
                config::Workspace {
                    name: "site".into(),
                    path: site.to_string_lossy().into(),
                },
                config::Workspace {
                    name: "other".into(),
                    path: other.to_string_lossy().into(),
                },
            ],
            ..Default::default()
        };
        let mut map = BTreeMap::new();
        map.insert("/client/repo".to_string(), "site".to_string());
        let tok = Token {
            name: "t".into(),
            workspaces: vec!["site".into()],
            default_workspace: "site".into(),
            map,
            ..Default::default()
        };
        (root, s, tok)
    }

    #[test]
    fn resolves_cwd() {
        let (root, s, tok) = setup();
        let site = root.join("site").to_string_lossy().into_owned();
        assert_eq!(resolve_cwd(&s, &tok, "actp://site").unwrap(), site);
        assert_eq!(
            resolve_cwd(&s, &tok, "actp://site/sub").unwrap(),
            join(&site, "sub")
        );
        assert!(
            resolve_cwd(&s, &tok, "actp://site/../other")
                .unwrap_err()
                .contains("leaves workspace \"site\"")
        );
        assert!(
            resolve_cwd(&s, &tok, "actp://other")
                .unwrap_err()
                .contains("unknown workspace \"other\"")
        );
        assert_eq!(
            resolve_cwd(&s, &tok, &join(&site, "sub")).unwrap(),
            join(&site, "sub")
        );
        assert_eq!(
            resolve_cwd(&s, &tok, &join(&site, "new/deeper")).unwrap(),
            join(&site, &from_slash("new/deeper"))
        );
        assert_eq!(
            resolve_cwd(&s, &tok, "/client/repo/sub").unwrap(),
            join(&site, "sub")
        );
        assert_eq!(
            resolve_cwd(&s, &tok, "/somewhere/else").unwrap_err(),
            "cwd not allowed: /somewhere/else"
        );
        let fallback = Token {
            cwd_fallback: true,
            ..tok
        };
        assert_eq!(resolve_cwd(&s, &fallback, "/somewhere/else").unwrap(), site);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolves_additional_directories() {
        let (root, s, tok) = setup();
        let tok = Token {
            cwd_fallback: true,
            ..tok
        };
        let sub = join(&root.join("site").to_string_lossy(), "sub");
        assert_eq!(
            resolve_additional_directories(&s, &tok, r#"["actp://site/sub"]"#).unwrap(),
            actp_proto::gojson::GoValue::Arr(vec![actp_proto::gojson::GoValue::Str(sub)]).encode()
        );
        // cwd_fallback must not turn an unknown folder into the default workspace.
        for raw in [
            r#"["actp://site","/"]"#,
            r#"["actp://other"]"#,
            r#"[""]"#,
            r#""actp://site""#,
            "[1]",
        ] {
            assert!(
                resolve_additional_directories(&s, &tok, raw).is_err(),
                "{raw}"
            );
        }
        assert_eq!(
            resolve_additional_directories(&s, &tok, "null").unwrap(),
            "null"
        );
        assert_eq!(
            resolve_additional_directories(&s, &tok, r#"["/"]"#).unwrap_err(),
            "additional directory not allowed: /"
        );
    }

    #[test]
    fn keeps_only_allowed_meta_keys() {
        let meta = r#"{"claudeCode":{"options":{"mcpServers":{}}},"trace":"x"}"#;
        assert_eq!(keep_meta_keys(meta, &[]), None);
        assert_eq!(
            keep_meta_keys(meta, &["trace".to_string()]).as_deref(),
            Some(r#"{"trace":"x"}"#)
        );
        assert_eq!(keep_meta_keys(meta, &["absent".to_string()]), None);
    }

    #[test]
    fn refuses_unknown_session_methods_with_policy_fields() {
        let p: RawMap = Some(
            [
                ("sessionId".to_string(), "\"s\"".to_string()),
                ("cwd".to_string(), "\"/\"".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            unchecked_session_field("session/frobnicate", &p),
            Some("cwd")
        );
        for m in [
            "session/prompt",
            "session/fork",
            "session/list",
            "initialize",
        ] {
            assert_eq!(unchecked_session_field(m, &p), None, "{m}");
        }
        for f in ["additionalDirectories", "mcpServers", "_meta"] {
            let p: RawMap = Some([(f.to_string(), "null".to_string())].into_iter().collect());
            assert_eq!(unchecked_session_field("session/frobnicate", &p), Some(f));
        }
        let plain: RawMap = Some(
            [("sessionId".to_string(), "\"s\"".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(unchecked_session_field("session/frobnicate", &plain), None);
        assert_eq!(
            unchecked_session_message("session/x", "cwd"),
            "invalid request: actp does not know session/x and cannot check its \"cwd\""
        );
    }

    #[test]
    fn strips_capabilities() {
        let out = strip_client_capabilities(Some(r#"{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":true},"terminal":true,"elicitation":{}}}"#)).unwrap();
        assert_eq!(
            out,
            r#"{"clientCapabilities":{"elicitation":{}},"protocolVersion":1}"#
        );
        assert_eq!(strip_client_capabilities(Some("null")).unwrap(), "null");
        assert!(strip_client_capabilities(None).is_none());
        assert!(strip_client_capabilities(Some("[1]")).is_none());
    }

    #[test]
    fn strips_terminal_auth() {
        let r = r#"{"authMethods":[{"id":"login","_meta":{"terminal-auth":true}}],"protocolVersion":1}"#;
        assert_eq!(
            strip_terminal_auth(Some(r)).unwrap(),
            r#"{"authMethods":[{"id":"login"}],"protocolVersion":1}"#
        );
        assert!(strip_terminal_auth(Some(r#"{"authMethods":[{"id":"x"}]}"#)).is_none());
    }

    #[test]
    fn filters_mcp_servers() {
        let servers = r#"[{"name":"local","command":"npx"},{"name":"web","type":"http","url":"https://mcp.example.com"},{"name":"lo","type":"sse","url":"http://127.0.0.1:3000/sse"},{"name":"lh","type":"http","url":"http://app.localhost/x"}]"#;
        let (kept, dropped) = filter_mcp_servers("remote", servers);
        assert_eq!(
            kept.unwrap(),
            r#"[{"name":"web","type":"http","url":"https://mcp.example.com"}]"#
        );
        assert_eq!(dropped.len(), 3);
        let (kept, dropped) = filter_mcp_servers("none", servers);
        assert_eq!((kept.unwrap().as_str(), dropped.len()), ("[]", 4));
        assert_eq!(filter_mcp_servers("remote", "null").0.unwrap(), "[]");
        assert_eq!(filter_mcp_servers("remote", r#""x""#).0, None);
    }

    #[test]
    fn loopback_urls() {
        for (u, want) in [
            ("http://localhost:3000", true),
            ("http://[::1]/x", true),
            ("http://0.0.0.0", true),
            ("https://example.com", false),
            ("http://user@127.0.0.2:9/", true),
            ("//localhost/x", true),
            ("localhost:3000", false),
            ("http://[::ffff:127.0.0.1]/", true),
        ] {
            assert_eq!(is_loopback_url(u), want, "{u}");
        }
    }

    #[test]
    fn cleans_like_go() {
        if cfg!(unix) {
            for (a, b) in [
                ("", "."),
                ("/a/../b", "/b"),
                ("a/./b/", "a/b"),
                ("/../a", "/a"),
                ("../a", "../a"),
                ("a/../..", ".."),
            ] {
                assert_eq!(clean(a), b, "{a}");
            }
        }
    }
}

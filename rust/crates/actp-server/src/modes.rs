//! Session modes (design 3.3). An agent mode can turn permission prompts off
//! (Claude's `bypassPermissions`), which would make the permission policy and
//! the human approval step meaningless. So a client may switch only to allowed
//! modes: an agent's `allowed_modes`, or by default the modes that keep prompts
//! or only narrow what runs. Unknown mode ids are refused. A port of Go's
//! `internal/server/modes.go`.

use std::collections::HashSet;

use actp_proto::gojson::{self, RawMap};

use crate::config::{Agent, Token};

/// Allowed when an agent sets no `allowed_modes`.
pub const DEFAULT_SAFE_MODES: [&str; 5] = ["default", "plan", "dontAsk", "acceptEdits", "auto"];

/// Modes that approve some actions without asking. A token whose permissions
/// are `auto_deny` never gets them: they would allow what actp denies.
const PROMPT_SKIPPING_MODES: [&str; 3] = ["acceptEdits", "auto", "bypassPermissions"];

pub const UNREADABLE_MODE: &str = "mode not allowed: the requested mode is not a string";

/// Whether a client may switch a session to `mode`.
pub fn mode_allowed(agent: &Agent, tok: &Token, mode: &str) -> bool {
    if tok.effective_permissions(agent) == "auto_deny" && PROMPT_SKIPPING_MODES.contains(&mode) {
        return false;
    }
    if agent.allowed_modes.is_empty() {
        DEFAULT_SAFE_MODES.contains(&mode)
    } else {
        agent.allowed_modes.iter().any(|m| m == mode)
    }
}

fn string_of(raw: Option<&String>) -> Option<String> {
    raw.and_then(|r| gojson::decode_string(r).ok().flatten())
}

/// The modes a client request would switch a session to: `session/set_mode`,
/// `session/set_config_option` on a mode option, and mode entries in the
/// `configOptions` of session setup requests. `Err` is the refusal message.
pub fn requested_modes(
    method: &str,
    p: &RawMap,
    is_mode_option: impl Fn(&str) -> bool,
) -> Result<Vec<String>, &'static str> {
    let get = |k: &str| p.as_ref().and_then(|m| m.get(k));
    match method {
        "session/set_mode" => string_of(get("modeId"))
            .map(|m| vec![m])
            .ok_or(UNREADABLE_MODE),
        "session/set_config_option" => {
            let id = string_of(get("configId")).unwrap_or_default();
            if !is_mode_option(&id) {
                return Ok(Vec::new());
            }
            string_of(get("value"))
                .map(|m| vec![m])
                .ok_or(UNREADABLE_MODE)
        }
        m if crate::rewrite::session_cwd_required(m) || m == "session/list" => {
            let Ok(Some(entries)) =
                gojson::decode_raw_maps(get("configOptions").map(String::as_str))
            else {
                return Ok(Vec::new());
            };
            let mut modes = Vec::new();
            for e in entries.iter().flatten() {
                let id = string_of(e.get("configId")).unwrap_or_default();
                if !is_mode_option(&id) {
                    continue;
                }
                modes.push(string_of(e.get("value")).ok_or(UNREADABLE_MODE)?);
            }
            Ok(modes)
        }
        _ => Ok(Vec::new()),
    }
}

/// Records, from a session response, which config options select the mode and
/// which mode ids the agent offers.
pub fn learn_modes(
    result: Option<&str>,
    mode_options: &mut HashSet<String>,
    offered: &mut HashSet<String>,
) {
    let Some(v) = result.and_then(gojson::decode_any) else {
        return;
    };
    let s = |v: &serde_json::Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
    if let Some(modes) = v
        .pointer("/modes/availableModes")
        .and_then(|m| m.as_array())
    {
        offered.extend(modes.iter().filter_map(|m| m.get("id").and_then(s)));
    }
    for o in v
        .get("configOptions")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
    {
        let id = o.get("id").and_then(s).unwrap_or_default();
        if o.get("category").and_then(|c| c.as_str()) != Some("mode") && id != "mode" {
            continue;
        }
        mode_options.insert(id);
        for opt in o
            .get("options")
            .and_then(|c| c.as_array())
            .into_iter()
            .flatten()
        {
            offered.extend(opt.get("value").and_then(s));
            for g in opt
                .get("options")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten()
            {
                offered.extend(g.get("value").and_then(s));
            }
        }
    }
}

/// The mode a client's answer to a permission request selects, when that
/// option is one of the agent's modes (Claude's plan-mode exit offers
/// "Yes, and bypass permissions" as option `bypassPermissions`).
pub fn permission_picks_mode(result: Option<&str>, offered: &HashSet<String>) -> Option<String> {
    let v = result.and_then(gojson::decode_any)?;
    if v.pointer("/outcome/outcome")?.as_str()? != "selected" {
        return None;
    }
    let id = v.pointer("/outcome/optionId")?.as_str()?;
    (offered.contains(id) || id == "bypassPermissions").then(|| id.to_string())
}

/// A session response's current mode values (`modes.currentModeId` and the
/// `currentValue` of mode config options) and the modes it offers, in order.
pub fn starting_modes(result: Option<&str>) -> (Vec<String>, Vec<String>) {
    let (mut current, mut offered) = (Vec::new(), Vec::new());
    let Some(v) = result.and_then(gojson::decode_any) else {
        return (current, offered);
    };
    let add = |list: &mut Vec<String>, v: Option<&serde_json::Value>| {
        if let Some(s) = v.and_then(|v| v.as_str()).filter(|s| !s.is_empty())
            && !list.iter().any(|x| x == s)
        {
            list.push(s.to_string());
        }
    };
    add(&mut current, v.pointer("/modes/currentModeId"));
    for m in v
        .pointer("/modes/availableModes")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
    {
        add(&mut offered, m.get("id"));
    }
    for o in v
        .get("configOptions")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
    {
        let is_mode = o.get("category").and_then(|c| c.as_str()) == Some("mode")
            || o.get("id").and_then(|c| c.as_str()) == Some("mode");
        if !is_mode {
            continue;
        }
        add(&mut current, o.get("currentValue"));
        for opt in o
            .get("options")
            .and_then(|c| c.as_array())
            .into_iter()
            .flatten()
        {
            add(&mut offered, opt.get("value"));
        }
    }
    (current, offered)
}

/// The mode a session that starts in a refused mode is switched to: the
/// agent's `default` when offered and allowed, else the first allowed mode it
/// offers, else none.
pub fn reset_target(offered: &[String], allowed: impl Fn(&str) -> bool) -> Option<String> {
    if offered.iter().any(|m| m == "default") && allowed("default") {
        return Some("default".into());
    }
    offered.iter().find(|m| allowed(m)).cloned()
}

/// Shows `mode` as the session's current mode in a session response.
pub fn rewrite_starting_mode(result: Option<&str>, mode: &str) -> Option<String> {
    let mut r = gojson::decode_raw_map(result).ok()??;
    let enc = gojson::string(mode);
    if let Some(raw) = r.get("modes").cloned()
        && let Ok(Some(mut modes)) = gojson::decode_raw_map(Some(&raw))
    {
        modes.insert("currentModeId".into(), enc.clone());
        r.insert("modes".into(), gojson::encode_raw_map(&Some(modes)));
    }
    if let Some(raw) = r.get("configOptions").cloned()
        && let Ok(mut opts) = gojson::decode_raw_maps(Some(&raw))
    {
        for o in opts.iter_mut().flatten().flatten() {
            let id = gojson::string_or_empty(o.get("id").map(String::as_str));
            let category = gojson::string_or_empty(o.get("category").map(String::as_str));
            if category == "mode" || id == "mode" {
                o.insert("currentValue".into(), enc.clone());
            }
        }
        r.insert("configOptions".into(), gojson::encode_raw_maps(&opts));
    }
    Some(gojson::encode_raw_map(&Some(r)))
}

#[cfg(test)]
mod starting_tests {
    use super::*;

    #[test]
    fn starting_mode_helpers() {
        let result = r#"{"sessionId":"s","modes":{"currentModeId":"bypassPermissions","availableModes":[{"id":"bypassPermissions"},{"id":"acceptEdits"},{"id":"default"}]},"configOptions":[{"id":"mode","category":"mode","type":"select","currentValue":"bypassPermissions","options":[{"value":"bypassPermissions"},{"value":"plan"}]},{"id":"model","currentValue":"opus"}]}"#;
        let (current, offered) = starting_modes(Some(result));
        assert_eq!(current, ["bypassPermissions"]);
        assert_eq!(
            offered,
            ["bypassPermissions", "acceptEdits", "default", "plan"]
        );
        let agent = Agent {
            permissions: "forward".into(),
            ..Default::default()
        };
        let tok = Token::default();
        let allowed = |m: &str| mode_allowed(&agent, &tok, m);
        assert_eq!(reset_target(&offered, allowed).as_deref(), Some("default"));
        assert_eq!(
            reset_target(&["bypassPermissions".into(), "plan".into()], allowed).as_deref(),
            Some("plan")
        );
        assert_eq!(reset_target(&["bypassPermissions".into()], allowed), None);
        assert_eq!(
            rewrite_starting_mode(Some(result), "default").unwrap(),
            r#"{"configOptions":[{"category":"mode","currentValue":"default","id":"mode","options":[{"value":"bypassPermissions"},{"value":"plan"}],"type":"select"},{"currentValue":"opus","id":"model"}],"modes":{"availableModes":[{"id":"bypassPermissions"},{"id":"acceptEdits"},{"id":"default"}],"currentModeId":"default"},"sessionId":"s"}"#
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_allowed() {
        let agent = Agent {
            permissions: "forward".into(),
            ..Default::default()
        };
        let tok = Token::default();
        for (mode, want) in [
            ("default", true),
            ("plan", true),
            ("acceptEdits", true),
            ("auto", true),
            ("dontAsk", true),
            ("bypassPermissions", false),
            ("somethingNew", false),
        ] {
            assert_eq!(mode_allowed(&agent, &tok, mode), want, "forward {mode}");
        }
        let deny = Token {
            permissions: "auto_deny".into(),
            ..Default::default()
        };
        for (mode, want) in [
            ("default", true),
            ("plan", true),
            ("acceptEdits", false),
            ("auto", false),
            ("bypassPermissions", false),
        ] {
            assert_eq!(mode_allowed(&agent, &deny, mode), want, "auto_deny {mode}");
        }
        let listed = Agent {
            allowed_modes: vec!["read-only".into(), "bypassPermissions".into()],
            ..agent
        };
        assert!(
            mode_allowed(&listed, &tok, "read-only")
                && mode_allowed(&listed, &tok, "bypassPermissions")
                && !mode_allowed(&listed, &tok, "default")
        );
        assert!(!mode_allowed(&listed, &deny, "bypassPermissions"));
    }

    #[test]
    fn modes_requested() {
        let is_mode = |id: &str| id == "mode" || id == "_perm";
        let p = |raw: &str| gojson::decode_raw_map(Some(raw)).unwrap();
        type Case<'a> = (&'a str, &'a str, Result<Vec<&'a str>, ()>);
        let cases: &[Case] = &[
            (
                "session/set_mode",
                r#"{"sessionId":"s","modeId":"bypassPermissions"}"#,
                Ok(vec!["bypassPermissions"]),
            ),
            (
                "session/set_mode",
                r#"{"sessionId":"s","modeId":1}"#,
                Err(()),
            ),
            (
                "session/set_config_option",
                r#"{"sessionId":"s","configId":"mode","value":"plan"}"#,
                Ok(vec!["plan"]),
            ),
            (
                "session/set_config_option",
                r#"{"sessionId":"s","configId":"_perm","value":"x"}"#,
                Ok(vec!["x"]),
            ),
            (
                "session/set_config_option",
                r#"{"sessionId":"s","configId":"mode","type":"boolean","value":true}"#,
                Err(()),
            ),
            (
                "session/set_config_option",
                r#"{"sessionId":"s","configId":"model","value":"opus"}"#,
                Ok(vec![]),
            ),
            (
                "session/new",
                r#"{"cwd":"/w","configOptions":[{"configId":"model","value":"x"},{"configId":"mode","value":"bypassPermissions"}]}"#,
                Ok(vec!["bypassPermissions"]),
            ),
            (
                "session/fork",
                r#"{"cwd":"/w","configOptions":[{"configId":"mode","value":"auto"}]}"#,
                Ok(vec!["auto"]),
            ),
            (
                "session/prompt",
                r#"{"sessionId":"s","configOptions":[{"configId":"mode","value":"x"}]}"#,
                Ok(vec![]),
            ),
        ];
        for (method, params, want) in cases {
            let got = requested_modes(method, &p(params), is_mode).map_err(|_| ());
            let want = want
                .clone()
                .map(|v| v.into_iter().map(str::to_string).collect::<Vec<_>>());
            assert_eq!(got, want, "{method} {params}");
        }
    }

    #[test]
    fn learns_modes_and_guards_permission_answers() {
        let (mut options, mut offered) = (HashSet::new(), HashSet::new());
        learn_modes(
            Some(
                r#"{"sessionId":"s","modes":{"currentModeId":"default","availableModes":[{"id":"default"},{"id":"plan"}]},"configOptions":[{"id":"perm","category":"mode","options":[{"value":"acceptEdits"},{"name":"g","options":[{"value":"auto"}]}]},{"id":"model","category":"model","options":[{"value":"opus"}]}]}"#,
            ),
            &mut options,
            &mut offered,
        );
        assert!(options.contains("perm") && !options.contains("model"));
        assert!(
            offered.contains("plan")
                && offered.contains("acceptEdits")
                && offered.contains("auto")
                && !offered.contains("opus")
        );
        assert_eq!(
            permission_picks_mode(
                Some(r#"{"outcome":{"outcome":"selected","optionId":"plan"}}"#),
                &offered
            )
            .as_deref(),
            Some("plan")
        );
        assert_eq!(
            permission_picks_mode(
                Some(r#"{"outcome":{"outcome":"selected","optionId":"allow"}}"#),
                &offered
            ),
            None
        );
        assert_eq!(
            permission_picks_mode(
                Some(r#"{"outcome":{"outcome":"selected","optionId":"bypassPermissions"}}"#),
                &HashSet::new()
            )
            .as_deref(),
            Some("bypassPermissions")
        );
    }
}

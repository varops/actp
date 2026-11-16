//! Probing (design 3.4): start an agent, run `initialize` without a session,
//! record what it says, stop it.

use std::path::PathBuf;
use std::time::Duration;

use actp_proto::api::AgentInfo;
use actp_proto::gojson::{self, GoValue, map, s};
use actp_proto::jsonrpc::{self, Kind, Line};
use tokio::io::BufReader;

use crate::agentproc::{Process, Spec};
use crate::config;
use crate::server::Server;

/// How long an agent may take to answer `initialize`.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

struct ProbeResult {
    info: Option<AgentInfo>,
    caps: Option<serde_json::Map<String, serde_json::Value>>,
    auth_hint: String,
}

impl Server {
    /// Probes an agent and records the result for `/api/v1/agents`. Returns
    /// the recorded status and its detail (the error or the login hint).
    pub async fn probe(&self, agent: &config::Agent) -> (String, String) {
        let result = probe_agent(
            agent,
            self.inner.base_env.clone(),
            crate::rewrite::home_dir(),
            self.version(),
        )
        .await;
        let mut out = (String::new(), String::new());
        self.set_status(&agent.id, |st| {
            match &result {
                Err(e) => {
                    st.status = "unavailable".into();
                    st.error = e.clone();
                }
                Ok(r) if !r.auth_hint.is_empty() && st.status == "auth_required" => {
                    st.auth_hint = r.auth_hint.clone()
                }
                Ok(r) => {
                    if st.status != "auth_required" {
                        st.status = "ready".into();
                        st.error.clear();
                    }
                    st.auth_hint = r.auth_hint.clone();
                }
            }
            if let Ok(r) = &result {
                st.agent_info = r.info.clone();
                st.capabilities = r.caps.clone();
            }
            out = (
                st.status.clone(),
                if st.status == "auth_required" {
                    st.auth_hint.clone()
                } else {
                    st.error.clone()
                },
            );
        });
        out
    }
}

async fn probe_agent(
    agent: &config::Agent,
    base_env: Vec<String>,
    dir: PathBuf,
    version: &str,
) -> Result<ProbeResult, String> {
    let spec = Spec {
        command: agent.command.clone(),
        args: agent.args.clone(),
        dir,
        base_env: Some(base_env),
        env: agent.env.clone(),
        env_remove: agent.env_remove.clone(),
    };
    let proc = Process::start(&spec).map_err(|e| e.to_string())?;
    let res = probe_running(&proc, version).await;
    proc.stop(Duration::from_secs(2)).await;
    res
}

async fn probe_running(proc: &Process, version: &str) -> Result<ProbeResult, String> {
    let req = jsonrpc::new_request(
        "\"actp-probe\"",
        "initialize",
        map([
            ("protocolVersion", GoValue::Int(1)),
            ("clientCapabilities", map([])),
            (
                "clientInfo",
                map([
                    ("name", s("actp")),
                    ("title", s("actp probe")),
                    ("version", s(version)),
                ]),
            ),
        ]),
    );
    let mut line = req.raw.clone();
    line.push('\n');
    proc.write_stdin(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let stdout = proc.take_stdout().ok_or("no stdout")?;
    let read = async {
        let mut rd = jsonrpc::Reader::new(BufReader::new(stdout));
        loop {
            match rd.read().await {
                Ok(Some(Line::Message(m)))
                    if m.kind() == Kind::Response && m.id_key() == "\"actp-probe\"" =>
                {
                    return Some(m);
                }
                Ok(Some(_)) => continue,
                _ => return None,
            }
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, read).await {
        Err(_) => Err("did not answer initialize within 10 s".into()),
        Ok(None) => {
            proc.wait().await;
            Err(format!(
                "exited with code {} before answering initialize: {}",
                proc.exit_code(),
                last_line(&proc.stderr())
            ))
        }
        Ok(Some(m)) => {
            if let Some(e) = &m.error {
                return Err(format!("initialize failed: {}", e.message));
            }
            let r = gojson::object(m.result.as_deref().unwrap_or(""))
                .ok()
                .flatten();
            let info = AgentInfo::decode(r.as_ref().and_then(|r| r.raw("agentInfo")));
            let caps = r
                .as_ref()
                .and_then(|r| r.raw("agentCapabilities"))
                .filter(|c| gojson::kind(c) == gojson::Kind::Object)
                .and_then(gojson::decode_any)
                .and_then(|v| v.as_object().cloned());
            let mut auth_hint = String::new();
            if let Some(methods) = r
                .as_ref()
                .and_then(|r| r.raw("authMethods"))
                .and_then(|raw| {
                    serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(raw).ok()
                })
            {
                for am in methods {
                    let mut errs = Vec::new();
                    let d = gojson::object(am.get())
                        .ok()
                        .flatten()
                        .and_then(|o| o.string("description", &mut errs))
                        .unwrap_or_default();
                    if !d.is_empty() {
                        auth_hint = d;
                        break;
                    }
                }
            }
            Ok(ProbeResult {
                info,
                caps,
                auth_hint,
            })
        }
    }
}

fn last_line(s: &str) -> String {
    let s = s.trim_end_matches(['\n', '\r']);
    if s.is_empty() {
        return "no output on stderr".into();
    }
    s.rsplit('\n').next().unwrap_or(s).to_string()
}

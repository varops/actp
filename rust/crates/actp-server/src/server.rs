//! The server core: configuration, links, agent status and the management
//! endpoints. Transport-independent: [`crate::http`] serves it over HTTP and
//! WebSocket, and anything that can produce a [`FrameConn`] can open links.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime};

use actp_proto::api;
use actp_proto::frame::{ERR_ENDED_BY_ADMIN, ERR_SERVER_SHUTDOWN, VERSIONS};
use actp_proto::{Endpoint, FrameConn};

use crate::agentproc::{self, Process};
use crate::audit::AuditLog;
use crate::auth::{Authenticator, ConfigTokens};
use crate::config::{self, Token};
use crate::link::{self, Link};

/// Knobs, mostly for tests and embedders.
#[derive(Clone)]
pub struct Options {
    pub version: String,
    /// The environment agents start from. `None` means the login shell's
    /// environment when `shell_env` is on (the default), else the current one.
    pub base_env: Option<Vec<String>>,
    pub wire: actp_proto::Options,
    /// How often links check their timers (1 s).
    pub tick: Duration,
    /// Runs an `initialize` probe against every agent at start.
    pub probe_on_start: bool,
    /// For tools like `actp doctor`: no crash cleanup, no audit log.
    pub read_only: bool,
    /// How long an agent may take to answer actp's switch of a session's
    /// starting mode (10 s).
    pub mode_reset_timeout: Duration,
    /// How long a `session/load` or `session/resume` may hold the session's
    /// next messages (60 s), and how many messages and bytes it may hold
    /// (256, 8 MB).
    pub held_load_timeout: Duration,
    pub max_held_messages: usize,
    pub max_held_bytes: usize,
    /// Who a bearer token belongs to (default: the config's hashed tokens).
    /// Not used in org mode, where callers present signed papers.
    pub authenticator: Arc<dyn Authenticator>,
    /// Checks callers' papers against their issuer in org mode
    /// (`server.org`). Org mode needs one; nobody gets in without it.
    pub papers_verifier: Option<Arc<dyn crate::org::PapersVerifier>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            version: "dev".into(),
            base_env: None,
            wire: actp_proto::Options::default(),
            tick: Duration::from_secs(1),
            probe_on_start: false,
            read_only: false,
            mode_reset_timeout: Duration::from_secs(10),
            held_load_timeout: Duration::from_secs(60),
            max_held_messages: 256,
            max_held_bytes: 8 << 20,
            authenticator: Arc::new(ConfigTokens),
            papers_verifier: None,
        }
    }
}

/// An agent's status for `/api/v1/agents`.
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentStatus {
    pub status: String,
    pub auth_hint: String,
    pub error: String,
    pub agent_info: Option<api::AgentInfo>,
    pub capabilities: Option<serde_json::Map<String, serde_json::Value>>,
}

pub(crate) struct State {
    pub links: HashMap<String, Arc<Link>>,
    /// agent id + "\0" + session id → the link holding it.
    pub sessions: HashMap<String, Arc<Link>>,
    pub status: HashMap<String, AgentStatus>,
    /// Links being started (agent id, token name), counted against the limits.
    pub slots: HashMap<u64, (String, String)>,
    pub next_slot: u64,
}

/// (person, refusal code) → (last written, repeats since).
type RefusalLog = HashMap<(String, &'static str), (Instant, u64)>;

pub(crate) struct Inner {
    cfg: RwLock<Arc<config::Server>>,
    pub opts: Options,
    pub base_env: Vec<String>,
    pub audit: AuditLog,
    public_url: Mutex<String>,
    pub st: Mutex<State>,
    /// Orders state-file writes; once true (after close), they stop.
    pids_closed: Mutex<bool>,
    /// Relay mode: the relay's org-wide stop is on.
    org_stopped: AtomicBool,
    /// Org mode: when each (person, refusal) was last written, and repeats since.
    refusals: Mutex<RefusalLog>,
}

/// A running server. Cheap to clone.
#[derive(Clone)]
pub struct Server {
    pub(crate) inner: Arc<Inner>,
}

/// A link for the tray, the CLI and tests.
#[derive(Clone, Debug)]
pub struct LinkInfo {
    pub id: String,
    pub agent: String,
    pub token: String,
    pub client_name: String,
    pub state: String,
    pub since: SystemTime,
    pub running: bool,
}

/// An agent's status for a dashboard.
#[derive(Clone, Debug)]
pub struct AgentState {
    pub id: String,
    pub name: String,
    pub status: String,
    pub auth_hint: String,
    pub error: String,
}

/// A refused link request: the HTTP status and the JSON error body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub retry_after: Option<u32>,
}

impl Rejection {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Rejection {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }
}

/// What a client asks for when it opens or resumes a link, whatever the transport.
#[derive(Clone, Debug, Default)]
pub struct LinkRequest {
    pub agent_id: String,
    pub client_name: Option<String>,
    pub link_id: Option<String>,
    pub last_seq: Option<i64>,
}

/// A link that is ready to be served once the transport is up.
pub struct PendingLink {
    link: Arc<Link>,
    last_seq: i64,
    resumed: bool,
}

impl PendingLink {
    pub fn link_id(&self) -> &str {
        &self.link.id
    }

    /// The highest client sequence number processed (`Actp-Last-Seq`).
    pub fn last_received(&self) -> i64 {
        self.link.ep.last_received()
    }

    /// Runs the link over the connection until the socket ends.
    pub async fn serve(self, conn: FrameConn) {
        self.link.serve(conn, self.last_seq).await;
    }

    /// The transport did not come up. A new link ends; a resumed one is left alone.
    pub async fn abandon(self) {
        if !self.resumed {
            self.link
                .end(actp_proto::frame::ERR_LINK_ENDED, "upgrade failed")
                .await;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Server {
    /// Builds a server for a validated config.
    pub async fn new(cfg: config::Server, opts: Options) -> std::io::Result<Server> {
        if cfg.org.is_some() && opts.papers_verifier.is_none() {
            return Err(std::io::Error::other(
                "org mode needs a papers verifier, supplied by the program that runs the server",
            ));
        }
        let base_env = match &opts.base_env {
            Some(env) => env.clone(),
            None if cfg.shell_env.unwrap_or(true) => agentproc::login_shell_env().await,
            None => agentproc::os_environ(),
        };
        let base_env = agentproc::append_path(base_env, &[config::agent_bin_dir()]);
        let mut status = HashMap::new();
        for a in &cfg.agents {
            status.insert(
                a.id.clone(),
                AgentStatus {
                    status: "unknown".into(),
                    ..Default::default()
                },
            );
        }
        let audit = if opts.read_only {
            AuditLog::disabled()
        } else {
            match AuditLog::open(&cfg.log_dir) {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(error = %e, "audit log disabled");
                    AuditLog::disabled()
                }
            }
        };
        let agents = cfg.agents.clone();
        let s = Server {
            inner: Arc::new(Inner {
                cfg: RwLock::new(Arc::new(cfg)),
                base_env,
                audit,
                public_url: Mutex::new(String::new()),
                st: Mutex::new(State {
                    links: HashMap::new(),
                    sessions: HashMap::new(),
                    status,
                    slots: HashMap::new(),
                    next_slot: 0,
                }),
                pids_closed: Mutex::new(false),
                org_stopped: AtomicBool::new(false),
                refusals: Mutex::new(HashMap::new()),
                opts,
            }),
        };
        if !s.inner.opts.read_only {
            crate::leftovers::cleanup(&s);
        }
        if s.inner.opts.probe_on_start {
            for a in agents {
                let s = s.clone();
                tokio::spawn(async move { s.probe(&a).await });
            }
        }
        Ok(s)
    }

    /// The configuration the server runs with now. Links keep the agent
    /// settings they started with.
    pub fn config(&self) -> Arc<config::Server> {
        self.inner
            .cfg
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub(crate) fn st(&self) -> MutexGuard<'_, State> {
        lock(&self.inner.st)
    }

    pub(crate) fn audit(&self) -> &AuditLog {
        &self.inner.audit
    }

    pub fn version(&self) -> &str {
        &self.inner.opts.version
    }

    /// Switches to a new configuration. New links and new requests use it;
    /// open links keep running with the settings they started with. A revoked
    /// token cannot open or resume links any more.
    pub fn reload(&self, cfg: config::Server) {
        if cfg.org.is_some() && self.inner.opts.papers_verifier.is_none() {
            tracing::error!(
                "config reload refused: org mode needs a papers verifier, and this server has none; keeping the old config"
            );
            return;
        }
        {
            let mut st = self.st();
            for a in &cfg.agents {
                st.status
                    .entry(a.id.clone())
                    .or_insert_with(|| AgentStatus {
                        status: "unknown".into(),
                        ..Default::default()
                    });
            }
        }
        let agents = cfg.agents.clone();
        let tokens = cfg.tokens.len();
        *self.inner.cfg.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(cfg);
        tracing::info!(agents = agents.len(), tokens, "configuration reloaded");
        if self.inner.opts.probe_on_start {
            for a in agents {
                let s = self.clone();
                tokio::spawn(async move { s.probe(&a).await });
            }
        }
    }

    /// Records a public URL (for example a tunnel's) for `/api/v1/info`.
    pub fn set_public_url(&self, u: &str) {
        *lock(&self.inner.public_url) = u.to_string();
    }

    pub fn public_url(&self) -> String {
        lock(&self.inner.public_url).clone()
    }

    /// Authenticates a bearer token against the current configuration: an
    /// actp token, or in org mode signed papers. Refused papers are audited.
    pub async fn authenticate(&self, presented: &str) -> Result<Token, crate::auth::Refused> {
        let cfg = self.config();
        let res = match &cfg.org {
            Some(org) => {
                crate::org::authenticate(self.inner.opts.papers_verifier.as_deref(), org, presented)
                    .await
            }
            None => {
                self.inner
                    .opts
                    .authenticator
                    .authenticate(&cfg, presented)
                    .await
            }
        };
        if let Err(r) = &res {
            // Only refusals of papers the verifier found genuine are
            // audited: they name a person. Junk costs a caller nothing, so
            // it is not written, like an unknown token. A person's refusals
            // are written once a minute per reason, with a count of repeats.
            if let Some(principal) = &r.principal {
                if let Some(repeats) = self.refusal_due(principal, r.code) {
                    tracing::info!(reason = r.code, principal = %principal, "papers refused");
                    self.inner.audit.event(
                        "auth_refused",
                        [
                            ("reason", actp_proto::gojson::GoValue::Str(r.code.into())),
                            (
                                "principal",
                                actp_proto::gojson::GoValue::Str(principal.clone()),
                            ),
                            ("repeats", actp_proto::gojson::GoValue::Int(repeats as i64)),
                        ],
                    );
                }
            } else if r.code != crate::auth::INVALID_TOKEN {
                tracing::debug!(reason = r.code, "credentials refused");
            }
        }
        res
    }

    /// Whether to write a refusal for (`principal`, `code`) now: once a
    /// minute, with how many were left out since.
    fn refusal_due(&self, principal: &str, code: &'static str) -> Option<u64> {
        let mut m = lock(&self.inner.refusals);
        let now = Instant::now();
        if m.len() > 10_000 {
            m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }
        match m.get_mut(&(principal.to_string(), code)) {
            Some((t, n)) if now.duration_since(*t) < Duration::from_secs(60) => {
                *n += 1;
                None
            }
            Some((t, n)) => {
                let repeats = *n;
                *t = now;
                *n = 0;
                Some(repeats)
            }
            None => {
                m.insert((principal.to_string(), code), (now, 0));
                Some(0)
            }
        }
    }

    /// Ends every link, settling its agent, after waiting up to `grace` for running turns.
    pub async fn close(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline && self.any_turn_running() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let links: Vec<Arc<Link>> = self.st().links.values().cloned().collect();
        futures_util::future::join_all(
            links
                .iter()
                .map(|l| l.end(ERR_SERVER_SHUTDOWN, "server is stopping")),
        )
        .await;
        for l in &links {
            l.finalize();
        }
        self.inner.audit.close();
        // No agents are left: a clean stop leaves no state for the next start to clean up.
        let mut closed = lock(&self.inner.pids_closed);
        *closed = true;
        let _ = std::fs::remove_file(self.state_path());
    }

    fn any_turn_running(&self) -> bool {
        let links: Vec<Arc<Link>> = self.st().links.values().cloned().collect();
        links.iter().any(|l| l.turn_running())
    }

    /// The open links.
    pub fn links(&self) -> Vec<LinkInfo> {
        let links: Vec<Arc<Link>> = self.st().links.values().cloned().collect();
        links
            .iter()
            .map(|l| l.info())
            .filter(|i| i.state != link::STATE_ENDED)
            .collect()
    }

    /// Relay mode: turns the org-wide stop on or off, as the relay says. While
    /// it is on, no link opens or resumes; turning it on ends every link.
    /// Returns whether it changed.
    pub async fn set_org_stopped(&self, on: bool) -> bool {
        let was = self.inner.org_stopped.swap(on, Ordering::SeqCst);
        if was == on {
            if on {
                // A link may have slipped in before the flag was seen; end it too.
                self.end_all_links("the organization-wide stop is on").await;
            }
            return false;
        }
        self.inner
            .audit
            .event(if on { "org_stop" } else { "org_release" }, []);
        tracing::warn!(stopped = on, "organization-wide stop changed by the relay");
        if on {
            self.end_all_links("the organization-wide stop is on").await;
        }
        true
    }

    /// Whether the org-wide stop is on.
    pub fn org_stopped(&self) -> bool {
        self.inner.org_stopped.load(Ordering::SeqCst)
    }

    /// Ends every open link and its agent, without waiting for running turns.
    pub async fn end_all_links(&self, reason: &str) {
        let links: Vec<Arc<Link>> = self.st().links.values().cloned().collect();
        futures_util::future::join_all(links.iter().map(|l| l.end(ERR_ENDED_BY_ADMIN, reason)))
            .await;
        for l in &links {
            l.finalize();
        }
    }

    /// Ends a link on an operator's request.
    pub async fn end_link(&self, id: &str) -> bool {
        let l = self.st().links.get(id).cloned();
        let Some(l) = l else {
            return false;
        };
        l.end(ERR_ENDED_BY_ADMIN, "ended by an operator").await;
        l.finalize();
        true
    }

    /// Every configured agent with its last known status.
    pub fn agents(&self) -> Vec<AgentState> {
        let cfg = self.config();
        let st = self.st();
        cfg.agents
            .iter()
            .map(|a| {
                let cur = st.status.get(&a.id);
                AgentState {
                    id: a.id.clone(),
                    name: a.name.clone(),
                    status: cur.map_or("unknown".into(), |c| c.status.clone()),
                    auth_hint: cur.map(|c| c.auth_hint.clone()).unwrap_or_default(),
                    error: cur.map(|c| c.error.clone()).unwrap_or_default(),
                }
            })
            .collect()
    }

    pub(crate) fn set_status(&self, agent_id: &str, update: impl FnOnce(&mut AgentStatus)) {
        let mut st = self.st();
        update(st.status.entry(agent_id.to_string()).or_default());
    }

    pub(crate) fn mark_auth_required(&self, agent_id: &str, message: &str) {
        self.set_status(agent_id, |st| {
            st.status = "auth_required".into();
            if st.auth_hint.is_empty() {
                st.auth_hint = message.to_string();
            }
        });
    }

    // ---- management endpoints (bodies; the transport adds the HTTP framing) ----

    /// `GET /api/v1/info`.
    pub fn info_body(&self) -> String {
        let cfg = self.config();
        let u = self.public_url();
        api::Info {
            name: (!cfg.name.is_empty()).then(|| cfg.name.clone()),
            prompt_timeout_seconds: cfg.prompt_timeout.as_secs() as i64,
            public_url: (!u.is_empty()).then_some(u),
            version: self.inner.opts.version.clone(),
            wire_versions: VERSIONS.iter().map(|v| v.to_string()).collect(),
        }
        .encode()
    }

    /// `GET /api/v1/agents` for this token.
    pub fn agents_body(&self, tok: &Token) -> String {
        let cfg = self.config();
        let workspaces = tok.allowed_workspaces(&cfg);
        let mut out = Vec::new();
        for a in &cfg.agents {
            if !tok.allows_agent(&a.id) {
                continue;
            }
            let st = self.st().status.get(&a.id).cloned().unwrap_or_default();
            out.push(api::Agent {
                agent_capabilities: st.capabilities,
                agent_info: st.agent_info,
                auth_hint: (!st.auth_hint.is_empty()).then_some(st.auth_hint),
                description: (!a.description.is_empty()).then(|| a.description.clone()),
                error: (!st.error.is_empty()).then_some(st.error),
                id: a.id.clone(),
                name: (!a.name.is_empty()).then(|| a.name.clone()),
                status: st.status,
                workspaces: workspaces
                    .iter()
                    .map(|n| api::Workspace {
                        default: *n == tok.default_workspace,
                        name: n.clone(),
                    })
                    .collect(),
            });
        }
        api::agent_list(&out)
    }

    /// The first checks on a link request: the agent exists and the token may use it.
    pub fn check_agent(&self, tok: &Token, agent_id: &str) -> Result<(), Rejection> {
        if self.config().agent(agent_id).is_none() {
            return Err(Rejection::new(
                404,
                "unknown_agent",
                format!("no agent named {agent_id}"),
            ));
        }
        if !tok.allows_agent(agent_id) {
            return Err(Rejection::new(
                403,
                "forbidden",
                format!("this token may not use agent {agent_id}"),
            ));
        }
        Ok(())
    }

    /// Opens a new link or finds the one to resume. Call [`Server::check_agent`] first.
    pub async fn open_link(
        &self,
        tok: &Token,
        req: &LinkRequest,
    ) -> Result<PendingLink, Rejection> {
        if self.org_stopped() {
            return Err(Rejection::new(
                503,
                "org_stopped",
                "the organization-wide stop is on",
            ));
        }
        let cfg = self.config();
        let Some(agent) = cfg.agent(&req.agent_id).cloned() else {
            return Err(Rejection::new(
                404,
                "unknown_agent",
                format!("no agent named {}", req.agent_id),
            ));
        };
        if let Some(id) = &req.link_id {
            let link = self.st().links.get(id).cloned();
            let Some(link) = link.filter(|l| l.resumable()) else {
                return Err(Rejection::new(410, "link_gone", "the link has ended"));
            };
            if link.token.name != tok.name {
                return Err(Rejection::new(
                    409,
                    "wrong_token",
                    "the link belongs to another token",
                ));
            }
            return Ok(PendingLink {
                link,
                last_seq: req.last_seq.unwrap_or(0),
                resumed: true,
            });
        }
        let slot = match self.reserve_link(&agent.id, &tok.name, agent.max_links, tok.max_links) {
            Ok(slot) => slot,
            Err(msg) => {
                return Err(Rejection {
                    retry_after: Some(30),
                    ..Rejection::new(429, "too_many_links", msg)
                });
            }
        };
        match self
            .start_link(
                agent,
                tok.clone(),
                req.client_name.clone().unwrap_or_default(),
                slot,
            )
            .await
        {
            Ok(link) => {
                // The stop may have come while the agent started: the link is
                // in the table now, so either the stop ended it or this sees it.
                if self.org_stopped() {
                    link.end(ERR_ENDED_BY_ADMIN, "the organization-wide stop is on")
                        .await;
                    link.finalize();
                    return Err(Rejection::new(
                        503,
                        "org_stopped",
                        "the organization-wide stop is on",
                    ));
                }
                Ok(PendingLink {
                    link,
                    last_seq: 0,
                    resumed: false,
                })
            }
            Err(e) => Err(Rejection::new(503, "agent_unavailable", e)),
        }
    }

    /// Checks the limits and holds a slot in the same step, so parallel requests
    /// cannot all pass the check before any of their links exists. The slot is
    /// given back when the link is in place, or when it is dropped.
    fn reserve_link(
        &self,
        agent_id: &str,
        token_name: &str,
        agent_max: i64,
        token_max: i64,
    ) -> Result<Slot, String> {
        let mut st = self.st();
        let (mut per_agent, mut per_token) = (0i64, 0i64);
        for (agent, token) in st.slots.values() {
            if agent == agent_id {
                per_agent += 1;
            }
            if token == token_name {
                per_token += 1;
            }
        }
        for l in st.links.values() {
            if l.is_ended() {
                continue; // ended links waiting for their client hold no agent process
            }
            if l.agent.id == agent_id {
                per_agent += 1;
            }
            if l.token.name == token_name {
                per_token += 1;
            }
        }
        if per_agent >= agent_max {
            return Err(format!("agent {agent_id} has reached its link limit"));
        }
        if per_token >= token_max {
            return Err("this token has reached its link limit".into());
        }
        st.next_slot += 1;
        let id = st.next_slot;
        st.slots
            .insert(id, (agent_id.to_string(), token_name.to_string()));
        Ok(Slot {
            srv: self.clone(),
            id,
        })
    }

    /// Starts an agent process for a new link.
    async fn start_link(
        &self,
        agent: config::Agent,
        tok: Token,
        client_name: String,
        slot: Slot,
    ) -> Result<Arc<Link>, String> {
        let cfg = self.config();
        let mut dir = crate::rewrite::home_dir();
        if let Some(ws) = cfg.workspace(&tok.default_workspace) {
            dir = PathBuf::from(&ws.path);
        } else if let Some(ws) = tok
            .allowed_workspaces(&cfg)
            .first()
            .and_then(|n| cfg.workspace(n))
        {
            dir = PathBuf::from(&ws.path);
        }
        let spec = agentproc::Spec {
            command: agent.command.clone(),
            args: agent.args.clone(),
            dir,
            base_env: Some(self.inner.base_env.clone()),
            env: agent.env.clone(),
            env_remove: agent.env_remove.clone(),
        };
        let proc = match Process::start(&spec) {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                self.set_status(&agent.id, |st| {
                    st.status = "unavailable".into();
                    st.error = msg.clone();
                });
                return Err(format!("agent {} did not start: {msg}", agent.id));
            }
        };
        let id = new_id();
        let mut wopts = self.inner.opts.wire.clone();
        wopts.spool_path = Some(self.spool_dir().join(format!("{id}.spool")));
        let link = Link::new(self.clone(), id, agent, tok, client_name, proc, wopts);
        {
            // The link takes the slot's place in one step.
            let mut st = self.st();
            st.links.insert(link.id.clone(), link.clone());
            st.slots.remove(&slot.id);
        }
        drop(slot);
        crate::leftovers::record_pids(self);
        link.started();
        Ok(link)
    }

    pub(crate) fn hold_session(&self, agent_id: &str, session_id: &str, l: &Arc<Link>) {
        self.st()
            .sessions
            .insert(format!("{agent_id}\0{session_id}"), l.clone());
    }

    pub(crate) fn release_session(&self, agent_id: &str, session_id: &str, l: &Link) {
        let mut st = self.st();
        let key = format!("{agent_id}\0{session_id}");
        if st
            .sessions
            .get(&key)
            .is_some_and(|cur| std::ptr::eq(Arc::as_ptr(cur), l))
        {
            st.sessions.remove(&key);
        }
    }

    pub(crate) fn session_holder(&self, agent_id: &str, session_id: &str) -> Option<Arc<Link>> {
        self.st()
            .sessions
            .get(&format!("{agent_id}\0{session_id}"))
            .cloned()
    }

    pub(crate) fn forget_link(&self, id: &str) {
        self.st().links.remove(id);
        crate::leftovers::record_pids(self);
    }

    pub(crate) fn pids_closed(&self) -> MutexGuard<'_, bool> {
        lock(&self.inner.pids_closed)
    }

    /// Where the server records agent process ids, for crash cleanup.
    pub fn state_path(&self) -> PathBuf {
        PathBuf::from(&self.config().state_dir).join("agents.json")
    }

    pub(crate) fn spool_dir(&self) -> PathBuf {
        PathBuf::from(&self.config().state_dir).join("spool")
    }

    pub(crate) fn new_endpoint(
        &self,
        opts: actp_proto::Options,
        deliver: actp_proto::Deliver,
    ) -> Endpoint {
        Endpoint::new(opts, deliver)
    }
}

/// A place under the link limits, held while an agent starts.
struct Slot {
    srv: Server,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.srv.st().slots.remove(&self.id);
    }
}

/// A random link id: 192 bits, hex.
pub(crate) fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

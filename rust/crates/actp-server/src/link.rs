//! A link: one ACP connection to one agent process (design 1, wire 3), its
//! states and timers (design 3.1), the rewrites (3.3) and the settle order
//! when it ends (3.2). A port of Go's `internal/server/link.go`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use actp_proto::frame::*;
use actp_proto::gojson::{self, GoValue, map, s};
use actp_proto::jsonrpc::{self, Kind, Line, Message};
use actp_proto::{Endpoint, FrameConn, ServeEnd, deliver_fn};
use tokio::io::BufReader;
use tokio::sync::watch;

use crate::agentproc::Process;
use crate::config::{self, Token};
use crate::rewrite;
use crate::server::{LinkInfo, Server};

pub const STATE_ATTACHED: &str = "attached";
pub const STATE_DETACHED: &str = "detached";
pub const STATE_UNATTENDED: &str = "unattended";
pub const STATE_ENDED: &str = "ended";

/// How long an ended link keeps output its client has not received.
pub const TOMBSTONE_FOR: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Default)]
struct ClientReq {
    method: String,
    session_id: String,
    orig_cwd: String,
    cwd: String,
}

#[derive(Clone, Debug)]
struct AgentReq {
    id: String,
    method: String,
    since: Instant,
}

#[derive(Clone, Debug)]
struct LinkSession {
    turn_running: bool,
    last_output: Instant,
}

#[derive(Clone, Debug)]
struct Tombstone {
    code: String,
    reason: String,
    data: Option<String>,
}

impl Tombstone {
    fn frame(&self) -> Frame {
        Frame::error(&self.code, self.reason.clone(), self.data.clone())
    }
}

struct LinkState {
    state: &'static str,
    state_since: Instant,
    state_since_wall: SystemTime,
    protocol_version: i64,
    can_close: bool,
    client_reqs: HashMap<String, ClientReq>,
    agent_reqs: HashMap<String, AgentReq>,
    sessions: HashMap<String, LinkSession>,
    server_reqs: HashSet<String>,
    next_server_req: u64,
    cancel_sent: bool,
    tomb: Option<Tombstone>,
    finalized: bool,
    last_busy: Option<Instant>,
}

pub(crate) struct Link {
    srv: Server,
    pub id: String,
    pub agent: config::Agent,
    pub token: Token,
    client_name: String,
    proc: Arc<Process>,
    pub ep: Endpoint,
    st: Mutex<LinkState>,
    ended: watch::Sender<bool>,
    drained: watch::Sender<bool>,
    end_once: tokio::sync::OnceCell<()>,
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn sv(v: &str) -> GoValue {
    GoValue::Str(v.to_string())
}

static SESSION_PARAMS: [&str; 4] = [
    "session/new",
    "session/load",
    "session/resume",
    "session/list",
];

impl Link {
    pub(crate) fn new(
        srv: Server,
        id: String,
        agent: config::Agent,
        token: Token,
        client_name: String,
        proc: Arc<Process>,
        wopts: actp_proto::Options,
    ) -> Arc<Link> {
        Arc::new_cyclic(|weak: &std::sync::Weak<Link>| {
            let w = weak.clone();
            let ep = srv.new_endpoint(
                wopts,
                deliver_fn(move |raw| {
                    let w = w.clone();
                    async move {
                        if let Some(l) = w.upgrade() {
                            l.from_client(raw).await;
                        }
                        Ok(())
                    }
                }),
            );
            let now = Instant::now();
            Link {
                srv,
                id,
                agent,
                token,
                client_name,
                proc,
                ep,
                st: Mutex::new(LinkState {
                    state: STATE_DETACHED,
                    state_since: now,
                    state_since_wall: SystemTime::now(),
                    protocol_version: 0,
                    can_close: false,
                    client_reqs: HashMap::new(),
                    agent_reqs: HashMap::new(),
                    sessions: HashMap::new(),
                    server_reqs: HashSet::new(),
                    next_server_req: 0,
                    cancel_sent: false,
                    tomb: None,
                    finalized: false,
                    last_busy: None,
                }),
                ended: watch::channel(false).0,
                drained: watch::channel(false).0,
                end_once: tokio::sync::OnceCell::new(),
            }
        })
    }

    /// Records the new link and starts reading the agent and the timers.
    pub(crate) fn started(self: &Arc<Self>) {
        self.srv.audit().event(
            "link_opened",
            [
                ("link", sv(short(&self.id))),
                ("agent", sv(&self.agent.id)),
                ("token", sv(&self.token.name)),
                ("client", sv(&self.client_name)),
            ],
        );
        tokio::spawn(self.clone().read_agent());
        tokio::spawn(self.clone().supervise());
    }

    fn st(&self) -> MutexGuard<'_, LinkState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn log(&self, msg: &str) {
        tracing::info!(link = short(&self.id), agent = %self.agent.id, "{msg}");
    }

    pub(crate) fn is_ended(&self) -> bool {
        *self.ended.borrow()
    }

    /// Attaches a socket and runs it until it ends.
    pub(crate) async fn serve(self: &Arc<Self>, conn: FrameConn, last_seq: i64) {
        let tomb = self.st().tomb.clone();
        if let Some(tomb) = tomb {
            // The link ended while the client was away: hand over what it missed, then say why.
            self.srv.audit().event(
                "link_resumed",
                [
                    ("link", sv(short(&self.id))),
                    ("ended", GoValue::Bool(true)),
                ],
            );
            self.ep.send_control(tomb.frame());
            let _ = self.ep.serve(conn, last_seq).await;
            self.finalize_if_delivered();
            return;
        }
        self.set_state(STATE_ATTACHED);
        if last_seq > 0 {
            self.srv
                .audit()
                .event("link_resumed", [("link", sv(short(&self.id)))]);
        }
        match self.ep.serve(conn, last_seq).await {
            ServeEnd::Replaced => {} // a newer socket owns the link now
            ServeEnd::Bye => {
                self.log("client left");
                self.become_unattended("client left").await;
            }
            other => {
                let ended = {
                    let mut st = self.st();
                    if st.state == STATE_ATTACHED {
                        st.state = STATE_DETACHED;
                        st.state_since = Instant::now();
                        st.state_since_wall = SystemTime::now();
                    }
                    st.state == STATE_ENDED
                };
                if ended {
                    self.finalize_if_delivered();
                }
                tracing::info!(link = short(&self.id), agent = %self.agent.id, reason = %other, "connection dropped");
            }
        }
    }

    fn set_state(&self, state: &'static str) {
        let mut st = self.st();
        if st.state == STATE_ENDED || st.state == STATE_UNATTENDED {
            return;
        }
        st.state = state;
        st.state_since = Instant::now();
        st.state_since_wall = SystemTime::now();
    }

    pub(crate) fn resumable(&self) -> bool {
        let st = self.st();
        st.state == STATE_ATTACHED
            || st.state == STATE_DETACHED
            || (st.tomb.is_some() && !st.finalized)
    }

    pub(crate) fn info(&self) -> LinkInfo {
        let st = self.st();
        LinkInfo {
            id: self.id.clone(),
            agent: self.agent.id.clone(),
            token: self.token.name.clone(),
            client_name: self.client_name.clone(),
            state: st.state.to_string(),
            since: st.state_since_wall,
            running: running_locked(&st),
        }
    }

    pub(crate) fn turn_running(&self) -> bool {
        running_locked(&self.st())
    }

    fn to_client(&self, m: &Message) {
        self.ep.send(m.raw.clone());
    }

    async fn write_agent(&self, m: &Message) {
        let mut buf = m.raw.clone();
        buf.push('\n');
        if let Err(e) = self.proc.write_stdin(buf.as_bytes()).await {
            tracing::info!(link = short(&self.id), agent = %self.agent.id, error = %e, "write to agent failed");
        }
    }

    /// Handles one ACP message from the bridge, in order.
    async fn from_client(self: &Arc<Self>, raw: String) {
        if let Err(a) = jsonrpc::check_envelope(&raw) {
            if let Some(reply) = self.refuse_ambiguous(&a, "client") {
                self.to_client(&reply);
            }
            return;
        }
        let m = match jsonrpc::parse(&raw) {
            Ok(m) => m,
            Err(e) => {
                tracing::info!(link = short(&self.id), agent = %self.agent.id, error = %e, "dropped invalid message from client");
                return;
            }
        };
        match m.kind() {
            Kind::Response => {
                let known = self.st().agent_reqs.remove(&m.id_key()).is_some();
                if known {
                    self.write_agent(&m).await;
                } // else: a late answer to a request already settled
            }
            Kind::Notification => self.write_agent(&m).await,
            Kind::Request => match self.rewrite_client_request(m).await {
                Ok(out) => self.write_agent(&out).await,
                Err(reply) => self.to_client(&reply),
            },
        }
    }

    /// Applies design 3.3 to a client request. `Err` is the server's own
    /// answer to the client; nothing goes to the agent then.
    async fn rewrite_client_request(self: &Arc<Self>, m: Message) -> Result<Message, Box<Message>> {
        let id = m.id.clone().unwrap_or_default();
        let mut req = ClientReq {
            method: m.method.clone(),
            ..Default::default()
        };
        let mut p = gojson::decode_raw_map(m.params.as_deref()).unwrap_or(None);
        if let Some(pm) = &p {
            req.session_id = gojson::string_or_empty(pm.get("sessionId").map(String::as_str));
        }
        let mut changed = false;

        if m.method == "initialize" {
            if let Some(stripped) = rewrite::strip_client_capabilities(m.params.as_deref()) {
                // Go unmarshals the stripped params into the same map.
                if let Ok(Some(sm)) = gojson::decode_raw_map(Some(&stripped)) {
                    p.get_or_insert_default().extend(sm);
                }
                changed = true;
            }
        } else if SESSION_PARAMS.contains(&m.method.as_str()) {
            let cwd = gojson::string_or_empty(
                p.as_ref().and_then(|pm| pm.get("cwd")).map(String::as_str),
            );
            if !cwd.is_empty() || m.method != "session/list" {
                let cfg = self.srv.config();
                match rewrite::resolve_cwd(&cfg, &self.token, &cwd) {
                    Err(msg) => {
                        self.srv.audit().event(
                            "cwd_rejected",
                            [("link", sv(short(&self.id))), ("cwd", sv(&cwd))],
                        );
                        return Err(Box::new(jsonrpc::new_error(
                            &id,
                            jsonrpc::CODE_INVALID_PARAMS,
                            &msg,
                        )));
                    }
                    Ok(resolved) => {
                        // Go would panic writing into a nil params map here (missing
                        // or non-object params with cwd_fallback); this port creates the map.
                        p.get_or_insert_default()
                            .insert("cwd".into(), gojson::string(&resolved));
                        req.orig_cwd = cwd;
                        req.cwd = resolved;
                        changed = true;
                    }
                }
            }
            if let Some(servers) = p.as_ref().and_then(|pm| pm.get("mcpServers")).cloned() {
                let (kept, dropped) =
                    rewrite::filter_mcp_servers(&self.token.mcp_servers, &servers);
                for d in dropped {
                    tracing::info!(link = short(&self.id), agent = %self.agent.id, server = %d, "dropped MCP server");
                }
                if let Some(pm) = p.as_mut() {
                    pm.insert("mcpServers".into(), kept.unwrap_or(servers));
                }
                changed = true;
            }
            // Policy was applied here: forward the re-encoded message, never the original bytes.
            if p.is_some() {
                changed = true;
            }
            if (m.method == "session/load" || m.method == "session/resume")
                && !req.session_id.is_empty()
            {
                let other = self.srv.session_holder(&self.agent.id, &req.session_id);
                if let Some(other) = other.filter(|o| !Arc::ptr_eq(o, self)) {
                    if other.token.name == self.token.name {
                        other
                            .become_unattended("session taken over by a new connection")
                            .await;
                    }
                    // A link with nothing running is closing right now; wait for it instead of failing.
                    if other.turn_running() || !other.wait_ended(Duration::from_secs(5)).await {
                        return Err(Box::new(jsonrpc::new_error(
                            &id,
                            jsonrpc::CODE_SERVER_ERROR,
                            "session still running on the agent host",
                        )));
                    }
                }
            }
        } else if m.method == "session/prompt" {
            let mut st = self.st();
            if let Some(sess) = st.sessions.get_mut(&req.session_id) {
                sess.turn_running = true;
                sess.last_output = Instant::now();
            }
        }

        self.st().client_reqs.insert(m.id_key(), req);
        if !changed {
            return Ok(m);
        }
        Ok(m.with_params(&jsonrpc::encode_params(&p)).unwrap_or(m))
    }

    /// Handles a message whose envelope two decoders could read differently (one
    /// key in two spellings, or twice): actp would route it by one reading and the
    /// peer act on the other, skipping the rewrites. It is never forwarded. A
    /// request with a usable id gets an error; anything else is dropped.
    fn refuse_ambiguous(&self, a: &jsonrpc::Ambiguous, from: &str) -> Option<Message> {
        tracing::info!(link = short(&self.id), agent = %self.agent.id, from, reason = %a.reason, "refused an ambiguous message");
        self.srv.audit().event(
            "message_refused",
            [
                ("link", sv(short(&self.id))),
                ("from", sv(from)),
                ("reason", sv(&a.reason)),
            ],
        );
        match (&a.id, a.request) {
            (Some(id), true) => Some(jsonrpc::new_error(
                id,
                jsonrpc::CODE_INVALID_REQUEST,
                &format!("invalid request: {a}"),
            )),
            _ => None,
        }
    }

    /// Handles the agent's output until it exits.
    async fn read_agent(self: Arc<Self>) {
        if let Some(stdout) = self.proc.take_stdout() {
            let mut rd = jsonrpc::Reader::new(BufReader::new(stdout));
            // A child the agent left behind may hold stdout open; stop reading soon after exit.
            let proc = self.proc.clone();
            let stop = async move {
                proc.wait().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            };
            tokio::pin!(stop);
            loop {
                let line = tokio::select! {
                    r = rd.read() => r,
                    _ = &mut stop => break,
                };
                match line {
                    Ok(Some(Line::Message(m))) => match jsonrpc::check_envelope(&m.raw) {
                        Ok(()) => self.from_agent(m).await,
                        Err(a) => {
                            if let Some(reply) = self.refuse_ambiguous(&a, "agent") {
                                self.write_agent(&reply).await;
                            }
                        }
                    },
                    Ok(Some(Line::Invalid(raw, _))) => {
                        tracing::info!(link = short(&self.id), agent = %self.agent.id, line = %truncate(&raw, 200), "agent wrote a non-JSON-RPC line");
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::info!(link = short(&self.id), agent = %self.agent.id, error = %e, "reading agent failed");
                        break;
                    }
                }
            }
        }
        self.drained.send_replace(true);
        self.proc.wait().await;
        let code = self.proc.exit_code();
        let data = map([
            ("exitCode", GoValue::Int(code as i64)),
            ("stderr", s(self.proc.stderr())),
        ])
        .encode();
        self.end_with_data(
            ERR_AGENT_EXITED,
            &format!("agent {} exited with code {code}", self.agent.id),
            Some(data),
        )
        .await;
    }

    /// Handles one ACP message from the agent.
    async fn from_agent(self: &Arc<Self>, m: Message) {
        match m.kind() {
            Kind::Response => {
                let req = {
                    let mut st = self.st();
                    if st.server_reqs.remove(&m.id_key()) {
                        return;
                    }
                    st.client_reqs.remove(&m.id_key())
                };
                let out = match req {
                    Some(req) => self.after_response(req, m),
                    None => m,
                };
                self.to_client(&out);
            }
            Kind::Request => match self.answer_agent_request(&m) {
                Some(reply) => self.write_agent(&reply).await,
                None => self.to_client(&m),
            },
            Kind::Notification => {
                let params = gojson::object(m.params.as_deref().unwrap_or(""))
                    .ok()
                    .flatten();
                let mut errs = Vec::new();
                let session_id = params
                    .as_ref()
                    .and_then(|p| p.string("sessionId", &mut errs))
                    .unwrap_or_default();
                let cancel_id = params
                    .as_ref()
                    .and_then(|p| p.raw("id").map(str::to_string));
                {
                    let mut st = self.st();
                    if let Some(sess) = st.sessions.get_mut(&session_id) {
                        sess.last_output = Instant::now();
                    }
                    if m.method == "$/cancel_request"
                        && let Some(id) = cancel_id
                    {
                        st.agent_reqs.remove(&gojson::compact(&id, false));
                    }
                }
                self.to_client(&m);
            }
        }
    }

    /// Tracks sessions and turns from a response, and rewrites it for the client.
    fn after_response(self: &Arc<Self>, req: ClientReq, m: Message) -> Message {
        match req.method.as_str() {
            "initialize" => {
                if m.error.is_some() {
                    return m;
                }
                let result = gojson::object(m.result.as_deref().unwrap_or(""))
                    .ok()
                    .flatten();
                let mut errs = Vec::new();
                let version = result
                    .as_ref()
                    .and_then(|r| r.int("protocolVersion", &mut errs))
                    .unwrap_or(0);
                let caps_raw = result
                    .as_ref()
                    .and_then(|r| r.raw("agentCapabilities").map(str::to_string));
                let caps_map = gojson::decode_raw_map(caps_raw.as_deref()).ok().flatten();
                let sc = gojson::decode_raw_map(
                    caps_map
                        .as_ref()
                        .and_then(|c| c.get("sessionCapabilities"))
                        .map(String::as_str),
                )
                .ok()
                .flatten();
                let can_close = sc.is_some_and(|sc| sc.contains_key("close"));
                {
                    let mut st = self.st();
                    st.protocol_version = version;
                    st.can_close = can_close;
                }
                let info = api_agent_info(result.as_ref().and_then(|r| r.raw("agentInfo")));
                let caps = caps_raw
                    .as_deref()
                    .filter(|r| gojson::kind(r) == gojson::Kind::Object)
                    .and_then(gojson::decode_any)
                    .and_then(|v| v.as_object().cloned());
                self.srv.set_status(&self.agent.id, |st| {
                    st.agent_info = info;
                    st.capabilities = caps;
                });
                if let Some(stripped) = rewrite::strip_terminal_auth(m.result.as_deref())
                    && let Ok(out) = m.with_result(&stripped)
                {
                    return out;
                }
            }
            "session/new" | "session/load" | "session/resume" => {
                if let Some(e) = &m.error {
                    if is_auth_error(e) {
                        self.srv.mark_auth_required(&self.agent.id, &e.message);
                    }
                    return m;
                }
                let mut id = req.session_id.clone();
                if req.method == "session/new" {
                    let r = gojson::object(m.result.as_deref().unwrap_or(""))
                        .ok()
                        .flatten();
                    let mut errs = Vec::new();
                    id = r
                        .and_then(|r| r.string("sessionId", &mut errs))
                        .unwrap_or_default();
                }
                if !id.is_empty() {
                    self.st().sessions.insert(
                        id.clone(),
                        LinkSession {
                            turn_running: false,
                            last_output: Instant::now(),
                        },
                    );
                    self.srv.hold_session(&self.agent.id, &id, self);
                    self.srv.audit().event(
                        "session_opened",
                        [
                            ("link", sv(short(&self.id))),
                            ("session", sv(&id)),
                            ("method", sv(&req.method)),
                        ],
                    );
                }
                self.srv.set_status(&self.agent.id, |st| {
                    st.status = "ready".into();
                    st.auth_hint.clear();
                    st.error.clear();
                });
            }
            "session/prompt" => {
                if let Some(sess) = self.st().sessions.get_mut(&req.session_id) {
                    sess.turn_running = false;
                }
                if let Some(e) = &m.error
                    && is_auth_error(e)
                {
                    self.srv.mark_auth_required(&self.agent.id, &e.message);
                }
            }
            "session/list" => {
                if !req.cwd.is_empty() && m.error.is_none() {
                    return map_list_cwd(&m, &req.cwd, &req.orig_cwd);
                }
            }
            "session/close" => {
                self.st().sessions.remove(&req.session_id);
                self.srv
                    .release_session(&self.agent.id, &req.session_id, self);
            }
            _ => {}
        }
        m
    }

    /// Answers agent→client requests the server handles itself, and records
    /// the rest as pending. `None` means forward to the client.
    fn answer_agent_request(&self, m: &Message) -> Option<Message> {
        let id = m.id.clone().unwrap_or_default();
        if m.method.starts_with("fs/") || m.method.starts_with("terminal/") {
            return Some(jsonrpc::new_error(
                &id,
                jsonrpc::CODE_METHOD_NOT_FOUND,
                "Method not found: files and terminals stay on the agent host",
            ));
        }
        let unattended = {
            let st = self.st();
            st.state == STATE_UNATTENDED || st.state == STATE_ENDED
        };
        if m.method == "session/request_permission" {
            let mut policy = self.token.effective_permissions(&self.agent);
            if unattended {
                policy = "cancel".into();
            }
            if let Some(reply) = permission_reply(m, &policy) {
                self.srv.audit().event(
                    "permission_answered",
                    [
                        ("link", sv(short(&self.id))),
                        ("by", sv("policy")),
                        ("policy", sv(&policy)),
                    ],
                );
                return Some(reply);
            }
        } else if unattended {
            return Some(settle_reply(&id, &m.method));
        }
        self.st().agent_reqs.insert(
            m.id_key(),
            AgentReq {
                id,
                method: m.method.clone(),
                since: Instant::now(),
            },
        );
        None
    }

    /// Answers every request the agent is waiting on.
    async fn settle_pending(&self) {
        let reqs: Vec<AgentReq> = std::mem::take(&mut self.st().agent_reqs)
            .into_values()
            .collect();
        for r in reqs {
            self.write_agent(&settle_reply(&r.id, &r.method)).await;
        }
    }

    /// Sends a request the client did not make, in actp's own id namespace.
    async fn server_request(&self, method: &str, params: GoValue) {
        let id = {
            let mut st = self.st();
            st.next_server_req += 1;
            let id = format!("\"actp-{}\"", st.next_server_req);
            st.server_reqs.insert(id.clone());
            id
        };
        self.write_agent(&jsonrpc::new_request(&id, method, params))
            .await;
    }

    async fn cancel_running_turns(&self) {
        let ids: Vec<String> = self
            .st()
            .sessions
            .iter()
            .filter(|(_, s)| s.turn_running)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.write_agent(&jsonrpc::new_notification(
                "session/cancel",
                map([("sessionId", s(id))]),
            ))
            .await;
        }
    }

    /// Marks that nobody will come back to this link (design 3.1).
    pub(crate) async fn become_unattended(&self, reason: &str) {
        {
            let mut st = self.st();
            if st.state == STATE_UNATTENDED || st.state == STATE_ENDED {
                return;
            }
            st.state = STATE_UNATTENDED;
            st.state_since = Instant::now();
            st.state_since_wall = SystemTime::now();
        }
        self.srv.audit().event(
            "link_unattended",
            [("link", sv(short(&self.id))), ("reason", sv(reason))],
        );
        self.ep.set_discard(true);
        self.ep.detach(CLOSE_LINK_ENDED, reason);
        self.settle_pending().await;
        if self.agent.on_client_exit == "cancel" {
            self.cancel_running_turns().await;
        }
    }

    /// Runs the link timers (design 3.1).
    async fn supervise(self: Arc<Self>) {
        let mut t = tokio::time::interval(self.srv.inner.opts.tick);
        t.tick().await;
        let mut ended = self.ended.subscribe();
        loop {
            tokio::select! {
                _ = ended.wait_for(|e| *e) => return,
                _ = t.tick() => {}
            }
            let (state, since, running, oldest, cancel_sent, idle_since) = {
                let mut st = self.st();
                let running = running_locked(&st);
                let oldest = st.agent_reqs.values().map(|r| r.since).min();
                if running || oldest.is_some() {
                    st.last_busy = Some(Instant::now());
                }
                let idle_since = match st.last_busy {
                    Some(b) if b > st.state_since => b,
                    _ => st.state_since,
                };
                (
                    st.state,
                    st.state_since,
                    running,
                    oldest,
                    st.cancel_sent,
                    idle_since,
                )
            };
            let cfg = self.srv.config();
            if state != STATE_ENDED && state != STATE_UNATTENDED {
                // Disk is bounded in every state, also for a slow client that is still attached.
                if self.ep.outbox_bytes() > cfg.spool_limit {
                    self.end(ERR_SPOOL_FULL, "output spool is full").await;
                    continue;
                }
                if let Some(e) = self.ep.spool_error() {
                    self.end(ERR_SPOOL_FULL, &format!("output spool failed: {e}"))
                        .await;
                    continue;
                }
            }
            match state {
                STATE_DETACHED => {
                    if oldest.is_some_and(|o| o.elapsed() >= cfg.prompt_timeout) {
                        self.end(ERR_LINK_ENDED, "prompt unanswered past prompt_timeout")
                            .await;
                    } else if !running && oldest.is_none() && idle_since.elapsed() >= cfg.idle_close
                    {
                        self.end(ERR_LINK_ENDED, "detached and idle past idle_close")
                            .await;
                    }
                }
                STATE_UNATTENDED => {
                    if !running {
                        self.end(ERR_LINK_ENDED, "client left and the turn is done")
                            .await;
                    } else if since.elapsed() >= self.agent.max_unattended + Duration::from_secs(30)
                    {
                        self.end(ERR_LINK_ENDED, "unattended turn did not stop after cancel")
                            .await;
                    } else if !cancel_sent && since.elapsed() >= self.agent.max_unattended {
                        self.st().cancel_sent = true;
                        self.log("unattended turn ran past max_unattended, cancelling");
                        self.cancel_running_turns().await;
                    }
                }
                _ => {}
            }
        }
    }

    pub(crate) async fn end(&self, code: &str, reason: &str) {
        self.end_with_data(code, reason, None).await;
    }

    /// Forgets an ended link once its client has everything.
    fn finalize_if_delivered(&self) {
        if !self.ep.attached() && self.ep.outbox_bytes() == 0 {
            self.finalize();
        }
    }

    /// Drops what an ended link still holds and forgets it.
    pub(crate) fn finalize(&self) {
        {
            let mut st = self.st();
            if st.finalized {
                return;
            }
            st.finalized = true;
        }
        self.ep.set_discard(true);
        self.ep.close();
        self.srv.forget_link(&self.id);
    }

    /// Settles the agent and closes the link (design 3.2).
    async fn end_with_data(&self, code: &str, reason: &str, data: Option<String>) {
        self.end_once
            .get_or_init(|| async {
                let (open, can_close) = {
                    let mut st = self.st();
                    st.state = STATE_ENDED;
                    st.state_since = Instant::now();
                    st.state_since_wall = SystemTime::now();
                    (st.sessions.keys().cloned().collect::<Vec<_>>(), st.can_close)
                };
                tracing::info!(link = short(&self.id), agent = %self.agent.id, reason, "link ended");
                self.srv.audit().event("link_ended", [("link", sv(short(&self.id))), ("code", sv(code)), ("reason", sv(reason))]);

                if !self.proc.exited() {
                    // Writes to a wedged agent can block, so they get a deadline; stop always runs.
                    let settle = async {
                        self.settle_pending().await;
                        self.cancel_running_turns().await;
                        if can_close {
                            for id in &open {
                                self.server_request("session/close", map([("sessionId", s(id.clone()))])).await;
                            }
                            let _ = tokio::time::timeout(Duration::from_secs(1), self.wait_server_reqs()).await;
                        }
                    };
                    if tokio::time::timeout(Duration::from_secs(3), settle).await.is_err() {
                        self.log("agent did not take the settle messages in time, stopping it");
                    }
                    self.proc.stop(Duration::from_secs(2)).await;
                }

                // Let the agent's last output reach the client before the error frame,
                // which the endpoint sends only after everything queued is on the wire.
                let mut drained = self.drained.subscribe();
                let _ = tokio::time::timeout(Duration::from_secs(2), drained.wait_for(|d| *d)).await;
                for id in &open {
                    self.srv.release_session(&self.agent.id, id, self);
                }
                // The error frame goes out on whatever socket is attached now or later,
                // after every queued message, so a client that is reconnecting still gets
                // its output and then the reason (design 3.1).
                let tomb = Tombstone { code: code.to_string(), reason: reason.to_string(), data };
                self.st().tomb = Some(tomb.clone());
                if self.ep.attached() || self.ep.outbox_bytes() > 0 {
                    self.ep.send_control(tomb.frame());
                    let me = self.srv.st().links.get(&self.id).cloned();
                    if let Some(me) = me {
                        tokio::spawn(async move {
                            tokio::time::sleep(TOMBSTONE_FOR).await;
                            me.finalize();
                        });
                    }
                } else {
                    self.finalize();
                }
                self.ended.send_replace(true);
            })
            .await;
    }

    /// Waits for the link to end, up to `d`.
    pub(crate) async fn wait_ended(&self, d: Duration) -> bool {
        let mut rx = self.ended.subscribe();
        tokio::time::timeout(d, rx.wait_for(|e| *e)).await.is_ok()
    }

    async fn wait_server_reqs(&self) {
        loop {
            if self.st().server_reqs.is_empty() || self.proc.exited() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub(crate) fn pid(&self) -> u32 {
        self.proc.pid()
    }
}

/// Whether any session has a turn running (design 3.7).
fn running_locked(st: &LinkState) -> bool {
    st.sessions.values().any(|s| {
        s.turn_running
            || (st.protocol_version >= 2 && s.last_output.elapsed() < Duration::from_secs(120))
    })
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n {
        let mut end = n;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

fn api_agent_info(raw: Option<&str>) -> Option<actp_proto::api::AgentInfo> {
    actp_proto::api::AgentInfo::decode(raw)
}

/// Go's `(?i)auth(entication|orization)? required|not (logged|signed) in|unauthenticated|please (log|sign) ?in`.
pub(crate) fn auth_error_text(text: &str) -> bool {
    let t = text.to_lowercase();
    let auth_required = [
        "auth required",
        "authentication required",
        "authorization required",
    ]
    .iter()
    .any(|p| t.contains(p));
    let not_in = ["not logged in", "not signed in"]
        .iter()
        .any(|p| t.contains(p));
    let please = [
        "please login",
        "please log in",
        "please signin",
        "please sign in",
    ]
    .iter()
    .any(|p| t.contains(p));
    auth_required || not_in || t.contains("unauthenticated") || please
}

fn is_auth_error(e: &jsonrpc::RpcError) -> bool {
    auth_error_text(&e.message) || e.data.as_deref().is_some_and(auth_error_text)
}

/// Shows the client its own cwd form in `session/list` results.
fn map_list_cwd(m: &Message, resolved: &str, orig: &str) -> Message {
    let Ok(Some(mut r)) = gojson::decode_raw_map(m.result.as_deref()) else {
        return m.clone();
    };
    let Ok(mut sessions) = gojson::decode_raw_maps(r.get("sessions").map(String::as_str)) else {
        return m.clone();
    };
    for sm in sessions.iter_mut().flatten().flatten() {
        if gojson::string_or_empty(sm.get("cwd").map(String::as_str)) == resolved {
            sm.insert("cwd".into(), gojson::string(orig));
        }
    }
    r.insert("sessions".into(), gojson::encode_raw_maps(&sessions));
    m.with_result(&gojson::encode_raw_map(&Some(r)))
        .unwrap_or_else(|_| m.clone())
}

fn is_elicitation(method: &str) -> bool {
    method == "elicitation/create" || method == "session/elicitation"
}

fn cancelled_outcome() -> GoValue {
    map([("outcome", map([("outcome", s("cancelled"))]))])
}

/// Answers a permission request by policy, or `None` to forward it.
fn permission_reply(m: &Message, policy: &str) -> Option<Message> {
    let id = m.id.clone().unwrap_or_default();
    let params = gojson::object(m.params.as_deref().unwrap_or(""))
        .ok()
        .flatten();
    let options: Vec<(String, String)> = params
        .as_ref()
        .and_then(|p| p.raw("options"))
        .and_then(|raw| serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(raw).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|o| gojson::object(o.get()).ok().flatten())
        .map(|o| {
            let mut errs = Vec::new();
            (
                o.string("optionId", &mut errs).unwrap_or_default(),
                o.string("kind", &mut errs).unwrap_or_default(),
            )
        })
        .collect();
    let pick = |kind: &str| {
        options
            .iter()
            .find(|(_, k)| k == kind)
            .map(|(id, _)| id.clone())
            .filter(|id| !id.is_empty())
    };
    let selected = |opt: String| {
        jsonrpc::new_result(
            &id,
            map([(
                "outcome",
                map([("outcome", s("selected")), ("optionId", s(opt))]),
            )]),
        )
    };
    match policy {
        "auto_allow" => pick("allow_once").map(selected),
        "auto_deny" => Some(
            pick("reject_once")
                .map(selected)
                .unwrap_or_else(|| jsonrpc::new_result(&id, cancelled_outcome())),
        ),
        "cancel" => Some(jsonrpc::new_result(&id, cancelled_outcome())),
        _ => None,
    }
}

/// The answer to an agent request nobody will answer (design 3.2).
fn settle_reply(id: &str, method: &str) -> Message {
    if method == "session/request_permission" {
        jsonrpc::new_result(id, cancelled_outcome())
    } else if is_elicitation(method) {
        jsonrpc::new_result(id, map([("action", s("cancel"))]))
    } else {
        jsonrpc::new_error(
            id,
            jsonrpc::CODE_METHOD_NOT_FOUND,
            "Method not found: the client has left",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_errors() {
        for t in [
            "Authentication required",
            "auth required",
            "You are not logged in",
            "UNAUTHENTICATED",
            "Please log in first",
            "please signin",
        ] {
            assert!(auth_error_text(t), "{t}");
        }
        for t in ["Invalid params", "authorized", "logged in"] {
            assert!(!auth_error_text(t), "{t}");
        }
    }

    #[test]
    fn permission_policies() {
        let m = jsonrpc::parse(r#"{"jsonrpc":"2.0","id":"agent-1","method":"session/request_permission","params":{"options":[{"optionId":"allow","kind":"allow_once"},{"optionId":"deny","kind":"reject_once"}]}}"#).unwrap();
        assert_eq!(
            permission_reply(&m, "auto_allow").unwrap().raw,
            r#"{"id":"agent-1","jsonrpc":"2.0","result":{"outcome":{"optionId":"allow","outcome":"selected"}}}"#
        );
        assert_eq!(
            permission_reply(&m, "auto_deny").unwrap().raw,
            r#"{"id":"agent-1","jsonrpc":"2.0","result":{"outcome":{"optionId":"deny","outcome":"selected"}}}"#
        );
        assert_eq!(
            permission_reply(&m, "cancel").unwrap().raw,
            r#"{"id":"agent-1","jsonrpc":"2.0","result":{"outcome":{"outcome":"cancelled"}}}"#
        );
        assert!(permission_reply(&m, "forward").is_none());
        assert_eq!(
            settle_reply("3", "elicitation/create").raw,
            r#"{"id":3,"jsonrpc":"2.0","result":{"action":"cancel"}}"#
        );
    }

    #[test]
    fn list_cwd_mapping() {
        let m = jsonrpc::parse(r#"{"jsonrpc":"2.0","id":1,"result":{"sessions":[{"sessionId":"a","cwd":"/srv/site"},{"sessionId":"b","cwd":"/other"}]}}"#).unwrap();
        assert_eq!(
            map_list_cwd(&m, "/srv/site", "actp://site").raw,
            r#"{"id":1,"jsonrpc":"2.0","result":{"sessions":[{"cwd":"actp://site","sessionId":"a"},{"cwd":"/other","sessionId":"b"}]}}"#
        );
    }
}

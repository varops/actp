//! A link: one ACP connection to one agent process (design 1, wire 3), its
//! states and timers (design 3.1), the rewrites (3.3) and the settle order
//! when it ends (3.2). A port of Go's `internal/server/link.go`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::AtomicBool;
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
    /// A load or resume holds the session's next messages until it is checked.
    check: Option<Arc<SessionCheck>>,
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
    /// actp's own requests; a sender gets the agent's answer.
    server_reqs: HashMap<String, Option<tokio::sync::oneshot::Sender<Message>>>,
    next_server_req: u64,
    cancel_sent: bool,
    tomb: Option<Tombstone>,
    finalized: bool,
    last_busy: Option<Instant>,
    /// Client messages for sessions whose starting mode is being checked.
    held: HashMap<String, HeldSession>,
    /// Client request ids actp already answered (timed-out loads).
    abandoned: HashSet<String>,
    /// Config options that select the session mode.
    mode_options: HashSet<String>,
    /// Mode ids the agent offers.
    offered_modes: HashSet<String>,
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
                    server_reqs: HashMap::new(),
                    next_server_req: 0,
                    cancel_sent: false,
                    tomb: None,
                    finalized: false,
                    last_busy: None,
                    held: HashMap::new(),
                    abandoned: HashSet::new(),
                    mode_options: HashSet::new(),
                    offered_modes: HashSet::new(),
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
        // A message for a session whose starting mode is still being checked
        // waits until the check is done, so it never reaches the agent in the
        // refused mode.
        let m = if m.kind() != Kind::Response {
            match self.hold_if_checking(m) {
                Some(m) => m,
                None => return,
            }
        } else {
            m
        };
        self.handle_client(m).await;
    }

    /// Handles one parsed client message (`from_client` after the checks).
    async fn handle_client(self: &Arc<Self>, m: Message) {
        match m.kind() {
            Kind::Response => {
                let (known, mode) = {
                    let mut st = self.st();
                    let req = st.agent_reqs.remove(&m.id_key());
                    let mode = req
                        .as_ref()
                        .filter(|r| r.method == "session/request_permission")
                        .and_then(|_| {
                            crate::modes::permission_picks_mode(
                                m.result.as_deref(),
                                &st.offered_modes,
                            )
                        });
                    (req.is_some(), mode)
                };
                if !known {
                    return; // a late answer to a request already settled
                }
                if let Some(mode) =
                    mode.filter(|mode| !crate::modes::mode_allowed(&self.agent, &self.token, mode))
                {
                    // Picking a mode in a permission answer switches the session to it.
                    self.srv.audit().event(
                        "mode_refused",
                        [
                            ("link", sv(short(&self.id))),
                            ("mode", sv(&mode)),
                            ("via", sv("permission")),
                        ],
                    );
                    let id = m.id.clone().unwrap_or_default();
                    self.write_agent(&jsonrpc::new_result(&id, cancelled_outcome()))
                        .await;
                    return;
                }
                self.write_agent(&m).await;
            }
            Kind::Notification => {
                let p = gojson::decode_raw_map(m.params.as_deref()).unwrap_or(None);
                if let Some(field) = rewrite::unchecked_session_field(&m.method, &p) {
                    tracing::info!(link = short(&self.id), agent = %self.agent.id, method = %m.method, field, "dropped a notification actp cannot check");
                    self.srv.audit().event(
                        "session_method_refused",
                        [
                            ("link", sv(short(&self.id))),
                            ("method", sv(&m.method)),
                            ("field", sv(field)),
                        ],
                    );
                    return;
                }
                self.write_agent(&m).await
            }
            Kind::Request => {
                // actp's own requests to the agent use ids starting with actp-;
                // a client id like that could be mistaken for one of them.
                if m.id
                    .as_deref()
                    .and_then(|id| gojson::decode_string(id).ok().flatten())
                    .is_some_and(|id| id.starts_with("actp-"))
                {
                    self.srv.audit().event(
                        "id_refused",
                        [("link", sv(short(&self.id))), ("method", sv(&m.method))],
                    );
                    let id = m.id.clone().unwrap_or_default();
                    self.to_client(&jsonrpc::new_error(
                        &id,
                        jsonrpc::CODE_INVALID_REQUEST,
                        "invalid request: ids starting with \"actp-\" are reserved for actp",
                    ));
                    return;
                }
                let load = (m.method == "session/load" || m.method == "session/resume")
                    .then(|| params_session_id(&m))
                    .filter(|s| !s.is_empty());
                let (req_id, req_key) = (m.id.clone(), m.id_key());
                match self.rewrite_client_request(m).await {
                    Ok(out) => {
                        // Until the agent's answer is through the starting-mode check,
                        // the client's next requests for this session wait (the load
                        // may switch the session to a mode from the workspace settings).
                        if let Some(sid) = load {
                            let c = self.start_check(&sid, req_id);
                            if let Some(r) = self.st().client_reqs.get_mut(&req_key) {
                                r.check = Some(c);
                            }
                        }
                        self.write_agent(&out).await
                    }
                    Err(reply) => self.to_client(&reply),
                }
            }
        }
    }

    /// Holds a session's client messages until the check ends. A check for a
    /// client's load or resume times out after `held_load_timeout`.
    fn start_check(self: &Arc<Self>, sid: &str, req_id: Option<String>) -> Arc<SessionCheck> {
        let c = Arc::new(SessionCheck {
            sid: sid.to_string(),
            req_id,
            done: AtomicBool::new(false),
        });
        self.st().held.entry(sid.to_string()).or_default().checks += 1;
        if c.req_id.is_some() {
            let (me, c2) = (self.clone(), c.clone());
            let timeout = self.srv.inner.opts.held_load_timeout;
            tokio::spawn(async move {
                tokio::time::sleep(timeout).await;
                me.time_out_check(&c2).await;
            });
        }
        c
    }

    /// Marks a check as ending; false means it already ended (timed out). The
    /// caller answers the client, then calls `end_check`.
    fn claim_check(c: &SessionCheck) -> bool {
        !c.done.swap(true, std::sync::atomic::Ordering::SeqCst)
    }

    /// Ends a claimed check. Without a refusal the queue drains once no check is
    /// left; with one, queued requests get it and notifications are dropped.
    fn end_check(self: &Arc<Self>, c: &SessionCheck, refusal: Option<&(i64, String)>) {
        let (refused, drain) = {
            let mut st = self.st();
            let Some(h) = st.held.get_mut(&c.sid) else {
                return;
            };
            h.checks = h.checks.saturating_sub(1);
            let mut refused = VecDeque::new();
            if refusal.is_some() {
                refused = std::mem::take(&mut h.queue);
                h.bytes = 0;
            }
            let drain = h.checks == 0 && !h.draining && !h.queue.is_empty();
            if drain {
                h.draining = true;
            }
            if h.checks == 0 && !h.draining && h.queue.is_empty() {
                st.held.remove(&c.sid);
            }
            (refused, drain)
        };
        if let Some((code, msg)) = refusal {
            for m in refused.into_iter().filter(|m| m.kind() == Kind::Request) {
                self.to_client(&jsonrpc::new_error(
                    &m.id.clone().unwrap_or_default(),
                    *code,
                    msg,
                ));
            }
        }
        if drain {
            // Never on the task that reads the agent: it must keep reading while
            // actp writes to the agent, or both could block on full pipes.
            tokio::spawn(self.clone().drain_held(c.sid.clone()));
        }
    }

    /// Hands queued messages on one at a time, and stops when one of them
    /// starts a new check (a queued load), which then owns what follows.
    async fn drain_held(self: Arc<Self>, sid: String) {
        loop {
            let m = {
                let mut st = self.st();
                let Some(h) = st.held.get_mut(&sid) else {
                    return;
                };
                if h.checks > 0 {
                    h.draining = false;
                    return;
                }
                let Some(m) = h.queue.pop_front() else {
                    st.held.remove(&sid);
                    return;
                };
                h.bytes = h.bytes.saturating_sub(m.raw.len());
                m
            };
            Box::pin(self.handle_client(m)).await;
        }
    }

    /// Queues a client message for a session under check; returns it when it
    /// can go on now. A full queue refuses the message.
    fn hold_if_checking(&self, m: Message) -> Option<Message> {
        let sid = params_session_id(&m);
        if sid.is_empty() {
            return Some(m);
        }
        let (max_n, max_b) = (
            self.srv.inner.opts.max_held_messages,
            self.srv.inner.opts.max_held_bytes,
        );
        {
            let mut st = self.st();
            let Some(h) = st.held.get_mut(&sid) else {
                return Some(m);
            };
            if h.queue.len() < max_n && h.bytes + m.raw.len() <= max_b {
                h.bytes += m.raw.len();
                h.queue.push_back(m);
                return None;
            }
        }
        self.srv.audit().event(
            "held_overflow",
            [
                ("link", sv(short(&self.id))),
                ("session", sv(&sid)),
                ("method", sv(&m.method)),
            ],
        );
        if m.kind() == Kind::Request {
            self.to_client(&jsonrpc::new_error(
                &m.id.clone().unwrap_or_default(),
                jsonrpc::CODE_SERVER_ERROR,
                "session busy: too many messages are waiting for this session's mode check",
            ));
        }
        None
    }

    /// Ends a load or resume the agent did not answer in time: the client gets
    /// an error for it and for everything queued, the agent's late answer is
    /// dropped, and the session is closed.
    async fn time_out_check(self: &Arc<Self>, c: &SessionCheck) {
        if !Self::claim_check(c) {
            return;
        }
        let req_id = c.req_id.clone().unwrap_or_default();
        let can_close = {
            let mut st = self.st();
            let st = &mut *st;
            abandon_pending(&mut st.client_reqs, &mut st.abandoned, &req_id);
            st.sessions.remove(&c.sid);
            st.can_close
        };
        self.srv.audit().event(
            "load_timed_out",
            [("link", sv(short(&self.id))), ("session", sv(&c.sid))],
        );
        let refusal = (
            jsonrpc::CODE_SERVER_ERROR,
            "session refused: the agent did not answer in time".to_string(),
        );
        self.to_client(&jsonrpc::new_error(&req_id, refusal.0, &refusal.1));
        self.end_check(c, Some(&refusal));
        self.srv.release_session(&self.agent.id, &c.sid, self);
        if can_close {
            self.server_request("session/close", map([("sessionId", s(c.sid.clone()))]))
                .await;
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
        } else if rewrite::session_cwd_required(&m.method) || m.method == "session/list" {
            let cwd = gojson::string_or_empty(
                p.as_ref().and_then(|pm| pm.get("cwd")).map(String::as_str),
            );
            if !cwd.is_empty() || rewrite::session_cwd_required(&m.method) {
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
            if let Some(dirs) = p
                .as_ref()
                .and_then(|pm| pm.get("additionalDirectories"))
                .cloned()
            {
                match rewrite::resolve_additional_directories(
                    &self.srv.config(),
                    &self.token,
                    &dirs,
                ) {
                    Ok(resolved) => {
                        if let Some(pm) = p.as_mut() {
                            pm.insert("additionalDirectories".into(), resolved);
                        }
                    }
                    Err(msg) => {
                        self.srv.audit().event(
                            "cwd_rejected",
                            [
                                ("link", sv(short(&self.id))),
                                ("additionalDirectories", sv(&dirs)),
                            ],
                        );
                        return Err(Box::new(jsonrpc::new_error(
                            &id,
                            jsonrpc::CODE_INVALID_PARAMS,
                            &msg,
                        )));
                    }
                }
            }
            if let Some(meta) = p.as_ref().and_then(|pm| pm.get("_meta")).cloned()
                && let Some(pm) = p.as_mut()
            {
                match rewrite::keep_meta_keys(&meta, &self.agent.keep_session_meta) {
                    Some(kept) => pm.insert("_meta".into(), kept),
                    None => pm.remove("_meta"),
                };
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
        } else if let Some(field) = rewrite::unchecked_session_field(&m.method, &p) {
            self.srv.audit().event(
                "session_method_refused",
                [
                    ("link", sv(short(&self.id))),
                    ("method", sv(&m.method)),
                    ("field", sv(field)),
                ],
            );
            return Err(Box::new(jsonrpc::new_error(
                &id,
                jsonrpc::CODE_INVALID_REQUEST,
                &rewrite::unchecked_session_message(&m.method, field),
            )));
        }

        let modes = {
            let st = self.st();
            crate::modes::requested_modes(&m.method, &p, |id| {
                id == "mode" || st.mode_options.contains(id)
            })
        };
        let refused = match modes {
            Err(msg) => Some((msg.to_string(), String::new())),
            Ok(modes) => modes
                .into_iter()
                .find(|mode| !crate::modes::mode_allowed(&self.agent, &self.token, mode))
                .map(|mode| (format!("mode not allowed: {mode}"), mode)),
        };
        if let Some((msg, mode)) = refused {
            if mode.is_empty() {
                self.srv.audit().event(
                    "mode_refused",
                    [("link", sv(short(&self.id))), ("method", sv(&m.method))],
                );
            } else {
                self.srv.audit().event(
                    "mode_refused",
                    [
                        ("link", sv(short(&self.id))),
                        ("method", sv(&m.method)),
                        ("mode", sv(&mode)),
                    ],
                );
            }
            return Err(Box::new(jsonrpc::new_error(
                &id,
                jsonrpc::CODE_INVALID_PARAMS,
                &msg,
            )));
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
                    if let Some(answer) = st.server_reqs.remove(&m.id_key()) {
                        if let Some(tx) = answer {
                            let _ = tx.send(m);
                        }
                        return;
                    }
                    if st.abandoned.remove(&m.id_key()) {
                        return; // actp answered it already (timed out)
                    }
                    st.client_reqs.remove(&m.id_key())
                };
                let check = req.as_ref().and_then(|r| r.check.clone());
                if let Some(c) = &check
                    && !Self::claim_check(c)
                {
                    return; // the load timed out; the client has its answer
                }
                let out = match req {
                    Some(req) => {
                        let (out, opened) = self.after_response(req, m);
                        match opened {
                            Some(sid) => self.check_starting_mode(out, sid, check.clone()).await,
                            None => Some(out),
                        }
                    }
                    None => Some(m),
                };
                // None: held until the agent answers actp's own request.
                if let Some(out) = out {
                    self.to_client(&out);
                    if let Some(c) = &check {
                        self.end_check(c, None);
                    }
                }
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
    /// Also returns the session id when the response opened a session.
    fn after_response(self: &Arc<Self>, req: ClientReq, m: Message) -> (Message, Option<String>) {
        match req.method.as_str() {
            "initialize" => {
                if m.error.is_some() {
                    return (m, None);
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
                    return (out, None);
                }
            }
            "session/set_config_option" | "session/options" => {
                if m.error.is_none() {
                    let mut st = self.st();
                    let st = &mut *st;
                    crate::modes::learn_modes(
                        m.result.as_deref(),
                        &mut st.mode_options,
                        &mut st.offered_modes,
                    );
                }
            }
            "session/new" | "session/load" | "session/resume" | "session/fork" => {
                if m.error.is_none() {
                    let mut st = self.st();
                    let st = &mut *st;
                    crate::modes::learn_modes(
                        m.result.as_deref(),
                        &mut st.mode_options,
                        &mut st.offered_modes,
                    );
                }
                if let Some(e) = &m.error {
                    if is_auth_error(e) {
                        self.srv.mark_auth_required(&self.agent.id, &e.message);
                    }
                    return (m, None);
                }
                let mut id = req.session_id.clone();
                if req.method == "session/new" || req.method == "session/fork" {
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
                if !id.is_empty() {
                    return (m, Some(id));
                }
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
                    return (map_list_cwd(&m, &req.cwd, &req.orig_cwd), None);
                }
            }
            "session/close" => {
                self.st().sessions.remove(&req.session_id);
                self.srv
                    .release_session(&self.agent.id, &req.session_id, self);
            }
            _ => {}
        }
        (m, None)
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
            let id = server_req_id(st.next_server_req);
            st.server_reqs.insert(id.clone(), None);
            id
        };
        self.write_agent(&jsonrpc::new_request(&id, method, params))
            .await;
    }

    /// `server_request` whose answer arrives on the returned receiver.
    async fn server_request_then(
        &self,
        method: &str,
        params: GoValue,
    ) -> (String, tokio::sync::oneshot::Receiver<Message>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = {
            let mut st = self.st();
            st.next_server_req += 1;
            let id = server_req_id(st.next_server_req);
            st.server_reqs.insert(id.clone(), Some(tx));
            id
        };
        self.write_agent(&jsonrpc::new_request(&id, method, params))
            .await;
        (id, rx)
    }

    /// Makes sure a session does not start in a refused mode. An agent can pick
    /// it from project settings in the workspace (Claude Code reads
    /// `permissions.defaultMode` from `.claude/settings.json`), so the client
    /// never asked for it. The session is switched to an allowed mode before the
    /// client sees the response; if that fails, the session is closed and the
    /// client gets an error. `None`: the response is held until the agent answers.
    ///
    /// `check` is the client's load or resume holding the session, already
    /// claimed; for a new or forked session one is started when a reset is needed.
    async fn check_starting_mode(
        self: &Arc<Self>,
        m: Message,
        sid: String,
        check: Option<Arc<SessionCheck>>,
    ) -> Option<Message> {
        let (current, offered) = crate::modes::starting_modes(m.result.as_deref());
        let allowed = |mode: &str| crate::modes::mode_allowed(&self.agent, &self.token, mode);
        let Some(bad) = current.into_iter().find(|mode| !allowed(mode)) else {
            return Some(m);
        };
        let Some(target) = crate::modes::reset_target(&offered, allowed) else {
            self.refuse_starting_mode(
                &m,
                &sid,
                &bad,
                "the agent offers no allowed mode",
                check.as_deref(),
            )
            .await;
            return None;
        };
        self.srv.audit().event(
            "mode_reset",
            [
                ("link", sv(short(&self.id))),
                ("session", sv(&sid)),
                ("from", sv(&bad)),
                ("to", sv(&target)),
            ],
        );
        let check = check.unwrap_or_else(|| {
            let c = self.start_check(&sid, None);
            Self::claim_check(&c);
            c
        });
        let (req_id, rx) = self
            .server_request_then(
                "session/set_mode",
                map([("sessionId", s(sid.clone())), ("modeId", s(target.clone()))]),
            )
            .await;
        let me = self.clone();
        let timeout = self.srv.inner.opts.mode_reset_timeout;
        tokio::spawn(async move {
            tokio::pin!(rx);
            let answer = tokio::select! {
                a = &mut rx => a,
                _ = tokio::time::sleep(timeout) => {
                    // An agent that never answers must not hold the session forever.
                    let waiting = me.st().server_reqs.remove(&req_id).is_some();
                    if waiting {
                        me.refuse_starting_mode(&m, &sid, &bad, "the agent did not answer the switch in time", Some(&check)).await;
                        return;
                    }
                    rx.await
                }
            };
            let Ok(answer) = answer else {
                return; // the link ended first
            };
            if let Some(e) = &answer.error {
                me.refuse_starting_mode(
                    &m,
                    &sid,
                    &bad,
                    &format!("the agent refused the switch: {}", e.message),
                    Some(&check),
                )
                .await;
                return;
            }
            match crate::modes::rewrite_starting_mode(m.result.as_deref(), &target)
                .and_then(|r| m.with_result(&r).ok())
            {
                Some(out) => {
                    me.to_client(&out);
                    me.end_check(&check, None);
                }
                None => {
                    me.refuse_starting_mode(
                        &m,
                        &sid,
                        &bad,
                        "the response could not be rewritten",
                        Some(&check),
                    )
                    .await
                }
            }
        });
        None
    }

    async fn refuse_starting_mode(
        self: &Arc<Self>,
        m: &Message,
        sid: &str,
        bad: &str,
        reason: &str,
        check: Option<&SessionCheck>,
    ) {
        self.srv.audit().event(
            "mode_reset_failed",
            [
                ("link", sv(short(&self.id))),
                ("session", sv(sid)),
                ("mode", sv(bad)),
                ("reason", sv(reason)),
            ],
        );
        let can_close = {
            let mut st = self.st();
            st.sessions.remove(sid);
            st.can_close
        };
        self.srv.release_session(&self.agent.id, sid, self);
        if can_close {
            self.server_request("session/close", map([("sessionId", s(sid.to_string()))]))
                .await;
        }
        let id = m.id.clone().unwrap_or_default();
        let refusal = (
            jsonrpc::CODE_SERVER_ERROR,
            format!(
                "session refused: it starts in mode {bad}, which is not allowed here, and could not be switched to an allowed mode"
            ),
        );
        self.to_client(&jsonrpc::new_error(&id, refusal.0, &refusal.1));
        if let Some(c) = check {
            self.end_check(c, Some(&refusal));
        }
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

/// The client messages of one session, held while its starting mode is checked.
#[derive(Default)]
struct HeldSession {
    queue: VecDeque<Message>,
    bytes: usize,
    /// Checks still running.
    checks: usize,
    /// A drain task owns the queue.
    draining: bool,
}

/// One running check of a session's starting mode.
#[derive(Debug)]
struct SessionCheck {
    sid: String,
    /// The client's load or resume request; `None` for a reset of a new session.
    req_id: Option<String>,
    done: AtomicBool,
}

/// Forgets a client request actp has answered itself. Only a request whose
/// agent answer is still to come is recorded, so that answer is dropped when it
/// arrives (which also clears the record). If the answer was already taken,
/// recording the id would drop the answer to a later request that reuses it.
fn abandon_pending(
    client_reqs: &mut HashMap<String, ClientReq>,
    abandoned: &mut HashSet<String>,
    key: &str,
) -> bool {
    if client_reqs.remove(key).is_none() {
        return false;
    }
    abandoned.insert(key.to_string());
    true
}

/// The sessionId a client message names, if any.
fn params_session_id(m: &Message) -> String {
    let mut errs = Vec::new();
    gojson::object(m.params.as_deref().unwrap_or(""))
        .ok()
        .flatten()
        .and_then(|p| p.string("sessionId", &mut errs))
        .unwrap_or_default()
}

/// An id for actp's own requests to the agent. Client ids starting with
/// `actp-` are refused; the random part also keeps these ids from being guessed.
fn server_req_id(n: u64) -> String {
    format!("\"actp-{n}-{}\"", &crate::server::new_id()[..16])
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
    fn only_pending_requests_are_abandoned() {
        let mut reqs = HashMap::new();
        let mut abandoned = HashSet::new();
        reqs.insert("7".to_string(), ClientReq::default());
        assert!(abandon_pending(&mut reqs, &mut abandoned, "7"));
        assert!(abandoned.contains("7") && reqs.is_empty());
        // The agent's answer was taken just before the timeout: nothing is recorded,
        // so a later request reusing the id still gets its answer.
        let mut abandoned = HashSet::new();
        assert!(!abandon_pending(&mut reqs, &mut abandoned, "7"));
        assert!(abandoned.is_empty());
    }

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

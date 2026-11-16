//! The actp relay (docs/relay.md): one server, hosted by the client, that
//! machines dial out to and callers connect through.
//!
//! - Machines log in with the org's device certificate over mutual TLS. The
//!   name in the certificate is the machine's address; the relay never
//!   assigns one.
//! - A caller reaches a machine at `/m/<address>/…`. The relay forwards the
//!   request, credentials and all, untouched over a stream the machine opens
//!   for it. The machine decides who may do what; the relay only routes.
//! - The relay knows who is online and when each machine was last seen.
//! - The org-wide stop drops every session and refuses new ones until it is
//!   released; machines are told, and end their sessions themselves too.
//! - The relay's half of the audit: who connected to which machine, when and
//!   for how long, and every stop and release with who and why.

pub mod audit;
pub mod config;
mod http;
mod limit;
pub mod state;
pub mod tls;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actp_proto::relay::Control;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, rfc3339};
use crate::config::Config;
use crate::limit::{RateLimiter, Throttle};
use crate::state::{Seen, Stop, Store};

pub use crate::http::Stream;

/// Timers, for tests.
#[derive(Clone, Debug)]
pub struct Timing {
    /// How often the relay pings a machine (15 s).
    pub ping_every: Duration,
    /// A machine is gone after this long without a message (45 s).
    pub dead_after: Duration,
    /// How long a machine has to open a stream for a caller (10 s).
    pub stream_timeout: Duration,
    /// How long a machine has to answer a forwarded request (60 s).
    pub response_timeout: Duration,
    /// How long one write to a machine's control connection may take (10 s).
    pub send_timeout: Duration,
    /// How often machines.json and an unsaved stop are written (10 s).
    pub flush_every: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            ping_every: Duration::from_secs(15),
            dead_after: Duration::from_secs(45),
            stream_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
            send_timeout: Duration::from_secs(10),
            flush_every: Duration::from_secs(10),
        }
    }
}

/// A cancel token that remembers why it was cancelled.
#[derive(Clone, Default)]
pub(crate) struct Cut {
    token: CancellationToken,
    why: Arc<OnceLock<&'static str>>,
}

impl Cut {
    pub(crate) fn cut(&self, why: &'static str) {
        let _ = self.why.set(why);
        self.token.cancel();
    }

    pub(crate) async fn cancelled(&self) {
        self.token.cancelled().await
    }

    pub(crate) fn why(&self) -> &'static str {
        self.why.get().copied().unwrap_or("closed")
    }
}

/// The running relay. Cheap to clone.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: RwLock<Arc<Config>>,
    tls: RwLock<Option<tokio_rustls::TlsAcceptor>>,
    timing: Timing,
    audit: Audit,
    store: Store,
    st: Mutex<State>,
    /// machines.json is behind the state in memory.
    seen_dirty: AtomicBool,
    /// The stop is on but stop.json does not say so yet.
    stop_unsaved: AtomicBool,
    /// One writer for the state files at a time.
    writing: Mutex<()>,
    callers: RateLimiter,
    refusals: Throttle,
}

struct State {
    machines: BTreeMap<String, Machine>,
    pending: HashMap<String, Pending>,
    sessions: HashMap<u64, Session>,
    stop: Stop,
    next_id: u64,
}

#[derive(Default)]
struct Machine {
    conn: Option<Conn>,
    seen: Seen,
    /// Callers waiting for or using a stream to this machine.
    streams: usize,
}

struct Conn {
    id: u64,
    tx: mpsc::Sender<Control>,
    cut: Cut,
    since: SystemTime,
}

struct Pending {
    machine: String,
    tx: oneshot::Sender<Stream>,
}

struct Session {
    machine: String,
    cut: Cut,
}

/// A machine as `GET /relay/v1/machines` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineInfo {
    pub machine: String,
    pub online: bool,
    pub connected_since: Option<SystemTime>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub sessions: usize,
}

/// What pressing the stop did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stopped {
    pub stop: Stop,
    /// Whether `stop.json` says so. If not, the relay keeps trying, and a
    /// restart before it succeeds would lose the stop.
    pub saved: bool,
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn from_unix(s: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(s))
        .unwrap_or(UNIX_EPOCH)
}

impl Relay {
    pub fn new(cfg: Config) -> std::io::Result<Relay> {
        Self::with_timing(cfg, Timing::default())
    }

    pub fn with_timing(cfg: Config, timing: Timing) -> std::io::Result<Relay> {
        let store = Store::open(&cfg.state_dir)?;
        let audit = Audit::open(&cfg.log_dir, cfg.audit_max_bytes())?;
        let stop = store.load_stop();
        let machines = store
            .load_seen()
            .into_iter()
            .filter(|(m, _)| actp_proto::relay::valid_machine_name(m))
            .map(|(m, seen)| {
                (
                    m,
                    Machine {
                        seen,
                        ..Default::default()
                    },
                )
            })
            .collect();
        if stop.stopped {
            tracing::warn!(by = %stop.by, reason = %stop.reason, "the org-wide stop is on");
        }
        let callers = RateLimiter::new(cfg.caller_rate.per_second, cfg.caller_rate.burst);
        Ok(Relay {
            inner: Arc::new(Inner {
                cfg: RwLock::new(Arc::new(cfg)),
                tls: RwLock::new(None),
                timing,
                audit,
                store,
                st: Mutex::new(State {
                    machines,
                    pending: HashMap::new(),
                    sessions: HashMap::new(),
                    stop,
                    next_id: 0,
                }),
                seen_dirty: AtomicBool::new(false),
                stop_unsaved: AtomicBool::new(false),
                writing: Mutex::new(()),
                callers,
                refusals: Throttle::new(20, Duration::from_secs(60)),
            }),
        })
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.inner.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The configuration in force.
    pub fn config(&self) -> Arc<Config> {
        self.inner
            .cfg
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub(crate) fn timing(&self) -> &Timing {
        &self.inner.timing
    }

    pub(crate) fn audit(&self) -> &Audit {
        &self.inner.audit
    }

    pub(crate) fn callers(&self) -> &RateLimiter {
        &self.inner.callers
    }

    /// Records a refusal, unless refusals of this kind are flooding in; the
    /// ones left out are counted and recorded once a minute.
    pub(crate) fn refusal<const N: usize>(&self, kind: &'static str, fields: [(&str, Value); N]) {
        if self.inner.refusals.allow(kind) {
            self.inner.audit.event(kind, fields);
        }
    }

    /// Takes a new configuration and TLS setup (`SIGHUP`): blocked machines,
    /// admin tokens, limits, the device roots and revocation lists. The
    /// listen address and the state and log folders need a restart. A machine
    /// that is now blocked is cut off.
    pub fn reload(&self, cfg: Config, tls: Arc<rustls::ServerConfig>) {
        let blocked = cfg.blocked_machines.clone();
        self.inner
            .callers
            .set_rate(cfg.caller_rate.per_second, cfg.caller_rate.burst);
        *self.inner.cfg.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(cfg);
        *self.inner.tls.write().unwrap_or_else(|p| p.into_inner()) =
            Some(tokio_rustls::TlsAcceptor::from(tls));
        let cut: Vec<Cut> = {
            let st = self.st();
            let mut v: Vec<Cut> = st
                .machines
                .iter()
                .filter(|(name, _)| blocked.contains(name))
                .filter_map(|(_, m)| m.conn.as_ref().map(|c| c.cut.clone()))
                .collect();
            v.extend(
                st.sessions
                    .values()
                    .filter(|s| blocked.contains(&s.machine))
                    .map(|s| s.cut.clone()),
            );
            v
        };
        for c in cut {
            c.cut("blocked");
        }
        self.inner.audit.event(
            "config_reloaded",
            [("blocked_machines", json!(blocked.len()))],
        );
        tracing::info!("configuration reloaded");
    }

    /// Serves machines and callers on `listener` until `shutdown` is cancelled.
    pub async fn serve(
        &self,
        listener: TcpListener,
        tls: Arc<rustls::ServerConfig>,
        shutdown: CancellationToken,
    ) -> std::io::Result<()> {
        *self.inner.tls.write().unwrap_or_else(|p| p.into_inner()) =
            Some(tokio_rustls::TlsAcceptor::from(tls));
        let flush = {
            let relay = self.clone();
            let shutdown = shutdown.clone();
            let every = self.inner.timing.flush_every;
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(every) => relay.flush().await,
                    }
                }
            })
        };
        loop {
            let (tcp, remote) = tokio::select! {
                _ = shutdown.cancelled() => break,
                a = listener.accept() => match a {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            let _ = tcp.set_nodelay(true);
            // Notice peers that vanish (a laptop that sleeps mid-session).
            let ka = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10));
            let _ = socket2::SockRef::from(&tcp).set_tcp_keepalive(&ka);
            let Some(acceptor) = self
                .inner
                .tls
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
            else {
                continue;
            };
            let relay = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp))
                    .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::debug!(%remote, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
                let which = relay.config().machine_name;
                let machine = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| tls::machine_name(c, which));
                http::serve_connection(relay, tls, http::Peer { remote, machine }, shutdown).await;
            });
        }
        // Machines reconnect to the next relay process; sessions end with it.
        self.drop_everything();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !self.st().sessions.is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        flush.abort();
        self.flush().await;
        Ok(())
    }

    fn drop_everything(&self) {
        let (conns, sessions) = {
            let st = self.st();
            let conns: Vec<Cut> = st
                .machines
                .values()
                .filter_map(|m| m.conn.as_ref().map(|c| c.cut.clone()))
                .collect();
            let sessions: Vec<Cut> = st.sessions.values().map(|s| s.cut.clone()).collect();
            (conns, sessions)
        };
        for c in conns {
            c.cut("relay stopping");
        }
        for s in sessions {
            s.cut("relay_stopping");
        }
        self.st().pending.clear();
    }

    /// Writes what is behind: machines.json, and a stop not yet recorded.
    async fn flush(&self) {
        let relay = self.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _w = relay
                .inner
                .writing
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if relay.inner.stop_unsaved.load(Ordering::SeqCst) {
                let stop = relay.st().stop.clone();
                if stop.stopped {
                    match relay.inner.store.save_stop(&stop) {
                        Ok(()) => {
                            relay.inner.stop_unsaved.store(false, Ordering::SeqCst);
                            relay.inner.audit.event("org_stop_saved", []);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "still cannot record the org-wide stop")
                        }
                    }
                } else {
                    relay.inner.stop_unsaved.store(false, Ordering::SeqCst);
                }
            }
            let seen: BTreeMap<String, Seen> = {
                let mut st = relay.st();
                let now = unix(SystemTime::now());
                for m in st.machines.values_mut() {
                    if m.conn.is_some() {
                        m.seen.last_seen = now;
                    }
                }
                st.machines
                    .iter()
                    .map(|(k, m)| (k.clone(), m.seen))
                    .collect()
            };
            relay.inner.seen_dirty.store(false, Ordering::SeqCst);
            if let Err(e) = relay.inner.store.save_seen(&seen) {
                relay.inner.seen_dirty.store(true, Ordering::SeqCst);
                tracing::warn!(error = %e, "could not save machines.json");
            }
            for (kind, n) in relay.inner.refusals.take_suppressed() {
                relay.inner.audit.event(
                    "refusals_not_logged",
                    [("kind", json!(kind)), ("count", json!(n))],
                );
            }
        })
        .await;
    }

    /// Every machine the relay has seen, online ones with their connection.
    pub fn machines(&self) -> Vec<MachineInfo> {
        let st = self.st();
        let mut sessions: HashMap<&str, usize> = HashMap::new();
        for s in st.sessions.values() {
            *sessions.entry(s.machine.as_str()).or_default() += 1;
        }
        let now = SystemTime::now();
        st.machines
            .iter()
            .map(|(name, m)| MachineInfo {
                machine: name.clone(),
                online: m.conn.is_some(),
                connected_since: m.conn.as_ref().map(|c| c.since),
                first_seen: from_unix(m.seen.first_seen),
                last_seen: if m.conn.is_some() {
                    now
                } else {
                    from_unix(m.seen.last_seen)
                },
                sessions: sessions.get(name.as_str()).copied().unwrap_or(0),
            })
            .collect()
    }

    /// The org-wide stop as it is now.
    pub fn stop_state(&self) -> Stop {
        self.st().stop.clone()
    }

    /// Presses the org-wide stop: every session ends now, every machine is
    /// told, and no caller gets through until [`Relay::release`]. Pressing it
    /// again while it is on keeps the first record.
    pub fn stop(&self, by: &str, reason: &str) -> Stopped {
        let (stop, sessions, conns, fresh) = {
            let mut st = self.st();
            let fresh = !st.stop.stopped;
            if fresh {
                st.stop = Stop {
                    stopped: true,
                    by: by.to_string(),
                    reason: reason.to_string(),
                    at: rfc3339(SystemTime::now()),
                };
            }
            st.pending.clear();
            let sessions: Vec<Cut> = st.sessions.values().map(|s| s.cut.clone()).collect();
            let conns: Vec<(mpsc::Sender<Control>, Cut)> = st
                .machines
                .values()
                .filter_map(|m| m.conn.as_ref().map(|c| (c.tx.clone(), c.cut.clone())))
                .collect();
            (st.stop.clone(), sessions, conns, fresh)
        };
        for s in &sessions {
            s.cut("org_stop");
        }
        for (tx, cut) in conns {
            // A machine that cannot take the message is cut off; it hears
            // about the stop in the hello when it reconnects.
            if tx.try_send(Control::Stop).is_err() {
                cut.cut("could not deliver the stop");
            }
        }
        if fresh {
            self.inner.audit.event(
                "org_stop",
                [
                    ("by", json!(by)),
                    ("reason", json!(reason)),
                    ("sessions_dropped", json!(sessions.len())),
                ],
            );
            tracing::warn!(by, reason, "org-wide stop pressed");
        }
        let saved = {
            let _w = self.inner.writing.lock().unwrap_or_else(|p| p.into_inner());
            if fresh || self.inner.stop_unsaved.load(Ordering::SeqCst) {
                match self.inner.store.save_stop(&stop) {
                    Ok(()) => {
                        self.inner.stop_unsaved.store(false, Ordering::SeqCst);
                        true
                    }
                    Err(e) => {
                        self.inner.stop_unsaved.store(true, Ordering::SeqCst);
                        tracing::error!(error = %e, "could not record the org-wide stop: a restart would lose it; retrying");
                        self.inner
                            .audit
                            .event("org_stop_not_saved", [("error", json!(e.to_string()))]);
                        false
                    }
                }
            } else {
                true
            }
        };
        Stopped { stop, saved }
    }

    /// Releases the org-wide stop. It is recorded first: if that fails the
    /// stop stays on.
    pub fn release(&self, by: &str, reason: &str) -> Result<Stop, String> {
        let next = Stop {
            stopped: false,
            by: by.to_string(),
            reason: reason.to_string(),
            at: rfc3339(SystemTime::now()),
        };
        let conns = {
            let _w = self.inner.writing.lock().unwrap_or_else(|p| p.into_inner());
            let mut st = self.st();
            if !st.stop.stopped {
                return Ok(st.stop.clone());
            }
            self.inner
                .store
                .save_stop(&next)
                .map_err(|e| format!("could not record the release: {e}"))?;
            self.inner.stop_unsaved.store(false, Ordering::SeqCst);
            st.stop = next.clone();
            st.machines
                .values()
                .filter_map(|m| m.conn.as_ref().map(|c| (c.tx.clone(), c.cut.clone())))
                .collect::<Vec<_>>()
        };
        for (tx, cut) in conns {
            if tx.try_send(Control::Release).is_err() {
                cut.cut("could not deliver the release");
            }
        }
        self.inner.audit.event(
            "org_release",
            [("by", json!(by)), ("reason", json!(reason))],
        );
        tracing::warn!(by, reason, "org-wide stop released");
        Ok(next)
    }

    // ---- machines ----

    /// Registers a machine's control connection. Returns its id, the queue of
    /// messages for it, its cut, and whether the stop is on.
    fn machine_connected(
        &self,
        machine: &str,
        remote: SocketAddr,
    ) -> (u64, mpsc::Receiver<Control>, Cut, bool) {
        let (tx, rx) = mpsc::channel(256);
        let cut = Cut::default();
        let (id, stopped, replaced) = {
            let mut st = self.st();
            st.next_id += 1;
            let id = st.next_id;
            let stopped = st.stop.stopped;
            let now = SystemTime::now();
            let m = st.machines.entry(machine.to_string()).or_default();
            if m.seen.first_seen == 0 {
                m.seen.first_seen = unix(now);
            }
            m.seen.last_seen = unix(now);
            let replaced = m.conn.replace(Conn {
                id,
                tx,
                cut: cut.clone(),
                since: now,
            });
            (id, stopped, replaced)
        };
        if let Some(old) = replaced {
            old.cut.cut("replaced");
            self.inner.audit.event(
                "machine_replaced",
                [
                    ("machine", json!(machine)),
                    ("remote", json!(remote.to_string())),
                ],
            );
        }
        self.inner.audit.event(
            "machine_online",
            [
                ("machine", json!(machine)),
                ("remote", json!(remote.to_string())),
            ],
        );
        self.inner.seen_dirty.store(true, Ordering::SeqCst);
        (id, rx, cut, stopped)
    }

    fn machine_seen(&self, machine: &str) {
        if let Some(m) = self.st().machines.get_mut(machine) {
            m.seen.last_seen = unix(SystemTime::now());
        }
    }

    /// The control connection `id` of `machine` ended. If it was the current
    /// one, the machine is offline and its sessions are cut: their streams
    /// went with the machine's network.
    fn machine_disconnected(&self, machine: &str, id: u64, why: &str) {
        let (since, sessions) = {
            let mut st = self.st();
            let Some(m) = st.machines.get_mut(machine) else {
                return;
            };
            if m.conn.as_ref().map(|c| c.id) != Some(id) {
                return; // replaced by a newer connection
            }
            let c = m.conn.take().expect("checked");
            m.seen.last_seen = unix(SystemTime::now());
            let sessions: Vec<Cut> = st
                .sessions
                .values()
                .filter(|s| s.machine == machine)
                .map(|s| s.cut.clone())
                .collect();
            (c.since, sessions)
        };
        for s in sessions {
            s.cut("machine_offline");
        }
        self.inner.audit.event(
            "machine_offline",
            [
                ("machine", json!(machine)),
                (
                    "seconds",
                    json!(since.elapsed().unwrap_or_default().as_secs()),
                ),
                ("reason", json!(why)),
            ],
        );
        self.inner.seen_dirty.store(true, Ordering::SeqCst);
    }

    // ---- callers ----

    /// Asks `machine` for a stream for a caller. Holds a place under the
    /// machine's limit until the returned slot is dropped.
    async fn open_stream(&self, machine: &str) -> Result<(Stream, StreamSlot), Refusal> {
        let max = self.config().max_streams_per_machine;
        let (rx, slot, _pending) = {
            let mut st = self.st();
            if st.stop.stopped {
                return Err(Refusal::Stopped);
            }
            let Some(m) = st.machines.get_mut(machine) else {
                return Err(Refusal::Offline);
            };
            let Some(conn) = m.conn.as_ref() else {
                return Err(Refusal::Offline);
            };
            if m.streams >= max {
                return Err(Refusal::Busy);
            }
            let id = new_stream_id();
            if conn
                .tx
                .try_send(Control::Open { stream: id.clone() })
                .is_err()
            {
                return Err(Refusal::Busy);
            }
            m.streams += 1;
            let (tx, rx) = oneshot::channel();
            st.pending.insert(
                id.clone(),
                Pending {
                    machine: machine.to_string(),
                    tx,
                },
            );
            (
                rx,
                StreamSlot {
                    relay: self.clone(),
                    machine: machine.to_string(),
                },
                // Forgets the stream id however this call ends, the caller
                // giving up included.
                PendingGuard {
                    relay: self.clone(),
                    id,
                },
            )
        };
        match tokio::time::timeout(self.inner.timing.stream_timeout, rx).await {
            Ok(Ok(s)) => Ok((s, slot)),
            Ok(Err(_)) if self.st().stop.stopped => Err(Refusal::Stopped),
            _ => Err(Refusal::Timeout),
        }
    }

    /// A machine opened the stream `id`. Only the machine it was asked of
    /// can take it.
    fn take_pending(&self, machine: &str, id: &str) -> Option<oneshot::Sender<Stream>> {
        let mut st = self.st();
        match st.pending.get(id) {
            Some(p) if p.machine == machine => st.pending.remove(id).map(|p| p.tx),
            _ => None,
        }
    }

    /// Registers a caller's session; `None` while the stop is on or the
    /// machine is gone.
    fn session_started(&self, machine: &str) -> Option<(u64, Cut)> {
        let mut st = self.st();
        if st.stop.stopped || st.machines.get(machine).is_none_or(|m| m.conn.is_none()) {
            return None;
        }
        st.next_id += 1;
        let id = st.next_id;
        let cut = Cut::default();
        st.sessions.insert(
            id,
            Session {
                machine: machine.to_string(),
                cut: cut.clone(),
            },
        );
        Some((id, cut))
    }

    fn session_ended(&self, id: u64) {
        self.st().sessions.remove(&id);
    }

    /// Whether `machine` is blocked in the configuration in force.
    fn blocked(&self, machine: &str) -> bool {
        self.config().blocked_machines.iter().any(|b| b == machine)
    }

    /// The admin token named by a presented bearer token.
    fn admin(&self, presented: &str) -> Option<String> {
        if presented.is_empty() {
            return None;
        }
        let want = config::hash_token(presented);
        let mut found = None;
        for t in &self.config().admin_tokens {
            if constant_time_eq(t.hash.as_bytes(), want.as_bytes()) {
                found = Some(t.name.clone());
            }
        }
        found
    }

    fn machines_json(&self) -> Value {
        let list: Vec<Value> = self
            .machines()
            .into_iter()
            .map(|m| {
                json!({
                    "machine": m.machine,
                    "online": m.online,
                    "connected_since": m.connected_since.map(rfc3339),
                    "first_seen": rfc3339(m.first_seen),
                    "last_seen": rfc3339(m.last_seen),
                    "sessions": m.sessions,
                })
            })
            .collect();
        json!({ "stop": self.stop_state(), "machines": list })
    }
}

/// Why a caller did not get through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Stopped,
    Offline,
    Busy,
    Timeout,
}

/// A place under a machine's stream limit.
struct StreamSlot {
    relay: Relay,
    machine: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        if let Some(m) = self.relay.st().machines.get_mut(&self.machine) {
            m.streams = m.streams.saturating_sub(1);
        }
    }
}

/// Removes a stream id from the waiting list when the wait ends.
struct PendingGuard {
    relay: Relay,
    id: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.relay.st().pending.remove(&self.id);
    }
}

fn new_stream_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

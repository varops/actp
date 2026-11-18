//! The actp relay (docs/relay.md): one server, hosted by the client, that
//! machines dial out to and callers connect through.
//!
//! - Machines log in with the org's device certificate over mutual TLS. The
//!   name in the certificate is the machine's address; the relay never
//!   assigns one.
//! - A caller with a caller certificate opens a tunnel to a machine, and
//!   runs TLS through it straight to the machine's device certificate. The
//!   relay joins the tunnel to a stream the machine opens, and carries bytes
//!   it cannot read or change. The machine decides who may do what; the
//!   relay only routes.
//! - The relay knows who is online and when each machine was last seen.
//! - The org-wide stop drops every session and refuses new ones until it is
//!   released; machines are told, and end their sessions themselves too.
//! - The relay's half of the audit: who connected to which machine, when and
//!   for how long, and every stop and release with who and why.
//! - Who may ask it: admin tokens, and operators, callers whose
//!   certificates the configuration gives a role (`operators`). Any other
//!   caller certificate opens tunnels and nothing else.

pub mod audit;
pub mod config;
mod http;
pub mod issuer;
mod limit;
pub mod state;
pub mod tls;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actp_proto::relay::Control;
use rustls_pki_types::CertificateDer;
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
    /// How long one write to a machine's control connection may take (10 s).
    pub send_timeout: Duration,
    /// How often machines.json and an unsaved stop are written (10 s).
    pub flush_every: Duration,
    /// For tests: cut idle tunnels after this instead of the configured
    /// `tunnel_idle_seconds`, which cannot be set below a minute.
    pub tunnel_idle: Option<Duration>,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            ping_every: Duration::from_secs(15),
            dead_after: Duration::from_secs(45),
            stream_timeout: Duration::from_secs(10),
            send_timeout: Duration::from_secs(10),
            flush_every: Duration::from_secs(10),
            tunnel_idle: None,
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

    pub(crate) fn is_cut(&self) -> bool {
        self.token.is_cancelled()
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
    tls: RwLock<Option<tls::Setup>>,
    timing: Timing,
    audit: Audit,
    store: Store,
    st: Mutex<State>,
    /// machines.json is behind the state in memory.
    seen_dirty: AtomicBool,
    /// The stop is on but stop.json does not say so yet.
    stop_unsaved: AtomicBool,
    /// One writer for the state files at a time; taken before `st`.
    writing: Mutex<()>,
    /// When machines.json was last written on the timer.
    seen_written: Mutex<std::time::Instant>,
    callers: RateLimiter,
    /// Taken while the stop is pressed or released and recorded, so the
    /// audit has them in the order they took effect. Taken after `writing`,
    /// never with it held the other way round.
    stop_order: Mutex<()>,
    /// Audit queries running (each reads the audit files back).
    audit_queries: Arc<tokio::sync::Semaphore>,
    /// The issuer pass-through, when configured.
    issuer: RwLock<Option<Arc<issuer::Issuer>>>,
    /// Its limits, kept across reloads.
    issuer_limits: Arc<issuer::Limits>,
    refusals: Throttle,
    /// Connections held, before and after the TLS handshake.
    connections: Arc<tokio::sync::Semaphore>,
    per_ip: Mutex<HashMap<std::net::IpAddr, usize>>,
    /// Device connections held per machine, before any becomes a stream.
    per_machine: Arc<Mutex<HashMap<String, usize>>>,
    /// When each machine's last `machine_key_refused` was written, and how
    /// many were left out since.
    key_refusals: Mutex<HashMap<String, (Option<std::time::Instant>, u64)>>,
    /// Open continuity nonces: nonce → (machine, when it was given).
    rekey_nonces: Mutex<HashMap<String, (String, std::time::Instant)>>,
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
    /// The device certificate chain the machine connected with.
    chain: Vec<CertificateDer<'static>>,
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
    /// The caller, by the name in its certificate, and that certificate's
    /// chain, checked again with the machines'.
    caller: String,
    caller_chain: Vec<CertificateDer<'static>>,
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
    /// The key the name is pinned to (SHA-256 of the public key, hex), and
    /// when that certificate expires, when known.
    pub key: Option<String>,
    pub key_until: Option<SystemTime>,
}

/// Who pressed or released the org-wide stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// The admin token's name, or the operator's caller name.
    pub name: String,
    pub kind: ActorKind,
    /// The operator's caller certificate (SHA-256 fingerprint).
    pub certificate: Option<String>,
    /// The person the operator acts for, as it said.
    pub on_behalf_of: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    Admin,
    Operator,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::Admin => "admin",
            ActorKind::Operator => "operator",
        }
    }
}

impl Actor {
    /// An admin token, by its name.
    pub fn admin(name: &str) -> Actor {
        Actor {
            name: name.to_string(),
            kind: ActorKind::Admin,
            certificate: None,
            on_behalf_of: None,
        }
    }

    fn fields(&self) -> [(&'static str, Value); 4] {
        [
            ("by", json!(self.name)),
            ("by_kind", json!(self.kind.as_str())),
            ("caller_certificate", json!(self.certificate)),
            ("on_behalf_of", json!(self.on_behalf_of)),
        ]
    }

    fn stop(&self, stopped: bool, reason: &str) -> Stop {
        Stop {
            stopped,
            by: self.name.clone(),
            by_kind: self.kind.as_str().to_string(),
            on_behalf_of: self.on_behalf_of.clone(),
            reason: reason.to_string(),
            at: rfc3339(SystemTime::now()),
        }
    }
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
        warn_renewal_window(&cfg);
        let store = Store::open(&cfg.state_dir)?;
        let audit = Audit::open(&cfg.log_dir, cfg.audit_max_bytes())?;
        let stop = store.load_stop();
        let machines = store
            .load_seen()?
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
        let issuer_limits = issuer::Limits::new(
            cfg.issuer
                .as_ref()
                .map_or(config::Rate::default(), |i| i.rate),
        );
        let issuer = match &cfg.issuer {
            Some(i) => Some(Arc::new(issuer::Issuer::from_config(
                i,
                issuer_limits.clone(),
            )?)),
            None => None,
        };
        let max_connections = cfg.max_connections;
        // So the audit shows who holds a role from the start, not only from
        // the first reload.
        audit.event("relay_started", [("operators", operators_json(&cfg))]);
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
                seen_written: Mutex::new(std::time::Instant::now()),
                callers,
                audit_queries: Arc::new(tokio::sync::Semaphore::new(2)),
                stop_order: Mutex::new(()),
                issuer: RwLock::new(issuer),
                issuer_limits,
                refusals: Throttle::new(20, Duration::from_secs(60)),
                connections: Arc::new(tokio::sync::Semaphore::new(max_connections)),
                per_ip: Mutex::new(HashMap::new()),
                per_machine: Arc::default(),
                key_refusals: Mutex::default(),
                rekey_nonces: Mutex::default(),
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

    /// The issuer pass-through in force, if one is configured.
    pub(crate) fn issuer(&self) -> Option<Arc<issuer::Issuer>> {
        self.inner
            .issuer
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
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
    pub fn reload(&self, cfg: Config, tls: tls::Setup) {
        warn_renewal_window(&cfg);
        let blocked = cfg.blocked_machines.len();
        let blocked_callers = cfg.blocked_callers.len();
        // Who holds a role at the relay, so the audit shows when someone
        // gained the right to stop the org.
        let operators = operators_json(&cfg);
        self.inner
            .callers
            .set_rate(cfg.caller_rate.per_second, cfg.caller_rate.burst);
        // A new issuer section takes effect only if it can be used; a broken
        // one (a missing CA file, an unset variable) keeps the old one.
        let limits = self.inner.issuer_limits.clone();
        match cfg
            .issuer
            .as_ref()
            .map(|i| (i.rate, issuer::Issuer::from_config(i, limits.clone())))
        {
            None => *self.inner.issuer.write().unwrap_or_else(|p| p.into_inner()) = None,
            Some((rate, Ok(i))) => {
                limits.set_rate(rate);
                *self.inner.issuer.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(i))
            }
            Some((_, Err(e))) => {
                tracing::error!(error = %e, "the issuer section was not reloaded");
                self.inner
                    .audit
                    .event("issuer_reload_refused", [("error", json!(e.to_string()))]);
            }
        }
        *self.inner.cfg.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(cfg);
        *self.inner.tls.write().unwrap_or_else(|p| p.into_inner()) = Some(tls);
        self.inner.audit.event(
            "config_reloaded",
            [
                ("blocked_machines", json!(blocked)),
                ("blocked_callers", json!(blocked_callers)),
                ("operators", json!(operators)),
            ],
        );
        tracing::info!("configuration reloaded");
        // Machines now blocked, or with certificates no longer valid, are cut
        // off; off the async workers, as checking can take a while.
        let relay = self.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn_blocking(move || relay.recheck_machines());
            }
            Err(_) => {
                relay.recheck_machines();
            }
        }
    }

    /// Whether a device certificate chain is valid now, by the TLS setup in
    /// force, and not also a caller certificate.
    pub(crate) fn chain_valid(&self, chain: &[CertificateDer<'static>]) -> bool {
        self.kind(chain) == tls::Kind::Device
    }

    /// Whether a caller certificate chain is valid now, and not also a
    /// device certificate.
    pub(crate) fn caller_chain_valid(&self, chain: &[CertificateDer<'static>]) -> bool {
        self.kind(chain) == tls::Kind::Caller
    }

    /// What a client certificate chain is now, by the TLS setup in force.
    pub(crate) fn kind(&self, chain: &[CertificateDer<'static>]) -> tls::Kind {
        self.inner
            .tls
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map_or(tls::Kind::Invalid, |t| t.kind(chain))
    }

    /// Whether `caller` is blocked in the configuration in force.
    pub(crate) fn caller_blocked(&self, caller: &str) -> bool {
        self.config().blocked_callers.iter().any(|b| b == caller)
    }

    /// Cuts off every online machine that is blocked now, or whose device
    /// certificate is no longer valid (expired, revoked, new roots), with its
    /// sessions, and every session whose caller is blocked now or whose
    /// caller certificate is no longer valid. Returns how many machines.
    fn recheck_machines(&self) -> usize {
        let sessions: Vec<(Cut, String, Vec<CertificateDer<'static>>)> = self
            .st()
            .sessions
            .values()
            .map(|s| (s.cut.clone(), s.caller.clone(), s.caller_chain.clone()))
            .collect();
        for (cut, caller, chain) in sessions {
            if self.caller_blocked(&caller) {
                cut.cut("caller_blocked");
            } else if !self.caller_chain_valid(&chain) {
                cut.cut("caller_certificate_invalid");
            }
        }
        // Verify outside the state lock: checking thousands of chains
        // against a long revocation list takes a while.
        let cfg = self.config();
        let online: Vec<(String, u64, Vec<CertificateDer<'static>>)> = {
            let st = self.st();
            st.machines
                .iter()
                .filter_map(|(n, m)| m.conn.as_ref().map(|c| (n.clone(), c.id, c.chain.clone())))
                .collect()
        };
        let failing: Vec<(String, u64, &'static str)> = online
            .into_iter()
            .filter_map(|(name, id, chain)| {
                if cfg.blocked_machines.contains(&name) {
                    Some((name, id, "blocked"))
                } else if !self.chain_valid(&chain) {
                    Some((name, id, "certificate_invalid"))
                } else if !chain.first().is_some_and(|l| self.key_matches(&name, l)) {
                    Some((name, id, "key_changed"))
                } else {
                    None
                }
            })
            .collect();
        let mut cut: Vec<(Cut, &'static str)> = Vec::new();
        let mut gone: Vec<(String, SystemTime, &'static str)> = Vec::new();
        {
            let mut st = self.st();
            for (name, id, why) in &failing {
                let Some(m) = st.machines.get_mut(name) else {
                    continue;
                };
                if m.conn.as_ref().map(|c| c.id) != Some(*id) {
                    continue; // reconnected meanwhile, and checked then
                }
                // Out of the table at once: no caller is routed to it while
                // its connection winds down.
                let c = m.conn.take().expect("checked");
                m.seen.last_seen = unix(SystemTime::now());
                cut.push((c.cut, why));
                gone.push((name.clone(), c.since, why));
            }
            for (name, _, why) in &gone {
                cut.extend(
                    st.sessions
                        .values()
                        .filter(|s| &s.machine == name)
                        .map(|s| (s.cut.clone(), *why)),
                );
            }
        }
        for (c, why) in cut {
            c.cut(why);
        }
        for (name, since, why) in &gone {
            self.inner.audit.event(
                "machine_offline",
                [
                    ("machine", json!(name)),
                    (
                        "seconds",
                        json!(since.elapsed().unwrap_or_default().as_secs()),
                    ),
                    ("reason", json!(why)),
                ],
            );
        }
        if !gone.is_empty() {
            self.inner.seen_dirty.store(true, Ordering::SeqCst);
        }
        gone.len()
    }

    /// Serves machines and callers on `listener` until `shutdown` is cancelled.
    pub async fn serve(
        &self,
        listener: TcpListener,
        tls: tls::Setup,
        shutdown: CancellationToken,
    ) -> std::io::Result<()> {
        *self.inner.tls.write().unwrap_or_else(|p| p.into_inner()) = Some(tls);
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
            // Caps on connections held, all told and per address, before any
            // work is done for them.
            let Some(held) = self.hold_connection(remote.ip()) else {
                drop(tcp);
                self.refusal(
                    "connection_refused",
                    [("remote", json!(limit::ip_key(remote.ip()).to_string()))],
                );
                continue;
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
                .as_ref()
                .map(|t| tokio_rustls::TlsAcceptor::from(t.config.clone()))
            else {
                continue;
            };
            let relay = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let tls = match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp))
                    .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::debug!(%remote, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
                let cfg = relay.config();
                let chain: Vec<CertificateDer<'static>> = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                    .unwrap_or_default();
                // Which kind of certificate this is, by the strict
                // verifiers. A certificate of one kind is refused, with a
                // reason, on the other kind's routes; one valid as both
                // (nested hierarchies) on all of them.
                let refused = |why: &str| Some(Err(why.to_string()));
                let (machine, caller) = match (relay.kind(&chain), chain.first()) {
                    (tls::Kind::Device, Some(c)) => (
                        Some(tls::machine_name(c, cfg.machine_name)),
                        refused("a device certificate is not a caller certificate"),
                    ),
                    (tls::Kind::Caller, Some(c)) => (
                        refused("a caller certificate is not a device certificate"),
                        Some(tls::machine_name(c, cfg.caller_name)),
                    ),
                    (tls::Kind::Both, _) => {
                        let why = "the certificate is valid as both a device and a caller certificate: device_ca and caller_ca must be separate hierarchies";
                        tracing::warn!(%remote, "{why}");
                        (refused(why), refused(why))
                    }
                    (tls::Kind::Invalid, _) => (
                        refused("the certificate is not valid now"),
                        refused("the certificate is not valid now"),
                    ),
                    _ => (None, None),
                };
                // A machine that proved itself, with the key its name is
                // pinned to, does not count against the limits meant for
                // anyone on the network, but against its own. Everyone
                // else's connection keeps its place, upgrades included; a
                // certificate with another key counts as anyone's, and its
                // requests are refused.
                // A blocked name is never pinned or renewed: its holder may
                // be the one it was blocked against.
                let pinned = |name: &str| {
                    !relay.blocked(name)
                        && chain
                            .first()
                            .is_some_and(|l| relay.check_key(name, l).is_ok())
                };
                let (held, _machine_slot) = match &machine {
                    Some(Ok(name)) if pinned(name) => match relay.hold_machine_connection(name) {
                        Some(slot) => {
                            drop(held);
                            (None, Some(slot))
                        }
                        None => {
                            relay.refusal(
                                "connection_refused",
                                [
                                    ("machine", json!(name)),
                                    ("remote", json!(limit::ip_key(remote.ip()).to_string())),
                                ],
                            );
                            return;
                        }
                    },
                    _ => (Some(Arc::new(held)), None),
                };
                http::serve_connection(
                    relay,
                    tls,
                    http::Peer {
                        remote,
                        machine,
                        caller,
                        chain,
                        held,
                    },
                    shutdown,
                )
                .await;
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
    /// A place among `machine`'s connections, or `None` when it holds
    /// `max_connections_per_machine` already. Freed when dropped.
    fn hold_machine_connection(&self, machine: &str) -> Option<MachineSlot> {
        let max = self.config().max_connections_per_machine;
        let mut m = self
            .inner
            .per_machine
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let n = m.entry(machine.to_string()).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(MachineSlot {
            map: self.inner.per_machine.clone(),
            machine: machine.to_string(),
        })
    }

    /// A place among the connections the relay holds, or `None` when the
    /// relay, or this address, is at its limit.
    fn hold_connection(&self, ip: std::net::IpAddr) -> Option<Held> {
        let permit = self.inner.connections.clone().try_acquire_owned().ok()?;
        let max = self.config().max_connections_per_ip;
        let ip = limit::ip_key(ip);
        let mut m = self.inner.per_ip.lock().unwrap_or_else(|p| p.into_inner());
        let n = m.entry(ip).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Held {
            relay: self.clone(),
            ip,
            _permit: permit,
        })
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
        // Certificates expire and revocation lists go stale while machines
        // stay connected.
        let relay = self.clone();
        let _ = tokio::task::spawn_blocking(move || relay.recheck_machines()).await;
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
                            relay.inner.audit.kept("org_stop_saved", []);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "still cannot record the org-wide stop")
                        }
                    }
                } else {
                    relay.inner.stop_unsaved.store(false, Ordering::SeqCst);
                }
            }
            let due = relay.inner.seen_dirty.swap(false, Ordering::SeqCst) || {
                let mut last = relay
                    .inner
                    .seen_written
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if last.elapsed() >= Duration::from_secs(60) {
                    *last = std::time::Instant::now();
                    true
                } else {
                    false
                }
            };
            let seen: Option<BTreeMap<String, Seen>> = due.then(|| {
                let mut st = relay.st();
                let now = unix(SystemTime::now());
                for m in st.machines.values_mut() {
                    if m.conn.is_some() {
                        m.seen.last_seen = now;
                    }
                }
                st.machines
                    .iter()
                    .map(|(k, m)| (k.clone(), m.seen.clone()))
                    .collect()
            });
            if let Some(seen) = seen {
                if let Err(e) = relay.inner.store.save_seen(&seen) {
                    relay.inner.seen_dirty.store(true, Ordering::SeqCst);
                    tracing::warn!(error = %e, "could not save machines.json");
                }
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
                key: m.seen.key.clone(),
                key_until: (m.seen.key_until != 0).then(|| from_unix(m.seen.key_until)),
            })
            .collect()
    }

    /// One page of the relay's audit, newest first ([`audit::query`]): the
    /// sessions, stops and machine events, without addresses. `None` while
    /// two queries are already running.
    pub async fn audit_page(&self, q: audit::Query) -> Option<std::io::Result<audit::Page>> {
        let permit = self.inner.audit_queries.clone().try_acquire_owned().ok()?;
        let files = self.inner.audit.snapshot();
        let r = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            audit::query(files, &q)
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
        Some(r)
    }

    /// The org-wide stop as it is now.
    pub fn stop_state(&self) -> Stop {
        self.st().stop.clone()
    }

    /// Presses the org-wide stop: every session ends now, every machine is
    /// told, and no caller gets through until [`Relay::release`]. Pressing it
    /// again while it is on keeps the first record.
    pub fn stop(&self, by: &str, reason: &str) -> Stopped {
        self.stop_as(&Actor::admin(by), reason)
    }

    /// [`Relay::stop`], pressed by `who`.
    pub fn stop_as(&self, who: &Actor, reason: &str) -> Stopped {
        // Everything is cut before anything is written: a slow disk must not
        // delay the stop, nor hold the relay's state. `stop_order` (not the
        // state) keeps stops and releases in the audit in the order they
        // took effect.
        let _order = self
            .inner
            .stop_order
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (stop, sessions, conns, fresh) = {
            let mut st = self.st();
            let fresh = !st.stop.stopped;
            if fresh {
                st.stop = who.stop(true, reason);
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
        // Pressed again while on, the first record stays, and this press is
        // recorded too.
        let [a, b, c, d] = who.fields();
        self.inner.audit.kept(
            if fresh {
                "org_stop"
            } else {
                "org_stop_repeated"
            },
            [
                a,
                b,
                c,
                d,
                ("reason", json!(reason)),
                ("sessions_dropped", json!(sessions.len())),
            ],
        );
        drop(_order);
        if fresh {
            tracing::warn!(by = who.name, on_behalf_of = ?who.on_behalf_of, reason, "org-wide stop pressed");
        }
        let saved = {
            let _w = self.inner.writing.lock().unwrap_or_else(|p| p.into_inner());
            // What is saved is the stop as it is now, under the writer lock:
            // a release in between changes it only while holding that lock,
            // so file and memory agree.
            let now = self.st().stop.clone();
            if !now.stopped {
                true // released meanwhile, and the release was recorded
            } else if fresh || self.inner.stop_unsaved.load(Ordering::SeqCst) {
                match self.inner.store.save_stop(&now) {
                    Ok(()) => {
                        self.inner.stop_unsaved.store(false, Ordering::SeqCst);
                        true
                    }
                    Err(e) => {
                        self.inner.stop_unsaved.store(true, Ordering::SeqCst);
                        tracing::error!(error = %e, "could not record the org-wide stop: a restart would lose it; retrying");
                        self.inner
                            .audit
                            .kept("org_stop_not_saved", [("error", json!(e.to_string()))]);
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
        self.release_as(&Actor::admin(by), reason)
    }

    /// [`Relay::release`], by `who`.
    pub fn release_as(&self, who: &Actor, reason: &str) -> Result<Stop, String> {
        let next = who.stop(false, reason);
        let conns = {
            let _w = self.inner.writing.lock().unwrap_or_else(|p| p.into_inner());
            if !self.st().stop.stopped {
                return Ok(self.st().stop.clone());
            }
            // Recorded before it takes effect, without holding up the relay
            // while the disk writes. Only stop and release change the stop,
            // and both hold the writer lock.
            self.inner
                .store
                .save_stop(&next)
                .map_err(|e| format!("could not record the release: {e}"))?;
            self.inner.stop_unsaved.store(false, Ordering::SeqCst);
            // After the disk write, so a stop is never held up by it.
            let _order = self
                .inner
                .stop_order
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let conns = {
                let mut st = self.st();
                st.stop = next.clone();
                st.machines
                    .values()
                    .filter_map(|m| m.conn.as_ref().map(|c| (c.tx.clone(), c.cut.clone())))
                    .collect::<Vec<_>>()
            };
            let [a, b, c, d] = who.fields();
            self.inner
                .audit
                .kept("org_release", [a, b, c, d, ("reason", json!(reason))]);
            conns
        };
        for (tx, cut) in conns {
            if tx.try_send(Control::Release).is_err() {
                cut.cut("could not deliver the release");
            }
        }
        tracing::warn!(by = who.name, on_behalf_of = ?who.on_behalf_of, reason, "org-wide stop released");
        Ok(next)
    }

    // ---- machines ----

    /// Registers a machine's control connection. Returns its id, the queue of
    /// messages for it, its cut, and whether the stop is on.
    fn machine_connected(
        &self,
        machine: &str,
        remote: SocketAddr,
        chain: Vec<CertificateDer<'static>>,
    ) -> Option<(u64, mpsc::Receiver<Control>, Cut, bool)> {
        let (tx, rx) = mpsc::channel(256);
        let cut = Cut::default();
        let (id, stopped, replaced) = {
            let mut st = self.st();
            // Checked under the lock a reload takes to cut machines off, so a
            // machine blocked meanwhile cannot slip in.
            if self.blocked(machine) || !self.chain_valid(&chain) {
                return None;
            }
            st.next_id += 1;
            let id = st.next_id;
            let stopped = st.stop.stopped;
            let now = SystemTime::now();
            let m = st.machines.entry(machine.to_string()).or_default();
            if m.seen.first_seen == 0 {
                m.seen.first_seen = unix(now);
            }
            m.seen.last_seen = unix(now);
            let fingerprint = chain.first().map(fingerprint);
            let replaced = m.conn.replace(Conn {
                id,
                chain,
                tx,
                cut: cut.clone(),
                since: now,
            });
            (id, stopped, replaced.map(|r| (r, fingerprint)))
        };
        if let Some((old, new_cert)) = replaced {
            old.cut.cut("replaced");
            // Both certificates, so a second certificate carrying a live
            // machine's name stands out.
            self.inner.audit.event(
                "machine_replaced",
                [
                    ("machine", json!(machine)),
                    ("remote", json!(remote.to_string())),
                    ("old_certificate", json!(old.chain.first().map(fingerprint))),
                    ("new_certificate", json!(new_cert)),
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
        Some((id, rx, cut, stopped))
    }

    /// Whether `leaf` may speak for `machine`: the first certificate seen
    /// for a name pins its public key. Another key is taken only as a
    /// renewal: the pinned certificate's expiry is known and within its last
    /// `machine_key_renewal_days` (or past), and the new certificate is
    /// newer (issued later) and outlasts it. The machine's connection with
    /// the old key is then cut. Otherwise it is refused until an admin
    /// re-pins the name ([`Relay::repin`]); refusals are recorded as
    /// `machine_key_refused`, once a minute per machine.
    pub(crate) fn check_key(
        &self,
        machine: &str,
        leaf: &CertificateDer<'static>,
    ) -> Result<(), &'static str> {
        let Some(cert) = cert_key(leaf) else {
            return Err("certificate_unreadable");
        };
        let window = self
            .config()
            .machine_key_renewal_days
            .saturating_mul(86_400);
        let now = unix(SystemTime::now());
        let mut offline = None;
        let renewed = {
            let mut st = self.st();
            let m = st.machines.entry(machine.to_string()).or_default();
            let seen = &mut m.seen;
            match seen.key.clone() {
                None => {
                    seen.key = Some(cert.key.clone());
                    seen.key_since = cert.not_before;
                    seen.key_until = cert.not_after;
                    if seen.first_seen == 0 {
                        seen.first_seen = now;
                        seen.last_seen = now;
                    }
                    None
                }
                Some(pinned) if pinned == cert.key => {
                    if cert.not_after <= seen.key_until && seen.key_since != 0 {
                        return Ok(());
                    }
                    // A renewal with the same key, or the first certificate
                    // seen after an admin pinned the key by itself.
                    seen.key_until = seen.key_until.max(cert.not_after);
                    if seen.key_since == 0 {
                        seen.key_since = cert.not_before;
                    }
                    None
                }
                Some(pinned)
                    if window > 0
                        && seen.key_until != 0
                        && now.saturating_add(window) >= seen.key_until
                        && cert.not_before > seen.key_since
                        && cert.not_after > seen.key_until =>
                {
                    seen.key = Some(cert.key.clone());
                    seen.key_since = cert.not_before;
                    seen.key_until = cert.not_after;
                    offline = take_offline(&mut st, machine);
                    Some(pinned)
                }
                Some(pinned) => {
                    drop(st);
                    self.key_refused(machine, &pinned, &cert.key);
                    return Err("key_changed");
                }
            }
        };
        self.inner.seen_dirty.store(true, Ordering::SeqCst);
        if let Some(old) = renewed {
            self.inner.audit.event(
                "machine_key_renewed",
                [
                    ("machine", json!(machine)),
                    ("old_key", json!(old)),
                    ("new_key", json!(cert.key)),
                ],
            );
        }
        if let Some(o) = offline {
            self.went_offline(machine, o, "key_renewed");
        }
        Ok(())
    }

    /// Records a refused key: at once the first time, then once a minute
    /// per machine with how many were left out. Only a certificate the
    /// org's CA signed gets this far, so the names are bounded.
    fn key_refused(&self, machine: &str, pinned: &str, presented: &str) {
        let repeats = {
            let mut m = self
                .inner
                .key_refusals
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let e = m.entry(machine.to_string()).or_insert((None, 0));
            if e.0.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                e.1 += 1;
                return;
            }
            let repeats = e.1;
            *e = (Some(std::time::Instant::now()), 0);
            repeats
        };
        self.inner.audit.event(
            "machine_key_refused",
            [
                ("machine", json!(machine)),
                ("pinned_key", json!(pinned)),
                ("presented_key", json!(presented)),
                ("repeats", json!(repeats)),
            ],
        );
    }

    /// A continuity nonce for `machine`: good once, for
    /// [`actp_proto::relay::REKEY_NONCE_SECONDS`]. At most four open per
    /// machine, and 10 000 in all.
    pub(crate) fn rekey_challenge(&self, machine: &str) -> Result<String, &'static str> {
        let ttl = Duration::from_secs(actp_proto::relay::REKEY_NONCE_SECONDS);
        let mut m = self
            .inner
            .rekey_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        m.retain(|_, (_, at)| at.elapsed() < ttl);
        if m.len() >= 10_000 || m.values().filter(|(n, _)| n == machine).count() >= 4 {
            return Err("too_many_challenges");
        }
        let nonce = new_stream_id();
        m.insert(
            nonce.clone(),
            (machine.to_string(), std::time::Instant::now()),
        );
        Ok(nonce)
    }

    /// Key continuity: moves `machine`'s pin to the key of the certificate
    /// in `ask`, if the key the name is pinned to (`old_leaf`, presented on
    /// this connection) signed it over a fresh nonce of the relay's. The
    /// nonce is used up whatever the outcome. The new certificate must be a
    /// valid device certificate now, for the same name, with another key.
    /// Recorded as `machine_key_continued`, and the machine's connection on
    /// the old key is cut so it reconnects on the new one. Returns the new
    /// key; an error is a short reason.
    pub(crate) fn rekey(
        &self,
        machine: &str,
        old_leaf: &CertificateDer<'static>,
        ask: actp_proto::relay::RekeyRequest,
    ) -> Result<String, &'static str> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        // The nonce first: used up even if the rest fails.
        let fresh = {
            let mut m = self
                .inner
                .rekey_nonces
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            m.remove(&ask.nonce).is_some_and(|(n, at)| {
                n == machine
                    && at.elapsed() < Duration::from_secs(actp_proto::relay::REKEY_NONCE_SECONDS)
            })
        };
        if !fresh {
            return Err("rekey_nonce_unknown");
        }
        if ask.certificates.is_empty() || ask.certificates.len() > 8 {
            return Err("rekey_certificate_invalid");
        }
        let mut chain = Vec::with_capacity(ask.certificates.len());
        for c in &ask.certificates {
            let der = b64.decode(c).map_err(|_| "rekey_certificate_invalid")?;
            chain.push(CertificateDer::from(der));
        }
        if self.kind(&chain) != tls::Kind::Device {
            return Err("rekey_certificate_invalid");
        }
        let cfg = self.config();
        if tls::machine_name(&chain[0], cfg.machine_name).as_deref() != Ok(machine) {
            return Err("rekey_other_machine");
        }
        let (Some(old), Some(new)) = (cert_key(old_leaf), cert_key(&chain[0])) else {
            return Err("rekey_certificate_invalid");
        };
        if old.key == new.key {
            return Err("rekey_same_key");
        }
        let signature = b64
            .decode(&ask.signature)
            .map_err(|_| "rekey_signature_invalid")?;
        let message = actp_proto::relay::rekey_message(machine, &ask.nonce, chain[0].as_ref());
        if !actp_proto::relay::rekey_verify(old_leaf.as_ref(), ask.scheme, &message, &signature) {
            return Err("rekey_signature_invalid");
        }
        // Saved before it is answered: a relay that restarted on the old pin
        // would lock out a machine that has moved to its new key.
        let _w = self.inner.writing.lock().unwrap_or_else(|p| p.into_inner());
        // The move is saved from a copy first; the pin in force changes
        // only once it is on disk.
        let seen = {
            let st = self.st();
            if st.machines.get(machine).and_then(|m| m.seen.key.as_deref())
                != Some(old.key.as_str())
            {
                return Err("rekey_not_pinned");
            }
            let mut seen: BTreeMap<String, Seen> = st
                .machines
                .iter()
                .map(|(k, m)| (k.clone(), m.seen.clone()))
                .collect();
            let s = seen.get_mut(machine).expect("checked");
            s.key = Some(new.key.clone());
            s.key_since = new.not_before;
            s.key_until = new.not_after;
            seen
        };
        if let Err(e) = self.inner.store.save_seen(&seen) {
            tracing::error!(error = %e, machine, "cannot save a moved pin: keeping the old one");
            return Err("rekey_not_saved");
        }
        {
            let mut st = self.st();
            let m = st.machines.entry(machine.to_string()).or_default();
            // Re-pinned meanwhile: the admin's pin stands, and is saved now
            // over the one just written.
            if m.seen.key.as_deref() != Some(old.key.as_str()) {
                let seen: BTreeMap<String, Seen> = st
                    .machines
                    .iter()
                    .map(|(k, m)| (k.clone(), m.seen.clone()))
                    .collect();
                drop(st);
                if let Err(e) = self.inner.store.save_seen(&seen) {
                    tracing::error!(error = %e, "could not save machines.json");
                    self.inner.seen_dirty.store(true, Ordering::SeqCst);
                }
                return Err("rekey_not_pinned");
            }
            m.seen.key = Some(new.key.clone());
            m.seen.key_since = new.not_before;
            m.seen.key_until = new.not_after;
        }
        self.forget_nonces(machine);
        // The machine reconnects on its new key by itself; a connection
        // left on the old one is cut by the next recheck (`key_changed`).
        self.inner.audit.event(
            "machine_key_continued",
            [
                ("machine", json!(machine)),
                ("old_key", json!(old.key)),
                ("new_key", json!(new.key)),
            ],
        );
        Ok(new.key)
    }

    /// Forgets `machine`'s open continuity nonces (its pin moved).
    fn forget_nonces(&self, machine: &str) {
        self.inner
            .rekey_nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (n, _)| n != machine);
    }

    /// Re-pins `machine`: to `key` (the SHA-256 of the public key, as
    /// hex) when given, otherwise to the next certificate seen. The
    /// machine's current connection is cut. Without `key`, whoever presents
    /// a certificate first is pinned, the old key too if its holder
    /// reconnects first: revoke it beforehand, or pass `key`. Recorded with
    /// who and why;
    /// returns whether the name was pinned before.
    pub fn repin(&self, by: &str, machine: &str, key: Option<&str>, reason: &str) -> bool {
        let (had, offline) = {
            let mut st = self.st();
            let m = st.machines.entry(machine.to_string()).or_default();
            let had = m.seen.key.is_some();
            m.seen.key = key.map(str::to_string);
            m.seen.key_since = 0;
            m.seen.key_until = 0;
            (had, take_offline(&mut st, machine))
        };
        self.inner.seen_dirty.store(true, Ordering::SeqCst);
        self.forget_nonces(machine);
        self.inner.audit.event(
            "machine_repinned",
            [
                ("machine", json!(machine)),
                ("by", json!(by)),
                ("reason", json!(reason)),
                ("key", json!(key)),
                ("was_pinned", json!(had)),
            ],
        );
        if let Some(o) = offline {
            self.went_offline(machine, o, "repinned");
        }
        had
    }

    /// Cuts what [`take_offline`] took and records it.
    fn went_offline(
        &self,
        machine: &str,
        (cuts, since): (Vec<Cut>, SystemTime),
        why: &'static str,
    ) {
        for c in cuts {
            c.cut(why);
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
    }

    /// Whether `leaf`'s key is the one `machine` is pinned to, or the name
    /// is pinned to none.
    fn key_matches(&self, machine: &str, leaf: &CertificateDer<'_>) -> bool {
        let pinned = self
            .st()
            .machines
            .get(machine)
            .and_then(|m| m.seen.key.clone());
        match pinned {
            None => true,
            Some(p) => cert_key(leaf).is_some_and(|c| c.key == p),
        }
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
    async fn open_stream(
        &self,
        machine: &str,
        opened_by: actp_proto::relay::OpenedBy,
    ) -> Result<(Stream, StreamSlot), Refusal> {
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
            if self.blocked(machine) {
                return Err(Refusal::Offline);
            }
            if m.streams >= max {
                return Err(Refusal::Busy);
            }
            let id = new_stream_id();
            if conn
                .tx
                .try_send(Control::Open {
                    stream: id.clone(),
                    opened_by: Some(opened_by),
                })
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
    fn session_started(
        &self,
        machine: &str,
        caller: &str,
        caller_chain: &[CertificateDer<'static>],
    ) -> Result<(u64, Cut), Refusal> {
        let mut st = self.st();
        if st.stop.stopped {
            return Err(Refusal::Stopped);
        }
        if st.machines.get(machine).is_none_or(|m| m.conn.is_none()) {
            return Err(Refusal::Offline);
        }
        // One caller cannot take all of a machine's streams.
        let max = self.config().max_streams_per_caller;
        let mine = st
            .sessions
            .values()
            .filter(|s| s.machine == machine && s.caller == caller)
            .count();
        if mine >= max {
            return Err(Refusal::CallerBusy);
        }
        st.next_id += 1;
        let id = st.next_id;
        let cut = Cut::default();
        st.sessions.insert(
            id,
            Session {
                machine: machine.to_string(),
                caller: caller.to_string(),
                caller_chain: caller_chain.to_vec(),
                cut: cut.clone(),
            },
        );
        Ok((id, cut))
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

    /// `GET /relay/v1/machines`: the stop, and the machines `keep` keeps.
    fn machines_json(&self, keep: impl Fn(&MachineInfo) -> bool) -> Value {
        let list: Vec<Value> = self
            .machines()
            .into_iter()
            .filter(|m| keep(m))
            .map(|m| {
                json!({
                    "machine": m.machine,
                    "online": m.online,
                    "connected_since": m.connected_since.map(rfc3339),
                    "first_seen": rfc3339(m.first_seen),
                    "last_seen": rfc3339(m.last_seen),
                    "sessions": m.sessions,
                    "key": m.key,
                    "key_until": m.key_until.map(rfc3339),
                })
            })
            .collect();
        json!({ "stop": self.stop_state(), "machines": list })
    }
}

/// Who holds a role at the relay, for the audit: each operator, what it
/// may do, and how many certificates it is pinned to.
fn operators_json(cfg: &Config) -> Value {
    cfg.operators
        .iter()
        .map(|o| {
            json!({
                "caller": o.caller,
                "may": o.may.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "certificates": o.certificates.len(),
            })
        })
        .collect()
}

/// A place among one machine's connections.
struct MachineSlot {
    map: Arc<Mutex<HashMap<String, usize>>>,
    machine: String,
}

impl Drop for MachineSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.machine) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.machine);
            }
        }
    }
}

/// Says so when a new key may take a pinned name on time alone.
fn warn_renewal_window(cfg: &Config) {
    if cfg.machine_key_renewal_days > 0 {
        tracing::warn!(
            days = cfg.machine_key_renewal_days,
            "machine_key_renewal_days is above 0: in the last days of a machine's pinned certificate, any newer certificate for its name takes it without the old key's proof; key continuity (POST /relay/v1/rekey) needs no window"
        );
    }
}

/// A certificate's public key, by SHA-256 of its SubjectPublicKeyInfo as
/// hex, and its validity (Unix seconds).
struct CertKey {
    key: String,
    not_before: u64,
    not_after: u64,
}

fn cert_key(c: &CertificateDer<'_>) -> Option<CertKey> {
    use sha2::Digest;
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, x) = X509Certificate::from_der(c.as_ref()).ok()?;
    let secs = |t: x509_parser::time::ASN1Time| u64::try_from(t.timestamp()).unwrap_or(0);
    Some(CertKey {
        key: hex::encode(sha2::Sha256::digest(x.public_key().raw)),
        not_before: secs(x.validity().not_before),
        not_after: secs(x.validity().not_after),
    })
}

/// Takes `machine`'s connection off the table, under the state lock: the
/// cuts for it and its sessions, and since when it was connected. `None`
/// when it is not connected.
fn take_offline(st: &mut State, machine: &str) -> Option<(Vec<Cut>, SystemTime)> {
    let m = st.machines.get_mut(machine)?;
    let c = m.conn.take()?;
    m.seen.last_seen = unix(SystemTime::now());
    let mut cuts = vec![c.cut];
    cuts.extend(
        st.sessions
            .values()
            .filter(|s| s.machine == machine)
            .map(|s| s.cut.clone()),
    );
    Some((cuts, c.since))
}

/// The SHA-256 of a certificate, as hex.
pub(crate) fn fingerprint(c: &CertificateDer<'_>) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(c.as_ref()))
}

/// Why a caller did not get through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Stopped,
    Offline,
    Busy,
    Timeout,
    /// This caller has `max_streams_per_caller` streams to this machine.
    CallerBusy,
    /// The session was cut while the machine was being asked, for this reason.
    Cut(&'static str),
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

/// A connection's place under the connection limits.
pub(crate) struct Held {
    relay: Relay,
    ip: std::net::IpAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut m = self
            .relay
            .inner
            .per_ip
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
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

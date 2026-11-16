//! One side of a link (docs/wire.md): ACP messages in numbered envelopes with
//! cumulative acks, heartbeats, a send window and replay after a reconnect.
//! A port of Go's `wire.Endpoint`. An endpoint outlives sockets: messages sent
//! while no socket is attached wait in the outbox and go out after the next
//! [`Endpoint::serve`].

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Notify, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::conn::{FrameConn, FrameSink, FrameStream, Incoming, Outgoing};
use crate::frame::*;

/// Liveness and flow-control knobs. The defaults are the ones in docs/wire.md.
#[derive(Clone, Debug)]
pub struct Options {
    /// Send something at least this often (10 s).
    pub heartbeat_every: Duration,
    /// Peer silent this long means the socket is dead (25 s).
    pub dead_after: Duration,
    /// Ack received messages within this delay (1 s).
    pub ack_delay: Duration,
    /// Or after this many messages (50).
    pub ack_every: i64,
    /// Stop sending with this many messages unacked (1000).
    pub window_msgs: i64,
    /// Or this many bytes unacked (4 MB).
    pub window_bytes: i64,
    /// Heartbeat with ping instead of ack.
    pub heartbeat_ping: bool,
    /// Writer housekeeping interval (100 ms).
    pub tick: Duration,
    /// A file unacked messages spill into once `memory_limit` bytes are held
    /// in memory (8 MB). The file is private to the user.
    pub spool_path: Option<PathBuf>,
    pub memory_limit: i64,
    /// Acked data in the spool that triggers compaction (64 MB).
    pub compact_min: i64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            heartbeat_every: Duration::from_secs(10),
            dead_after: Duration::from_secs(25),
            ack_delay: Duration::from_secs(1),
            ack_every: 50,
            window_msgs: 1000,
            window_bytes: 4 << 20,
            heartbeat_ping: false,
            tick: Duration::from_millis(100),
            spool_path: None,
            memory_limit: 8 << 20,
            compact_min: 64 << 20,
        }
    }
}

/// Why [`Endpoint::serve`] returned. Every return means this socket is over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeEnd {
    /// The peer said its client has left.
    Bye,
    /// Nothing arrived from the peer for too long.
    Dead,
    /// A newer socket took over the link.
    Replaced,
    /// The socket was closed on purpose by this side.
    Detached,
    /// An error frame from the peer (or a sequence gap this side detected).
    Remote(RemoteError),
    /// A malformed frame from the peer.
    Protocol(String),
    /// The socket failed or the peer closed it.
    Closed(String),
    /// The local consumer refused a message.
    Deliver(String),
}

impl std::fmt::Display for ServeEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeEnd::Bye => f.write_str("peer said bye"),
            ServeEnd::Dead => f.write_str("peer went silent"),
            ServeEnd::Replaced => f.write_str("replaced by a newer connection"),
            ServeEnd::Detached => f.write_str("detached"),
            ServeEnd::Remote(e) => write!(f, "{e}"),
            ServeEnd::Protocol(e) => write!(f, "{ERR_PROTOCOL}: {e}"),
            ServeEnd::Closed(e) => f.write_str(e),
            ServeEnd::Deliver(e) => f.write_str(e),
        }
    }
}

type DeliverFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Called once per peer message, in order. The message counts as processed
/// when the future resolves to `Ok`.
pub type Deliver = Arc<dyn Fn(String) -> DeliverFuture + Send + Sync>;

/// Wraps an async closure as a [`Deliver`].
pub fn deliver_fn<F, Fut>(f: F) -> Deliver
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    Arc::new(move |m| Box::pin(f(m)))
}

struct OutItem {
    seq: i64,
    /// `None` when the message is in the spool file.
    raw: Option<String>,
    off: u64,
    size: i64,
}

/// Controls one socket: who closes it, with which code, and what goes last.
struct ConnCtl {
    token: CancellationToken,
    cause: Mutex<Option<(u16, String)>>,
    last_words: Mutex<Vec<Frame>>,
}

impl ConnCtl {
    fn new() -> Self {
        ConnCtl {
            token: CancellationToken::new(),
            cause: Mutex::new(None),
            last_words: Mutex::new(Vec::new()),
        }
    }

    /// Closes the socket once; the first code wins.
    fn close(&self, code: u16, reason: &str) {
        let mut c = lock(&self.cause);
        if c.is_none() {
            *c = Some((code, reason.to_string()));
            drop(c);
            self.token.cancel();
        }
    }

    /// Sends `f` just before the close frame, then closes.
    fn close_after(&self, f: Frame, code: u16, reason: &str) {
        lock(&self.last_words).push(f);
        self.close(code, reason);
    }

    fn cause_error(&self) -> Option<ServeEnd> {
        lock(&self.cause).as_ref().map(|(code, _)| match *code {
            CLOSE_REPLACED => ServeEnd::Replaced,
            CLOSE_DEAD => ServeEnd::Dead,
            _ => ServeEnd::Detached,
        })
    }
}

struct Attached {
    ctl: Arc<ConnCtl>,
    done: watch::Receiver<bool>,
}

struct State {
    next_seq: i64,
    outbox: VecDeque<OutItem>,
    out_bytes: i64,
    mem_bytes: i64,
    spool: Option<File>,
    spool_end: u64,
    spool_err: Option<String>,
    peer_ack: i64,
    sent_seq: i64,
    last_recv: i64,
    ack_sent: i64,
    ack_due: Option<Instant>,
    pong_due: bool,
    control: Vec<Frame>,
    discard: bool,
    conn: Option<Attached>,
    last_heard: Instant,
    last_sent: Instant,
}

struct Inner {
    opts: Options,
    deliver: Deliver,
    st: Mutex<State>,
    wake: Notify,
    deliver_mu: tokio::sync::Mutex<()>,
}

/// One side of a link. Cheap to clone.
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Endpoint {
    pub fn new(opts: Options, deliver: Deliver) -> Self {
        let now = Instant::now();
        Endpoint {
            inner: Arc::new(Inner {
                opts,
                deliver,
                st: Mutex::new(State {
                    next_seq: 0,
                    outbox: VecDeque::new(),
                    out_bytes: 0,
                    mem_bytes: 0,
                    spool: None,
                    spool_end: 0,
                    spool_err: None,
                    peer_ack: 0,
                    sent_seq: 0,
                    last_recv: 0,
                    ack_sent: 0,
                    ack_due: None,
                    pong_due: false,
                    control: Vec::new(),
                    discard: false,
                    conn: None,
                    last_heard: now,
                    last_sent: now,
                }),
                wake: Notify::new(),
                deliver_mu: tokio::sync::Mutex::new(()),
            }),
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        lock(&self.inner.st)
    }

    fn poke(&self) {
        self.inner.wake.notify_one();
    }

    /// Queues an ACP message for the peer.
    pub fn send(&self, raw: String) {
        {
            let mut st = self.st();
            if st.discard {
                return;
            }
            st.next_seq += 1;
            let size = raw.len() as i64;
            let mut it = OutItem {
                seq: st.next_seq,
                raw: Some(raw),
                off: 0,
                size,
            };
            if self.inner.opts.spool_path.is_some()
                && st.mem_bytes + it.size > self.inner.opts.memory_limit
            {
                if let Err(e) = self.spill(&mut st, &mut it) {
                    st.spool_err = Some(e.to_string());
                }
            }
            if it.raw.is_some() {
                st.mem_bytes += it.size;
            }
            st.out_bytes += it.size;
            st.outbox.push_back(it);
        }
        self.poke();
    }

    /// Drops queued and future outgoing messages. Used once nobody will read them.
    pub fn set_discard(&self, on: bool) {
        let mut st = self.st();
        st.discard = on;
        if on {
            st.outbox.clear();
            st.out_bytes = 0;
            st.mem_bytes = 0;
            reset_spool(&mut st);
            st.peer_ack = st.next_seq;
            st.sent_seq = st.next_seq;
        }
    }

    /// The size of messages waiting for an ack.
    pub fn outbox_bytes(&self) -> i64 {
        self.st().out_bytes
    }

    /// The highest peer sequence number processed.
    pub fn last_received(&self) -> i64 {
        self.st().last_recv
    }

    /// Whether a socket is being served.
    pub fn attached(&self) -> bool {
        self.st().conn.is_some()
    }

    /// Queues a control frame (bye, error) on the current socket.
    pub fn send_control(&self, f: Frame) {
        self.st().control.push(f);
        self.poke();
    }

    /// Closes the current socket, if any, with the given code.
    pub fn detach(&self, code: u16, reason: &str) {
        let ctl = self.st().conn.as_ref().map(|c| c.ctl.clone());
        if let Some(ctl) = ctl {
            ctl.close(code, reason);
        }
    }

    /// A failure to use the spool file, if any.
    pub fn spool_error(&self) -> Option<String> {
        self.st().spool_err.clone()
    }

    /// Deletes the spool file. The endpoint must not be used afterwards.
    pub fn close(&self) {
        let mut st = self.st();
        if st.spool.take().is_some()
            && let Some(p) = &self.inner.opts.spool_path
        {
            let _ = fs::remove_file(p);
        }
        st.outbox.clear();
        st.out_bytes = 0;
        st.mem_bytes = 0;
    }

    /// Runs the link over `conn` until the socket ends. `peer_last_seq` is the
    /// highest of our messages the peer has processed; everything after it is resent.
    pub async fn serve(&self, conn: FrameConn, peer_last_seq: i64) -> ServeEnd {
        let ctl = Arc::new(ConnCtl::new());
        let (done_tx, done_rx) = watch::channel(false);
        // Only one socket at a time: close the old one and wait until its serve
        // has fully returned, so it cannot deliver a message the new one delivers again.
        loop {
            let old = {
                let mut st = self.st();
                match &st.conn {
                    Some(c) => (c.ctl.clone(), c.done.clone()),
                    None => {
                        st.conn = Some(Attached {
                            ctl: ctl.clone(),
                            done: done_rx.clone(),
                        });
                        ack_peer(&self.inner, &mut st, peer_last_seq);
                        st.sent_seq = st.peer_ack;
                        st.ack_sent = 0; // re-announce our position on the new socket
                        let now = Instant::now();
                        st.ack_due = Some(now);
                        st.last_heard = now;
                        st.last_sent = now;
                        break;
                    }
                }
            };
            old.0.close(CLOSE_REPLACED, "replaced");
            let mut done = old.1;
            let _ = done.wait_for(|d| *d).await;
        }
        let _done = DoneGuard(done_tx);
        self.poke();

        let FrameConn { sink, mut stream } = conn;
        let writer = tokio::spawn(write_loop(self.inner.clone(), sink, ctl.clone()));
        let read_end = self.read_loop(&mut stream, &ctl).await;
        ctl.close(CLOSE_NORMAL, "");
        let _ = writer.await;
        if !matches!(read_end, ServeEnd::Closed(_)) {
            // Give the peer a moment to answer our close frame.
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while let Some(Ok(item)) = stream.next().await {
                    if matches!(item, Incoming::Close(_)) {
                        break;
                    }
                }
            })
            .await;
        }
        {
            let mut st = self.st();
            if st.conn.as_ref().is_some_and(|c| Arc::ptr_eq(&c.ctl, &ctl)) {
                st.conn = None;
            }
        }
        read_end
    }

    async fn read_loop(&self, stream: &mut FrameStream, ctl: &ConnCtl) -> ServeEnd {
        loop {
            let item = tokio::select! {
                biased;
                _ = ctl.token.cancelled() => {
                    return ctl.cause_error().unwrap_or(ServeEnd::Detached);
                }
                item = stream.next() => item,
            };
            let text = match item {
                None => {
                    return ctl
                        .cause_error()
                        .unwrap_or_else(|| ServeEnd::Closed("connection closed".into()));
                }
                Some(Err(e)) => {
                    return ctl
                        .cause_error()
                        .unwrap_or_else(|| ServeEnd::Closed(e.to_string()));
                }
                Some(Ok(Incoming::Close(code))) => {
                    if let Some(c) = ctl.cause_error() {
                        return c;
                    }
                    return match code {
                        Some(CLOSE_REPLACED) => ServeEnd::Replaced,
                        Some(code) => {
                            ServeEnd::Closed(format!("closed by the peer with status {code}"))
                        }
                        None => ServeEnd::Closed("closed by the peer".into()),
                    };
                }
                Some(Ok(Incoming::Binary)) => {
                    self.st().last_heard = Instant::now();
                    continue;
                }
                Some(Ok(Incoming::Text(t))) => t,
            };
            self.st().last_heard = Instant::now();
            let f = match Frame::decode(&text) {
                Ok(f) => f,
                Err(e) => {
                    ctl.close_after(
                        Frame::error(ERR_PROTOCOL, "invalid frame", None),
                        CLOSE_PROTOCOL_ERROR,
                        "invalid frame",
                    );
                    return ServeEnd::Protocol(e.to_string());
                }
            };
            match f.t.as_str() {
                T_MSG => {
                    self.handle_ack(f.ack);
                    // deliver_mu makes check, deliver and update one step, so a message is
                    // never delivered twice or out of order, whichever socket it came on.
                    let guard = self.inner.deliver_mu.lock().await;
                    let last = self.st().last_recv;
                    if f.seq <= last {
                        continue;
                    }
                    if f.seq != last + 1 {
                        drop(guard);
                        let msg = format!("expected {}, got {}", last + 1, f.seq);
                        ctl.close_after(
                            Frame::error(ERR_SEQUENCE_GAP, msg, None),
                            CLOSE_PROTOCOL_ERROR,
                            "sequence gap",
                        );
                        return ServeEnd::Remote(RemoteError {
                            code: ERR_SEQUENCE_GAP.into(),
                            message: "sequence gap".into(),
                            data: None,
                        });
                    }
                    if let Err(e) = (self.inner.deliver)(f.msg.unwrap_or_default()).await {
                        return ServeEnd::Deliver(e);
                    }
                    {
                        let mut st = self.st();
                        st.last_recv = f.seq;
                        drop(guard);
                        let now = Instant::now();
                        if st.last_recv - st.ack_sent >= self.inner.opts.ack_every {
                            st.ack_due = Some(now);
                        } else if st.ack_due.is_none() {
                            st.ack_due = Some(now + self.inner.opts.ack_delay);
                        }
                    }
                    self.poke();
                }
                T_ACK => self.handle_ack(f.ack),
                T_PING => {
                    self.st().pong_due = true;
                    self.poke();
                }
                T_PONG => {}
                T_BYE => return ServeEnd::Bye,
                T_ERROR => {
                    return ServeEnd::Remote(RemoteError {
                        code: f.code,
                        message: f.message,
                        data: f.data,
                    });
                }
                _ => {}
            }
        }
    }

    fn handle_ack(&self, a: i64) {
        let changed = {
            let mut st = self.st();
            ack_peer(&self.inner, &mut st, a)
        };
        if changed {
            self.poke();
        }
    }

    /// Writes a message to the spool file; the caller holds the state lock.
    fn spill(&self, st: &mut State, it: &mut OutItem) -> std::io::Result<()> {
        let path = self.inner.opts.spool_path.as_ref().expect("spool path");
        if st.spool.is_none() {
            if let Some(dir) = path.parent() {
                create_private_dir(dir)?;
            }
            st.spool = Some(open_private(path, true)?);
            st.spool_end = 0;
        }
        let raw = it.raw.as_ref().expect("in memory");
        write_at(
            st.spool.as_ref().expect("spool"),
            raw.as_bytes(),
            st.spool_end,
        )?;
        it.off = st.spool_end;
        it.raw = None;
        st.spool_end += it.size as u64;
        Ok(())
    }
}

struct DoneGuard(watch::Sender<bool>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// A message's bytes, read from the spool when needed; the caller holds the state lock.
fn load(st: &State, it: &OutItem) -> std::io::Result<String> {
    if let Some(raw) = &it.raw {
        return Ok(raw.clone());
    }
    let Some(f) = &st.spool else {
        return Err(std::io::Error::other("spool file is gone"));
    };
    let mut buf = vec![0u8; it.size as usize];
    read_at(f, &mut buf, it.off)
        .map_err(|e| std::io::Error::other(format!("reading spool: {e}")))?;
    String::from_utf8(buf).map_err(|e| std::io::Error::other(format!("reading spool: {e}")))
}

/// Empties the spool file once nothing in it is needed; the caller holds the state lock.
fn reset_spool(st: &mut State) {
    if st.spool_end > 0
        && let Some(f) = &st.spool
    {
        let _ = f.set_len(0);
        st.spool_end = 0;
    }
}

/// Rewrites the spool without acked data once that data is most of the file,
/// so a long stream to a slow reader does not grow it forever.
fn maybe_compact_spool(inner: &Inner, st: &mut State) {
    if st.spool.is_none() {
        return;
    }
    let live: i64 = st
        .outbox
        .iter()
        .filter(|it| it.raw.is_none())
        .map(|it| it.size)
        .sum();
    let dead = st.spool_end as i64 - live;
    if dead < inner.opts.compact_min || dead < st.spool_end as i64 / 2 {
        return;
    }
    let path = inner.opts.spool_path.clone().expect("spool path");
    let mut tmp_path = path.clone().into_os_string();
    tmp_path.push(".tmp");
    let tmp_path = PathBuf::from(tmp_path);
    let tmp = match open_private(&tmp_path, true) {
        Ok(f) => f,
        Err(e) => {
            st.spool_err = Some(e.to_string());
            return;
        }
    };
    let mut off = 0u64;
    let mut moved = vec![0u64; st.outbox.len()];
    for (i, it) in st.outbox.iter().enumerate() {
        if it.raw.is_some() {
            continue;
        }
        let res = load(st, it).and_then(|buf| write_at(&tmp, buf.as_bytes(), off));
        if let Err(e) = res {
            drop(tmp);
            let _ = fs::remove_file(&tmp_path);
            st.spool_err = Some(e.to_string());
            return;
        }
        moved[i] = off;
        off += it.size as u64;
    }
    // Windows cannot rename open files, so close both, rename, and reopen.
    st.spool = None;
    drop(tmp);
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        st.spool_err = Some(e.to_string());
        st.spool = open_private(&path, false).ok();
        return;
    }
    match open_private(&path, false) {
        Ok(f) => {
            for (i, it) in st.outbox.iter_mut().enumerate() {
                if it.raw.is_none() {
                    it.off = moved[i];
                }
            }
            st.spool = Some(f);
            st.spool_end = off;
        }
        Err(e) => {
            st.spool_err = Some(e.to_string());
            st.spool = None;
        }
    }
}

/// Trims the outbox up to `a`; the caller holds the state lock.
fn ack_peer(inner: &Inner, st: &mut State, a: i64) -> bool {
    if a <= st.peer_ack {
        return false;
    }
    let a = a.min(st.next_seq);
    st.peer_ack = a;
    while st.outbox.front().is_some_and(|it| it.seq <= a) {
        let it = st.outbox.pop_front().expect("front");
        st.out_bytes -= it.size;
        if it.raw.is_some() {
            st.mem_bytes -= it.size;
        }
    }
    if st.outbox.is_empty() {
        reset_spool(st);
    } else {
        maybe_compact_spool(inner, st);
    }
    if st.sent_seq < a {
        st.sent_seq = a;
    }
    true
}

/// What to write next and whether the socket is dead; the writer sends it
/// without holding the lock.
fn collect(inner: &Inner) -> (Vec<Frame>, bool, u16) {
    let mut st = lock(&inner.st);
    let opts = &inner.opts;
    let now = Instant::now();
    if now.duration_since(st.last_heard) > opts.dead_after {
        return (Vec::new(), true, 0);
    }
    let mut frames = Vec::new();
    let mut close_after = 0u16;
    // A bye or a link-ending error waits until every queued message is on the
    // wire, so nothing the peer still needs is overtaken by it.
    let control = std::mem::take(&mut st.control);
    for c in control {
        if c.t == T_BYE || c.t == T_ERROR {
            st.control.push(c);
        } else {
            frames.push(c);
        }
    }
    if st.pong_due {
        frames.push(Frame::of(T_PONG));
        st.pong_due = false;
    }
    let mut inflight: i64 = 0;
    for it in &st.outbox {
        if it.seq > st.sent_seq {
            break;
        }
        if it.seq > st.peer_ack {
            inflight += it.size;
        }
    }
    while st.sent_seq < st.next_seq && !st.outbox.is_empty() {
        if st.sent_seq - st.peer_ack >= opts.window_msgs || inflight >= opts.window_bytes {
            break;
        }
        let idx = st.sent_seq + 1 - st.outbox[0].seq;
        if idx < 0 || idx as usize >= st.outbox.len() {
            break;
        }
        let it = &st.outbox[idx as usize];
        let (seq, size) = (it.seq, it.size);
        let raw = match load(&st, it) {
            Ok(r) => r,
            Err(e) => {
                st.spool_err = Some(e.to_string());
                break;
            }
        };
        frames.push(Frame::msg(seq, st.last_recv, raw));
        inflight += size;
        st.sent_seq = seq;
        st.ack_sent = st.last_recv;
    }
    if !st.control.is_empty() && st.sent_seq >= st.next_seq {
        close_after = CLOSE_NORMAL;
        if st.control.iter().any(|c| c.t == T_ERROR) {
            close_after = CLOSE_LINK_ENDED;
        }
        frames.append(&mut st.control);
    }
    let ack_owed = st.last_recv > st.ack_sent && st.ack_due.is_some_and(|d| now >= d);
    let heartbeat = now.duration_since(st.last_sent) >= opts.heartbeat_every;
    if frames.is_empty() && (ack_owed || heartbeat) {
        if heartbeat && opts.heartbeat_ping && !ack_owed {
            frames.push(Frame::of(T_PING));
        } else {
            frames.push(Frame::ack(st.last_recv));
            st.ack_sent = st.last_recv;
        }
    }
    if st.last_recv <= st.ack_sent {
        st.ack_due = None;
    }
    if !frames.is_empty() {
        st.last_sent = now;
    }
    (frames, false, close_after)
}

async fn write_loop(inner: Arc<Inner>, mut sink: FrameSink, ctl: Arc<ConnCtl>) -> Option<ServeEnd> {
    let mut ticker = tokio::time::interval(inner.opts.tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut result = None;
    let mut broken = false;
    'outer: loop {
        tokio::select! {
            _ = ctl.token.cancelled() => break,
            _ = ticker.tick() => {}
            _ = inner.wake.notified() => {}
        }
        if ctl.token.is_cancelled() {
            break;
        }
        let (frames, dead, close_after) = collect(&inner);
        if dead {
            ctl.close(CLOSE_DEAD, "peer silent");
            result = Some(ServeEnd::Dead);
            break;
        }
        for f in frames {
            let sent = tokio::time::timeout(
                Duration::from_secs(10),
                sink.send(Outgoing::Text(f.encode())),
            )
            .await;
            if !matches!(sent, Ok(Ok(()))) {
                broken = true;
                ctl.close(CLOSE_NORMAL, "");
                result = Some(ServeEnd::Closed("write failed".into()));
                break 'outer;
            }
        }
        if close_after != 0 {
            ctl.close(close_after, "");
            break;
        }
    }
    let last_words = std::mem::take(&mut *lock(&ctl.last_words));
    let (code, reason) = lock(&ctl.cause)
        .clone()
        .unwrap_or((CLOSE_NORMAL, String::new()));
    if broken {
        return result;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        for f in last_words {
            sink.send(Outgoing::Text(f.encode())).await?;
        }
        sink.send(Outgoing::Close(code, reason)).await
    })
    .await;
    result
}

fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn open_private(path: &std::path::Path, truncate: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    if truncate {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}

#[cfg(windows)]
fn write_at(f: &File, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn read_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_compacts_acked_data() {
        let dir = std::env::temp_dir().join(format!("actp-compact-{}", std::process::id()));
        let path = dir.join("link.spool");
        let opts = Options {
            spool_path: Some(path.clone()),
            memory_limit: 1,
            compact_min: 200,
            ..Options::default()
        };
        let e = Endpoint::new(opts, deliver_fn(|_| async { Ok(()) }));
        for i in 1..=40 {
            e.send(format!(r#"{{"n":{i:02}}}"#)); // 8 bytes each
        }
        {
            let mut st = e.st();
            ack_peer(&e.inner, &mut st, 30); // 240 bytes dead, 80 live
            assert_eq!(st.spool_end, 80);
            assert_eq!(load(&st, &st.outbox[0]).unwrap(), r#"{"n":31}"#);
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), 80);
        e.close();
        let _ = fs::remove_dir_all(dir);
    }
}

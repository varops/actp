//! End-to-end encryption through a relay that is not on the caller's side.
//!
//! A hostile relay speaks the relay protocol faithfully to real machines
//! and real callers, but reads everything it carries, changes bytes, sends
//! callers to another machine, or answers as the machine itself. None of it
//! gets the relay anything: it sees ciphertext, and every change or detour
//! breaks the connection.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actp_proto::relay::Control;
use actp_proto::wsio::WsIo;
use common::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

/// What the hostile relay does with a caller's tunnel.
#[derive(Clone)]
enum Mode {
    /// Carries the bytes, and keeps a copy.
    Read,
    /// Flips one bit of the byte at `at` going to the machine, or (with
    /// `to_caller`) coming back.
    Tamper { at: usize, to_caller: bool },
    /// Sends every caller to this machine instead.
    SendTo(String),
    /// Answers the caller's TLS itself, with this configuration.
    Answer(Arc<rustls::ServerConfig>),
}

type Wire = WsIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>;

#[derive(Default)]
struct Hub {
    controls: HashMap<String, mpsc::UnboundedSender<String>>,
    pending: HashMap<String, oneshot::Sender<Wire>>,
}

struct Hostile {
    port: u16,
    /// Everything the relay carried, both ways.
    seen: Arc<Mutex<Vec<u8>>>,
    /// Bytes carried to the machine and to the caller.
    carried: Arc<Mutex<(usize, usize)>>,
    /// Whether a byte was changed.
    tampered: Arc<AtomicBool>,
}

// The callback's error type is set by tungstenite.
#[allow(clippy::result_large_err)]
async fn hostile_relay(pki: &Pki, mode: Mode) -> Hostile {
    let cfg = actp_relay::config::Config::parse(&relay_yaml(pki, &pki.dir, "")).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.config);
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let hub: Arc<Mutex<Hub>> = Arc::default();
    let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
    let seen2 = seen.clone();
    let carried: Arc<Mutex<(usize, usize)>> = Arc::default();
    let carried2 = carried.clone();
    let tampered: Arc<AtomicBool> = Arc::default();
    let tampered2 = tampered.clone();
    tokio::spawn(async move {
        let mut next_id = 0u64;
        while let Ok((tcp, _)) = ln.accept().await {
            next_id += 1;
            let (acceptor, hub, seen, mode) =
                (acceptor.clone(), hub.clone(), seen2.clone(), mode.clone());
            let (carried, tampered) = (carried2.clone(), tampered2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let name = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first().cloned())
                    .and_then(|c| {
                        actp_proto::e2e::machine_name(&c, actp_proto::e2e::MachineName::Cn).ok()
                    })
                    .unwrap_or_default();
                let path = Arc::new(Mutex::new(String::new()));
                let p2 = path.clone();
                let cb = move |req: &Request, mut resp: Response| {
                    *p2.lock().unwrap() = req.uri().path().to_string();
                    if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                        resp.headers_mut()
                            .insert("Sec-WebSocket-Protocol", proto.clone());
                    }
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, cb).await else {
                    return;
                };
                let path = path.lock().unwrap().clone();
                if path == actp_proto::relay::PATH_CONNECT {
                    // A machine: say hello, and pass on stream requests.
                    let hello = Control::Hello {
                        machine: name.clone(),
                        stopped: false,
                    };
                    let _ = ws.send(Message::text(hello.encode())).await;
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    hub.lock().unwrap().controls.insert(name, tx);
                    loop {
                        tokio::select! {
                            m = ws.next() => if !matches!(m, Some(Ok(_))) { return },
                            open = rx.recv() => match open {
                                Some(text) => { let _ = ws.send(Message::text(text)).await; }
                                None => return,
                            },
                        }
                    }
                } else if let Some(id) = path.strip_prefix(actp_proto::relay::PATH_STREAM) {
                    if let Some(tx) = hub.lock().unwrap().pending.remove(id) {
                        let _ = tx.send(WsIo::new(ws));
                    }
                } else if let Some(asked) = path.strip_prefix(actp_proto::relay::PATH_TUNNEL) {
                    let caller = WsIo::new(ws);
                    let target = match &mode {
                        Mode::Answer(cfg) => {
                            // Pretend to be the machine.
                            let _ = tokio_rustls::TlsAcceptor::from(cfg.clone())
                                .accept(caller)
                                .await;
                            return;
                        }
                        Mode::SendTo(other) => other.clone(),
                        _ => asked.to_string(),
                    };
                    let id = format!("{next_id:064x}");
                    let (tx, rx) = oneshot::channel();
                    let control = {
                        let mut h = hub.lock().unwrap();
                        h.pending.insert(id.clone(), tx);
                        h.controls.get(&target).cloned()
                    };
                    let Some(control) = control else { return };
                    // It also lies about who opened the stream, in a shape
                    // the machine does not record.
                    let opened_by = Some(actp_proto::relay::OpenedBy {
                        caller: "someone else".into(),
                        caller_certificate: "0".repeat(64),
                        on_behalf_of: None,
                    });
                    let _ = control.send(
                        Control::Open {
                            stream: id,
                            opened_by,
                        }
                        .encode(),
                    );
                    let Ok(Ok(machine)) = tokio::time::timeout(Duration::from_secs(5), rx).await
                    else {
                        return;
                    };
                    splice(caller, machine, mode, seen, carried, tampered).await;
                }
            });
        }
    });
    Hostile {
        port,
        seen,
        carried,
        tampered,
    }
}

/// Carries bytes both ways, recording them, changing one if asked.
async fn splice(
    caller: Wire,
    machine: Wire,
    mode: Mode,
    seen: Arc<Mutex<Vec<u8>>>,
    carried: Arc<Mutex<(usize, usize)>>,
    tampered: Arc<AtomicBool>,
) {
    let (mut cr, mut cw) = tokio::io::split(caller);
    let (mut mr, mut mw) = tokio::io::split(machine);
    let tamper = |to_caller: bool| match &mode {
        Mode::Tamper { at, to_caller: t } if *t == to_caller => Some(*at),
        _ => None,
    };
    let (up, down) = (tamper(false), tamper(true));
    let (s1, s2) = (seen.clone(), seen);
    let (c1, c2) = (carried.clone(), carried);
    let (t1, t2) = (tampered.clone(), tampered);
    let one = async move {
        let mut buf = vec![0u8; 16 << 10];
        let mut sent = 0usize;
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(at) = up
                && (sent..sent + n).contains(&at)
            {
                buf[at - sent] ^= 0x01;
                t1.store(true, Ordering::SeqCst);
            }
            sent += n;
            c1.lock().unwrap().0 += n;
            s1.lock().unwrap().extend_from_slice(&buf[..n]);
            if mw.write_all(&buf[..n]).await.is_err() || mw.flush().await.is_err() {
                break;
            }
        }
        let _ = mw.shutdown().await;
    };
    let two = async move {
        let mut buf = vec![0u8; 16 << 10];
        let mut sent = 0usize;
        loop {
            let n = match mr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(at) = down
                && (sent..sent + n).contains(&at)
            {
                buf[at - sent] ^= 0x01;
                t2.store(true, Ordering::SeqCst);
            }
            sent += n;
            c2.lock().unwrap().1 += n;
            s2.lock().unwrap().extend_from_slice(&buf[..n]);
            if cw.write_all(&buf[..n]).await.is_err() || cw.flush().await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };
    tokio::join!(one, two);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_reads_sees_only_ciphertext() {
    let dir = scratch("e2e-read");
    let pki = Pki::new(&dir);
    let relay = hostile_relay(&pki, Mode::Read).await;
    let mut a = start_laptop(&pki, "laptop-a", relay.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    // A whole session, carried by the relay.
    let mut caller = Caller::start(&pki, relay.port, "laptop-a");
    let init = caller
        .call(1, "initialize", json!({"protocolVersion": 1}))
        .await;
    assert!(init.get("result").is_some(), "{init}");
    // A malformed account of who opened the stream is not recorded, but
    // that the relay gave one is.
    eventually("the link", || {
        a.audit().iter().any(|e| e["event"] == "link_opened")
    })
    .await;
    assert!(
        a.audit()
            .iter()
            .filter(|e| e["event"] == "link_opened")
            .all(|e| e["relay_report"] == "malformed" && e["relay_caller"] == "")
    );
    let (status, body) = tunnel_request(
        &pki.route("laptop-a"),
        relay.port,
        "laptop-a",
        "GET",
        "/api/v1/info",
        TOKEN,
        None,
    )
    .await
    .unwrap();
    assert_eq!((status, body["name"].as_str()), (200, Some("laptop-a")));
    drop(caller);
    let seen = relay.seen.lock().unwrap().clone();
    assert!(seen.len() > 1000, "the relay carried the session");
    for secret in [
        TOKEN.as_bytes(),
        b"Bearer".as_slice(),
        b"initialize",
        b"protocolVersion",
        b"/actp/v1/agents",
        b"/api/v1/info",
        b"laptop-a\"",
    ] {
        assert!(
            !contains(&seen, secret),
            "the relay saw {:?}",
            String::from_utf8_lossy(secret)
        );
    }
}

/// Thirty requests on one tunnel; how many were answered, or the error
/// that stopped them.
async fn thirty_requests(pki: &Pki, port: u16) -> Result<usize, String> {
    let tls = open_tunnel(&pki.route("laptop-a"), port, "laptop-a")
        .await
        .map_err(|e| format!("{e:?}"))?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    for i in 0..30 {
        // A kept-alive connection is ready again once the last answer is in.
        tokio::time::timeout(Duration::from_secs(5), sender.ready())
            .await
            .map_err(|_| format!("request {i}: the connection never got ready"))?
            .map_err(|e| format!("request {i}: {e}"))?;
        let req = http::Request::builder()
            .uri("/api/v1/info")
            .header("host", "machine.actp.invalid")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), sender.send_request(req))
            .await
            .map_err(|_| format!("request {i}: no answer"))?
            .map_err(|e| format!("request {i}: {e}"))?;
        use http_body_util::BodyExt;
        let body = tokio::time::timeout(Duration::from_secs(5), resp.into_body().collect())
            .await
            .map_err(|_| format!("request {i}: no body"))?
            .map_err(|e| format!("request {i}: {e}"))?
            .to_bytes();
        let info: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| format!("request {i}: {e}"))?;
        if info["name"] != "laptop-a" {
            return Err(format!("request {i}: {info}"));
        }
    }
    Ok(30)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_changes_a_byte_breaks_the_connection() {
    let dir = scratch("e2e-tamper");
    let pki = Pki::new(&dir);
    // The same thirty requests go through when nothing is changed.
    let honest = hostile_relay(&pki, Mode::Read).await;
    let mut a = start_laptop(&pki, "laptop-a", honest.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    assert_eq!(thirty_requests(&pki, honest.port).await, Ok(30));
    let (up, down) = *honest.carried.lock().unwrap();
    drop(a);
    // One bit changed in the handshake, halfway through the requests on
    // their way, or halfway through the answers coming back: the connection
    // breaks, and nothing changed is ever taken for real.
    for (at, to_caller) in [(40, false), (up / 2, false), (down / 2, true)] {
        let relay = hostile_relay(&pki, Mode::Tamper { at, to_caller }).await;
        let mut a = start_laptop(&pki, "laptop-a", relay.port, pki.device("laptop-a", None)).await;
        a.wait_connected().await;
        let got = thirty_requests(&pki, relay.port).await;
        assert!(
            relay.tampered.load(Ordering::SeqCst),
            "byte {at} (to the caller: {to_caller}) was never carried"
        );
        assert!(
            got.is_err(),
            "byte {at} (to the caller: {to_caller}): {got:?}"
        );
        drop(a);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_cannot_send_a_caller_to_another_machine() {
    let dir = scratch("e2e-misroute");
    let pki = Pki::new(&dir);
    let relay = hostile_relay(&pki, Mode::SendTo("laptop-b".into())).await;
    let mut a = start_laptop(&pki, "laptop-a", relay.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", relay.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;
    let got = tunnel_request(
        &pki.route("laptop-a"),
        relay.port,
        "laptop-a",
        "GET",
        "/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    match got {
        Err(Refused::Tls(e)) => assert!(e.contains("NotValidForName"), "{e}"),
        other => panic!("{other:?}"),
    }
    // laptop-b never saw the caller's request.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(b.srv.links().is_empty());
    assert!(!b.audit().iter().any(|e| e["token"] == "it"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_cannot_answer_as_the_machine() {
    let dir = scratch("e2e-impostor");
    let pki = Pki::new(&dir);
    let server = |cert: (std::path::PathBuf, std::path::PathBuf)| {
        actp_server::relay::stream_tls(&actp_server::config::Relay {
            url: String::new(),
            cert: cert.0.to_string_lossy().into_owned(),
            key: cert.1.to_string_lossy().into_owned(),
            ca: String::new(),
        })
        .unwrap()
    };
    let (rp, rk, _) = ca("rogue CA");
    let rogue = rcgen::Issuer::new(rp, rk);
    for (what, cfg, expect) in [
        // A certificate that names laptop-a, from a CA the org does not use.
        (
            "a forged certificate",
            server(pki.device("laptop-a", Some(&rogue))),
            "UnknownIssuer",
        ),
        // Another machine's real certificate (a relay holding a stolen one).
        (
            "another machine's certificate",
            server(pki.device("laptop-b", None)),
            "NotValidForName",
        ),
        // A caller certificate (the org's, but not a device's).
        (
            "a caller certificate",
            server(pki.caller("it-bridge-9", None)),
            "UnknownIssuer",
        ),
    ] {
        let relay = hostile_relay(&pki, Mode::Answer(cfg)).await;
        let got = tunnel_request(
            &pki.route("laptop-a"),
            relay.port,
            "laptop-a",
            "GET",
            "/api/v1/info",
            TOKEN,
            None,
        )
        .await;
        match got {
            Err(Refused::Tls(e)) => assert!(e.contains(expect), "{what}: {e}"),
            other => panic!("{what}: {other:?}"),
        }
    }
}

//! Relay hardening: a machine name is pinned to its first key, each
//! machine's connections are capped, and idle tunnels are cut.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actp_relay::Timing;
use actp_server::relay::Status;
use common::*;
use serde_json::{Value, json};
use tokio::net::TcpStream;

/// A TLS connection to the relay with the device certificate `cert`.
async fn device_tls(
    pki: &Pki,
    port: u16,
    cert: &(PathBuf, PathBuf),
) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(pki.dir.join("relay-ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(
        CertificateDer::pem_file_iter(&cert.0)
            .unwrap()
            .map(|c| c.unwrap())
            .collect(),
        PrivateKeyDer::from_pem_file(&cert.1).unwrap(),
    )
    .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap()
}

/// What the relay answers a machine holding `cert`. With no issuer
/// configured, a machine it accepts gets 404 `not_found` from the issuer
/// route: the machine check comes first.
async fn as_machine(pki: &Pki, port: u16, cert: &(PathBuf, PathBuf)) -> (u16, String) {
    let tls = device_tls(pki, port, cert).await;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = http::Request::get("/relay/v1/issuer/v1/anything")
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    use http_body_util::BodyExt;
    let body: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
        .unwrap_or(Value::Null);
    (status, body["error"].as_str().unwrap_or("").to_string())
}

const ACCEPTED: (u16, &str) = (404, "not_found");
const KEY_CHANGED: (u16, &str) = (403, "machine_key_changed");

fn is(got: &(u16, String), want: (u16, &str)) -> bool {
    got.0 == want.0 && got.1 == want.1
}

/// A device certificate for `cn` with a fresh key, valid for `days` more.
fn device_for_days(pki: &Pki, cn: &str, file: &str, days: i64) -> (PathBuf, PathBuf) {
    let (c, k) = pki.device_with(cn, None, |p| {
        p.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        p.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    });
    let (c2, k2) = (
        pki.dir.join(format!("{file}.pem")),
        pki.dir.join(format!("{file}.key")),
    );
    std::fs::rename(&c, &c2).unwrap();
    std::fs::rename(&k, &k2).unwrap();
    (c2, k2)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_name_keeps_its_first_key_until_an_admin_repins_it() {
    let dir = scratch("pin");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let first = device_for_days(&pki, "laptop-a", "first", 365);
    let second = device_for_days(&pki, "laptop-a", "second", 365);

    // The first key seen for the name is pinned.
    let got = as_machine(&pki, env.port, &first).await;
    assert!(is(&got, ACCEPTED), "{got:?}");
    assert!(is(&as_machine(&pki, env.port, &first).await, ACCEPTED));
    assert_eq!(env.relay.machines().len(), 1, "seen from its first request");

    // Another certificate for the name, as valid, with another key: refused,
    // though the org's CA signed it, while the pinned one is far from expiry.
    let got = as_machine(&pki, env.port, &second).await;
    assert!(is(&got, KEY_CHANGED), "{got:?}");
    assert!(
        env.audit_has("machine_refused", |e| e["machine"] == "laptop-a"
            && e["reason"] == "key_changed")
    );
    // A real machine with it never connects.
    let mut laptop = start_laptop(&pki, "laptop-a", env.port, second.clone()).await;
    laptop
        .wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    drop(laptop);

    // The pin outlives a restart (the relay writes what it saw as it stops).
    drop(env);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let env = start_relay(&pki, &dir).await;
    assert!(is(&as_machine(&pki, env.port, &second).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &first).await, ACCEPTED));

    // Re-pinning takes an admin, a machine name and a reason.
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/repin",
        "",
        Some(json!({"machine": "laptop-a", "reason": "new disk"})),
    )
    .await;
    assert_eq!(status, 401);
    for body in [
        json!({"machine": "laptop-a"}),
        json!({"machine": "laptop-a", "reason": "  "}),
        json!({"machine": "odd name", "reason": "x"}),
        json!({"reason": "x"}),
    ] {
        let (status, b) =
            request(&pki, env.port, "POST", "/relay/v1/repin", ADMIN, Some(body)).await;
        assert_eq!(
            (status, b["error"].as_str()),
            (400, Some("machine_and_reason_required"))
        );
    }
    let (status, _) = request(&pki, env.port, "GET", "/relay/v1/repin", ADMIN, None).await;
    assert_eq!(status, 405);
    let (status, b) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/repin",
        ADMIN,
        Some(json!({"machine": "laptop-a", "reason": "new disk"})),
    )
    .await;
    assert_eq!((status, &b["was_pinned"]), (200, &json!(true)));
    assert!(
        env.audit_has("machine_repinned", |e| e["machine"] == "laptop-a"
            && e["by"] == "dave"
            && e["reason"] == "new disk"
            && e["was_pinned"] == true)
    );

    // The next key seen is pinned, and the old one is now the stranger.
    let mut laptop = start_laptop(&pki, "laptop-a", env.port, second.clone()).await;
    laptop.wait_connected().await;
    assert!(is(&as_machine(&pki, env.port, &first).await, KEY_CHANGED));
    assert!(
        !env.audit_has("machine_key_renewed", |_| true),
        "a re-pin pins afresh: it is not a renewal"
    );
    drop(laptop);

    // Re-pinning a name never seen says so.
    let (status, b) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/repin",
        ADMIN,
        Some(json!({"machine": "laptop-z", "reason": "tidy"})),
    )
    .await;
    assert_eq!((status, &b["was_pinned"]), (200, &json!(false)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_key_is_taken_as_a_renewal_only_near_the_pinned_expiry() {
    let dir = scratch("renew");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;

    // Pinned to a certificate with 10 days left: within the 30-day window,
    // so a certificate with a new key is its renewal.
    let old = device_for_days(&pki, "laptop-a", "old", 10);
    let renewed = device_for_days(&pki, "laptop-a", "renewed", 365);
    let later = device_for_days(&pki, "laptop-a", "later", 365);
    assert!(is(&as_machine(&pki, env.port, &old).await, ACCEPTED));
    assert!(is(&as_machine(&pki, env.port, &renewed).await, ACCEPTED));
    assert!(
        env.audit_has("machine_key_renewed", |e| e["machine"] == "laptop-a"
            && e["old_key"] != e["new_key"]
            && e["new_key"].as_str().is_some_and(|k| k.len() == 64))
    );
    // The renewal is now the pin: the old key is refused, and so is a third
    // key while the renewal is far from expiry.
    assert!(is(&as_machine(&pki, env.port, &old).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &later).await, KEY_CHANGED));
    drop(env);

    // With the window at 0, no new key is ever taken by itself.
    let dir = scratch("renew-off");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, "machine_key_renewal_days: 0\n").await;
    let old = device_for_days(&pki, "laptop-b", "old", 1);
    let renewed = device_for_days(&pki, "laptop-b", "renewed", 365);
    assert!(is(&as_machine(&pki, env.port, &old).await, ACCEPTED));
    assert!(is(&as_machine(&pki, env.port, &renewed).await, KEY_CHANGED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_machine_holds_only_so_many_connections() {
    let dir = scratch("per-machine");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, "max_connections_per_machine: 2\n").await;
    let a = pki.device("laptop-a", None);
    let b = pki.device("laptop-b", None);

    let _one = device_tls(&pki, env.port, &a).await;
    let _two = device_tls(&pki, env.port, &a).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The third is closed at once, and recorded with the machine's name.
    let mut three = device_tls(&pki, env.port, &a).await;
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut three, &mut buf),
    )
    .await
    .expect("closed by the relay");
    assert!(matches!(n, Ok(0) | Err(_)));
    eventually("the refusal recorded", || {
        env.audit_has("connection_refused", |e| e["machine"] == "laptop-a")
    })
    .await;
    // Another machine is not affected.
    assert!(is(&as_machine(&pki, env.port, &b).await, ACCEPTED));

    // Closing one frees its place.
    drop(_one);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(is(&as_machine(&pki, env.port, &a).await, ACCEPTED));

    // The limit is checked when the configuration loads.
    let bad = relay_yaml(&pki, &dir, "max_connections_per_machine: 0\n");
    assert!(actp_relay::config::Config::parse(&bad).is_err());
}

/// An HTTP/1 connection to `machine` through a tunnel, kept open.
async fn held_tunnel(
    pki: &Pki,
    port: u16,
    machine: &str,
) -> hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>> {
    let tls = open_tunnel(&pki.route(machine), port, machine)
        .await
        .unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

async fn health(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
) -> Option<u16> {
    sender.ready().await.ok()?;
    let req = http::Request::get("/api/v1/info")
        .header("host", "machine.actp.invalid")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), sender.send_request(req))
        .await
        .ok()?
        .ok()?;
    use http_body_util::BodyExt;
    let status = resp.status().as_u16();
    resp.into_body().collect().await.ok()?;
    Some(status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tunnel_that_carries_nothing_is_cut() {
    let dir = scratch("idle");
    let pki = Pki::new(&dir);
    // The configured limit is a minute at least; the test cuts at 2 s.
    let timing = Timing {
        tunnel_idle: Some(Duration::from_secs(2)),
        ..fast_timing()
    };
    let env = start_relay_timed(&pki, &dir, "", timing).await;
    let mut laptop = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    laptop.wait_connected().await;

    let mut quiet = held_tunnel(&pki, env.port, "laptop-a").await;
    let mut busy = held_tunnel(&pki, env.port, "laptop-a").await;
    assert_eq!(health(&mut quiet).await, Some(200));
    // The busy tunnel carries something twice a second; the quiet one
    // carries nothing after its first request. (The machine itself closes
    // a connection idle for 10 s, so the test stays well under that.)
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        assert_eq!(
            health(&mut busy).await,
            Some(200),
            "the busy tunnel is kept"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(health(&mut quiet).await, None, "the quiet tunnel was cut");
    let closed: Vec<Value> = env
        .audit()
        .into_iter()
        .filter(|e| e["event"] == "session_closed")
        .collect();
    assert_eq!(closed.len(), 1, "{closed:?}");
    assert_eq!(closed[0]["reason"], "idle", "{closed:?}");

    // Configured, at least a minute, so heartbeats keep a live session.
    let bad = relay_yaml(&pki, &dir, "tunnel_idle_seconds: 59\n");
    assert!(actp_relay::config::Config::parse(&bad).is_err());
    let ok = relay_yaml(&pki, &dir, "tunnel_idle_seconds: 60\n");
    assert!(actp_relay::config::Config::parse(&ok).is_ok());
    drop(laptop);
}

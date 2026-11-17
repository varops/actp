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

/// A device certificate for `cn` with a fresh key, valid for `days` more,
/// issued a day ago.
fn device_for_days(pki: &Pki, cn: &str, file: &str, days: i64) -> (PathBuf, PathBuf) {
    device_issued(pki, cn, file, 24, days)
}

/// [`device_for_days`], issued `hours_ago`.
fn device_issued(pki: &Pki, cn: &str, file: &str, hours_ago: i64, days: i64) -> (PathBuf, PathBuf) {
    let (c, k) = pki.device_with(cn, None, |p| {
        p.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(hours_ago);
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
    let pinned_key = key_of(&first.0);
    assert!(
        env.audit_has("machine_key_refused", |e| e["machine"] == "laptop-a"
            && e["pinned_key"] == pinned_key
            && e["presented_key"] == key_of(&second.0)
            && e["repeats"] == 0)
    );
    // Its own record, once a minute per machine, whatever else is refused.
    assert!(is(&as_machine(&pki, env.port, &second).await, KEY_CHANGED));
    let refused = |env: &RelayEnv| {
        env.audit()
            .iter()
            .filter(|e| e["event"] == "machine_key_refused")
            .count()
    };
    assert_eq!(refused(&env), 1);
    // The listing shows the pin.
    let (_, list) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(list["machines"][0]["key"], pinned_key.as_str());
    assert!(list["machines"][0]["key_until"].is_string());
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
            && e["key"].is_null()
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

    // Re-pinning to a given key cuts the machine off at once, and only that
    // key is taken next: neither the old one, however quick, nor any other.
    let third = device_for_days(&pki, "laptop-a", "third", 365);
    for bad in [json!("AB".repeat(32)), json!("ab"), json!(7)] {
        let (status, b) = request(
            &pki,
            env.port,
            "POST",
            "/relay/v1/repin",
            ADMIN,
            Some(json!({"machine": "laptop-a", "reason": "x", "key": bad})),
        )
        .await;
        assert_eq!((status, b["error"].as_str()), (400, Some("bad_key")));
    }
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/repin",
        ADMIN,
        Some(json!({"machine": "laptop-a", "reason": "laptop replaced", "key": key_of(&third.0)})),
    )
    .await;
    assert_eq!(status, 200);
    laptop
        .wait_status(|s| matches!(s, Status::Disconnected { .. }))
        .await;
    assert!(
        env.audit_has("machine_offline", |e| e["machine"] == "laptop-a"
            && e["reason"] == "repinned")
    );
    assert!(is(&as_machine(&pki, env.port, &second).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &first).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &third).await, ACCEPTED));
    drop(laptop);

    // A blocked name (the test relay blocks lost-laptop) is never pinned:
    // its holder may be the one it was blocked against.
    let lost = pki.device("lost-laptop", None);
    let (status, _) = as_machine(&pki, env.port, &lost).await;
    assert_eq!(status, 403);
    assert!(
        !env.relay
            .machines()
            .iter()
            .any(|m| m.machine == "lost-laptop"),
        "a blocked name gets no pin"
    );

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
    // so a newer certificate with a new key that outlasts it is its renewal.
    let old = device_issued(&pki, "laptop-a", "old", 48, 10);
    let older = device_issued(&pki, "laptop-a", "older", 72, 365);
    let shorter = device_issued(&pki, "laptop-a", "shorter", 24, 5);
    let renewed = device_issued(&pki, "laptop-a", "renewed", 24, 365);
    let later = device_issued(&pki, "laptop-a", "later", 1, 365);
    let mut laptop = start_laptop(&pki, "laptop-a", env.port, old.clone()).await;
    laptop.wait_connected().await;
    // Issued before the pinned certificate, or ending before it: refused.
    assert!(is(&as_machine(&pki, env.port, &older).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &shorter).await, KEY_CHANGED));
    assert!(is(&as_machine(&pki, env.port, &renewed).await, ACCEPTED));
    // The machine on the old key is cut off at once, and cannot come back.
    assert!(
        env.audit_has("machine_offline", |e| e["machine"] == "laptop-a"
            && e["reason"] == "key_renewed")
    );
    laptop
        .wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    drop(laptop);
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

    // More than 90 days would leave a name open most of the time.
    let bad = relay_yaml(&pki, &dir, "machine_key_renewal_days: 91\n");
    assert!(actp_relay::config::Config::parse(&bad).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pins_that_cannot_be_read_stop_the_relay_from_starting() {
    let dir = scratch("pins-damaged");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let a = pki.device("laptop-a", None);
    assert!(is(&as_machine(&pki, env.port, &a).await, ACCEPTED));
    drop(env);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let path = dir.join("state").join("machines.json");
    assert!(std::fs::read_to_string(&path).unwrap().contains("laptop-a"));

    // Damaged: no start, and the file is left as it was.
    std::fs::write(&path, b"{\"laptop-a\": {\"first_seen\": 1, \"la").unwrap();
    let cfg = actp_relay::config::Config::parse(&relay_yaml(&pki, &dir, "")).unwrap();
    let err = actp_relay::Relay::with_timing(cfg, fast_timing())
        .err()
        .expect("refused");
    assert!(err.to_string().contains("pinned key"), "{err}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{\"laptop-a\": {\"first_seen\": 1, \"la"
    );
    // Moved aside, the relay starts and pins afresh.
    std::fs::rename(&path, path.with_extension("bad")).unwrap();
    let env = start_relay(&pki, &dir).await;
    assert!(is(&as_machine(&pki, env.port, &a).await, ACCEPTED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_key_cannot_take_a_machines_places_nor_a_machine_anyones() {
    let dir = scratch("wrong-key-cap");
    let pki = Pki::new(&dir);
    let env = start_relay_with(
        &pki,
        &dir,
        "max_connections_per_machine: 2\nmax_connections_per_ip: 3\n",
    )
    .await;
    let real = device_for_days(&pki, "laptop-a", "real", 365);
    let rogue = device_for_days(&pki, "laptop-a", "rogue", 365);
    assert!(is(&as_machine(&pki, env.port, &real).await, ACCEPTED));

    // Two connections with another key for the name, kept busy: they count
    // as anyone's, so the real machine still gets in.
    let _r1 = device_tls(&pki, env.port, &rogue).await;
    let _r2 = device_tls(&pki, env.port, &rogue).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // (Held, they would last until the relay's 10 s header timeout: the
    // real machine must get in well before that, and never be refused.)
    let mut laptop = start_laptop(&pki, "laptop-a", env.port, real.clone()).await;
    tokio::time::timeout(Duration::from_secs(3), laptop.wait_connected())
        .await
        .expect("the real machine connects at once");
    assert!(is(&as_machine(&pki, env.port, &real).await, ACCEPTED));
    assert!(!env.audit_has("connection_refused", |e| e["machine"] == "laptop-a"));
    drop((_r1, _r2, laptop));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // And a machine's own connections do not count against its address:
    // three held, and a caller from the same address still gets through.
    let b = pki.device("laptop-b", None);
    let c = pki.device("laptop-c", None);
    let _h = [
        device_tls(&pki, env.port, &b).await,
        device_tls(&pki, env.port, &b).await,
        device_tls(&pki, env.port, &c).await,
    ];
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (status, _) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(status, 200);
}

/// The SHA-256 of the public key in the certificate at `pem`, as hex.
fn key_of(pem: &std::path::Path) -> String {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use sha2::Digest;
    use x509_parser::prelude::{FromDer, X509Certificate};
    let der = CertificateDer::from_pem_file(pem).unwrap();
    let (_, x) = X509Certificate::from_der(der.as_ref()).unwrap();
    hex::encode(sha2::Sha256::digest(x.public_key().raw))
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

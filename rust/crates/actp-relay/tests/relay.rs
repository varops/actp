//! The relay end to end, in one process: a relay, two machines running
//! `actp_server` in relay mode with device certificates, and callers going
//! through the relay with the actp bridge library or plain HTTPS.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actp_relay::Relay;
use actp_server::relay::Status;
use common::*;
use rcgen::Issuer;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

// ---- tests ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_callers_to_the_right_machine() {
    let dir = scratch("route");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;

    // Each machine answers as itself.
    for m in ["laptop-a", "laptop-b"] {
        let (status, body) = request(
            &pki,
            env.port,
            "GET",
            &format!("/m/{m}/api/v1/info"),
            TOKEN,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["name"], m);
    }
    // The machine checks the caller's credentials, not the relay.
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        "actp_wrong",
        None,
    )
    .await;
    assert_eq!(status, 401);

    // A session through the relay reaches the agent on laptop-a only.
    let mut caller = Caller::start(&pki, env.port, "laptop-a");
    let init = caller
        .call(1, "initialize", json!({"protocolVersion": 1}))
        .await;
    assert!(init.get("result").is_some(), "{init}");
    eventually("the link on laptop-a", || a.srv.links().len() == 1).await;
    assert!(b.srv.links().is_empty());

    // Who is online, and the audit of the session.
    let (status, list) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(status, 200);
    let machines = list["machines"].as_array().unwrap();
    let online: Vec<&str> = machines
        .iter()
        .filter(|m| m["online"] == true)
        .map(|m| m["machine"].as_str().unwrap())
        .collect();
    assert_eq!(online, ["laptop-a", "laptop-b"]);
    let a_row = machines
        .iter()
        .find(|m| m["machine"] == "laptop-a")
        .unwrap();
    assert_eq!(a_row["sessions"], 1);
    assert!(a_row["last_seen"].is_string() && a_row["connected_since"].is_string());
    assert!(env.audit_has("session_open", |e| e["machine"] == "laptop-a"
        && e["agent"] == "test"
        && e["client_name"] == "relay-test"));
    assert!(env.audit_has("machine_online", |e| e["machine"] == "laptop-b"));
    // Never anything the session carried.
    let text = std::fs::read_to_string(env.dir.join("logs").join("audit.jsonl")).unwrap();
    assert!(!text.contains("protocolVersion") && !text.contains(TOKEN));

    // A machine that is not connected, and malformed addresses.
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-c/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (503, Some("machine_offline"))
    );
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/../relay/v1/machines",
        ADMIN,
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = request(&pki, env.port, "GET", "/relay/v1/machines", "", None).await;
    assert_eq!(status, 401);

    drop(caller);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn machines_need_a_device_certificate_from_the_org() {
    let dir = scratch("certs");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;

    // No client certificate: the machine routes refuse.
    let (status, body) = request(&pki, env.port, "GET", "/relay/v1/connect", "", None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("device_certificate_required"))
    );
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        &format!("/relay/v1/stream/{}", "ab".repeat(32)),
        "",
        None,
    )
    .await;
    assert_eq!(status, 401);

    // A certificate from another CA never connects.
    let (rp, rk, _) = ca("rogue CA");
    let rogue = Issuer::new(rp, rk);
    let mut r = start_laptop(
        &pki,
        "laptop-a",
        env.port,
        pki.device("laptop-a", Some(&rogue)),
    )
    .await;
    let s = r
        .wait_status(|s| matches!(s, Status::Disconnected { .. }))
        .await;
    assert!(matches!(s, Status::Disconnected { .. }));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(env.relay.machines().is_empty());

    // A blocked machine is refused even with a good certificate.
    let mut lost = start_laptop(
        &pki,
        "lost-laptop",
        env.port,
        pki.device("lost-laptop", None),
    )
    .await;
    lost.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    assert!(env.audit_has("machine_refused", |e| e["machine"] == "lost-laptop"));

    // A certificate whose name is not a valid address is refused.
    let mut odd = start_laptop(&pki, "odd name", env.port, pki.device("odd name", None)).await;
    odd.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    drop((r, lost, odd));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_org_wide_stop_drops_sessions_and_refuses_new_ones() {
    let dir = scratch("stop");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;
    let mut ca_ = Caller::start(&pki, env.port, "laptop-a");
    let mut cb = Caller::start(&pki, env.port, "laptop-b");
    assert!(
        ca_.call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    assert!(
        cb.call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    eventually("both links", || {
        a.srv.links().len() == 1 && b.srv.links().len() == 1
    })
    .await;

    // Pressing needs an admin token and a reason.
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        TOKEN,
        Some(json!({"reason": "x"})),
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({"reason": "suspicious activity"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stop"]["stopped"], true);
    assert_eq!(body["stop"]["by"], "dave");

    // Every session ends, on both machines, and the machines know.
    eventually("links ended", || {
        a.srv.links().is_empty() && b.srv.links().is_empty()
    })
    .await;
    eventually("machines stopped", || {
        a.srv.org_stopped() && b.srv.org_stopped()
    })
    .await;
    let r = tokio::time::timeout(Duration::from_secs(10), ca_.done)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err(), "the bridge must lose its session: {r:?}");

    // Nobody new gets through, and the machines are still listed online.
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!((status, body["error"].as_str()), (503, Some("org_stopped")));
    let (_, list) = request(&pki, env.port, "GET", "/relay/v1/machines", ADMIN, None).await;
    assert_eq!(list["stop"]["stopped"], true);
    assert!(
        list["machines"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["online"] == true)
    );
    assert!(env.audit_has("org_stop", |e| e["by"] == "dave"
        && e["reason"] == "suspicious activity"
        && e["sessions_dropped"] == 2));
    assert!(env.audit_has("session_closed", |e| e["reason"] == "org_stop"));

    // A machine that reconnects while the stop is on hears it in the hello.
    let mut c = start_laptop(&pki, "laptop-c", env.port, pki.device("laptop-c", None)).await;
    c.wait_connected().await;
    eventually("laptop-c stopped", || c.srv.org_stopped()).await;

    // The stop survives a relay restart.
    let cfg = (*env.relay.config()).clone();
    let again = Relay::with_timing(cfg, fast_timing()).unwrap();
    assert!(again.stop_state().stopped);
    drop(again);

    // Releasing lets callers through again.
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/release",
        ADMIN,
        Some(json!({"reason": "all clear"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    eventually("machines released", || {
        !a.srv.org_stopped() && !c.srv.org_stopped()
    })
    .await;
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(env.audit_has("org_release", |e| e["by"] == "dave"
        && e["reason"] == "all clear"));
    drop(cb);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_reconnects_after_a_drop() {
    let dir = scratch("reconnect");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let proxy = Proxy::start(env.port).await;
    let mut a = start_laptop(&pki, "laptop-a", proxy.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200);

    // The network drops: the machine goes offline at the relay and comes back.
    proxy.drop_all();
    a.wait_status(|s| !matches!(s, Status::Connected { .. }))
        .await;
    a.wait_connected().await;
    eventually("offline then online again", || {
        env.audit_has("machine_offline", |e| e["machine"] == "laptop-a")
            && env
                .audit()
                .iter()
                .filter(|e| e["event"] == "machine_online" && e["machine"] == "laptop-a")
                .count()
                >= 2
    })
    .await;
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let m = env.relay.machines();
    assert_eq!(m.len(), 1);
    assert!(m[0].online);

    // A machine that just vanishes is noticed through the missing pings.
    drop(a);
    proxy.drop_all();
    eventually("laptop-a offline", || {
        env.relay.machines().iter().all(|m| !m.online)
    })
    .await;
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (503, Some("machine_offline"))
    );
}

/// Dials a relay WebSocket route as a machine with `cert`.
async fn dial_as(
    pki: &Pki,
    port: u16,
    cert: &(PathBuf, PathBuf),
    path: &str,
    protocol: &str,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, u16> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let tls = actp_server::relay::client_tls(&actp_server::config::Relay {
        url: String::new(),
        cert: cert.0.to_string_lossy().into_owned(),
        key: cert.1.to_string_lossy().into_owned(),
        ca: pki.dir.join("relay-ca.pem").to_string_lossy().into_owned(),
    })
    .unwrap();
    let mut req = format!("wss://localhost:{port}{path}")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", protocol.parse().unwrap());
    match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        true,
        Some(tokio_tungstenite::Connector::Rustls(tls)),
    )
    .await
    {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("dial {path}: {e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_machine_asked_can_take_a_stream() {
    use actp_proto::relay::{Control, PROTOCOL_CONTROL, PROTOCOL_STREAM};
    use futures_util::StreamExt;
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::tungstenite::Message;

    let dir = scratch("steal");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let a = pki.device("laptop-a", None);
    let b = pki.device("laptop-b", None);
    let ctl = dial_as(&pki, env.port, &a, "/relay/v1/connect", PROTOCOL_CONTROL)
        .await
        .unwrap();
    // Read the control connection all the time, as a machine does, so pings
    // are answered; hand the control messages over.
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut ctl = ctl;
        while let Some(Ok(m)) = ctl.next().await {
            if let Message::Text(t) = m {
                if let Some(c) = Control::decode(t.as_str()) {
                    let _ = ctl_tx.send(c);
                }
            }
        }
    });
    let mut next = async || {
        tokio::time::timeout(Duration::from_secs(10), ctl_rx.recv())
            .await
            .expect("a control message in time")
            .expect("control connection open")
    };
    assert_eq!(
        next().await,
        Control::Hello {
            machine: "laptop-a".into(),
            stopped: false
        }
    );
    // The control route wants its subprotocol.
    assert_eq!(
        dial_as(&pki, env.port, &b, "/relay/v1/connect", "other")
            .await
            .err(),
        Some(400)
    );

    let port = env.port;
    let tls = pki.caller_tls();
    let caller = tokio::spawn(async move {
        request_with(tls, port, "GET", "/m/laptop-a/api/v1/info", TOKEN, None).await
    });
    let id = loop {
        if let Control::Open { stream } = next().await {
            break stream;
        }
    };
    // laptop-b cannot take laptop-a's stream, and trying does not use it up.
    let path = format!("/relay/v1/stream/{id}");
    assert_eq!(
        dial_as(&pki, env.port, &b, &path, PROTOCOL_STREAM)
            .await
            .err(),
        Some(404)
    );
    let ws = dial_as(&pki, env.port, &a, &path, PROTOCOL_STREAM)
        .await
        .unwrap();
    let mut io = actp_proto::wsio::WsIo::new(ws);
    let mut got = Vec::new();
    while !got.ends_with(b"\r\n\r\n") {
        got.push(io.read_u8().await.unwrap());
    }
    let head = String::from_utf8(got).unwrap();
    assert!(head.starts_with("GET /api/v1/info HTTP/1.1\r\n"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    );
    io.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"name\":\"fake\"}")
        .await
        .unwrap();
    io.flush().await.unwrap();
    let (status, body) = caller.await.unwrap();
    assert_eq!((status, body["name"].as_str()), (200, Some("fake")));
    // The same stream id cannot be taken twice.
    assert_eq!(
        dial_as(&pki, env.port, &a, &path, PROTOCOL_STREAM)
            .await
            .err(),
        Some(404)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_cuts_off_a_newly_blocked_machine() {
    let dir = scratch("reload");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    let mut caller = Caller::start(&pki, env.port, "laptop-a");
    assert!(
        caller
            .call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );

    let yaml = relay_yaml(&pki, &dir, "").replace("[lost-laptop]", "[lost-laptop, laptop-a]");
    let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    env.relay.reload(cfg, tls);
    eventually("laptop-a offline", || {
        env.relay.machines().iter().all(|m| !m.online)
    })
    .await;
    a.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("403")))
        .await;
    assert!(env.audit_has("session_closed", |e| e["reason"] == "blocked"));
    assert!(env.audit_has("machine_offline", |e| e["reason"] == "blocked"));
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 503);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callers_are_rate_limited_and_floods_do_not_flood_the_audit() {
    let dir = scratch("rate");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, "caller_rate: {per_second: 1, burst: 30}\n").await;
    let started = std::time::Instant::now();
    let mut statuses = Vec::new();
    for _ in 0..40 {
        statuses.push(
            request(&pki, env.port, "GET", "/m/laptop-x/health", "", None)
                .await
                .0,
        );
    }
    // The burst of 30, plus one a second refilled while the test ran.
    let refill = started.elapsed().as_secs() as usize + 1;
    let through = statuses.iter().filter(|s| **s == 503).count();
    let limited = statuses.iter().filter(|s| **s == 429).count();
    assert!((30..=30 + refill).contains(&through), "{statuses:?}");
    assert_eq!(through + limited, 40);
    assert!(limited >= 10 - refill.min(10), "{statuses:?}");
    // Of the refusals, 20 written, the rest counted.
    let refused = || {
        env.audit()
            .iter()
            .filter(|e| e["event"] == "caller_refused")
            .count()
    };
    assert_eq!(refused(), 20);
    let left_out = (through - 20) as u64;
    // Counted per flush, so possibly over several lines.
    eventually("the count of refusals left out", || {
        env.audit()
            .iter()
            .filter(|e| e["event"] == "refusals_not_logged" && e["kind"] == "caller_refused")
            .map(|e| e["count"].as_u64().unwrap_or(0))
            .sum::<u64>()
            == left_out
    })
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_cannot_be_recorded_says_so_and_is_recorded_later() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("unsaved");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let state = dir.join("state");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(state.join("probe"), b"x").is_ok() {
        return; // running as root: permissions do not stop writes
    }
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({"reason": "incident"})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (500, Some("stop_not_saved"))
    );
    assert_eq!(body["stop"]["stopped"], true);
    assert!(env.relay.stop_state().stopped, "the stop holds anyway");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    eventually("the stop recorded", || {
        env.audit_has("org_stop_saved", |_| true)
    })
    .await;
    let cfg = (*env.relay.config()).clone();
    assert!(
        Relay::with_timing(cfg, fast_timing())
            .unwrap()
            .stop_state()
            .stopped
    );
}

/// A relay config line naming revocation lists.
fn crls(paths: &[&std::path::Path]) -> String {
    let list: Vec<String> = paths.iter().map(|p| yaml_path(p)).collect();
    format!("device_crls: [{}]\n", list.join(", "))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_and_expired_certificates_are_refused_and_cut_off() {
    let dir = scratch("revoke");
    let pki = Pki::new(&dir);
    let empty = pki.crl("empty.crl", &[], false);
    let env = start_relay_with(&pki, &dir, &crls(&[&empty])).await;
    let mut a = start_laptop(
        &pki,
        "laptop-a",
        env.port,
        pki.device_with("laptop-a", None, |p| {
            p.serial_number = Some(rcgen::SerialNumber::from(1001u64))
        }),
    )
    .await;
    let mut b = start_laptop(
        &pki,
        "laptop-b",
        env.port,
        pki.device_with("laptop-b", None, |p| {
            p.serial_number = Some(rcgen::SerialNumber::from(1002u64))
        }),
    )
    .await;
    a.wait_connected().await;
    b.wait_connected().await;
    let mut caller = Caller::start(&pki, env.port, "laptop-a");
    assert!(
        caller
            .call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );

    // laptop-a's certificate is revoked: a reload cuts it off, with its
    // session, and it cannot come back; laptop-b stays.
    let revoked = pki.crl("revoked.crl", &[1001], false);
    let yaml = relay_yaml(&pki, &dir, &crls(&[&revoked]));
    let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    env.relay.reload(cfg, tls);
    a.wait_status(|s| !matches!(s, Status::Connected { .. }))
        .await;
    eventually("laptop-a cut off with its session", || {
        env.audit_has("machine_offline", |e| {
            e["machine"] == "laptop-a" && e["reason"] == "certificate_invalid"
        }) && env.audit_has("session_closed", |e| {
            e["machine"] == "laptop-a" && e["reason"] == "certificate_invalid"
        })
    })
    .await;
    drop(caller);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let online: Vec<String> = env
        .relay
        .machines()
        .into_iter()
        .filter(|m| m.online)
        .map(|m| m.machine)
        .collect();
    assert_eq!(online, ["laptop-b"]);

    // A list past its next update fails closed: everyone is cut off.
    let stale = pki.crl("stale.crl", &[], true);
    let yaml = relay_yaml(&pki, &dir, &crls(&[&stale]));
    let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    env.relay.reload(cfg, tls);
    eventually("nobody online", || {
        env.relay.machines().iter().all(|m| !m.online)
    })
    .await;
    b.wait_status(|s| !matches!(s, Status::Connected { .. }))
        .await;

    // An expired certificate never connects.
    let dir2 = scratch("expired");
    let pki2 = Pki::new(&dir2);
    let env2 = start_relay(&pki2, &dir2).await;
    let mut old = start_laptop(
        &pki2,
        "laptop-old",
        env2.port,
        pki2.device_with("laptop-old", None, |p| {
            p.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
            p.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        }),
    )
    .await;
    old.wait_status(|s| matches!(s, Status::Disconnected { .. }))
        .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(env2.relay.machines().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_timed_out_replaced_and_offline_machines() {
    use actp_proto::relay::PROTOCOL_CONTROL;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let dir = scratch("lifecycle");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, "max_streams_per_machine: 1\n").await;

    // One caller at a time: the second gets machine_busy.
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    let mut caller = Caller::start(&pki, env.port, "laptop-a");
    assert!(
        caller
            .call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (429, Some("machine_busy"))
    );

    // The machine goes away: its session ends at the relay.
    drop(a);
    eventually("the session cut", || {
        env.audit_has("session_closed", |e| {
            e["machine"] == "laptop-a" && e["reason"] == "machine_offline"
        })
    })
    .await;
    drop(caller);

    // A machine that never opens the stream: the caller gets machine_timeout.
    let c = pki.device("laptop-c", None);
    let first = dial_as(&pki, env.port, &c, "/relay/v1/connect", PROTOCOL_CONTROL)
        .await
        .unwrap();
    let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut ws = first;
        while let Some(m) = ws.next().await {
            let _ = first_tx.send(m.map(|m| matches!(m, Message::Close(_))));
        }
        let _ = first_tx.send(Ok(true));
    });
    eventually("laptop-c online", || {
        env.relay
            .machines()
            .iter()
            .any(|m| m.machine == "laptop-c" && m.online)
    })
    .await;
    let started = std::time::Instant::now();
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-c/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (504, Some("machine_timeout"))
    );
    assert!(started.elapsed() >= Duration::from_secs(4));

    // The same machine connects again: the older connection is closed.
    let second = dial_as(&pki, env.port, &c, "/relay/v1/connect", PROTOCOL_CONTROL)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(m) = first_rx.recv().await {
            if matches!(m, Ok(true) | Err(_)) {
                return true;
            }
        }
        true
    })
    .await
    .unwrap();
    assert!(closed);
    assert!(env.audit_has("machine_replaced", |e| e["machine"] == "laptop-c"));
    drop(second);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_that_cannot_be_recorded_leaves_the_stop_on() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("unreleased");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let (status, _) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/stop",
        ADMIN,
        Some(json!({"reason": "incident"})),
    )
    .await;
    assert_eq!(status, 200);
    let state = dir.join("state");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(state.join("probe"), b"x").is_ok() {
        return; // running as root: permissions do not stop writes
    }
    let (status, body) = request(
        &pki,
        env.port,
        "POST",
        "/relay/v1/release",
        ADMIN,
        Some(json!({"reason": "all clear"})),
    )
    .await;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        (status, body["error"].as_str()),
        (500, Some("not_released"))
    );
    assert!(env.relay.stop_state().stopped);
    // Who stopped and why is kept apart from the rotated audit log.
    let kept = std::fs::read_to_string(dir.join("logs").join("org_stops.jsonl")).unwrap();
    assert!(kept.contains("\"event\":\"org_stop\"") && kept.contains("incident"));
}

/// A fake relay: TLS with the relay's certificate, WebSockets on any path.
/// It sends `script` on every control connection and records the paths
/// machines dial.
struct FakeRelay {
    port: u16,
    dialed: Arc<std::sync::Mutex<Vec<String>>>,
}

// The callback's error type is set by tungstenite.
#[allow(clippy::result_large_err)]
async fn fake_relay(pki: &Pki, script: Vec<String>) -> FakeRelay {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    let cfg = actp_relay::config::Config::parse(&relay_yaml(pki, &pki.dir, "")).unwrap();
    let tls = actp_relay::tls::server_config(&cfg).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.config);
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let dialed: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let d2 = dialed.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let (acceptor, dialed, script) = (acceptor.clone(), d2.clone(), script.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let path = Arc::new(std::sync::Mutex::new(String::new()));
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
                dialed.lock().unwrap().push(path.clone());
                if path == "/relay/v1/connect" {
                    for m in &script {
                        let _ = ws.send(Message::text(m.clone())).await;
                    }
                }
                // Hold the connection open, answering pings.
                while let Some(Ok(_)) = ws.next().await {}
            });
        }
    });
    FakeRelay { port, dialed }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_machine_checks_what_the_relay_says() {
    use actp_proto::relay::Control;
    let dir = scratch("fake-relay");
    let pki = Pki::new(&dir);
    let open = |id: &str| Control::Open { stream: id.into() }.encode();
    let hello = Control::Hello {
        machine: "laptop-a".into(),
        stopped: false,
    }
    .encode();

    // Anything before the hello: the machine hangs up.
    let fake = fake_relay(&pki, vec![open(&"ab".repeat(32))]).await;
    let mut a = start_laptop(&pki, "laptop-a", fake.port, pki.device("laptop-a", None)).await;
    a.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("hello first")))
        .await;
    assert!(
        !fake
            .dialed
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.starts_with("/relay/v1/stream/"))
    );
    drop(a);

    // A malformed address in the hello: the machine hangs up.
    let bad_hello = Control::Hello {
        machine: "a/b".into(),
        stopped: false,
    }
    .encode();
    let fake = fake_relay(&pki, vec![bad_hello]).await;
    let mut b = start_laptop(&pki, "laptop-b", fake.port, pki.device("laptop-b", None)).await;
    b.wait_status(|s| matches!(s, Status::Disconnected { error } if error.contains("malformed")))
        .await;
    drop(b);

    // Malformed stream ids are not dialed, and no more streams are opened
    // than the machine allows at once.
    let script = vec![
        hello,
        open("../../relay/v1/connect"),
        open(&"AB".repeat(32)),
        open(&"01".repeat(32)),
        open(&"02".repeat(32)),
        open(&"03".repeat(32)),
    ];
    let fake = fake_relay(&pki, script).await;
    let mut c = start_laptop_full(
        &pki,
        "laptop-c",
        fake.port,
        pki.device("laptop-c", None),
        "",
        |o| o.max_streams = 1,
    )
    .await;
    c.wait_connected().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let streams: Vec<String> = fake
        .dialed
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.starts_with("/relay/v1/stream/"))
        .cloned()
        .collect();
    assert_eq!(streams, [format!("/relay/v1/stream/{}", "01".repeat(32))]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_sessions_are_never_resumed() {
    let dir = scratch("resume-tls");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    // One client config, so a resumable session would be reused.
    let tls = pki.caller_tls();
    for _ in 0..2 {
        let tcp = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
        let mut s = tokio_rustls::TlsConnector::from(tls.clone())
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        s.write_all(b"GET /health HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut s, &mut out).await;
        assert_eq!(
            s.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_per_address_are_capped_and_refusals_answered_are_throttled() {
    let dir = scratch("caps");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, "max_connections_per_ip: 2\n").await;
    // Two connections held (no TLS yet); the third is closed at once.
    let _one = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    let _two = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut three = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut three, &mut buf),
    )
    .await
    .expect("closed by the relay");
    assert!(matches!(n, Ok(0) | Err(_)));
    eventually("the refusal recorded", || {
        env.audit_has("connection_refused", |e| e["remote"] == "127.0.0.1")
    })
    .await;
    drop((_one, _two));

    // A machine's refusals of callers are throttled in the audit.
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..25 {
        let (status, _) = request(
            &pki,
            env.port,
            "GET",
            "/m/laptop-a/api/v1/info",
            "wrong",
            None,
        )
        .await;
        assert_eq!(status, 401);
    }
    let answered = env
        .audit()
        .iter()
        .filter(|e| e["event"] == "caller_answered")
        .count();
    assert_eq!(answered, 20);
    // Requests that worked on routes other than links are not recorded.
    let (status, _) = request(&pki, env.port, "GET", "/m/laptop-a/health", "", None).await;
    assert_eq!(status, 200);
    assert!(!env.audit_has("caller_answered", |e| e["status"] == 200));
}

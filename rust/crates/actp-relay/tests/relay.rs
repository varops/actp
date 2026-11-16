//! The relay end to end, in one process: a relay, two machines running
//! `actp_server` in relay mode with device certificates, and callers going
//! through the relay with the actp bridge library or plain HTTPS.

mod common;

use std::path::PathBuf;
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
    let mut ctl = dial_as(&pki, env.port, &a, "/relay/v1/connect", PROTOCOL_CONTROL)
        .await
        .unwrap();
    let next = |m: Option<Result<Message, _>>| match m {
        Some(Ok(Message::Text(t))) => Control::decode(t.as_str()).unwrap(),
        other => panic!("expected a control message, got {other:?}"),
    };
    assert_eq!(
        next(ctl.next().await),
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
        match next(ctl.next().await) {
            Control::Open { stream } => break stream,
            _ => continue,
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
    let mut statuses = Vec::new();
    for _ in 0..40 {
        statuses.push(
            request(&pki, env.port, "GET", "/m/laptop-x/health", "", None)
                .await
                .0,
        );
    }
    assert_eq!(statuses.iter().filter(|s| **s == 503).count(), 30);
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 10);
    // 30 refusals, 20 written, the rest counted.
    let refused = || {
        env.audit()
            .iter()
            .filter(|e| e["event"] == "caller_refused")
            .count()
    };
    assert_eq!(refused(), 20);
    eventually("the count of refusals left out", || {
        env.audit_has("refusals_not_logged", |e| {
            e["kind"] == "caller_refused" && e["count"] == 10
        })
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

//! Operators: callers whose certificates the relay gives a role. Who is
//! online, the relay's half of the audit, and the org-wide stop, through
//! the client library the IT app uses (`actp_client::ops`), and everyone
//! else refused.

mod common;

use std::sync::Arc;
use std::time::Duration;

use actp_client::ops::{AuditKind, AuditQuery, MachinesQuery, RelayOps};
use common::*;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const OPERATORS: &str = "operators:\n  - caller: it-bridge\n    may: [machines, audit, stop, release]\n  - caller: manager\n    may: [machines]\n  - caller: blocked-op\n    may: [machines, audit, stop, release]\n  - caller: revoked-op\n    may: [machines, audit, stop, release]\nblocked_callers: [blocked-op]\n";

fn relay_url(port: u16) -> String {
    format!("https://localhost:{port}")
}

/// The relay's management API as the holder of `cert`.
fn ops_as(pki: &Pki, cert: &(std::path::PathBuf, std::path::PathBuf), port: u16) -> RelayOps {
    RelayOps::new(&relay_url(port), pki.route_as(cert, "unused").relay_tls).unwrap()
}

fn it_bridge(pki: &Pki) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        pki.dir.join(format!("caller-{CALLER}.pem")),
        pki.dir.join(format!("caller-{CALLER}.key")),
    )
}

/// One request to the relay with `tls`; `Err` when TLS itself refused.
async fn try_request(
    tls: Arc<rustls::ClientConfig>,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Result<(u16, Value), String> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let mut req = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    use http_body_util::BodyExt;
    let req = req
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// Every operator route, as (method, path, body).
fn routes() -> Vec<(&'static str, &'static str, Option<Value>)> {
    let why = Some(json!({"reason": "x"}));
    vec![
        ("GET", "/relay/v1/machines", None),
        ("GET", "/relay/v1/audit", None),
        ("GET", "/relay/v1/stop", None),
        ("POST", "/relay/v1/stop", why.clone()),
        ("POST", "/relay/v1/release", why.clone()),
        (
            "POST",
            "/relay/v1/repin",
            Some(json!({"machine": "laptop-a", "reason": "x"})),
        ),
    ]
}

const OBO: (&str, &str) = ("X-Actp-On-Behalf-Of", "mallory@example.com");

// ---- the permissive-by-omission case ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nobody_but_an_operator_gets_anything() {
    let dir = scratch("ops-hostile");
    let pki = Pki::new(&dir);
    // revoked-op's certificate is on the caller revocation list.
    let revoked_cert = pki.caller_with("revoked-op", None, |p| {
        p.serial_number = Some(rcgen::SerialNumber::from(7007u64))
    });
    let crl = pki.caller_crl("callers.crl", &[7007]);
    let extra = format!("{OPERATORS}caller_crls: [{}]\n", yaml_path(&crl));
    let env = start_relay_with(&pki, &dir, &extra).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;

    let tls_of =
        |cert: &(std::path::PathBuf, std::path::PathBuf)| pki.route_as(cert, "x").relay_tls;
    // A caller certificate that opens tunnels, with no role.
    let tunnel_only = tls_of(&pki.caller("tunnel-only", None));
    // The machine's own device certificate.
    let device = tls_of(&pki.device("laptop-z", None));
    let blocked = tls_of(&pki.caller("blocked-op", None));
    let revoked = tls_of(&revoked_cert);
    // An org caller certificate with the operator's name, issued by
    // someone else's CA.
    let (fp, fk, _) = ca("someone else's CA");
    let foreign_ca = rcgen::Issuer::new(fp, fk);
    let foreign_dir = scratch("ops-hostile-foreign");
    std::fs::create_dir_all(&foreign_dir).unwrap();
    let foreign_pki = Pki {
        dir: foreign_dir.clone(),
        device_ca: rcgen::Issuer::new(ca("x").0, rcgen::KeyPair::generate().unwrap()),
        caller_ca: foreign_ca,
    };
    std::fs::copy(
        pki.dir.join("relay-ca.pem"),
        foreign_dir.join("relay-ca.pem"),
    )
    .unwrap();
    std::fs::copy(
        pki.dir.join("device-ca.pem"),
        foreign_dir.join("device-ca.pem"),
    )
    .unwrap();
    let impostor = foreign_pki
        .route_as(&foreign_pki.caller(CALLER, None), "x")
        .relay_tls;
    let operator = tls_of(&it_bridge(&pki));
    let manager = tls_of(&pki.caller("manager", None));

    let mut tried = 0;
    for (method, path, body) in routes() {
        // Nothing at all: 401. A machine's own certificate: 403. Nothing
        // else in the answer.
        for (tls, want) in [
            (pki.caller_tls(), (401, Some("unauthorized"))),
            (device.clone(), (403, Some("bad_caller_certificate"))),
        ] {
            let (status, b) = try_request(tls, env.port, method, path, &[OBO], body.clone())
                .await
                .unwrap();
            assert_eq!((status, b["error"].as_str()), want, "{method} {path}: {b}");
            assert!(
                b.get("machines").is_none() && b.get("events").is_none() && b.get("stop").is_none()
            );
            tried += 1;
        }
        // A caller certificate without a role.
        let (status, b) = try_request(
            tunnel_only.clone(),
            env.port,
            method,
            path,
            &[OBO],
            body.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            (status, b["error"].as_str()),
            (403, Some("not_an_operator")),
            "{method} {path}"
        );
        // An operator that is blocked, or whose certificate is revoked.
        let (status, b) = try_request(
            blocked.clone(),
            env.port,
            method,
            path,
            &[OBO],
            body.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            (status, b["error"].as_str()),
            (403, Some("caller_blocked")),
            "{method} {path}"
        );
        // A revoked certificate, and the operator's name on a certificate
        // from another CA, are refused at the TLS handshake: no HTTP at all.
        // (A certificate revoked after the handshake is refused per request:
        // operators_lose_their_role_on_a_live_connection.)
        for (who, tls) in [("revoked", revoked.clone()), ("impostor", impostor.clone())] {
            let r = try_request(tls, env.port, method, path, &[OBO], body.clone()).await;
            assert!(r.is_err(), "{who} {method} {path}: {r:?}");
        }
        // A real operator with a bad admin token: the token decides, and
        // there is no falling back to the certificate.
        let (status, _) = try_request(
            operator.clone(),
            env.port,
            method,
            path,
            &[OBO, ("Authorization", "Bearer actpr_wrong")],
            body.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, 401, "{method} {path}");
        let (status, _) = try_request(
            operator.clone(),
            env.port,
            method,
            path,
            &[OBO, ("Authorization", "Basic aXQ6aXQ=")],
            body.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, 401, "{method} {path}");
        tried += 1;
    }
    assert_eq!(tried, 18);

    // An operator may do only what it was given.
    let expect = [
        ("GET", "/relay/v1/machines", 200),
        ("GET", "/relay/v1/audit", 403),
        ("GET", "/relay/v1/stop", 200),
        ("POST", "/relay/v1/stop", 403),
        ("POST", "/relay/v1/release", 403),
        ("POST", "/relay/v1/repin", 403),
    ];
    for ((method, path, body), (_, _, want)) in routes().into_iter().zip(expect) {
        let (status, b) = try_request(manager.clone(), env.port, method, path, &[OBO], body)
            .await
            .unwrap();
        assert_eq!(status, want, "manager {method} {path}: {b}");
        if want == 403 {
            assert_eq!(b["error"], "operator_not_permitted");
        }
    }
    // Re-pinning stays an admin's, whatever the operator holds.
    let (status, b) = try_request(
        operator.clone(),
        env.port,
        "POST",
        "/relay/v1/repin",
        &[OBO],
        Some(json!({"machine": "laptop-a", "reason": "x"})),
    )
    .await
    .unwrap();
    assert_eq!(
        (status, b["error"].as_str()),
        (403, Some("operator_not_permitted"))
    );

    // None of it pressed the stop or moved a pin, and the machine is still
    // connected.
    assert!(!env.relay.stop_state().stopped);
    assert!(!env.audit_has("org_stop", |_| true));
    assert!(!env.audit_has("machine_repinned", |_| true));
    assert!(
        env.relay
            .machines()
            .iter()
            .any(|m| m.machine == "laptop-a" && m.online)
    );
    // The refusals are recorded, by caller and reason.
    assert!(
        env.audit_has("operator_refused", |e| e["caller"] == "tunnel-only"
            && e["reason"] == "not_an_operator")
    );
    assert!(
        env.audit_has("operator_refused", |e| e["caller"] == "manager"
            && e["reason"] == "operator_not_permitted")
    );
    assert!(env.audit_has("admin_refused", |_| true));

    // With no operators configured, the operator's certificate gets nothing.
    let dir2 = scratch("ops-none");
    let env2 = start_relay(&pki, &dir2).await;
    for (method, path, body) in routes() {
        let (status, b) = try_request(operator.clone(), env2.port, method, path, &[OBO], body)
            .await
            .unwrap();
        assert_eq!(
            (status, b["error"].as_str()),
            (403, Some("not_an_operator")),
            "{method} {path}"
        );
    }
    drop(a);
    let _ = std::fs::remove_dir_all(&foreign_dir);
}

// ---- who is online ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_sees_who_is_online_and_when_each_was_last_seen() {
    let dir = scratch("ops-online");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, OPERATORS).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;
    let ops = ops_as(&pki, &pki.caller("manager", None), env.port);
    let all = ops.machines(&MachinesQuery::default()).await.unwrap();
    assert_eq!(all.machines.len(), 2);
    assert!(
        all.machines
            .iter()
            .all(|m| m.online && m.connected_since.is_some())
    );
    assert!(!all.stop.stopped);

    // laptop-b goes away: it is listed offline, last seen before now.
    drop(b);
    eventually("laptop-b offline", || {
        env.relay
            .machines()
            .iter()
            .any(|m| m.machine == "laptop-b" && !m.online)
    })
    .await;
    let all = ops.machines(&MachinesQuery::default()).await.unwrap();
    let lb = all
        .machines
        .iter()
        .find(|m| m.machine == "laptop-b")
        .unwrap();
    assert!(!lb.online && lb.connected_since.is_none());
    assert!(lb.last_seen >= lb.first_seen, "{lb:?}");
    assert!(
        lb.last_seen.as_str() <= actp_relay::audit::rfc3339(std::time::SystemTime::now()).as_str()
    );

    let online = ops
        .machines(&MachinesQuery {
            online: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        online
            .machines
            .iter()
            .map(|m| m.machine.as_str())
            .collect::<Vec<_>>(),
        ["laptop-a"]
    );
    let one = ops
        .machines(&MachinesQuery {
            machines: vec!["laptop-b".into(), "never-seen".into()],
            online: None,
        })
        .await
        .unwrap();
    assert_eq!(
        one.machines
            .iter()
            .map(|m| m.machine.as_str())
            .collect::<Vec<_>>(),
        ["laptop-b"]
    );
    // A query the relay does not understand is refused, never ignored.
    let tls = pki.route_as(&pki.caller("manager", None), "x").relay_tls;
    for q in [
        "online=yes",
        "machine=a%2Fb",
        "machin=laptop-a",
        "machine=%FF",
    ] {
        let (status, body) = try_request(
            tls.clone(),
            env.port,
            "GET",
            &format!("/relay/v1/machines?{q}"),
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("bad_query")),
            "{q}"
        );
    }
    // Admin tokens still work.
    let admin = RelayOps::new(&relay_url(env.port), pki.caller_tls())
        .unwrap()
        .admin_token(Some(ADMIN.into()));
    assert_eq!(
        admin
            .machines(&MachinesQuery::default())
            .await
            .unwrap()
            .machines
            .len(),
        2
    );
    drop(a);
}

// ---- the org-wide stop, by an operator, and the audit ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operators_stop_drops_live_sessions_and_refuses_new_ones_until_released() {
    let dir = scratch("ops-stop");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, OPERATORS).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    a.wait_connected().await;

    // Dave, from IT, is on laptop-a through the IT app.
    let mut route = pki.route("laptop-a");
    route.on_behalf_of = Some("dave@example.com".into());
    let mut dave = Caller::start_with(&pki, env.port, "laptop-a", |o| o.relay = Some(route));
    assert!(
        dave.call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    eventually("dave's link", || a.srv.links().len() == 1).await;

    let ops = ops_as(&pki, &it_bridge(&pki), env.port);
    // The IT app must say whom it presses the stop for.
    match ops.stop("incident").await {
        Err(actp_client::Error::Status(s)) => {
            assert_eq!((s.status, s.code.as_str()), (400, "on_behalf_of_required"))
        }
        r => panic!("a stop for nobody: {r:?}"),
    }
    assert!(!env.relay.stop_state().stopped);
    assert_eq!(a.srv.links().len(), 1);

    // Dana presses it.
    let dana = ops.clone().on_behalf_of(Some("dana@example.com".into()));
    let s = dana
        .stop("suspicious activity on an IT account")
        .await
        .unwrap();
    assert!(s.stopped);
    assert_eq!(
        (s.by.as_str(), s.by_kind.as_str(), s.on_behalf_of.as_deref()),
        ("it-bridge", "operator", Some("dana@example.com"))
    );
    // Dave's session ends, and the machine knows of the stop.
    eventually("dave's link ended", || a.srv.links().is_empty()).await;
    eventually("laptop-a stopped", || a.srv.org_stopped()).await;
    let r = tokio::time::timeout(Duration::from_secs(10), dave.done)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err(), "the bridge must lose its session: {r:?}");
    // Nobody new gets through: not the IT app, not anyone else.
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
    let other = pki.caller("tunnel-only", None);
    match tunnel_request(
        &pki.route_as(&other, "laptop-a"),
        env.port,
        "laptop-a",
        "GET",
        "/api/v1/info",
        TOKEN,
        None,
    )
    .await
    {
        Err(Refused::Relay(503, b)) => assert_eq!(b["error"], "org_stopped"),
        r => panic!("a new session during the stop: {r:?}"),
    }
    // Pressing it again keeps the first record.
    let again = ops
        .clone()
        .on_behalf_of(Some("eve@example.com".into()))
        .stop("again")
        .await
        .unwrap();
    assert_eq!(again.on_behalf_of.as_deref(), Some("dana@example.com"));
    assert!(env.audit_has("org_stop_repeated", |e| e["on_behalf_of"]
        == "eve@example.com"
        && e["by"] == "it-bridge"));
    // Anyone with a role sees it.
    let manager = ops_as(&pki, &pki.caller("manager", None), env.port);
    let seen = manager.stop_state().await.unwrap();
    assert!(seen.stopped && seen.by == "it-bridge");
    // Still refused a while later: the stop holds until released.
    tokio::time::sleep(Duration::from_millis(500)).await;
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

    // Sam releases it, also with a reason and a name.
    match ops.release("all clear").await {
        Err(actp_client::Error::Status(s)) => assert_eq!(s.code, "on_behalf_of_required"),
        r => panic!("a release for nobody: {r:?}"),
    }
    let sam = ops.clone().on_behalf_of(Some("sam@example.com".into()));
    let s = sam.release("account secured, ticket 4411").await.unwrap();
    assert!(!s.stopped);
    assert_eq!(s.on_behalf_of.as_deref(), Some("sam@example.com"));
    eventually("laptop-a released", || !a.srv.org_stopped()).await;
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

    // The audit, as the IT app reads it: the stop and the release with
    // who, for whom and why, newest first.
    let stops = sam
        .audit(&AuditQuery {
            kinds: vec![AuditKind::Stops],
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        stops.events.iter().all(|e| e.event.starts_with("org_")),
        "{stops:?}"
    );
    let release = stops
        .events
        .iter()
        .find(|e| e.event == "org_release")
        .unwrap();
    assert_eq!(release.fields["on_behalf_of"], "sam@example.com");
    assert_eq!(release.fields["by_kind"], "operator");
    assert_eq!(release.fields["reason"], "account secured, ticket 4411");
    let stop = stops.events.iter().find(|e| e.event == "org_stop").unwrap();
    assert_eq!(stop.fields["by"], "it-bridge");
    assert_eq!(stop.fields["on_behalf_of"], "dana@example.com");
    assert_eq!(stop.fields["sessions_dropped"], 1);
    assert_eq!(
        stop.fields["caller_certificate"].as_str().map(str::len),
        Some(64)
    );
    assert!(release.time > stop.time);
    assert!(
        stops.events.iter().any(
            |e| e.event == "org_stop_repeated" && e.fields["on_behalf_of"] == "eve@example.com"
        )
    );
    // The stops a program pressed are found by its name too.
    let by_bridge = sam
        .audit(&AuditQuery {
            kinds: vec![AuditKind::Stops],
            caller: Some(CALLER.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(by_bridge.events.iter().any(|e| e.event == "org_stop"));
    assert!(by_bridge.events.iter().any(|e| e.event == "org_release"));

    // Who connected to laptop-a, when and for how long: dave's session,
    // ended by the stop.
    let sessions = sam
        .audit(&AuditQuery {
            kinds: vec![AuditKind::Sessions],
            machine: Some("laptop-a".into()),
            on_behalf_of: Some("dave@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let closed = sessions
        .events
        .iter()
        .find(|e| e.event == "session_closed")
        .expect("dave's session_closed");
    assert_eq!(closed.fields["reason"], "org_stop");
    assert_eq!(closed.fields["caller"], "it-bridge");
    assert!(closed.fields["seconds"].is_u64());
    assert!(closed.fields["opened_at"].as_str().unwrap() <= closed.time.as_str());
    let opened = sessions
        .events
        .iter()
        .find(|e| e.event == "session_open")
        .expect("dave's session_open");
    assert_eq!(opened.fields["session"], closed.fields["session"]);
    // Ids and names only: no addresses, nothing a session carried.
    let everything = sam
        .audit(&AuditQuery {
            limit: Some(1000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!everything.events.is_empty());
    for e in &everything.events {
        assert!(!e.fields.contains_key("remote"), "{e:?}");
        assert!(!e.fields.contains_key("error"), "{e:?}");
        assert!(
            !e.event.ends_with("_refused") || e.event == "machine_key_refused",
            "{e:?}"
        );
    }
    assert!(
        everything
            .events
            .iter()
            .any(|e| e.event == "machine_online")
    );
    // The record of the stop is kept apart from rotation too.
    let kept = std::fs::read_to_string(dir.join("logs").join("org_stops.jsonl")).unwrap();
    assert!(kept.contains("dana@example.com") && kept.contains("sam@example.com"));
    // A restarted relay still shows who released it.
    let cfg = (*env.relay.config()).clone();
    let again = actp_relay::Relay::with_timing(cfg, fast_timing()).unwrap();
    let st = again.stop_state();
    assert_eq!(
        (st.stopped, st.by_kind.as_str(), st.on_behalf_of.as_deref()),
        (false, "operator", Some("sam@example.com"))
    );
    drop(again);
    drop(a);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_audit_pages_newest_first_without_losing_an_event() {
    let dir = scratch("ops-audit");
    let pki = Pki::new(&dir);
    let env = start_relay_with(&pki, &dir, OPERATORS).await;
    let mut a = start_laptop(&pki, "laptop-a", env.port, pki.device("laptop-a", None)).await;
    let mut b = start_laptop(&pki, "laptop-b", env.port, pki.device("laptop-b", None)).await;
    a.wait_connected().await;
    b.wait_connected().await;
    for i in 0..5 {
        for m in ["laptop-a", "laptop-b"] {
            let (status, _) = request(
                &pki,
                env.port,
                "GET",
                &format!("/m/{m}/api/v1/info"),
                TOKEN,
                None,
            )
            .await;
            assert_eq!(status, 200, "{i} {m}");
        }
    }
    eventually("ten sessions closed", || {
        env.audit()
            .iter()
            .filter(|e| e["event"] == "session_closed")
            .count()
            == 10
    })
    .await;
    let ops = ops_as(&pki, &it_bridge(&pki), env.port);
    let mut q = AuditQuery {
        kinds: vec![AuditKind::Sessions],
        machine: Some("laptop-b".into()),
        limit: Some(3),
        ..Default::default()
    };
    let mut got = Vec::new();
    let mut pages = 0;
    loop {
        let p = ops.audit(&q).await.unwrap();
        pages += 1;
        assert!(p.events.len() <= 3);
        got.extend(p.events.iter().map(|e| (e.time.clone(), e.event.clone())));
        if !p.more {
            break;
        }
        q.cursor = p.next;
    }
    assert_eq!(pages, 4, "ten events in pages of three");
    assert_eq!(got.len(), 10);
    let mut sorted = got.clone();
    sorted.sort();
    sorted.reverse();
    sorted.dedup();
    assert_eq!(sorted, got, "newest first, each once");
    // since: only what came after.
    let since = got[3].0.clone();
    let recent = ops
        .audit(&AuditQuery {
            kinds: vec![AuditKind::Sessions],
            machine: Some("laptop-b".into()),
            since: Some(since),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(recent.events.len(), 4);
    // By the caller, and the kinds together.
    let mine = ops
        .audit(&AuditQuery {
            kinds: vec![AuditKind::Sessions, AuditKind::Machines],
            caller: Some(CALLER.into()),
            limit: Some(1000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(mine.events.len(), 20);
    // Malformed queries are refused, never widened.
    let tls = pki.route_as(&it_bridge(&pki), "x").relay_tls;
    for q in [
        "kind=everything",
        "limit=0",
        "limit=1001",
        "since=yesterday",
        "before=2026-11-18T10:00:00",
        "machine=a%2Fb",
        "machine=laptop-a&machine=laptop-b",
        "on_behalf_of=%0Aroot",
        "remote=127.0.0.1",
    ] {
        let (status, body) = try_request(
            tls.clone(),
            env.port,
            "GET",
            &format!("/relay/v1/audit?{q}"),
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("bad_query")),
            "{q}"
        );
    }
    drop(a);
    drop(b);
}

// ---- a role taken away on a connection that stays open ----

/// One kept-alive HTTPS connection to the relay.
struct Conn {
    sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
}

impl Conn {
    async fn open(tls: Arc<rustls::ClientConfig>, port: u16) -> Conn {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(tls)
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        let (sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        Conn { sender }
    }

    async fn get(&mut self, path: &str) -> (u16, Value) {
        use http_body_util::BodyExt;
        self.sender.ready().await.unwrap();
        let req = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let resp = self.sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operators_lose_their_role_on_a_live_connection() {
    let dir = scratch("ops-reload");
    let pki = Pki::new(&dir);
    let cert = pki.caller_with("ops-live", None, |p| {
        p.serial_number = Some(rcgen::SerialNumber::from(8008u64))
    });
    let fp = {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        use sha2::Digest;
        let der = CertificateDer::pem_file_iter(&cert.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        hex::encode(sha2::Sha256::digest(der.as_ref()))
    };
    let empty = pki.caller_crl("callers-empty.crl", &[]);
    let crls = |p: &std::path::Path| format!("caller_crls: [{}]\n", yaml_path(p));
    let role = "operators:\n  - caller: ops-live\n    may: [machines, audit]\n";
    let env = start_relay_with(&pki, &dir, &format!("{role}{}", crls(&empty))).await;
    let reload = |extra: String| {
        let yaml = relay_yaml(&pki, &dir, &extra);
        let cfg = actp_relay::config::Config::parse(&yaml).unwrap();
        let tls = actp_relay::tls::server_config(&cfg).unwrap();
        env.relay.reload(cfg, tls);
    };
    let mut c = Conn::open(pki.route_as(&cert, "x").relay_tls, env.port).await;
    assert_eq!(c.get("/relay/v1/machines").await.0, 200);

    // The role is taken away: the same connection gets nothing.
    reload(crls(&empty));
    let (status, b) = c.get("/relay/v1/machines").await;
    assert_eq!(
        (status, b["error"].as_str()),
        (403, Some("not_an_operator"))
    );
    // Given back, then the caller is blocked.
    reload(format!("{role}{}", crls(&empty)));
    assert_eq!(c.get("/relay/v1/audit").await.0, 200);
    reload(format!(
        "{role}blocked_callers: [ops-live]\n{}",
        crls(&empty)
    ));
    let (status, b) = c.get("/relay/v1/audit").await;
    assert_eq!((status, b["error"].as_str()), (403, Some("caller_blocked")));
    // Pinned to another certificate: the name alone is not enough.
    let other = format!("sha256:{}", "ab".repeat(32));
    reload(format!(
        "operators:\n  - caller: ops-live\n    may: [machines]\n    certificates: [{other}]\n{}",
        crls(&empty)
    ));
    let (status, b) = c.get("/relay/v1/machines").await;
    assert_eq!(
        (status, b["error"].as_str()),
        (403, Some("operator_certificate_not_listed"))
    );
    // Pinned to its own (in upper case, as some tools write it): taken.
    reload(format!(
        "operators:\n  - caller: ops-live\n    may: [machines]\n    certificates: [{other}, \"SHA256:{}\"]\n{}",
        fp.to_ascii_uppercase(),
        crls(&empty)
    ));
    assert_eq!(c.get("/relay/v1/machines").await.0, 200);
    // Its certificate is revoked: refused on the open connection.
    let revoked = pki.caller_crl("callers-revoked.crl", &[8008]);
    reload(format!("{role}{}", crls(&revoked)));
    let (status, b) = c.get("/relay/v1/machines").await;
    assert_eq!(
        (status, b["error"].as_str()),
        (403, Some("bad_caller_certificate"))
    );
    // Every reload records who holds a role.
    assert!(
        env.audit_has("config_reloaded", |e| e["operators"][0]["caller"]
            == "ops-live"
            && e["operators"][0]["may"] == json!(["machines", "audit"]))
    );
    assert!(env.audit_has("config_reloaded", |e| e["operators"] == json!([])));
}

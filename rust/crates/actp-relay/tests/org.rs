//! Org mode end to end: machines in relay mode that accept signed papers
//! instead of actp tokens, checked by a papers verifier (the shared-secret
//! test verifier here), and callers presenting papers through the relay.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actp_server::org::testing::SharedSecret;
use common::*;
use serde_json::json;

const GRANT: &str = "machines.operate";

fn org_block(machine: &str) -> String {
    format!(
        "  org:\n    machine: {machine}\n    require_grant: {GRANT}\n    access:\n      agents: [\"*\"]\n      workspaces: [\"*\"]\n      default_workspace: site\n"
    )
}

async fn org_laptop(pki: &Pki, machine: &str, relay_port: u16, v: &Arc<SharedSecret>) -> Laptop {
    let mut l = start_laptop_verified(
        pki,
        machine,
        relay_port,
        pki.device(machine, None),
        &org_block(machine),
        Some(v.clone()),
    )
    .await;
    l.wait_connected().await;
    l
}

fn papers(v: &SharedSecret, who: &str, machine: &str) -> String {
    v.issue(
        who,
        machine,
        json!({ GRANT: true }),
        Duration::from_secs(60),
    )
}

fn refusals(l: &Laptop) -> Vec<(String, String)> {
    l.audit()
        .into_iter()
        .filter(|e| e["event"] == "auth_refused")
        .map(|e| {
            (
                e["reason"].as_str().unwrap_or("").to_string(),
                e["principal"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Tries to resume `link` on `machine` with `bearer`; returns the HTTP status.
async fn resume_status(pki: &Pki, port: u16, machine: &str, link: &str, bearer: &str) -> u16 {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("wss://localhost:{port}/m/{machine}/actp/v1/agents/test/link")
        .into_client_request()
        .unwrap();
    let h = req.headers_mut();
    h.insert("Authorization", format!("Bearer {bearer}").parse().unwrap());
    h.insert("Sec-WebSocket-Protocol", "actp.v1".parse().unwrap());
    h.insert("Actp-Link-Id", link.parse().unwrap());
    h.insert("Actp-Last-Seq", "0".parse().unwrap());
    match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(pki.caller_tls())),
    )
    .await
    {
        Ok(_) => 101,
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => r.status().as_u16(),
        Err(e) => panic!("{e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn papers_open_sessions_on_the_machine_they_are_for() {
    let dir = scratch("org");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let v = Arc::new(SharedSecret::new(b"org secret"));
    let a = org_laptop(&pki, "laptop-a", env.port, &v).await;
    let b = org_laptop(&pki, "laptop-b", env.port, &v).await;

    let for_a = papers(&v, "dave", "laptop-a");
    let (status, body) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        &for_a,
        None,
    )
    .await;
    assert_eq!((status, body["name"].as_str()), (200, Some("laptop-a")));

    // A session as Dave, with fresh papers for every connection.
    let v2 = v.clone();
    let mut caller = Caller::start_with(&pki, env.port, "laptop-a", |o| {
        o.token_source = Some(Arc::new(move || {
            let p = papers(&v2, "dave", "laptop-a");
            Box::pin(async move { Ok(p) })
        }));
    });
    let init = caller
        .call(1, "initialize", json!({"protocolVersion": 1}))
        .await;
    assert!(init.get("result").is_some(), "{init}");
    eventually("Dave's link", || {
        a.srv.links().iter().any(|l| l.token == "papers:dave")
    })
    .await;
    assert!(
        a.audit()
            .iter()
            .any(|e| e["event"] == "link_opened" && e["token"] == "papers:dave")
    );

    // Someone else, with good papers of their own, cannot take the link over.
    let link = a.srv.links()[0].id.clone();
    let alice = papers(&v, "alice", "laptop-a");
    assert_eq!(
        resume_status(&pki, env.port, "laptop-a", &link, &alice).await,
        409
    );

    // Papers for laptop-a do not open laptop-b.
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-b/api/v1/info",
        &for_a,
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        refusals(&b),
        [("papers_other_machine".to_string(), "dave".to_string())]
    );
    assert!(b.srv.links().is_empty());

    // actp tokens mean nothing in org mode.
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        TOKEN,
        None,
    )
    .await;
    assert_eq!(status, 401);
    drop(caller);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_expired_and_ungranted_papers_are_refused() {
    let dir = scratch("org-bad");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let v = Arc::new(SharedSecret::new(b"org secret"));
    let a = org_laptop(&pki, "laptop-a", env.port, &v).await;

    let tampered = {
        // Signed for Dave, then the body swapped for Mallory's.
        let good = papers(&v, "dave", "laptop-a");
        let mac = good.split_once('.').unwrap().1.to_string();
        let mallory = papers(&v, "mallory", "laptop-a");
        format!("{}.{mac}", mallory.split_once('.').unwrap().0)
    };
    let cases: Vec<(&str, String, &str, &str)> = vec![
        ("an actp token", TOKEN.to_string(), "papers_malformed", ""),
        (
            "another issuer's key",
            papers(&SharedSecret::new(b"other"), "dave", "laptop-a"),
            "papers_signature",
            "",
        ),
        ("edited after signing", tampered, "papers_signature", ""),
        (
            "expired",
            v.issue("dave", "laptop-a", json!({ GRANT: true }), Duration::ZERO),
            "papers_expired",
            "dave",
        ),
        (
            "another machine",
            papers(&v, "dave", "laptop-b"),
            "papers_other_machine",
            "dave",
        ),
        (
            "no grant",
            v.issue(
                "dave",
                "laptop-a",
                json!({"recorder": true}),
                Duration::from_secs(60),
            ),
            "papers_no_grant",
            "dave",
        ),
        (
            "a grant that is not true",
            v.issue(
                "dave",
                "laptop-a",
                json!({ GRANT: "yes" }),
                Duration::from_secs(60),
            ),
            "papers_no_grant",
            "dave",
        ),
        (
            "no caller",
            v.sign(&json!({"machine": "laptop-a", "grants": { GRANT: true }, "expires": u64::MAX})),
            "papers_malformed",
            "",
        ),
    ];
    for (what, p, want, who) in &cases {
        let before = refusals(&a).len();
        let (status, _) = request(&pki, env.port, "GET", "/m/laptop-a/api/v1/info", p, None).await;
        assert_eq!(status, 401, "{what}");
        if who.is_empty() {
            // Papers nobody vouches for are refused without a trace in the
            // audit log, so junk cannot fill it.
            assert_eq!(refusals(&a).len(), before, "{what} ({want})");
        } else {
            let last = refusals(&a).last().cloned().unwrap_or_default();
            assert_eq!((last.0.as_str(), last.1.as_str()), (*want, *who), "{what}");
        }
    }
    // Nothing unverified is recorded as a person.
    assert!(refusals(&a).iter().all(|(_, p)| p != "mallory"));

    // The issuer cannot be asked: refused, not waved through.
    let good = papers(&v, "dave", "laptop-a");
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        &good,
        None,
    )
    .await;
    assert_eq!(status, 200);
    v.unavailable.store(true, Ordering::SeqCst);
    let before = refusals(&a).len();
    let (status, _) = request(
        &pki,
        env.port,
        "GET",
        "/m/laptop-a/api/v1/info",
        &good,
        None,
    )
    .await;
    // Not a refusal: try again later.
    assert_eq!(status, 503);
    // An issuer that cannot be asked vouches for nobody: not audited either.
    assert_eq!(refusals(&a).len(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_resumes_with_fresh_papers_after_a_drop() {
    let dir = scratch("org-resume");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let v = Arc::new(SharedSecret::new(b"org secret"));
    let a = org_laptop(&pki, "laptop-a", env.port, &v).await;
    let proxy = Proxy::start(env.port).await;
    let issued = Arc::new(Mutex::new(0u32));
    let (v2, i2) = (v.clone(), issued.clone());
    let mut caller = Caller::start_with(&pki, proxy.port, "laptop-a", move |o| {
        o.give_up_after = Duration::from_secs(10);
        o.token_source = Some(Arc::new(move || {
            *i2.lock().unwrap() += 1;
            // Papers that expire in two seconds.
            let p = v2.issue(
                "dave",
                "laptop-a",
                json!({ GRANT: true }),
                Duration::from_secs(2),
            );
            Box::pin(async move { Ok(p) })
        }));
    });
    assert!(
        caller
            .call(1, "initialize", json!({"protocolVersion": 1}))
            .await
            .get("result")
            .is_some()
    );
    eventually("Dave's link", || a.srv.links().len() == 1).await;

    // The first papers expire, then the connection drops while the issuer
    // cannot be asked: the bridge keeps trying instead of giving up.
    tokio::time::sleep(Duration::from_millis(3100)).await;
    v.unavailable.store(true, Ordering::SeqCst);
    proxy.drop_all();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    v.unavailable.store(false, Ordering::SeqCst);
    let new = caller
        .call(
            2,
            "session/new",
            json!({"cwd": "actp://site", "mcpServers": []}),
        )
        .await;
    assert!(new.get("result").is_some(), "{new}");
    assert!(
        *issued.lock().unwrap() >= 2,
        "fresh papers for the reconnect"
    );
    assert!(a.audit().iter().any(|e| e["event"] == "link_resumed"));
    assert_eq!(a.srv.links().len(), 1, "the same link, resumed");
}

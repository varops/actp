//! The issuer pass-through: machines ask the identity service configured
//! questions through the relay, with the relay's credentials there.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A stand-in for the identity service: records each request's head and
/// answers with `answer`.
struct FakeIssuer {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    answer: Arc<Mutex<(u16, String)>>,
    down: Arc<AtomicBool>,
}

async fn fake_issuer() -> FakeIssuer {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let answer = Arc::new(Mutex::new((200, r#"{"verdict":"current"}"#.to_string())));
    let down = Arc::new(AtomicBool::new(false));
    let (s, a, d) = (seen.clone(), answer.clone(), down.clone());
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = ln.accept().await {
            let (s, a, d) = (s.clone(), a.clone(), d.clone());
            tokio::spawn(async move {
                if d.load(Ordering::SeqCst) {
                    return; // hang up without an answer
                }
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                s.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_string());
                let (status, body) = a.lock().unwrap().clone();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\nset-cookie: x=y\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(resp.as_bytes()).await;
            });
        }
    });
    FakeIssuer {
        port,
        seen,
        answer,
        down,
    }
}

fn issuer_yaml(port: u16, extra: &str) -> String {
    format!(
        "issuer:\n  url: http://127.0.0.1:{port}/eunomia\n  headers:\n    X-Eunomia-Caller: relay\n    X-Eunomia-Caller-Secret: env:ACTP_TEST_ISSUER_SECRET\n  paths: [/v1/generation/signed]\n  rate: {{per_second: 1, burst: 3}}\n{extra}"
    )
}

/// One request to the relay as the holder of `cert` (a client certificate
/// and key); the status, the content type and the body.
async fn ask_as(
    pki: &Pki,
    port: u16,
    cert: Option<&(PathBuf, PathBuf)>,
    method: &str,
    target: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String, Value) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(pki.dir.join("relay-ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots);
    let tls = match cert {
        Some((c, k)) => builder
            .with_client_auth_cert(
                CertificateDer::pem_file_iter(c)
                    .unwrap()
                    .map(|c| c.unwrap())
                    .collect(),
                PrivateKeyDer::from_pem_file(k).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let mut req = http::Request::builder()
        .method(method)
        .uri(target)
        .header("host", "localhost");
    for (n, v) in extra_headers {
        req = req.header(*n, *v);
    }
    let req = req
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "nothing else comes back"
    );
    use http_body_util::BodyExt;
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        ctype,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

const QUESTION: &str = "/relay/v1/issuer/v1/generation/signed?tenant_id=acme&principal_id=usr_dana&expected=0123456789abcdef&nonce=kZ3v0w1T6mF2yq8Ha9cX0w";

fn set_secret() {
    // SAFETY: set before any relay in this test binary reads it, to the
    // same value every time.
    unsafe {
        std::env::set_var(
            "ACTP_TEST_ISSUER_SECRET",
            "relay-secret-0123456789abcdef0123",
        )
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn machines_ask_configured_questions_with_the_relays_credentials() {
    set_secret();
    let dir = scratch("issuer");
    let pki = Pki::new(&dir);
    let fake = fake_issuer().await;
    let env = start_relay_with(&pki, &dir, &issuer_yaml(fake.port, "")).await;
    let laptop = pki.device("laptop-a", None);
    let (status, ctype, body) = ask_as(
        &pki,
        env.port,
        Some(&laptop),
        "GET",
        QUESTION,
        &[
            ("authorization", "Bearer machine-secret"),
            ("x-eunomia-caller", "laptop-a"),
        ],
    )
    .await;
    assert_eq!((status, ctype.as_str()), (200, "application/json"));
    assert_eq!(body["verdict"], "current");
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let head = seen[0].to_ascii_lowercase();
    assert!(
        head.starts_with("get /eunomia/v1/generation/signed?tenant_id=acme&principal_id=usr_dana&expected=0123456789abcdef&nonce=kz3v0w1t6mf2yq8ha9cx0w http/1.1\r\n"),
        "{head}"
    );
    // The relay's credentials, never the machine's.
    assert!(head.contains("x-eunomia-caller: relay\r\n"), "{head}");
    assert!(head.contains("x-eunomia-caller-secret: relay-secret-0123456789abcdef0123\r\n"));
    assert!(
        !head.contains("laptop-a") && !head.contains("machine-secret"),
        "{head}"
    );
    // The issuer's refusals come back as they are.
    *fake.answer.lock().unwrap() = (422, r#"{"reason":"nonce_invalid"}"#.into());
    let (status, _, body) = ask_as(&pki, env.port, Some(&laptop), "GET", QUESTION, &[]).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (422, Some("nonce_invalid"))
    );
    // Nothing the machine asked is in the relay's audit.
    let audit = std::fs::read_to_string(dir.join("logs").join("audit.jsonl")).unwrap_or_default();
    assert!(!audit.contains("usr_dana"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_machines_and_only_the_configured_questions() {
    set_secret();
    let dir = scratch("issuer-who");
    let pki = Pki::new(&dir);
    let fake = fake_issuer().await;
    let env = start_relay_with(&pki, &dir, &issuer_yaml(fake.port, "")).await;
    let laptop = pki.device("laptop-a", None);
    let caller = pki.caller("it-bridge-2", None);
    for (cert, method, target, status, code) in [
        (None, "GET", QUESTION, 401, "device_certificate_required"),
        (
            Some(&caller),
            "GET",
            QUESTION,
            403,
            "bad_device_certificate",
        ),
        (Some(&laptop), "POST", QUESTION, 405, "method_not_allowed"),
        (
            Some(&laptop),
            "GET",
            "/relay/v1/issuer/v1/generation?principal_id=usr_dana",
            404,
            "issuer_path_not_forwarded",
        ),
        (
            Some(&laptop),
            "GET",
            "/relay/v1/issuer/v1/assert",
            404,
            "issuer_path_not_forwarded",
        ),
        (
            Some(&laptop),
            "GET",
            "/relay/v1/issuer/x/../v1/generation/signed",
            404,
            "issuer_path_not_forwarded",
        ),
    ] {
        let (got, _, body) = ask_as(&pki, env.port, cert, method, target, &[]).await;
        assert_eq!(
            (got, body["error"].as_str()),
            (status, Some(code)),
            "{method} {target}"
        );
    }
    let long = format!("{QUESTION}&pad={}", "x".repeat(3000));
    let (got, _, body) = ask_as(&pki, env.port, Some(&laptop), "GET", &long, &[]).await;
    assert_eq!(
        (got, body["error"].as_str()),
        (414, Some("issuer_query_too_long"))
    );
    assert!(
        fake.seen.lock().unwrap().is_empty(),
        "none of it reached the issuer"
    );
    // A blocked machine is refused like on every machine route.
    let lost = pki.device("lost-laptop", None);
    let (got, _, body) = ask_as(&pki, env.port, Some(&lost), "GET", QUESTION, &[]).await;
    assert_eq!(
        (got, body["error"].as_str()),
        (403, Some("machine_blocked"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_machine_is_limited_and_the_issuer_failing_is_a_502() {
    set_secret();
    let dir = scratch("issuer-limits");
    let pki = Pki::new(&dir);
    let fake = fake_issuer().await;
    let env = start_relay_with(&pki, &dir, &issuer_yaml(fake.port, "")).await;
    let a = pki.device("laptop-a", None);
    let b = pki.device("laptop-b", None);
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(
            ask_as(&pki, env.port, Some(&a), "GET", QUESTION, &[])
                .await
                .0,
        );
    }
    // A burst of 3, then refused (perhaps one refilled while asking).
    assert!(
        statuses.iter().filter(|s| **s == 429).count() >= 2,
        "{statuses:?}"
    );
    assert!(
        env.audit_has("issuer_refused", |e| e["machine"] == "laptop-a"
            && e["reason"] == "issuer_rate_limited")
    );
    // Another machine has its own allowance.
    assert_eq!(
        ask_as(&pki, env.port, Some(&b), "GET", QUESTION, &[])
            .await
            .0,
        200
    );
    // An issuer that hangs up, or answers too much: 502, never its answer.
    fake.down.store(true, Ordering::SeqCst);
    let c = pki.device("laptop-c", None);
    let (status, _, body) = ask_as(&pki, env.port, Some(&c), "GET", QUESTION, &[]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (502, Some("issuer_unavailable"))
    );
    fake.down.store(false, Ordering::SeqCst);
    *fake.answer.lock().unwrap() = (200, "x".repeat(100 << 10));
    let (status, _, _) = ask_as(&pki, env.port, Some(&c), "GET", QUESTION, &[]).await;
    assert_eq!(status, 502);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_an_issuer_section_nothing_is_forwarded() {
    let dir = scratch("issuer-off");
    let pki = Pki::new(&dir);
    let env = start_relay(&pki, &dir).await;
    let laptop = pki.device("laptop-a", None);
    let (status, _, body) = ask_as(&pki, env.port, Some(&laptop), "GET", QUESTION, &[]).await;
    assert_eq!((status, body["error"].as_str()), (404, Some("not_found")));
}

#[test]
fn issuer_configuration_is_checked() {
    let dir = scratch("issuer-config");
    let pki = Pki::new(&dir);
    let start = |extra: &str| {
        actp_relay::config::Config::parse(&relay_yaml(&pki, &dir, extra))
            .map_err(|e| e.to_string())
            .and_then(|cfg| {
                actp_relay::Relay::new(cfg)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
    };
    for (yaml, want) in [
        (
            "issuer:\n  url: https://issuer.example\n  paths: [/v1/x]\n",
            "needs ca",
        ),
        (
            "issuer:\n  url: http://issuer.example\n  paths: [/v1/x]\n",
            "loopback",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1/?x=1\n  paths: [/v1/x]\n",
            "query",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1\n  paths: []\n",
            "at least one path",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1\n  paths: [v1/x]\n",
            "must start with /",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1\n  paths: [/v1/../x]\n",
            "must start with /",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1\n  paths: [/v1/x]\n  headers:\n    X-Secret: env:ACTP_TEST_NOT_SET_ANYWHERE\n",
            "is not set",
        ),
        (
            "issuer:\n  url: http://127.0.0.1:1\n  paths: [/v1/x]\n  timeout_seconds: 0\n",
            "timeout_seconds",
        ),
    ] {
        let e = start(yaml).unwrap_err();
        assert!(e.contains(want), "{yaml}: {e}");
    }
    assert!(start("issuer:\n  url: http://127.0.0.1:1/eunomia\n  paths: [/v1/x]\n").is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_https_issuer_is_checked_against_its_roots() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    set_secret();
    let dir = scratch("issuer-tls");
    let pki = Pki::new(&dir);
    // The issuer serves the test PKI's server certificate (for localhost).
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        CertificateDer::pem_file_iter(pki.dir.join("relay.pem"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect(),
        PrivateKeyDer::from_pem_file(pki.dir.join("relay.key")).unwrap(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = r#"{"verdict":"changed"}"#;
                let _ = tls
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    let yaml = |ca: &std::path::Path| {
        format!(
            "issuer:\n  url: https://localhost:{port}\n  ca: {}\n  paths: [/v1/generation/signed]\n",
            yaml_path(ca)
        )
    };
    let laptop = pki.device("laptop-a", None);
    let env = start_relay_with(&pki, &dir, &yaml(&pki.dir.join("relay-ca.pem"))).await;
    let (status, _, body) = ask_as(&pki, env.port, Some(&laptop), "GET", QUESTION, &[]).await;
    assert_eq!((status, body["verdict"].as_str()), (200, Some("changed")));
    drop(env);
    // Roots that do not sign the issuer's certificate: no answer.
    let dir2 = scratch("issuer-tls-wrong");
    let env = start_relay_with(&pki, &dir2, &yaml(&pki.dir.join("device-ca.pem"))).await;
    let (status, _, body) = ask_as(&pki, env.port, Some(&laptop), "GET", QUESTION, &[]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (502, Some("issuer_unavailable"))
    );
}

//! Ports of Go's internal/wire tests: two endpoints over a real WebSocket.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actp_proto::conn::websocket_config;
use actp_proto::frame::{CLOSE_GOING_AWAY, T_BYE, T_MSG};
use actp_proto::{Endpoint, Frame, FrameConn, Options, ServeEnd, deliver_fn};
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<String>>>);

impl Collector {
    fn endpoint(&self, opts: Options) -> Endpoint {
        let c = self.0.clone();
        Endpoint::new(
            opts,
            deliver_fn(move |m| {
                let c = c.clone();
                async move {
                    c.lock().unwrap().push(m);
                    Ok(())
                }
            }),
        )
    }
    fn list(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

fn fast() -> Options {
    Options {
        heartbeat_every: Duration::from_millis(50),
        dead_after: Duration::from_millis(300),
        ack_delay: Duration::from_millis(20),
        tick: Duration::from_millis(10),
        ..Options::default()
    }
}

async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Serves `server` on a local WebSocket; every accepted socket is served in turn.
async fn pair(server: Endpoint) -> (String, mpsc::UnboundedReceiver<ServeEnd>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", ln.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let server = server.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(ws) =
                    tokio_tungstenite::accept_async_with_config(tcp, Some(websocket_config())).await
                {
                    let _ = tx.send(server.serve(FrameConn::from_websocket(ws), 0).await);
                }
            });
        }
    });
    (url, rx)
}

async fn dial(url: &str) -> FrameConn {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    FrameConn::from_websocket(ws)
}

#[tokio::test]
async fn messages_flow_both_ways_and_are_acked() {
    let (sc, cc) = (Collector::default(), Collector::default());
    let server = sc.endpoint(fast());
    let client = cc.endpoint(fast());
    let (url, _) = pair(server.clone()).await;
    let conn = dial(&url).await;
    let c2 = client.clone();
    tokio::spawn(async move { c2.serve(conn, 0).await });
    for i in 1..=120 {
        server.send(format!(r#"{{"n":{i}}}"#));
    }
    client.send(r#"{"hello":1}"#.into());
    wait_for("client to get 120", || cc.list().len() == 120).await;
    wait_for("server to get 1", || sc.list().len() == 1).await;
    wait_for("server outbox to drain", || server.outbox_bytes() == 0).await;
    assert_eq!(cc.list()[0], r#"{"n":1}"#);
    assert_eq!(cc.list()[119], r#"{"n":120}"#);
}

#[tokio::test]
async fn resume_replays_what_was_missed() {
    let (sc, cc) = (Collector::default(), Collector::default());
    let server = sc.endpoint(fast());
    let client = cc.endpoint(fast());
    let (url, mut ends) = pair(server.clone()).await;
    let conn = dial(&url).await;
    let c2 = client.clone();
    let first = tokio::spawn(async move { c2.serve(conn, 0).await });
    server.send(r#"{"n":1}"#.into());
    wait_for("first message", || cc.list().len() == 1).await;

    client.detach(CLOSE_GOING_AWAY, "test");
    first.await.unwrap();
    ends.recv().await.unwrap();
    server.send(r#"{"n":2}"#.into());
    server.send(r#"{"n":3}"#.into());
    client.send(r#"{"c":1}"#.into());

    let conn = dial(&url).await;
    let c2 = client.clone();
    tokio::spawn(async move { c2.serve(conn, 0).await });
    wait_for("replay", || cc.list().len() == 3).await;
    wait_for("client message after resume", || sc.list().len() == 1).await;
    assert_eq!(cc.list().join(","), r#"{"n":1},{"n":2},{"n":3}"#);
}

#[tokio::test]
async fn silent_peer_is_detected() {
    let server = Collector::default().endpoint(fast());
    let (url, mut ends) = pair(server).await;
    let (_ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap(); // never reads or writes
    let end = tokio::time::timeout(Duration::from_secs(3), ends.recv())
        .await
        .expect("silent peer not detected");
    assert_eq!(end, Some(ServeEnd::Dead));
}

#[tokio::test]
async fn bye_ends_serve() {
    let server = Collector::default().endpoint(fast());
    let client = Collector::default().endpoint(fast());
    let (url, mut ends) = pair(server).await;
    let conn = dial(&url).await;
    let c2 = client.clone();
    tokio::spawn(async move { c2.serve(conn, 0).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    client.send_control(Frame::of(T_BYE));
    let end = tokio::time::timeout(Duration::from_secs(3), ends.recv())
        .await
        .expect("bye not seen");
    assert_eq!(end, Some(ServeEnd::Bye));
}

#[tokio::test]
async fn new_socket_replaces_old() {
    let server = Collector::default().endpoint(fast());
    let (url, mut ends) = pair(server.clone()).await;
    let c1 = Collector::default().endpoint(fast());
    let conn = dial(&url).await;
    tokio::spawn(async move { c1.serve(conn, 0).await });
    let s2 = server.clone();
    wait_for("attach", move || s2.attached()).await;
    let cc2 = Collector::default();
    let c2 = cc2.endpoint(fast());
    let conn = dial(&url).await;
    tokio::spawn(async move { c2.serve(conn, 0).await });
    let end = tokio::time::timeout(Duration::from_secs(3), ends.recv())
        .await
        .expect("old socket not replaced");
    assert_eq!(end, Some(ServeEnd::Replaced));
    server.send(r#"{"x":1}"#.into());
    wait_for("new socket gets messages", || cc2.list().len() == 1).await;
}

#[tokio::test]
async fn window_stops_sending_without_acks() {
    let server = Collector::default().endpoint(Options {
        window_msgs: 5,
        ..fast()
    });
    let (url, _) = pair(server.clone()).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    for _ in 0..20 {
        server.send("{}".into());
    }
    let mut got = 0;
    let _ = tokio::time::timeout(Duration::from_millis(250), async {
        while let Some(Ok(m)) = ws.next().await {
            if let Message::Text(t) = m
                && Frame::decode(t.as_str()).unwrap().t == T_MSG
            {
                got += 1;
            }
        }
    })
    .await;
    assert_eq!(got, 5, "sent {got} messages without acks, want 5");
}

#[tokio::test]
async fn spool_spills_to_disk_and_replays() {
    let dir = tempdir();
    let path = dir.join("link.spool");
    let server = Collector::default().endpoint(Options {
        spool_path: Some(path.clone()),
        memory_limit: 100,
        ..fast()
    });
    for i in 1..=50 {
        server.send(format!(r#"{{"n":{i},"pad":"{}"}}"#, "x".repeat(20)));
    }
    assert_eq!(server.spool_error(), None);
    let meta = std::fs::metadata(&path).unwrap();
    assert!(meta.len() > 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o077, 0);
    }
    let (url, _) = pair(server.clone()).await;
    let cc = Collector::default();
    let client = cc.endpoint(fast());
    let conn = dial(&url).await;
    tokio::spawn(async move { client.serve(conn, 0).await });
    wait_for("replay of 50", || cc.list().len() == 50).await;
    for (i, m) in cc.list().iter().enumerate() {
        assert!(
            m.starts_with(&format!(r#"{{"n":{},"#, i + 1)),
            "message {} is {m}",
            i + 1
        );
    }
    let p2 = path.clone();
    wait_for("acks to empty the spool", move || {
        std::fs::metadata(&p2)
            .map(|m| m.len() == 0)
            .unwrap_or(false)
    })
    .await;
    server.close();
    assert!(!path.exists(), "spool file not removed");
}

#[tokio::test]
async fn duplicate_delivery_across_replace() {
    let count = Arc::new(AtomicI32::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let (c, r) = (count.clone(), release.clone());
    let server = Endpoint::new(
        fast(),
        deliver_fn(move |_| {
            let (c, r) = (c.clone(), r.clone());
            async move {
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    r.notified().await; // first delivery is slow (agent stdin full, ...)
                }
                Ok(())
            }
        }),
    );
    let (url, _) = pair(server.clone()).await;
    let client = Collector::default().endpoint(fast());
    let conn = dial(&url).await;
    let c2 = client.clone();
    let first = tokio::spawn(async move { c2.serve(conn, 0).await });
    client.send(r#"{"n":1}"#.into());
    let c3 = count.clone();
    wait_for("first delivery started", move || {
        c3.load(Ordering::SeqCst) == 1
    })
    .await;
    client.detach(CLOSE_GOING_AWAY, "drop");
    first.await.unwrap();
    let conn = dial(&url).await;
    let last = server.last_received();
    let c2 = client.clone();
    tokio::spawn(async move { c2.serve(conn, last).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "message seq 1 delivered more than once"
    );
}

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "actp-proto-test-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

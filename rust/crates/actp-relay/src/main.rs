//! `actp-relay`: the relay server (docs/relay.md).

use std::path::PathBuf;
use std::time::Duration;

use actp_relay::config::{self, Config};
use tokio_util::sync::CancellationToken;

const VERSION: &str = match option_env!("ACTP_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const USAGE: &str = "actp-relay – the server machines dial out to and callers connect through

Usage:
  actp-relay serve --config FILE
  actp-relay token create          print a new admin token and the hash for the config
  actp-relay version
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match rt.block_on(run(args)) {
        Ok(()) => 0,
        Err((code, msg)) => {
            if !msg.is_empty() {
                eprintln!("actp-relay: {msg}");
            }
            code
        }
    };
    rt.shutdown_timeout(Duration::from_millis(100));
    std::process::exit(code);
}

async fn run(args: Vec<String>) -> Result<(), (i32, String)> {
    let strs: Vec<&str> = args.iter().map(String::as_str).collect();
    match strs.as_slice() {
        ["serve", "--config", path] => serve(PathBuf::from(path)).await,
        ["token", "create"] => {
            let t = config::generate_token();
            println!("token: {t}");
            println!("hash:  {}", config::hash_token(&t));
            Ok(())
        }
        ["version" | "--version" | "-v"] => {
            println!("actp-relay {VERSION}");
            Ok(())
        }
        _ => {
            print!("{USAGE}");
            Err((2, String::new()))
        }
    }
}

async fn serve(path: PathBuf) -> Result<(), (i32, String)> {
    let fail = |e: String| (1, e);
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let cfg = Config::load(&path).map_err(fail)?;
    let tls = actp_relay::tls::server_config(&cfg).map_err(|e| fail(e.to_string()))?;
    if cfg.admin_tokens.is_empty() {
        tracing::warn!("no admin tokens: the machine list and the org-wide stop cannot be used");
    }
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .map_err(|e| fail(format!("listen {}: {e}", cfg.listen)))?;
    let listen = cfg.listen.clone();
    let relay = actp_relay::Relay::new(cfg).map_err(|e| fail(e.to_string()))?;
    let stop = CancellationToken::new();
    let task = {
        let (relay, stop) = (relay.clone(), stop.clone());
        tokio::spawn(async move { relay.serve(listener, tls, stop).await })
    };
    tracing::info!(addr = %listen, version = VERSION, "actp relay listening");
    shutdown_signal().await;
    tracing::info!("stopping");
    stop.cancel();
    let _ = task.await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

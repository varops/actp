//! A thin `actp` binary over the libraries: `actp serve` and the bridge
//! (`actp bridge <agent>@<server>`, or the short form `actp <agent>@<server>`).
//! Same flags, messages and exit codes as the Go binary for these commands.
//! The tray, dashboard, tunnel, Docker and installer commands are not here.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actp_server::config::{self, Config};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

const VERSION: &str = match option_env!("ACTP_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const USAGE: &str = "actp – Agent Client Transport Protocol (ACP over HTTP), Rust build

Usage:
  actp serve [--config FILE]
  actp <agent>@<server> [options]        bridge to a remote agent
  actp bridge <agent>@<server> [options]
  actp version

Bridge options:
  --token-env NAME     read the token from this environment variable
  --token-file PATH    read the token from this file
  --cwd VALUE          replace every cwd the client sends, e.g. actp://website
  --map FROM=TO        rewrite cwd values starting with FROM (repeatable)
  --name NAME          client name shown on the server (default: host name)
  --log-file PATH      write debug logs here (stdout is ACP)
  --config FILE        config file with saved remotes
";

/// A failure with an exit code; the message (if any) goes to stderr as `actp: <msg>`.
struct Exit(i32, Option<String>);

impl<E: std::fmt::Display> From<E> for Exit {
    fn from(e: E) -> Self {
        Exit(1, Some(e.to_string()))
    }
}

fn fail(msg: impl Into<String>) -> Exit {
    Exit(1, Some(msg.into()))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match rt.block_on(run(args)) {
        Ok(()) => 0,
        Err(Exit(code, msg)) => {
            if let Some(m) = msg {
                eprintln!("actp: {m}");
            }
            code
        }
    };
    rt.shutdown_timeout(Duration::from_millis(100));
    std::process::exit(code);
}

async fn run(args: Vec<String>) -> Result<(), Exit> {
    let Some((cmd, rest)) = args.split_first() else {
        print!("{USAGE}");
        return Err(Exit(2, None));
    };
    match cmd.as_str() {
        "serve" | "server" => cmd_serve(rest).await,
        "bridge" => cmd_bridge(rest).await,
        "version" | "--version" | "-v" => {
            println!("actp {VERSION}");
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        // Loads and validates a config like the server does; for the conformance tests.
        "check-config" => {
            let f = Flags::parse(rest, &["config"], &[])?;
            Config::load(f.get("config").map(PathBuf::from).as_deref())?;
            println!("ok");
            Ok(())
        }
        c if c.contains('@') && !c.starts_with('-') => cmd_bridge(&args).await,
        c => {
            eprint!("{USAGE}");
            Err(fail(format!("unknown command \"{c}\"")))
        }
    }
}

/// Go `flag` style: `-name value`, `--name value`, `-name=value`, booleans without a value.
struct Flags {
    values: Vec<(String, String)>,
    rest: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], with_value: &[&str], booleans: &[&str]) -> Result<Flags, Exit> {
        let mut values = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                i += 1;
                break;
            }
            let Some(name) = a
                .strip_prefix("--")
                .or_else(|| a.strip_prefix('-'))
                .filter(|n| !n.is_empty() && !a.starts_with("---"))
            else {
                break;
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (name.to_string(), None),
            };
            if booleans.contains(&name.as_str()) {
                values.push((name, inline.unwrap_or_else(|| "true".into())));
            } else if with_value.contains(&name.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i).cloned().ok_or_else(|| {
                            eprintln!("flag needs an argument: -{name}");
                            Exit(2, None)
                        })?
                    }
                };
                values.push((name, v));
            } else {
                eprintln!("flag provided but not defined: -{name}");
                return Err(Exit(2, None));
            }
            i += 1;
        }
        Ok(Flags {
            values,
            rest: args[i..].to_vec(),
        })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> impl Iterator<Item = &str> {
        self.values
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

async fn cmd_bridge(args: &[String]) -> Result<(), Exit> {
    let Some((target, rest)) = args.split_first().filter(|(t, _)| !t.starts_with('-')) else {
        return Err(fail("usage: actp <agent>@<server> [options]"));
    };
    let f = Flags::parse(
        rest,
        &[
            "token-env",
            "token-file",
            "cwd",
            "name",
            "log-file",
            "config",
            "p",
            "prompt",
            "map",
        ],
        &["yes", "no"],
    )?;
    if !f.rest.is_empty() {
        let prompt = f.get("p").or(f.get("prompt")).unwrap_or("");
        if prompt.is_empty() && f.rest.len() == 1 {
            let a = &f.rest[0];
            return Err(fail(format!(
                "unexpected argument {a:?}. To send it as a prompt, use: actp {target} -p {a:?}"
            )));
        }
        return Err(fail(format!("unexpected arguments: {}", f.rest.join(" "))));
    }
    let mut maps = Vec::new();
    for m in f.all("map") {
        match m.split_once('=') {
            Some((from, to)) if !from.is_empty() && !to.is_empty() => maps.push(actp_client::Map {
                from: from.into(),
                to: to.into(),
            }),
            _ => {
                eprintln!("invalid value {m:?} for flag -map: --map needs FROM=TO, got {m:?}");
                return Err(Exit(2, None));
            }
        }
    }
    let Some((agent, server)) = target
        .split_once('@')
        .filter(|(a, s)| !a.is_empty() && !s.is_empty())
    else {
        return Err(fail(format!("expected <agent>@<server>, got {target:?}")));
    };
    let cfg = Config::load(f.get("config").map(PathBuf::from).as_deref())?;
    let (base_url, remote) = resolve_server(&cfg, server);
    let token = resolve_token(
        f.get("token-env").unwrap_or(""),
        f.get("token-file").unwrap_or(""),
        remote,
    )?;
    if f.get("p")
        .or(f.get("prompt"))
        .is_some_and(|p| !p.is_empty())
    {
        return Err(fail(
            "-p (one prompt from a terminal) is not part of the Rust build; use the Go actp for it",
        ));
    }
    let name = f.get("name").map(str::to_string).unwrap_or_else(hostname);
    if std::io::stdin().is_terminal() {
        eprintln!(
            "actp: bridging {target} for an ACP client: it expects JSON-RPC on stdin. To type a prompt, use: actp {target} -p \"…\""
        );
    }
    if let Some(path) = f.get("log-file") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let _ = tracing_subscriber::fmt()
            .with_writer(Arc::new(file))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    // A signal counts as the client leaving: stdin ends and the bridge says bye.
    let (stdin_r, mut stdin_w) = tokio::io::duplex(64 << 10);
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 64 << 10];
        let stop = shutdown_signal();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => return,
                n = stdin.read(&mut buf) => match n {
                    Ok(0) | Err(_) => return,
                    Ok(n) => if stdin_w.write_all(&buf[..n]).await.is_err() { return },
                },
            }
        }
    });
    let opts = actp_client::Options {
        agent: agent.into(),
        base_url,
        token,
        client_name: name,
        cwd: f.get("cwd").unwrap_or("").into(),
        maps,
        ..Default::default()
    };
    match actp_client::run(opts, stdin_r, tokio::io::stdout()).await {
        Ok(()) => Ok(()),
        Err(e @ actp_client::Error::Lost(_)) => {
            eprintln!("actp: {e}");
            Err(Exit(1, None))
        }
        Err(e) => Err(e.into()),
    }
}

/// Turns the part after `@` into a base URL, using saved remotes.
fn resolve_server<'a>(cfg: &'a Config, server: &str) -> (String, Option<&'a config::Remote>) {
    if server.contains("://") {
        return (server.to_string(), None);
    }
    if let Some(r) = cfg.remote(server) {
        return (r.url.clone(), Some(r));
    }
    let host = split_host(server);
    if is_loopback(host.trim_start_matches('[').trim_end_matches(']')) {
        return (format!("http://{server}"), None);
    }
    (format!("https://{server}"), None)
}

/// The host of `host:port` (or the whole string), like `net.SplitHostPort`.
fn split_host(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('[')
        && let Some((h, port)) = rest.split_once(']')
        && port.starts_with(':')
    {
        return h;
    }
    match s.rsplit_once(':') {
        Some((h, _)) if !h.contains(':') => h,
        _ => s,
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Never takes a token from the command line: other users can see it there.
fn resolve_token(env: &str, file: &str, remote: Option<&config::Remote>) -> Result<String, Exit> {
    let read = |env: &str, file: &str| -> Result<String, Exit> {
        if !env.is_empty() {
            let v = std::env::var(env).unwrap_or_default().trim().to_string();
            if v.is_empty() {
                return Err(fail(format!("environment variable {env} is empty")));
            }
            return Ok(v);
        }
        let data = std::fs::read_to_string(config::expand_home(file))
            .map_err(|e| fail(format!("open {file}: {e}")))?;
        Ok(data.trim().to_string())
    };
    if !env.is_empty() || !file.is_empty() {
        return read(env, file);
    }
    if let Ok(v) = std::env::var("ACTP_TOKEN")
        && !v.trim().is_empty()
    {
        return Ok(v.trim().to_string());
    }
    if let Some(r) = remote {
        if !r.token_env.is_empty() || !r.token_file.is_empty() {
            return read(&r.token_env, &r.token_file);
        }
        if r.token_keychain {
            return Err(fail(format!(
                "the token for {} is in the OS keychain, which the Rust build does not read; use --token-env or --token-file",
                r.name
            )));
        }
    }
    Err(fail(
        "no token: use --token-env, --token-file, ACTP_TOKEN, or a saved remote with a token",
    ))
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes at most buf.len() bytes into buf.
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        String::new()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
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

async fn cmd_serve(args: &[String]) -> Result<(), Exit> {
    let f = Flags::parse(args, &["config"], &["dashboard"])?;
    if f.get("dashboard").is_some_and(|v| v == "true") {
        return Err(fail("--dashboard is not part of the Rust build"));
    }
    let path = f.get("config").map(PathBuf::from);
    let cfg = Config::load(path.as_deref())?;
    let Some(sc) = cfg.server.clone() else {
        return Err(fail(format!(
            "{} has no server section",
            cfg.path().display()
        )));
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    check_listen(&sc)?;
    if sc.tunnel.mode != "off" {
        if !sc.tls_cert.is_empty() {
            return Err(fail(
                "the tunnel needs the server on plain HTTP on loopback; remove tls_cert and tls_key",
            ));
        }
        tracing::warn!(mode = %sc.tunnel.mode, "the Rust build does not run tunnels; serving on the listen address only");
    }
    if sc.tokens.is_empty() {
        tracing::warn!(
            "no tokens configured: nobody can connect. Create one with `actp token create --name NAME`."
        );
    }
    if sc.agents.is_empty() {
        tracing::warn!("no agents configured");
    }
    let listener = tokio::net::TcpListener::bind(&sc.listen).await?;
    let server = actp_server::Server::new(
        sc.clone(),
        actp_server::Options {
            version: VERSION.into(),
            probe_on_start: true,
            ..Default::default()
        },
    )
    .await?;
    let stop = CancellationToken::new();
    let http = {
        let server = server.clone();
        let stop = stop.clone();
        let tls = if sc.tls_cert.is_empty() {
            None
        } else {
            Some(actp_server::http::tls_config_from_pem(
                &sc.tls_cert,
                &sc.tls_key,
            )?)
        };
        tokio::spawn(async move {
            match tls {
                Some(cfg) => {
                    actp_server::http::serve(
                        server,
                        actp_server::http::TlsAcceptor {
                            tcp: listener,
                            tls: tokio_rustls::TlsAcceptor::from(cfg),
                        },
                        stop,
                    )
                    .await
                }
                None => {
                    actp_server::http::serve(server, actp_server::http::TcpAcceptor(listener), stop)
                        .await
                }
            }
        })
    };
    tracing::info!(addr = %sc.listen, version = VERSION, agents = sc.agents.len(), "actp server listening");

    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        #[cfg(unix)]
        let reload = hup.recv();
        #[cfg(not(unix))]
        let reload = std::future::pending::<Option<()>>();
        tokio::select! {
            _ = shutdown_signal() => break,
            _ = reload => {
                match Config::load(path.as_deref()) {
                    Ok(c) => match c.server {
                        Some(next) => {
                            let running = server.config();
                            if next.listen != running.listen || next.tls_cert != running.tls_cert {
                                tracing::warn!("listen and TLS changes need a restart; other changes apply now");
                            }
                            server.reload(next);
                        }
                        None => tracing::error!(error = "the server section is gone from the config", "config reload failed, keeping the old config"),
                    },
                    Err(e) => tracing::error!(error = %e, "config reload failed, keeping the old config"),
                }
            }
        }
    }
    tracing::info!("stopping: waiting up to 30 s for running turns");
    server.close(Duration::from_secs(30)).await;
    stop.cancel();
    let _ = http.await;
    Ok(())
}

/// Refuses plain HTTP on a public address unless told it sits behind a TLS proxy.
fn check_listen(sc: &config::Server) -> Result<(), Exit> {
    let host = match sc.listen.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => {
            return Err(fail(format!(
                "listen {:?}: missing port in address",
                sc.listen
            )));
        }
    };
    if is_loopback(host) || !sc.tls_cert.is_empty() || sc.insecure_listen {
        return Ok(());
    }
    Err(fail(format!(
        "listen {:?} is not a loopback address: set tls_cert and tls_key, or insecure_listen: true behind a TLS proxy",
        sc.listen
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_like_go() {
        let f = Flags::parse(
            &strs(&[
                "--token-env",
                "T",
                "-cwd=actp://w",
                "--map",
                "a=b",
                "-map",
                "c=d",
                "--yes",
                "extra",
            ]),
            &["token-env", "cwd", "map"],
            &["yes"],
        )
        .ok()
        .unwrap();
        assert_eq!(f.get("token-env"), Some("T"));
        assert_eq!(f.get("cwd"), Some("actp://w"));
        assert_eq!(f.all("map").collect::<Vec<_>>(), ["a=b", "c=d"]);
        assert_eq!(f.get("yes"), Some("true"));
        assert_eq!(f.rest, ["extra"]);
        assert!(Flags::parse(&strs(&["--nope"]), &[], &[]).is_err());
    }

    #[test]
    fn servers_resolve_like_go() {
        let cfg = Config::default();
        assert_eq!(
            resolve_server(&cfg, "localhost:7860").0,
            "http://localhost:7860"
        );
        assert_eq!(
            resolve_server(&cfg, "127.0.0.1:7860").0,
            "http://127.0.0.1:7860"
        );
        assert_eq!(resolve_server(&cfg, "[::1]:7860").0, "http://[::1]:7860");
        assert_eq!(
            resolve_server(&cfg, "agents.example.com").0,
            "https://agents.example.com"
        );
        assert_eq!(
            resolve_server(&cfg, "https://x.example").0,
            "https://x.example"
        );
    }
}

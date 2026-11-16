//! Crash cleanup: the server records its agents' process ids, and on start it
//! stops any left over from a server that crashed and purges spool files.

use std::path::Path;

use actp_proto::gojson::{GoValue, map};

use crate::agentproc;
use crate::server::Server;

/// Writes the running agents' process ids, so a crashed server can stop them
/// on its next start. Does nothing after the server closed.
pub(crate) fn record_pids(s: &Server) {
    let closed = s.pids_closed();
    if *closed {
        return;
    }
    let pids: Vec<GoValue> = s
        .st()
        .links
        .values()
        .map(|l| GoValue::Int(l.pid() as i64))
        .collect();
    let dir = s.config().state_dir.clone();
    if crate::fsutil::create_private_dir(Path::new(&dir)).is_err() {
        return;
    }
    let data = map([
        ("serverPid", GoValue::Int(std::process::id() as i64)),
        ("agentPids", GoValue::Arr(pids)),
    ])
    .encode();
    let path = s.state_path();
    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    if crate::fsutil::write_private(Path::new(&tmp), data.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
    drop(closed);
}

/// Stops agents left running by a server that crashed, and deletes spool
/// files, which can hold code and secrets.
pub(crate) fn cleanup(s: &Server) {
    let spool = s.spool_dir();
    let purge = || {
        if let Ok(entries) = std::fs::read_dir(&spool) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    };
    let Ok(data) = std::fs::read_to_string(s.state_path()) else {
        purge();
        return;
    };
    let Ok(st) = serde_json::from_str::<serde_json::Value>(&data) else {
        return;
    };
    let server_pid = st.get("serverPid").and_then(|v| v.as_i64()).unwrap_or(0);
    if server_pid != std::process::id() as i64 && agentproc::process_alive(server_pid) {
        tracing::warn!(pid = server_pid, state = %s.config().state_dir, "another actp server seems to be running with the same state folder");
        return;
    }
    purge();
    for pid in st
        .get("agentPids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_i64())
    {
        if agentproc::process_alive(pid) {
            tracing::info!(pid, "stopping agent left over from an earlier run");
            agentproc::kill_group_by_pid(pid);
        }
    }
    let _ = std::fs::remove_file(s.state_path());
}

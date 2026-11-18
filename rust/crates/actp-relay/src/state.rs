//! What the relay keeps on disk in `state_dir`: the org-wide stop
//! (`stop.json`) and when each machine was first and last seen
//! (`machines.json`). Files are written whole and renamed into place.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The org-wide stop as recorded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stop {
    pub stopped: bool,
    /// Who pressed or released it last: an admin token's name, or an
    /// operator's caller name ([`Stop::by_kind`]).
    #[serde(default)]
    pub by: String,
    /// `admin`, `operator`, or `relay` (the relay itself, when `stop.json`
    /// could not be read). Records written before operators existed have
    /// none, and were an admin's.
    #[serde(default)]
    pub by_kind: String,
    /// The person an operator pressed or released it for, as the operator
    /// said (`X-Actp-On-Behalf-Of`).
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    #[serde(default)]
    pub reason: String,
    /// RFC 3339.
    #[serde(default)]
    pub at: String,
}

/// When a machine was seen, in Unix seconds, and the key its name is
/// pinned to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub first_seen: u64,
    pub last_seen: u64,
    /// SHA-256 of the public key (SubjectPublicKeyInfo) of the device
    /// certificate this name was first seen with, as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// When that certificate was issued (its notBefore, Unix seconds): a
    /// renewal must be newer. 0 when an admin pinned the key by itself.
    #[serde(default)]
    pub key_since: u64,
    /// When that certificate expires (Unix seconds): near it, a renewal
    /// with a new key is taken. 0: not known yet, and no renewal is taken.
    #[serde(default)]
    pub key_until: u64,
}

pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // The rename itself survives a crash only once the folder is synced.
    // Some file systems (network and FUSE mounts) cannot sync a folder;
    // the file itself is synced, so that is no reason to report a failure.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        match std::fs::File::open(dir).and_then(|d| d.sync_all()) {
            Err(e)
                if e.kind() == io::ErrorKind::Unsupported
                    || e.kind() == io::ErrorKind::InvalidInput => {}
            r => r?,
        }
    }
    Ok(())
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> io::Result<Store> {
        create_private_dir(dir)?;
        Ok(Store {
            dir: dir.to_path_buf(),
        })
    }

    fn stop_path(&self) -> PathBuf {
        self.dir.join("stop.json")
    }

    fn machines_path(&self) -> PathBuf {
        self.dir.join("machines.json")
    }

    /// The recorded stop. No file means no stop; a file that cannot be read
    /// means the stop is on, so a damaged file never releases it.
    pub fn load_stop(&self) -> Stop {
        match std::fs::read(self.stop_path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Stop::default(),
            Err(e) => {
                tracing::error!(error = %e, "cannot read stop.json: starting with the org-wide stop on");
                damaged()
            }
            Ok(b) => match serde_json::from_slice::<Stop>(&b) {
                Ok(mut s) => {
                    if s.by_kind.is_empty() && !s.by.is_empty() {
                        s.by_kind = "admin".into();
                    }
                    s
                }
                Err(e) => {
                    tracing::error!(error = %e, "stop.json is damaged: starting with the org-wide stop on");
                    damaged()
                }
            },
        }
    }

    pub fn save_stop(&self, s: &Stop) -> io::Result<()> {
        write_atomic(
            &self.stop_path(),
            serde_json::to_vec_pretty(s).expect("encodes").as_slice(),
        )
    }

    /// The machines seen, with their pinned keys. A file that cannot be
    /// read or is damaged is an error, never an empty start: it holds the
    /// pins, and starting without them would pin whatever key comes first.
    pub fn load_seen(&self) -> io::Result<BTreeMap<String, Seen>> {
        let path = self.machines_path();
        let hint = "it holds each machine's pinned key: restore it, or move it aside to pin every machine afresh";
        match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(io::Error::new(
                e.kind(),
                format!("cannot read {}: {e}; {hint}", path.display()),
            )),
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is damaged: {e}; {hint}", path.display()),
                )
            }),
        }
    }

    pub fn save_seen(&self, seen: &BTreeMap<String, Seen>) -> io::Result<()> {
        write_atomic(
            &self.machines_path(),
            serde_json::to_vec(seen).expect("encodes").as_slice(),
        )
    }
}

fn damaged() -> Stop {
    Stop {
        stopped: true,
        by: "relay".into(),
        by_kind: "relay".into(),
        on_behalf_of: None,
        reason: "stop.json could not be read".into(),
        at: crate::audit::rfc3339(std::time::SystemTime::now()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_damaged_stop_file_keeps_the_stop_on() {
        let dir = std::env::temp_dir().join(format!("actp-relay-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let st = Store::open(&dir).unwrap();
        assert!(!st.load_stop().stopped);
        let s = Stop {
            stopped: true,
            by: "it-bridge".into(),
            by_kind: "operator".into(),
            on_behalf_of: Some("dana@example.com".into()),
            reason: "incident".into(),
            at: "x".into(),
        };
        st.save_stop(&s).unwrap();
        assert_eq!(st.load_stop(), s);
        // A record from before operators was an admin's.
        std::fs::write(
            dir.join("stop.json"),
            br#"{"stopped": true, "by": "dave", "reason": "r", "at": "x"}"#,
        )
        .unwrap();
        let old = st.load_stop();
        assert_eq!((old.by.as_str(), old.by_kind.as_str()), ("dave", "admin"));
        assert_eq!(old.on_behalf_of, None);
        std::fs::write(dir.join("stop.json"), b"{not json").unwrap();
        assert!(st.load_stop().stopped);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

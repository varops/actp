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
    /// The admin token name that pressed or released it last.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub reason: String,
    /// RFC 3339.
    #[serde(default)]
    pub at: String,
}

/// When a machine was seen, in Unix seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub first_seen: u64,
    pub last_seen: u64,
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
    std::fs::rename(&tmp, path)
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
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::error!(error = %e, "stop.json is damaged: starting with the org-wide stop on");
                damaged()
            }),
        }
    }

    pub fn save_stop(&self, s: &Stop) -> io::Result<()> {
        write_atomic(
            &self.stop_path(),
            serde_json::to_vec_pretty(s).expect("encodes").as_slice(),
        )
    }

    pub fn load_seen(&self) -> BTreeMap<String, Seen> {
        match std::fs::read(self.machines_path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                tracing::warn!(error = %e, "cannot read machines.json: last-seen times start empty");
                BTreeMap::new()
            }
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "machines.json is damaged: last-seen times start empty");
                BTreeMap::new()
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
            by: "dave".into(),
            reason: "incident".into(),
            at: "x".into(),
        };
        st.save_stop(&s).unwrap();
        assert_eq!(st.load_stop(), s);
        std::fs::write(dir.join("stop.json"), b"{not json").unwrap();
        assert!(st.load_stop().stopped);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

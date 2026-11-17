//! The relay's half of the audit: one JSON object per line in
//! `<log_dir>/audit.jsonl`. Ids, addresses, times and counts only, never
//! anything a session carries.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub struct Audit {
    f: Mutex<Option<Log>>,
    /// `org_stops.jsonl`: the org-wide stop's records, never rotated.
    stops: Mutex<Option<File>>,
}

struct Log {
    file: File,
    dir: PathBuf,
    size: u64,
    max: u64,
}

/// Old audit files kept after rotation: `audit.jsonl.1` (newest) to `.10`.
const KEEP: u32 = 10;

fn open_log(dir: &Path) -> std::io::Result<File> {
    open_append(&dir.join("audit.jsonl"))
}

fn open_append(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

impl Audit {
    pub fn disabled() -> Self {
        Audit {
            f: Mutex::new(None),
            stops: Mutex::new(None),
        }
    }

    /// Appends to `<dir>/audit.jsonl`, rotating it at `max` bytes.
    pub fn open(dir: &Path, max: u64) -> std::io::Result<Self> {
        crate::state::create_private_dir(dir)?;
        let file = open_log(dir)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Audit {
            f: Mutex::new(Some(Log {
                file,
                dir: dir.to_path_buf(),
                size,
                max,
            })),
            stops: Mutex::new(Some(open_append(&dir.join("org_stops.jsonl"))?)),
        })
    }
    /// Records an event of the org-wide stop: in the audit log, and in
    /// `org_stops.jsonl`, which is never rotated, so floods of other events
    /// cannot push who stopped and released out of the record.
    pub fn kept<const N: usize>(&self, kind: &str, fields: [(&str, Value); N]) {
        let line = Self::line(kind, fields);
        let mut g = self.stops.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = g.as_mut() {
            if let Err(e) = f.write_all(line.as_bytes()) {
                tracing::error!(error = %e, "could not write org_stops.jsonl");
            }
        }
        drop(g);
        self.write(line);
    }

    fn line<const N: usize>(kind: &str, fields: [(&str, Value); N]) -> String {
        let mut m = Map::new();
        for (k, v) in fields {
            if !v.is_null() {
                m.insert(k.to_string(), v);
            }
        }
        m.insert("time".into(), Value::String(rfc3339(SystemTime::now())));
        m.insert("event".into(), Value::String(kind.to_string()));
        let mut line = Value::Object(m).to_string();
        line.push('\n');
        line
    }

    /// Records one event; keys come out sorted.
    pub fn event<const N: usize>(&self, kind: &str, fields: [(&str, Value); N]) {
        self.write(Self::line(kind, fields));
    }

    fn write(&self, line: String) {
        let mut g = self.f.lock().unwrap_or_else(|e| e.into_inner());
        let Some(log) = g.as_mut() else {
            return;
        };
        if log.size + line.len() as u64 > log.max && log.size > 0 {
            for i in (1..KEEP).rev() {
                let _ = std::fs::rename(
                    log.dir.join(format!("audit.jsonl.{i}")),
                    log.dir.join(format!("audit.jsonl.{}", i + 1)),
                );
            }
            let _ = std::fs::rename(log.dir.join("audit.jsonl"), log.dir.join("audit.jsonl.1"));
            match open_log(&log.dir) {
                Ok(f) => {
                    log.file = f;
                    log.size = 0;
                }
                Err(e) => tracing::error!(error = %e, "could not rotate the audit log"),
            }
        }
        match log.file.write_all(line.as_bytes()) {
            Ok(()) => log.size += line.len() as u64,
            Err(e) => tracing::error!(error = %e, "could not write the audit log"),
        }
    }
}

/// RFC 3339 in UTC with milliseconds.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, da) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{da:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_times() {
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::new(951_782_400, 5_000_000)),
            "2000-02-29T00:00:00.005Z"
        );
    }
}

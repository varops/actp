//! The relay's half of the audit: one JSON object per line in
//! `<log_dir>/audit.jsonl`. Ids, addresses, times and counts only, never
//! anything a session carries.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub struct Audit {
    f: Mutex<Option<File>>,
}

impl Audit {
    pub fn disabled() -> Self {
        Audit {
            f: Mutex::new(None),
        }
    }

    pub fn open(dir: &Path) -> std::io::Result<Self> {
        crate::state::create_private_dir(dir)?;
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let f = o.open(dir.join("audit.jsonl"))?;
        Ok(Audit {
            f: Mutex::new(Some(f)),
        })
    }

    /// Records one event; keys come out sorted.
    pub fn event<const N: usize>(&self, kind: &str, fields: [(&str, Value); N]) {
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
        let mut g = self.f.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = g.as_mut() {
            if let Err(e) = f.write_all(line.as_bytes()) {
                tracing::error!(error = %e, "could not write the audit log");
            }
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

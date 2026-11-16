//! The audit log: one JSON object per line, like the Go server writes it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use actp_proto::gojson::GoValue;

/// Writes audit events to `<log_dir>/audit.jsonl`. A missing log drops events.
pub struct AuditLog {
    f: Mutex<Option<File>>,
}

impl AuditLog {
    pub fn disabled() -> Self {
        AuditLog {
            f: Mutex::new(None),
        }
    }

    pub fn open(dir: &str) -> std::io::Result<Self> {
        if dir.is_empty() {
            return Ok(Self::disabled());
        }
        crate::fsutil::create_private_dir(Path::new(dir))?;
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let f = o.open(Path::new(dir).join("audit.jsonl"))?;
        Ok(AuditLog {
            f: Mutex::new(Some(f)),
        })
    }

    /// Records one event. Keys are sorted, like Go's map encoding.
    pub fn event<const N: usize>(&self, kind: &str, fields: [(&str, GoValue); N]) {
        let mut m: std::collections::BTreeMap<String, GoValue> = fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        m.insert("time".into(), GoValue::Str(rfc3339_nano(SystemTime::now())));
        m.insert("event".into(), GoValue::Str(kind.to_string()));
        let mut line = GoValue::Map(m).encode();
        line.push('\n');
        let mut g = self.f.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = g.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    pub fn close(&self) {
        self.f.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

/// Go's `time.RFC3339Nano` in UTC: trailing zeros of the fraction trimmed.
pub fn rfc3339_nano(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let nanos = d.subsec_nanos();
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, da) = civil_from_days(days);
    let mut s = format!(
        "{y:04}-{mo:02}-{da:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    if nanos > 0 {
        let frac = format!("{nanos:09}");
        s.push('.');
        s.push_str(frac.trim_end_matches('0'));
    }
    s.push('Z');
    s
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
    fn times_like_go() {
        assert_eq!(
            rfc3339_nano(UNIX_EPOCH + Duration::new(1_763_302_620, 120_000_000)),
            "2025-11-16T14:17:00.12Z"
        );
        assert_eq!(
            rfc3339_nano(UNIX_EPOCH + Duration::new(951_782_400, 0)),
            "2000-02-29T00:00:00Z"
        );
    }
}

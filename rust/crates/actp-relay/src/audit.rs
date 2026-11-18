//! The relay's half of the audit: one JSON object per line in
//! `<log_dir>/audit.jsonl`. Ids, addresses, times and counts only, never
//! anything a session carries.
//!
//! Every line's `time` is in microseconds and later than the line before
//! it, also across rotations and restarts. The audit query ([`query`])
//! pages by position in the files, so older relays' lines (millisecond
//! times, not always in order) page exactly too.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub struct Audit {
    f: Mutex<Option<Log>>,
    /// `org_stops.jsonl`: the org-wide stop's records, never rotated.
    /// Taken after `f`.
    stops: Mutex<Option<File>>,
}

struct Log {
    file: File,
    dir: PathBuf,
    size: u64,
    max: u64,
    /// The last line's time, in microseconds since the epoch.
    last: u64,
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

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// The time of the last line of the newest audit file, so times keep
/// rising across a restart even if the clock went back. A time more than a
/// day ahead (a damaged line) is not followed.
fn last_time(dir: &Path) -> u64 {
    let t = newest_time(dir);
    if t > now_micros().saturating_add(86_400_000_000) {
        tracing::warn!(
            "the audit log's last line is dated more than a day ahead: not continuing from it"
        );
        return 0;
    }
    t
}

fn newest_time(dir: &Path) -> u64 {
    for name in std::iter::once("audit.jsonl".to_string())
        .chain((1..=KEEP).map(|i| format!("audit.jsonl.{i}")))
    {
        let Ok(f) = File::open(dir.join(&name)) else {
            continue;
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut lines = Lines::new(f, len);
        while let Ok(Some(line)) = lines.next_line() {
            if let Some(t) = serde_json::from_slice::<Value>(&line).ok().and_then(|v| {
                v.get("time")
                    .and_then(|t| t.as_str())
                    .and_then(parse_rfc3339)
            }) {
                return t;
            }
        }
    }
    0
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
                last: last_time(dir),
            })),
            stops: Mutex::new(Some(open_append(&dir.join("org_stops.jsonl"))?)),
        })
    }

    /// Records an event of the org-wide stop: in the audit log, and in
    /// `org_stops.jsonl`, which is never rotated, so floods of other events
    /// cannot push who stopped and released out of the record.
    pub fn kept<const N: usize>(&self, kind: &str, fields: [(&str, Value); N]) {
        self.append(kind, fields, true);
    }

    /// Records one event; keys come out sorted.
    pub fn event<const N: usize>(&self, kind: &str, fields: [(&str, Value); N]) {
        self.append(kind, fields, false);
    }

    fn line<const N: usize>(kind: &str, fields: [(&str, Value); N], time: u64) -> String {
        let mut m = Map::new();
        for (k, v) in fields {
            if !v.is_null() {
                m.insert(k.to_string(), v);
            }
        }
        m.insert("time".into(), Value::String(rfc3339_micros(time)));
        m.insert("event".into(), Value::String(kind.to_string()));
        let mut line = Value::Object(m).to_string();
        line.push('\n');
        line
    }

    /// The line is stamped and written under the log's lock, so lines are
    /// in the order of their times.
    fn append<const N: usize>(&self, kind: &str, fields: [(&str, Value); N], kept: bool) {
        let mut g = self.f.lock().unwrap_or_else(|e| e.into_inner());
        let time = match g.as_mut() {
            Some(log) => {
                log.last = now_micros().max(log.last + 1);
                log.last
            }
            None if kept => now_micros(),
            None => return,
        };
        let line = Self::line(kind, fields, time);
        if kept {
            let mut s = self.stops.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(f) = s.as_mut()
                && let Err(e) = f.write_all(line.as_bytes())
            {
                tracing::error!(error = %e, "could not write org_stops.jsonl");
            }
        }
        if let Some(log) = g.as_mut() {
            log.write(&line);
        }
    }

    /// The audit files as they are now, newest first, each with its length
    /// at this moment: taken under the writer's lock, so a rotation cannot
    /// show a file twice or skip one, and a line being written is not
    /// half-read. Empty when the audit is off.
    pub(crate) fn snapshot(&self) -> Vec<(File, u64)> {
        let g = self.f.lock().unwrap_or_else(|e| e.into_inner());
        let Some(log) = g.as_ref() else {
            return Vec::new();
        };
        std::iter::once("audit.jsonl".to_string())
            .chain((1..=KEEP).map(|i| format!("audit.jsonl.{i}")))
            .filter_map(|name| {
                let f = File::open(log.dir.join(name)).ok()?;
                let len = f.metadata().ok()?.len();
                Some((f, len))
            })
            .collect()
    }
}

impl Log {
    fn write(&mut self, line: &str) {
        if self.size + line.len() as u64 > self.max && self.size > 0 {
            for i in (1..KEEP).rev() {
                let from = self.dir.join(format!("audit.jsonl.{i}"));
                if let Err(e) =
                    std::fs::rename(&from, self.dir.join(format!("audit.jsonl.{}", i + 1)))
                    && e.kind() != io::ErrorKind::NotFound
                {
                    tracing::error!(error = %e, file = %from.display(), "could not rotate an audit file");
                }
            }
            if let Err(e) =
                std::fs::rename(self.dir.join("audit.jsonl"), self.dir.join("audit.jsonl.1"))
            {
                // The file goes on growing past the limit until a rotation
                // succeeds (on Windows, a file being read cannot always be
                // renamed); nothing is lost.
                tracing::error!(error = %e, "could not rotate the audit log");
                self.size = 0;
                return self.append_only(line);
            }
            match open_log(&self.dir) {
                Ok(f) => {
                    self.file = f;
                    self.size = 0;
                }
                Err(e) => tracing::error!(error = %e, "could not rotate the audit log"),
            }
        }
        self.append_only(line);
    }

    fn append_only(&mut self, line: &str) {
        match self.file.write_all(line.as_bytes()) {
            Ok(()) => self.size += line.len() as u64,
            Err(e) => tracing::error!(error = %e, "could not write the audit log"),
        }
    }
}

// ---- reading it back ----

/// The lines of the first `len` bytes of a file, last first, each with
/// the offset it starts at.
struct Lines {
    f: File,
    /// Bytes not read yet, from the start of the file.
    pos: u64,
    /// The start of a line whose beginning is further back.
    carry: Vec<u8>,
    /// Whole lines read, in file order, with their offsets.
    ready: Vec<(u64, Vec<u8>)>,
}

/// Bytes read at a time, going back.
const CHUNK: u64 = 64 << 10;
/// A line longer than this is skipped (the relay writes none).
const MAX_LINE: usize = 1 << 20;

impl Lines {
    fn new(f: File, len: u64) -> Lines {
        Lines {
            f,
            pos: len,
            carry: Vec::new(),
            ready: Vec::new(),
        }
    }

    fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.next_at()?.map(|(_, l)| l))
    }

    /// The next line back, and the offset it starts at.
    fn next_at(&mut self) -> io::Result<Option<(u64, Vec<u8>)>> {
        loop {
            if let Some(l) = self.ready.pop() {
                return Ok(Some(l));
            }
            if self.pos == 0 {
                let l = std::mem::take(&mut self.carry);
                return Ok((!l.is_empty()).then_some((0, l)));
            }
            let n = CHUNK.min(self.pos);
            self.pos -= n;
            self.f.seek(SeekFrom::Start(self.pos))?;
            let mut data = vec![0u8; n as usize];
            self.f.read_exact(&mut data)?;
            data.extend_from_slice(&self.carry);
            let mut ready = Vec::new();
            let mut first_end = None;
            let mut start = 0usize;
            for (i, b) in data.iter().enumerate() {
                if *b != b'\n' {
                    continue;
                }
                match first_end {
                    None => first_end = Some(i),
                    Some(_) => {
                        let l = &data[start..i];
                        if !l.is_empty() && l.len() <= MAX_LINE {
                            ready.push((self.pos + start as u64, l.to_vec()));
                        }
                    }
                }
                start = i + 1;
            }
            match first_end {
                None => {
                    // No line ends in it: all of it is the start of a line
                    // further back.
                    self.carry = if data.len() > MAX_LINE {
                        Vec::new()
                    } else {
                        data
                    };
                }
                Some(fe) => {
                    let l = &data[start..];
                    if !l.is_empty() && l.len() <= MAX_LINE {
                        ready.push((self.pos + start as u64, l.to_vec()));
                    }
                    self.carry = if fe > MAX_LINE {
                        Vec::new()
                    } else {
                        data[..fe].to_vec()
                    };
                }
            }
            self.ready = ready;
        }
    }
}

/// Which events the audit query shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Who connected to which machine, when and for how long.
    Sessions,
    /// The org-wide stop: every press and release.
    Stops,
    /// Machines coming and going, and every change to a machine's pinned
    /// key (an admin's re-pin included).
    Machines,
    /// Configuration reloads, with who holds a role at the relay.
    Config,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "sessions" => Some(Kind::Sessions),
            "stops" => Some(Kind::Stops),
            "machines" => Some(Kind::Machines),
            "config" => Some(Kind::Config),
            _ => None,
        }
    }
}

/// The events the query shows, and of each the fields: the relay's
/// remote addresses, refusals and errors stay in the file.
fn projection(event: &str) -> Option<(Kind, &'static [&'static str])> {
    Some(match event {
        "session_open" => (
            Kind::Sessions,
            &[
                "session",
                "machine",
                "caller",
                "caller_certificate",
                "on_behalf_of",
            ],
        ),
        "session_closed" => (
            Kind::Sessions,
            &[
                "session",
                "machine",
                "caller",
                "on_behalf_of",
                "opened_at",
                "seconds",
                "bytes_to_machine",
                "bytes_to_caller",
                "reason",
            ],
        ),
        "org_stop" => (
            Kind::Stops,
            &[
                "by",
                "by_kind",
                "caller_certificate",
                "on_behalf_of",
                "reason",
                "sessions_dropped",
            ],
        ),
        "org_release" => (
            Kind::Stops,
            &[
                "by",
                "by_kind",
                "caller_certificate",
                "on_behalf_of",
                "reason",
            ],
        ),
        "org_stop_repeated" => (
            Kind::Stops,
            &[
                "by",
                "by_kind",
                "caller_certificate",
                "on_behalf_of",
                "reason",
                "sessions_dropped",
            ],
        ),
        "org_stop_not_saved" | "org_stop_saved" => (Kind::Stops, &[]),
        "config_reloaded" | "relay_started" => (Kind::Config, &["operators"]),
        "machine_online" => (Kind::Machines, &["machine"]),
        "machine_offline" => (Kind::Machines, &["machine", "seconds", "reason"]),
        "machine_replaced" => (
            Kind::Machines,
            &["machine", "old_certificate", "new_certificate"],
        ),
        "machine_repinned" => (
            Kind::Machines,
            &["machine", "by", "reason", "key", "was_pinned"],
        ),
        "machine_key_continued" | "machine_key_renewed" => {
            (Kind::Machines, &["machine", "old_key", "new_key"])
        }
        "machine_key_refused" => (
            Kind::Machines,
            &["machine", "pinned_key", "presented_key", "repeats"],
        ),
        _ => return None,
    })
}

/// An audit query (`GET /relay/v1/audit`).
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Which kinds of events; empty: all.
    pub kinds: Vec<Kind>,
    /// Only events naming exactly this machine, or person. `caller` also
    /// matches the operator (`by`) that pressed or released the stop.
    pub machine: Option<String>,
    pub caller: Option<String>,
    pub on_behalf_of: Option<String>,
    /// Events at or after this time (microseconds since the epoch).
    pub since: Option<u64>,
    /// Events before this time.
    pub before: Option<u64>,
    /// Where the page before ended ([`Page::next`]): this page goes on
    /// from there, older.
    pub cursor: Option<String>,
    /// Events per page (at least 1).
    pub limit: usize,
    /// Bytes of the log one page reads at most (0: no limit). A page that
    /// reaches it ends early, with `more` and a cursor to go on from.
    pub budget: u64,
}

/// One page of events, newest first.
#[derive(Clone, Debug, PartialEq)]
pub struct Page {
    pub events: Vec<Value>,
    /// There may be more: ask again with `cursor` = `next`.
    pub more: bool,
    pub next: Option<String>,
}

/// A file's identity across renames: the hash of its first line (the
/// files are only ever appended to); and whether that line has a
/// microsecond time, as this relay writes them. Older relays wrote
/// millisecond times, not always in order.
fn file_id(f: &mut File) -> io::Result<Option<(String, bool)>> {
    use sha2::Digest;
    f.seek(SeekFrom::Start(0))?;
    let mut first = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(None); // no whole line yet
        }
        match buf[..n].iter().position(|b| *b == b'\n') {
            Some(i) => {
                first.extend_from_slice(&buf[..i]);
                break;
            }
            None => first.extend_from_slice(&buf[..n]),
        }
        if first.len() > MAX_LINE {
            return Ok(None);
        }
    }
    let ordered = field(&first, "time")
        .and_then(|t| t.rsplit_once('.'))
        .is_some_and(|(_, frac)| frac.len() == 7 && frac.ends_with('Z'));
    Ok(Some((
        hex::encode(&sha2::Sha256::digest(&first)[..12]),
        ordered,
    )))
}

fn cursor(file: &str, offset: u64) -> String {
    format!("{file}-{offset}")
}

/// A cursor's file and offset, if it is one.
pub fn parse_cursor(c: &str) -> Option<(String, u64)> {
    let (file, offset) = c.split_once('-')?;
    (file.len() == 24 && file.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then_some(())?;
    Some((file.to_string(), offset.parse().ok()?))
}

/// The string value of `"key":"…"` in a line the relay wrote, without
/// parsing it all. Inside a JSON string every `"` is escaped, so the
/// pattern only matches a key.
fn field<'a>(line: &'a [u8], key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let at = line.windows(pat.len()).position(|w| w == pat.as_bytes())? + pat.len();
    let end = line[at..].iter().position(|b| *b == b'"')? + at;
    std::str::from_utf8(&line[at..end]).ok()
}

/// Reads the audit files of a [`Audit::snapshot`], newest first, for the
/// events `q` asks for.
pub(crate) fn query(files: Vec<(File, u64)>, q: &Query) -> io::Result<Page> {
    let limit = q.limit.max(1);
    let mut events = Vec::new();
    let mut scanned = 0u64;
    let matches = |v: &Map<String, Value>, key: &str, want: &Option<String>| match want {
        None => true,
        Some(w) => v.get(key).and_then(|x| x.as_str()) == Some(w.as_str()),
    };
    let from = match &q.cursor {
        None => None,
        Some(c) => Some(
            parse_cursor(c)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a cursor"))?,
        ),
    };
    // With a cursor, files newer than its file are passed over, and its
    // file is read from the cursor back.
    let mut found = from.is_none();
    let mut last: Option<String> = None;
    'files: for (mut f, len) in files {
        let Some((id, ordered)) = file_id(&mut f)? else {
            continue;
        };
        let end = match &from {
            Some((file, offset)) if !found => {
                if *file != id {
                    continue;
                }
                found = true;
                (*offset).min(len)
            }
            _ => len,
        };
        let mut lines = Lines::new(f, end);
        while let Some((at, line)) = lines.next_at()? {
            if q.budget > 0 && scanned >= q.budget {
                return Ok(Page {
                    events,
                    more: true,
                    next: last,
                });
            }
            scanned += line.len() as u64 + 1;
            last = Some(cursor(&id, at));
            let (Some(event), Some(time)) = (field(&line, "event"), field(&line, "time")) else {
                continue;
            };
            let Some(t) = parse_rfc3339(time) else {
                continue;
            };
            if ordered && q.since.is_some_and(|s| t < s) {
                // This file's lines are in the order of their times: the
                // rest of it is older. An older file is checked from its
                // newest line again (one line, for files this relay wrote;
                // older relays' files are read through).
                continue 'files;
            }
            if q.since.is_some_and(|s| t < s) || q.before.is_some_and(|b| t >= b) {
                continue;
            }
            let Some((kind, fields)) = projection(event) else {
                continue;
            };
            if !(q.kinds.is_empty() || q.kinds.contains(&kind)) {
                continue;
            }
            let Ok(Value::Object(v)) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            let caller_ok = matches(&v, "caller", &q.caller)
                || (kind == Kind::Stops
                    && matches(&v, "by", &q.caller)
                    && v.get("by_kind").and_then(|k| k.as_str()) == Some("operator"));
            if !matches(&v, "machine", &q.machine)
                || !caller_ok
                || !matches(&v, "on_behalf_of", &q.on_behalf_of)
            {
                continue;
            }
            let mut out = Map::new();
            out.insert("event".into(), json_str(event));
            out.insert("time".into(), json_str(time));
            for k in fields {
                if let Some(x) = v.get(*k) {
                    out.insert((*k).to_string(), x.clone());
                }
            }
            events.push(Value::Object(out));
            if events.len() == limit {
                return Ok(Page {
                    events,
                    more: true,
                    next: last,
                });
            }
        }
    }
    Ok(Page {
        events,
        more: false,
        next: None,
    })
}

fn json_str(s: &str) -> Value {
    Value::String(s.to_string())
}

/// Parses an RFC 3339 time in UTC (`Z` or `+00:00`), with up to nine
/// fractional digits, to microseconds since the epoch.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let s = s
        .strip_suffix('Z')
        .or_else(|| s.strip_suffix('z'))
        .or_else(|| s.strip_suffix("+00:00"))?;
    let (date, clock) = s.split_once(['T', 't'])?;
    let num = |x: &str| -> Option<u64> {
        (!x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
            .then(|| x.parse().ok())
            .flatten()
    };
    let mut d = date.split('-');
    let (y, mo, da) = (num(d.next()?)?, num(d.next()?)?, num(d.next()?)?);
    if d.next().is_some() || date.len() != 10 {
        return None;
    }
    let (hms, frac) = match clock.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (clock, None),
    };
    if hms.len() != 8 {
        return None;
    }
    let mut c = hms.split(':');
    let (h, mi, se) = (num(c.next()?)?, num(c.next()?)?, num(c.next()?)?);
    if c.next().is_some()
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&da)
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    let micros = match frac {
        None => 0,
        Some(f) if (1..=9).contains(&f.len()) => {
            let digits = num(f)?;
            let scale = 10u64.pow(9 - f.len() as u32);
            digits * scale / 1000
        }
        Some(_) => return None,
    };
    if !(1970..=9999).contains(&y) {
        return None;
    }
    let days = days_from_civil(y as i64, mo as u32, da as u32);
    let secs = days * 86400 + (h * 3600 + mi * 60 + se) as i64;
    (secs >= 0).then(|| secs as u64 * 1_000_000 + micros)
}

/// Days since 1970-01-01 of a date, proleptic Gregorian.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 in UTC with microseconds, from microseconds since the epoch.
pub fn rfc3339_micros(us: u64) -> String {
    let secs = (us / 1_000_000) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, mo, da) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{da:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        us % 1_000_000
    )
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
        assert_eq!(
            rfc3339_micros(951_782_400_000_000 + 5_123),
            "2000-02-29T00:00:00.005123Z"
        );
    }

    #[test]
    fn parses_times() {
        let t = 951_782_400_000_000u64;
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(t));
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00.005Z"), Some(t + 5_000));
        assert_eq!(
            parse_rfc3339("2000-02-29T00:00:00.005123Z"),
            Some(t + 5_123)
        );
        assert_eq!(
            parse_rfc3339("2000-02-29T00:00:00.005123999+00:00"),
            Some(t + 5_123)
        );
        for us in [0, 1, t, 1_794_000_000_123_456] {
            assert_eq!(parse_rfc3339(&rfc3339_micros(us)), Some(us));
        }
        for bad in [
            "",
            "2000-02-29",
            "2000-02-29T00:00:00",
            "2000-02-29T00:00:00+01:00",
            "2000-13-01T00:00:00Z",
            "2000-02-29T24:00:00Z",
            "2000-2-29T00:00:00Z",
            "2000-02-29T00:00:00.Z",
            "2000-02-29T00:00:00.0000000001Z",
            "1969-12-31T23:59:59Z",
            "+2000-02-29T00:00:00Z",
            "2000-02-29T00:00:-1Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("actp-relay-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn reads_lines_back_last_first() {
        let dir = scratch("lines");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        // Lines across chunk boundaries, and a last line without its end.
        let mut want: Vec<String> = (0..20_000)
            .map(|i| format!("line {i} {}", "x".repeat(i % 37)))
            .collect();
        std::fs::write(&p, want.join("\n")).unwrap();
        let len = std::fs::metadata(&p).unwrap().len();
        let mut r = Lines::new(File::open(&p).unwrap(), len);
        let mut got = Vec::new();
        while let Some(l) = r.next_line().unwrap() {
            got.push(String::from_utf8(l).unwrap());
        }
        want.reverse();
        assert_eq!(got, want);
        // Each line's offset is where it starts.
        let bytes = std::fs::read(&p).unwrap();
        let mut r = Lines::new(File::open(&p).unwrap(), len);
        while let Some((at, l)) = r.next_at().unwrap() {
            assert_eq!(&bytes[at as usize..at as usize + l.len()], &l[..]);
            assert!(at == 0 || bytes[at as usize - 1] == b'\n');
        }
        // Only the first `len` bytes count.
        let mut r = Lines::new(File::open(&p).unwrap(), 7);
        assert_eq!(r.next_line().unwrap().as_deref(), Some(&b"line 0 "[..]));
        assert_eq!(r.next_line().unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lines from before times were unique: the same millisecond several
    /// times, and out of order.
    #[test]
    fn old_lines_are_paged_without_loss() {
        let dir = scratch("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let times = [".001", ".002", ".002", ".002", ".004", ".003", ".005"];
        let mut text = String::new();
        for (i, t) in times.iter().enumerate() {
            text.push_str(&format!(
                "{{\"caller\":\"c\",\"event\":\"session_open\",\"machine\":\"m\",\"remote\":\"1.2.3.4:5\",\"session\":{i},\"time\":\"2026-11-18T10:00:00{t}Z\"}}\n"
            ));
        }
        std::fs::write(dir.join("audit.jsonl"), text).unwrap();
        let a = Audit::open(&dir, 1 << 20).unwrap();
        let mut q = Query {
            limit: 2,
            ..Query::default()
        };
        let mut seen = Vec::new();
        loop {
            let p = query(a.snapshot(), &q).unwrap();
            seen.extend(p.events.iter().map(|e| e["session"].as_u64().unwrap()));
            if !p.more {
                break;
            }
            q.cursor = p.next;
        }
        assert_eq!(seen, [6, 5, 4, 3, 2, 1, 0]);
        let p = query(
            a.snapshot(),
            &Query {
                since: parse_rfc3339("2026-11-18T10:00:00.004Z"),
                limit: 100,
                ..Query::default()
            },
        )
        .unwrap();
        let got: Vec<u64> = p
            .events
            .iter()
            .map(|e| e["session"].as_u64().unwrap())
            .collect();
        assert_eq!(got, [6, 4]);
        // A limit of 0 is taken as 1, so a caller looping on `more` ends.
        let p = query(a.snapshot(), &Query::default()).unwrap();
        assert_eq!(p.events.len(), 1);
        assert!(p.next.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn times_rise_and_pages_are_exact() {
        let dir = scratch("pages");
        let a = Audit::open(&dir, 16 << 10).unwrap();
        for i in 0..300 {
            a.event(
                "session_open",
                [
                    ("session", Value::from(i)),
                    (
                        "machine",
                        Value::from(if i % 3 == 0 { "m-a" } else { "m-b" }),
                    ),
                    ("caller", Value::from("it-bridge")),
                    ("remote", Value::from("10.0.0.1:5000")),
                ],
            );
            a.event("caller_refused", [("remote", Value::from("10.0.0.2:5000"))]);
        }
        a.kept(
            "org_stop",
            [("by", Value::from("dave")), ("reason", Value::from("r"))],
        );
        // Rotated into several files, nothing lost, times strictly rising.
        assert!(dir.join("audit.jsonl.3").exists());
        let all = query(
            a.snapshot(),
            &Query {
                limit: 10_000,
                ..Query::default()
            },
        )
        .unwrap();
        assert!(!all.more);
        assert_eq!(all.events.len(), 301);
        assert_eq!(all.events[0]["event"], "org_stop");
        let times: Vec<u64> = all
            .events
            .iter()
            .map(|e| parse_rfc3339(e["time"].as_str().unwrap()).unwrap())
            .collect();
        assert!(
            times.windows(2).all(|w| w[0] > w[1]),
            "newest first, strictly"
        );
        // The projection leaves addresses out, and refusals.
        assert!(all.events.iter().all(|e| e.get("remote").is_none()));
        // Paging by the cursor gives every match exactly once.
        let mut q = Query {
            machine: Some("m-a".into()),
            kinds: vec![Kind::Sessions],
            limit: 7,
            ..Query::default()
        };
        let mut seen = Vec::new();
        loop {
            let p = query(a.snapshot(), &q).unwrap();
            assert!(p.events.len() <= 7);
            seen.extend(p.events.iter().map(|e| e["session"].as_u64().unwrap()));
            if !p.more {
                break;
            }
            q.cursor = p.next;
        }
        let want: Vec<u64> = (0..300).rev().filter(|i| i % 3 == 0).collect();
        assert_eq!(seen, want);
        // since bounds it from below.
        let since = parse_rfc3339(all.events[10]["time"].as_str().unwrap());
        let p = query(
            a.snapshot(),
            &Query {
                since,
                limit: 100,
                ..Query::default()
            },
        )
        .unwrap();
        assert_eq!(p.events.len(), 11);
        // A small budget ends pages early; the cursor goes on from there,
        // and nothing is lost or repeated.
        let mut q = Query {
            kinds: vec![Kind::Sessions],
            limit: 1000,
            budget: 3000,
            ..Query::default()
        };
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let p = query(a.snapshot(), &q).unwrap();
            pages += 1;
            seen.extend(p.events.iter().map(|e| e["session"].as_u64().unwrap()));
            if !p.more {
                break;
            }
            q.cursor = p.next;
        }
        assert!(pages > 10, "{pages}");
        assert_eq!(seen, (0..300).rev().collect::<Vec<u64>>());
        // A cursor the relay never gave is refused.
        for bad in [
            "",
            "x",
            "0123456789abcdef01234567",
            "0123456789abcdef0123456g-1",
            "0123456789abcdef01234567-x",
        ] {
            let q = Query {
                cursor: Some(bad.into()),
                limit: 1,
                ..Query::default()
            };
            assert!(query(a.snapshot(), &q).is_err(), "{bad}");
        }
        // Times keep rising after a restart.
        drop(a);
        let b = Audit::open(&dir, 16 << 10).unwrap();
        b.event("machine_online", [("machine", Value::from("m-a"))]);
        let p = query(
            b.snapshot(),
            &Query {
                limit: 1,
                ..Query::default()
            },
        )
        .unwrap();
        assert_eq!(p.events[0]["event"], "machine_online");
        assert!(parse_rfc3339(p.events[0]["time"].as_str().unwrap()).unwrap() > times[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

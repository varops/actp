//! Limits on what anyone on the network can make the relay do: a rate per
//! caller address, and a cap on how many refusals of one kind are written
//! to the audit log per minute.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The address limits count by: IPv4 addresses as they are, IPv6 by their
/// /64 network (one host usually has a whole /64).
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// A token bucket per caller IP address (see [`ip_key`]).
pub struct RateLimiter {
    inner: Mutex<Buckets>,
}

struct Buckets {
    per_second: f64,
    burst: f64,
    map: HashMap<IpAddr, (f64, Instant)>,
    pruned: Instant,
}

impl RateLimiter {
    pub fn new(per_second: u32, burst: u32) -> Self {
        RateLimiter {
            inner: Mutex::new(Buckets {
                per_second: per_second as f64,
                burst: burst.max(1) as f64,
                map: HashMap::new(),
                pruned: Instant::now(),
            }),
        }
    }

    pub fn set_rate(&self, per_second: u32, burst: u32) {
        let mut b = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        b.per_second = per_second as f64;
        b.burst = burst.max(1) as f64;
    }

    /// Takes one request from `ip`'s allowance.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let ip = ip_key(ip);
        let mut b = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let (rate, burst) = (b.per_second, b.burst);
        if b.map.len() > 50_000 && now.duration_since(b.pruned) >= Duration::from_secs(10) {
            // Forget addresses that have refilled completely; at most every
            // ten seconds, so a flood of addresses cannot make every request
            // scan the map.
            let full = Duration::from_secs_f64(burst / rate.max(0.001));
            b.map.retain(|_, (_, t)| now.duration_since(*t) < full);
            b.pruned = now;
        }
        let (tokens, last) = b.map.entry(ip).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * rate).min(burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per kind: events let through in this window, events left out.
type Counts = HashMap<&'static str, (u32, u64)>;

/// Lets through `per_window` events of each kind per window; counts the rest.
pub struct Throttle {
    per_window: u32,
    window: Duration,
    inner: Mutex<(Instant, Counts)>,
}

impl Throttle {
    pub fn new(per_window: u32, window: Duration) -> Self {
        Throttle {
            per_window,
            window,
            inner: Mutex::new((Instant::now(), HashMap::new())),
        }
    }

    pub fn allow(&self, kind: &'static str) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.0.elapsed() >= self.window {
            g.0 = Instant::now();
            for (logged, _) in g.1.values_mut() {
                *logged = 0;
            }
        }
        let e = g.1.entry(kind).or_default();
        if e.0 < self.per_window {
            e.0 += 1;
            true
        } else {
            e.1 += 1;
            false
        }
    }

    /// The events left out since the last call, by kind.
    pub fn take_suppressed(&self) -> Vec<(&'static str, u64)> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        for (k, (_, n)) in g.1.iter_mut() {
            if *n > 0 {
                out.push((*k, *n));
                *n = 0;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_throttles() {
        let r = RateLimiter::new(1, 3);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(r.allow(ip) && r.allow(ip) && r.allow(ip));
        assert!(!r.allow(ip));
        assert!(r.allow(other));
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_eq!(ip_key("::ffff:192.0.2.1".parse().unwrap()), ip);

        let t = Throttle::new(2, Duration::from_secs(60));
        assert!(t.allow("a") && t.allow("a"));
        assert!(!t.allow("a") && !t.allow("a"));
        assert!(t.allow("b"));
        assert_eq!(t.take_suppressed(), [("a", 2)]);
        assert!(t.take_suppressed().is_empty());
    }
}

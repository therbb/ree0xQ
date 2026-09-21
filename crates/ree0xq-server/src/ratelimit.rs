//! Per-client sliding-window rate limiter for the bootstrap
//! endpoints.
//!
//! The bootstrap listener exposes `/v1/enrol` (redeem a one-time
//! token for an agent cert) and `/v1/admin/bootstrap-tokens` (mint
//! a token). Both are reachable before any client cert exists, so
//! they are the most exposed surface on the server. Two concrete
//! risks motivate a limit:
//!
//! - **Enrol-flood.** A successful enrolment runs an ECDSA key
//!   generation via `rcgen`. A client holding (or guessing at)
//!   tokens could drive repeated keygen to burn CPU.
//! - **Admin brute-force / log-spam.** Repeated wrong-token
//!   attempts against the admin endpoint generate a `warn!` per
//!   try; the admin token itself is compared in constant time, but
//!   there is no reason to let one source hammer the endpoint.
//!
//! This is defence in depth, not the primary control — the token
//! checks already reject unauthorised callers cheaply. The limiter
//! caps how fast any single client can retry regardless.
//!
//! # Algorithm
//!
//! A sliding window per key: we keep the timestamps of recent
//! requests, drop those older than `window`, and reject once the
//! surviving count reaches `max_requests`. More accurate than a
//! fixed-window counter at the window boundary, and cheap at the
//! request rates a bootstrap endpoint sees.
//!
//! # Keying
//!
//! The caller supplies the key — in practice the client IP (see
//! [`crate::ratelimit::client_key`]). When the server is run
//! without connection info wired (some integration tests), every
//! caller collapses to one shared key; that is fine because those
//! tests stay well under the limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default request ceiling per window for the bootstrap endpoints.
pub const DEFAULT_MAX_REQUESTS: usize = 20;

/// Default sliding-window length.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Soft cap on distinct keys held before a full prune runs. Bounds
/// memory under a spray of unique source IPs.
const KEY_SOFT_CAP: usize = 65_536;

/// Sliding-window rate limiter, keyed by an arbitrary string.
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    /// Build a limiter allowing `max_requests` per `window` per key.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests: max_requests.max(1),
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Production default — [`DEFAULT_MAX_REQUESTS`] per
    /// [`DEFAULT_WINDOW`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW)
    }

    /// Record a request for `key` and report whether it is allowed.
    /// `true` — under the limit, proceed. `false` — limit reached,
    /// the caller should reject (HTTP 429).
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    /// [`Self::check`] with an explicit `now`, for deterministic
    /// tests.
    fn check_at(&self, key: &str, now: Instant) -> bool {
        let mut map = self.buckets.lock().expect("ratelimit mutex");

        // Bound memory: if we are holding too many keys, drop every
        // key whose entire window has expired before inserting.
        if map.len() >= KEY_SOFT_CAP {
            map.retain(|_, hits| hits.iter().any(|t| now.duration_since(*t) < self.window));
        }

        let hits = map.entry(key.to_string()).or_default();
        hits.retain(|t| now.duration_since(*t) < self.window);
        if hits.len() >= self.max_requests {
            return false;
        }
        hits.push(now);
        true
    }
}

/// Derive a rate-limit key from a request's connection info and
/// headers. Prefers the first hop in `X-Forwarded-For` (or
/// `X-Real-IP`) when the server sits behind a reverse proxy, then
/// the direct peer address, then a constant fallback when neither
/// is available.
pub fn client_key(peer: Option<std::net::SocketAddr>, headers: &axum::http::HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let first = first.trim();
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if !xri.trim().is_empty() {
            return xri.trim().to_string();
        }
    }
    match peer {
        Some(addr) => addr.ip().to_string(),
        None => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        // 4th in the window is rejected.
        assert!(!rl.check_at("a", t0));
    }

    #[test]
    fn distinct_keys_have_independent_budgets() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        assert!(!rl.check_at("a", t0));
        // "b" is untouched.
        assert!(rl.check_at("b", t0));
        assert!(rl.check_at("b", t0));
        assert!(!rl.check_at("b", t0));
    }

    #[test]
    fn window_slides_old_requests_out() {
        let rl = RateLimiter::new(2, Duration::from_millis(100));
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0 + Duration::from_millis(10)));
        assert!(!rl.check_at("a", t0 + Duration::from_millis(20)));
        // 150 ms after the first two: both have aged out, budget free.
        assert!(rl.check_at("a", t0 + Duration::from_millis(150)));
    }

    #[test]
    fn client_key_prefers_forwarded_for() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let peer = Some("10.9.9.9:5555".parse().unwrap());
        assert_eq!(client_key(peer, &h), "203.0.113.7");
    }

    #[test]
    fn client_key_falls_back_to_peer_then_unknown() {
        let h = axum::http::HeaderMap::new();
        let peer = Some("198.51.100.4:443".parse().unwrap());
        assert_eq!(client_key(peer, &h), "198.51.100.4");
        assert_eq!(client_key(None, &h), "unknown");
    }
}

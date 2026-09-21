//! Recent-session dedup cache for the live observer.
//!
//! `module-net.md` mandates a "5-min TTL recent-session cache" on the
//! userspace side. Without it the live path emits one
//! `crypto_inventory_event` per ClientHello retransmit / TCP-retry
//! and the collector ends up storing duplicates that the operator
//! has to filter out downstream.
//!
//! Keys are whatever the caller hands us — in practice
//! [`crate::live::session_identity`] which is FNV-1a over the
//! 4-tuple. That's stable across retransmits of the same flow and
//! distinct between flows. Values are the wall-clock [`Instant`] of
//! the first observation; everything older than `ttl` is treated as
//! a fresh observation.
//!
//! # Sizing
//!
//! The default capacity is 65 536 sessions which, at the
//! design-doc budget of 10 000 handshakes/s, gives ~6.5 s of buffer
//! — plenty of headroom over the 5-min TTL because the prune step
//! reclaims expired entries on each insert. If the cache fills
//! without anything having expired (pathological burst of unique
//! flows) the oldest entry is evicted and a counter ticks up so the
//! operator can spot it.
//!
//! # Concurrency
//!
//! The cache is `!Sync` — callers wrap it in `Mutex` if they need
//! cross-thread access. The libpcap and pcap-file paths are
//! single-threaded so the bare `&mut self` API is fine; the eBPF
//! path in `live_iface` is also single-threaded (one drain loop) so
//! same story there.
//!
//! Removing the cache from the path is a one-line change for the
//! caller (`None` instead of `Some(cache)`); the live observer
//! preserves the old "emit-everything" behaviour when no cache is
//! supplied so existing tests keep passing without modification.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default TTL — matches the value `module-net.md` documents.
pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);

/// Default capacity. 64K sessions is ~3 MB of resident memory
/// (the keys are 21-byte `live-XXXXXXXXXXXXXXXX` strings).
pub const DEFAULT_CAPACITY: usize = 65_536;

/// TTL-bounded LRU-ish dedup cache.
#[derive(Debug)]
pub struct DedupCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<String, Instant>,
    /// Forced-eviction counter — bumped when we hit the capacity
    /// ceiling and have to evict a non-expired entry. Operators
    /// watching this counter is the signal to bump `capacity`.
    forced_evictions: u64,
}

impl Default for DedupCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }
}

impl DedupCache {
    /// Build a cache with the given TTL and capacity.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: HashMap::with_capacity(capacity.min(1024)),
            forced_evictions: 0,
        }
    }

    /// Returns `true` if `identity` is a fresh observation (caller
    /// should emit the event), `false` if it's a duplicate within
    /// the TTL window (caller should drop the event).
    ///
    /// Side-effect: the identity is inserted / refreshed on first
    /// observation only — duplicate hits don't refresh the timestamp,
    /// so a session that's been retransmitted continuously for the
    /// full TTL window is eventually re-emitted exactly once.
    pub fn observe(&mut self, identity: &str) -> bool {
        self.observe_at(identity, Instant::now())
    }

    /// Internal version with explicit `now` so tests can drive time
    /// deterministically without `tokio::time::pause`.
    fn observe_at(&mut self, identity: &str, now: Instant) -> bool {
        // Cheap path: hit on a non-expired entry → dup.
        if let Some(seen_at) = self.entries.get(identity).copied() {
            if now.duration_since(seen_at) < self.ttl {
                return false;
            }
            // Expired entry; fall through to the insert path.
        }

        // Prune everything older than `ttl` lazily on insert. O(n)
        // in the cache size but bounded by `capacity`, so per-event
        // cost stays well under the 500 µs userspace budget for a
        // 64K cache.
        self.entries
            .retain(|_, t| now.duration_since(*t) < self.ttl);

        if self.entries.len() >= self.capacity {
            // Evict the oldest entry by `Instant`. We don't keep an
            // explicit LRU list — at the design point of 64K entries
            // a linear scan once per overflow is cheaper than the
            // bookkeeping needed for a doubly-linked list.
            if let Some((oldest_key, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, t)| (k.clone(), *t))
            {
                self.entries.remove(&oldest_key);
                self.forced_evictions = self.forced_evictions.saturating_add(1);
            }
        }

        self.entries.insert(identity.to_string(), now);
        true
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds any entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of times a non-expired entry had to be evicted to
    /// fit a new one — operators watching this counter rise is the
    /// signal to bump `capacity`.
    pub fn forced_evictions(&self) -> u64 {
        self.forced_evictions
    }

    /// TTL the cache was built with — surfaced for diagnostics.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_emits_second_is_dup() {
        let mut c = DedupCache::new(Duration::from_secs(60), 16);
        assert!(c.observe("live-aaa"));
        assert!(!c.observe("live-aaa"));
        assert!(!c.observe("live-aaa"));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn distinct_keys_each_emit_once() {
        let mut c = DedupCache::new(Duration::from_secs(60), 16);
        assert!(c.observe("live-a"));
        assert!(c.observe("live-b"));
        assert!(c.observe("live-c"));
        assert!(!c.observe("live-a"));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn dup_outside_ttl_re_emits() {
        let mut c = DedupCache::new(Duration::from_millis(50), 16);
        let t0 = Instant::now();
        assert!(c.observe_at("live-a", t0));
        // 10 ms after — still dedup.
        assert!(!c.observe_at("live-a", t0 + Duration::from_millis(10)));
        // 100 ms after — TTL elapsed, treated as fresh.
        assert!(c.observe_at("live-a", t0 + Duration::from_millis(100)));
    }

    #[test]
    fn capacity_overflow_evicts_oldest_and_ticks_counter() {
        let mut c = DedupCache::new(Duration::from_secs(60), 3);
        let t0 = Instant::now();
        // Spread observations far enough apart that the oldest is
        // unambiguously t0.
        assert!(c.observe_at("a", t0));
        assert!(c.observe_at("b", t0 + Duration::from_millis(10)));
        assert!(c.observe_at("c", t0 + Duration::from_millis(20)));
        assert_eq!(c.forced_evictions(), 0);
        // d kicks a out (the oldest).
        assert!(c.observe_at("d", t0 + Duration::from_millis(30)));
        assert_eq!(c.len(), 3);
        assert_eq!(c.forced_evictions(), 1);
        // a is gone → it would now be treated as fresh again.
        assert!(c.observe_at("a", t0 + Duration::from_millis(40)));
        assert_eq!(c.forced_evictions(), 2);
    }

    #[test]
    fn prune_step_reclaims_expired_before_eviction() {
        let mut c = DedupCache::new(Duration::from_millis(50), 3);
        let t0 = Instant::now();
        c.observe_at("a", t0);
        c.observe_at("b", t0);
        c.observe_at("c", t0);
        // 100 ms later: all three are expired. Inserting `d`
        // should *not* trigger a forced eviction — the prune step
        // reclaims first.
        assert!(c.observe_at("d", t0 + Duration::from_millis(100)));
        assert_eq!(c.forced_evictions(), 0);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn default_constructor_uses_documented_constants() {
        let c = DedupCache::default();
        assert_eq!(c.ttl(), DEFAULT_TTL);
        assert!(c.is_empty());
    }
}

//! Load balancing across the outbound tags a matched rule points at (objective
//! requirement 5): `random`, `round_robin`, and `user_auth_hash`.
//!
//! A [`LoadBalancer`] owns the mode plus the small mutable state a mode needs
//! (the round-robin cursor). Selection is index-only and never panics: an empty
//! tag set yields `None` (the caller routes to blackhole), and every modulo is
//! guarded against a zero divisor (SPEC §P7).

use std::sync::atomic::{AtomicUsize, Ordering};

/// How a rule with several outbound tags spreads flows across them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceMode {
    /// Uniform random pick per flow.
    Random,
    /// Rotate through tags in order, one flow each.
    RoundRobin,
    /// Deterministic pick keyed on the authenticated user's stable hash, so a
    /// given user always lands on the same outbound (session affinity).
    UserAuthHash,
}

impl BalanceMode {
    /// Parse a config token (`"random"`, `"round_robin"`/`"roundrobin"`,
    /// `"user_auth_hash"`/`"userauthhash"`). Unknown → `None`.
    pub fn parse(s: &str) -> Option<BalanceMode> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "random" | "rand" => Some(BalanceMode::Random),
            "round_robin" | "roundrobin" | "rr" => Some(BalanceMode::RoundRobin),
            "user_auth_hash" | "userauthhash" | "auth_hash" | "hash" => {
                Some(BalanceMode::UserAuthHash)
            }
            _ => None,
        }
    }
}

/// The load-balancer state for one match rule.
#[derive(Debug)]
pub struct LoadBalancer {
    mode: BalanceMode,
    cursor: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(mode: BalanceMode) -> LoadBalancer {
        LoadBalancer {
            mode,
            cursor: AtomicUsize::new(0),
        }
    }

    pub fn mode(&self) -> BalanceMode {
        self.mode
    }

    /// Pick an index into a `count`-length tag list for this flow.
    ///
    /// `auth_hash` is the authenticated user's [`stable_hash`] when known; it
    /// only matters for [`BalanceMode::UserAuthHash`] (unauthenticated flows
    /// fall back to `0`, keeping selection total).
    ///
    /// [`stable_hash`]: crate::runtime::user::UserAuthorization::stable_hash
    pub fn pick(&self, count: usize, auth_hash: Option<u64>) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let idx = match self.mode {
            BalanceMode::Random => {
                let r = rand::random::<u64>();
                usize::try_from(r.checked_rem(count as u64).unwrap_or(0)).unwrap_or(0)
            }
            BalanceMode::RoundRobin => {
                // `fetch_add` wraps on overflow (documented, not UB); the modulo
                // maps it into range. `count != 0` guaranteed above.
                let n = self.cursor.fetch_add(1, Ordering::Relaxed);
                n.checked_rem(count).unwrap_or(0)
            }
            BalanceMode::UserAuthHash => {
                let h = auth_hash.unwrap_or(0);
                usize::try_from(h.checked_rem(count as u64).unwrap_or(0)).unwrap_or(0)
            }
        };
        Some(idx)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(BalanceMode::parse("random"), Some(BalanceMode::Random));
        assert_eq!(
            BalanceMode::parse("round-robin"),
            Some(BalanceMode::RoundRobin)
        );
        assert_eq!(
            BalanceMode::parse("Round_Robin"),
            Some(BalanceMode::RoundRobin)
        );
        assert_eq!(
            BalanceMode::parse("user_auth_hash"),
            Some(BalanceMode::UserAuthHash)
        );
        assert_eq!(BalanceMode::parse("bogus"), None);
    }

    #[test]
    fn empty_is_none() {
        let lb = LoadBalancer::new(BalanceMode::RoundRobin);
        assert_eq!(lb.pick(0, None), None);
    }

    #[test]
    fn round_robin_cycles_in_order() {
        let lb = LoadBalancer::new(BalanceMode::RoundRobin);
        let seq: Vec<usize> = (0..7).map(|_| lb.pick(3, None).unwrap()).collect();
        assert_eq!(seq, vec![0, 1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn user_auth_hash_is_stable_per_user() {
        let lb = LoadBalancer::new(BalanceMode::UserAuthHash);
        let a = lb.pick(4, Some(0xdead_beef));
        let b = lb.pick(4, Some(0xdead_beef));
        assert_eq!(a, b, "same user -> same outbound");
        assert!(a.unwrap() < 4);
    }

    #[test]
    fn random_in_range() {
        let lb = LoadBalancer::new(BalanceMode::Random);
        for _ in 0..100 {
            assert!(lb.pick(5, None).unwrap() < 5);
        }
    }
}

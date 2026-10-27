//! In-memory relay store — `docs/COMMS-M1-INTERFACES.md` §4 semantics.
//!
//! One [`Store`] holds every undelivered envelope for every recipient. Design
//! points from the spec:
//! - **Dedup by `id`** — re-POSTing the same envelope is idempotent.
//! - **Inbox** returns undelivered envelopes only, oldest first, ≤ `limit`
//!   (max [`MAX_INBOX_LIMIT`]) and optionally filtered by `since` ms.
//! - **`ack`** is the only delete path (GET never deletes).
//! - **TTL clamp** on ingest: `expiresAt ≤ now + MAX_TTL_MS`; a background
//!   [`Store::sweep`] drops expired envelopes.
//! - **Quota**: ≤ [`MAX_PER_RECIPIENT`] stored envelopes per recipient; overflow
//!   is [`StoreError::RateLimited`] (mapped to HTTP `429`).

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::Envelope;

/// Default inbox page size when the client omits `limit`.
pub const DEFAULT_INBOX_LIMIT: usize = 50;

/// Hard maximum for the `limit` query parameter.
pub const MAX_INBOX_LIMIT: usize = 200;

/// Default envelope TTL (14 days) — documented default, not enforced on ingest.
pub const DEFAULT_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Hard maximum TTL (30 days). `expiresAt` is clamped to `now + MAX_TTL_MS`.
pub const MAX_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Maximum stored envelopes per recipient before the relay answers `429`.
pub const MAX_PER_RECIPIENT: usize = 1000;

/// Result of ingesting an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The envelope was stored.
    Inserted,
    /// An envelope with the same `id` was already present (no-op, idempotent).
    Duplicate,
}

/// Store-level errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The recipient is at [`MAX_PER_RECIPIENT`]; mapped to HTTP `429`.
    #[error("recipient quota exceeded")]
    RateLimited,
}

#[derive(Clone, Debug)]
pub struct Credit {
    pub amount: u64,
    pub expires_at: u64, // ms
}

#[derive(Debug, Default)]
struct Inner {
    by_id: HashMap<String, Stored>,
    /// Per-recipient insertion-ordered ids (oldest first).
    queues: HashMap<String, Vec<String>>,
    /// Prepaid credit per comms_id(to)
    credits: HashMap<String, Credit>,
}

#[derive(Clone, Debug)]
struct Stored {
    to: String,
    sent_at: u64,
    expires_at: u64,
    envelope: Envelope,
}

/// In-memory, process-local store of undelivered envelopes.
///
/// Cheap to wrap in an `Arc`; all operations take a single mutex.
#[derive(Debug, Default)]
pub struct Store {
    inner: Mutex<Inner>,
}

impl Store {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an envelope, deduplicating by `id` and clamping its TTL.
    ///
    /// `now` is the current wall-clock ms (the relay's clock, not the client's).
    /// Returns [`StoreError::RateLimited`] when the recipient is at quota.
    pub fn insert(&self, envelope: Envelope, now: u64) -> Result<InsertOutcome, StoreError> {
        let mut inner = self.inner.lock();
        if inner.by_id.contains_key(&envelope.id) {
            return Ok(InsertOutcome::Duplicate);
        }
        let to = envelope.to.clone();
        if inner.queues.get(&to).map(Vec::len).unwrap_or(0) >= MAX_PER_RECIPIENT {
            return Err(StoreError::RateLimited);
        }
        let expires_at = envelope.expires_at.min(now.saturating_add(MAX_TTL_MS));
        let stored = Stored {
            to: to.clone(),
            sent_at: envelope.sent_at,
            expires_at,
            envelope,
        };
        inner
            .queues
            .entry(to)
            .or_default()
            .push(stored.envelope.id.clone());
        let id = stored.envelope.id.clone();
        inner.by_id.insert(id, stored);
        Ok(InsertOutcome::Inserted)
    }

    /// Undelivered envelopes for `to`, oldest first (arrival order), ≤ `limit`
    /// (clamped to [`MAX_INBOX_LIMIT`]) and with `sentAt ≥ since` when set.
    ///
    /// Expired envelopes are skipped defensively even if a sweep has not run.
    /// An unknown recipient yields an empty vector (never an error).
    pub fn inbox(&self, to: &str, limit: usize, since: Option<u64>, now: u64) -> Vec<Envelope> {
        let limit = limit.min(MAX_INBOX_LIMIT);
        let inner = self.inner.lock();
        let Some(queue) = inner.queues.get(to) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for id in queue {
            if out.len() >= limit {
                break;
            }
            let Some(stored) = inner.by_id.get(id) else {
                continue;
            };
            if stored.expires_at <= now {
                continue;
            }
            if let Some(since) = since {
                if stored.sent_at < since {
                    continue;
                }
            }
            out.push(stored.envelope.clone());
        }
        out
    }

    /// Delete the given `ids` for recipient `to`; returns how many were removed.
    ///
    /// Ids belonging to another recipient (or already gone) are ignored.
    pub fn ack(&self, to: &str, ids: &[String]) -> usize {
        let mut inner = self.inner.lock();
        let mut deleted = 0usize;
        for id in ids {
            match inner.by_id.get(id) {
                Some(stored) if stored.to == to => {
                    inner.by_id.remove(id);
                    deleted += 1;
                }
                _ => {}
            }
        }
        if deleted > 0 {
            let dead: std::collections::HashSet<&String> = ids.iter().collect();
            if let Some(queue) = inner.queues.get_mut(to) {
                queue.retain(|id| !dead.contains(id));
            }
        }
        deleted
    }

    /// Drop every envelope whose `expiresAt ≤ now`; returns the number removed.
    pub fn sweep(&self, now: u64) -> usize {
        let mut inner = self.inner.lock();
        let expired: Vec<String> = inner
            .by_id
            .iter()
            .filter(|(_, stored)| stored.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        if expired.is_empty() {
            // still sweep credits
            return Self::credit_sweep_locked(&mut inner, now);
        }
        let dead: std::collections::HashSet<&String> = expired.iter().collect();
        for id in &expired {
            inner.by_id.remove(id);
        }
        inner.queues.retain(|_, queue| {
            queue.retain(|id| !dead.contains(id));
            !queue.is_empty()
        });
        let _ = Self::credit_sweep_locked(&mut inner, now);
        expired.len()
    }

    /// Total number of stored (undelivered) envelopes.
    pub fn len(&self) -> usize {
        self.inner.lock().by_id.len()
    }

    /// Whether the store holds no envelopes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of stored envelopes for a single recipient.
    pub fn count_for(&self, to: &str) -> usize {
        self.inner.lock().queues.get(to).map(Vec::len).unwrap_or(0)
    }

    /// Add prepaid credit (atoms) to `to`. Returns new total amount.
    pub fn credit_add(&self, to: &str, atoms: u64, now: u64) -> u64 {
        if atoms == 0 {
            return self.credit_balance(to, now);
        }
        let mut inner = self.inner.lock();
        let credit_ttl = std::env::var("KOVANICA_RELAY_CREDIT_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(24 * 60 * 60 * 1000);
        let max_credit = std::env::var("KOVANICA_RELAY_MAX_CREDIT_PER_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10_000_000);
        let entry = inner.credits.entry(to.to_string()).or_insert(Credit {
            amount: 0,
            expires_at: now + credit_ttl,
        });
        if entry.expires_at <= now {
            entry.amount = 0;
            entry.expires_at = now + credit_ttl;
        } else {
            entry.expires_at = now + credit_ttl;
        }
        entry.amount = entry.amount.saturating_add(atoms).min(max_credit);
        entry.amount
    }

    /// Deduct prepaid credit; returns true if sufficient unexpired credit exists.
    pub fn credit_deduct(&self, to: &str, atoms: u64, now: u64) -> bool {
        if atoms == 0 {
            return true;
        }
        let mut inner = self.inner.lock();
        let Some(entry) = inner.credits.get_mut(to) else {
            return false;
        };
        if entry.expires_at <= now {
            inner.credits.remove(to);
            return false;
        }
        if entry.amount < atoms {
            return false;
        }
        entry.amount -= atoms;
        if entry.amount == 0 {
            inner.credits.remove(to);
        }
        true
    }

    /// Sweep expired credits; returns number removed.
    pub fn credit_sweep(&self, now: u64) -> usize {
        let mut inner = self.inner.lock();
        Self::credit_sweep_locked(&mut inner, now)
    }

    /// Sweep expired credits while the caller already holds the store lock.
    fn credit_sweep_locked(inner: &mut Inner, now: u64) -> usize {
        let mut removed = 0;
        inner.credits.retain(|_, c| {
            if c.expires_at <= now {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    pub fn credit_balance(&self, to: &str, now: u64) -> u64 {
        let inner = self.inner.lock();
        match inner.credits.get(to) {
            Some(c) if c.expires_at > now => c.amount,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{comms_id_hex, ENVELOPE_VERSION};
    use crate::ALG_V1;

    fn env(id: &str, to: &str, sent_at: u64, expires_at: u64) -> Envelope {
        Envelope {
            v: ENVELOPE_VERSION,
            id: id.to_string(),
            to: to.to_string(),
            from: comms_id_hex(&[9u8; 32]),
            sent_at,
            expires_at,
            alg: ALG_V1.to_string(),
            epk: vec![1u8; 32],
            nonce: vec![2u8; 24],
            ct: vec![3u8; 8],
            sig: vec![4u8; 64],
        }
    }

    #[test]
    fn dedup_by_id() {
        let store = Store::new();
        assert_eq!(
            store.insert(env("aa", "to", 1, u64::MAX), 0).unwrap(),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(env("aa", "to", 1, u64::MAX), 0).unwrap(),
            InsertOutcome::Duplicate
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn inbox_is_arrival_ordered_and_filtered() {
        let store = Store::new();
        store.insert(env("id1", "to", 10, u64::MAX), 0).unwrap();
        store.insert(env("id2", "to", 20, u64::MAX), 0).unwrap();
        store.insert(env("id3", "to", 30, u64::MAX), 0).unwrap();

        let all = store.inbox("to", 50, None, 0);
        assert_eq!(
            all.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["id1", "id2", "id3"]
        );

        // limit
        let two = store.inbox("to", 2, None, 0);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].id, "id1");

        // since filters by sentAt
        let since = store.inbox("to", 50, Some(20), 0);
        assert_eq!(
            since.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["id2", "id3"]
        );

        // unknown recipient → empty
        assert!(store.inbox("nobody", 50, None, 0).is_empty());
    }

    #[test]
    fn limit_is_clamped_to_max() {
        let store = Store::new();
        for i in 0..300u32 {
            store
                .insert(env(&format!("id{i}"), "to", i as u64, u64::MAX), 0)
                .unwrap();
        }
        assert_eq!(store.inbox("to", 1000, None, 0).len(), MAX_INBOX_LIMIT);
    }

    #[test]
    fn ack_deletes_only_own_ids() {
        let store = Store::new();
        store.insert(env("a", "alice", 1, u64::MAX), 0).unwrap();
        store.insert(env("b", "alice", 2, u64::MAX), 0).unwrap();
        store.insert(env("c", "bob", 3, u64::MAX), 0).unwrap();

        assert_eq!(store.ack("alice", &["a".into(), "c".into()]), 1);
        assert_eq!(store.inbox("alice", 10, None, 0).len(), 1);
        assert_eq!(store.inbox("bob", 10, None, 0).len(), 1);
        assert_eq!(store.ack("alice", &["missing".into()]), 0);
    }

    #[test]
    fn expiry_is_clamped_and_swept() {
        let store = Store::new();
        // expiresAt far in the future → the *drop deadline* is clamped to
        // now + MAX_TTL_MS, but the envelope's own signed expiresAt is intact.
        let now = 1_000;
        store.insert(env("x", "to", 1, u64::MAX), now).unwrap();
        let stored = store.inbox("to", 10, None, now);
        assert_eq!(stored[0].expires_at, u64::MAX, "signed field untouched");

        // Still present just before the clamped deadline, dropped at it.
        assert_eq!(store.inbox("to", 10, None, now + MAX_TTL_MS - 1).len(), 1);
        assert_eq!(store.inbox("to", 10, None, now + MAX_TTL_MS).len(), 0);
        assert_eq!(store.sweep(now + MAX_TTL_MS), 1);

        // expiresAt already in the past → dropped by sweep, skipped by inbox.
        store.insert(env("y", "to", 1, 500), now).unwrap();
        assert_eq!(store.inbox("to", 10, None, 2_000).len(), 0);
        assert_eq!(store.sweep(2_000), 1);
    }

    #[test]
    fn quota_overflow_is_rate_limited() {
        let store = Store::new();
        for i in 0..MAX_PER_RECIPIENT {
            store
                .insert(env(&format!("id{i}"), "to", i as u64, u64::MAX), 0)
                .unwrap();
        }
        assert_eq!(
            store.insert(env("overflow", "to", 0, u64::MAX), 0),
            Err(StoreError::RateLimited)
        );
        assert_eq!(store.count_for("to"), MAX_PER_RECIPIENT);
    }
}

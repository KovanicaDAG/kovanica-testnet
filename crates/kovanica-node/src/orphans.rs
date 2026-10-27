//! Bounded buffer for blocks whose parents are not in the DAG yet.
//!
//! When `process_block` fails because a parent is missing, the block is kept
//! here and its missing parents are requested (`BlockSyncRequest::ByHash`)
//! from the peer that delivered it. When a parent is accepted, every buffered
//! child waiting only on it becomes ready and is re-processed by the caller
//! (iteratively, see [`OrphanBuffer::parent_accepted`]).
//!
//! Everything is bounded:
//! * total orphans (`max_orphans`) and total serialized bytes (`max_bytes`):
//!   oldest orphans are evicted first;
//! * per-peer orphans (`max_per_peer`): further orphans from that peer are
//!   refused, so one peer cannot fill the buffer;
//! * age (`ttl`): expired orphans are dropped;
//! * parent requests: deduplicated while in flight, re-sent at most every
//!   `request_retry`, and at most `max_in_flight` outstanding at once, so a
//!   burst of orphans cannot cause a request storm.
//!
//! Time is passed in explicitly so the logic is deterministic in tests.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use kovanica_network::PeerId;
use kovanica_types::{block::StatementBlock, Hash};

/// Limits for [`OrphanBuffer`].
#[derive(Debug, Clone, Copy)]
pub struct OrphanLimits {
    pub max_orphans: usize,
    pub max_bytes: usize,
    pub max_per_peer: usize,
    pub ttl: Duration,
    pub max_in_flight: usize,
    pub request_retry: Duration,
}

impl Default for OrphanLimits {
    fn default() -> Self {
        Self {
            max_orphans: 1024,
            max_bytes: 32 * 1024 * 1024,
            max_per_peer: 256,
            ttl: Duration::from_secs(60),
            max_in_flight: 256,
            request_retry: Duration::from_secs(5),
        }
    }
}

/// Result of [`OrphanBuffer::insert`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InsertOutcome {
    /// The orphan is (now) buffered.
    pub buffered: bool,
    /// Parents to request from the delivering peer (deduplicated, bounded).
    pub requests: Vec<Hash>,
    /// Orphans evicted to make room.
    pub evicted: usize,
}

#[derive(Debug)]
struct Orphan {
    block: StatementBlock,
    peer: PeerId,
    size: usize,
    inserted: Instant,
    missing: HashSet<Hash>,
}

/// See the module docs.
#[derive(Debug)]
pub struct OrphanBuffer {
    limits: OrphanLimits,
    orphans: HashMap<Hash, Orphan>,
    /// Insertion order for FIFO eviction / TTL (may hold stale digests).
    order: VecDeque<Hash>,
    /// parent digest -> children waiting on it.
    waiting: HashMap<Hash, HashSet<Hash>>,
    per_peer: HashMap<PeerId, usize>,
    bytes: usize,
    /// parent digest -> when it was last requested.
    in_flight: HashMap<Hash, Instant>,
}

impl OrphanBuffer {
    pub fn new(limits: OrphanLimits) -> Self {
        Self {
            limits,
            orphans: HashMap::new(),
            order: VecDeque::new(),
            waiting: HashMap::new(),
            per_peer: HashMap::new(),
            bytes: 0,
            in_flight: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub fn contains(&self, digest: &Hash) -> bool {
        self.orphans.contains_key(digest)
    }

    /// Buffer `block` (delivered by `peer`) until `missing` parents arrive.
    pub fn insert(
        &mut self,
        block: StatementBlock,
        peer: PeerId,
        missing: Vec<Hash>,
        now: Instant,
    ) -> InsertOutcome {
        let mut outcome = InsertOutcome::default();
        self.expire(now);
        let missing: HashSet<Hash> = missing.into_iter().collect();
        if missing.is_empty() {
            return outcome;
        }
        let digest = block.digest;
        if self.orphans.contains_key(&digest) {
            // Duplicate delivery: keep the original, maybe re-request.
            outcome.buffered = true;
            outcome.requests = self.select_requests(missing.iter().copied(), now);
            return outcome;
        }
        let size = bincode::serialized_size(&block).map_or(usize::MAX, |s| s as usize);
        if size > self.limits.max_bytes || self.limits.max_orphans == 0 {
            return outcome;
        }
        if self.per_peer.get(&peer).copied().unwrap_or(0) >= self.limits.max_per_peer {
            return outcome;
        }
        while self.orphans.len() >= self.limits.max_orphans
            || self.bytes + size > self.limits.max_bytes
        {
            match self.order.pop_front() {
                Some(old) => {
                    if self.remove(&old).is_some() {
                        outcome.evicted += 1;
                    }
                }
                None => break,
            }
        }
        for parent in &missing {
            self.waiting.entry(*parent).or_default().insert(digest);
        }
        *self.per_peer.entry(peer).or_default() += 1;
        self.bytes += size;
        self.order.push_back(digest);
        outcome.requests = self.select_requests(missing.iter().copied(), now);
        self.orphans.insert(
            digest,
            Orphan {
                block,
                peer,
                size,
                inserted: now,
                missing,
            },
        );
        outcome.buffered = true;
        outcome
    }

    /// `parent` is now in the DAG: return the orphans that no longer miss any
    /// parent (removed from the buffer). The caller processes each one and,
    /// on success, calls this again with its digest (iterative, no recursion).
    pub fn parent_accepted(&mut self, parent: &Hash) -> Vec<(StatementBlock, PeerId)> {
        self.in_flight.remove(parent);
        let Some(children) = self.waiting.remove(parent) else {
            return Vec::new();
        };
        let mut ready = Vec::new();
        for child in children {
            let done = match self.orphans.get_mut(&child) {
                Some(orphan) => {
                    orphan.missing.remove(parent);
                    orphan.missing.is_empty()
                }
                None => false,
            };
            if done {
                if let Some(orphan) = self.remove(&child) {
                    ready.push((orphan.block, orphan.peer));
                }
            }
        }
        // Deterministic processing order: lower rounds first.
        ready.sort_by_key(|(b, _)| (b.round, b.author));
        ready
    }

    /// Drop orphans older than the TTL and stale in-flight markers.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        while let Some(front) = self.order.front().copied() {
            match self.orphans.get(&front) {
                None => {
                    self.order.pop_front();
                }
                Some(o) if now.duration_since(o.inserted) >= self.limits.ttl => {
                    self.order.pop_front();
                    self.remove(&front);
                    dropped += 1;
                }
                Some(_) => break,
            }
        }
        let ttl = self.limits.ttl;
        self.in_flight.retain(|_, t| now.duration_since(*t) < ttl);
        dropped
    }

    fn select_requests(&mut self, parents: impl Iterator<Item = Hash>, now: Instant) -> Vec<Hash> {
        let mut out: Vec<Hash> = Vec::new();
        for parent in parents {
            let due = self
                .in_flight
                .get(&parent)
                .is_none_or(|t| now.duration_since(*t) >= self.limits.request_retry);
            if !due {
                continue;
            }
            if !self.in_flight.contains_key(&parent)
                && self.in_flight.len() >= self.limits.max_in_flight
            {
                continue;
            }
            self.in_flight.insert(parent, now);
            out.push(parent);
        }
        out.sort_by_key(|h| h.0);
        out
    }

    fn remove(&mut self, digest: &Hash) -> Option<Orphan> {
        let orphan = self.orphans.remove(digest)?;
        self.bytes -= orphan.size;
        if let Some(n) = self.per_peer.get_mut(&orphan.peer) {
            *n -= 1;
            if *n == 0 {
                self.per_peer.remove(&orphan.peer);
            }
        }
        for parent in &orphan.missing {
            if let Some(set) = self.waiting.get_mut(parent) {
                set.remove(digest);
                if set.is_empty() {
                    self.waiting.remove(parent);
                }
            }
        }
        Some(orphan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::{block::BlockReference, Signature};

    fn block(round: u64, author: u16, parents: &[Hash]) -> StatementBlock {
        let parents: Vec<BlockReference> = parents
            .iter()
            .map(|d| BlockReference {
                author: 0,
                round: round.saturating_sub(1),
                digest: *d,
            })
            .collect();
        let digest = StatementBlock::compute_digest(author, round, &parents, &[]);
        StatementBlock {
            author,
            round,
            parents,
            transactions: Vec::new(),
            statements: Vec::new(),
            signature: Signature([0; 64]),
            digest,
            merkle_root: StatementBlock::compute_merkle_root(&[]),
        }
    }

    fn h(tag: &[u8]) -> Hash {
        Hash::new(tag)
    }

    fn limits() -> OrphanLimits {
        OrphanLimits {
            max_orphans: 4,
            max_bytes: 1 << 20,
            max_per_peer: 3,
            ttl: Duration::from_secs(60),
            max_in_flight: 8,
            request_retry: Duration::from_secs(5),
        }
    }

    #[test]
    fn buffers_and_releases_children_iteratively() {
        let mut buf = OrphanBuffer::new(limits());
        let now = Instant::now();
        let peer = PeerId::random();
        let p = h(b"p");
        let child = block(2, 1, &[p]);
        let grandchild = block(3, 1, &[child.digest]);
        let out = buf.insert(child.clone(), peer, vec![p], now);
        assert!(out.buffered);
        assert_eq!(out.requests, vec![p]);
        let out = buf.insert(grandchild.clone(), peer, vec![child.digest], now);
        assert_eq!(out.requests, vec![child.digest]);
        assert_eq!(buf.len(), 2);

        let ready = buf.parent_accepted(&p);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0.digest, child.digest);
        let ready = buf.parent_accepted(&child.digest);
        assert_eq!(ready[0].0.digest, grandchild.digest);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.bytes(), 0);
    }

    #[test]
    fn child_waits_for_all_missing_parents() {
        let mut buf = OrphanBuffer::new(limits());
        let now = Instant::now();
        let (a, b) = (h(b"a"), h(b"b"));
        let child = block(2, 1, &[a, b]);
        buf.insert(child, PeerId::random(), vec![a, b], now);
        assert!(buf.parent_accepted(&a).is_empty());
        assert_eq!(buf.parent_accepted(&b).len(), 1);
    }

    #[test]
    fn duplicate_orphan_is_deduplicated_and_requests_not_repeated() {
        let mut buf = OrphanBuffer::new(limits());
        let now = Instant::now();
        let peer = PeerId::random();
        let p = h(b"p");
        let child = block(2, 1, &[p]);
        assert_eq!(
            buf.insert(child.clone(), peer, vec![p], now).requests,
            vec![p]
        );
        let again = buf.insert(child.clone(), peer, vec![p], now + Duration::from_secs(1));
        assert!(again.buffered);
        assert!(
            again.requests.is_empty(),
            "in-flight request must not repeat"
        );
        assert_eq!(buf.len(), 1);
        // A different orphan with the same missing parent shares the request.
        let sibling = block(2, 2, &[p]);
        assert!(buf.insert(sibling, peer, vec![p], now).requests.is_empty());
        // After the retry interval the parent may be requested again.
        let later = buf.insert(child, peer, vec![p], now + Duration::from_secs(6));
        assert_eq!(later.requests, vec![p]);
    }

    #[test]
    fn oldest_orphan_is_evicted_at_capacity() {
        let mut buf = OrphanBuffer::new(OrphanLimits {
            max_per_peer: 100,
            ..limits()
        });
        let now = Instant::now();
        let peer = PeerId::random();
        let blocks: Vec<_> = (0..5u16).map(|i| block(2, i, &[h(&[i as u8])])).collect();
        for (i, b) in blocks.iter().enumerate() {
            let out = buf.insert(b.clone(), peer, vec![h(&[i as u8])], now);
            assert_eq!(out.evicted, usize::from(i == 4));
        }
        assert_eq!(buf.len(), 4);
        assert!(!buf.contains(&blocks[0].digest), "oldest evicted");
        assert!(buf.contains(&blocks[4].digest));
        // The evicted orphan is no longer released by its parent.
        assert!(buf.parent_accepted(&h(&[0])).is_empty());
    }

    #[test]
    fn byte_limit_evicts_and_oversized_block_is_refused() {
        let one = bincode::serialized_size(&block(2, 0, &[h(b"x")])).unwrap() as usize;
        let mut buf = OrphanBuffer::new(OrphanLimits {
            max_bytes: one * 2,
            max_per_peer: 100,
            ..limits()
        });
        let now = Instant::now();
        let peer = PeerId::random();
        for i in 0..3u16 {
            buf.insert(block(2, i, &[h(b"x")]), peer, vec![h(b"x")], now);
        }
        assert_eq!(buf.len(), 2);
        assert!(buf.bytes() <= one * 2);

        let mut tiny = OrphanBuffer::new(OrphanLimits {
            max_bytes: one - 1,
            ..limits()
        });
        assert!(
            !tiny
                .insert(block(2, 0, &[h(b"x")]), peer, vec![h(b"x")], now)
                .buffered
        );
    }

    #[test]
    fn ttl_expires_orphans_and_in_flight_markers() {
        let mut buf = OrphanBuffer::new(limits());
        let now = Instant::now();
        let p = h(b"p");
        buf.insert(block(2, 1, &[p]), PeerId::random(), vec![p], now);
        assert_eq!(buf.expire(now + Duration::from_secs(59)), 0);
        assert_eq!(buf.expire(now + Duration::from_secs(60)), 1);
        assert_eq!(buf.len(), 0);
        assert!(buf.parent_accepted(&p).is_empty());
        // In-flight marker expired too: a new orphan requests the parent again.
        let out = buf.insert(
            block(2, 2, &[p]),
            PeerId::random(),
            vec![p],
            now + Duration::from_secs(61),
        );
        assert_eq!(out.requests, vec![p]);
    }

    #[test]
    fn per_peer_limit_refuses_further_orphans_from_that_peer() {
        let mut buf = OrphanBuffer::new(limits());
        let now = Instant::now();
        let (noisy, other) = (PeerId::random(), PeerId::random());
        for i in 0..3u16 {
            assert!(
                buf.insert(
                    block(2, i, &[h(&[i as u8])]),
                    noisy,
                    vec![h(&[i as u8])],
                    now
                )
                .buffered
            );
        }
        assert!(
            !buf.insert(block(2, 9, &[h(b"z")]), noisy, vec![h(b"z")], now)
                .buffered
        );
        assert!(
            buf.insert(block(2, 9, &[h(b"z")]), other, vec![h(b"z")], now)
                .buffered
        );
        // Releasing one frees a slot for the noisy peer.
        assert_eq!(buf.parent_accepted(&h(&[0])).len(), 1);
        assert!(
            buf.insert(block(2, 7, &[h(b"y")]), noisy, vec![h(b"y")], now)
                .buffered
        );
    }

    #[test]
    fn in_flight_requests_are_capped() {
        let mut buf = OrphanBuffer::new(OrphanLimits {
            max_in_flight: 2,
            max_per_peer: 100,
            ..limits()
        });
        let now = Instant::now();
        let parents = [h(b"1"), h(b"2"), h(b"3")];
        let out = buf.insert(
            block(2, 1, &parents),
            PeerId::random(),
            parents.to_vec(),
            now,
        );
        assert_eq!(out.requests.len(), 2, "no request storm beyond the cap");
    }
}

//! Node health shared between background tasks and the `/health` endpoint.
//!
//! The execution worker stops on the first error (so committed decisions are
//! replayed after a restart), and the consensus engine task can exit with an
//! error. Without a shared status the node kept answering `/health` with
//! `ok` while no longer executing anything. [`NodeHealth`] lets those tasks
//! report their state so `/health` turns `degraded` (HTTP 503) and container
//! health checks / orchestrators can restart the node.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Maximum length of an error message exposed through `/health`.
const MAX_ERROR_LEN: usize = 256;

/// Default window, in seconds, after which a node that has not committed a new
/// leader is reported unhealthy.
///
/// The round loop keeps advancing and gossip keeps flowing even when the
/// commit rule has stalled, so component state alone produces a *false green*:
/// a node can report `running`/`healthy` indefinitely while the chain never
/// advances. With `KOVANICA_ROUND_DURATION_MS=4000` and `WAVE_LENGTH=3` a
/// leader commits every ~12 s, so 120 s is ten missed leaders — well beyond
/// normal jitter. The check is measured from node start until the first
/// commit, so a node that has never committed is also caught.
pub const DEFAULT_COMMIT_STALL_SECS: u64 = 120;

/// Lifecycle state of a supervised component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Started, no progress reported yet.
    Starting,
    /// Running and has made progress.
    Running,
    /// Exited without an error (e.g. its input channel closed).
    Stopped,
    /// Exited with an error.
    Failed,
}

impl ComponentState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Running,
            2 => Self::Stopped,
            3 => Self::Failed,
            _ => Self::Starting,
        }
    }

    fn is_down(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

#[derive(Debug)]
struct Inner {
    execution_state: AtomicU8,
    executed_subdags: AtomicU64,
    last_executed_round: AtomicU64,
    last_execution_unix_ms: AtomicU64,
    consensus_state: AtomicU8,
    /// Number of committed leaders observed by this node.
    committed_leaders: AtomicU64,
    /// Leader round of the most recent commit.
    last_committed_round: AtomicU64,
    /// Wall-clock time of the most recent commit. Seeded with the node start
    /// time so "never committed yet" still has a measurable age.
    last_commit_unix_ms: AtomicU64,
    /// Commit-liveness window in seconds; `0` disables the check.
    commit_stall_secs: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            execution_state: AtomicU8::new(ComponentState::Starting as u8),
            executed_subdags: AtomicU64::new(0),
            last_executed_round: AtomicU64::new(0),
            last_execution_unix_ms: AtomicU64::new(0),
            consensus_state: AtomicU8::new(ComponentState::Starting as u8),
            committed_leaders: AtomicU64::new(0),
            last_committed_round: AtomicU64::new(0),
            last_commit_unix_ms: AtomicU64::new(now_ms()),
            commit_stall_secs: AtomicU64::new(DEFAULT_COMMIT_STALL_SECS),
            last_error: Mutex::new(None),
        }
    }
}

/// Cheaply clonable handle to the node's health state.
#[derive(Debug, Clone, Default)]
pub struct NodeHealth {
    inner: Arc<Inner>,
}

/// Execution part of a [`HealthSnapshot`].
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionHealth {
    pub state: ComponentState,
    pub executed_subdags: u64,
    pub last_executed_round: Option<u64>,
    /// Seconds since the last successfully executed sub-DAG, if any.
    pub seconds_since_last_execution: Option<u64>,
}

/// Consensus part of a [`HealthSnapshot`].
#[derive(Debug, Clone, Serialize)]
pub struct ConsensusHealth {
    pub state: ComponentState,
    /// Committed leaders observed by this node.
    pub committed_leaders: u64,
    /// Leader round of the most recent commit, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_committed_round: Option<u64>,
    /// Seconds since the last commit, or since node start when nothing has
    /// committed yet. `None` when commit-liveness tracking is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_since_last_commit: Option<u64>,
    /// Window after which the absence of a new commit makes the node
    /// unhealthy. `None` when commit-liveness tracking is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_stall_secs: Option<u64>,
}

/// Point-in-time view of the node's health.
#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
    pub healthy: bool,
    pub execution: ExecutionHealth,
    pub consensus: ConsensusHealth,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Move `state` to `Stopped` unless it is already `Failed` (a failure must
/// stay visible).
fn mark_stopped(state: &AtomicU8) {
    let mut current = state.load(Ordering::Relaxed);
    while current != ComponentState::Failed as u8 {
        match state.compare_exchange_weak(
            current,
            ComponentState::Stopped as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate(msg: &str) -> String {
    if msg.len() <= MAX_ERROR_LEN {
        return msg.to_string();
    }
    let mut end = MAX_ERROR_LEN;
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &msg[..end])
}

impl NodeHealth {
    /// New health handle with every component in [`ComponentState::Starting`].
    pub fn new() -> Self {
        Self::default()
    }

    fn set_error(&self, msg: &str) {
        let mut guard = self
            .inner
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(truncate(msg));
    }

    /// Record a successfully executed committed sub-DAG.
    pub fn execution_progress(&self, leader_round: u64) {
        let i = &self.inner;
        i.executed_subdags.fetch_add(1, Ordering::Relaxed);
        i.last_executed_round.store(leader_round, Ordering::Relaxed);
        i.last_execution_unix_ms.store(now_ms(), Ordering::Relaxed);
        // Never resurrect a stopped/failed worker from a stale progress call.
        let _ = i.execution_state.compare_exchange(
            ComponentState::Starting as u8,
            ComponentState::Running as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Record a newly committed leader.
    ///
    /// This is the consensus-liveness signal: the round loop keeps advancing
    /// and gossip keeps flowing even when the commit rule has stalled, so only
    /// an actual commit proves the chain is making progress. Call it from the
    /// commit/execution path, once per committed leader.
    pub fn commit_progress(&self, leader_round: u64) {
        let i = &self.inner;
        i.committed_leaders.fetch_add(1, Ordering::Relaxed);
        i.last_committed_round
            .store(leader_round, Ordering::Relaxed);
        i.last_commit_unix_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Override the commit-liveness window.
    ///
    /// `secs` is the number of seconds without a new commit after which
    /// [`Self::is_healthy`] returns `false`. `0` disables the check entirely
    /// (useful for nodes that are deliberately not following the chain).
    pub fn set_commit_stall_secs(&self, secs: u64) {
        self.inner.commit_stall_secs.store(secs, Ordering::Relaxed);
    }

    /// Configured commit-liveness window; `0` means the check is disabled.
    pub fn commit_stall_secs(&self) -> u64 {
        self.inner.commit_stall_secs.load(Ordering::Relaxed)
    }

    /// Seconds since the last commit (or since node start when nothing has
    /// committed yet).
    pub fn seconds_since_last_commit(&self) -> u64 {
        let last = self.inner.last_commit_unix_ms.load(Ordering::Relaxed);
        if last == 0 {
            return 0;
        }
        now_ms().saturating_sub(last) / 1000
    }

    /// `true` when no commit has been observed within the configured window.
    fn commit_stalled(&self) -> bool {
        let window = self.commit_stall_secs();
        window > 0 && self.seconds_since_last_commit() > window
    }

    /// The execution worker stopped because of an error.
    pub fn execution_failed(&self, error: &str) {
        self.set_error(&format!("execution: {error}"));
        self.inner
            .execution_state
            .store(ComponentState::Failed as u8, Ordering::Relaxed);
    }

    /// The execution worker exited without an error (input closed or shutdown).
    pub fn execution_stopped(&self) {
        mark_stopped(&self.inner.execution_state);
    }

    /// The consensus engine is running.
    pub fn consensus_running(&self) {
        let _ = self.inner.consensus_state.compare_exchange(
            ComponentState::Starting as u8,
            ComponentState::Running as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// The consensus engine task exited with an error.
    pub fn consensus_failed(&self, error: &str) {
        self.set_error(&format!("consensus: {error}"));
        self.inner
            .consensus_state
            .store(ComponentState::Failed as u8, Ordering::Relaxed);
    }

    /// The consensus engine task exited without an error.
    pub fn consensus_stopped(&self) {
        mark_stopped(&self.inner.consensus_state);
    }

    /// Current state of the execution worker.
    pub fn execution_state(&self) -> ComponentState {
        ComponentState::from_u8(self.inner.execution_state.load(Ordering::Relaxed))
    }

    /// Current state of the consensus engine.
    pub fn consensus_state(&self) -> ComponentState {
        ComponentState::from_u8(self.inner.consensus_state.load(Ordering::Relaxed))
    }

    /// `false` once execution or consensus has stopped or failed, or once the
    /// node has gone too long without committing a new leader.
    pub fn is_healthy(&self) -> bool {
        !self.execution_state().is_down()
            && !self.consensus_state().is_down()
            && !self.commit_stalled()
    }

    /// Snapshot for `/health`.
    pub fn snapshot(&self) -> HealthSnapshot {
        let i = &self.inner;
        let executed = i.executed_subdags.load(Ordering::Relaxed);
        let last_ms = i.last_execution_unix_ms.load(Ordering::Relaxed);
        let committed_leaders = i.committed_leaders.load(Ordering::Relaxed);
        let stall_window = self.commit_stall_secs();
        HealthSnapshot {
            healthy: self.is_healthy(),
            execution: ExecutionHealth {
                state: self.execution_state(),
                executed_subdags: executed,
                last_executed_round: (executed > 0)
                    .then(|| i.last_executed_round.load(Ordering::Relaxed)),
                seconds_since_last_execution: (last_ms > 0)
                    .then(|| now_ms().saturating_sub(last_ms) / 1000),
            },
            consensus: ConsensusHealth {
                state: self.consensus_state(),
                committed_leaders,
                last_committed_round: (committed_leaders > 0)
                    .then(|| i.last_committed_round.load(Ordering::Relaxed)),
                seconds_since_last_commit: (stall_window > 0)
                    .then(|| self.seconds_since_last_commit()),
                commit_stall_secs: (stall_window > 0).then_some(stall_window),
            },
            last_error: i
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy_and_tracks_progress() {
        let h = NodeHealth::new();
        assert!(h.is_healthy());
        assert_eq!(h.execution_state(), ComponentState::Starting);
        h.execution_progress(7);
        h.consensus_running();
        let s = h.snapshot();
        assert!(s.healthy);
        assert_eq!(s.execution.state, ComponentState::Running);
        assert_eq!(s.execution.executed_subdags, 1);
        assert_eq!(s.execution.last_executed_round, Some(7));
        assert_eq!(s.consensus.state, ComponentState::Running);
        assert!(s.last_error.is_none());
    }

    /// A node whose components are all `running` but which has stopped
    /// committing leaders must not report `healthy` (the false-green this
    /// check exists to prevent).
    #[test]
    fn commit_stall_degrades_while_components_still_report_running() {
        let h = NodeHealth::new();
        h.execution_progress(3);
        h.commit_progress(3);
        h.consensus_running();
        assert!(h.is_healthy());

        let s = h.snapshot();
        assert_eq!(s.consensus.committed_leaders, 1);
        assert_eq!(s.consensus.last_committed_round, Some(3));
        assert_eq!(
            s.consensus.commit_stall_secs,
            Some(DEFAULT_COMMIT_STALL_SECS)
        );

        // Shrink the window, then let time pass without committing.
        h.set_commit_stall_secs(1);
        std::thread::sleep(std::time::Duration::from_millis(2_100));

        let s = h.snapshot();
        assert_eq!(
            s.consensus.state,
            ComponentState::Running,
            "component state alone still looks fine"
        );
        assert_eq!(s.execution.state, ComponentState::Running);
        assert!(
            s.consensus.seconds_since_last_commit.unwrap_or(0) > 1,
            "no commit inside the window"
        );
        assert!(!s.healthy, "commit stall must degrade /health");
        assert!(!h.is_healthy());

        // A fresh commit clears the stall.
        h.commit_progress(9);
        assert!(h.is_healthy());
        assert_eq!(h.snapshot().consensus.last_committed_round, Some(9));
    }

    #[test]
    fn commit_liveness_can_be_disabled() {
        let h = NodeHealth::new();
        h.set_commit_stall_secs(0);
        let s = h.snapshot();
        assert!(s.healthy, "0 disables the check");
        assert!(s.consensus.seconds_since_last_commit.is_none());
        assert!(s.consensus.commit_stall_secs.is_none());
    }

    /// A node that has never committed still ages towards a stall, measured
    /// from node start rather than from an unset timestamp.
    #[test]
    fn never_committed_node_ages_from_start() {
        let h = NodeHealth::new();
        h.set_commit_stall_secs(1);
        assert!(h.is_healthy());
        std::thread::sleep(std::time::Duration::from_millis(2_100));
        assert!(
            !h.is_healthy(),
            "no commit since start must eventually degrade"
        );
        assert_eq!(h.snapshot().consensus.last_committed_round, None);
    }

    #[test]
    fn execution_failure_degrades_and_sticks() {
        let h = NodeHealth::new();
        h.execution_progress(1);
        h.execution_failed("state root mismatch");
        h.execution_progress(2);
        h.execution_stopped();
        let s = h.snapshot();
        assert!(!s.healthy);
        assert_eq!(s.execution.state, ComponentState::Failed);
        assert_eq!(
            s.last_error.as_deref(),
            Some("execution: state root mismatch")
        );
    }

    #[test]
    fn stopped_components_are_unhealthy() {
        let h = NodeHealth::new();
        h.execution_stopped();
        assert!(!h.is_healthy());

        let h = NodeHealth::new();
        h.consensus_failed("boom");
        assert!(!h.is_healthy());
        assert_eq!(h.snapshot().consensus.state, ComponentState::Failed);
    }

    #[test]
    fn long_errors_are_truncated_on_char_boundary() {
        let h = NodeHealth::new();
        h.execution_failed(&"ž".repeat(500));
        let err = h.snapshot().last_error.unwrap();
        assert!(err.len() <= MAX_ERROR_LEN + "…".len());
        assert!(err.ends_with('…'));
    }
}

//! Prometheus metrics for MysticGhost consensus.

use once_cell::sync::Lazy;
use prometheus_client::encoding::text::{encode, encode_eof};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};
use std::sync::Mutex;

/// Global metrics registry.
static REGISTRY: Lazy<Mutex<Registry>> = Lazy::new(|| Mutex::new(Registry::default()));

/// Get the global metrics registry.
pub fn registry() -> &'static Mutex<Registry> {
    &REGISTRY
}

/// Labels for MysticGhost metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct MysticGhostLabels {
    pub result: &'static str, // "success", "fallback", "error"
}

/// MysticGhost mergeset size (number of blocks in mergeset before colouring).
static MYSTICGHOST_MERGESET_SIZE: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "mysticghost_mergeset_size",
        "Number of blocks in the mergeset before GHOSTDAG colouring",
        gauge.clone(),
    );
    gauge
});

/// MysticGhost colouring duration in milliseconds.
static MYSTICGHOST_COLOURING_DURATION_MS: Lazy<Family<MysticGhostLabels, Histogram>> =
    Lazy::new(|| {
        let family = Family::<MysticGhostLabels, Histogram>::new_with_constructor(|| {
            let buckets: Vec<f64> =
                prometheus_client::metrics::histogram::exponential_buckets(1.0, 2.0, 20).collect();
            Histogram::new(buckets)
        });
        let mut registry = REGISTRY.lock().unwrap();
        registry.register(
            "mysticghost_colouring_duration_ms",
            "Duration of GHOSTDAG colouring in milliseconds",
            family.clone(),
        );
        family
    });

/// Total number of non-blue blocks pruned.
static MYSTICGHOST_PRUNED_BLOCKS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "mysticghost_pruned_blocks",
        "Total number of DAG blocks removed by wave pruning after commit",
        counter.clone(),
    );
    counter
});

/// Total number of waves pruned.
static MYSTICGHOST_PRUNED_WAVES_TOTAL: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "mysticghost_pruned_waves",
        "Total number of waves pruned (all blocks in old waves)",
        counter.clone(),
    );
    counter
});

/// Record mergeset size.
pub fn record_mergeset_size(size: usize) {
    MYSTICGHOST_MERGESET_SIZE.set(size as i64);
}

/// Record colouring duration.
pub fn record_colouring_duration_ms(duration_ms: f64, result: &'static str) {
    let labels = MysticGhostLabels { result };
    MYSTICGHOST_COLOURING_DURATION_MS
        .get_or_create(&labels)
        .observe(duration_ms);
}

/// Record pruned blocks count.
pub fn record_pruned_blocks(count: u64) {
    MYSTICGHOST_PRUNED_BLOCKS_TOTAL.inc_by(count);
}

/// Record pruned waves count.
pub fn record_pruned_waves(count: u64) {
    MYSTICGHOST_PRUNED_WAVES_TOTAL.inc_by(count);
}

/// Current block height.
static BLOCK_HEIGHT: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register("block_height", "Current chain block height", gauge.clone());
    gauge
});

/// Number of connected peers.
static PEER_COUNT: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register("peer_count", "Number of connected P2P peers", gauge.clone());
    gauge
});

/// Size of the mempool (pending transactions).
static MEMPOOL_SIZE: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "mempool_size",
        "Number of pending transactions in mempool",
        gauge.clone(),
    );
    gauge
});

/// Commit latency in milliseconds.
static COMMIT_LATENCY: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "commit_latency",
        "Commit latency in milliseconds (proxy)",
        gauge.clone(),
    );
    gauge
});

/// Mergeset size.
static MERGESET_SIZE: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "mergeset_size",
        "Number of blocks in the mergeset (proxy)",
        gauge.clone(),
    );
    gauge
});

/// RSS memory proxy (MB).
static RSS_PROXY: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "rss_proxy",
        "Approximate RSS memory footprint in MB (proxy)",
        gauge.clone(),
    );
    gauge
});

/// Current consensus round.
///
/// Separate from `block_height` on purpose: rounds advance every round interval
/// (4 s) while a leader commits every wave (12 s), so writing the round into
/// `block_height` made that gauge jump backwards on every commit.
static CURRENT_ROUND: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "current_round",
        "Current consensus round (advances every round interval)",
        gauge.clone(),
    );
    gauge
});

/// Record block height.
///
/// This is the *committed leader* height. Do not feed it the local round number
/// — use [`record_current_round`] for that.
pub fn record_block_height(height: i64) {
    BLOCK_HEIGHT.set(height);
}

/// Record the current consensus round.
pub fn record_current_round(round: i64) {
    CURRENT_ROUND.set(round);
}

/// Record peer count.
pub fn record_peer_count(count: i64) {
    PEER_COUNT.set(count);
}

/// Record mempool size.
pub fn record_mempool_size(size: i64) {
    MEMPOOL_SIZE.set(size);
}

/// Record commit latency (ms).
pub fn record_commit_latency(ms: f64) {
    COMMIT_LATENCY.set(ms as i64);
}

/// Record mergeset size.
pub fn record_mergeset_size_metric(size: usize) {
    MERGESET_SIZE.set(size as i64);
}

/// Record RSS proxy (MB).
pub fn record_rss_proxy(mb: i64) {
    RSS_PROXY.set(mb);
}

// ---------------------------------------------------------------------------
// `kovanica_*` operational metrics (PRO-10, M1-M8)
// ---------------------------------------------------------------------------
//
// These are additive: the older unprefixed series above stay exactly as they
// are so dashboards deployed on the VPS keep working. New series carry the
// `kovanica_` prefix agreed for the M1-M8 set.

/// Reason for a skipped leader. The label values are compile-time constants
/// so a caller cannot create series at will.
///
/// Today only [`SkipReason::Timeout`] is emitted: with `WAVE_LENGTH = 3` there
/// is exactly one leader per wave, and the cross-wave and local-timeout skip
/// paths were removed to eliminate the PRO-35 fork. `Indirect` and
/// `DirectBlame` are defined for the indirect/blame code paths, which are
/// reachable only from tests today; a label value that is never observed does
/// not create a series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// The leader block did not arrive before the local leader deadline.
    Timeout,
    /// The leader was indirectly skipped because it is not causally connected
    /// to a committed leader of its wave.
    Indirect,
    /// The direct rule decided to skip the leader (blame path).
    DirectBlame,
    /// A quorum skip certificate moved the commit cursor past the slot
    /// (PRO-40 (b)). The only skip that is a decision.
    Certified,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::Timeout => "timeout",
            SkipReason::Indirect => "indirect",
            SkipReason::DirectBlame => "direct_blame",
            SkipReason::Certified => "certified",
        }
    }
}

/// Kind of block/state sync failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncErrorKind {
    /// The request could not be issued to the peer.
    Request,
    /// A state-sync request could not be issued.
    StateRequest,
    /// The peer answered that it does not have the requested block.
    NotFound,
    /// The peer rejected the request as malformed.
    InvalidRequest,
}

impl SyncErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncErrorKind::Request => "request",
            SyncErrorKind::StateRequest => "state_request",
            SyncErrorKind::NotFound => "not_found",
            SyncErrorKind::InvalidRequest => "invalid_request",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SkipReasonLabels {
    pub reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SyncErrorLabels {
    pub kind: &'static str,
}

/// Leaders committed by this node.
static KOVANICA_COMMITTED_LEADERS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_committed_leaders",
        "Total committed leaders",
        counter.clone(),
    );
    counter
});

/// Leader slots whose block did not arrive by this node's leader deadline, by
/// reason.
///
/// Since PRO-35 a timeout is **not** a decision: the committer stalls at the
/// round instead of skipping it. The counter therefore measures missed leader
/// blocks, not rounds the chain moved past.
static KOVANICA_SKIPPED_LEADERS_TOTAL: Lazy<Family<SkipReasonLabels, Counter>> = Lazy::new(|| {
    let family = Family::<SkipReasonLabels, Counter>::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_skipped_leaders",
        "Leader slots that timed out (block missed the deadline); the chain stalls, it does not skip",
        family.clone(),
    );
    family
});

/// Time from first sighting the leader block to committing it, in seconds.
///
/// This is node-local finality latency: it measures how long this node needed
/// from receiving the leader block to a durable commit. It is *not* the time
/// from proposal — `StatementBlock` carries no timestamp — so a leader's own
/// node sees roughly the vote-round delay. Buckets cover 1 ms .. ~4 s, which
/// is the useful range at a 4 s round / 12 s commit cadence.
static KOVANICA_FINALITY_LATENCY_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    let buckets: Vec<f64> =
        prometheus_client::metrics::histogram::exponential_buckets(0.001, 2.0, 13).collect();
    let histogram = Histogram::new(buckets);
    let mut registry = REGISTRY.lock().unwrap();
    registry.register_with_unit(
        "kovanica_finality_latency",
        "Seconds from first sighting a leader block to committing it",
        Unit::Seconds,
        histogram.clone(),
    );
    histogram
});

/// Round of the most recently committed leader.
static KOVANICA_LAST_COMMITTED_ROUND: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_last_committed_round",
        "Round of the most recently committed leader",
        gauge.clone(),
    );
    gauge
});

/// Connected P2P peers.
static KOVANICA_CONNECTED_PEERS: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_connected_peers",
        "Number of connected P2P peers",
        gauge.clone(),
    );
    gauge
});

/// Active validators in the current committee.
static KOVANICA_ACTIVE_VALIDATORS: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_active_validators",
        "Number of active validators in the current committee",
        gauge.clone(),
    );
    gauge
});

/// Sync failures, by kind.
static KOVANICA_SYNC_ERRORS_TOTAL: Lazy<Family<SyncErrorLabels, Counter>> = Lazy::new(|| {
    let family = Family::<SyncErrorLabels, Counter>::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_sync_errors",
        "Total block/state sync failures, by kind",
        family.clone(),
    );
    family
});

/// Leading 8 bytes of the last committed leader digest, as a `u64`.
///
/// Deliberately **not** an info metric: a `digest` label would create one
/// series per commit (~7 200/day at a 12 s cadence) and exhaust Prometheus.
/// Exposing the leading 64 bits as a number keeps cardinality at one series
/// per node while still answering the only question operators ask of it — do
/// two nodes agree on the last committed history? Equal values mean they agree
/// (64-bit collision is negligible); different values mean they diverged.
static KOVANICA_LAST_COMMITTED_DIGEST_PREFIX: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_last_committed_digest_prefix",
        "Leading 64 bits of the last committed leader digest (divergence fingerprint)",
        gauge.clone(),
    );
    gauge
});

/// Resident set size in bytes.
static KOVANICA_RSS_BYTES: Lazy<Gauge> = Lazy::new(|| {
    let gauge = Gauge::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_rss_bytes",
        "Resident set size in bytes",
        gauge.clone(),
    );
    gauge
});

/// Record one committed leader: counter, round, and digest fingerprint.
///
/// `digest_prefix` is the leading 8 bytes of the leader digest interpreted as
/// a big-endian `u64`; see [`KOVANICA_LAST_COMMITTED_DIGEST_PREFIX`] for why it
/// is a gauge rather than a labelled info metric.
pub fn record_committed_leader(round: i64, digest_prefix: u64) {
    KOVANICA_COMMITTED_LEADERS_TOTAL.inc();
    KOVANICA_LAST_COMMITTED_ROUND.set(round);
    // Prometheus gauges are i64; the fingerprint is used only for equality
    // comparisons, so its signedness does not matter.
    KOVANICA_LAST_COMMITTED_DIGEST_PREFIX.set(digest_prefix as i64);
}

/// Timeouts this node signed for a leader slot it never voted for
/// (PRO-40 (b)).
static KOVANICA_TIMEOUTS_SIGNED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_timeouts_signed",
        "Leader-slot timeouts signed by this node",
        counter.clone(),
    );
    counter
});

/// Validators seen signing both a vote and a timeout for the same slot.
static KOVANICA_VOTE_TIMEOUT_EQUIVOCATIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "kovanica_vote_timeout_equivocations",
        "Validators observed signing both a vote and a timeout for one leader slot",
        counter.clone(),
    );
    counter
});

/// Record one timeout signed by this node.
pub fn record_timeout_signed() {
    KOVANICA_TIMEOUTS_SIGNED_TOTAL.inc();
}

/// Record a vote/timeout equivocation (evidence only; no slashing yet).
pub fn record_vote_timeout_equivocation() {
    KOVANICA_VOTE_TIMEOUT_EQUIVOCATIONS_TOTAL.inc();
}

/// Record a skipped leader slot.
pub fn record_skipped_leader(reason: SkipReason) {
    KOVANICA_SKIPPED_LEADERS_TOTAL
        .get_or_create(&SkipReasonLabels {
            reason: reason.as_str(),
        })
        .inc();
}

/// Observe node-local finality latency in seconds.
pub fn observe_finality_latency(seconds: f64) {
    KOVANICA_FINALITY_LATENCY_SECONDS.observe(seconds);
}

/// Record the connected peer count.
pub fn record_connected_peers(count: i64) {
    KOVANICA_CONNECTED_PEERS.set(count);
}

/// Record the number of active validators in the current committee.
pub fn record_active_validators(count: i64) {
    KOVANICA_ACTIVE_VALIDATORS.set(count);
}

/// Record one sync failure.
pub fn record_sync_error(kind: SyncErrorKind) {
    KOVANICA_SYNC_ERRORS_TOTAL
        .get_or_create(&SyncErrorLabels {
            kind: kind.as_str(),
        })
        .inc();
}

/// Record resident set size in bytes.
pub fn record_rss_bytes(bytes: u64) {
    // RSS above i64::MAX would be more than 8 EiB; saturate rather than wrap.
    KOVANICA_RSS_BYTES.set(bytes.min(i64::MAX as u64) as i64);
}

/// Encode the metrics registry to the Prometheus text format.
pub fn metrics_text() -> String {
    let mut buffer = String::new();
    let reg = REGISTRY.lock().unwrap();
    let _ = encode(&mut buffer, &reg);
    buffer
}

/// Encode registry content (without EOF) for streaming responses.
pub fn metrics_text_stream(buffer: &mut String) {
    let reg = REGISTRY.lock().unwrap();
    let _ = encode(buffer, &reg);
}

// ---------------------------------------------------------------------------
// JSON-RPC server metrics
// ---------------------------------------------------------------------------

/// Labels for RPC-level metrics.
///
/// `method` is always a bounded, compile-time method name taken from the RPC
/// server's own registry (`"other"` for anything unrecognised). Nothing
/// caller-supplied is ever used verbatim, so the number of series an RPC
/// client can create is fixed at the number of registered methods — a request
/// for an arbitrary method name cannot grow the cardinality.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RpcMethodLabels {
    pub method: &'static str,
}

/// Total JSON-RPC requests handled, by method.
static RPC_REQUESTS_TOTAL: Lazy<Family<RpcMethodLabels, Counter>> = Lazy::new(|| {
    let family = Family::<RpcMethodLabels, Counter>::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "rpc_requests",
        "Total number of JSON-RPC requests handled, by method",
        family.clone(),
    );
    family
});

/// Total JSON-RPC requests answered with a JSON-RPC error, by method.
static RPC_ERRORS_TOTAL: Lazy<Family<RpcMethodLabels, Counter>> = Lazy::new(|| {
    let family = Family::<RpcMethodLabels, Counter>::default();
    let mut registry = REGISTRY.lock().unwrap();
    registry.register(
        "rpc_errors",
        "Total number of JSON-RPC requests answered with an error, by method",
        family.clone(),
    );
    family
});

/// JSON-RPC request latency in seconds, by method.
static RPC_REQUEST_DURATION_SECONDS: Lazy<Family<RpcMethodLabels, Histogram>> = Lazy::new(|| {
    let family = Family::<RpcMethodLabels, Histogram>::new_with_constructor(|| {
        // ~1 ms .. ~16 s, doubling: covers the whole call range up to the
        // 10 s request timeout without a bucket per millisecond.
        let buckets: Vec<f64> =
            prometheus_client::metrics::histogram::exponential_buckets(0.001, 2.0, 15).collect();
        Histogram::new(buckets)
    });
    let mut registry = REGISTRY.lock().unwrap();
    registry.register_with_unit(
        "rpc_request_duration",
        "JSON-RPC request latency in seconds, by method",
        Unit::Seconds,
        family.clone(),
    );
    family
});

/// Record one handled JSON-RPC request: increments the per-method request
/// counter and observes its latency in seconds.
///
/// `method` must be a bounded label (see [`RpcMethodLabels`]); callers pass the
/// handler's registered name, or `"other"` for an unknown method.
pub fn observe_rpc_request(method: &'static str, duration_secs: f64) {
    let labels = RpcMethodLabels { method };
    RPC_REQUESTS_TOTAL.get_or_create(&labels).inc();
    RPC_REQUEST_DURATION_SECONDS
        .get_or_create(&labels)
        .observe(duration_secs);
}

/// Record one JSON-RPC request that was answered with an error (bad version,
/// unauthorized, unknown method, handler error or timeout).
pub fn record_rpc_error(method: &'static str) {
    RPC_ERRORS_TOTAL
        .get_or_create(&RpcMethodLabels { method })
        .inc();
}

/// Read the per-method request counter (diagnostics and tests).
pub fn rpc_request_count(method: &'static str) -> u64 {
    RPC_REQUESTS_TOTAL
        .get_or_create(&RpcMethodLabels { method })
        .get()
}

/// Read the per-method error counter (diagnostics and tests).
pub fn rpc_error_count(method: &'static str) -> u64 {
    RPC_ERRORS_TOTAL
        .get_or_create(&RpcMethodLabels { method })
        .get()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is process-global, but tests run on parallel threads: the
    /// tests that assert on a concrete gauge value must not overlap, or one
    /// test overwrites another's value between the write and the scrape.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        // A panicking test poisons the lock; the value assertions are still
        // meaningful afterwards.
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_metrics_registration() {
        let _guard = serial();
        // Just verify metrics can be registered and used
        record_mergeset_size(100);
        record_colouring_duration_ms(10.5, "success");
        record_colouring_duration_ms(5.2, "fallback");
        record_pruned_blocks(50);
        record_pruned_waves(2);
    }

    /// `block_height` and `current_round` must be separate series. They used to
    /// be the same gauge, fed the local round by the ticker and the committed
    /// leader round by the commit path.
    #[test]
    fn block_height_and_current_round_are_independent() {
        let _guard = serial();
        record_current_round(41);
        record_block_height(13);

        let text = metrics_text();
        assert!(
            text.contains("block_height 13"),
            "block_height should be the committed height, got:\n{text}"
        );
        assert!(
            text.contains("current_round 41"),
            "current_round should be the local round, got:\n{text}"
        );
    }

    /// Pull the `expr:` values out of the alert rules (including `expr: |`
    /// block scalars).
    fn alert_expressions(yaml: &str) -> Vec<String> {
        let lines: Vec<&str> = yaml.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("expr:") {
                let rest = rest.trim();
                if rest.is_empty() || rest == "|" || rest == ">" {
                    let base_indent = line.len() - trimmed.len();
                    i += 1;
                    let mut block = String::new();
                    while i < lines.len() {
                        let cur = lines[i];
                        let cur_trimmed = cur.trim();
                        if cur_trimmed.is_empty() {
                            i += 1;
                            continue;
                        }
                        let indent = cur.len() - cur.trim_start().len();
                        if indent <= base_indent {
                            break;
                        }
                        block.push_str(cur_trimmed);
                        block.push(' ');
                        i += 1;
                    }
                    out.push(block);
                    continue;
                }
                out.push(rest.to_string());
            }
            i += 1;
        }
        out
    }

    /// Identifiers in a PromQL expression, ignoring quoted label values and
    /// unit suffixes (`5m` must not yield `m`).
    fn promql_identifiers(expr: &str) -> Vec<String> {
        // Drop quoted strings (label values), keeping a separator.
        let mut cleaned = String::new();
        let mut in_quotes = false;
        for ch in expr.chars() {
            if ch == '"' {
                in_quotes = !in_quotes;
                cleaned.push(' ');
                continue;
            }
            if !in_quotes {
                cleaned.push(ch);
            }
        }

        let mut out = Vec::new();
        let mut current = String::new();
        let mut prev_alnum = false;
        for ch in cleaned.chars() {
            let is_alnum = ch.is_ascii_alphanumeric() || ch == '_';
            let starts = (ch.is_ascii_alphabetic() || ch == '_') && !prev_alnum;
            if starts {
                current.clear();
                current.push(ch);
            } else if is_alnum && !current.is_empty() {
                current.push(ch);
            } else if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            prev_alnum = is_alnum;
        }
        if !current.is_empty() {
            out.push(current);
        }
        out
    }

    /// Every series the shipped Prometheus rules alert on must exist in this
    /// registry.
    ///
    /// This is the check that was missing: `rss_proxy` and `commit_latency` were
    /// registered but never updated, so `KovanicaMemoryHigh` and
    /// `KovanicaCommitLatencyHigh` could never fire, and nothing noticed because
    /// each side was valid on its own.
    #[test]
    fn alerts_reference_registered_metrics() {
        let _guard = serial();
        // Force every lazily-registered family into the registry.
        record_peer_count(0);
        record_mempool_size(0);
        record_commit_latency(0.0);
        record_rss_proxy(0);
        record_block_height(0);
        record_current_round(0);
        record_mergeset_size(0);
        record_mergeset_size_metric(0);
        record_colouring_duration_ms(0.0, "fallback");
        record_pruned_blocks(0);
        record_pruned_waves(0);
        observe_rpc_request("other", 0.0);
        record_rpc_error("other");

        let text = metrics_text();
        let mut names: Vec<String> = text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let series = line.split_whitespace().next()?;
                // Drop the label set: we compare family names.
                Some(series.split('{').next().unwrap_or(series).to_string())
            })
            .collect();
        names.sort();
        names.dedup();
        assert!(
            names.iter().any(|n| n == "block_height"),
            "registry did not populate:\n{text}"
        );
        // prometheus_client appends `_total`/the unit itself; registering a name
        // that already carries it exported `…_total_total` and
        // `…_seconds_seconds`, which no query would match.
        for name in &names {
            assert!(
                !name.ends_with("_total_total") && !name.ends_with("_seconds_seconds"),
                "metric name has a doubled suffix: {name}"
            );
        }
        // The encoder appends `_total` to counters and `_bucket`/`_sum`/`_count`
        // to histograms, so those exact suffixes are accepted — an arbitrary
        // prefix is not, or a rename would slip through.
        let registered = |name: &str| {
            names.iter().any(|n| {
                n == name
                    || ["_total", "_bucket", "_sum", "_count"]
                        .iter()
                        .any(|suffix| n.strip_prefix(name) == Some(*suffix))
            })
        };

        for expected in [
            "rpc_requests_total",
            "rpc_errors_total",
            "rpc_request_duration_seconds_bucket",
            "mysticghost_pruned_blocks_total",
            "mysticghost_pruned_waves_total",
        ] {
            assert!(
                registered(expected),
                "expected exported series {expected}; registered: {names:?}"
            );
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ops/prometheus/alerts.yml"
        );
        let yaml =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let exprs = alert_expressions(&yaml);
        assert!(!exprs.is_empty(), "no expr: values parsed from {path}");

        // PromQL keywords/functions and Prometheus' own series, not ours.
        const NOT_OURS: &[&str] = &[
            "and",
            "avg",
            "by",
            "changes",
            "count",
            "count_values",
            "delta",
            "group_left",
            "group_right",
            "ignoring",
            "increase",
            "instance",
            "job",
            "max",
            "min",
            "on",
            "or",
            "rate",
            "result",
            "severity",
            "sum",
            "unless",
            "up",
            "without",
        ];

        let mut missing: Vec<String> = Vec::new();
        for expr in &exprs {
            for token in promql_identifiers(expr) {
                if NOT_OURS.contains(&token.as_str()) || registered(&token) {
                    continue;
                }
                missing.push(token);
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "alerts.yml alerts on series this registry never exports: {missing:?}\n\
             registered: {names:?}"
        );
    }

    /// The M1-M8 series must exist under the agreed `kovanica_` prefix, with
    /// the encoder-applied suffixes and bounded label values.
    #[test]
    fn kovanica_metrics_export_the_pro10_names() {
        let _guard = serial();
        record_committed_leader(7, 0xdead_beef_0000_0001);
        record_skipped_leader(SkipReason::Timeout);
        observe_finality_latency(0.25);
        record_connected_peers(4);
        record_active_validators(17);
        record_sync_error(SyncErrorKind::NotFound);
        record_rss_bytes(64 * 1024 * 1024);
        record_skipped_leader(SkipReason::Certified);
        record_timeout_signed();
        record_vote_timeout_equivocation();

        let text = metrics_text();
        for expected in [
            "kovanica_committed_leaders_total",
            "kovanica_skipped_leaders_total{reason=\"timeout\"}",
            "kovanica_finality_latency_seconds_bucket",
            "kovanica_finality_latency_seconds_count",
            "kovanica_last_committed_round",
            "kovanica_last_committed_digest_prefix",
            "kovanica_connected_peers",
            "kovanica_active_validators",
            "kovanica_sync_errors_total{kind=\"not_found\"}",
            "kovanica_rss_bytes",
            "kovanica_skipped_leaders_total{reason=\"certified\"}",
            "kovanica_timeouts_signed_total",
            "kovanica_vote_timeout_equivocations_total",
        ] {
            assert!(text.contains(expected), "missing {expected} in:\n{text}");
        }
        // The reason/kind labels are bounded compile-time constants: no
        // caller-supplied string can grow the cardinality.
        assert_eq!(SkipReason::Timeout.as_str(), "timeout");
        assert_eq!(SkipReason::Indirect.as_str(), "indirect");
        assert_eq!(SkipReason::DirectBlame.as_str(), "direct_blame");
        assert_eq!(SkipReason::Certified.as_str(), "certified");
        assert_eq!(SyncErrorKind::Request.as_str(), "request");
        assert_eq!(SyncErrorKind::StateRequest.as_str(), "state_request");
        assert_eq!(SyncErrorKind::NotFound.as_str(), "not_found");
        assert_eq!(SyncErrorKind::InvalidRequest.as_str(), "invalid_request");
    }

    /// The alert rules read `rss_proxy` and `commit_latency`; a recorder that is
    /// never called leaves the series at 0 and the alert can never fire.
    #[test]
    fn alert_backed_metrics_are_exported() {
        let _guard = serial();
        record_rss_proxy(1234);
        record_commit_latency(321.0);
        record_peer_count(4);
        record_mempool_size(7);

        let text = metrics_text();
        for expected in [
            "rss_proxy 1234",
            "commit_latency 321",
            "peer_count 4",
            "mempool_size 7",
        ] {
            assert!(text.contains(expected), "missing {expected} in:\n{text}");
        }
    }
}

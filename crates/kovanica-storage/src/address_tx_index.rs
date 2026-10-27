//! Local index of committed transactions by address.
//!
//! Written in the same redb write transaction as commit application. The table
//! is not an input to the account state root, snapshot export, or any
//! consensus hash. A chain that predates the table keeps working: startup does
//! not open it, and a query before the first indexed commit returns an empty
//! page.
//!
//! # Key and value
//!
//! Key, 44 bytes: `(address[32], committed_leader_height u64, tx_index u32)`.
//! `tx_index` is the transaction's position in that commit (sub-DAG block
//! order, then transaction order), starting at 0. redb orders integer key
//! parts big-endian, so a reverse range on one address is newest-first.
//!
//! Value, 117 bytes, little-endian, version 1:
//!
//! ```text
//!  0        version = 1
//!  1        role (1 sent, 2 received, 3 both)
//!  2        kind code
//!  3        success (1 or 0)
//!  4..36    tx hash
//!  36..68   sender
//!  68       has counterparty (1 or 0)
//!  69..101  counterparty (zeros when has counterparty is 0)
//!  101..109 amount in atoms (0 when the kind has no KUNA amount)
//!  109..117 fee in atoms
//! ```
//!
//! Logical payload is 44 + 117 = 161 bytes per row, plus redb B-tree page
//! overhead. Each committed transaction writes one row for its sender. It
//! writes a second row when the kind names a counterparty address that is
//! not the sender (322 bytes). A self-counterparty (for example a transfer
//! to oneself) is a single row with role `both`.
//!
//! Counterparty addresses:
//!
//! - `Transfer.to`
//! - `Delegate.validator`
//! - `Call.contract`
//! - `SetCommission.validator`
//! - `ClaimRewards.validator` when set
//!
//! Other kinds index the sender only. Block rewards are not transactions and
//! are not in the history. There is no backfill: commits applied before this
//! table existed are absent. Chain-4 reset starts empty, so no migration is
//! required.
//!
//! # Growth
//!
//! Rows are not pruned with DAG blocks. Block bodies live in the consensus
//! database, which the history read path does not open, so the summary is
//! stored here. Like the per-hash receipt index, the table grows with
//! executed transactions for the life of the database.

use kovanica_types::{Address, Hash, Transaction, TransactionKind};
use redb::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use thiserror::Error;

/// redb table. Created on the first indexed commit, not at `Storage::new`.
const ADDRESS_TX_INDEX: TableDefinition<([u8; 32], u64, u32), [u8; VALUE_LEN]> =
    TableDefinition::new("address_tx_index");

/// Bytes of one key: address + height + tx index.
pub const ADDRESS_TX_INDEX_KEY_LEN: usize = 32 + 8 + 4;

/// Bytes of one value. Layout is documented at the module root.
pub const ADDRESS_TX_INDEX_VALUE_LEN: usize = VALUE_LEN;

const VALUE_LEN: usize = 117;
const VALUE_VERSION: u8 = 1;
const CURSOR_MAGIC: &[u8; 4] = b"kvh1";
const CURSOR_LEN: usize = 16;

/// Role byte: the address signed the transaction.
pub const ROLE_SENT: u8 = 1;
/// Role byte: the address is the kind's counterparty and is not the sender.
pub const ROLE_RECEIVED: u8 = 2;
/// Role byte: the address is both sender and counterparty. One row, not two.
pub const ROLE_BOTH: u8 = 3;

/// Default page size when the caller omits `limit`.
pub const DEFAULT_TX_HISTORY_LIMIT: u64 = 20;
/// Hard cap on a page. Larger requests are clamped, not rejected.
pub const MAX_TX_HISTORY_LIMIT: u64 = 100;

/// Which side of a transaction the caller asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDirection {
    /// Address is the sender, including rows where it is also the counterparty.
    Sent,
    /// Address is the counterparty, including rows where it is also the sender.
    Received,
    /// Every row for the address.
    All,
}

/// One committed transaction touching an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxHistoryEntry {
    /// Transaction hash.
    pub tx_hash: Hash,
    /// Committed-leader height of the sub-DAG that executed it.
    pub height: u64,
    /// Position inside that commit, starting at 0.
    pub tx_index: u32,
    /// Transaction sender.
    pub from: Address,
    /// Counterparty, when the kind has one.
    pub to: Option<Address>,
    /// KUNA amount in atoms. `0` when the kind has no amount field.
    pub amount: u64,
    /// Fee in atoms.
    pub fee: u64,
    /// Stable kind name (`transfer`, `stake`, …).
    pub kind: &'static str,
    /// Whether execution reported the body as successful.
    pub success: bool,
    /// [`ROLE_SENT`], [`ROLE_RECEIVED`], or [`ROLE_BOTH`].
    pub role: u8,
}

/// A newest-first page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxHistoryPage {
    /// Matching rows, newest first.
    pub entries: Vec<TxHistoryEntry>,
    /// Opaque cursor for the next page. `None` when this page is the last.
    pub next_cursor: Option<String>,
}

/// Bounded read of one address.
#[derive(Clone, Debug)]
pub struct TxHistoryQuery {
    /// Account to list.
    pub address: Address,
    /// Page size. `None` uses [`DEFAULT_TX_HISTORY_LIMIT`]. Values above
    /// [`MAX_TX_HISTORY_LIMIT`] are clamped. `Some(0)` returns an empty page.
    pub limit: Option<u64>,
    /// Opaque cursor returned by a previous page. `None` starts at the newest row.
    pub cursor: Option<String>,
    /// Sent, received, or both.
    pub direction: TxDirection,
}

/// Failures from the address index.
#[derive(Debug, Error)]
pub enum AddressTxIndexError {
    /// The cursor was not produced by [`query_tx_history`].
    #[error("invalid transaction history cursor")]
    InvalidCursor,
    /// A stored row is not version 1 or fails its field checks.
    #[error("corrupt address transaction index row")]
    CorruptRow,
    /// More than `u32::MAX` transactions in one commit.
    #[error("too many transactions in one commit to index")]
    TooManyInCommit,
    /// redb read or write failure.
    #[error("database error: {0}")]
    Storage(#[from] redb::StorageError),
    /// redb table failure other than a missing index on a pre-upgrade database.
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
}

/// Record `txs` under `committed_height` in `txn`.
///
/// `txs` is the commit's transactions in execution order, paired with the
/// receipt success flag. An empty slice does not create the table. Calling
/// this again for the same height and indexes overwrites those rows.
pub fn index_committed_txs(
    txn: &WriteTransaction,
    committed_height: u64,
    txs: &[(&Transaction, bool)],
) -> Result<(), AddressTxIndexError> {
    if txs.is_empty() {
        return Ok(());
    }
    let mut table = txn.open_table(ADDRESS_TX_INDEX)?;
    for (i, (tx, success)) in txs.iter().enumerate() {
        let tx_index = u32::try_from(i).map_err(|_| AddressTxIndexError::TooManyInCommit)?;
        let value = encode_value(tx, *success)?;
        let sender = tx.sender.0;
        let other = counterparty(&tx.kind);
        match other {
            Some(addr) if addr != tx.sender => {
                table.insert((sender, committed_height, tx_index), value)?;
                let mut received = value;
                received[1] = ROLE_RECEIVED;
                table.insert((addr.0, committed_height, tx_index), received)?;
            }
            Some(_) => {
                let mut both = value;
                both[1] = ROLE_BOTH;
                table.insert((sender, committed_height, tx_index), both)?;
            }
            None => {
                table.insert((sender, committed_height, tx_index), value)?;
            }
        }
    }
    Ok(())
}

/// Newest-first page for `query.address`.
///
/// The scan is the key range of that address only. It stops after `limit`
/// matching rows or `limit` scanned rows (plus one peek to decide
/// `next_cursor`). When `direction` is `Sent` or `Received` and the scan hits
/// the scan cap before filling `limit` matches, `next_cursor` points at the
/// last scanned row so the caller can continue without an unbounded scan. A
/// database that has never created the table returns an empty page.
pub fn query_tx_history(
    txn: &ReadTransaction,
    query: &TxHistoryQuery,
) -> Result<TxHistoryPage, AddressTxIndexError> {
    if let Some(raw) = &query.cursor {
        decode_cursor(raw)?;
    }
    let limit = clamp_limit(query.limit);
    if limit == 0 {
        return Ok(TxHistoryPage {
            entries: Vec::new(),
            next_cursor: None,
        });
    }

    let table = match txn.open_table(ADDRESS_TX_INDEX) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Ok(TxHistoryPage {
                entries: Vec::new(),
                next_cursor: None,
            });
        }
        Err(e) => return Err(e.into()),
    };

    let addr = query.address.0;
    let start = (addr, 0u64, 0u32);
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let mut entries = Vec::new();
    let mut last_pos: Option<(u64, u32)> = None;
    let mut scanned = 0u64;
    let mut more = false;

    let mut accept = |row_addr: [u8; 32],
                      height: u64,
                      tx_index: u32,
                      value: &[u8; VALUE_LEN]|
     -> Result<bool, AddressTxIndexError> {
        if row_addr != addr {
            return Ok(false);
        }
        let decoded = decode_value(value)?;
        let matches = direction_matches(query.direction, decoded.role);
        if entries.len() == limit as usize || scanned == limit {
            if matches || scanned == limit {
                more = true;
                return Ok(false);
            }
            return Ok(true);
        }
        scanned += 1;
        last_pos = Some((height, tx_index));
        if matches {
            entries.push(decoded.into_entry(height, tx_index));
        }
        Ok(true)
    };

    if let Some((height, tx_index)) = cursor {
        for item in table.range(start..(addr, height, tx_index))?.rev() {
            let (key, value) = item?;
            let (row_addr, row_height, row_index) = key.value();
            if !accept(row_addr, row_height, row_index, &value.value())? {
                break;
            }
        }
    } else {
        for item in table.range(start..=(addr, u64::MAX, u32::MAX))?.rev() {
            let (key, value) = item?;
            let (row_addr, row_height, row_index) = key.value();
            if !accept(row_addr, row_height, row_index, &value.value())? {
                break;
            }
        }
    }

    let next_cursor = if more {
        last_pos.map(|(height, tx_index)| encode_cursor(height, tx_index))
    } else {
        None
    };
    Ok(TxHistoryPage {
        entries,
        next_cursor,
    })
}

struct Decoded {
    tx_hash: Hash,
    from: Address,
    to: Option<Address>,
    amount: u64,
    fee: u64,
    kind: &'static str,
    success: bool,
    role: u8,
}

impl Decoded {
    fn into_entry(self, height: u64, tx_index: u32) -> TxHistoryEntry {
        TxHistoryEntry {
            tx_hash: self.tx_hash,
            height,
            tx_index,
            from: self.from,
            to: self.to,
            amount: self.amount,
            fee: self.fee,
            kind: self.kind,
            success: self.success,
            role: self.role,
        }
    }
}

fn clamp_limit(limit: Option<u64>) -> u64 {
    match limit {
        None => DEFAULT_TX_HISTORY_LIMIT,
        Some(0) => 0,
        Some(n) => n.min(MAX_TX_HISTORY_LIMIT),
    }
}

fn direction_matches(direction: TxDirection, role: u8) -> bool {
    match direction {
        TxDirection::All => true,
        TxDirection::Sent => role == ROLE_SENT || role == ROLE_BOTH,
        TxDirection::Received => role == ROLE_RECEIVED || role == ROLE_BOTH,
    }
}

fn counterparty(kind: &TransactionKind) -> Option<Address> {
    match kind {
        TransactionKind::Transfer { to, .. } => Some(*to),
        TransactionKind::Delegate { validator, .. } => Some(*validator),
        TransactionKind::Call { contract, .. } => Some(*contract),
        TransactionKind::SetCommission { validator, .. } => Some(*validator),
        TransactionKind::ClaimRewards { validator } => *validator,
        TransactionKind::Stake { .. }
        | TransactionKind::Unstake { .. }
        | TransactionKind::Deploy { .. }
        | TransactionKind::RegisterLightNode { .. }
        | TransactionKind::ExitLightNode
        | TransactionKind::SubmitLightWitness { .. }
        | TransactionKind::ClaimTreasury { .. }
        | TransactionKind::Evidence { .. } => None,
    }
}

fn kind_code(kind: &TransactionKind) -> u8 {
    match kind {
        TransactionKind::Transfer { .. } => 0,
        TransactionKind::Stake { .. } => 1,
        TransactionKind::Unstake { .. } => 2,
        TransactionKind::Delegate { .. } => 3,
        TransactionKind::ClaimRewards { .. } => 4,
        TransactionKind::Deploy { .. } => 5,
        TransactionKind::Call { .. } => 6,
        TransactionKind::RegisterLightNode { .. } => 7,
        TransactionKind::ExitLightNode => 8,
        TransactionKind::SubmitLightWitness { .. } => 9,
        TransactionKind::SetCommission { .. } => 10,
        TransactionKind::ClaimTreasury { .. } => 11,
        TransactionKind::Evidence { .. } => 12,
    }
}

fn kind_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "transfer",
        1 => "stake",
        2 => "unstake",
        3 => "delegate",
        4 => "claim_rewards",
        5 => "deploy",
        6 => "call",
        7 => "register_light_node",
        8 => "exit_light_node",
        9 => "submit_light_witness",
        10 => "set_commission",
        11 => "claim_treasury",
        12 => "evidence",
        _ => return None,
    })
}

fn kind_amount(kind: &TransactionKind) -> u64 {
    match kind {
        TransactionKind::Transfer { amount, .. }
        | TransactionKind::Stake { amount }
        | TransactionKind::Unstake { amount }
        | TransactionKind::Delegate { amount, .. }
        | TransactionKind::ClaimTreasury { amount } => *amount,
        TransactionKind::Call { value, .. } => *value,
        TransactionKind::RegisterLightNode { stake, .. } => *stake,
        TransactionKind::ClaimRewards { .. }
        | TransactionKind::Deploy { .. }
        | TransactionKind::ExitLightNode
        | TransactionKind::SubmitLightWitness { .. }
        | TransactionKind::SetCommission { .. }
        | TransactionKind::Evidence { .. } => 0,
    }
}

fn encode_value(tx: &Transaction, success: bool) -> Result<[u8; VALUE_LEN], AddressTxIndexError> {
    let mut out = [0u8; VALUE_LEN];
    out[0] = VALUE_VERSION;
    out[1] = ROLE_SENT;
    out[2] = kind_code(&tx.kind);
    out[3] = u8::from(success);
    out[4..36].copy_from_slice(&tx.hash.0);
    out[36..68].copy_from_slice(&tx.sender.0);
    if let Some(addr) = counterparty(&tx.kind) {
        out[68] = 1;
        out[69..101].copy_from_slice(&addr.0);
    }
    out[101..109].copy_from_slice(&kind_amount(&tx.kind).to_le_bytes());
    out[109..117].copy_from_slice(&tx.fee.to_le_bytes());
    Ok(out)
}

fn decode_value(bytes: &[u8; VALUE_LEN]) -> Result<Decoded, AddressTxIndexError> {
    if bytes[0] != VALUE_VERSION {
        return Err(AddressTxIndexError::CorruptRow);
    }
    let role = bytes[1];
    if role != ROLE_SENT && role != ROLE_RECEIVED && role != ROLE_BOTH {
        return Err(AddressTxIndexError::CorruptRow);
    }
    let kind = kind_name(bytes[2]).ok_or(AddressTxIndexError::CorruptRow)?;
    let success = match bytes[3] {
        0 => false,
        1 => true,
        _ => return Err(AddressTxIndexError::CorruptRow),
    };
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&bytes[4..36]);
    let mut from = [0u8; 32];
    from.copy_from_slice(&bytes[36..68]);
    let to = match bytes[68] {
        0 => None,
        1 => {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes[69..101]);
            Some(Address(raw))
        }
        _ => return Err(AddressTxIndexError::CorruptRow),
    };
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&bytes[101..109]);
    let mut fee = [0u8; 8];
    fee.copy_from_slice(&bytes[109..117]);
    Ok(Decoded {
        tx_hash: Hash(tx_hash),
        from: Address(from),
        to,
        amount: u64::from_le_bytes(amount),
        fee: u64::from_le_bytes(fee),
        kind,
        success,
        role,
    })
}

fn encode_cursor(height: u64, tx_index: u32) -> String {
    let mut raw = [0u8; CURSOR_LEN];
    raw[0..4].copy_from_slice(CURSOR_MAGIC);
    raw[4..12].copy_from_slice(&height.to_be_bytes());
    raw[12..16].copy_from_slice(&tx_index.to_be_bytes());
    hex::encode(raw)
}

fn decode_cursor(raw: &str) -> Result<(u64, u32), AddressTxIndexError> {
    let raw = raw.trim();
    let bytes = hex::decode(raw).map_err(|_| AddressTxIndexError::InvalidCursor)?;
    if bytes.len() != CURSOR_LEN || bytes[0..4] != CURSOR_MAGIC[..] {
        return Err(AddressTxIndexError::InvalidCursor);
    }
    let mut height = [0u8; 8];
    height.copy_from_slice(&bytes[4..12]);
    let mut tx_index = [0u8; 4];
    tx_index.copy_from_slice(&bytes[12..16]);
    Ok((u64::from_be_bytes(height), u32::from_be_bytes(tx_index)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::Account;
    use crate::Storage;
    use kovanica_types::Signature;
    use tempfile::tempdir;

    fn hash_at(i: u64) -> Hash {
        let mut raw = [0u8; 32];
        raw[24..].copy_from_slice(&i.to_be_bytes());
        Hash(raw)
    }

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn tx(sender: Address, kind: TransactionKind, nonce: u64, fee: u64, n: u64) -> Transaction {
        Transaction {
            sender,
            nonce,
            kind,
            fee,
            signature: Signature([0u8; 64]),
            hash: hash_at(n),
        }
    }

    fn transfer(sender: Address, to: Address, amount: u64, n: u64) -> Transaction {
        tx(sender, TransactionKind::Transfer { to, amount }, n, 7, n)
    }

    fn write(storage: &Storage, height: u64, txs: &[(&Transaction, bool)]) {
        let txn = storage.begin_write().unwrap();
        index_committed_txs(&txn, height, txs).unwrap();
        txn.commit().unwrap();
    }

    fn page(
        storage: &Storage,
        address: Address,
        limit: Option<u64>,
        cursor: Option<String>,
        direction: TxDirection,
    ) -> TxHistoryPage {
        let txn = storage.begin_read().unwrap();
        query_tx_history(
            &txn,
            &TxHistoryQuery {
                address,
                limit,
                cursor,
                direction,
            },
        )
        .unwrap()
    }

    fn all_pages(
        storage: &Storage,
        address: Address,
        limit: u64,
        direction: TxDirection,
    ) -> Vec<TxHistoryEntry> {
        let mut out = Vec::new();
        let mut cursor = None;
        for _ in 0..10_000 {
            let next = page(storage, address, Some(limit), cursor.clone(), direction);
            let n = next.entries.len();
            assert!(n <= limit as usize);
            out.extend(next.entries);
            match next.next_cursor {
                Some(c) => {
                    assert_ne!(cursor.as_deref(), Some(c.as_str()), "cursor must advance");
                    cursor = Some(c);
                }
                None => return out,
            }
        }
        panic!("pagination did not finish");
    }

    #[test]
    fn row_payload_is_161_bytes() {
        assert_eq!(ADDRESS_TX_INDEX_KEY_LEN, 44);
        assert_eq!(ADDRESS_TX_INDEX_VALUE_LEN, 117);
        assert_eq!(ADDRESS_TX_INDEX_KEY_LEN + ADDRESS_TX_INDEX_VALUE_LEN, 161);
    }

    #[test]
    fn indexes_sender_and_recipient_and_reads_them_back() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("idx.redb")).unwrap();
        let alice = addr(0x11);
        let bob = addr(0x22);
        let transfer = transfer(alice, bob, 50, 1);
        let stake = tx(alice, TransactionKind::Stake { amount: 9 }, 2, 3, 2);
        write(&storage, 4, &[(&transfer, true), (&stake, false)]);

        let sent = page(&storage, alice, Some(10), None, TxDirection::Sent);
        assert_eq!(sent.entries.len(), 2);
        assert!(sent.next_cursor.is_none());
        // Newest tx index first inside the same height.
        assert_eq!(sent.entries[0].tx_hash, stake.hash);
        assert_eq!(sent.entries[0].kind, "stake");
        assert!(!sent.entries[0].success);
        assert_eq!(sent.entries[0].amount, 9);
        assert_eq!(sent.entries[0].fee, 3);
        assert_eq!(sent.entries[0].to, None);
        assert_eq!(sent.entries[0].role, ROLE_SENT);
        assert_eq!(sent.entries[0].height, 4);
        assert_eq!(sent.entries[0].tx_index, 1);
        assert_eq!(sent.entries[1].tx_hash, transfer.hash);
        assert_eq!(sent.entries[1].kind, "transfer");
        assert!(sent.entries[1].success);
        assert_eq!(sent.entries[1].amount, 50);
        assert_eq!(sent.entries[1].fee, 7);
        assert_eq!(sent.entries[1].from, alice);
        assert_eq!(sent.entries[1].to, Some(bob));
        assert_eq!(sent.entries[1].role, ROLE_SENT);

        let received = page(&storage, bob, None, None, TxDirection::Received);
        assert_eq!(received.entries.len(), 1);
        assert_eq!(received.entries[0].tx_hash, transfer.hash);
        assert_eq!(received.entries[0].role, ROLE_RECEIVED);
        assert!(page(&storage, bob, None, None, TxDirection::Sent)
            .entries
            .is_empty());

        let carol = addr(0x33);
        assert!(page(&storage, carol, None, None, TxDirection::All)
            .entries
            .is_empty());
    }

    #[test]
    fn sent_received_and_all_filters_count_a_self_transfer_once() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("filter.redb")).unwrap();
        let alice = addr(0x11);
        let bob = addr(0x22);
        let out = transfer(alice, bob, 1, 1);
        let stake = tx(alice, TransactionKind::Stake { amount: 2 }, 2, 1, 2);
        let self_tx = transfer(alice, alice, 3, 3);
        let inbound = transfer(bob, alice, 4, 4);
        write(&storage, 1, &[(&out, true)]);
        write(&storage, 2, &[(&stake, true)]);
        write(&storage, 3, &[(&self_tx, true)]);
        write(&storage, 4, &[(&inbound, true)]);

        let sent = all_pages(&storage, alice, 10, TxDirection::Sent);
        let received = all_pages(&storage, alice, 10, TxDirection::Received);
        let all = all_pages(&storage, alice, 10, TxDirection::All);

        let hashes =
            |rows: &[TxHistoryEntry]| -> Vec<Hash> { rows.iter().map(|r| r.tx_hash).collect() };
        assert_eq!(hashes(&sent), vec![self_tx.hash, stake.hash, out.hash]);
        assert_eq!(hashes(&received), vec![inbound.hash, self_tx.hash]);
        assert_eq!(
            hashes(&all),
            vec![inbound.hash, self_tx.hash, stake.hash, out.hash]
        );
        assert_eq!(all.iter().filter(|r| r.tx_hash == self_tx.hash).count(), 1);
        assert_eq!(
            all.iter().find(|r| r.tx_hash == self_tx.hash).unwrap().role,
            ROLE_BOTH
        );
        assert!(page(&storage, bob, None, None, TxDirection::Received)
            .entries
            .iter()
            .any(|r| r.tx_hash == out.hash));
        assert!(page(&storage, bob, None, None, TxDirection::Sent)
            .entries
            .iter()
            .any(|r| r.tx_hash == inbound.hash));
    }

    #[test]
    fn pagination_cursor_has_no_dupes_or_gaps() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("pages.redb")).unwrap();
        let alice = addr(0x11);
        let bob = addr(0x22);
        let mut expected = Vec::new();
        for height in 1u64..=5 {
            let first = transfer(alice, bob, height, height * 2);
            let second = transfer(alice, bob, height + 100, height * 2 + 1);
            write(&storage, height, &[(&first, true), (&second, true)]);
            // tx_index 0 is `first`, tx_index 1 is `second`. Newest-first
            // returns the higher index first; reverse() then walks heights down.
            expected.push(first.hash);
            expected.push(second.hash);
        }
        expected.reverse();

        let paged = all_pages(&storage, alice, 3, TxDirection::All);
        assert_eq!(paged.len(), expected.len());
        assert_eq!(
            paged.iter().map(|r| r.tx_hash).collect::<Vec<_>>(),
            expected
        );
        let mut seen = std::collections::BTreeSet::new();
        for entry in &paged {
            assert!(seen.insert(entry.tx_hash.0), "duplicate across pages");
        }

        // Mixed roles: stakes occupy even heights and must not create gaps
        // in the received page.
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("mixed.redb")).unwrap();
        let mut received_expected = Vec::new();
        for height in 1u64..=6 {
            if height % 2 == 0 {
                let stake = tx(
                    alice,
                    TransactionKind::Stake { amount: height },
                    height,
                    1,
                    height,
                );
                write(&storage, height, &[(&stake, true)]);
            } else {
                let payment = transfer(bob, alice, height, 100 + height);
                write(&storage, height, &[(&payment, true)]);
                received_expected.push(payment.hash);
            }
        }
        received_expected.reverse();
        let received = all_pages(&storage, alice, 1, TxDirection::Received);
        assert_eq!(
            received.iter().map(|r| r.tx_hash).collect::<Vec<_>>(),
            received_expected
        );
    }

    #[test]
    fn limit_defaults_and_clamps_to_the_hard_max() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("limit.redb")).unwrap();
        let alice = addr(0x41);
        let bob = addr(0x42);
        let mut txs = Vec::new();
        for i in 0..120u64 {
            txs.push(transfer(alice, bob, i + 1, i + 1));
        }
        let refs: Vec<(&Transaction, bool)> = txs.iter().map(|t| (t, true)).collect();
        // One row per height keeps tx_index at 0 and makes newest == highest height.
        for (height, tx) in refs.iter().enumerate() {
            write(&storage, height as u64 + 1, &[*tx]);
        }

        let defaulted = page(&storage, alice, None, None, TxDirection::All);
        assert_eq!(defaulted.entries.len(), DEFAULT_TX_HISTORY_LIMIT as usize);
        assert!(defaulted.next_cursor.is_some());
        assert_eq!(defaulted.entries[0].height, 120);

        let clamped = page(&storage, alice, Some(10_000), None, TxDirection::All);
        assert_eq!(clamped.entries.len(), MAX_TX_HISTORY_LIMIT as usize);
        let rest = page(
            &storage,
            alice,
            Some(10_000),
            clamped.next_cursor,
            TxDirection::All,
        );
        assert_eq!(rest.entries.len(), 20);
        assert!(rest.next_cursor.is_none());
        let mut all = clamped.entries;
        all.extend(rest.entries);
        assert_eq!(all.len(), 120);
        assert_eq!(all.first().unwrap().height, 120);
        assert_eq!(all.last().unwrap().height, 1);
        let mut heights: Vec<u64> = all.iter().map(|e| e.height).collect();
        let mut sorted = heights.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(heights, sorted);
        heights.sort();
        heights.dedup();
        assert_eq!(heights.len(), 120);

        let empty = page(&storage, alice, Some(0), None, TxDirection::All);
        assert!(empty.entries.is_empty());
        assert!(empty.next_cursor.is_none());
    }

    #[test]
    fn invalid_cursors_are_rejected_without_a_scan() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("cursor.redb")).unwrap();
        let alice = addr(0x11);
        let bob = addr(0x22);
        let payment = transfer(alice, bob, 1, 1);
        write(&storage, 1, &[(&payment, true)]);

        let txn = storage.begin_read().unwrap();
        for bad in ["", "zz", "00", &"ab".repeat(15), &"00".repeat(16)] {
            let err = query_tx_history(
                &txn,
                &TxHistoryQuery {
                    address: alice,
                    limit: Some(5),
                    cursor: Some(bad.to_string()),
                    direction: TxDirection::All,
                },
            );
            assert!(
                matches!(err, Err(AddressTxIndexError::InvalidCursor)),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn preexisting_database_without_the_index_opens_and_queries_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("old.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut blocks = txn.open_table(crate::tables::BLOCKS).unwrap();
                blocks.insert([1u8; 32], vec![1u8, 2, 3]).unwrap();
            }
            txn.commit().unwrap();
        }

        let storage = Storage::new(&path).unwrap();
        let empty = page(&storage, addr(0x11), Some(20), None, TxDirection::All);
        assert!(empty.entries.is_empty());
        assert!(empty.next_cursor.is_none());

        let payment = transfer(addr(0x11), addr(0x22), 8, 1);
        write(&storage, 3, &[(&payment, true)]);
        let found = page(&storage, addr(0x11), None, None, TxDirection::Sent);
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].amount, 8);
    }

    #[test]
    fn index_rows_do_not_change_the_state_root() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("root.redb")).unwrap();
        let alice = addr(0x11);
        {
            let txn = storage.begin_write().unwrap();
            storage
                .state()
                .set_account(
                    &txn,
                    &alice,
                    &Account {
                        balance: 5,
                        nonce: 1,
                        ..Account::default()
                    },
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let before = {
            let txn = storage.begin_read().unwrap();
            storage.state().compute_state_root(&txn).unwrap()
        };
        let payment = transfer(alice, addr(0x22), 5, 1);
        write(&storage, 9, &[(&payment, true)]);
        let after = {
            let txn = storage.begin_read().unwrap();
            storage.state().compute_state_root(&txn).unwrap()
        };
        assert_eq!(before, after);
        assert_ne!(before, Hash([0u8; 32]));
        assert_eq!(
            page(&storage, alice, None, None, TxDirection::All)
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn direction_filter_caps_scanned_rows_on_a_busy_address() {
        let dir = tempdir().unwrap();
        let storage = Storage::new(dir.path().join("busy.redb")).unwrap();
        let alice = addr(0x11);
        let bob = addr(0x22);

        // Height 1: one outgoing transfer from Alice.
        let earliest_sent = transfer(alice, bob, 99, 1);
        let mut inbound_txs = Vec::new();
        for n in 2..=251u64 {
            inbound_txs.push(transfer(bob, alice, n, n));
        }
        {
            let txn = storage.begin_write().unwrap();
            index_committed_txs(&txn, 1, &[(&earliest_sent, true)]).unwrap();
            // Heights 2..=251: 250 incoming transfers to Alice (wrong direction for `Sent`).
            for (i, inbound) in inbound_txs.iter().enumerate() {
                index_committed_txs(&txn, i as u64 + 2, &[(inbound, true)]).unwrap();
            }
            txn.commit().unwrap();
        }

        // Querying `Sent` with limit 50 must stop after scanning 50 rows
        // (heights 251..=202) and return a cursor at height 202 instead of
        // scanning all 250 incoming rows in a single call.
        let first = page(&storage, alice, Some(50), None, TxDirection::Sent);
        assert!(first.entries.is_empty());
        assert_eq!(first.next_cursor, Some(encode_cursor(202, 0)));

        // Walking all pages with limit 50 eventually reaches height 1 and
        // returns the single `Sent` row with no duplicates or gaps.
        let all_sent = all_pages(&storage, alice, 50, TxDirection::Sent);
        assert_eq!(all_sent.len(), 1);
        assert_eq!(all_sent[0].tx_hash, earliest_sent.hash);
        assert_eq!(all_sent[0].height, 1);
    }
}

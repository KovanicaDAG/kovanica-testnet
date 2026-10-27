//! Sparse Merkle tree over account balance and nonce.
//!
//! Keys are the 32-byte address, most-significant bit first. A missing
//! account and an account with zero balance and zero nonce are the same
//! leaf, so the root does not depend on empty rows. Contract code is not
//! in the leaf. The tree is order-independent: inserting the same accounts
//! in any order yields the same root.

use crate::hash::Hash;
use crate::Address;
use std::collections::HashMap;
use std::sync::OnceLock;

const DEPTH: usize = 256;

/// One account's inclusion (or absence) path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountProof {
    /// Account address.
    pub address: Address,
    /// Balance in atoms. Zero when [`Self::present`] is false.
    pub balance: u64,
    /// Nonce. Zero when [`Self::present`] is false.
    pub nonce: u64,
    /// Whether the account is stored. False means absence.
    pub present: bool,
    /// Sibling at each level. Index 0 is the sibling under the root.
    pub siblings: [Hash; DEPTH],
}

/// In-memory account tree. Built from the account rows of one commit.
#[derive(Clone, Debug)]
pub struct AccountSmt {
    /// Subtree hash at `(depth, prefix)`. Depth 0 is the root. Only the
    /// first `depth` bits of the prefix are significant.
    nodes: HashMap<(u16, [u8; 32]), Hash>,
    root: Hash,
}

impl AccountSmt {
    /// Tree with no accounts.
    pub fn empty() -> Self {
        Self {
            nodes: HashMap::new(),
            root: empty_at(0),
        }
    }

    /// Root of the tree.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Insert or replace one account. Zero balance and zero nonce removes it.
    pub fn insert(&mut self, address: Address, balance: u64, nonce: u64) {
        let leaf = if balance == 0 && nonce == 0 {
            empty_at(DEPTH)
        } else {
            account_leaf_hash(&address, balance, nonce)
        };
        self.nodes.insert((DEPTH as u16, address.0), leaf);
        let mut hash = leaf;
        for level in (0..DEPTH).rev() {
            let bit = address_bit(&address.0, level);
            let sibling = self.sibling_hash(&address.0, level);
            hash = if bit {
                smt_pair(sibling, hash)
            } else {
                smt_pair(hash, sibling)
            };
            let prefix = mask_prefix(&address.0, level);
            self.nodes.insert((level as u16, prefix), hash);
        }
        self.root = hash;
    }

    /// Inclusion or absence proof for `address`.
    ///
    /// `present`, `balance`, and `nonce` are what the caller claims is in
    /// the tree. [`verify_account_proof`] rejects a claim that does not
    /// match this root.
    pub fn prove(
        &self,
        address: &Address,
        balance: u64,
        nonce: u64,
        present: bool,
    ) -> AccountProof {
        let siblings: [Hash; DEPTH] =
            std::array::from_fn(|level| self.sibling_hash(&address.0, level));
        AccountProof {
            address: *address,
            balance,
            nonce,
            present,
            siblings,
        }
    }

    fn sibling_hash(&self, address: &[u8; 32], level: usize) -> Hash {
        let mut sibling_addr = *address;
        flip_bit(&mut sibling_addr, level);
        let prefix = mask_prefix(&sibling_addr, level + 1);
        self.nodes
            .get(&((level + 1) as u16, prefix))
            .copied()
            .unwrap_or_else(|| empty_at(level + 1))
    }
}

/// Leaf hash for a non-empty account. Not used for absence.
pub fn account_leaf_hash(address: &Address, balance: u64, nonce: u64) -> Hash {
    let mut data = [0u8; 48];
    data[..32].copy_from_slice(&address.0);
    data[32..40].copy_from_slice(&balance.to_le_bytes());
    data[40..48].copy_from_slice(&nonce.to_le_bytes());
    Hash::new_keyed(Hash::DOMAIN_ACCOUNT, data)
}

/// Check `proof` against `root`.
pub fn verify_account_proof(root: &Hash, proof: &AccountProof) -> bool {
    if proof.siblings.len() != DEPTH {
        return false;
    }
    if !proof.present && (proof.balance != 0 || proof.nonce != 0) {
        return false;
    }
    let mut hash = if proof.present {
        account_leaf_hash(&proof.address, proof.balance, proof.nonce)
    } else {
        empty_at(DEPTH)
    };
    for level in (0..DEPTH).rev() {
        let bit = address_bit(&proof.address.0, level);
        let sibling = proof.siblings[level];
        hash = if bit {
            smt_pair(sibling, hash)
        } else {
            smt_pair(hash, sibling)
        };
    }
    hash == *root
}

/// Build a tree from `(address, balance, nonce)` rows.
///
/// Rows with zero balance and zero nonce are skipped. Later rows for the
/// same address replace earlier ones.
pub fn account_root<'a>(rows: impl IntoIterator<Item = (&'a Address, u64, u64)>) -> Hash {
    let mut tree = AccountSmt::empty();
    for (address, balance, nonce) in rows {
        if balance != 0 || nonce != 0 {
            tree.insert(*address, balance, nonce);
        }
    }
    tree.root()
}

fn address_bit(address: &[u8; 32], level: usize) -> bool {
    let byte = level / 8;
    let shift = 7 - (level % 8);
    (address[byte] >> shift) & 1 == 1
}

fn flip_bit(address: &mut [u8; 32], level: usize) {
    let byte = level / 8;
    let shift = 7 - (level % 8);
    address[byte] ^= 1 << shift;
}

/// Keep the first `depth` bits and clear the rest.
fn mask_prefix(address: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if depth == 0 {
        return out;
    }
    let full = depth / 8;
    let rem = depth % 8;
    if full > 0 {
        out[..full].copy_from_slice(&address[..full]);
    }
    if rem > 0 && full < 32 {
        let mask = !((1u8 << (8 - rem)) - 1);
        out[full] = address[full] & mask;
    }
    out
}

fn smt_pair(left: Hash, right: Hash) -> Hash {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left.as_ref());
    data[32..].copy_from_slice(right.as_ref());
    Hash::new_keyed(Hash::DOMAIN_SMT, data)
}

fn empty_at(depth: usize) -> Hash {
    empty_hashes()[depth]
}

fn empty_hashes() -> &'static [Hash; DEPTH + 1] {
    static CACHE: OnceLock<[Hash; DEPTH + 1]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut hashes = [Hash::zero(); DEPTH + 1];
        hashes[DEPTH] = Hash::new_keyed(Hash::DOMAIN_ACCOUNT_EMPTY, []);
        for depth in (0..DEPTH).rev() {
            hashes[depth] = smt_pair(hashes[depth + 1], hashes[depth + 1]);
        }
        hashes
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    #[test]
    fn empty_proof_of_absence_verifies() {
        let tree = AccountSmt::empty();
        let proof = tree.prove(&addr(1), 0, 0, false);
        assert!(verify_account_proof(&tree.root(), &proof));
    }

    #[test]
    fn one_account_round_trips_and_rejects_a_lie() {
        let mut tree = AccountSmt::empty();
        let address = addr(7);
        tree.insert(address, 50, 2);
        let proof = tree.prove(&address, 50, 2, true);
        assert!(verify_account_proof(&tree.root(), &proof));
        let mut lied = proof.clone();
        lied.balance = 49;
        assert!(!verify_account_proof(&tree.root(), &lied));
    }

    #[test]
    fn insert_order_does_not_change_the_root() {
        let a = addr(1);
        let b = addr(2);
        let mut left = AccountSmt::empty();
        left.insert(a, 10, 1);
        left.insert(b, 20, 3);
        let mut right = AccountSmt::empty();
        right.insert(b, 20, 3);
        right.insert(a, 10, 1);
        assert_eq!(left.root(), right.root());
        assert!(verify_account_proof(
            &left.root(),
            &left.prove(&b, 20, 3, true)
        ));
    }

    #[test]
    fn replacing_with_zero_returns_the_empty_root() {
        let empty = AccountSmt::empty().root();
        let mut tree = AccountSmt::empty();
        tree.insert(addr(4), 9, 1);
        assert_ne!(tree.root(), empty);
        tree.insert(addr(4), 0, 0);
        assert_eq!(tree.root(), empty);
    }

    #[test]
    fn absence_of_a_neighbour_still_verifies() {
        let mut tree = AccountSmt::empty();
        tree.insert(addr(1), 5, 1);
        let missing = addr(2);
        let proof = tree.prove(&missing, 0, 0, false);
        assert!(verify_account_proof(&tree.root(), &proof));
        let mut forged = proof;
        forged.present = true;
        forged.balance = 5;
        forged.nonce = 1;
        assert!(!verify_account_proof(&tree.root(), &forged));
    }
}

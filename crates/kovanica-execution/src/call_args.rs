//! Bincode argument bytes for a native `TransactionKind::Call`.
//!
//! `method` must be one of [`crate::ENTRY_POINTS`]. `args` must be the bytes
//! from the matching `encode_*` function. That is the layout
//! [`crate::contracts`] decodes. It is not JSON, and it is not the body of
//! the off-chain `htlc_create` / `vault_create` / `token_create` RPC methods.
//!
//! These helpers do not submit anything. A caller builds a signed `Call`
//! and sends it to a node of their own choosing.

use kovanica_common::{Amount, Timestamp};
use kovanica_vault::VestingSchedule;
use serde::Serialize;

/// Failure while encoding call arguments. The inputs are plain data, so this
/// only fires if bincode itself rejects the value.
#[derive(Debug)]
pub struct EncodeError(bincode::Error);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "contract call argument encode failed: {}", self.0)
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn enc<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serialize(value).map_err(EncodeError)
}

/// `htlc_create(claimer, amount, hash_lock, expiry)`.
pub fn encode_htlc_create(
    claimer: [u8; 32],
    amount: Amount,
    hash_lock: [u8; 32],
    expiry: Timestamp,
) -> Result<Vec<u8>, EncodeError> {
    enc(&(claimer, amount, hash_lock, expiry))
}

/// `htlc_claim(id, preimage)`.
pub fn encode_htlc_claim(id: [u8; 32], preimage: &[u8]) -> Result<Vec<u8>, EncodeError> {
    enc(&(id, preimage.to_vec()))
}

/// `htlc_refund(id)`.
pub fn encode_htlc_refund(id: [u8; 32]) -> Result<Vec<u8>, EncodeError> {
    enc(&id)
}

/// `vault_create(beneficiary, amount, schedule)`.
pub fn encode_vault_create(
    beneficiary: [u8; 32],
    amount: Amount,
    schedule: &VestingSchedule,
) -> Result<Vec<u8>, EncodeError> {
    enc(&(beneficiary, amount, schedule))
}

/// `vault_claim(id)`.
pub fn encode_vault_claim(id: [u8; 32]) -> Result<Vec<u8>, EncodeError> {
    enc(&id)
}

/// `vault_cancel(id)`.
pub fn encode_vault_cancel(id: [u8; 32]) -> Result<Vec<u8>, EncodeError> {
    enc(&id)
}

/// `multisig_create(owners, threshold)`.
pub fn encode_multisig_create(owners: &[[u8; 32]], threshold: u32) -> Result<Vec<u8>, EncodeError> {
    enc(&(owners.to_vec(), threshold))
}

/// `multisig_propose(id, to, amount, data)`.
pub fn encode_multisig_propose(
    id: [u8; 32],
    to: [u8; 32],
    amount: Amount,
    data: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    enc(&(id, to, amount, data.to_vec()))
}

/// `multisig_confirm(id, tx_id)`.
pub fn encode_multisig_confirm(id: [u8; 32], tx_id: u64) -> Result<Vec<u8>, EncodeError> {
    enc(&(id, tx_id))
}

/// `multisig_execute(id, tx_id)`.
pub fn encode_multisig_execute(id: [u8; 32], tx_id: u64) -> Result<Vec<u8>, EncodeError> {
    enc(&(id, tx_id))
}

/// `token_create(name, symbol, decimals, initial_supply)`.
pub fn encode_token_create(
    name: &str,
    symbol: &str,
    decimals: u8,
    initial_supply: Amount,
) -> Result<Vec<u8>, EncodeError> {
    enc(&(
        name.to_string(),
        symbol.to_string(),
        decimals,
        initial_supply,
    ))
}

/// `token_transfer(to, amount)`.
pub fn encode_token_transfer(to: [u8; 32], amount: Amount) -> Result<Vec<u8>, EncodeError> {
    enc(&(to, amount))
}

/// `token_approve(spender, amount)`.
pub fn encode_token_approve(spender: [u8; 32], amount: Amount) -> Result<Vec<u8>, EncodeError> {
    enc(&(spender, amount))
}

/// `token_transfer_from(from, to, amount)`.
pub fn encode_token_transfer_from(
    from: [u8; 32],
    to: [u8; 32],
    amount: Amount,
) -> Result<Vec<u8>, EncodeError> {
    enc(&(from, to, amount))
}

/// `token_mint(to, amount)`.
pub fn encode_token_mint(to: [u8; 32], amount: Amount) -> Result<Vec<u8>, EncodeError> {
    enc(&(to, amount))
}

/// `token_burn(amount)`.
pub fn encode_token_burn(amount: Amount) -> Result<Vec<u8>, EncodeError> {
    enc(&amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{execute_contract_call, execute_contract_call_with_value};
    use crate::ExecutionError;
    use kovanica_common::ContractError;
    use kovanica_storage::Storage;
    use kovanica_types::Address;
    use kovanica_vault::VestingSchedule;

    fn addr(tag: u8) -> Address {
        Address([tag; 32])
    }

    fn fund(storage: &Storage, address: &Address, balance: u64) {
        let txn = storage.begin_write().expect("write");
        let mut account = storage
            .state()
            .get_account_or_default_write(&txn, address)
            .expect("account");
        account.balance = balance;
        storage
            .state()
            .set_account(&txn, address, &account)
            .expect("set");
        txn.commit().expect("commit");
    }

    fn deploy(storage: &Storage, address: &Address) {
        let txn = storage.begin_write().expect("write");
        let mut account = storage
            .state()
            .get_account_or_default_write(&txn, address)
            .expect("account");
        account.code = b"\0asm-test-contract".to_vec();
        account.code_hash = kovanica_common::hash(&account.code);
        storage
            .state()
            .set_account(&txn, address, &account)
            .expect("set");
        txn.commit().expect("commit");
    }

    #[test]
    fn encoders_round_trip_the_dispatcher_layout() {
        let id = [7u8; 32];
        let other = [9u8; 32];
        let schedule = VestingSchedule::Absolute { unlock_at: 50 };

        let htlc_create = encode_htlc_create(other, 10, id, 99).unwrap();
        let decoded: ([u8; 32], Amount, [u8; 32], Timestamp) =
            bincode::deserialize(&htlc_create).unwrap();
        assert_eq!(decoded, (other, 10, id, 99));

        let claim = encode_htlc_claim(id, b"preimage").unwrap();
        let decoded: ([u8; 32], Vec<u8>) = bincode::deserialize(&claim).unwrap();
        assert_eq!(decoded, (id, b"preimage".to_vec()));

        assert_eq!(
            bincode::deserialize::<[u8; 32]>(&encode_htlc_refund(id).unwrap()).unwrap(),
            id
        );

        let vault = encode_vault_create(other, 5, &schedule).unwrap();
        let decoded: ([u8; 32], Amount, VestingSchedule) = bincode::deserialize(&vault).unwrap();
        assert_eq!(decoded.0, other);
        assert_eq!(decoded.1, 5);
        assert_eq!(decoded.2, schedule);

        let owners = vec![[1u8; 32], [2u8; 32]];
        let created = encode_multisig_create(&owners, 2).unwrap();
        let decoded: (Vec<[u8; 32]>, u32) = bincode::deserialize(&created).unwrap();
        assert_eq!(decoded, (owners, 2));

        let proposed = encode_multisig_propose(id, other, 3, b"data").unwrap();
        let decoded: ([u8; 32], [u8; 32], Amount, Vec<u8>) =
            bincode::deserialize(&proposed).unwrap();
        assert_eq!(decoded, (id, other, 3, b"data".to_vec()));

        assert_eq!(
            bincode::deserialize::<([u8; 32], u64)>(&encode_multisig_confirm(id, 4).unwrap())
                .unwrap(),
            (id, 4)
        );
        assert_eq!(
            bincode::deserialize::<([u8; 32], u64)>(&encode_multisig_execute(id, 4).unwrap())
                .unwrap(),
            (id, 4)
        );

        let token = encode_token_create("N", "S", 9, 1_000).unwrap();
        let decoded: (String, String, u8, Amount) = bincode::deserialize(&token).unwrap();
        assert_eq!(decoded, ("N".into(), "S".into(), 9, 1_000));

        assert_eq!(
            bincode::deserialize::<([u8; 32], Amount)>(&encode_token_transfer(other, 4).unwrap())
                .unwrap(),
            (other, 4)
        );
        assert_eq!(
            bincode::deserialize::<([u8; 32], Amount)>(&encode_token_approve(other, 4).unwrap())
                .unwrap(),
            (other, 4)
        );
        assert_eq!(
            bincode::deserialize::<([u8; 32], [u8; 32], Amount)>(
                &encode_token_transfer_from(id, other, 4).unwrap()
            )
            .unwrap(),
            (id, other, 4)
        );
        assert_eq!(
            bincode::deserialize::<([u8; 32], Amount)>(&encode_token_mint(other, 4).unwrap())
                .unwrap(),
            (other, 4)
        );
        assert_eq!(
            bincode::deserialize::<Amount>(&encode_token_burn(4).unwrap()).unwrap(),
            4
        );
        assert_eq!(
            bincode::deserialize::<[u8; 32]>(&encode_vault_claim(id).unwrap()).unwrap(),
            id
        );
        assert_eq!(
            bincode::deserialize::<[u8; 32]>(&encode_vault_cancel(id).unwrap()).unwrap(),
            id
        );
    }

    #[test]
    fn encoded_token_calls_execute_on_a_local_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
        let contract = addr(30);
        let caller = addr(1);
        let recipient = [4u8; 32];
        deploy(&storage, &contract);

        let create = encode_token_create("Test", "TST", 9, 1_000).unwrap();
        execute_contract_call("token_create", contract, caller, 1, 1, &create, &storage)
            .expect("token_create");

        let transfer = encode_token_transfer(recipient, 400).unwrap();
        execute_contract_call(
            "token_transfer",
            contract,
            caller,
            2,
            2,
            &transfer,
            &storage,
        )
        .expect("token_transfer");

        let over = encode_token_transfer(recipient, 700).unwrap();
        let err = execute_contract_call("token_transfer", contract, caller, 3, 3, &over, &storage)
            .expect_err("balance is 600");
        assert!(
            matches!(
                err,
                ExecutionError::Contract(ContractError::InsufficientBalance)
            ),
            "{err:?}"
        );

        let spender = addr(2);
        let third = [5u8; 32];
        // token_approve
        let approve = encode_token_approve(spender.0, 200).unwrap();
        execute_contract_call("token_approve", contract, caller, 4, 4, &approve, &storage)
            .expect("token_approve");

        // token_transfer_from
        let transfer_from = encode_token_transfer_from(caller.0, third, 150).unwrap();
        execute_contract_call(
            "token_transfer_from",
            contract,
            spender,
            5,
            5,
            &transfer_from,
            &storage,
        )
        .expect("token_transfer_from");

        // token_mint
        let mint = encode_token_mint(recipient, 300).unwrap();
        execute_contract_call("token_mint", contract, caller, 6, 6, &mint, &storage)
            .expect("token_mint");

        // token_burn
        let burn = encode_token_burn(100).unwrap();
        execute_contract_call("token_burn", contract, caller, 7, 7, &burn, &storage)
            .expect("token_burn");
    }

    #[test]
    fn encoded_htlc_calls_execute_on_a_local_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
        let contract = addr(31);
        let sender = addr(1);
        let claimer = addr(2);
        deploy(&storage, &contract);
        fund(&storage, &sender, 2_000);

        let preimage = b"htlc_call_args_secret";
        let hash_lock = kovanica_common::hash(preimage);

        // 1. Create with encode_htlc_create
        let create = encode_htlc_create(claimer.0, 500, hash_lock, 1_000).unwrap();
        let out = execute_contract_call_with_value(
            "htlc_create",
            contract,
            sender,
            1,
            100,
            &create,
            500,
            &storage,
        )
        .expect("htlc_create");
        let id: [u8; 32] = bincode::deserialize(&out).expect("id");

        // 2. Claim with encode_htlc_claim
        let claim = encode_htlc_claim(id, preimage).unwrap();
        execute_contract_call("htlc_claim", contract, claimer, 2, 200, &claim, &storage)
            .expect("htlc_claim");

        // 3. Create expiring swap and refund with encode_htlc_refund
        let create2 = encode_htlc_create(claimer.0, 300, hash_lock, 500).unwrap();
        let out2 = execute_contract_call_with_value(
            "htlc_create",
            contract,
            sender,
            3,
            300,
            &create2,
            300,
            &storage,
        )
        .expect("htlc_create2");
        let id2: [u8; 32] = bincode::deserialize(&out2).expect("id2");

        let refund = encode_htlc_refund(id2).unwrap();
        execute_contract_call(
            "htlc_refund",
            contract,
            sender,
            4,
            600, // > expiry (500)
            &refund,
            &storage,
        )
        .expect("htlc_refund");
    }

    #[test]
    fn encoded_vault_calls_execute_on_a_local_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
        let contract = addr(32);
        let creator = addr(1);
        let beneficiary = addr(2);
        deploy(&storage, &contract);
        fund(&storage, &creator, 3_000);

        let schedule = VestingSchedule::Absolute { unlock_at: 500 };

        // 1. Create with encode_vault_create
        let create = encode_vault_create(beneficiary.0, 1_000, &schedule).unwrap();
        let out = execute_contract_call_with_value(
            "vault_create",
            contract,
            creator,
            1,
            100,
            &create,
            1_000,
            &storage,
        )
        .expect("vault_create");
        let id: kovanica_vault::VaultId = bincode::deserialize(&out).expect("id");

        // 2. Claim after unlock with encode_vault_claim
        let claim = encode_vault_claim(id).unwrap();
        let claim_out = execute_contract_call(
            "vault_claim",
            contract,
            beneficiary,
            2,
            600, // > unlock_at (500)
            &claim,
            &storage,
        )
        .expect("vault_claim");
        let claimed_amount: Amount = bincode::deserialize(&claim_out).expect("amount");
        assert_eq!(claimed_amount, 1_000);

        // 3. Create vault 2 and cancel with encode_vault_cancel
        let create2 = encode_vault_create(beneficiary.0, 500, &schedule).unwrap();
        let out2 = execute_contract_call_with_value(
            "vault_create",
            contract,
            creator,
            3,
            200,
            &create2,
            500,
            &storage,
        )
        .expect("vault_create2");
        let id2: kovanica_vault::VaultId = bincode::deserialize(&out2).expect("id2");

        let cancel = encode_vault_cancel(id2).unwrap();
        execute_contract_call("vault_cancel", contract, creator, 4, 300, &cancel, &storage)
            .expect("vault_cancel");
    }

    #[test]
    fn encoded_multisig_calls_execute_on_a_local_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
        let contract = addr(33);
        let owner1 = addr(1);
        let owner2 = addr(2);
        let recipient = addr(3);
        deploy(&storage, &contract);
        fund(&storage, &contract, 20_000);

        // 1. Create with encode_multisig_create
        let create = encode_multisig_create(&[owner1.0, owner2.0], 2).unwrap();
        let out = execute_contract_call(
            "multisig_create",
            contract,
            owner1,
            1,
            100,
            &create,
            &storage,
        )
        .expect("multisig_create");
        let id: kovanica_multisig::MultisigId = bincode::deserialize(&out).expect("id");

        // 2. Propose with encode_multisig_propose
        let propose = encode_multisig_propose(id, recipient.0, 5_000, &[]).unwrap();
        let p_out = execute_contract_call(
            "multisig_propose",
            contract,
            owner1,
            2,
            110,
            &propose,
            &storage,
        )
        .expect("multisig_propose");
        let tx_id: kovanica_multisig::TxId = bincode::deserialize(&p_out).expect("tx_id");

        // 3. Confirm with encode_multisig_confirm
        let confirm = encode_multisig_confirm(id, tx_id).unwrap();
        execute_contract_call(
            "multisig_confirm",
            contract,
            owner2,
            3,
            120,
            &confirm,
            &storage,
        )
        .expect("multisig_confirm");

        // 4. Execute with encode_multisig_execute
        let execute = encode_multisig_execute(id, tx_id).unwrap();
        execute_contract_call(
            "multisig_execute",
            contract,
            owner1,
            4,
            130,
            &execute,
            &storage,
        )
        .expect("multisig_execute");
    }
}

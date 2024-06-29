use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use ethereum_types::{H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use mpt_trie::nibbles::Nibbles;

use crate::{hash, TxnMeta, TxnTrace};
use crate::{ContractCodeUsage, TxnInfo};

/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

#[derive(Debug)]
pub(crate) struct ProcessedTxnInfo {
    pub nodes_used_by_txn: NodesUsedByTxn,
    pub contract_code_accessed: HashMap<H256, Vec<u8>>,
    pub meta: TxnMetaState,
}

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub state_accesses: Vec<H256>,
    pub state_writes: Vec<(H256, StateTrieWrites)>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub storage_accesses: Vec<(H256, Vec<Nibbles>)>,
    #[allow(clippy::type_complexity)]
    pub storage_writes: Vec<(H256, Vec<(Nibbles, Vec<u8>)>)>,
    pub state_accounts_with_no_accesses_but_storage_tries: HashMap<H256, H256>,
    pub self_destructed_accounts: Vec<H256>,
}

#[derive(Debug)]
pub(crate) struct StateTrieWrites {
    pub balance: Option<U256>,
    pub nonce: Option<U256>,
    pub storage_trie_change: bool,
    pub code_hash: Option<H256>,
}

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    pub txn_bytes: Option<Vec<u8>>,
    pub receipt_node_bytes: Vec<u8>,
    pub gas_used: u64,
}
pub fn process(
    TxnInfo { traces, meta }: TxnInfo,
    all_accounts_in_pre_image: &[(H256, AccountRlp)],
    extra_state_accesses: &[H256],
    // Code hash mappings that we have constructed from parsing the block
    // trace. If there are any txns that create contracts, then they will also
    // get added here as we process the deltas.
    hash2code: &mut HashMap<H256, Vec<u8>>,
) -> ProcessedTxnInfo {
    let mut nodes_used_by_txn = NodesUsedByTxn::default();
    let mut contract_code_accessed = HashMap::from([(hash([]), Vec::new())]);

    for (
        addr,
        TxnTrace {
            balance,
            nonce,
            storage_read,
            storage_written,
            code_usage,
            self_destructed,
        },
    ) in traces
    {
        let hashed_addr = hash(addr.as_bytes());

        let storage_writes = storage_written.unwrap_or_default();
        let storage_read_keys = storage_read.into_iter().flatten();
        let storage_write_keys = storage_writes.keys();
        let storage_access_keys = storage_read_keys.chain(storage_write_keys.copied());

        nodes_used_by_txn.storage_accesses.push((
            hashed_addr,
            storage_access_keys
                .map(|k| Nibbles::from_h256_be(hash(k)))
                .collect(),
        ));

        let storage_trie_change = !storage_writes.is_empty();
        let code_change = code_usage.is_some();
        let state_write_occurred =
            balance.is_some() || nonce.is_some() || storage_trie_change || code_change;

        if state_write_occurred {
            let state_trie_writes = StateTrieWrites {
                balance,
                nonce,
                storage_trie_change,
                code_hash: code_usage.as_ref().map(|usage| match usage {
                    ContractCodeUsage::Read(hash) => *hash,
                    ContractCodeUsage::Write(bytes) => hash(bytes),
                }),
            };

            nodes_used_by_txn
                .state_writes
                .push((hashed_addr, state_trie_writes))
        }

        let storage_writes_vec = storage_writes
            .into_iter()
            .map(|(k, v)| (Nibbles::from_h256_be(k), rlp::encode(&v).to_vec()))
            .collect();

        nodes_used_by_txn
            .storage_writes
            .push((hashed_addr, storage_writes_vec));

        nodes_used_by_txn.state_accesses.push(hashed_addr);

        if let Some(c_usage) = code_usage {
            match c_usage {
                ContractCodeUsage::Read(c_hash) => {
                    contract_code_accessed
                        .entry(c_hash)
                        .or_insert_with(|| hash2code.get(&c_hash).cloned().unwrap());
                }
                ContractCodeUsage::Write(c_bytes) => {
                    let c_hash = hash(&c_bytes);

                    contract_code_accessed.insert(c_hash, c_bytes.clone());
                    hash2code.insert(c_hash, c_bytes);
                }
            }
        }

        if self_destructed.map_or(false, |self_destructed| self_destructed) {
            nodes_used_by_txn.self_destructed_accounts.push(hashed_addr);
        }
    }

    for &hashed_addr in extra_state_accesses {
        nodes_used_by_txn.state_accesses.push(hashed_addr);
    }

    let accounts_with_storage_accesses = HashSet::<_>::from_iter(
        nodes_used_by_txn
            .storage_accesses
            .iter()
            .filter(|(_, slots)| !slots.is_empty())
            .map(|(addr, _)| *addr),
    );

    let all_accounts_with_non_empty_storage = all_accounts_in_pre_image
        .iter()
        .filter(|(_, data)| data.storage_root != EMPTY_TRIE_HASH);

    let accounts_with_storage_but_no_storage_accesses = all_accounts_with_non_empty_storage
        .filter(|&(addr, _data)| !accounts_with_storage_accesses.contains(addr))
        .map(|(addr, data)| (*addr, data.storage_root));

    nodes_used_by_txn
        .state_accounts_with_no_accesses_but_storage_tries
        .extend(accounts_with_storage_but_no_storage_accesses);

    let TxnMeta {
        byte_code,
        new_receipt_trie_node_byte,
        gas_used,
    } = meta;

    ProcessedTxnInfo {
        nodes_used_by_txn,
        contract_code_accessed,
        meta: TxnMetaState {
            txn_bytes: match byte_code.is_empty() {
                false => Some(byte_code),
                true => None,
            },
            receipt_node_bytes: {
                let raw_bytes = new_receipt_trie_node_byte;
                match rlp::decode::<LegacyReceiptRlp>(&raw_bytes) {
                    Ok(_) => raw_bytes,
                    Err(_) => {
                        // Must be non-legacy then.
                        rlp::decode::<Vec<u8>>(&raw_bytes).unwrap()
                    }
                }
            },
            gas_used,
        },
    }
}

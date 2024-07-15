use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::ops::Div;

use ethereum_types::{Address, Bloom, H256, U256, U64};
use ethers::abi::AbiEncode;
use ethers::prelude::{AccountState, DiffMode, Http, Provider};
use ethers::types::{Block, PreStateMode, Transaction, TransactionReceipt};
use ethers::utils::rlp;
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::TrieRoots;
use evm_arithmetization::GenerationInputs;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie};

use crate::mpt::{apply_diffs, insert_mpt, trim, Mpt};
use crate::rpc_utils::{
    get_block_by_number, get_block_hashes, get_block_metadata, get_diffmode_trace,
    get_prestatemode_trace, get_proof, get_receipt, get_tx,
};
use crate::utils::{
    has_storage_deletion, keccak, OPTIMISM_BASE_FEE_ADDR, OPTIMISM_L1_BLOCK_ADDR,
    OPTIMISM_L1_FEE_ADDR,
};

pub fn merge_accounts(lhs: &AccountState, rhs: &AccountState) -> AccountState {
    let mut acc = lhs.clone();
    let mut new_store = acc.storage.clone().unwrap_or_default();
    if let Some(s) = rhs.storage.clone() {
        for (k, v) in s {
            new_store.insert(k, v);
        }
    }
    acc.storage = if new_store.is_empty() {
        None
    } else {
        Some(new_store)
    };

    acc
}

pub async fn construct_state_mpt_and_storage_mpts(
    state_kv: &BTreeMap<Address, AccountState>,
    state_mpt: &mut Mpt,
    storage_mpts: &mut HashMap<H256, Mpt>,
    block: &Block<H256>,
    provider: &Provider<Http>,
) -> anyhow::Result<()> {
    let block_number = block.number.unwrap();
    // construct state_mpt, storage_mpts and contract_codes
    for (address, account) in state_kv {
        let AccountState { storage, .. } = account;
        let empty_storage = storage.is_none();
        let mut storage_keys = vec![];
        if let Some(stor) = storage {
            storage_keys.extend(stor.keys().copied());
        }
        let (proof, storage_proof, account_info, ..) =
            get_proof(*address, storage_keys.clone(), block_number - 1, provider).await?;
        insert_mpt(state_mpt, proof);

        let (next_proof, next_storage_proof, ..) =
            get_proof(*address, storage_keys, block_number, provider).await?;
        insert_mpt(state_mpt, next_proof);

        let key = keccak(address.0);
        if !empty_storage {
            let mut storage_mpt = Mpt::new();
            storage_mpt.root = account_info.storage_root;
            for sp in storage_proof {
                insert_mpt(&mut storage_mpt, sp.proof);
            }
            for sp in next_storage_proof {
                insert_mpt(&mut storage_mpt, sp.proof);
            }
            storage_mpts.insert(key.into(), storage_mpt);
        }
    }

    if let Some(v) = &block.withdrawals {
        for w in v {
            let (proof, ..) = get_proof(w.address, vec![], block_number - 1, provider).await?;
            insert_mpt(state_mpt, proof);
        }
    }

    Ok(())
}

pub fn encode_recepits(receipt: &TransactionReceipt) -> Vec<u8> {
    let mut bs = rlp::RlpStream::new();
    bs.begin_list(4);
    bs.append(&receipt.status.unwrap());
    bs.append(&receipt.cumulative_gas_used);
    bs.append(&receipt.logs_bloom);
    bs.append_list(&receipt.logs);
    let bs_r = bs.out().freeze();
    let mut ref_bytes: Vec<u8> = Vec::new();
    ref_bytes.extend(bs_r);
    if !receipt.transaction_type.unwrap().is_zero() {
        // logic of remote block
        let pre_fix = receipt.transaction_type.unwrap().0[0] as u8;
        ref_bytes.insert(0, pre_fix);
    }

    ref_bytes
}

pub async fn gather_witness(
    block_number: u64,
    provider: &Provider<Http>,
) -> anyhow::Result<Vec<GenerationInputs>> {
    let chain_id: U256 = 0x15eb.into();
    let block = get_block_by_number(block_number.into(), provider).await?;
    let tx_count = block.transactions.len();

    let prev_block = get_block_by_number((block_number - 1).into(), provider).await?;

    let (block_metadata, _final_hash) =
        get_block_metadata(block_number.into(), chain_id, provider).await?;

    // Block hashes
    let block_hashes = get_block_hashes(block_number.into(), provider).await?;

    let mut txs: Vec<Transaction> = Vec::new();
    let mut txn_rlps = vec![];
    let mut receipts: Vec<TransactionReceipt> = Vec::new();
    let mut prestate_traces: Vec<PreStateMode> = Vec::new();
    let mut diffstate_traces: Vec<DiffMode> = Vec::new();

    for i in 0..tx_count {
        let tx_hash = block.transactions[i];
        let tx = get_tx(tx_hash, provider).await?;
        txs.push(tx.clone());
        txn_rlps.push(tx.rlp().to_vec());

        let receipt = get_receipt(tx_hash, provider).await?;
        receipts.push(receipt);

        let prestate_trace = get_prestatemode_trace(tx_hash, provider).await?;
        prestate_traces.push(prestate_trace);

        let diffstate_trace = get_diffmode_trace(tx_hash, provider).await?;
        diffstate_traces.push(diffstate_trace);
    }
    // Withdrawals
    let wds = if let Some(v) = &block.withdrawals {
        v.iter()
            .map(|w| (w.address, w.amount * 1_000_000_000)) // Alchemy returns Gweis for some reason
            .collect()
    } else {
        vec![]
    };

    let mut state_mpt = Mpt::new();
    state_mpt.root = prev_block.state_root;
    let mut contract_codes = crate::utils::contract_codes();
    let mut storage_mpts = HashMap::new();
    let mut alladdrs = vec![];
    let mut state_kv = BTreeMap::<Address, AccountState>::new();

    // construct state_kv from prestate_traces
    for prestate in prestate_traces.iter() {
        for (address, account) in prestate.0.clone() {
            alladdrs.push(address);
            // If this account already exists, merge the storage.
            if let Some(acc) = state_kv.get(&address) {
                let acc_merged = merge_accounts(&account, acc);
                state_kv.insert(address, acc_merged);
            } else {
                state_kv.insert(address, account);
            }
        }
    }

    construct_state_mpt_and_storage_mpts(
        &state_kv,
        &mut state_mpt,
        &mut storage_mpts,
        &block,
        provider,
    )
    .await?;

    // construct contract_codes
    for account in state_kv.values() {
        if let Some(code) = account.code.clone() {
            let code = hex::decode(&code[2..])?;
            let codehash = keccak(&code);
            contract_codes.insert(codehash.into(), code);
        }
    }

    // process tx in block one-by-one
    let mut proof_gen_ir = Vec::new();
    let mut state_mpt = state_mpt.to_partial_trie();
    let mut txns_mpt = HashedPartialTrie::from(Node::Empty);
    let mut receipts_mpt = HashedPartialTrie::from(Node::Empty);
    let mut gas_used = U256::zero();
    let mut bloom: Bloom = Bloom::zero();
    let mut storage_mpts: HashMap<_, _> = storage_mpts
        .iter()
        .map(|(a, m)| (*a, m.to_partial_trie()))
        .collect();

    let mut op_account_15: Option<AccountState> = None;
    let mut op_account_19: Option<AccountState> = None;
    let mut op_account_1a: Option<AccountState> = None;
    let op_base_fee_per_gas = block.base_fee_per_gas.unwrap();
    for i in 0..tx_count {
        let tx = txs[i].clone();
        tracing::info!("Processing {}-th transaction: {:?}", i, tx.hash);
        let mut prestate_trace = prestate_traces[i].clone();
        let signed_txn = txn_rlps[i].clone();
        let receipt = receipts[i].clone();
        let last_tx = i == tx_count - 1;
        let mut diffstate_trace = diffstate_traces[i].clone();
        let has_storage_deletion = has_storage_deletion(&diffstate_trace);
        if i == 0 {
            op_account_15 = Some(
                prestate_trace
                    .0
                    .get(&OPTIMISM_L1_BLOCK_ADDR)
                    .unwrap()
                    .clone(),
            );
            op_account_19 = Some(
                prestate_trace
                    .0
                    .get(&OPTIMISM_BASE_FEE_ADDR)
                    .unwrap()
                    .clone(),
            );
            op_account_1a = Some(prestate_trace.0.get(&OPTIMISM_L1_FEE_ADDR).unwrap().clone());
        }
        if i > 0 {
            let mut op_account_19_new = op_account_19.clone().unwrap();
            let mut op_account_1a_new = op_account_1a.clone().unwrap();
            if tx.transaction_type.unwrap() != U64::from(126) {
                // calculate op base fee
                let gas_used_in_receipt = receipt.gas_used.unwrap();
                op_account_19_new.balance = Some(
                    op_account_19_new.balance.unwrap() + gas_used_in_receipt * op_base_fee_per_gas,
                );
                // calculate op L1 fee
                let sto = op_account_15.clone().unwrap().storage.unwrap();
                let param_1 = U256::from(sto.get(&H256::from_low_u64_be(1)).unwrap().0);
                let param_5 = U256::from(sto.get(&H256::from_low_u64_be(5)).unwrap().0);
                let param_6 = U256::from(sto.get(&H256::from_low_u64_be(6)).unwrap().0);
                let cnt_zero = signed_txn.iter().filter(|&n| *n == 0).count();
                let cnt_non_zero = signed_txn.len() - cnt_zero;
                let op_rollup_data_gas = cnt_zero * 4 + cnt_non_zero * 16; // Regolith only
                let op_l1_fee = (U256::from(op_rollup_data_gas) + param_5) * param_1 * param_6;
                let op_l1_fee = op_l1_fee.div(U256::from(1_000_000));
                tracing::debug!(
                    "op_acc_1a.balance_pre: {}",
                    op_account_1a_new.balance.unwrap().encode_hex()
                );
                op_account_1a_new.balance = Some(op_account_1a_new.balance.unwrap() + op_l1_fee);
                tracing::debug!("op_param_1: {}", param_1.encode_hex());
                tracing::debug!("op_param_5: {}", param_5.encode_hex());
                tracing::debug!("op_param_6: {}", param_6.encode_hex());
                tracing::debug!("cnt_zero: {}", cnt_zero);
                tracing::debug!("cnt_non_zero: {}", cnt_non_zero);
                tracing::debug!(
                    "op_acc_19.balance: {}",
                    op_account_19_new.balance.unwrap().encode_hex()
                );
                tracing::debug!("op_l1_fee: {}", op_l1_fee.encode_hex());
                tracing::debug!(
                    "op_acc_1a.balance_post: {}",
                    op_account_1a_new.balance.unwrap().encode_hex()
                );

                let account_state = AccountState {
                    balance: op_account_19.clone().unwrap().balance,
                    code: None,
                    nonce: None,
                    storage: None,
                };
                diffstate_trace
                    .pre
                    .insert(OPTIMISM_BASE_FEE_ADDR, account_state);

                let account_state = AccountState {
                    balance: op_account_19_new.balance,
                    code: None,
                    nonce: None,
                    storage: None,
                };
                diffstate_trace
                    .post
                    .insert(OPTIMISM_BASE_FEE_ADDR, account_state);

                let account_state = AccountState {
                    balance: op_account_1a.clone().unwrap().balance,
                    code: None,
                    nonce: None,
                    storage: None,
                };
                diffstate_trace
                    .pre
                    .insert(OPTIMISM_L1_FEE_ADDR, account_state);
                let account_state = AccountState {
                    balance: op_account_1a_new.balance,
                    code: None,
                    nonce: None,
                    storage: None,
                };
                diffstate_trace
                    .post
                    .insert(OPTIMISM_L1_FEE_ADDR, account_state);

                let mut file = File::create(format!(
                    "dump/trace_diffmode_{}_2.json",
                    tx.hash.encode_hex()
                ))?;
                file.write_all(&serde_json::to_vec(&diffstate_trace)?)?;
            }

            let account_state = op_account_19.unwrap().clone();
            prestate_trace
                .0
                .insert(OPTIMISM_BASE_FEE_ADDR, account_state);

            let account_state = op_account_1a.unwrap().clone();
            prestate_trace.0.insert(OPTIMISM_L1_FEE_ADDR, account_state);
            let mut file = File::create(format!(
                "dump/trace_prestatemode_{}_2.json",
                tx.hash.encode_hex()
            ))?;
            file.write_all(&serde_json::to_vec(&prestate_trace)?)?;

            op_account_19 = Some(op_account_19_new);
            op_account_1a = Some(op_account_1a_new);
        }

        if tx_count == 1 {
            // padding nil tx to the front
            let trie_roots_after = TrieRoots {
                state_root: state_mpt.hash(),
                transactions_root: txns_mpt.hash(),
                receipts_root: receipts_mpt.hash(),
            };

            let dummy_txn = GenerationInputs {
                txn_number_before: U256::zero(),
                gas_used_before: U256::zero(),
                gas_used_after: U256::zero(),
                gas_used_l1: U256::zero(),
                signed_txn: None,
                withdrawals: vec![],
                tries: TrieInputs {
                    state_trie: state_mpt.clone(), // TODO trim
                    transactions_trie: txns_mpt.clone(),
                    receipts_trie: receipts_mpt.clone(),
                    storage_tries: storage_mpts.clone().into_iter().collect(),
                },
                trie_roots_after,
                checkpoint_state_trie_root: prev_block.state_root,
                contract_code: HashMap::default(),
                block_metadata: block_metadata.clone(),
                block_hashes: block_hashes.clone(),
            };
            proof_gen_ir.insert(0, dummy_txn);
        }
        tracing::debug!(
            "state_root before apply_diff: {}",
            state_mpt.hash().encode_hex()
        );
        let (next_state_mpt, next_storage_mpts) = apply_diffs(
            state_mpt.clone(),
            storage_mpts.clone(),
            &mut contract_codes,
            diffstate_trace,
        );
        tracing::debug!(
            "state_root after apply_diff: {}",
            next_state_mpt.hash().encode_hex()
        );
        // For the last tx, we want to include the withdrawal addresses in the state
        // trie
        if last_tx {
            for (addr, _) in &wds {
                if !prestate_trace.0.contains_key(addr) {
                    prestate_trace.0.insert(*addr, AccountState::default());
                }
            }
        }
        let (trimmed_state_mpt, trimmed_storage_mpts) = trim(
            state_mpt.clone(),
            storage_mpts.clone(),
            prestate_trace.0.clone(),
            has_storage_deletion,
        );
        assert_eq!(trimmed_state_mpt.hash(), state_mpt.hash());
        let mut new_bloom = bloom;
        new_bloom.accrue_bloom(&receipt.logs_bloom);
        let mut new_txns_mpt = txns_mpt.clone();
        new_txns_mpt.insert(
            Nibbles::from_bytes_be(&rlp::encode(&receipt.transaction_index)).unwrap(),
            signed_txn.clone(),
        )?;
        let mut new_receipts_mpt = receipts_mpt.clone();

        new_receipts_mpt.insert(
            Nibbles::from_bytes_be(&rlp::encode(&receipt.transaction_index)).unwrap(),
            encode_recepits(&receipt),
        )?;

        // Use withdrawals for the last tx in the block.
        let withdrawals = if last_tx { wds.clone() } else { vec![] };
        // For the last tx, we check that the final trie roots match those in the block
        // header.
        let trie_roots_after = if last_tx {
            tracing::debug!(
                "{} new receipt_root hash from local computation {}",
                i,
                new_receipts_mpt.hash()
            );
            tracing::debug!(
                "{} new receipt_root hash from block value {}",
                i,
                block.receipts_root
            );
            tracing::debug!(
                "{} new state_root hash from local computation {}",
                i,
                next_state_mpt.hash()
            );
            tracing::debug!(
                "{} new state_root hash from block value {}",
                i,
                block.state_root
            );
            tracing::debug!(
                "{} new tx_root hash from local computation {}",
                i,
                new_txns_mpt.hash()
            );
            tracing::debug!(
                "{} new tx_root hash from block value {}",
                i,
                block.transactions_root
            );
            TrieRoots {
                state_root: block.state_root,
                transactions_root: block.transactions_root,
                receipts_root: block.receipts_root,
            }
        } else {
            TrieRoots {
                state_root: next_state_mpt.hash(),
                transactions_root: new_txns_mpt.hash(),
                receipts_root: new_receipts_mpt.hash(),
            }
        };
        let gas_used_l1 = receipt
            .other
            .get_deserialized::<U256>("l1Fee")
            .unwrap_or_else(|| Ok(U256::zero()))
            .unwrap_or_default();
        tracing::debug!("gas_used_l1: {}", gas_used_l1);
        let inputs = GenerationInputs {
            signed_txn: Some(signed_txn),
            tries: TrieInputs {
                state_trie: trimmed_state_mpt,
                transactions_trie: txns_mpt.clone(),
                receipts_trie: receipts_mpt.clone(),
                storage_tries: trimmed_storage_mpts.into_iter().collect(),
            },
            withdrawals,
            contract_code: contract_codes.clone(),
            block_metadata: block_metadata.clone(),
            block_hashes: block_hashes.clone(),
            gas_used_before: gas_used,
            gas_used_after: gas_used + receipt.gas_used.unwrap(),
            gas_used_l1,

            checkpoint_state_trie_root: prev_block.state_root, // TODO: make it configurable
            trie_roots_after,
            txn_number_before: i.into(), // receipt.transaction_index.0[0].into(),
        };

        state_mpt = next_state_mpt;
        storage_mpts = next_storage_mpts;
        gas_used += receipt.gas_used.unwrap();
        assert_eq!(gas_used, receipt.cumulative_gas_used);
        bloom = new_bloom;
        txns_mpt = new_txns_mpt;
        receipts_mpt = new_receipts_mpt;

        proof_gen_ir.push(inputs);
    }

    Ok(proof_gen_ir)
}

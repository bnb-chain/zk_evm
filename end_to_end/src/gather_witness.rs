use std::collections::{BTreeMap, HashMap};
use std::default::Default;
use std::fs::File;
use std::io::Write;
use std::ops::Div;

use ethereum_types::{Address, Bloom, H256, U256, U64};
use ethers::abi::AbiEncode;
use ethers::prelude::{AccountState, DiffMode, Http, Provider, StorageProof};
use ethers::types::{Block, PreStateMode, Transaction, TransactionReceipt};
use ethers::utils::rlp;
use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::TrieRoots;
use evm_arithmetization::GenerationInputs;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie};
use mpt_trie::trie_subsets::create_trie_subset;

use crate::mpt::{apply_diffs, get_account_storage_post, insert_mpt, trim, Mpt};
use crate::rpc_utils::{
    get_beacon_root_proof, get_block_by_number, get_block_hashes, get_block_metadata,
    get_diffmode_trace, get_prestatemode_trace, get_proof, get_receipt, get_tx, AccountInfo,
};
use crate::utils::{has_storage_deletion, keccak, HardFork, BEACON_ADDR, OPTIMISM_BASE_FEE_ADDR, OPTIMISM_L1_BLOCK_ADDR, OPTIMISM_L1_FEE_ADDR, BLOCK_MINER_ADDR};

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

        // for debugging
        let (_next_proof, _next_storage_proof, ..) =
             get_proof(*address, storage_keys, block_number, provider).await?;
        // insert_mpt(state_mpt, next_proof);

        let key = keccak(address.0);
        if !empty_storage {
            let mut storage_mpt = Mpt::new();
            storage_mpt.root = account_info.storage_root;
            for sp in storage_proof {
                insert_mpt(&mut storage_mpt, sp.proof);
            }
            // for sp in next_storage_proof {
            //     insert_mpt(&mut storage_mpt, sp.proof);
            // }
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

pub fn encode_recepits(receipt: &TransactionReceipt, fork: HardFork, tx_type: usize) -> Vec<u8> {
    let mut bs = rlp::RlpStream::new();
    let is_extend = fork == HardFork::Ecotone && tx_type == 126;
    if is_extend {
        bs.begin_list(6);
    } else {
        bs.begin_list(4);
    }
    bs.append(&receipt.status.unwrap());
    bs.append(&receipt.cumulative_gas_used);
    bs.append(&receipt.logs_bloom);
    bs.append_list(&receipt.logs);
    if is_extend {
        let deposit_nonce = receipt
            .other
            .get_deserialized::<String>("depositNonce")
            .unwrap_or_else(|| Ok("".into()))
            .unwrap_or_default();
        let deposit_nonce =
            u64::from_str_radix(deposit_nonce.trim_start_matches("0x"), 16).unwrap();
        bs.append(&deposit_nonce);
        let deposit_receipt_version = receipt
            .other
            .get_deserialized::<String>("depositReceiptVersion")
            .unwrap_or_else(|| Ok("".into()))
            .unwrap_or_default();
        let deposit_receipt_version =
            u64::from_str_radix(deposit_receipt_version.trim_start_matches("0x"), 16).unwrap();
        bs.append(&deposit_receipt_version);
    }
    let bs_r = bs.out().freeze();
    let mut ref_bytes: Vec<u8> = Vec::new();
    ref_bytes.extend(bs_r);
    if !receipt.transaction_type.unwrap().is_zero() {
        // logic of remote block
        let pre_fix = receipt.transaction_type.unwrap().0[0] as u8;
        ref_bytes.insert(0, pre_fix);
    }

    // println!("###### receipts: {:?}", ref_bytes);
    ref_bytes
}

pub fn infer_chain_id_from_rpc_url(url: String) -> U256 {
    if url.contains("opbnb-mainnet") {
        return 0xcc.into();
    }
    if url.contains("opbnb-testnet") {
        return 0x15eb.into();
    }
    if url.contains("opt-mainnet") {
        return 0xa.into();
    }
    if url.contains("optimism") {
        return 0xa.into();
    }
    if url.contains("opt-testnet") {
        return 0xaa37dc.into();
    }
    U256::one()
}
// TODO: just map.extend()
fn merge_btree_maps<K: Ord + Clone, V: Clone + std::fmt::Debug>(
    map1: &mut BTreeMap<K, V>,
    map2: &BTreeMap<K, V>,
) {
    for (key, value) in map2.iter() {
        if map1.contains_key(key) {
            continue;
        }
        map1.insert(key.clone(), value.clone());
    }
}

fn update_beacon_root(
    state_mpt: &mut HashedPartialTrie,
    storage_mpts: &mut HashMap<H256, HashedPartialTrie>,
    block_timestamp: U256,
    beacon_acc_info: AccountInfo,
    beacon_storage_proofs: &Vec<StorageProof>,
) {
    println!(
        "before update beacon root: {}",
        state_mpt.hash().encode_hex()
    );
    let slot = block_timestamp % 8191;
    let prev_val = beacon_storage_proofs[0].value;
    let to_val = block_timestamp;
    let key = H256(keccak(BEACON_ADDR.0));
    let mut trie = storage_mpts.get(&key).unwrap().clone();
    let slot_h256: H256 = slot.encode_hex().parse().unwrap();
    let slot_nibbles = Nibbles::from_bytes_be(&keccak(slot_h256.0)).unwrap();
    let sanity = trie.get(slot_nibbles).unwrap();
    let sanity = rlp::decode::<U256>(sanity).unwrap();
    println!("sanity: {}", sanity.encode_hex());
    println!("prev_val: {}", prev_val.encode_hex());
    trie.insert(slot_nibbles, rlp::encode(&block_timestamp).to_vec())
        .unwrap();
    let sanity = trie.get(slot_nibbles).unwrap();
    let sanity = rlp::decode::<U256>(sanity).unwrap();
    println!("sanity: {}", sanity.encode_hex());
    println!("to_val: {}", to_val.encode_hex());
    storage_mpts.insert(key, trie.clone());

    let addr_nibbles = Nibbles::from_bytes_be(&keccak(BEACON_ADDR.0)).unwrap();
    let account = AccountRlp {
        nonce: U256::from(beacon_acc_info.nonce.as_u64()),
        balance: beacon_acc_info.balance,
        storage_root: trie.hash(),
        code_hash: beacon_acc_info.code_hash,
    };
    state_mpt
        .insert(addr_nibbles, rlp::encode(&account).to_vec())
        .unwrap();
    println!(
        "after update beacon root: {}",
        state_mpt.hash().encode_hex()
    );
}

pub async fn gather_witness(
    block_number: u64,
    fork: HardFork,
    provider: &Provider<Http>,
) -> anyhow::Result<Vec<GenerationInputs>> {
    let chain_id = infer_chain_id_from_rpc_url(provider.url().to_string());
    println!("chain id: {}", chain_id.as_u64());
    println!("input block_number: {}", block_number);
    // let block_number = provider.get_block_number().await?.as_u64();
    println!("using block_number: {}", block_number);
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
    // get tx, receipt, debug_trace(prestate) and debug_trace(diff)
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

    // init beacon root account
    let (beacon_account_proof, beacon_storage_proofs, beacon_acc_info) =
        get_beacon_root_proof(block_number.into(), block.timestamp, provider).await?;
    insert_mpt(&mut state_mpt, beacon_account_proof);
    let key = H256(keccak(BEACON_ADDR.0));
    let mut sto = Mpt::new();
    sto.root = beacon_acc_info.storage_root;
    for slot_proof in beacon_storage_proofs.iter() {
        insert_mpt(&mut sto, slot_proof.proof.clone());
    }
    storage_mpts.insert(key, sto);

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
            update_beacon_root(
                &mut state_mpt,
                &mut storage_mpts,
                block.timestamp,
                beacon_acc_info,
                &beacon_storage_proofs,
            );
            op_account_15 = Some(
                prestate_trace
                    .0
                    .get(&OPTIMISM_L1_BLOCK_ADDR)
                    .unwrap()
                    .clone(),
            );
            let acc = prestate_trace.0.get(&OPTIMISM_BASE_FEE_ADDR);
            if let Some(account_state) = acc {
                op_account_19 = Some(account_state.clone());
            }

            let acc = prestate_trace.0.get(&OPTIMISM_L1_FEE_ADDR);
            if let Some(account_sate) = acc {
                op_account_1a = Some(account_sate.clone());
            }
        }
        if i > 0 {
            let mut op_account_19_new = op_account_19.clone().unwrap();
            let mut op_account_1a_new = op_account_1a.clone().unwrap();
            if tx.transaction_type.unwrap() != U64::from(126) {
                // calculate op base fee
                let gas_used_in_receipt = receipt.gas_used.unwrap();
                op_account_19_new.balance = Some(
                    op_account_19_new.balance.unwrap() + gas_used_in_receipt * op_base_fee_per_gas,
                    // op_account_19_new.balance.unwrap(),
                );
                println!("############ 19 fee: {}", (gas_used_in_receipt * op_base_fee_per_gas).encode_hex());
                // calculate op L1 fee
                let cnt_zero = signed_txn.iter().filter(|&n| *n == 0).count();
                let cnt_non_zero = signed_txn.len() - cnt_zero;
                let sto = op_account_15.clone().unwrap().storage.unwrap();
                let param_1 = U256::from(
                    sto.get(&H256::from_low_u64_be(1))
                        .unwrap_or(&H256::zero())
                        .0,
                );
                // let param_1: U256 = 13279463729u64.into(); // todo
                let param_5 = U256::from(
                    sto.get(&H256::from_low_u64_be(5))
                        .unwrap_or(&H256::zero())
                        .0,
                );
                let param_6 = U256::from(
                    sto.get(&H256::from_low_u64_be(6))
                        .unwrap_or(&H256::zero())
                        .0,
                );

                let param_3 = U256::from(
                    sto.get(&H256::from_low_u64_be(3))
                        .unwrap_or(&H256::zero())
                        .0,
                );
                let param_3_16_20 = param_3.0[1] >> 32;
                let param_3_20_24 = param_3.0[1] % (1 << 32);
                let param_7 = U256::from(
                    sto.get(&H256::from_low_u64_be(7))
                        .unwrap_or(&H256::zero())
                        .0,
                );
                // check
                // let key = H256(keccak(OPTIMISM_L1_BLOCK_ADDR.0));
                // let trie = storage_mpts.get(&key).unwrap().clone();
                // let slot = U256::from(3);
                // let slot_h256: H256 = slot.encode_hex().parse().unwrap();
                // let slot_nibbles = Nibbles::from_bytes_be(&keccak(slot_h256.0)).unwrap();
                // let p3 = trie.get(slot_nibbles).unwrap();
                // let p3 = rlp::decode::<U256>(p3).unwrap();

                let op_rollup_data_gas = match fork {
                    HardFork::BedRock => cnt_zero * 4 + (cnt_non_zero + 68) * 16,
                    _ => cnt_zero * 4 + cnt_non_zero * 16,
                };
                let op_l1_fee: U256 = match fork {
                    HardFork::Ecotone => {
                        (U256::from(op_rollup_data_gas)
                            * (U256::from(16) * param_1 * U256::from(param_3_16_20) + param_7 * U256::from(param_3_20_24))).div(16_000_000)
                    }
                    _ => {
                        ((U256::from(op_rollup_data_gas) + param_5) * param_1 * param_6)
                                .div(U256::from(1_000_000))
                    }
                };
                op_account_1a_new.balance = Some(op_account_1a_new.balance.unwrap() + op_l1_fee);
                println!("############ op_l1_fee: {}", op_l1_fee.encode_hex());

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

            op_account_19 = Some(op_account_19_new.clone());
            op_account_1a = Some(op_account_1a_new.clone());
        }

        if tx_count == 1 {
            // padding nil tx to the front
            let trie_roots_after = TrieRoots {
                state_root: state_mpt.hash(),
                transactions_root: txns_mpt.hash(),
                receipts_root: receipts_mpt.hash(),
            };

            let addr_nibbles = Nibbles::from_bytes_be(&keccak(BEACON_ADDR.0)).unwrap();
            let keys: Vec<Nibbles> = vec![addr_nibbles];
            let trimmed_state_mpt = create_trie_subset(&state_mpt, keys).unwrap();
            let mut trimmed_storage_mpts = storage_mpts.clone();
            let beacon_storage_key = H256(keccak(BEACON_ADDR.0));
            for (k, t) in trimmed_storage_mpts.iter_mut() {
                if k.eq(&beacon_storage_key) {
                    continue;
                }
                *t = HashedPartialTrie::from(Node::Hash(t.hash()));
            }

            let dummy_txn = GenerationInputs {
                txn_number_before: U256::zero(),
                gas_used_before: U256::zero(),
                gas_used_after: U256::zero(),
                gas_used_l1: U256::zero(),
                signed_txn: None,
                withdrawals: vec![],
                global_exit_roots: vec![],
                tries: TrieInputs {
                    state_trie: trimmed_state_mpt,
                    transactions_trie: txns_mpt.clone(),
                    receipts_trie: receipts_mpt.clone(),
                    storage_tries: trimmed_storage_mpts.into_iter().collect(),
                },
                trie_roots_after,
                checkpoint_state_trie_root: prev_block.state_root,
                contract_code: HashMap::default(),
                block_metadata: block_metadata.clone(),
                block_hashes: block_hashes.clone(),
            };
            proof_gen_ir.insert(0, dummy_txn);
        }
        println!(
            "state_root before apply_diff: {}",
            state_mpt.hash().encode_hex()
        );

        let (next_state_mpt, next_storage_mpts) = apply_diffs(
            state_mpt.clone(),
            storage_mpts.clone(),
            &mut contract_codes,
            diffstate_trace.clone(),
        );
        
        let op_account_15_origin = op_account_15.unwrap().clone();
        op_account_15 = Some(
            get_account_storage_post(OPTIMISM_L1_BLOCK_ADDR, &diffstate_trace)
                .unwrap_or(op_account_15_origin.clone()),
        );
        let sto_origin: BTreeMap<H256, H256> = op_account_15_origin.clone().storage.unwrap();
        merge_btree_maps(
            op_account_15.as_mut().unwrap().storage.as_mut().unwrap(),
            &sto_origin,
        );
        // after the transaction
        println!(
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
        let beacon_storage_key = H256(keccak(BEACON_ADDR.0));
        let beacon_storage = storage_mpts.get(&beacon_storage_key).unwrap().clone();
        let (trimmed_state_mpt, mut trimmed_storage_mpts) = trim(
            state_mpt.clone(),
            storage_mpts.clone(),
            prestate_trace.0.clone(),
            has_storage_deletion,
        );
        trimmed_storage_mpts.insert(beacon_storage_key, beacon_storage.clone());
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
            encode_recepits(&receipt, fork, tx.transaction_type.unwrap().as_usize()),
        )?;

        // Use withdrawals for the last tx in the block.
        let withdrawals = if last_tx { wds.clone() } else { vec![] };
        // For the last tx, we check that the final trie roots match those in the block
        // header.
        // check account 19
        check_account(&OPTIMISM_BASE_FEE_ADDR, &state_mpt, &next_state_mpt);
        // check account 1a
        check_account(&OPTIMISM_L1_FEE_ADDR, &state_mpt, &next_state_mpt);
        // check account 11
        check_account(&BLOCK_MINER_ADDR, &state_mpt, &next_state_mpt);
        // check account 15
        check_account(&OPTIMISM_L1_BLOCK_ADDR, &state_mpt, &next_state_mpt);
        // check beacon account
        check_account(&BEACON_ADDR, &state_mpt, &next_state_mpt);
        let trie_roots_after = if last_tx {
            println!(
                "{} new receipt_root hash from local computation {}",
                i,
                new_receipts_mpt.hash()
            );
            println!(
                "{} new receipt_root hash from block value {}",
                i, block.receipts_root
            );
            println!(
                "{} new state_root hash from local computation {}",
                i,
                next_state_mpt.hash()
            );
            println!(
                "{} new state_root hash from block value {}",
                i, block.state_root
            );
            println!(
                "{} new tx_root hash from local computation {}",
                i,
                new_txns_mpt.hash()
            );
            println!(
                "{} new tx_root hash from block value {}",
                i, block.transactions_root
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
        println!("gas_used_l1: {}", gas_used_l1);
        let col: Vec<_> = trimmed_storage_mpts.into_iter().collect();
        let cloned: Vec<(ethereum_types::H256, HashedPartialTrie)> = serde_json::from_str(&serde_json::to_string(&col).unwrap()).unwrap();
        let inputs = GenerationInputs {
            signed_txn: Some(signed_txn),
            tries: TrieInputs {
                state_trie: trimmed_state_mpt,
                transactions_trie: txns_mpt.clone(),
                receipts_trie: receipts_mpt.clone(),
                storage_tries: cloned,
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
            global_exit_roots: vec![],
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

fn check_account(addr: &Address, state_mpt: &HashedPartialTrie, next_state_mpt: &HashedPartialTrie) {
    // check beacon account
    println!("CHECKing addr: {}", addr.encode_hex());
    let addr_nibbles = Nibbles::from_bytes_be(&keccak(addr.0)).unwrap();
    let acc = state_mpt
        .get(addr_nibbles)
        .unwrap();
    let acc = rlp::decode::<AccountRlp>(acc).unwrap();
    println!(
        "BEFORE: acc balance from state_trie: {}",
        acc.balance.encode_hex()
    );
    println!(
        "BEFORE: acc nonce from state_trie: {}",
        acc.nonce.encode_hex()
    );
    println!(
        "BEFORE: acc storage_root from state_trie: {}",
        acc.storage_root.encode_hex()
    );
    println!(
        "BEFORE: acc code_hash from state_trie: {}",
        acc.code_hash.encode_hex()
    );
    let acc = next_state_mpt
        .get(addr_nibbles)
        .unwrap();
    let acc = rlp::decode::<AccountRlp>(acc).unwrap();
    println!(
        "AFTER : acc balance from state_trie: {}",
        acc.balance.encode_hex()
    );
    println!(
        "AFTER : acc storage_root from state_trie: {}",
        acc.storage_root.encode_hex()
    );
    println!(
        "AFTER : acc nonce from state_trie: {}",
        acc.nonce.encode_hex()
    );
    println!(
        "AFTER : acc code_hash from state_trie: {}",
        acc.code_hash.encode_hex()
    );
}
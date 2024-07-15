#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

use anyhow::anyhow;
use ethers::abi::AbiEncode;
use ethers::prelude::*;
use ethers::types::Address;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use serde::{Deserialize, Serialize};

use crate::utils::{convert_bloom, EMPTY_HASH, OPTIMISM_BASE_FEE_ADDR, OPTIMISM_L1_FEE_ADDR};

fn address_formatter(address: Address) -> String {
    address
        .encode_hex()
        .chars()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>()
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct AccountInfo {
    pub address: Address,
    pub nonce: U64,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AccountProof(pub Vec<Bytes>);

impl From<Vec<Bytes>> for AccountProof {
    fn from(value: Vec<Bytes>) -> Self {
        AccountProof(value)
    }
}

impl From<AccountProof> for Vec<Bytes> {
    fn from(val: AccountProof) -> Self {
        val.0
    }
}

/// Get the block from block_number
pub async fn get_block_by_number(
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<Block<H256>> {
    // try load tx
    let mut block: Option<Block<H256>>;
    if let Ok(file) = File::open(format!("dump/blocks/block_{}.json", block_number)) {
        block = Some(serde_json::from_reader::<_, Block<H256>>(file).expect("dump file error"));
    } else {
        block = None
    }

    // fetch data from rpc
    if block.is_none() {
        block = Some(
            provider
                .get_block(block_number)
                .await?
                .ok_or_else(|| anyhow!("Block not found."))?,
        );

        // dump block
        let mut file = File::create(format!("dump/blocks/block_{}.json", block_number))?;
        file.write_all(&serde_json::to_vec(&block.clone().unwrap())?)?;
    }

    Ok(block.unwrap())
}

/// Get the tx
pub async fn get_tx(
    transaction_hash: TxHash,
    provider: &Provider<Http>,
) -> anyhow::Result<Transaction> {
    // try load tx
    let mut tx: Option<Transaction>;
    if let Ok(file) = File::open(format!("dump/tx_{}.json", transaction_hash.encode_hex())) {
        tx = Some(serde_json::from_reader::<_, Transaction>(file).expect("dump file error"));
    } else {
        tx = None
    }

    // fetch data from rpc
    if tx.is_none() {
        tx = Some(
            provider
                .get_transaction(transaction_hash)
                .await?
                .ok_or_else(|| anyhow!("Transaction not found."))?,
        );

        // dump tx
        let mut file = File::create(format!("dump/tx_{}.json", transaction_hash.encode_hex()))?;
        file.write_all(&serde_json::to_vec(&tx.clone().unwrap())?)?;
    }

    Ok(tx.unwrap())
}

/// Get the receipt
pub async fn get_receipt(
    transaction_hash: TxHash,
    provider: &Provider<Http>,
) -> anyhow::Result<TransactionReceipt> {
    // try load receipt
    let mut receipt: Option<TransactionReceipt>;
    if let Ok(file) = File::open(format!(
        "dump/receipt_{}.json",
        transaction_hash.encode_hex()
    )) {
        receipt =
            Some(serde_json::from_reader::<_, TransactionReceipt>(file).expect("dump file error"));
    } else {
        receipt = None
    }

    // fetch data from rpc
    if receipt.is_none() {
        receipt = Some(
            provider
                .get_transaction_receipt(transaction_hash)
                .await?
                .ok_or_else(|| anyhow!("Receipt not found."))?,
        );

        // dump receipt
        let mut file = File::create(format!(
            "dump/receipt_{}.json",
            transaction_hash.encode_hex()
        ))?;
        file.write_all(&serde_json::to_vec(&receipt.clone().unwrap())?)?;
    }

    Ok(receipt.unwrap())
}

pub(crate) async fn get_prestate_account_state(
    address: Address,
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<AccountState> {
    let (_proof, _storage_proof, account_info, ..) =
        get_proof(address, vec![], block_number, provider).await?;
    let code = Some(get_account_code(address, block_number, provider).await?);
    let account_state = AccountState {
        balance: Some(account_info.balance),
        code,
        nonce: None,
        storage: None,
    };

    Ok(account_state)
}

async fn add_optimism_fee_accounts_to_prestatemode(
    debug_trace: &mut PreStateMode,
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<()> {
    let prev_block_number = block_number - 1;
    for address in [OPTIMISM_BASE_FEE_ADDR, OPTIMISM_L1_FEE_ADDR] {
        let account_state =
            get_prestate_account_state(address, prev_block_number, provider).await?;
        debug_trace.0.insert(address, account_state);
    }

    Ok(())
}

/// Get the prestatemode trace
pub async fn get_prestatemode_trace(
    transaction_hash: TxHash,
    provider: &Provider<Http>,
) -> anyhow::Result<PreStateMode> {
    // try load receipt
    let debug_trace: Option<PreStateMode>;
    if let Ok(file) = File::open(format!(
        "dump/trace_prestatemode_{}.json",
        transaction_hash.encode_hex()
    )) {
        debug_trace =
            Some(serde_json::from_reader::<_, PreStateMode>(file).expect("dump file error"));
    } else {
        debug_trace = None
    }

    // fetch data from rpc
    if debug_trace.is_none() {
        let geth_trace = provider
            .debug_trace_transaction(transaction_hash, tracing_options())
            .await?;
        let mut trace: PreStateMode;
        if let GethTrace::Known(GethTraceFrame::PreStateTracer(PreStateFrame::Default(tr))) =
            geth_trace
        {
            trace = tr;
        } else {
            panic!("debug trace failed to parse")
        }

        let tx = get_tx(transaction_hash, provider).await?;
        let block_number = tx.block_number.unwrap();
        let tx_index = tx.transaction_index.unwrap().0[0];
        if tx_index == 0 {
            add_optimism_fee_accounts_to_prestatemode(&mut trace, block_number, provider).await?;
        }

        // dump trace
        let mut file = File::create(format!(
            "dump/trace_prestatemode_{}.json",
            transaction_hash.encode_hex()
        ))?;
        file.write_all(&serde_json::to_vec(&trace)?)?;
        return Ok(trace);
    }

    Ok(debug_trace.unwrap())
}

/// Get the diffmode trace
pub async fn get_diffmode_trace(
    transaction_hash: TxHash,
    provider: &Provider<Http>,
) -> anyhow::Result<DiffMode> {
    // try load receipt
    let debug_trace: Option<DiffMode>;
    if let Ok(file) = File::open(format!(
        "dump/trace_diffmode_{}.json",
        transaction_hash.encode_hex()
    )) {
        debug_trace = Some(serde_json::from_reader::<_, DiffMode>(file).expect("dump file error"));
    } else {
        debug_trace = None
    }

    // fetch data from rpc
    if debug_trace.is_none() {
        let geth_trace = provider
            .debug_trace_transaction(transaction_hash, tracing_options_diff())
            .await?;
        let trace: DiffMode;
        if let GethTrace::Known(GethTraceFrame::PreStateTracer(PreStateFrame::Diff(tr))) =
            geth_trace
        {
            trace = tr;
        } else {
            panic!("debug trace failed to parse")
        }

        // dump trace
        let mut file = File::create(format!(
            "dump/trace_diffmode_{}.json",
            transaction_hash.encode_hex()
        ))?;
        file.write_all(&serde_json::to_vec(&trace)?)?;
        return Ok(trace);
    }

    Ok(debug_trace.unwrap())
}

pub async fn get_account_code(
    address: Address,
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<String> {
    // try load code
    let mut code: Option<String>;
    if let Ok(file) = File::open(format!(
        "dump/code_{}_{}.json",
        address_formatter(address),
        block_number
    )) {
        code = Some(serde_json::from_reader::<_, String>(file).expect("dump file error"));
    } else {
        code = None
    }

    // fetch data from rpc
    if code.is_none() {
        let res: Bytes = provider
            .get_code(address, Some(block_number.into()))
            .await?;
        let res = res.to_string();
        code = Some(res);

        // dump code
        let mut file = File::create(format!(
            "dump/code_{}_{}.json",
            address_formatter(address),
            block_number
        ))?;
        file.write_all(&serde_json::to_vec(&code.clone().unwrap())?)?;
    }

    Ok(code.unwrap())
}

/// Get the proof for an account + storage locations at a given block number.
pub async fn get_proof(
    address: Address,
    locations: Vec<H256>,
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<(Vec<Bytes>, Vec<StorageProof>, AccountInfo, bool)> {
    // tracing::info!("Proof {:?}: {:?} {:?}", block_number, address, locations);
    // println!("Proof {:?}: {:?} {:?}", block_number, address, locations);

    // try load account_info
    let mut account_info: Option<AccountInfo>;
    if let Ok(file) = File::open(format!(
        "dump/account_info_{}_0x{}.json",
        block_number,
        address_formatter(address)
    )) {
        account_info =
            Some(serde_json::from_reader::<_, AccountInfo>(file).expect("dump file error"));
    } else {
        account_info = None;
    }
    // try load account_proof
    let mut account_proof: Option<AccountProof>;
    if let Ok(file) = File::open(format!(
        "dump/account_proof_{}_0x{}.json",
        block_number,
        address_formatter(address)
    )) {
        account_proof =
            Some(serde_json::from_reader::<_, AccountProof>(file).expect("dump file error"));
    } else {
        account_proof = None
    }
    // try load storage_proof
    let mut storage_proofs: BTreeMap<usize, StorageProof> = BTreeMap::new();
    let mut query_locations: Vec<(usize, H256)> = Vec::new();
    for (i, loc) in locations.iter().enumerate() {
        if let Ok(file) = File::open(format!(
            "dump/account_storage_proof_{}_0x{}_{}.json",
            block_number,
            address_formatter(address),
            (*loc).encode_hex()
        )) {
            let single_storage_proof = serde_json::from_reader(file).expect("dump file error");
            storage_proofs.insert(i, single_storage_proof);
        } else {
            query_locations.push((i, *loc));
        }
    }

    // fetch data from rpc
    if account_info.is_none() || account_proof.is_none() || !query_locations.is_empty() {
        let proof = provider
            .get_proof(
                address,
                query_locations.iter().map(|item| item.1).collect(),
                Some(block_number.into()),
            )
            .await?;
        if account_info.is_none() {
            account_info = Some(AccountInfo {
                address,
                nonce: proof.nonce,
                balance: proof.balance,
                storage_root: proof.storage_hash,
                code_hash: proof.code_hash,
            });
            // dump account info
            let mut file = File::create(format!(
                "dump/account_info_{}_0x{}.json",
                block_number,
                address_formatter(address)
            ))?;
            file.write_all(&serde_json::to_vec(&account_info.unwrap())?)?;
        }
        if account_proof.is_none() {
            account_proof = Some(proof.account_proof.into());
            // dump account proof
            let mut file = File::create(format!(
                "dump/account_proof_{}_0x{}.json",
                block_number,
                address_formatter(address)
            ))?;
            file.write_all(&serde_json::to_vec(&account_proof.clone().unwrap())?)?;
        }
        for (idx, item) in query_locations.iter().enumerate() {
            storage_proofs.insert(item.0, proof.storage_proof[idx].clone());
            // dump storage proofs
            let mut file = File::create(format!(
                "dump/account_storage_proof_{}_0x{}_{}.json",
                block_number,
                address_formatter(address),
                item.1.encode_hex()
            ))?;
            file.write_all(&serde_json::to_vec(&proof.storage_proof[idx])?)?;
        }
    }
    let is_empty = account_info.unwrap().balance.is_zero()
        && account_info.unwrap().nonce.is_zero()
        && account_info.unwrap().code_hash == EMPTY_HASH;

    assert_eq!(storage_proofs.len(), locations.len());
    let ret = (
        account_proof.unwrap().into(),
        storage_proofs.values().cloned().collect::<Vec<_>>(), // BTreeMap is ordered
        account_info.unwrap(),
        is_empty,
    );
    Ok(ret)
}

/// Tracing options for the debug_traceTransaction call.
pub(crate) fn tracing_options() -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::PreStateTracer,
        )),

        ..GethDebugTracingOptions::default()
    }
}

pub(crate) fn tracing_options_diff() -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::PreStateTracer,
        )),

        tracer_config: Some(GethDebugTracerConfig::BuiltInTracer(
            GethDebugBuiltInTracerConfig::PreStateTracer(PreStateConfig {
                diff_mode: Some(true),
            }),
        )),
        ..GethDebugTracingOptions::default()
    }
}

/// Get the Plonky2 block metadata at the given block number.
pub async fn get_block_metadata(
    block_number: U64,
    block_chain_id: U256,
    provider: &Provider<Http>,
) -> anyhow::Result<(BlockMetadata, H256)> {
    let block = get_block_by_number(block_number, provider).await?;

    let block_l1_beneficiary_address_str = "0x420000000000000000000000000000000000001a";
    // Parse the string into an Address type
    let block_l1_beneficiary_address: Address = block_l1_beneficiary_address_str
        .parse()
        .expect("Failed to parse address");

    let block_base_beneficiary_address_str = "0x4200000000000000000000000000000000000019";
    // Parse the string into an Address type
    let block_base_beneficiary_address: Address = block_base_beneficiary_address_str
        .parse()
        .expect("Failed to parse address");
    Ok((
        BlockMetadata {
            block_beneficiary: block.author.unwrap(),
            block_l1_beneficiary: block_l1_beneficiary_address,
            block_base_beneficiary: block_base_beneficiary_address,
            block_timestamp: block.timestamp,
            block_number: U256([block_number.0[0], 0, 0, 0]),
            block_difficulty: block.difficulty,
            block_gaslimit: block.gas_limit,
            block_chain_id,
            block_base_fee: block.base_fee_per_gas.unwrap(),
            block_bloom: convert_bloom(block.logs_bloom.unwrap()),
            block_gas_used: block.gas_used,
            block_random: block.mix_hash.unwrap(),
        },
        block.state_root,
    ))
}

pub async fn get_block_hashes(
    block_number: U64,
    provider: &Provider<Http>,
) -> anyhow::Result<BlockHashes> {
    let mut prev_hashes = vec![H256::zero(); 256];
    let cur_hash = get_block_by_number(block_number, provider)
        .await?
        .hash
        .unwrap();
    for i in 1..=256 {
        let hash = get_block_by_number(block_number - i, provider)
            .await?
            .hash
            .unwrap();
        prev_hashes[256 - i] = hash;
    }

    Ok(BlockHashes {
        prev_hashes,
        cur_hash,
    })
}

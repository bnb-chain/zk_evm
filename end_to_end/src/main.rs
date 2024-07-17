use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Error, Result};
use ciborium_io::Write;
use ethers::prelude::*;
use evm_arithmetization::generation::generate_traces;
use evm_arithmetization::{AllStark, GenerationInputs, StarkConfig};
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::util::timing::TimingTree;
use proof_gen::proof_gen::{generate_agg_proof, generate_txn_proof};
use proof_gen::proof_types::{AggregatableProof, GeneratedTxnProof};
use proof_gen::prover_state::ProverStateBuilder;
use proof_gen::ProverState;

use crate::gather_witness::gather_witness;
use crate::rpc_utils::{OPBNB_MAINNET_RPC, OPBNB_TESTNET_RPC, OPTIMISM_MAINNET_RPC};
use crate::utils::HardFork;

mod gather_witness;
mod mpt;
mod rpc_utils;
mod utils;

async fn dump_witness_if_not_exist(
    block_number: u64,
    fork: HardFork,
    provider: &Provider<Http>,
) -> Result<()> {
    let witness_file: String = format!("witness/test_witness_{}.json", block_number);
    if !Path::new(&witness_file).exists() {
        println!("{} not exist, get witness from RPC...", witness_file);
        let proof_gen_ir = gather_witness(block_number, fork, provider).await?;
        // std::io::stdout().write_all(&serde_json::to_vec(&gen_inputs)?)?;
        let mut file = File::create(witness_file)?;
        file.write_all(&serde_json::to_vec(&proof_gen_ir)?)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let active_fork = HardFork::Ecotone;
    let block_number = env::var("BLOCK_NUMBER")
        .unwrap_or("114165249".into())
        .parse::<u64>()
        .expect("get block number from env error");
    let run_prover: bool = env::var("RUN_PROVER")
        .unwrap_or("0".into())
        .parse::<usize>()
        .expect("env error")
        > 0;
    let fetch_witness_only: bool = env::var("FETCH_WITNESS")
        .unwrap_or("0".into())
        .parse::<usize>()
        .expect("env error")
        > 0;
    let rpc_provider: String = env::var("RPC").unwrap_or("OPBNB_TESTNET".into());

    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
        .build("log/output.log")?;
    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(LevelFilter::Trace),
        )?;
    log4rs::init_config(config)?;

    let provider_url = if rpc_provider.eq("OPBNB_MAINNET") {
        OPBNB_MAINNET_RPC
    } else if rpc_provider.eq("OPBNB_TESTNET") {
        OPBNB_TESTNET_RPC
    } else if rpc_provider.eq("OPTIMISM_MAINNET") {
        OPTIMISM_MAINNET_RPC
    } else {
        OPBNB_TESTNET_RPC //default
    };
    let provider =
        Provider::<Http>::try_from(provider_url).expect("could not instantiate HTTPs Provider");

    dump_witness_if_not_exist(block_number, active_fork, &provider).await?;
    if fetch_witness_only {
        return Ok(());
    }

    // generate trace (default) or run prover if RUN_PROVER is set
    let witness_file: String = format!("witness/test_witness_{}.json", block_number);
    println!("reading from {}...", witness_file);
    let mut file = File::open(witness_file)?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer)?;
    println!("witness length: {}", buffer.len());
    let proof_gen_ir: Vec<GenerationInputs> = serde_json::from_str(&buffer)?;

    let builder = ProverStateBuilder::default();
    let prover_state: Option<ProverState> = if run_prover {
        Some(builder.build())
    } else {
        None
    };

    let mut proofs: Vec<GeneratedTxnProof> = Vec::new();
    for (i, input) in proof_gen_ir.into_iter().enumerate() {
        if !run_prover {
            println!("Processing tx {} trace", i);
            if let Err(error) = generate_traces(
                &AllStark::<GoldilocksField, 2>::default(),
                input,
                &StarkConfig::standard_fast_config(),
                &mut TimingTree::default(),
            ) {
                println!("Error tracing tx: {:?}", error);
            }
            continue;
        }
        println!("Processing tx {} proof", i);
        let proof = generate_txn_proof(prover_state.as_ref().unwrap(), input, None);
        if let Err(error) = proof {
            println!("Error proving tx: {:?}", error);
        } else {
            proofs.push(proof.unwrap());
            println!("Successfully proved tx {}", i)
        }
    }

    if !run_prover {
        return Ok(());
    }
    // Aggregate proofs
    println!("generate agg proof");
    assert!(proofs.len() > 1);
    let prover_state = prover_state.as_ref().unwrap();
    proofs.reverse();
    // init: grab 2 tx proofs
    let mut result = generate_agg_proof(
        prover_state,
        &AggregatableProof::from(proofs.pop().unwrap()),
        &AggregatableProof::from(proofs.pop().unwrap()),
    );
    if result.is_err() {
        return Err(Error::from(result.err().unwrap()));
    }
    // iter over proofs merge
    while !proofs.is_empty() {
        println!("remaining len(proofs): {}", proofs.len());
        let lhs = AggregatableProof::from(result.unwrap());
        result = generate_agg_proof(
            prover_state,
            &lhs,
            &AggregatableProof::from(proofs.pop().unwrap()),
        );
        if result.is_err() {
            return Err(Error::from(result.err().unwrap()));
        }
    }
    println!("aggregate proofs finished");

    Ok(())
}

#[cfg(test)]
mod est {
    use std::ops::Div;

    use ethereum_types::Address;
    use ethereum_types::{BigEndianHash, H256, U256};
    use ethers::abi::AbiEncode;
    use ethers::prelude::*;
    use ethers::utils::rlp;
    use evm_arithmetization::Node;
    use keccak_hash::keccak;
    use mpt_trie::nibbles::{Nibbles, ToNibbles};
    use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};

    use crate::mpt::{insert_mpt, Mpt};
    use crate::rpc_utils::{get_account_code, get_block_by_number, get_prestatemode_trace, get_proof, get_receipt, get_tx, OPBNB_MAINNET_RPC, OPBNB_TESTNET_RPC, OPTIMISM_MAINNET_RPC};
    use crate::utils::{BEACON_ADDR, OPTIMISM_L1_BLOCK_ADDR};

    #[tokio::test]
    async fn test_get_tx() -> anyhow::Result<()> {
        println!("Get witness from RPC...");
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");

        // tx1 simple tx
        // let tx_hash: TxHash =
        // "0xca70656217989acbbf3c45442b7b6011e9872e9f4a72e33126512e607ca065c1"
        //     .parse()
        //     .unwrap();
        // gg_witness(tx_hash, &provider).await?;

        // tx0 setL1Msg
        let tx_hash: TxHash = "0xca8aa2398ad488bf70a72b7168d2b11d7abf2d8858b0b0f65ef651f4247386b3"
            .parse()
            .unwrap();
        let tx = get_tx(tx_hash, &provider).await?;
        println!("tx: {:?}", tx);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_proof() -> anyhow::Result<()> {
        let address: Address = OPTIMISM_L1_BLOCK_ADDR;
        let provider = Provider::<Http>::try_from(OPTIMISM_MAINNET_RPC)
            .expect("could not instantiate HTTPs Provider");

        // let block_number = provider.get_block_number().await?;
        let block_number = provider.get_block_number().await?;
        let (_proof, _storage_proof, account_info, ..) =
            get_proof(address, vec![], block_number - 1, &provider).await?;
        println!("address: {}", account_info.address.encode_hex());
        println!("balance: {}", account_info.balance.encode_hex());
        println!("nonce: {}", account_info.nonce.as_u64());

        let (_proof, _storage_proof, account_info, ..) =
            get_proof(address, vec![], block_number, &provider).await?;
        println!("address: {}", account_info.address.encode_hex());
        println!("balance: {}", account_info.balance.encode_hex());
        println!("nonce: {}", account_info.nonce.as_u64());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_code() -> anyhow::Result<()> {
        let address: Address = "0x4200000000000000000000000000000000000015"
            .parse()
            .unwrap();
        println!("Address: {:?}", address.to_fixed_bytes());
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");
        let block_number = provider.get_block_number().await?;

        let (_state_proof, _storage_proof, account_info, account_empty) =
            get_proof(address, Vec::new(), block_number.into(), &provider).await?;

        println!("account_info: {:?}", account_info);
        println!("account_empty: {}", account_empty);

        let res: Bytes = provider
            .get_code(account_info.address, Some(block_number.into()))
            .await?;
        let res = res.to_string();
        println!("res: {}", res);

        let res = get_account_code(address, block_number.into(), &provider).await?;
        println!("res: {}", res);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_receipt() -> anyhow::Result<()> {
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");

        // let tx_hash: TxHash =
        // "0x2a2c5ae4c1ce1c8ab1c7d17e0bc993108afe32bacdb6c67ae327d51074fa4f05"
        let tx_hash: TxHash = "0x70c6b23bea6ccb539fbc064982e28758146b9ef98fb7310f70f392f04159ddaf"
            .parse()
            .unwrap();
        let receipt = get_receipt(tx_hash, &provider).await?;
        println!("receipt: {:?}", receipt);

        Ok(())
    }

    fn insert_storage(trie: &mut HashedPartialTrie, slot: U256, value: U256) -> anyhow::Result<()> {
        let mut bytes = [0; 32];
        slot.to_big_endian(&mut bytes);
        let key = keccak(bytes);
        let nibbles = Nibbles::from_bytes_be(key.as_bytes()).unwrap();
        if value.is_zero() {
            trie.delete(nibbles)?;
        } else {
            let r = rlp::encode(&value);
            trie.insert(nibbles, r.freeze().to_vec())?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn test_get_storage_at() -> anyhow::Result<()> {
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");
        // let address: Address = "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001"
        // let address: Address = "0x4200000000000000000000000000000000000015"
        let addr: Address = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
            .parse()
            .unwrap();
        // let ref_block = 30969466u64;
        let ref_block = provider.get_block_number().await?.as_u64();
        // let ref_block = ref_block - 1;
        let block = get_block_by_number(ref_block.into(), &provider).await?;
        let block_time = block.timestamp;
        let slot = block_time % 8191;
        println!("block_time: {}", block_time.encode_hex());
        println!("slot: {}", slot.encode_hex());

        let locs = (0..8191)
            .collect::<Vec<u64>>()
            .iter()
            .map(|i| H256::from_low_u64_be(*i))
            .collect();

        let (_, sproofs, acc_info, _) =
            get_proof(addr, locs, (ref_block - 1).into(), &provider).await?;

        let loc = H256::from_low_u64_be(slot.as_u64());
        let value = provider
            .get_storage_at(addr, loc, Some((ref_block - 1).into()))
            .await?;
        println!("value from get_storage_at: {}", value.encode_hex());
        println!(
            "value from storage_proofs: {}",
            sproofs[slot.as_usize()].value.encode_hex()
        );

        let mut trie: HashedPartialTrie = Node::Empty.into();
        for i in 0..8191 {
            insert_storage(&mut trie, sproofs[i].key, sproofs[i].value).unwrap()
        }
        println!("trie: {}", trie.hash().encode_hex());

        let mut mpt: Mpt = Mpt::new();
        for proof in sproofs {
            insert_mpt(&mut mpt, proof.proof)
        }
        mpt.root = acc_info.storage_root;
        let trie = mpt.to_partial_trie();
        println!("trie from mpt: {}", trie.hash().encode_hex());

        Ok(())
    }

    #[tokio::test]
    async fn test_at() -> anyhow::Result<()> {
        let a = (U256::from(2) * U256::from(30) * U256::from(40)).div(100);
        println!("a:{}", a.as_u64());
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");
        let block = get_block_by_number(31236729.into(), &provider).await?;
        println!("block timestamp: {}", block.timestamp.encode_hex());
        println!("slot of timestamp: {}", block.timestamp % 8191);

        let addr: Address = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
            .parse()
            .unwrap();
        println!("beacon addr: {:?}", addr.0);
        let value = provider
            .get_storage_at(
                addr,
                H256::from_low_u64_be(3839),
                Some((31236729 - 1).into()),
            )
            .await?;
        println!("value before set: {}", value.encode_hex());
        let value = provider
            .get_storage_at(addr, H256::from_low_u64_be(3839), Some(31236729.into()))
            .await?;
        println!("value after set: {}", value.encode_hex());

        let slot = block.timestamp % 8191;
        println!("slot: {}", slot.encode_hex());
        println!("slot nibbles: {}", slot.to_nibbles());
        let slot_h256: H256 = slot.encode_hex().parse().unwrap();
        println!("slot(h256): {}", slot_h256.encode_hex());
        let key = Nibbles::from_bytes_be(keccak(slot_h256).as_bytes()).unwrap();
        println!("key: {}", key);
        let key = Nibbles::from_bytes_be(&crate::utils::keccak(slot_h256)).unwrap();
        println!("key: {}", key);
        let mut ss = &mut [0; 32];
        slot.to_big_endian(ss);
        let key = Nibbles::from_bytes_be(keccak(ss).as_bytes()).unwrap();
        println!("key: {}", key);
        Ok(())
    }
    #[tokio::test]
    async fn test_tok() -> anyhow::Result<()> {
        let block_number = 32011152;
        let provider = Provider::<Http>::try_from(OPBNB_TESTNET_RPC)
            .expect("could not instantiate HTTPs Provider");
        let block = get_block_by_number(block_number.into(), &provider).await?;

        let slot = block.timestamp % 8191;
        let slot = slot.encode_hex().parse().unwrap();
        let (beacon_account_proof, slot_proof, beacon_acc_info, _) = get_proof(
            BEACON_ADDR,
            vec![slot],
            (block_number - 1).into(),
            &provider,
        )
        .await?;
        // let locs = (0..8191).collect::<Vec<u64>>().iter().map(|i|
        // H256::from_low_u64_be(*i)).collect(); let (beacon_account_proof,
        // slot_proof, beacon_acc_info, _) = get_proof(BEACON_ADDR, locs,
        // (block_number-1).into(), &provider).await?;

        let key = H256(crate::utils::keccak(BEACON_ADDR.0));
        let mut sto = Mpt::new();
        sto.root = beacon_acc_info.storage_root;
        insert_mpt(&mut sto, slot_proof[0].proof.clone());
        // let val = sto.mpt.get(&key).unwrap();
        // println!("val_mpt: {:?}", val);

        let trie = sto.to_partial_trie();
        let slot_nibbles = Nibbles::from_bytes_be(&crate::utils::keccak(slot.0)).unwrap();
        let val = trie.get(slot_nibbles).unwrap();
        let val = rlp::decode::<U256>(val).unwrap();
        println!("val_hpt: {}", val.encode_hex());

        Ok(())
    }

    #[test]
    fn test_type_conversion() {
        let addr = BEACON_ADDR;
        // Address is alias of H160
        let h160: H160 = addr;
        println!("h160: {:?}", h160);

        // H160 -> H256
        let h256: H256 = H256::from(h160);
        println!("h256: {:?}", h256);

        // H256 trunc to H160
        let h160: H160 = H160::from(h256);
        println!("h160: {:?}", h160);

        // H256 to U256
        let u256: U256 = h256.into_uint();
        println!("u256: {:?}", u256.encode_hex());

        // U256 to H256
        let h256: H256 = u256.encode_hex().parse().unwrap();
        println!("h256: {:?}", h256);

        // U64 to U256
        let u64 = U64::from(123);
        println!("u64: {:?}", u64);
        let u256 = U256::from(u64.as_u64());
        println!("u256: {:?}", u256);
    }
    
    #[tokio::test]
    async fn test_opmainnet() -> anyhow::Result<()> {
        let provider = Provider::<Http>::try_from(OPBNB_MAINNET_RPC)
            .expect("could not instantiate HTTPs Provider");
        let block = get_block_by_number(27369749.into(), &provider).await?;
        println!("block timestamp: {}", block.timestamp.encode_hex());
        let tx_hash = block.transactions[1];
        let tx = get_tx(tx_hash, &provider).await?;
        println!("tx1: {:?}", tx);
        let receipt = get_receipt(tx_hash, &provider).await?;
        println!("receipt1: {:?}", receipt);
        println!("tx0 hash: {}", block.transactions[0].encode_hex());
        let pre = get_prestatemode_trace(block.transactions[0], &provider).await?;
        println!("pre: {:?}", pre);
        let acc15 = pre
            .0
            .get(&OPTIMISM_L1_BLOCK_ADDR)
            .unwrap()
            .clone();
        
        let sto = acc15.clone().storage.unwrap();
        println!("sto: {:?}", sto);
        let p3 = sto.get(&H256::from_low_u64_be(3)).unwrap().clone().into_uint();
        println!("p3: {:?}", p3.encode_hex());
        println!("p3: {:?}", p3.0);
        
        Ok(())
    }
    
    #[test]
    fn test_nib() {
        let idx = 3u64;
        let nib = Nibbles::from_bytes_be(&rlp::encode(&idx)).unwrap();
        println!("nib: {:?}", nib);
    }
}

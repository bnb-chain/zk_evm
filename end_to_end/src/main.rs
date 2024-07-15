use std::collections::HashMap;
use std::ops::Range;
use std::{env, thread};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Error, Result};
use ciborium_io::Write;
use ethers::prelude::*;
use evm_arithmetization::GenerationInputs;
use evm_arithmetization::generation::generate_traces;
use evm_arithmetization::{AllStark, StarkConfig};
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log::LevelFilter;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::util::timing::TimingTree;
use proof_gen::proof_gen::{generate_agg_proof, generate_txn_proof};
use proof_gen::proof_types::{AggregatableProof, GeneratedTxnProof};
use proof_gen::prover_state::ProverStateBuilder;
use proof_gen::ProverState;

use crate::gather_witness::gather_witness;
use crate::rpc_utils::OPTIMISM_MAINNET_RPC;
use crate::utils::HardFork;

mod gather_witness;
mod mpt;
mod rpc_utils;
mod utils;
use std::time::Instant;

type F = GoldilocksField;
const D: usize = 2;

#[tokio::main]
async fn main() -> Result<()> {
    let run_prover: bool = env::var("RUN_PROVER")
        .unwrap_or("0".into())
        .parse::<usize>()
        .expect("env error")
        > 0;

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

    let block_ranges = [
        // (114165248u64..114165254u64, 70),
        // (113963904u64..113963910u64, 43),
        // (114020226u64..114020232u64, 66),
        // (114223489u64..114223495u64, 76),
        (114547270u64..114547276u64, 35),
        (114453441u64..114453447u64, 43),
        // (114511644u64..114511650u64, 38),
        // (114354387u64..114354393u64, 47),
        // (114089340u64..114089351u64, 149),
        // (114400259u64..114400283u64, 195),
    ];

    let skipped_cases: [(u64, usize); 20] = [
        (114165250, 6), // 2689s
        (114165250, 7), // 1236s - gas little keccak m
        (114165251, 4), // 2698s
        (114165253, 7), // 2701s

        (114020231, 1), // 1075s
        (114020231, 4), // 2338s

        (114223492, 4), // 2860s

        (113963907, 1), // 950s
        (113963909, 7), // 3006s

        (114511644, 1), // 1291s
        (114511644, 6), // 2777s
        (114511649, 2), // 2703s

        (114354389, 4), // 1302s
        (114354388, 7), // 1700s

        (114547274, 14),
        (114547275, 3),
        (114453441, 1),
        (114453443, 8),
        (114453446, 9),
        (114453446, 10)
    ];

    for (i, block_range) in block_ranges.iter().enumerate() {
        println!("start to record block_range {}", i);
        benchmark_one_block_range(run_prover, block_range.0.clone(), block_range.1, skipped_cases).await?;
    }
    Ok(())
}

async fn benchmark_one_block_range(run_prover: bool, block_numbers: Range<u64>, max_transactions_num: usize, skipped_cases: [(u64, usize); 20]) -> Result<()> {

    let start = Instant::now();
    let duration = start.elapsed();
    println!("Time elapsed in start proving blocks {:?} circuit start is: {:?}", block_numbers, duration);

    let mut block_number_proofs: HashMap<u64, Vec<GenerationInputs>> = HashMap::new();
    for block_number in block_numbers.clone() {
        let proof_gen_ir;
        let witness_file: String = format!("witness/test_witness_{}.json", block_number);

        if Path::new(&witness_file).exists() {
            println!("reading from {}...", witness_file);
            let mut file = File::open(witness_file)?;
            let mut buffer = String::new();
            file.read_to_string(&mut buffer)?;
            println!("witness length: {}", buffer.len());
            proof_gen_ir = serde_json::from_str(&buffer)?;
            block_number_proofs.insert(block_number, proof_gen_ir);
        }
    }

    println!("Time elapsed loading all witnesses {:?}", duration);

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();

    let builder = ProverStateBuilder::default();
    let p_state_arc: Arc<ProverState> = Arc::new(builder.build());
    let mut proof_cnt = 0;

    let prove_start = Instant::now();
    for block_number in block_numbers.clone() {

        let proof_gen_ir: Vec<GenerationInputs>;
        let witness_file: String = format!("witness/test_witness_{}.json", block_number);
        if Path::new(&witness_file).exists() {
            proof_gen_ir = block_number_proofs.get(&block_number).unwrap().clone();
        } else {
            println!("{} not exist, get witness from RPC...", witness_file);
            let provider = Provider::<Http>::try_from(
                OPTIMISM_MAINNET_RPC
            )
            .expect("could not instantiate HTTPs Provider");
            println!("Working on block {}", block_number);
            proof_gen_ir = gather_witness(block_number, HardFork::Regolith, &provider).await?;
            // std::io::stdout().write_all(&serde_json::to_vec(&gen_inputs)?)?;
            let mut file = File::create(witness_file)?;
            file.write_all(&serde_json::to_vec(&proof_gen_ir)?)?;
        }

        let duration = prove_start.elapsed();
        println!("Time elapsed loading all witnesses {:?}", duration);
        let p_clone = Arc::clone(&p_state_arc);
        
        let thread_one = thread::spawn(move || {
            for (i, input) in proof_gen_ir.iter().enumerate() {
                if proof_cnt > max_transactions_num {
                    break;
                }
                if skipped_cases.contains(&(block_number, i)) {
                    println!("skipped {} {}", block_number, i);
                    continue;
                }
                let tx_instant = Instant::now();
 
                // let all_stark = AllStark::<F, D>::default();
                // let config = StarkConfig::standard_fast_config();
                // let mut timing = TimingTree::new("prove", log::Level::Debug);
                // if let Err(error) = generate_traces(&all_stark.clone(), input.clone(), &config, &mut timing) {
                //     println!("Error proving tx: {:?}", error);
                // }
                let proof = generate_txn_proof(&p_clone, input.clone(), None);
                if let Err(error) = proof {
                    println!("Error proving tx: {:?}", error);
                } else {
                    let duration = tx_instant.elapsed();
                    println!("proved tx {} {} {:?}", block_number, i, duration);
                    proof_cnt += 1;
                }
            }
        });
        threads.push(thread_one);
        println!("finished");
    }

    println!("total threads {}", threads.len());
    for thread in threads {
        thread.join().expect("Failed to join thread");
    }

    println!("Proving blocks done {:?} is: {:?} ms", block_numbers, prove_start.elapsed());
    Ok(())
}

#[cfg(test)]
mod est {
    use ethereum_types::Address;
    use ethers::abi::AbiEncode;
    use ethers::prelude::*;

    use crate::rpc_utils::{get_account_code, get_proof, get_receipt, get_tx, OPBNB_TESTNET_RPC, OPTIMISM_MAINNET_RPC};
    use crate::utils::OPTIMISM_L1_BLOCK_ADDR;

    #[tokio::test]
    async fn test_get_tx() -> anyhow::Result<()> {
        println!("Get witness from RPC...");
        let provider = Provider::<Http>::try_from(
            OPBNB_TESTNET_RPC
        )
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
        let provider = Provider::<Http>::try_from(
            OPTIMISM_MAINNET_RPC
        )
        .expect("could not instantiate HTTPs Provider");

        // let block_number = provider.get_block_number().await?;
        let block_number = provider.get_block_number().await?;
        let (_proof, _storage_proof, account_info, ..) = get_proof(address, vec![], block_number-1, &provider).await?;
        println!("address: {}", account_info.address.encode_hex());
        println!("balance: {}", account_info.balance.encode_hex());
        println!("nonce: {}", account_info.nonce.as_u64());

        let (_proof, _storage_proof, account_info, ..) = get_proof(address, vec![], block_number, &provider).await?;
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
        let provider = Provider::<Http>::try_from(
            OPBNB_TESTNET_RPC
        )
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
        let provider = Provider::<Http>::try_from(
            OPBNB_TESTNET_RPC
        )
        .expect("could not instantiate HTTPs Provider");

        // let tx_hash: TxHash = "0x2a2c5ae4c1ce1c8ab1c7d17e0bc993108afe32bacdb6c67ae327d51074fa4f05"
        let tx_hash: TxHash = "0x70c6b23bea6ccb539fbc064982e28758146b9ef98fb7310f70f392f04159ddaf"
            .parse()
            .unwrap();
        let receipt = get_receipt(tx_hash, &provider).await?;
        println!("receipt: {:?}", receipt);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_storage_at() -> anyhow::Result<()> {
        let provider = Provider::<Http>::try_from(
            OPTIMISM_MAINNET_RPC
        )
            .expect("could not instantiate HTTPs Provider");
        // let address: Address = "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001"
        let address: Address = "0x4200000000000000000000000000000000000015"
            .parse()
            .unwrap();
        println!("Address: {}", address.encode_hex());
        let ref_block = provider.get_block_number().await?.as_u64();

        for block_number in ref_block-3.. ref_block {
            for i in 0.. 8 {
                let loc = H256::from_low_u64_be(i);
                let res = provider.get_storage_at(address, loc, Some(block_number.into())).await?;
                println!("{}: {}", i, res.encode_hex());
            }
            let bal = provider.get_balance(address, Some(block_number.into())).await?;
            let non = provider.get_transaction_count(address, Some(block_number.into())).await?;
            println!("{} balance: {}, nonce: {}", block_number, bal, non.as_u64());
        }

        Ok(())
    }
}

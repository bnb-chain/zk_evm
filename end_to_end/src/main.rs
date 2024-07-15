use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use ciborium_io::Write;
use ethers::prelude::*;
use evm_arithmetization::all_stark::AllStark;
use evm_arithmetization::generation::generate_traces;
use evm_arithmetization::StarkConfig;
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

mod gather_witness;
mod mpt;
mod rpc_utils;
mod utils;

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

    let proof_gen_ir;
    if Path::new("test_witness.json").exists() {
        println!("reading from test_witness.json...");
        let mut file = File::open("test_witness.json")?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        println!("witness length: {}", buffer.len());
        proof_gen_ir = serde_json::from_str(&buffer)?;
    } else {
        println!("test_witness.json not exist, get witness from RPC...");
        let provider = Provider::<Http>::try_from(
            "https://opbnb-testnet.nodereal.io/v1/b1acba7dd0f74d61942619cf09ec30da",
        )
        .expect("could not instantiate HTTPs Provider");
        let block_number = env::var("BLOCK_NUMBER")
            .unwrap_or("25569387".into())
            .parse::<u64>()
            .expect("get block number from env error");
        println!("Working on block {}", block_number);
        proof_gen_ir = gather_witness(block_number, &provider).await?;
        // std::io::stdout().write_all(&serde_json::to_vec(&gen_inputs)?)?;
        let mut file = File::create("test_witness.json")?;
        file.write_all(&serde_json::to_vec(&proof_gen_ir)?)?;
    }

    let builder = ProverStateBuilder::default();
    let prover_state: Option<ProverState> = if run_prover {
        Some(builder.build())
    } else {
        None
    };
    let mut proofs: Vec<GeneratedTxnProof> = Vec::new();
    for (i, input) in proof_gen_ir.iter().enumerate() {
        println!("Processing tx {}", i);
        log::info!("Tracing tx {}", i);
        if let Err(error) = generate_traces(
            &AllStark::<GoldilocksField, 2>::default(),
            input.clone(),
            &StarkConfig::standard_fast_config(),
            &mut TimingTree::default(),
        ) {
            println!("Error tracing tx: {:?}", error);
        }

        if let Some(p_state) = prover_state.as_ref() {
            let proof = generate_txn_proof(p_state, input.clone(), None);
            if let Err(error) = proof {
                println!("Error proving tx: {:?}", error);
            } else {
                proofs.push(proof.unwrap());
                println!("proved tx {}", i)
            }
        }
    }

    if let Some(p_state) = prover_state.as_ref() {
        println!("generate agg proof");
        let result = generate_agg_proof(
            p_state,
            &AggregatableProof::from(proofs[0].clone()),
            &AggregatableProof::from(proofs[1].clone()),
        );
        if result.is_err() {
            println!("Error generate agg proof");
        }
    }
    println!("finished");

    Ok(())
}

#[cfg(test)]
mod test {
    use ethereum_types::Address;
    use ethers::prelude::*;

    use crate::rpc_utils::{get_account_code, get_proof, get_tx};

    #[tokio::test]
    async fn test_get_tx() -> anyhow::Result<()> {
        println!("Get witness from RPC...");
        let provider = Provider::<Http>::try_from(
            "https://opbnb-testnet.nodereal.io/v1/b1acba7dd0f74d61942619cf09ec30da",
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
        // let address = "0x0761ad996d476bb567f75ee111a2b5df2c74031c"
        // let address = "0x07dbe8500fc591d1852b76fee44d5a05e13097ff"
        let address: Address = "0x4200000000000000000000000000000000000015"
            .parse()
            .unwrap();
        // let block_number = 30259443;
        let block_number = 25569387;
        let provider = Provider::<Http>::try_from(
            "https://opbnb-testnet.nodereal.io/v1/b1acba7dd0f74d61942619cf09ec30da",
        )
        .expect("could not instantiate HTTPs Provider");

        // let tx_hash = "0xc77aa4609ef436b6b382d272d3160490f3ff581cea2d32520391a559a7072665"
        //     .parse()
        //     .unwrap();
        // let prestate_trace = get_prestatemode_trace(tx_hash, &provider).await?;
        // println!("prestate: {:?}", prestate_trace);

        let proof = provider
            .get_proof(address, Vec::new(), Some(block_number.into()))
            .await?;
        println!("proof: {:?}", proof);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_code() -> anyhow::Result<()> {
        let address: Address = "0x4200000000000000000000000000000000000019"
            .parse()
            .unwrap();
        println!("Address: {:?}", address.to_fixed_bytes());
        let address = H160([66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25]);
        println!("Address: {:?}", address.to_fixed_bytes());
        let block_number = 25569387;
        let provider = Provider::<Http>::try_from(
            "https://opbnb-testnet.nodereal.io/v1/b1acba7dd0f74d61942619cf09ec30da",
        )
        .expect("could not instantiate HTTPs Provider");

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
}

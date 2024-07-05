//! This test aims at ensuring that the decoder can properly parse a block trace
//! received from Jerigon into zkEVM `GenerationInputs`, which the prover can
//! then pick to prove each transaction in the block independently.
//!
//! This test only `simulates` the zkEVM CPU, i.e. does not generate STARK
//! traces nor generates proofs, as its purpose is to be runnable easily in the
//! CI even in `debug` mode.

use evm_arithmetization::{prover::testing::prove_all_segments, AllStark, StarkConfig};
use plonky2::{
    field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    util::timing::TimingTree,
};
use pretty_env_logger::env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use serde::{Deserialize, Serialize};
use trace_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};

fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn test_block(path: &str) {
    init_logger();

    let bytes = std::fs::read(path).unwrap();
    let prover_inputs: Vec<ProverInput> = serde_json::from_slice(&bytes).unwrap();

    for prover_input in prover_inputs.into_iter() {
        let tx_inputs = prover_input
            .block_trace
            .into_txn_proof_gen_ir(
                &ProcessingMeta::new(resolve_code_hash_fn),
                prover_input.other_data.clone(),
                50,
            )
            .unwrap();

        let _ = tx_inputs
            .into_iter()
            .take(3)
            .map(|tx_input| {
                println!("");
                let mut timing = TimingTree::new("prove", log::Level::Info);
                prove_all_segments::<F, C, 2>(
                    &AllStark::default(),
                    &StarkConfig::default(),
                    tx_input,
                    20,
                    &mut timing,
                    None,
                )
                .unwrap();
            })
            .collect::<Vec<_>>();
    }
}

/// Tests an empty block with withdrawals: <https://etherscan.io/block/19840104>.
#[test]
fn test_block_19840104() {
    test_block("tests/tmp.json")
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

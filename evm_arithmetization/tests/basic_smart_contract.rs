use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use ethereum_types::{Address, H256, U256};
use evm_arithmetization::cpu::kernel::opcodes::{get_opcode, get_push_opcode};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::prove;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, eth_to_wei,
    ger_account_nibbles, init_logger, preinitialized_state_and_storage_tries,
    update_beacon_roots_account_storage, GLOBAL_EXIT_ROOT_ACCOUNT,
};
use evm_arithmetization::verifier::verify_proof;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

/// Test a simple token transfer to a new address.
#[test]
#[ignore] // Too slow to run on CI.
fn test_basic_smart_contract() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let base_beneficiary = hex!("4200000000000000000000000000000000000019");
    let sender = hex!("2c7536e3605d9c16a7a3d7b1898e529396a65c23");
    let to = hex!("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

    let beneficiary_state_key = keccak(beneficiary);
    let base_beneficiary_state_key = keccak(base_beneficiary);
    let sender_state_key = keccak(sender);
    let to_state_key = keccak(to);

    let beneficiary_nibbles = Nibbles::from_bytes_be(beneficiary_state_key.as_bytes()).unwrap();
    let base_beneficiary_nibbles =
        Nibbles::from_bytes_be(base_beneficiary_state_key.as_bytes()).unwrap();
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_state_key.as_bytes()).unwrap();

    let push1 = get_push_opcode(1);
    let add = get_opcode("ADD");
    let stop = get_opcode("STOP");
    let code = [push1, 3, push1, 4, add, stop];
    let code_gas = 3 + 3 + 3;
    let code_hash = keccak(code);

    let beneficiary_account_before = AccountRlp {
        nonce: 1.into(),
        ..AccountRlp::default()
    };
    let sender_account_before = AccountRlp {
        nonce: 5.into(),
        balance: eth_to_wei(100_000.into()),
        ..AccountRlp::default()
    };
    let to_account_before = AccountRlp {
        code_hash,
        ..AccountRlp::default()
    };
    let base_beneficiary_account_before = AccountRlp {
        balance: 0u64.into(),
        nonce: 1.into(),
        ..AccountRlp::default()
    };

    let (mut state_trie_before, storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();

    state_trie_before.insert(
        beneficiary_nibbles,
        rlp::encode(&beneficiary_account_before).to_vec(),
    )?;
    state_trie_before.insert(
        base_beneficiary_nibbles,
        rlp::encode(&base_beneficiary_account_before).to_vec(),
    )?;
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())?;
    state_trie_before.insert(to_nibbles, rlp::encode(&to_account_before).to_vec())?;

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries,
    };

    let txdata_gas = 2 * 16;
    let gas_used = 21_000 + code_gas + txdata_gas;

    // Generated using a little py-evm script.
    let txn = hex!("f861050a8255f094a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0648242421ba02c89eb757d9deeb1f5b3859a9d4d679951ef610ac47ad4608dc142beb1b7e313a05af7e9fbab825455d36c36c7f4cfcafbeafa9a77bdff936b52afb36d4fe4bcdd");
    let value = U256::from(100u32);

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_base_beneficiary: Address::from(base_beneficiary),
        // block_l1_beneficiary: Default::default(),
        block_difficulty: 0x20000.into(),
        block_number: 1.into(),
        block_chain_id: 1.into(),
        block_timestamp: 0x03e8.into(),
        block_gaslimit: 0xff112233u32.into(),
        block_gas_used: gas_used.into(),
        block_base_fee: 0xa.into(),
        ..Default::default()
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let expected_state_trie_after = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let beneficiary_account_after = AccountRlp {
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let base_beneficiary_account_after = AccountRlp {
            balance: 0xd34aau64.into(),
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let sender_account_after = AccountRlp {
            balance: sender_account_before.balance - value - gas_used * 10,
            nonce: sender_account_before.nonce + 1,
            ..sender_account_before
        };
        let to_account_after = AccountRlp {
            balance: to_account_before.balance + value,
            ..to_account_before
        };

        state_trie_after.insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_after).to_vec(),
        )?;
        state_trie_after.insert(
            base_beneficiary_nibbles,
            rlp::encode(&base_beneficiary_account_after).to_vec(),
        )?;
        state_trie_after.insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())?;
        state_trie_after.insert(to_nibbles, rlp::encode(&to_account_after).to_vec())?;

        state_trie_after.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;
        state_trie_after.insert(
            ger_account_nibbles(),
            rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
        )?;

        state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: gas_used.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(
        Nibbles::from_str("0x80").unwrap(),
        rlp::encode(&receipt_0).to_vec(),
    )?;
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };
    let inputs = GenerationInputs {
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        global_exit_roots: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: gas_used.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
        gas_used_l1: 0.into(),
    };

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing, None)?;
    timing.filter(Duration::from_millis(100)).print();

    verify_proof(&all_stark, proof, &config)
}

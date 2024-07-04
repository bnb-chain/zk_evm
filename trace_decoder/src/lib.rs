//! <div class="warning">
//! This library is undergoing major refactoring as part of (#275)(https://github.com/0xPolygonZero/zk_evm/issues/275).
//! Consider all TODOs to be tracked under that issue.
//! </div>
//!
//! Your neighborhood zk-ready [ethereum](https://github.com/0xPolygonZero/erigon)
//! [node](https://github.com/0xPolygonHermez/cdk-erigon/) emits binary "witnesses"[^1].
//!
//! But [`plonky2`], your prover, wants [`GenerationInputs`].
//!
//! This library helps you get there.
//!
//! [^1]: A witness is an attestation of the state of the world, which can be
//!       proven by a prover.
//!
//! # Non-Goals
//! - Performance - this won't be the bottleneck in any proving system.
//! - Robustness - malicious or malformed input may crash this library.
//!
//! TODO(0xaatif): refactor all the docs below
//!
//! It might not be obvious why we need traces for each txn in order to generate
//! proofs. While it's true that we could just run all the txns of a block in an
//! EVM to generate the traces ourselves, there are a few major downsides:
//! - The client is likely a full node and already has to run the txns in an EVM
//!   anyways.
//! - We want this protocol to be as agnostic as possible to the underlying
//!   chain that we're generating proofs for, and running our own EVM would
//!   likely cause us to loose this genericness.
//!
//! While it's also true that we run our own zk-EVM (plonky2) to generate
//! proofs, it's critical that we are able to generate txn proofs in parallel.
//! Since generating proofs with plonky2 is very slow, this would force us to
//! sequentialize the entire proof generation process. So in the end, it's ideal
//! if we can get this information sent to us instead.
//!
//! This library generates an Intermediary Representation (IR) of
//! a block's transactions, given a [BlockTrace] and some additional
//! data represented by [OtherBlockData].
//!
//! It first preprocesses the [BlockTrace] to provide transaction,
//! withdrawals and tries data that can be directly used to generate an IR.
//! For each transaction, this library extracts the
//! necessary data from the processed transaction information to
//! return the IR.
//!
//! The IR is used to generate root proofs, then aggregation proofs and finally
//! block proofs. Because aggregation proofs require at least two entries, we
//! pad the vector of IRs thanks to additional dummy payload intermediary
//! representations whenever necessary.
//!
//! ### [Withdrawals](https://ethereum.org/staking/withdrawals) and Padding
//!
//! Withdrawals are all proven together in a dummy payload. A dummy payload
//! corresponds to the IR of a proof with no transaction. They must, however, be
//! proven last. The padding is therefore carried out as follows: If there are
//! no transactions in the block, we add two dummy transactions. The withdrawals
//! -- if any -- are added to the second dummy transaction. If there is only one
//! transaction in the block, we add one dummy transaction. If
//! there are withdrawals, the dummy transaction is at the end. Otherwise, it is
//! added at the start. If there are two or more transactions:
//! - if there are no withdrawals, no dummy transactions are added
//! - if there are withdrawals, one dummy transaction is added at the end, with
//!   all the withdrawals in it.

#![deny(rustdoc::broken_intra_doc_links)]

/// The broad overview is as follows:
///
/// 1. Ethereum nodes emit a bunch of binary [`wire::Instruction`]s, which are
///    parsed in [`wire`].
/// 2. They are passed to one of two "frontends", depending on the node
///    - [`hermez_cdk_erigon`], which contains an [`smt_trie`].
///    - [`zero_jerigon`], which contains an [`mpt_trie`].
/// 3. The frontend ([`hermez_cdk_erigon::Frontend`] or
///    [`zero_jerigon::Frontend`]) is passed to the "backend", which lowers to
///    [`evm_arithmetization::GenerationInputs`].
const _DEVELOPER_DOCS: () = ();

/// Defines the main functions used to generate the IR.
mod decoding;
// TODO(0xaatif): add backend/prod support
// #[cfg(test)]
// #[allow(dead_code)]
mod hermez_cdk_erigon;
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
mod processed_block_trace;
mod wire;
mod zero_jerigon;

use std::collections::HashMap;

use anyhow::{bail, Context as _};
use ethereum_types::{Address, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use evm_arithmetization::GenerationInputs;
use itertools::Itertools;
use keccak_hash::keccak as hash;
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};

/// Core payload needed to generate a proof for a block. Note that the scheduler
/// may need to request some additional data from the client along with this in
/// order to generate a proof.
///
/// The trie preimages are the hashed partial tries at the
/// start of the block. A [TxnInfo] contains all the transaction data
/// necessary to generate an IR.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The state and storage trie pre-images (i.e. the tries before
    /// the execution of the current block) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// The code_db is a map of code hashes to the actual code. This is needed
    /// to execute transactions.
    #[serde(default)]
    pub code_db: HashMap<H256, Vec<u8>>,

    /// Traces and other info per transaction. The index of the transaction
    /// within the block corresponds to the slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with separate state/storage tries.
    Separate(SeparateTriePreImages),
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateTriePreImage,
    /// Storage trie.
    pub storage: SeparateStorageTriesPreImage,
}

/// A trie pre-image where state & storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateTriePreImage {
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(HashedPartialTrie),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    /// Compact combined state and storage tries.
    #[serde(with = "crate::hex")]
    pub compact: Vec<u8>,
}

/// A trie pre-image where state and storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<H256, SeparateTriePreImage>),
}

/// Info specific to txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: HashMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

/// Structure holding metadata for one transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnMeta {
    /// Txn byte code.
    #[serde(with = "crate::hex")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde(with = "crate::hex")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// Account addresses that were only read by the txn.
    ///
    /// Note that if storage is written to, then it does not need to appear in
    /// this list (but is also fine if it does).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_read: Option<Vec<H256>>,

    /// Account storage addresses that were mutated by the txn along with their
    /// new value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_written: Option<HashMap<H256, U256>>,

    /// Contract code that this address accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// True if the account existed before this txn but self-destructed at the
    /// end of this txn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destructed: Option<bool>,
}

/// Contract code access type. Used by txn traces.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(H256),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde(with = "crate::hex")] Vec<u8>),
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: H256,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(Address, U256)>,
}

pub fn entrypoint2(
    trace: BlockTrace,
    other: OtherBlockData,
) -> anyhow::Result<Vec<GenerationInputs>> {
    use evm_arithmetization::generation::mpt::AccountRlp;
    use hermez_cdk_erigon::CollatedLeaf;

    let BlockTrace {
        trie_pre_images,
        code_db: out_band_code,
        txn_info,
    } = trace;
    match trie_pre_images {
        BlockTraceTriePreImages::Separate(_) => bail!("TODO(0xaatif)"),
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions =
                wire::parse(&compact).context("couldn't parse instructions from binary format")?;
            let hermez_cdk_erigon::Frontend {
                trie,
                code: in_band_code,
                collation,
            } = hermez_cdk_erigon::frontend(instructions)
                .context("couldn't execute instructions")?;
            let accounts = collation
                .into_iter()
                .map(
                    |(
                        k,
                        CollatedLeaf {
                            balance,
                            nonce,
                            code_hash,
                            storage_root,
                        },
                    )| {
                        (
                            hash(k), // TODO(0xaatif): is this even the right thing to do?
                            AccountRlp {
                                nonce: nonce.unwrap_or_default(),
                                balance: balance.unwrap_or_default(),
                                storage_root: storage_root.unwrap_or_default(),
                                code_hash: code_hash.unwrap_or_default(),
                            },
                        )
                    },
                )
                .collect();

            let txn_infos = txn_infos(
                txn_info,
                &other.b_data.withdrawals,
                in_band_code
                    .into_iter()
                    .map(|it| it.into_vec())
                    .chain(out_band_code.into_values()),
                &accounts,
            )
            .collect::<Vec<_>>();
        }
    };
    todo!()
}

pub fn entrypoint(
    trace: BlockTrace,
    other: OtherBlockData,
    _resolve: impl Fn(H256) -> Vec<u8>,
) -> anyhow::Result<Vec<GenerationInputs>> {
    use evm_arithmetization::generation::mpt::AccountRlp;
    use mpt_trie::partial_trie::PartialTrie as _;

    let BlockTrace {
        trie_pre_images,
        code_db: out_band_code,
        txn_info,
    } = trace;

    let (state, storage, in_band_code) = match trie_pre_images {
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => (
            state,
            storage
                .into_iter()
                .map(|(k, SeparateTriePreImage::Direct(v))| (k, v))
                .collect::<HashMap<_, _>>(),
            vec![],
        ),
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions =
                wire::parse(&compact).context("couldn't parse instructions from binary format")?;
            let zero_jerigon::Frontend {
                state,
                code,
                storage,
            } = zero_jerigon::frontend(instructions)?;
            {
                (
                    state,
                    storage.into_iter().collect(),
                    code.into_iter().map(|it| it.into_vec()).collect(),
                )
            }
        }
    };

    let accounts = state
        .items()
        .filter_map(|(address, leaf)| {
            Some(
                rlp::decode::<AccountRlp>(leaf.as_val()?)
                    .context("expected `state` trie value leaves to consist only of AccountRlp")
                    .map(|account| (H256::from(address), account)),
            )
        })
        .collect::<Result<_, _>>()?;

    Ok(ProcessedBlockTrace {
        txn_info: txn_infos(
            txn_info,
            &other.b_data.withdrawals,
            in_band_code.into_iter().chain(out_band_code.into_values()), // later keys overwrite
            &accounts,
        )
        .collect(),
        withdrawals: other.b_data.withdrawals.clone(),
        state,
        storage,
    }
    .into_txn_proof_gen_ir(other)?)
}

fn txn_infos<'a>(
    txn_info: Vec<TxnInfo>,
    withdrawals: &'a [(Address, U256)],
    code: impl IntoIterator<Item = Vec<u8>>,
    accounts: &'a HashMap<H256, AccountRlp>,
) -> impl Iterator<Item = processed_block_trace::ProcessedTxnInfo> + 'a {
    let mut hash2code = code.into_iter().map(|code| (hash(&code), code)).collect();
    update_last(
        txn_info.into_iter().map(|it| (it, Vec::new())),
        |(_, xtra)| {
            // If this is the last transaction, we mark the withdrawal addresses
            // as accessed in the state trie.
            *xtra = withdrawals
                .iter()
                .map(|(addr, _)| crate::hash(addr.as_bytes()))
                .collect();
        },
    )
    .map(move |(info, xtra)| processed_block_trace::process(info, accounts, &xtra, &mut hash2code))
}

fn update_last<T>(
    it: impl IntoIterator<Item = T>,
    f: impl FnOnce(&mut T),
) -> impl Iterator<Item = T> {
    use itertools::Position;
    let mut f = Some(f);
    it.into_iter()
        .with_position()
        .map(move |(pos, mut it)| match pos {
            Position::First | Position::Middle => it,
            Position::Last | Position::Only => {
                (f.take().unwrap())(&mut it);
                it
            }
        })
}

#[derive(Debug)]
struct ProcessedBlockTrace {
    state: HashedPartialTrie,
    storage: HashMap<H256, HashedPartialTrie>,
    txn_info: Vec<processed_block_trace::ProcessedTxnInfo>,
    withdrawals: Vec<(Address, U256)>,
}

/// Like `#[serde(with = "hex")`, but tolerates and emits leading `0x` prefixes
mod hex {
    use std::{borrow::Cow, fmt};

    use serde::{de::Error as _, Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: hex::ToHex,
    {
        let s = data.encode_hex::<String>();
        serializer.serialize_str(&format!("0x{}", s))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: hex::FromHex,
        T::Error: fmt::Display,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        match s.strip_prefix("0x") {
            Some(rest) => T::from_hex(rest),
            None => T::from_hex(&*s),
        }
        .map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[derive(serde::Deserialize)]
struct Case {
    #[serde(with = "hex")]
    pub bytes: Vec<u8>,
    #[serde(deserialize_with = "h256")]
    pub expected_state_root: ethereum_types::H256,
}

#[cfg(test)]
fn h256<'de, D: serde::Deserializer<'de>>(it: D) -> Result<ethereum_types::H256, D::Error> {
    Ok(ethereum_types::H256(hex::deserialize(it)?))
}

#![allow(missing_docs)]

use std::collections::HashMap;

use ethers::prelude::*;
use ethers::utils::keccak256;

#[allow(dead_code)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum HardFork {
    BedRock,
    Regolith,
    Ecotone,
    TBD,
}

/// Keccak of empty bytes.
pub const EMPTY_HASH: H256 = H256([
    197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202,
    130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
]);

// OPTIMISM_L1_BLOCK_ADDR: "0x4200000000000000000000000000000000000015"
pub const OPTIMISM_L1_BLOCK_ADDR: Address =
    H160([66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21]);

// OPTIMISM_BASE_FEE_ADDR: "0x4200000000000000000000000000000000000019"
pub const OPTIMISM_BASE_FEE_ADDR: Address =
    H160([66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25]);

// OPTIMISM_L1_FEE_ADDR: "0x420000000000000000000000000000000000001a"
pub const OPTIMISM_L1_FEE_ADDR: Address =
    H160([66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26]);

pub fn keccak<T: AsRef<[u8]> + Clone>(bytes: T) -> [u8; 32] {
    keccak256(bytes.clone())
}

pub fn has_storage_deletion(diff: &DiffMode) -> bool {
    for (addr, old) in &diff.pre {
        if !diff.post.contains_key(addr) {
            return true;
        } else {
            let new = diff.post.get(addr).unwrap();
            for &k in old.storage.clone().unwrap_or_default().keys() {
                if !new.storage.clone().unwrap_or_default().contains_key(&k) {
                    return true;
                }
            }
        }
    }
    false
}

/// Hash map from code hash to code.
/// Add the empty code hash to the map.
pub(crate) fn contract_codes() -> HashMap<H256, Vec<u8>> {
    let mut map = HashMap::new();
    map.insert(EMPTY_HASH, vec![]);
    map
}

pub(crate) fn convert_bloom(bloom: Bloom) -> [U256; 8] {
    let mut other_bloom = [U256::zero(); 8];
    for (i, c) in other_bloom.iter_mut().enumerate() {
        *c = U256::from_big_endian(&bloom.0[i * 32..(i + 1) * 32]);
    }
    other_bloom
}

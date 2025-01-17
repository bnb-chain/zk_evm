pub mod aggregator;
pub mod assembler;
mod ast;
pub(crate) mod constants;
mod cost_estimator;
pub(crate) mod keccak_util;
pub mod opcodes;
mod optimizer;
mod parser;
pub mod stack;
mod utils;

pub(crate) mod interpreter;

pub use constants::cancun_constants;
pub use constants::global_exit_root;

#[cfg(test)]
mod tests;

use assembler::assemble;
use parser::parse;

use crate::cpu::kernel::constants::evm_constants;

/// Assemble files, outputting bytes.
/// This is for debugging the kernel only.
pub fn assemble_to_bytes(files: &[String]) -> Vec<u8> {
    let parsed_files: Vec<_> = files.iter().map(|f| parse(f)).collect();
    let kernel = assemble(parsed_files, evm_constants(), true);
    kernel.code
}

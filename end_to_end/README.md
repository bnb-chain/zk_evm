# End to end example

## Update Plonky2

```shell
git submodule update --init
```

## Update Rust Toolchain

A working rust nightly build is rustc 1.79.0-nightly (e3181b091 2024-04-18), update if necessary.

```shell
rustup update
```

## Run example

### Fetch Witness from RPC

```shell
#export BLOCK_NUMBER=114165247 # op
#export BLOCK_NUMBER=25569387
export BLOCK_NUMBER=30933580
export RPC=OPBNB_TESTNET
rm witness/test_witness_$BLOCK_NUMBER.json
rm log/output.log
FETCH_WITNESS=1 RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
```

### Run Prover with Witness from Dump

```shell
# export BLOCK_NUMBER=32536652
export BLOCK_NUMBER=27954261
export RPC=OPBNB_MAINNET
# rm witness/test_witness_$BLOCK_NUMBER.json
rm log/output.log
# FETCH_WITNESS=1 RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
# RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
RUN_PROVER=1 RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
```

### Run Prover with Existing Witness

```shell
export BLOCK_NUMBER=114165247
rm log/output.log
RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
```

trace log will be in the log/output.log

### Run Real Prover

```shell
export BLOCK_NUMBER=114165247
rm log/output.log
RUN_PROVER=1 RUST_LOG=trace RUST_BACKTRACE=full cargo run --release --package end_to_end
```

## Change witness

Change accordingly in main.rs, remove test_witness.json and run again.

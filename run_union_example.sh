export RUST_BACKTRACE=1
export RUST_LOG=bitvmx_client=debug

cargo run --example union setup_bitcoin_node && cargo run all

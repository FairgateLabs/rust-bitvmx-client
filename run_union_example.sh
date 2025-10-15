export RUST_BACKTRACE=1
export RUST_LOG=bitvmx_client=info

cargo run --release --example union setup_bitcoin_node && cargo run --release all --fresh

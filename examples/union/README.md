## Bridge example

To run this example, first `cd` into rust-bitvmx-client root and start a bitcoin node:
```bash
cargo run --release --example union setup_bitcoin_node
```

Start a Bitvmx instance (defaults to four operators):
```bash
cargo run all
```

or, clear all persistent data with
```bash
rm -rf /tmp/regtest/
RUST_BACKTRACE=1 cargo run --release all --fresh
```

Run the committee flow:
```bash
RUST_BACKTRACE=1 cargo run --release --example union committee
```

## Using scripts

Another option is to run them via the provided scripts in `examples/union/scripts`.
NOTE: Scripts should be run from the root of the repository to ensure correct config paths.

For example, to run the committee setup:
```bash
./examples/union/scripts/run-example.sh committee
```


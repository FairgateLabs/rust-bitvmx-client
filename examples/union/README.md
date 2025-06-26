## Bridge example

To run this example, first `cd` into rust-bitvmx-client root and start a bitcoin node:
```bash
cargo run --example union setup_bitcoin_node
```

Start a Bitvmx instance (defaults to four operators):
```bash
cargo run all
# or, clear all persistent data with
rm -rf /tmp/broker_p2p_6118*; rm -r /tmp/op_* ; RUST_BACKTRACE=1 cargo run all
```

Run a pegin example script:
```bash
RUST_BACKTRACE=1 cargo run --example union pegin
```

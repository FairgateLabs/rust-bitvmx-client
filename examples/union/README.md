## Bridge example

To run this example, first `cd` into rust-bitvmx-client root and start a bitcoin node:
```bash
cargo run --example union setup_bitcoin_node
```

Start a Bitvmx instance (defaults to four operators):
```bash
cargo run all
```

Run a pegin example script:
```bash
RUST_BACKTRACE=1 cargo run --example union pegin
```

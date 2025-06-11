## Bridge example

To run this example, first `cd` into rust-bitvmx-client root and start a bitcoin node:
```bash
cargo test  -- --ignored test_prepare_bitcoin
```

Start a Bitvmx instance (defaults to four operators):
```bash
cargo run all
```

Run the example script:
```bash
RUST_BACKTRACE=1 cargo run --example bridge
```

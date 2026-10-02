# Bridge example

//TODO this needs to be updated

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

### Challenge example

The `challenge` example uses the Dispute Resolution Protocol (DRP). Before
running it, disable the high-fee regtest node in
`examples/union/bitcoin.rs`:

```rust
pub const HIGH_FEE_NODE_ENABLED: bool = false;
```

Build the emulator dispatcher once before starting the example. From the
`rust-bitvmx-job-dispatcher` repository root, run:

```bash
cargo build --release --bin bitvmx-emulator-dispatcher
```

Then, from the `rust-bitvmx-client` repository root, start the example and
specify the winning party (`op` or `wt`):

```bash
./examples/union/scripts/run-example.sh challenge op
```

Keep that process running. After it prints
`Running union example: challenge...`, open a separate terminal and start the
four dispatcher instances from the `rust-bitvmx-job-dispatcher` repository
root:

```bash
./dev/scripts/run-emulator-dispatcher-all.sh
```

The dispatchers listen on ports `22222`, `33333`, `44444`, and `55554`, which
must match the broker ports configured for `op_1` through `op_4`. The launcher
runs them in the background and writes their output under the job dispatcher
repository's `logs/` directory, so returning to the shell prompt is expected.

- Port to solidity:

There is a particular script for porting the example Bitcoin transactions brodcasted to a Solidity file, so they can be used in the smart contracts for verification. You need to run:

```bash
./examples/union/scripts/run-example.sh solidity_txs
```

It will create a `BitVMXCompatibilityData.sol` file in the logs folder.

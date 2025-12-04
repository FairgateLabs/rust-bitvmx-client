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

- Challenge example: 

In the case of `challenge` example you should provide who is the winning party `op` or `wt`:

```bash
./examples/union/scripts/run-example.sh challenge op
```

Also, in the examples that involve DRP (Dispute Resolution Protocol) you it is needed to run job dispatcher emulators in a separated terminal.
There is a script for that as well, inside `/rust-bitvmx-workspace/rust-bitvmx-job-dispatcher/` run:

```bash
./dev/scripts/run-emulator-dispatcher-all.sh
```

NOTE: This script should be run after all BitVMX clients are running and point to the same port as the clients.

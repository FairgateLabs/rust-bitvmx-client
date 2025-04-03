# BitVMX Client
The BitVMX Client provides the core functionality for interacting with BitVMX protocol and the Bitcoin blockchain.

## Installation
Clone the repository and initialize the submodules:
```bash
$ git clone git@github.com:FairgateLabs/rust-bitvmx-client.git
```

## Build

```bash
cargo build
```


## Testing

### Client test

You will need a regtest Bitcoin node running.

```bash
docker run --rm --name bitcoin-server -it \
    -p 18443:18443 \
    -p 18444:18444 \
    ruimarinho/bitcoin-core:24.0.1 \
    -printtoconsole \
    -regtest=1 \
    -rpcallowip=172.17.0.0/16 \
    -rpcbind=0.0.0.0 \
    -rpcauth='foo:337f951003371b21ba0a964464a1d34a$591adbcccece2e5bc1fdd8426c3aa9441a8a6c5cf0fa9a3ed6f7f53029e76130' \
    -fallbackfee=0.0001 \
    -minrelaytxfee=0.00001 \
    -maxtxfee=10000000 \
    -txindex \
```

Start a bitvmx instance with a prover role:
```bash
RUST_BACKTRACE=1 cargo run -- prover
```

Also start a verifier:
```bash
RUST_BACKTRACE=1 cargo run -- verifier
```

Run the client tests:
```bash
RUST_BACKTRACE=1 cargo test client -- --ignored
```

### Integration test

If you are running a bitcoin node, you should stop it before running the integratio test (as it handles its own node).
```bash
RUST_BACKTRACE=1 cargo test test_single_run -- --ignored
```
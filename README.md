# BitVMX Client
The BitVMX Client provides the core functionality for interacting with BitVMX protocol and the Bitcoin blockchain.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.


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

Run the client tests:
```bash
RUST_BACKTRACE=1 cargo test --package bitvmx-client --test client -- test_client --exact --show-output --ignored
```

### Integration test

If you are running a bitcoin node, you should stop it before running the integratio test (as it handles its own node).
```bash
RUST_BACKTRACE=1 cargo test test_single_run -- --ignored
```
 

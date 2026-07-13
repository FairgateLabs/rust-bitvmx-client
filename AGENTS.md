# AGENTS.md — rust-bitvmx-client

Guidance for AI agents working in this repository.

## What this is

The BitVMX client: core Rust library + binary for interacting with the BitVMX
protocol (disputable computation secured by Bitcoin). Part of the FairgateLabs
BitVMX ecosystem. Not production-ready, unaudited, breaking changes expected.

- Crate name: `bitvmx-client` (lib name `bitvmx_client`)
- Edition 2021, current version tracked in `Cargo.toml`
- All sibling BitVMX crates are pulled as git dependencies from
  `github.com/FairgateLabs/*`, pinned by tag (usually all bumped to the same
  version tag together, e.g. `v0.8.0`).

## Workspace context

This repo lives inside `rust-bitvmx-workspace/`, which contains checkouts of
all sibling repos (`rust-bitvmx-broker`, `rust-bitvmx-protocol-builder`,
`BitVMX-CPU`, etc.) plus a `Meta.toml` cargo workspace for local cross-repo
development. Day-to-day work in this repo uses its own `Cargo.toml` with
git-tagged dependencies; do not add path dependencies unless asked.

## Build

```bash
cargo build                              # debug
cargo build --profile release-with-debug  # release + debug symbols
```

- `build.rs` embeds git describe info; harmless, no setup needed.
- Features: `default = ["cardinal", "union"]`, plus `testpanic` (test-only
  failure injection). Keep feature-gated code compiling with each feature
  combination.

## Tests

Heavy integration tests are `#[ignore]`d and run in release mode. Many need a
regtest bitcoind (Docker) and a prebuilt BitVMX-CPU emulator binary:

```bash
# one-time: build emulator used by tests
cd ../BitVMX-CPU && cargo build --release

# fast unit tests
cargo test

# client tests (regtest bitcoind must NOT be running separately for some)
RUST_BACKTRACE=1 cargo test --release -- --ignored test_all

# full integration test (manages its own bitcoin node)
RUST_BACKTRACE=1 cargo test --release -- --ignored test_full
```

- `scripts/run-tests.sh` is what CI uses (see `.github/workflows/test.yml`);
  it manages a `bitcoind` Docker container via `docker-compose.yml` and
  restarts it between long tests.
- `tests/docker/` has the bitcoind container setup.
- Shared test helpers live in `tests/common/` (`helper.rs`, `dispute.rs`).
- Key ignored tests: `test_all` (integration.rs), `test_full`, `test_drp`
  (fulltest.rs — dispute resolution), `test_lock` (locktest.rs).
- Don't run ignored/integration tests unless asked — they take tens of
  minutes and need Docker.

## Source layout

```
src/
  main.rs            # binary: runs one or more operator instances from config/
  lib.rs             # library root; re-exports bitcoin, protocol_builder, etc.
  bitvmx.rs          # BitVMX struct — central orchestrator / main loop (largest file)
  client.rs          # client-side API wrapper
  types.rs           # IncomingBitVMXApiMessages / OutgoingBitVMXApiMessages (broker JSON-RPC API)
  config.rs          # YAML config loading (config/*.yaml, one per operator)
  comms_helper.rs    # P2P comms message (de)serialization
  message_queue.rs   # queued/retryable message handling
  leader_broadcast.rs# leader-based message broadcast among participants
  signature_verifier.rs, timestamp_verifier.rs, spv_proof.rs, throttle.rs
  program/
    program.rs       # Program state machine
    participant.rs   # participants, CommsAddress, roles
    variables.rs     # program variables / globals / witness vars
    witness.rs       # witness encoding/decoding
    setup/           # multi-party setup engine: keys -> nonces -> signatures (+ garbler) steps
    protocols/
      protocol_handler.rs, protocol_type.rs  # ProtocolHandler trait + dispatch
      dispute/       # DRP: challenges, execution, input handling
      cardinal/      # cardinal protocol: lock, slot, transfer (feature "cardinal")
      union/         # union protocol: pegin/pegout, penalization (feature "union")
      aggregated_key.rs, claim.rs, gc_*.rs, timeouts.rs
```

Other directories:

- `config/` — per-operator YAML configs (`op_1.yaml` … `op_10.yaml`,
  `testnet*_op_*.yaml`, `user_1.yaml`, wallets, broker, routing table).
  `main.rs` panics if the named config file is missing.
- `examples/cardinal`, `examples/union` — runnable end-to-end examples
  (`run_union_example.sh` drives the union one).
- `verifiers/` — verifier program artifacts used by dispute tests.
- `scripts/` — test/coverage/testnet helpers.

## Architecture notes

- The client talks to external components (job dispatchers, brokers, wallet,
  bitcoin coordinator) over the BitVMX broker using JSON-RPC style messages.
  The request/response message pairs are documented in `README.md`
  ("BitVMX API Message" section) and defined in `src/types.rs`
  (`IncomingBitVMXApiMessages` / `OutgoingBitVMXApiMessages`). Keep the
  README table in sync when changing the API enums.
- Programs are multi-party: participants run a setup engine
  (`src/program/setup/`) exchanging keys, nonces, and signatures, then execute
  a protocol (`src/program/protocols/`) that builds and dispatches Bitcoin
  transactions via the bitcoin coordinator.
- `BitVMX::tick()`-style processing in `src/bitvmx.rs` drives everything;
  `main.rs` spins one thread per operator instance.
- Protocols implement the `ProtocolHandler` trait
  (`src/program/protocols/protocol_handler.rs`) and are dispatched by
  `protocol_type.rs` via `enum_dispatch`.
- `union` protocol subtree has its own `CHANGELOG.md`, `DISCLAIMER.md`, and
  `errors.rs`; update the changelog when changing union behavior.

## Conventions

- Errors: `thiserror` enums in `src/errors.rs` (`BitVMXError`); `anyhow` only
  at binary/test level.
- Logging: `tracing` with env-filter; default filter set in `main.rs`
  silences noisy deps. Use `info_span!` with operator id for per-instance logs.
- Branches: work happens on `dev`; PRs target `main`.
- Version bumps: bump `Cargo.toml` version and dependency tags together
  (see commits like "bump to 0.8.0"), typically coordinated across all
  FairgateLabs repos.
- Config/key material lives in `config/`; never commit real secrets, regtest
  keys there are for local development only.

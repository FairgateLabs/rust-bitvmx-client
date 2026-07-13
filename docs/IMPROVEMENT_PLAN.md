# BitVMX Client — Improvement Plan (Ports & Adapters for Unit Testability)

**Goal:** Refactor incrementally toward a hexagonal (ports & adapters) architecture so that core logic
(`BitVMX` orchestration, `Program` lifecycle, protocol handlers, setup engine) can be unit-tested with
in-memory fakes — no bitcoind, no RocksDB, no network, no broker.

**Ground rule:** Every task below is independently mergeable. The code compiles and existing
integration tests pass after each one. Tasks within a phase are ordered by blast radius (smallest first),
but most are parallelizable.

---

## Current State Assessment

### Architecture snapshot

- `src/bitvmx.rs` (~1,600 lines) — god object: constructs all infrastructure (storage, key manager,
  comms, coordinator, wallet, broker), routes API messages (a ~340-line `match`), processes bitcoin
  news, handles ZKP jobs, drives the tick loop.
- `src/types.rs` → `ProgramContext` — the coupling hub passed into `Program` and every protocol handler.
  All fields are **concrete infrastructure types**:

  | Field | Concrete type | External effect |
  |---|---|---|
  | `bitcoin_coordinator` | `BitcoinCoordinator` | Bitcoin RPC, monitoring |
  | `comms` | `QueueChannel` | P2P network |
  | `broker_channel` | `LocalChannel<BrokerStorage>` | L2 / job-dispatcher messaging |
  | `key_manager` | `Rc<KeyManager>` | Key storage on disk |
  | `globals` / `witness` | `Globals` / `WitnessVars` | Backed by `Rc<Storage>` (RocksDB) |
  | `leader_broadcast_helper` | `LeaderBroadcastHelper` | Backed by `Rc<Storage>` |

- `Program` / `SetupEngine` / protocol handlers all take `&ProgramContext` (or `&mut`), so nothing in
  the domain layer can be instantiated without real infrastructure.
- Protocol layer: `protocol_handler.rs` (~1,000 lines of trait with default impls),
  `union/dispute_core.rs` (~3,400 lines) — large modules mixing graph construction (pure) with
  I/O (storage, coordinator, comms).

### Test snapshot

- Unit tests exist in only 10 files, all leaf utilities (`throttle`, `timestamp_verifier`,
  `message_queue`, `comms_helper`, `spv_proof`, …) — i.e., the code that *already* has few dependencies.
- Everything else is covered (partially) by `tests/*.rs` integration tests that boot multiple operators
  plus bitcoind — slow, flaky-prone, and impossible to target edge cases (error paths, reorgs,
  malformed messages, timeout branches).

### Leverage points

- `BitcoinCoordinatorApi` **trait already exists** in the `bitcoin-coordinator` crate and `bitvmx.rs`
  already imports it. This is a ready-made port; we mostly need to change the field type.
- `Globals`/`WitnessVars` funnel all storage access through a narrow surface — one trait unlocks them.
- The broker channel surface actually used is tiny (`send`, `recv`) — a trivial port.

---

## Target Architecture

```
             ┌───────────────────────────────────────────────┐
             │              Domain / Core                    │
             │  BitVMX orchestration · Program lifecycle     │
             │  SetupEngine · Protocol handlers (graph       │
             │  building, news handling, state machines)     │
             └───────┬───────────┬──────────┬────────┬───────┘
                     │  ports (traits in src/ports/)         │
      BitcoinCoordinatorPort  CommsPort  L2ChannelPort       │
      KeyValueStorePort   KeyServicePort  WalletPort  ClockPort
                     │           │          │        │
             ┌───────┴───────────┴──────────┴────────┴───────┐
             │            Adapters                           │
             │  prod: BitcoinCoordinator, QueueChannel,      │
             │        LocalChannel, KeyManager, Wallet,      │
             │        Storage (RocksDB), SystemClock         │
             │  test: RecordingCoordinator, InMemoryComms,   │
             │        InMemoryChannel, InMemoryKV, FakeClock │
             └───────────────────────────────────────────────┘
```

`ProgramContext` becomes a bag of trait objects (`Box<dyn …>` / `Rc<dyn …>`). Production wiring stays
in `BitVMX::new()`; tests wire a `TestContextBuilder` with in-memory adapters.

Note on `KeyManager`: it is deterministic and local (no network). For most tests a **real** KeyManager
over a temp dir is fine and avoids mocking crypto. The port for it is therefore *lower priority* and
scoped to the small method subset actually used.

---

## Phase 0 — Groundwork (no behavior change)

### Task 0.2 — Test taxonomy & fast-test target ✅ DONE
Split test execution: tag integration tests that require bitcoind (feature flag `integration` or
`#[ignore]` + a `just`/script target) so `cargo test` runs only fast tests. Add a CI-friendly
`cargo test --lib` lane. This gives the new unit tests a fast home from day one.
*Effort: S. Risk: none.*
**Done:** all integration `#[ignore]` attributes carry a reason string (bitcoind / BitVMX-CPU /
gnova); `prepare_bitcoin` fails fast with a clear message when docker is unavailable; cargo
aliases `cargo test-fast` and `cargo test-integration` added in `.cargo/config.toml`.

### Task 0.3 — Coverage baseline ✅ DONE
Add `cargo llvm-cov` (or `tarpaulin`) config and record the current line/branch coverage per module in
this document. Re-measure after each phase.
*Effort: XS. Risk: none.*
**Done:** baseline recorded in the [Coverage](#coverage) section below (`cargo llvm-cov --lib`,
2026-07-13). Re-run with `cargo llvm-cov --lib` and update the table after each phase.

### Task 0.4 — Dev-dependency for mocking (decision)
Decide: hand-rolled fakes (recommended — the ports are small and fakes double as simulators) vs
`mockall`. Recommendation: **hand-rolled fakes in `src/adapters/test/`** (behind `#[cfg(any(test, feature = "test-utils"))]`)
so integration tests and downstream crates can reuse them.
*Effort: XS. Risk: none.*

---

## Phase 1 — Introduce Ports (one field of `ProgramContext` at a time)

Pattern for every task in this phase:
1. Define trait in `src/ports/<name>.rs` mirroring **only the methods actually called** (grep first).
2. `impl <Port> for <ConcreteType>` (or a thin newtype wrapper if the impl must live in this crate).
3. Change the `ProgramContext` field to the trait object; fix call sites (usually zero signature churn
   because callers already go through the field).
4. Add the in-memory test adapter + first unit tests that use it.

### Task 1.1 — `KeyValueStorePort` (storage)
Define `trait KeyValueStorePort` covering the `get`/`set`/`transaction` subset of
`storage_backend::KeyValueStore` used by `Globals`, `WitnessVars`, `Program::save/load`,
`LeaderBroadcastHelper`, `MessageQueue`, and the ZKP store keys in `bitvmx.rs`.
Implement for `Storage`. Add `InMemoryStore` (a `RefCell<HashMap<String, Vec<u8>>>` with the same
transaction semantics).
**First consumers:** switch `Globals` and `WitnessVars` to hold `Rc<dyn KeyValueStorePort>`.
**Unit tests unlocked:** full coverage of `Globals`, `WitnessVars`, variable type round-trips.
*Effort: M. Risk: low — mechanical. This is the foundation task; do it first.*

### Task 1.2 — `L2ChannelPort` (broker channel)
Surface used: `send(&Identifier, String)`, `recv() -> Option<(String, Identifier)>`.
Change `ProgramContext::broker_channel` to `Box<dyn L2ChannelPort>`. Test adapter
`InMemoryChannel` records sent messages and lets tests inject inbound ones.
**Unit tests unlocked:** every `reply(...)` path in `bitvmx.rs`; `Program::send_setup_completed`;
`notify_news` L2 notifications — assert on the exact `OutgoingBitVMXApiMessages` emitted.
*Effort: S. Risk: low.*

### Task 1.3 — `BitcoinCoordinatorPort`
Check object safety of the existing `BitcoinCoordinatorApi` trait. If object-safe, use it directly:
`bitcoin_coordinator: Box<dyn BitcoinCoordinatorApi>`. Otherwise define a local port trait with the
used subset (`dispatch`, `monitor`, `get_news`, `ack_news`, `get_transaction`, `add_funding`,
`is_ready`, `tick`) and implement it for `BitcoinCoordinator`.
Test adapter `FakeCoordinator`: records `dispatch`/`monitor` calls; tests push canned
`MonitorNews`/`CoordinatorNews` into it.
**Unit tests unlocked:** `Program::start_monitoring`, `dispatch_transaction_name`,
`BitVMX::process_bitcoin_updates` news fan-out (per-variant, including all the `CoordinatorNews` error
branches that are currently `// TODO: Complete`), `subscribe_to_*`.
*Effort: M. Risk: medium — most-referenced port; do after 1.1/1.2 experience.*

### Task 1.4 — `CommsPort` (P2P)
Surface used: `send`, `check_receive`, `check_deadletter`, `tick`, `get_address`, `get_pubk_hash`,
`close`. Change `ProgramContext::comms` to `Box<dyn CommsPort>`.
Test adapter `InMemoryComms` with an injectable pubkey-hash/address; a `CommsHub` test helper can wire
N `InMemoryComms` together to simulate multi-operator message exchange **in-process**.
**Unit tests unlocked:** `BitVMX::process_comms_messages`, message buffering/replay logic in
`process_msg`, `SignatureVerifier` flows, and — critically — multi-participant `SetupEngine` runs
without any network.
*Effort: M. Risk: medium.*

### Task 1.5 — `ClockPort`
Inject `now()` into `TimestampVerifier`, `Throttle`, and `MessageQueue` retry logic (default adapter:
system clock). Existing unit tests for these modules get faster/deterministic; timeout branches become
testable.
*Effort: S. Risk: low.*

### Task 1.6 — `WalletPort`
Surface used in `bitvmx.rs`: `receive_address`, `balance`, `create_tx`, `update_with_tx`,
`get_wallet_tx`, `cancel_tx`, `tick`, `sync_wallet`, `is_ready`. Wrap in a port; `BitVMX` holds
`Box<dyn WalletPort>`.
**Unit tests unlocked:** `GetFundingAddress` / `GetFundingBalance` / `SendFunds` handlers including
wallet-not-ready and error-reply paths.
*Effort: S. Risk: low.*

### Task 1.7 — `KeyServicePort` (subset of KeyManager)
Grep-derived subset: `sign_ecdsa_recoverable_message`, `next_keypair(_adjusted)`,
`get_my_public_key`, `get_key_pair_for_too_insecure`, `encrypt_rsa_message`, `decrypt_rsa_message`,
`import_rsa_private_key`, plus the musig/winternitz methods used by setup steps and
`ProtocolHandler::sign`. Keep `Rc<dyn KeyServicePort>`; production impl is `KeyManager`.
**Note:** for protocol-level tests, prefer a *real* KeyManager over a temp dir (deterministic, no
network). The port's main value is (a) documenting the true dependency surface and (b) enabling
signature-failure injection.
*Effort: M. Risk: medium — widest method surface. Can be deferred; do last in Phase 1.*

### Task 1.8 — `TestContextBuilder`
With 1.1–1.7 merged, add `src/adapters/test/context.rs` (feature `test-utils`):
`TestContextBuilder::new().with_participants(3).with_leader(0).build()` → `ProgramContext` wired with
in-memory everything + temp-dir KeyManager. Convert one existing integration test scenario
(e.g., a slice of `aggregated_key.rs`) into a fast unit test as a proof of concept.
*Effort: M. Risk: low. This is the payoff milestone of Phase 1.*

---

## Phase 2 — Decompose the `BitVMX` God Object

Each extraction moves code into a struct that takes **ports only**, leaving `BitVMX` as thin wiring.
Order matters less here; each is independent.

### Task 2.1 — Extract `ZkpService`
Move `generate_zkp`, `proof_ready`, `get_zkp_execution_result`, `handle_prover_message`, and the
`StoreKey::ZKP*` keys into `src/services/zkp.rs`. Dependencies: `KeyValueStorePort`, `L2ChannelPort`.
Unit-test the full happy path plus malformed-result-JSON branches (currently untested `warn!` paths).
*Effort: M. Risk: low — self-contained.*

### Task 2.2 — Extract `ApiHandler`
Move the giant `handle_api_message` match into `src/services/api_handler.rs` as
`ApiHandler::handle(msg, from, &mut deps)`. Split the match arms into one method per message.
Unit-test message → reply mapping per variant (table-driven).
*Effort: L. Risk: medium — big mechanical move; keep it a pure cut-paste PR with no logic change.*

### Task 2.3 — Extract `NewsProcessor`
Move `process_bitcoin_updates` news loops + `handle_news` into `src/services/news.rs`.
Unit-test every `MonitorNews`/`CoordinatorNews` variant, including `RSK_PEGIN_TAG` legacy fan-out and
ack emission (assert every processed news gets acked — a real invariant worth locking down).
*Effort: M. Risk: low.*

### Task 2.4 — Extract `ProgramRegistry`
Move `get_programs`/`add_new_program`/`program_exists`/`load_program`/`is_active_program` into
`src/program/registry.rs` over `KeyValueStorePort`. Unit-test duplicate-program rejection, active
filtering.
*Effort: S. Risk: low.*

### Task 2.5 — `MessageRouter` for dispatcher/prover/API routing
Extract the `process_api_messages` `from`-based routing into a small router with tests
(garbler/emulator/prover/API classification).
*Effort: S. Risk: low.*

---

## Phase 3 — Protocol-Layer Testability

### Task 3.1 — Separate graph construction from I/O in `ProtocolHandler`
The `build()` implementations are mostly **pure** (keys in → transaction graph out) but currently read
inputs via `context.globals`. Refactor pattern per protocol: introduce a typed
`<Protocol>Params::from_globals(&Globals) -> Result<Self>` step, then make graph building a pure
function of params + keys. Start with the smallest protocol (`AggregatedKeyProtocol`), establish the
pattern, then replicate.
**Unit tests unlocked:** golden/snapshot tests — given fixed keys and params, assert the built
protocol graph (tx names, structure, txids) is stable. This is the single highest-value protection
against regressions in protocol code.
*Effort: M per protocol (there are ~14). Split into one task per protocol; prioritize
`dispute_core`, `accept_pegin`, `drp` (most business-critical).*

### Task 3.2 — Unit-test setup steps with simulated participants
Using `TestContextBuilder` + `CommsHub` (Task 1.4/1.8): run `SetupEngine` for N in-process participants
through keys → nonces → signatures. Test: happy path, out-of-order message arrival (the buffering
logic in `process_msg`), duplicate messages, leader vs non-leader paths.
*Effort: L. Risk: low (test-only). Very high value — this is the most fragile area per git history.*

### Task 3.3 — Unit-test `Program` state machine
With fakes: `SettingUp → WaitingData → Ready` transitions, save/load round-trip (in-memory store),
`notify_news` routing, `receive_dispatcher_result` context-variant handling (including the invalid
context error branches).
*Effort: M.*

### Task 3.4 — Split oversized protocol modules
`union/dispute_core.rs` (3,400 lines) and `protocol_handler.rs` (1,000 lines): extract pure helpers
(script building, leaf calculations) into submodules with direct unit tests. Mechanical, guided by the
snapshot tests from 3.1 (do 3.1 for a protocol before splitting it).
*Effort: M per module.*

---

## Phase 4 — Quality Hardening (opportunistic, after each phase)

### Task 4.1 — Error hygiene
`BitVMXError::InvalidMessageFormat` is used for ~10 unrelated failures with no payload — replace with
variants carrying context (which field, which message). Unit tests from Phase 2 make this safe.
*Effort: S.*

### Task 4.2 — Resolve TODO debt in news handling
The empty `CoordinatorNews` branches (`TransactionAlreadyInMempool`, `MempoolRejection`,
`NetworkError`) and the deadletter TODO in `process_comms_messages` — now testable via
`FakeCoordinator`, implement real policies with tests first.
*Effort: M (needs product decisions).*

### Task 4.3 — `rsa_public_key` placement
The `//TODO: this should not be here` on `ProgramContext::rsa_public_key` — fold it into the
`KeyServicePort` surface (Task 1.7 makes this trivial).
*Effort: XS.*

### Task 4.4 — CI gate
Once fast unit tests exist: CI job running `cargo fmt --check`, `clippy -D warnings` (or a curated
lint set), `cargo test --lib` on every PR; integration lane nightly/on-label.
*Effort: S.*

---

## Sequencing Summary

```
Phase 0 (hygiene)        0.2 → 0.3 → 0.4                [1–2 days total]
Phase 1 (ports)          1.1 → 1.2 → 1.3 → 1.4 → 1.5/1.6 (parallel) → 1.7 → 1.8
Phase 2 (decompose)      2.1 … 2.5 in any order, after Phase 1
Phase 3 (protocols)      3.1 per-protocol → 3.4 per-module; 3.2/3.3 after 1.8
Phase 4 (hardening)      opportunistic once the relevant tests exist
```

**Recommended first PR chain:** 0.2 → 1.1 (storage port + `Globals` tests) → 1.2 (channel port +
first `bitvmx.rs` reply tests). Three small PRs that prove the pattern end-to-end and deliver the
first real unit tests within days.

## Success Metrics

- `cargo test --lib` runs in < 30 s with no external processes. *(baseline: 65 tests, < 1 s ✅)*
- Coverage on `src/` (excluding adapters): baseline 9.91 % → 40 % after Phase 2 → 60 %+ after Phase 3.
- New protocol changes require a snapshot-test update (i.e., graph changes are always intentional).
- Integration tests shrink to true end-to-end scenarios instead of being the only safety net.

## Coverage

Baseline measured 2026-07-13 with `cargo llvm-cov --lib` (unit tests only; 65 tests, < 1 s).
**Totals: 9.91 % lines · 14.65 % functions · 10.81 % regions.**

Line coverage per area (files ordered worst-offender first within each group):

| Area | Line coverage | Notes |
|---|---|---|
| `throttle.rs` | 100 % | existing unit tests |
| `message_queue.rs` | 99.7 % | existing unit tests |
| `spv_proof.rs` | 79.6 % | existing unit tests |
| `timestamp_verifier.rs` | 78.6 % | existing unit tests |
| `comms_helper.rs` | 73.2 % | existing unit tests |
| `helper.rs` | 55.4 % | |
| `signature_verifier.rs` | 54.4 % | |
| `leader_broadcast.rs` | 49.2 % | |
| `config.rs` | 47.1 % | |
| `program/setup/setup_engine.rs` | 19.0 % | steps (keys/nonces/signatures/garbler): 0–4 % |
| `program/participant.rs` | 14.7 % | |
| `program/variables.rs` | 10.5 % | unlocked by Task 1.1 |
| `bitvmx.rs` | 0 % | 1,209 lines — unlocked by Phases 1–2 |
| `program/program.rs` | 0 % | unlocked by Task 3.3 |
| `types.rs`, `client.rs`, `ping_helper.rs` | 0 % | |
| `program/protocols/**` (all protocols) | ~0 % | dispute/mod 0.2 %, tx_news 8.1 %, timeouts 24.7 %; union/cardinal/claim/gc: 0 % — unlocked by Task 3.1 |

Re-measure after each phase and append a dated row of totals here:

| Date | Milestone | Lines | Functions | Regions |
|---|---|---|---|---|
| 2026-07-13 | Baseline (pre-Phase 1) | 9.91 % | 14.65 % | 10.81 % |

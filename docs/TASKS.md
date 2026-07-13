# Implementation Hints per Task

Companion to [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md). For each task: files to touch, approach,
and starter snippets. Snippets are sketches — adjust names/signatures to what compiles.

---

## Phase 0 — Groundwork

### Task 0.2 — Test taxonomy & fast-test target

**Files:** every `tests/*.rs` that spawns bitcoind; new `justfile` or `Makefile.toml` (optional).

Simplest mechanism — `#[ignore]` on heavy tests, no feature flags needed:

```rust
#[test]
#[ignore = "integration: requires bitcoind"]
fn test_full_union_flow() { ... }
```

Lanes (aliases defined in `.cargo/config.toml`):

```sh
cargo test --lib          # fast: unit tests only (in src/)
cargo test-fast           # --lib + --tests, skips #[ignore] — no bitcoind/docker needed
cargo test-integration    # --tests -- --ignored --test-threads=1 (serial: shared container/ports)
```

**Done:** ignore reasons added per file (bitcoind / bitcoind+BitVMX-CPU / bitcoind+gnova);
`prepare_bitcoin` calls `ensure_docker_available()` so accidental local runs fail fast with a
clear message instead of a timeout.

### Task 0.3 — Coverage baseline

No repo changes strictly needed:

```sh
cargo install cargo-llvm-cov
cargo llvm-cov --lib --html      # baseline: unit-test coverage only
```

Record per-module numbers in a `## Coverage` section at the bottom of IMPROVEMENT_PLAN.md.

### Task 0.4 — Test-utils infrastructure decision

**Files:** `Cargo.toml`, `src/lib.rs`, new empty modules.

```toml
# Cargo.toml
[features]
default = ["cardinal", "union"]
test-utils = []       # exposes in-memory adapters to integration tests & downstream crates
```

```rust
// src/lib.rs
pub mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_adapters;
```

Layout: `src/ports/mod.rs` (traits only), `src/test_adapters/mod.rs` (fakes). Production adapters are
just `impl Port for ConcreteType` blocks living next to the trait or in the module that owns the type.

---

## Phase 1 — Ports

### Task 1.1 — `KeyValueStorePort`

**Files:** new `src/ports/store.rs`; then `src/program/variables.rs` (`Globals`, `WitnessVars`),
`src/message_queue.rs`, `src/leader_broadcast.rs`, `src/program/program.rs`, `src/bitvmx.rs`.

**⚠ Key obstacle:** `storage_backend::KeyValueStore::get<T>/set<T>` are *generic* methods → not
object-safe → cannot be `Rc<dyn ...>` directly. Solution: object-safe trait over `serde_json::Value`,
plus an extension trait with the generic sugar (blanket impl):

```rust
// src/ports/store.rs
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub type TxId = usize; // match storage_backend's transaction id type

pub trait KeyValueStorePort {
    fn get_value(&self, key: &str) -> Result<Option<Value>, StoreError>;
    fn set_value(&self, key: &str, value: Value, tx: Option<TxId>) -> Result<(), StoreError>;
    fn has_key(&self, key: &str) -> Result<bool, StoreError>;
    fn partial_compare_keys(&self, prefix: &str) -> Result<Vec<String>, StoreError>;
    fn begin_transaction(&self) -> TxId;
    fn commit_transaction(&self, tx: TxId) -> Result<(), StoreError>;
    fn begin_global_transaction(&self) -> Result<(), StoreError>;
    fn commit_global_transaction(&self) -> Result<(), StoreError>;
}

/// Generic sugar — this is what call sites keep using, so churn stays minimal.
pub trait KvExt: KeyValueStorePort {
    fn get_t<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        Ok(self.get_value(key)?.map(serde_json::from_value).transpose()?)
    }
    fn set_t<T: Serialize>(&self, key: &str, v: &T, tx: Option<TxId>) -> Result<(), StoreError> {
        self.set_value(key, serde_json::to_value(v)?, tx)
    }
}
impl<S: KeyValueStorePort + ?Sized> KvExt for S {}
```

Production adapter — route through `Storage`'s own generic methods with `T = Value` so the on-disk
serialization format is **unchanged** (verify: `storage_backend` serializes via serde_json; if it
uses a different codec, adapt here, never in callers):

```rust
impl KeyValueStorePort for Storage {
    fn get_value(&self, key: &str) -> Result<Option<Value>, StoreError> {
        Ok(KeyValueStore::get::<Value>(self, key, None)?)
    }
    // ...
}
```

Field changes (example `Globals`, src/program/variables.rs:137):

```rust
pub struct Globals {
    storage: Rc<dyn KeyValueStorePort>,   // was: Rc<Storage>
}
```

`Rc<Storage>` coerces to `Rc<dyn KeyValueStorePort>` automatically at construction sites
(`Globals::new(store.clone())` keeps working if `new` takes the trait object).

Test adapter:

```rust
// src/test_adapters/store.rs
#[derive(Default)]
pub struct InMemoryStore {
    data: RefCell<HashMap<String, Value>>,
    // transactions can be no-ops for unit tests, or a staged HashMap if you want rollback fidelity
}
impl KeyValueStorePort for InMemoryStore { /* HashMap ops */ }
```

**First tests:** `Globals` set/get round-trip for every `VariableTypes` variant; `WitnessVars` same.

### Task 1.2 — `L2ChannelPort`

**Files:** new `src/ports/l2_channel.rs`; `src/types.rs:39` (field), `src/bitvmx.rs` construction site
(bitvmx.rs:185).

Surface (from grep — only two methods used):

```rust
pub trait L2ChannelPort {
    fn send(&self, to: &Identifier, msg: String) -> Result<(), ChannelError>;
    fn recv(&self) -> Result<Option<(String, Identifier)>, ChannelError>;
}

impl L2ChannelPort for LocalChannel<BrokerStorage> { /* delegate */ }
```

```rust
// src/types.rs
pub struct ProgramContext {
    pub broker_channel: Box<dyn L2ChannelPort>,   // was: LocalChannel<BrokerStorage>
    ...
}
```

Test adapter — the workhorse assertion tool for Phases 2–3:

```rust
#[derive(Default, Clone)]
pub struct InMemoryChannel {
    pub sent: Rc<RefCell<Vec<(Identifier, String)>>>,
    pub inbound: Rc<RefCell<VecDeque<(String, Identifier)>>>,
}
impl InMemoryChannel {
    /// test helper: parse the nth sent message as an outgoing API message
    pub fn sent_msg(&self, n: usize) -> OutgoingBitVMXApiMessages {
        serde_json::from_str(&self.sent.borrow()[n].1).unwrap()
    }
}
```

**First tests:** `BitVMX::reply` paths — e.g. `Ping` → assert exactly one `Pong(uuid)` sent to `from`.

### Task 1.3 — `BitcoinCoordinatorPort`

**Files:** `src/types.rs:38` (field), `src/bitvmx.rs:152` (construction). Call sites need no edits if
the trait is in scope — they already call methods via the field, and several files already
`use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi`.

**Step 1 — probe object safety** (5 min): change the field and compile.

```rust
pub bitcoin_coordinator: Box<dyn BitcoinCoordinatorApi>,
```

If the compiler rejects (generic methods / `Self` returns), define a local
`src/ports/coordinator.rs` trait with the used subset and `impl` it for `BitcoinCoordinator`:
`dispatch`, `monitor`, `get_news`, `ack_news`, `get_transaction`, `add_funding`, `is_ready`, `tick`.

Test adapter:

```rust
pub struct FakeCoordinator {
    pub dispatched: RefCell<Vec<(Transaction, String /*context*/)>>,
    pub monitored: RefCell<Vec<TypesToMonitor>>,
    pub acked: RefCell<Vec<AckNews>>,
    pub news_queue: RefCell<VecDeque<News>>,   // tests push canned news here
    pub tx_by_id: RefCell<HashMap<Txid, TransactionStatus>>,
    pub ready: Cell<bool>,
}
```

**First tests:** `Program::start_monitoring` (assert one `TypesToMonitor::Transactions` +
one `SpendingUTXOTransaction` per vout); `process_bitcoin_updates` — push each `CoordinatorNews`
variant, assert the matching `AckNews` and L2 message (uses `InMemoryChannel` from 1.2).

### Task 1.4 — `CommsPort`

**Files:** new `src/ports/comms.rs`; `src/types.rs:37`; call sites in `src/bitvmx.rs`,
`src/signature_verifier.rs`, `src/leader_broadcast.rs`, `src/comms_helper.rs`, setup steps
(grep `\.comms\.` — ~10 files).

Surface: `send`, `check_receive`, `check_deadletter`, `tick`, `get_address`, `get_pubk_hash`, `close`.

```rust
pub trait CommsPort {
    fn send(&self, to: &Identifier, msg: Vec<u8>, ctx: &str) -> Result<(), CommsError>; // match QueueChannel sig
    fn check_receive(&self) -> Result<Vec<ReceiveHandlerChannel>, CommsError>;
    fn check_deadletter(&self) -> Result<Vec<(ReceiveHandlerChannel, String)>, CommsError>;
    fn tick(&self) -> Result<(), CommsError>;
    fn get_address(&self) -> SocketAddr;
    fn get_pubk_hash(&self) -> Result<PubkHash, CommsError>;
    fn close(&self);
}
```

Test adapter + hub for multi-operator simulation (the piece that makes Task 3.2 possible):

```rust
pub struct CommsHub {                       // shared post office
    mailboxes: Rc<RefCell<HashMap<PubkHash, VecDeque<(Identifier, Vec<u8>)>>>>,
}
impl CommsHub {
    pub fn endpoint(&self, pubkey_hash: PubkHash, addr: SocketAddr) -> InMemoryComms { ... }
}
pub struct InMemoryComms { me: PubkHash, addr: SocketAddr, hub: /* Rc to hub state */ }
impl CommsPort for InMemoryComms {
    fn send(&self, to, msg, _ctx) { /* push into to's mailbox */ }
    fn check_receive(&self) { /* drain own mailbox */ }
}
```

### Task 1.5 — `ClockPort`

**Files:** new `src/ports/clock.rs`; `src/timestamp_verifier.rs`, `src/throttle.rs`.

```rust
pub trait ClockPort {
    fn now(&self) -> Instant;          // Throttle
    fn now_unix_ms(&self) -> i64;      // TimestampVerifier
}
pub struct SystemClock;
pub struct FakeClock { instant: Cell<Instant>, unix_ms: Cell<i64> }
impl FakeClock { pub fn advance(&self, d: Duration) { ... } }
```

Add the clock as a constructor param with a `SystemClock` default (`new()` keeps its signature,
add `new_with_clock()` for tests) — zero churn at call sites.

### Task 1.6 — `WalletPort`

**Files:** new `src/ports/wallet.rs`; `src/bitvmx.rs:82` (field), construction at bitvmx.rs:143.
Only `bitvmx.rs` touches the wallet — smallest blast radius of all ports.

```rust
pub trait WalletPort {
    fn is_ready(&self) -> bool;                        // note: field today, becomes method
    fn receive_address(&mut self) -> Result<Address, WalletError>;
    fn balance(&self) -> Balance;
    fn create_tx(&mut self, dest: Destination, fee: Option<u64>) -> Result<Transaction, WalletError>;
    fn update_with_tx(&mut self, tx: &Transaction) -> Result<(), WalletError>;
    fn get_wallet_tx(&self, txid: Txid) -> Result<Option<WalletTx>, WalletError>;
    fn cancel_tx(&mut self, tx: &Transaction) -> Result<(), WalletError>;
    fn tick(&mut self) -> Result<(), WalletError>;
    fn sync_wallet(&mut self) -> Result<(), WalletError>;
}
```

Watch out: `wallet.is_ready` is a public **field** today (bitvmx.rs:1480, 1499) — the trait makes it
a method; fix those two call sites.

**First tests:** `SendFunds` with `FakeWallet::create_tx` returning Err → assert `WalletError` reply
and **no** dispatch on the `FakeCoordinator`.

### Task 1.7 — `KeyServicePort`

**Files:** new `src/ports/keys.rs`; `src/types.rs:35`; call sites across `src/bitvmx.rs`,
`src/program/protocols/protocol_handler.rs:160` (`sign` takes `&Rc<KeyManager>` — change to the port),
setup steps (`keys_step.rs`, `nonces_step.rs`, `signatures_step.rs`), `src/signature_verifier.rs`.

Build the trait from grep, not from KeyManager's full API. Known subset:
`sign_ecdsa_recoverable_message`, `next_keypair`, `next_keypair_adjusted`, `get_my_public_key`,
`get_key_pair_for_too_insecure`, `encrypt_rsa_message`, `decrypt_rsa_message`,
`import_rsa_private_key`, plus musig2 aggregation + winternitz/lamport methods used by setup steps
and `Protocol::sign` (protocol-builder calls into KeyManager — check whether `Protocol::sign` needs
the concrete type; if so, the port must expose `as_key_manager(&self) -> &KeyManager` as an escape
hatch initially, removed later).

Fold `ProgramContext::rsa_public_key` into this port at the same time (Task 4.3):

```rust
pub trait KeyServicePort {
    fn rsa_public_key(&self) -> &str;
    // ... subset above
}
```

**Testing note:** do NOT write a fake for crypto. Tests use a real `KeyManager` over
`tempfile::tempdir()` — see the construction recipe in `tests/common/` and `bitvmx.rs:126`.

### Task 1.8 — `TestContextBuilder`

**Files:** new `src/test_adapters/context.rs`.

```rust
pub struct TestContextBuilder { n_participants: usize, leader: usize }

pub struct TestHarness {
    pub contexts: Vec<ProgramContext>,      // one per participant, comms wired via CommsHub
    pub coordinators: Vec<Rc<FakeCoordinator>>,
    pub l2: Vec<InMemoryChannel>,
    pub addresses: Vec<CommsAddress>,
    _tmp: tempfile::TempDir,                // keeps KeyManager dirs alive
}

impl TestContextBuilder {
    pub fn build(self) -> TestHarness {
        let hub = CommsHub::default();
        // per participant: temp KeyManager, InMemoryStore, hub.endpoint(...), FakeCoordinator,
        // InMemoryChannel, Globals/WitnessVars over the in-memory store
    }
}
```

Add `tempfile` to `[dev-dependencies]`.

**Proof of concept:** port the aggregated-key happy path from `tests/aggregated_key.rs` to a unit
test: create `Program::new(...)` per participant with `PROGRAM_TYPE_AGGREGATED_KEY`, loop
`program.tick()` + pump `CommsHub` until all reach `Ready`, assert `final_aggregated_key` equal in
every participant's globals.

---

## Phase 2 — Decompose `BitVMX`

General technique for all extractions: **cut-paste methods into a new struct whose fields are ports;
`BitVMX` keeps a field of the new service and delegates.** No logic edits in the moving PR.

### Task 2.1 — `ZkpService`

**Files:** new `src/services/zkp.rs` (+ `src/services/mod.rs`); remove from `src/bitvmx.rs`:
`StoreKey::ZKP*` variants (bitvmx.rs:95-99), `handle_prover_message` (bitvmx.rs:754),
`generate_zkp`, `proof_ready`, `get_zkp_execution_result` (bitvmx.rs:1203-1286).

```rust
pub struct ZkpService {
    store: Rc<dyn KeyValueStorePort>,
    prover: Identifier,               // config.components.prover
}
impl ZkpService {
    pub fn generate(&self, from: Identifier, id: Uuid, input: Vec<u8>, elf: String,
                    l2: &dyn L2ChannelPort) -> Result<(), BitVMXError> { ... }
    pub fn handle_prover_result(&self, msg: &str, l2: &dyn L2ChannelPort) -> ... { ... }
    pub fn proof_status(&self, id: Uuid) -> Result<ProofStatus, BitVMXError> { ... }
}
```

**Tests:** feed `handle_prover_result` a canned prover JSON (copy shape from an integration-test log);
assert store contents + `ProofReady` sent. Then the malformed branches: missing `data`, missing
`status`, missing `journal`/`seal`, missing stored `from`.

### Task 2.2 — `ApiHandler`

**Files:** new `src/services/api_handler.rs`; `src/bitvmx.rs:1411` (`handle_api_message`).

The match arms use nearly every `BitVMX` field, so pass a deps struct to avoid borrow tangles:

```rust
pub struct ApiDeps<'a> {
    pub ctx: &'a mut ProgramContext,
    pub wallet: &'a mut dyn WalletPort,
    pub store: &'a Rc<dyn KeyValueStorePort>,
    pub zkp: &'a ZkpService,
    pub registry: &'a ProgramRegistry,
    pub config: &'a Config,
}

pub fn handle_api_message(msg: String, from: Identifier, deps: &mut ApiDeps)
    -> Result<(), BitVMXError>
```

Split each arm into a named function (`fn handle_send_funds(...)`) — table-driven tests then call the
functions directly. Keep this PR pure code motion; the per-arm split can be a follow-up.

### Task 2.3 — `NewsProcessor`

**Files:** new `src/services/news.rs`; from `src/bitvmx.rs`: `handle_news` (bitvmx.rs:546),
`process_bitcoin_updates` news loops (bitvmx.rs:586-752), `send_new_block_news` (bitvmx.rs:1081).

**Tests (invariant worth locking):** for every `MonitorNews`/`CoordinatorNews` variant pushed into
`FakeCoordinator.news_queue`, exactly one matching `AckNews` lands in `FakeCoordinator.acked`.
Plus: `OutputPatternTransaction` with `RSK_PEGIN_TAG` emits **two** L2 messages (legacy
`PeginTransactionFound` + `OutputPatternTransactionFound`); any other tag emits one.

### Task 2.4 — `ProgramRegistry`

**Files:** new `src/program/registry.rs`; from `src/bitvmx.rs`: `get_programs`, `add_new_program`,
`program_exists`, `load_program`, `StoreKey::Programs`; plus `is_active_program` from
`src/program/program.rs:615`.

```rust
pub struct ProgramRegistry { store: Rc<dyn KeyValueStorePort> }
impl ProgramRegistry {
    pub fn add(&self, id: &Uuid) -> Result<(), BitVMXError>;      // errs on duplicate
    pub fn load(&self, id: &Uuid) -> Result<Program, BitVMXError>;
    pub fn all(&self) -> Result<Vec<ProgramStatus>, BitVMXError>;
    pub fn is_active(&self, id: &Uuid) -> Result<bool, BitVMXError>;
}
```

### Task 2.5 — `MessageRouter`

**Files:** new `src/services/router.rs`; `src/bitvmx.rs:860` (`process_api_messages` routing match).

```rust
pub enum Route { Garbler, Emulator, Prover, Api }
pub fn classify(from: &Identifier, components: &ComponentsConfig) -> Route { ... }
```

Trivial, but makes the `from`-matching testable (it silently falls through to `Api` today — test
that this is intended for unknown senders).

---

## Phase 3 — Protocol Layer

### Task 3.1 — Pure graph construction (pattern, per protocol)

**Start with:** `src/program/protocols/aggregated_key.rs` (smallest), then replicate to
`union/dispute_core.rs`, `union/accept_pegin.rs`, `dispute/mod.rs`, …

Pattern — split `build()` into "gather" (I/O) and "construct" (pure):

```rust
// before: build() reads context.globals mid-construction
// after:
pub struct DisputeCoreParams { /* every value build() reads from globals, typed */ }

impl DisputeCoreParams {
    pub fn from_globals(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> { ... }
}

/// Pure: no ProgramContext, no storage. Deterministic given inputs.
pub fn build_graph(params: &DisputeCoreParams, keys: &[ParticipantKeys],
                   aggregated: &HashMap<String, PublicKey>) -> Result<Protocol, BitVMXError> { ... }

// ProtocolHandler::build() becomes: gather params → call build_graph → save_protocol
```

**Golden tests** — add `insta` to dev-dependencies:

```rust
#[test]
fn dispute_core_graph_is_stable() {
    let (params, keys, agg) = fixed_test_inputs();   // hardcoded keys, deterministic
    let protocol = build_graph(&params, &keys, &agg).unwrap();
    insta::assert_snapshot!(protocol.visualize(GraphOptions::EdgeArrows).unwrap());
    // optionally also snapshot tx names + txids
}
```

Fixed keys: generate once with a seeded KeyManager, paste the hex constants into the test fixture.

### Task 3.2 — Setup-engine tests with simulated participants

**Files:** new `tests/setup_engine_unit.rs` (or `src/program/setup/tests.rs`); uses `TestContextBuilder`.

Driver skeleton:

```rust
fn run_until_ready(harness: &mut TestHarness, id: &Uuid, max_ticks: usize) {
    for _ in 0..max_ticks {
        for i in 0..harness.contexts.len() {
            let mut p = Program::load(harness.store(i), id).unwrap();
            p.tick(&mut harness.contexts[i]).unwrap();
            harness.pump_comms(i);      // drain InMemoryComms -> process_comms_message
        }
        if harness.all_ready(id) { return; }
    }
    panic!("setup did not converge");
}
```

Scenarios: happy path; deliver one participant's message **before** its program exists (exercises
`message_queue.push_back` buffering, bitvmx.rs:473); duplicate delivery; leader vs non-leader.

### Task 3.3 — `Program` state-machine tests

**Files:** `src/program/program.rs` (add `#[cfg(test)] mod tests`).

Targets: `save()`/`load()` round-trip over `InMemoryStore` (incl. `setup_engine_state` restore,
program.rs:194); `tick()` transitions; `receive_dispatcher_result` with each `Context` variant —
especially the error arms (`Context::RequestId` → Garbler = InvalidMessage, program.rs:409).

### Task 3.4 — Split oversized modules

**`union/dispute_core.rs` (3.4k lines)** → after its 3.1 snapshot exists, split into:
`dispute_core/mod.rs` (handler impl), `dispute_core/graph.rs` (pure build), `dispute_core/params.rs`,
`dispute_core/news.rs` (notify_news logic). Snapshot test must not change.

**`protocol_handler.rs` (1k lines)** → move the fat default methods (winternitz/lamport signing
helpers, monitor helpers) into free functions in `protocols/handler_helpers.rs`; trait defaults
become one-line delegations. Free functions get direct unit tests.

---

## Phase 4 — Hardening

### Task 4.1 — Error hygiene

**Files:** `src/errors.rs`, then grep `InvalidMessageFormat` (~15 sites in bitvmx.rs alone).

```rust
#[error("invalid message: missing field `{field}` in {message_kind}")]
MalformedMessage { message_kind: &'static str, field: &'static str },
#[error("leader index {leader} out of bounds for {participants} participants")]
InvalidLeaderIndex { leader: u16, participants: usize },
```

Mechanical; do after Phase 2 so the new unit tests catch mapping mistakes.

### Task 4.2 — News-handling TODOs

**Files:** `src/services/news.rs` (post-2.3). Empty branches at bitvmx.rs:730-743
(`TransactionAlreadyInMempool`, `MempoolRejection`, `NetworkError`) + deadletter TODO
(bitvmx.rs:535). Write the failing test first (push the news variant, assert desired L2
message/retry), then implement. Needs product input on desired policy — capture decisions in the
protocol docs.

### Task 4.3 — `rsa_public_key` placement

Folded into Task 1.7 (`KeyServicePort::rsa_public_key()`). Delete the field from `ProgramContext`
and fix `signature_verifier.rs` call sites.

### Task 4.4 — CI gate

**Files:** `.github/workflows/ci.yml` (or existing workflow).

```yaml
- run: cargo fmt --check
- run: cargo clippy --all-targets -- -D warnings   # or a curated -A list initially
- run: cargo test --lib --tests                    # fast lane; #[ignore] keeps bitcoind out
```

Integration lane: separate job, nightly schedule or `integration` PR label, installs/starts bitcoind.

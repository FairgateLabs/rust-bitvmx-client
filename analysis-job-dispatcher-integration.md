# Async Setup Step: Design Decisions

Feature branch: `feature/protocol-setup-async-step`
Status: on standby until the real garbled-dispatcher is ready.

---

## 1. Problem

Existing setup steps (Keys, Nonces, Signatures) are synchronous: `generate_data()` produces data and returns immediately. For garbled circuits we need:

1. **Async generation**: send a job to an external dispatcher and wait for the result
2. **Async verification**: after receiving data from all participants, send a verification job to the same dispatcher

## 2. Decision: generic step, not specific

Instead of creating a garbled-specific `GarbledStep`, we created a generic `AsyncDispatcherStep` that delegates concrete logic to an `AsyncStepHandler` trait. Any future dispatcher can implement this trait without touching the step or engine.

**Files:**
- `src/program/setup/steps/async_dispatcher_step.rs` — generic step + trait
- `src/program/setup/steps/garbled_handler.rs` — first implementation (mock)

## 3. Decision: enum_dispatch instead of Box<dyn>

The tech lead prefers avoiding `Box<dyn>` and `Send + Sync`. We use `enum_dispatch` (consistent with `SetupStepEnum`, `ProtocolType`):

```rust
// src/program/setup/steps/mod.rs
#[enum_dispatch(AsyncStepHandler)]
pub enum AsyncStepHandlerEnum {
    Garbled(GarbledHandler),
}
```

Handlers are registered in `ProgramContext.async_step_handlers: HashMap<String, AsyncStepHandlerEnum>` and looked up by step name.

## 4. Full state machine

```
Generating
  → (sync step produces data)  → WaitingForParticipants / AllParticipantsCompleted
  → (async step, no data yet)  → WaitingGeneration

WaitingGeneration
  → (dispatcher result arrives) → WaitingForParticipants

WaitingForParticipants
  → (all participants sent data) → AllParticipantsCompleted

AllParticipantsCompleted
  → (sync step)  → on_step_complete() → Completed → next step
  → (async step) → send_verification_job() → WaitingVerification

WaitingVerification
  → (verification OK)   → on_step_complete() → Completed → next step
  → (verification FAIL) → error, setup aborts
```

## 5. Decision: both leader and non-leaders verify independently

Both verify **independently** after having all data:

- **Leader**: receives data from all non-leaders → AllParticipantsCompleted → sends verify job → waits for result → completes step → broadcasts to non-leaders
- **Non-leader**: receives broadcast from leader with all data → AllParticipantsCompleted → sends verify job → waits for result → completes step

Each participant sends its own verify job to the dispatcher. No one trusts another's verification.

## 6. Decision: same dispatcher, different job type

Verification goes to the **same** garbled-dispatcher as generation. Distinguished by `GarbledJobType`:
- `Prove(inputs, circuit_type, output_dir)` — generation
- `Verify(Vec<GarbledStepData>)` — verification with all participants' data

Response routing from dispatcher to engine is based on the **engine's current state**, not the message type:
- If engine is in `WaitingGeneration` → `receive_async_result()`
- If engine is in `WaitingVerification` → `receive_async_verification_result()`

This is implemented in `Program::receive_dispatcher_result()` (renamed from `receive_async_generation_result()`).

## 7. Decision: SetupStepMessage wrapper for routing

When the leader broadcasts data to non-leaders, the message contains data from ALL participants. These are processed one at a time. If processing the first message advances the engine to the next step, the second message (from the previous step) gets misrouted.

**Solution**: wrap each broadcast in `SetupStepMessage { step_name, data }`. The receiver ignores messages whose `step_name` doesn't match the current step.

```rust
// src/program/setup/setup_engine.rs
#[derive(Serialize, Deserialize)]
struct SetupStepMessage {
    step_name: String,
    data: Vec<u8>,
}
```

## 8. Decision: GarbledHandler with mock internals, no feature flag

Instead of `MockGarbledHandler` behind `#[cfg(feature = "testutils")]`, we named it `GarbledHandler` directly with mock internals and TODOs. Reasons:
- `enum_dispatch` doesn't support empty enums (no mock = no variant)
- When the real dispatcher is ready, internals get replaced without renaming

## 9. AsyncStepHandler trait

```rust
#[enum_dispatch]
pub trait AsyncStepHandler {
    // --- Generation ---
    fn create_job(&self, protocol_id: &Uuid, protocol: &mut ProtocolType) -> Result<String, BitVMXError>;
    fn parse_result(&self, result: &[u8]) -> Result<String, BitVMXError>;
    fn validate_received(&self, data: &str) -> Result<(), BitVMXError>;
    fn dispatcher_id(&self, config: &ComponentsConfig) -> Option<Identifier>;

    // --- Verification ---
    fn create_verify_job(&self, protocol_id: &Uuid, all_data: &[String]) -> Result<String, BitVMXError>;
    fn parse_verify_result(&self, result: &[u8]) -> Result<(), BitVMXError>;
}
```

`create_verify_job` receives `all_data`: a slice with each participant's JSON data (in index order).

## 10. Broker architecture in tests

Each operator has its own broker on a different port (op_1: 22222, op_2: 33333). The mock garbled dispatcher needs a `DualChannel` **per broker** so both operators can reach it:

```rust
let (mock_garbled_channel_op1, garbled_identifier) = create_mock_garbled_channel(&config_op1)?;
let (mock_garbled_channel_op2, _) = create_mock_garbled_channel(&config_op2)?;
```

Both channels use the same identity (prover key + id 99) but connect to different brokers.

## 11. Borrow checker workaround in AsyncDispatcherStep

The handler is looked up from `context.async_step_handlers` (borrows `context`). Then `context.broker_channel` is needed to send. To avoid borrow conflicts:

```rust
let (msg, dispatcher_id) = {
    let handler = context.async_step_handlers.get(&self.name)...;
    let msg = handler.create_job(...)?;
    let id = handler.dispatcher_id(...)?;
    (msg, id)
}; // handler borrow dropped here
context.broker_channel.send(&dispatcher_id, msg)?;
```

This pattern repeats in `generate_data()`, `send_verification_job()`, and `receive_verification_result()`.

## 12. GarbledProtocol

Test protocol using `setup_steps() = [Keys, GarbledCircuits]`. Registered as `PROGRAM_TYPE_GARBLED = "garbled"`.

- `src/program/protocols/garbled.rs`
- Generates a key, adds it, and in `build()` stores the aggregated key
- Does not build Bitcoin transactions (only tests the async flow)

## 13. Globals storage convention

| Key | Contents |
|-----|----------|
| `my_{step_name}` | own generated data |
| `participant_{idx}_{step_name}` | data from participant idx |
| `all_{step_name}` | JSON array with all participants' data (post-verification) |

## 14. Integration test

```bash
cargo test --test garbled_test -- --ignored --nocapture
```

The test (`tests/garbled_test.rs`) verifies:
- 2 Prove jobs processed (generation, one per participant)
- 2 Verify jobs processed (verification, one per participant)
- Setup completed by both participants
- Garbled data consistent in both participants' globals
- Aggregated key identical across both participants

## 15. TODOs for real integration

When the `garbled-dispatcher` branch is merged:

1. **`garbled_handler.rs`**: replace local `GarbledJob`/`GarbledJobType` with `DispatcherJob<GarbledJobType>` from the `bitvmx-job-dispatcher-types` crate
2. **`garbled_handler.rs`**: implement `create_job()` with real inputs and circuit type from the protocol
3. **`garbled_handler.rs`**: implement `create_verify_job()` with real verification data
4. **`garbled_handler.rs`**: implement `parse_result()` and `parse_verify_result()` with real response types
5. **`Cargo.toml`**: add `bitvmx-job-dispatcher-types` dependency with `garbled` feature
6. **Config**: production YAMLs need `components.garbled` with the real dispatcher identifier
7. **Test**: replace in-process mock dispatcher with the real one (or keep mock for CI)

## 16. Files modified/created

| File | Action | Description |
|------|--------|-------------|
| `src/program/setup/steps/async_dispatcher_step.rs` | New | Generic async step + AsyncStepHandler trait |
| `src/program/setup/steps/garbled_handler.rs` | New | GarbledHandler with mock internals |
| `src/program/protocols/garbled.rs` | New | GarbledProtocol [Keys, GarbledCircuits] |
| `tests/garbled_test.rs` | New | End-to-end test with mock dispatcher |
| `src/program/setup/setup_engine.rs` | Modified | WaitingGeneration, WaitingVerification, SetupStepMessage, receive_async_result, receive_async_verification_result |
| `src/program/setup/setup_step.rs` | Modified | is_async, receive_generation_result, send_verification_job, receive_verification_result |
| `src/program/setup/steps/mod.rs` | Modified | AsyncStepHandlerEnum, GarbledCircuits variant, factory |
| `src/program/program.rs` | Modified | receive_dispatcher_result (routes by engine state) |
| `src/bitvmx.rs` | Modified | handle_garbled_message, register_async_step_handler |
| `src/config.rs` | Modified | ComponentsConfig.garbled |
| `src/ping_helper.rs` | Modified | JobDispatcherType::Garbled |
| `src/api.rs` | Modified | handle_garbled_message in trait |
| `src/types.rs` | Modified | async_step_handlers in ProgramContext, PROGRAM_TYPE_GARBLED |

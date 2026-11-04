# `src/bitvmx.rs` readability cleanup

Readability and code-quality suggestions for the BitVMX orchestrator. Every item is meant to
preserve behavior exactly. Apply each one as a separate commit and run `cargo test` after it.

Line numbers refer to `src/bitvmx.rs` at commit `dff87b5`, before the file split in item 1.

## High value

### 1. Split the file

Status: applied.

The file was 2554 lines, of which 1060 (41%) were tests.

- Replace the `#[path]` attributes with the standard layout: `src/bitvmx.rs` plus
  `src/bitvmx/{api,job_handler}.rs`.
- Move code out by topic:
  - `peer_messages.rs`: peer message handling and comms queues (288-717)
  - `news.rs`: Bitcoin coordinator and monitor news (719-1006, 1308-1316, 1464-1472)
  - `steps.rs`: step and transaction runners (1045-1200)
  - `timeouts.rs`: operation timeouts (1318-1406)
  - `tests.rs`: the former `transaction_tests` module (1475-2534)
- Move `Context` from below the tests (2536) to the top of `bitvmx.rs`.

### 2. Replace the message tuple with a struct

Status: applied.

The same six fields passed through `deserialize_msg`, `process_decoded_peer_message` and
`process_program_message`. The last had 9 parameters including `self`, over the clippy limit.

```rust
pub struct DecodedPeerMessage { version, msg_type, program_id, data, timestamp, signature }
```

`deserialize_msg` now returns this struct, which changes the signature of a public function.
`process_program_message` no longer takes a separate `program_id`. It only used
`peer_address.pubkey_hash`, so it takes that alone.

### 3. Add step helpers

Status: applied.

`run_step` wrapping `run_transaction` appeared 9 times, and
`measure_time("x", || run_step("x", ...)).unwrap_or(true)` repeated the name each time.

```rust
fn run_tx_step<T>(&mut self, name: &str, work: impl FnOnce(&mut Self) -> Result<T, BitVMXError>)
    -> Result<Option<T>, BitVMXError>;
fn timed_step(&mut self, name: &str, work: ...) -> Result<bool, BitVMXError>; // unwrap_or(true) inside
fn timed_tx_step(&mut self, name: &str, work: ...) -> Result<bool, BitVMXError>; // same, in a transaction
```

This also removed most `let store = self.store.clone()` lines. `tick_inner` shrank to a list of
phases:

- The application phase moved to `process_application_phase()`.
- The two `if process_application` blocks (1224, 1231) merged. Only an `Rc` clone sat between them.

Some call sites keep `measure_time` directly because they don't fit the helpers:

- `operation timeouts` and `comms messages` aren't wrapped in `run_step`.
- `bitcoin updates` returns `()`, not whether it did work.

### 4. Simplify `process_decoded_peer_message`

Status: applied.

No helpers were extracted: each would have one caller and only forward a call.

- 545-556: the match and `.expect()` reduced to
  `if let Some(reason) = setup_state.into_no_op_reason() { return ... }`.
- 532: uses the existing `ResultDisposition::fail_peer_reason`.
- The participant check became a `let ... else`.

### 5. Add `report_coordinator_news(context, kind)`

Status: applied.

`self.reporter.coordinator_news(..., &self.program_context.broker_channel)?` appeared 8 times in
`process_coordinator_news` (865-1006).

### 6. Flatten `apply_operation_timeout`

Lines 1333-1379 have four nesting levels and call `cancel(id)` 5 times. Extract
`apply_job_timeout` and `apply_program_job_timeout`.

### 7. Remove `SetupMessageState`

`classify_participant_message` could return `Option<NoOpReason>` directly, which removes the enum
and `into_no_op_reason`. `None` means the message continues to authentication.

- `Pending` and `NotForCurrentStep` lead to the same handling in both callers, so `None` loses no
  production behavior. The `setup_engine.rs` test that asserts `Pending` must assert `None` instead.
- `leader_broadcast.rs` hand-writes the same mapping, except that `UnauthorizedSender` falls
  through instead of being a no-op. Both callers reject non-participants first, so that arm can't
  run. Keep those earlier checks: they log and, for the leader, report a peer fault.
- The return type gets less precise, since `NoOpReason` has 9 variants and this returns 3.

## Medium value

- **Inbox duplication:** `process_comms_inbox` and `process_deadletters` differ by one call. Use
  `drain(Self::process_one_x)` with a shared `MAX_MESSAGES`.
- **Retry arm (418-451):** extract `defer_message`, and move the logic to
  `RetryReason::needs_verification_keys()` and `RetryReason::setup_failure(sender)`.
- **Catch-all `_ => unreachable!` (463):** list the remaining variants so a new one causes a
  compile error. Panic behavior stays the same.
- **L2 sends:** `process_monitor_news` serializes and sends 3 times. Add `notify_l2(&msg)`.
- **Failed attempts:** move the runtime-job arm of `settle_failed_attempt` (1099-1132) to its own
  function.
- **`tick`:** extract `log_error_chain(e)` and `report_tick_error(e) -> bool`.
- **Always-true returns:** `handle_news` and `process_broker_queues` can return `Result<()>`.
  `handle_news` also has no external callers, so make it private.

## Small cleanups

- Delete commented-out code (372-378).
- Merge nested ifs: `if program.my_idx == program.leader && msg_type.should_store()` (346-348).
- Drop needless clones: `&config.key_storage.clone()` (150), `store: store.clone()` (244).
- `process_bitcoin_updates_with_throttle`: remove the redundant early return (1313).
- `send_new_block_news`: remove the `context` parameter, and simplify to
  `.ok().flatten().and_then(|v| v.bool().ok()).unwrap_or(false)`.
- Name magic numbers: `expired(32)`, and the `- 1` header reserve in `process_msg` (475).
- Rename `count` to `tick_count`.
- Normalize imports, which mix flat and nested styles, with `bitcoin_coordinator` imported twice.

## Tests

- **Setup duplication:** `Program::new` is repeated about 10 times, although
  `create_single_participant_program` exists. `serialize_msg("1.0", ..., 0, vec![1])` is repeated
  9 times, so add a helper.
- **Module name:** `transaction_tests` also held peer and broadcast tests. Split them by topic.
- **Misleading names:** these only exercise `run_transaction` or raw storage, not news or broker
  code, so merge or rename them:
  - `news_handler_and_acknowledgement_commit_independently_per_item` (2242)
  - `broker_commit_survives_application_rollback` (2395)
  - `failed_second_broker_does_not_undo_first_broker` (2418)
  - `fatal_broker_error_also_rolls_back` (2515)
- **Weak assertion:** after its `process_msg` calls,
  `terminal_programs_discard_peer_messages_before_payload_processing` (1754) only checks that they
  return `Ok`. Fixing this adds a check rather than refactoring.

## Traps: tempting changes that alter behavior

- **`process_pending_messages` (625-634):** don't collapse `is_empty` and `pop_front`. `pop_front`
  returns `None` while messages wait on backoff, and that case currently returns `true`.
- **`Context` named fields:** don't convert the tuple variants. Serde output changes, and these
  strings are persisted job IDs. Use doc comments instead.
- **Two `Broadcasted` checks (525, 579):** don't merge them. Authorization must run before
  authentication, and payload handling after it.
- **Helper nesting order:** keep `run_transaction` inside `run_step`, because
  `settle_failed_attempt` needs the transaction closed.
- **Severity handling in `tick` and `finish_step`:** only the non-fatal arms can be shared.
  `finish_step` deliberately doesn't report fatal errors.
- **Reusing `reply()` for L2 sends:** it adds a debug log, so `notify_l2` should stay separate if
  logs must be identical.

## Possible bugs (separate from this cleanup)

These are behavior questions, so they are out of scope for a behavior-preserving refactor.

- **`process_operation_timeouts` isn't wrapped in `run_step` (1236):** a non-fatal error from
  `expired()` aborts the rest of the tick. Every other phase is isolated.
- **Backoff counts as work:** because of the `pop_front` case above, messages waiting on backoff
  count as `had_work`, which may keep the throttle from treating the node as idle.

# Support modules readability cleanup

Readability and code-quality suggestions for `expected_job.rs`, `leader_broadcast.rs`,
`message_queue.rs`, `operation_timeout.rs`, `signature_verifier.rs` and `error_handling.rs`. Every
item is meant to preserve behavior, and any exception is stated in the item. Apply each one as a
separate commit and run `cargo test` after it.

Line numbers refer to commit `a8a79de`. Items are proposed unless marked as applied.

## High value

### 1. Let `ExpectedJobs` own its `OperationTimeouts`

Status: applied. `ProgramContext.operation_timeouts` stays, for setup timeouts and the expiry loop.

`expected_job.rs`

Eight `ExpectedJobs` methods take `timeouts: &OperationTimeouts`, and 12 production call sites pass
`&program_context.operation_timeouts`. Both objects always wrap the same store (`bitvmx.rs:210-211`,
`test_utils.rs:525-526`, `api.rs:1542-1545`), and `OperationTimeouts` holds nothing but that
`Rc<Storage>`.

```rust
pub fn new(storage: Rc<Storage>) -> Self {
    Self { timeouts: OperationTimeouts::new(storage.clone()), storage }
}
```

- `send_dispatcher_job` drops from 8 parameters to 7, which is within the clippy limit.
- The test-only `register` no longer builds its own `OperationTimeouts` (144), and tests stop
  passing one.
- `complete_job`, `fail_job`, `discard_job` and `retry_job` (`job_handler.rs:91-119`) exist mostly to
  supply this argument. They would only shorten a path afterwards, so they can go.

Writes still join the same global transaction, because the store is the same object.

### 2. Reduce `authenticate_message` to 8 parameters

Status: applied.

`signature_verifier.rs`

It took 10 parameters. Both production callers (`peer_messages.rs`, `leader_broadcast.rs`) have a
`ProgramContext` and unpacked `globals`, `rsa_public_key` and the comms hash from it. Both also called
`program_id.to_string()` at the call site.

```rust
pub fn authenticate_message<BC: BitcoinCoordinatorApi>(
    program_context: &ProgramContext<BC>,
    program_id: &Uuid,
    version: &str,
    msg_type: CommsMessageType,
    data: &Value,
    timestamp: i64,
    signature: &[u8],
    sender_pubkey_hash: &PubkHash,
) -> Result<ResultDisposition, BitVMXError>;
```

- `msg_type` is `Copy`, so it no longer needs a reference.
- The parameter list in the doc comment stays, with `program_context` replacing the removed entries.
- A local `rejected()` closure replaces the 3 identical `fail_peer_reason(..., AuthenticationRejected)`
  calls. The log lines stay separate.
- Tests that passed `"self"` as both sender and own hash now use the real comms hash.
- A struct for the signed fields would reach 4 parameters, but was rejected to avoid a new type. The
  function stays one over the clippy limit of 7.

### 3. Remove `SuccessDetail` by building messages in the queueing pass

Status: applied.

`leader_broadcast.rs:process_broadcasted_message, evaluate_original_message`, `types/mod.rs:53-68`

`evaluate_original_message` returns a built message inside `SuccessDetail::QueuedMessage`. That variant
exists only for this path, and it is the reason for the hand-written `PartialEq` on `SuccessDetail` and
part of the `unreachable!` arm at `peer_messages.rs:166`. The caller also has two `unreachable!` arms.

Keep `ResultDisposition` as the return type, without adding an outcome type. A verified original returns
`Success`, and the queueing pass builds the message from the original it already has:

```rust
for (original_msg, outcome) in broadcasted_msg.original_messages.iter().zip(outcomes) {
    match outcome {
        ResultDisposition::Success => {
            let full_message = serialize_msg(/* moved from evaluate_original_message */)?;
            message_queue.push_new_unique(
                Identifier::new(original_msg.sender_pubkey_hash.clone(), COMMS_ID),
                full_message,
            )?;
            queued_count += 1;
        }
        ResultDisposition::Retry(reason) => {
            info!("Deferring leader envelope: {:?}", reason);
            retries.push(reason);
        }
        ResultDisposition::NoOp(reason) => {
            debug!("Discarding redundant embedded original: {:?}", reason);
            no_op_count += 1;
        }
        ResultDisposition::Fail(_) => unreachable!("handled before queueing"),
    }
}
```

- Without `QueuedMessage`, `SuccessDetail` only had `Processed` left and carried no data, so the whole
  type is removed and the variant is plain `ResultDisposition::Success`.
- `evaluate_original_message` ends by returning the `authenticate_message` result directly.
- `push_new_unique` already builds a `QueuedMessage`, so the queueing pass doesn't build one first.
- Keeping the whole `RetryReason` removes the `_ => unreachable!` arm, leaving one panic in this `match`.

Keep the two passes and the "first fault wins" order. See Traps.

This item changes behavior in three small ways:

- **Failure order:** building the message moves after the fault check. `QueuedMessage::new` fails if
  reading the clock fails. `serialize_msg` can only fail on the version or type bytes, which
  `construct_message` has already checked, or on JSON encoding. An envelope with both a fault and one of
  these failures now returns the fault instead of `Err`.
- **Partial queueing:** a build failure can happen after earlier originals were queued.
  `push_new_unique` could already fail at that point. Both production paths run inside
  `run_transaction` (`process_pending_messages` through `timed_tx_step`, `process_one_comms_message`
  through `process_inputs`), which rolls back on `Err`.
- **Logs:** the deferral log prints the retry reason instead of only the peer.

### 4. Remove the forwarders in `signature_verifier.rs`

Status: applied.

- `handle_verification_key_request` (340) calls `respond_with_verification_key` (132), which calls
  `send_verification_key_to_peer`. Each layer has one caller and only forwards. Call
  `send_verification_key_to_peer` directly from the match arm at 267.
- `SignatureVerifier::has_all_keys` (354) only forwards to `OperatorVerificationStore::has_all_keys`.
  `peer_messages.rs:76` can call the store, and the test at 522 moves with it.

### 5. Delete `MessageQueue::push_back`

Status: applied.

`message_queue.rs:145-161`

Production code never calls it. Its only callers are `tests/message_queue_test.rs:106` and one unit
test, and no sibling repo uses `MessageQueue`. Its body duplicates `push_deferred` (184-199) apart
from the last line, so deleting it also removes the need for a shared helper.

- Move both tests to `push_deferred`. Their messages are unique, so deduplication doesn't change the
  result.
- `push_new` is also unused in production, but `benches/message_queue.rs` depends on it. Replacing it
  with `push_new_unique` would change what the benchmark measures, because that path scans the queue.
  Keep it unless the benchmark is meant to follow the production path.

### 6. Share the repeated storage steps

Status: applied.

`expected_job.rs`, `operation_timeout.rs`

- **ID list:** the same `get(IDS_KEY).unwrap_or_default()` appears at `expected_job.rs:186-189, 296-299`
  and `operation_timeout.rs:67-70, 118-121, 143-146`. Add a private `load_ids()` to each type.
- **Registered job lookup:** `expected_job.rs:250-255` and `366-371` are the same lookup and error. Add
  `get_registered(job_id)`. `steps.rs:148-156` builds the same message by hand and can use it too.
- **Duration conversion:** `u64::try_from(d.as_millis()).unwrap_or(u64::MAX)` appears at
  `expected_job.rs:162` and `operation_timeout.rs:50`. Add one `pub(crate) fn duration_ms`.
- **`OperationTimeouts::register` (61-75):** flatten the nested `if`:

  ```rust
  let existing: Option<OperationTimeout> = self.storage.get(&key, None)?;
  if existing.is_some() && !renew {
      return Ok(());
  }
  if existing.is_none() {
      // append the id
  }
  ```

### 7. Flatten `classify`, and share the `Reporter` report

Status: applied.

`error_handling.rs:123-176, 43-118`

`classify` nests `if let` and `if` five times, and only `Fatal` or the outage result can come out. A
link in the chain has one concrete type, so the order of checks within a link doesn't matter.

```rust
for error in std::iter::successors(Some(error), |&error| error.source()) {
    let fatal = matches!(
        error.downcast_ref::<StorageError>(),
        Some(
            StorageError::WriteError
                | StorageError::ReadError(_)
                | StorageError::CommitError
                | StorageError::TransactionRollbackFailed
        )
    ) || error.downcast_ref::<BrokerError>().is_some_and(BrokerError::is_fatal)
        || error.downcast_ref::<IdentificationError>().is_some_and(|e| e.severity().is_fatal())
        || error.downcast_ref::<RetryPolicyError>().is_some_and(|e| e.severity().is_fatal())
        || matches!(
            error.downcast_ref::<BitVMXError>(),
            Some(BitVMXError::PoisonedLockError(_))
        );
    if fatal {
        return Severity::Fatal;
    }
    if matches!(
        error.downcast_ref::<BitcoinRpcError>(),
        Some(BitcoinRpcError::JsonRpc(jsonrpc::Error::Transport(_)))
    ) {
        return Severity::BitcoinNodeUnreachable;
    }
}
Severity::Other
```

Keep the comment explaining why the two broker types are checked directly.

`fatal`, `rpc_unavailable` and `non_fatal` repeat the same `send_error_report(...)` call with
`ErrorScope::Node` and `Some(error.to_string())`. Add `report_node_error(&self, kind, error,
broker_node)`.

## Medium value

- **Split `process_broadcasted_message` (applied, `leader_broadcast.rs:361-483`):** it runs 122 lines
  and has three phases. Evaluation moved to `evaluate_originals`, and the queueing pass to
  `queue_outcomes`. Each has one caller but holds real logic. The envelope check stays in the caller,
  because it returns a disposition rather than a list of outcomes.
- **Its parameters (applied, 361-369):** `self` is unused, so it can be an associated function.
  `leader_identifier: Identifier` only supplies `pubkey_hash`, so it can be `&PubkHash`, which also
  removes the `msg.identifier.clone()` at `peer_messages.rs:303`.
- **Redundant check (applied, 404):** `!original_msg.msg_type.should_store()` can't be true. Line 403 has just
  established that the type equals `original_msg_type`, which line 392 already checked. The
  `seen_senders.insert` that follows still runs in the same cases.
- **`fail_peer_reason` (applied, 377, 394, 407, 500, 522):** five `fail_peer(PeerSetupFault { .. })` calls can
  use the existing helper.
- **`retry_pending` backoff (applied, `expected_job.rs:257-268`):** replace
  `.as_ref().map(|_| ...).transpose()?` with a plain `if job.dispatch.is_some()`, and move the delay
  calculation to `retry_delay_ms(attempts)`.
- **`register_with_dispatch` (applied, 160-198):** it builds the whole `ExpectedJob` before the check that may
  discard it. Compare `dispatcher`, `target` and the timeout first, and build the job only for a new
  registration. `job.execution_timeout_ms.map(Duration::from_millis)` (195) can become
  `Some(timeout)`. Past `u64::MAX` ms both forms saturate to the same deadline.
- **`redispatch_due` target check (applied, `expected_job.rs:322-328`):** the check runs after `send_service`
  and relies on rollback to undo the outbox write. Move it between the `warn!` and the send. The result
  and the logs stay the same, because `run_transaction` (`steps.rs:199`) already rolls back on this
  error.
- **`request_missing_verification_keys` (applied, `signature_verifier.rs:92-129`):** it builds a hash list,
  computes the missing ones, builds a set, and loops over the peers again, with two early returns that
  the loop would handle anyway. A single loop over non-self peers with `Self::has` is enough. The only
  change is on a storage read error, where earlier requests may already be in the outbox. Both callers
  run in a transaction that rolls those back.
- **`handle_verification_key_announcement` (applied, 283):** borrow `&peer_address.pubkey_hash` instead of
  cloning it and then comparing against the original at 315.
- **`get_original_messages` (applied, `leader_broadcast.rs:231-243`):** replace the manual loop with
  `.into_iter().map(...).collect()`. Keep the `InvalidMessage` mapping, which rules out
  `partial_get` because it would return `ConversionError`.

## Small cleanups (applied)

`message_queue.rs`:

- Drop `.map_err(BitVMXError::StorageError)` (7 sites). `?` converts through the same `#[from]`.
- Remove `message_queue_key` (66-75). Its callers always pass two parts, and `StorageKey::new` already
  takes an array: `StorageKey::new(["bitvmx", "message_queue", "msg", &id.to_string()])`. The joined
  key is unchanged.
- Inline `remove_entry` (139), which has one caller and only forwards.
- 207-210: `.map(...).unwrap_or(true)` becomes `.is_none_or(...)`, already used in `expected_job.rs:308`.
- `is_empty` (281) can be one expression.

`leader_broadcast.rs`:

- Delete comments that restate the next line (60, 93, 101, 109, 300, 342).
- `validate` messages (95-122) print values already known to be empty, such as
  `Version is empty: ""`. Shorten them. This only changes error text.

`signature_verifier.rs`:

- Move "This module provides..." (22-25) from the struct to a `//!` module comment.
- `OperatorVerificationStore::get` (50-56): use `.map(|value| value.string()).transpose()`.

`error_handling.rs`:

- `resolve_scope` (185) is only used in this file, so make it private.
- The `non_fatal` doc comment (107) says the node is stopping. It isn't: `report_tick_error` returns
  `false` for this case, and `finish_step` carries on.

`operation_timeout.rs`:

- `#[derive(Clone)]` on `OperationTimeouts` (33) has no `.clone()` caller. Remove it if that compiles.

## Tests

- **Weak assertion in `cancellation_is_idempotent` (applied, `operation_timeout.rs:185`):** it registers with
  the default 1-hour deadline and then asserts `expired(10)` is empty, which holds even if `cancel`
  does nothing. Assert `timeouts.get(&id)` is `None`, or register with `Duration::ZERO`.
- **Weak assertions in `leader_broadcast.rs` (applied):**
  - `process_broadcasted_message_queues_verified_original` (1069-1079) ignores the returned
    disposition. Assert `Success`.
  - Three tests (1194, 1226, 1249) only assert `Fail(_)`, so they pass with the wrong peer or reason.
    Assert the fault: the sender for a bad signature, the leader for a non-participant or malformed
    envelope.
- **Duplicate tests in `signature_verifier.rs` (applied):** `verify_message_signature_accepts_valid_payload`
  (376) and `verify_message_signature_detects_tampering` (426) repeat
  `authenticate_message_accepts_valid_and_rejects_tampered` (682). Remove the first two.
- **Stale names (applied):** the remaining `verify_message_signature_*` tests should be named
  `authenticate_message_*`. In `expected_job.rs:389`, "in_the_new_format" no longer contrasts with
  anything.
- **Serialization tests (applied, `leader_broadcast.rs:1254-1306`):** they only round-trip derived serde code
  and assert `!serialized.is_empty()`. Neither pins the wire format, and the
  `process_broadcasted_message_*` tests already go through serde. Remove them.
- **Setup duplication in `leader_broadcast.rs` (applied):**
  - 10 `OriginalMessage` literals can use `test_original_message` plus one changed field.
  - 5 copies of the `process_broadcasted_message` call can share one helper.
  - Line 869 reassigns the field that line 868 already set to empty.
- **Setup duplication elsewhere (applied, except the last point):**
  - `expected_jobs` (`expected_job.rs:384`) only forwards to `ExpectedJobs::new`.
  - `build_test_env` (`signature_verifier.rs:371`) only fixes a directory name.
  - A `sign_test_message` helper can replace the repeated construct-then-sign blocks. Not applied:
    after the duplicate tests were removed, only one such block remains.
- **Needless code in `signature_verifier.rs` tests (applied):** `msg_type.clone()` on a `Copy` type, and
  `&globals` or `&rsa_public_key` on values that are already references.
- **`tests/message_queue_test.rs` (applied, using `TestStorageDir`):** `test_message_queue_persistence` repeats
  `queue_persists_across_storage_reopen` (`message_queue.rs:574`), and both tests write under `/tmp`.
  Remove the first, and use `TestStorageDir` or `std::env::temp_dir()` for the other.
- **Flaky `test_queue_no_starvation` (applied, `tests/message_queue_test.rs:62`):** its loop got only
  `max_delay_ms * max_attempts` (150ms) of wall-clock time, and a normal run takes about 130ms. A slow
  run ended the loop with the poison message still queued, and the assert at 119 failed. It failed 1 of
  8 runs of the file both at `a8a79de` and with item 5 applied. The loop now ends when the queue drains,
  with a 30s deadline only as a guard against hanging.
- **Missing coverage (applied):** nothing asserted that `register_job(.., renew: true)` moves the
  deadline. `job_renewal_moves_the_deadline_without_duplicating_the_id` now does.

## Traps: tempting changes that alter behavior

- **`pop_front` rotation (`message_queue.rs:248-274`):** don't replace it with a search for the first
  ready ID. Not-ready IDs move to the back and that order is persisted, which is what prevents
  starvation.
- **Two passes in `process_broadcasted_message`:** don't queue during evaluation. A later bad original
  must prevent queueing the earlier good ones.
- **Early return on the first fault:** it looks equivalent but isn't. Evaluating the remaining originals
  can still return `Err` for a local failure, which takes priority over the fault, and it emits logs.
- **`BroadcastedMessage::validate` on receipt:** don't reuse it in `process_broadcasted_message`. It
  returns `Err` where the receiver needs a disposition, and it can't assign a fault to a peer.
- **`construct_message` before authentication (`leader_broadcast.rs:513`):** it looks redundant with
  `signature_verifier.rs:201` but gives a different fault. Here it's `MalformedMessage`, there
  `AuthenticationRejected`.
- **`get` versus `has_key`:** `store_original_message` (206) and `OperationTimeouts::cancel` (114) read
  the full value. `has_key` is cheaper but stops corrupt records from surfacing as errors, and
  `get_original_messages_surfaces_corrupt_stored_entry` relies on that behavior for the read path.
- **Persisted formats:**
  - `OperationTimeouts::key` hashes the JSON of `OperationTimeoutId`, so changing its serde shape
    orphans existing timeouts.
  - Don't merge `StoredMessage` into `QueuedMessage`, because retry state lives under a separate key.
  - Keep the `#[serde(default)]` fields on `ExpectedJob`, which older records need.
- **Records without a dispatch payload (`expected_job.rs:262-268`):** `retry_pending` must leave
  `retry_not_before_ms` as `None` for them, so `redispatch_due` skips them instead of hitting the error
  at 313.
- **`send_error_report` versus `try_send_error_report`:** `coordinator_news` propagates the failure so
  its transaction rolls back. The `Reporter` helper in item 7 is for the three best-effort reports only.
- **`Reporter` flags:** they are set before the send, so a failed report isn't retried. Keep that order.
- **`classify` walk order:** the outermost matching link decides. Keep walking from the outside in.
- **`handle_verification_messages` catch-all (274):** the caller filters on message type, but
  `handle_verification_messages_ignores_other_types` asserts this arm returns success.

## Possible bugs (separate from this cleanup)

These are behavior questions, so they are out of scope for a behavior-preserving refactor.

- **`redispatch_due` reads every job ever registered (fixed):** `EXPECTED_JOB_IDS_KEY` was never pruned
  because terminal records are kept on purpose, and `redispatch_due` loaded each record on every
  application tick (`bitvmx.rs:380`). The cost grew with the node's lifetime job count. Records now
  live under `bitvmx/expected_job/active/` while a result is expected and move to
  `bitvmx/expected_job/finished/` once terminal. `redispatch_due` scans only the active prefix, and
  the ID list is gone.
- **One bad job blocks all retries:** the errors at `expected_job.rs:313` and `324` abort the shared
  transaction, so every other due job in that pass rolls back too, on every tick. Normal flows can't
  reach either one (`retry_pending` guards the first and `steps.rs:157` the second), so this needs
  corrupt data.
- **Unused bootstrap exception in `authenticate_message` (175-180):** it returns success for unsigned
  verification messages, but no production path reaches it. `peer_messages.rs:266` skips authentication
  for those types, and `leader_broadcast.rs:392` rejects them earlier. Removing it would make the
  function fail closed if a future caller forgets the filter, but it changes what the function returns
  and `authenticate_message_allows_bootstrap_messages` asserts the current result.
- **`queued_count` includes duplicates (`leader_broadcast.rs:442-443`):** the `push_new_unique` outcome
  is ignored, so `AlreadyQueued` counts as queued and the result is `Success` instead of `NoOp`.
  `apply_message_disposition` settles both the same way, so only the logs are affected.

# Source readability cleanup (outside protocols)

Readability and code-quality suggestions for everything under `src/` except `src/program/protocols/`.
Every item in the cleanup sections is meant to preserve behavior, and any exception is stated in the
item. Apply each one as a separate commit and run `cargo test` after it.

`expected_job.rs`, `leader_broadcast.rs`, `message_queue.rs`, `operation_timeout.rs`,
`signature_verifier.rs` and `error_handling.rs` are covered by `SUPPORT_MODULES_CLEANUP.md`, and
`bitvmx.rs` with `bitvmx/` by `BITVMX_RS_CLEANUP.md`. This pass only adds what those two missed.

Three files are copied verbatim into `rust-bitvmx-client-types` on release: `program/participant.rs`,
`program/variables/shared.rs` and `types/shared.rs` (also `spv_proof.rs`). A change there has to be
mirrored in that crate.

Line numbers refer to commit `c9d7976`. Items are proposed unless marked as applied.

## High value

### 1. Keep `ProgramState` in step with the engine in one place

Status: applied.

`program/program.rs`

After the setup engine changes, three places derive `ProgramState` from the engine's step state with
the same `if WaitingForParticipants { WaitingData } else { SettingUp }`:

- `tick_inner` (441-448)
- `receive_dispatcher_result_inner` (740-746), which also clones `StepState` to compare it
- `receive_setup_data` (820-828)

Add `fn sync_state_with_engine(&mut self)`. `tick_inner` can then drop the block that returns a
`(bool, bool, SetupEngineState)` tuple (417-439), since it only clones the whole engine state to read
`current_step_state`.

### 2. `handle_setup_error` never returns `Ok`

Status: applied.

`program/program.rs:483-504`

All three arms return `Err`, so both callers carry dead code:

- `process_comms_message` (895-901) has `self.handle_setup_error(..)?; Ok(ResultDisposition::Success)`,
  and the `Ok` is unreachable.
- `tick` (399-404) matches on a result that is always `Err`.

Make it `fn setup_error(&self, error, peer) -> BitVMXError` and call it as
`Err(e) if .. => Err(self.setup_error(e, peer))`. The `_program_context` parameter is unused and goes
away too. `test_setup_rpc_outage_propagates_without_failing_setup` (1325) changes from `.unwrap_err()`
to a plain call.

### 3. Share `can_advance` across the setup steps

`program/setup/steps/{keys,nonces,signatures}_step.rs`

`KeysStep::can_advance` (250-274), `NoncesStep::can_advance` (225-249) and
`SignaturesStep::can_advance` (270-294) are the same loop over `has_participant_data` with a different
name in the log. Make it the default method on `SetupStep`, using `self.step_name()` in the log.
`GarblerStep` keeps its override.

### 4. Merge the nonce and signature step bodies

`program/setup/steps/nonces_step.rs`, `signatures_step.rs`

The two files differ mostly in the payload type and the key-manager call:

- `validate_received_nonce_entries` (nonces 42-81) and `validate_received_signatures` (signatures
  44-89) run the same four checks. The signature version also checks emptiness, while the nonce
  caller does that itself (180).
- `on_step_complete` builds the same `HashMap<aggregated, HashMap<participant key, entries>>` from
  every other participant (nonces 262-292, signatures 307-340), with the same duplicate error.
- `PubNonceMessage` and `PartialSignatureMessage` are the same tuple shape over different entry types.

Add `type ContributionMessage<T> = Vec<(PublicKey, PublicKey, Vec<(MessageId, T)>)>`, plus generic
`validate_entries<T>` and `collect_other_participants<T>` helpers in `steps/mod.rs`. Keep the step
specific parts: the signature verification loop (signatures 221-247), and the two key-manager calls.

### 5. Collapse `comms_helper::request` onto `prepare_message`

`comms_helper.rs:116-176`

`request` repeats the body of `prepare_message` (88-114) inline: it builds the canonical message, then
signs it. It then hands the original `msg: T` to `serialize_msg`, which serializes it a second time
even though `msg_value` already exists. Rewrite it as `prepare_message(to_value(msg))`, then
`serialize_msg(.., msg_value, ..)`, then `send_peer`.

- `response` (158-176) has one caller, `send_verification_key_to_peer`, and only forwards to `request`.
  Call `request` directly.
- Both signing paths copy the signature twice: `let signature = &...to_vec();` and then
  `signature.to_vec()` (104-112, 136-147).

The wire bytes don't change: the signature covers the sorted-key string of the same JSON value.

## Medium value

- **`SetupEngine::tick` change tracking (`setup_engine.rs:777-883`):** the before/after comparison of
  the engine state (860-867) already catches every change the explicit `state_changed = true` lines
  record. Generation always moves `current_step_state`, advancing moves the index or the completion
  flag, and `process_produced_data` marks this participant. Compare once at the end, after
  `process_produced_data`, and drop the flags.
- **Setup checks repeated in three layers:** membership and the step's message type are checked by
  `classify_participant_message` at the peer boundary, again by `receive_current_step_data`
  (`setup_engine.rs:413-423`), and again by `SetupStep::verify_received` (`setup_step.rs:110-131`).
  The second and third return different retry reasons for the same condition (`SetupNotReady` and
  `UnexpectedSetupMessageType`). The engine always runs its checks first, so the step's checks only
  ever see the node's own data from `tick`, where they cannot fail. Keep the step's checks only if
  direct callers of the trait are expected. In either case, pick one retry reason.
- **`receive_setup_data` (`setup_engine.rs:624-704`):** the doc lists "3. Tries to advance the
  current step", which it doesn't do. It resolves the sender twice, with
  `get_comms_address_by_pubkey_hash` (660) and then `get_index_by_pubkey_hash` inside
  `receive_current_step_data` (413). `participants_completed_before` (665) only feeds a log line.
- **Unreachable match arms after preflight (`program.rs:759-764, 774-779`; `setup_engine.rs:315-320`):**
  `dispatcher_result_preflight` only lets through Garbler with `SetupStep`/`ProgramStep` and Emulator
  with `ProgramStep`. The `_ =>` arms that build `InvalidMessage` errors can't run. Replace them with
  `unreachable!`, as `receive_dispatcher_failure` (690) already does.
- **`create_setup_engine` (`program.rs:262-269`):** it forwards to `SetupEngine::new` with a debug log,
  and its only production caller is `Program::new`. `Deserialize` (131-133) already calls
  `SetupEngine::new` directly. Inline it.
- **`GarblerStep::receive_dispatcher_result` (`garbler_step.rs:154-268`):** it matches `sub_step` to
  get the role, then runs `if sub_step == GENERATE {..}` and `if sub_step == VERIFY {..}` and finishes
  with `unreachable!`. A single `match` with two arms, and the role check before it, says the same.
- **Nested results in the garbler step (`garbler_step.rs:455-534, 650-707`):** `import_public_keys` and
  `import_public_lamport` return `Result<Result<T, PeerSetupFaultReason>, BitVMXError>`, while
  `import_public_input_signature` (393) returns `ResultDisposition`. Use one shape. The two
  `hex::decode` blocks for `h0` and `h1` (656-678) can share a closure.
- **The aggregated key lookup in `api.rs`:** `get_key_pair` (320-340) and the `!new` branch of
  `get_pub_key` (368-387) repeat "load `FINAL_AGGREGATED_KEY`, call `pubkey()`, or answer with
  `api_error`", and `get_aggregated_pubkey` (490-519) does the same lookup. Share one helper.
- **`setup_key` validation (`api.rs:235-283`):** it rejects an empty participant list and an
  out-of-range leader before `Program::new` does the same (`program.rs:287-292`), with different
  messages. `program_exists` runs in `setup_key` (246), again in `setup` (58), and a third time in
  `add_new_program` (38). Item 1 of the possible bugs below replaces that list anyway.
- **`comms_allow_list::mutate` (68-88):** it runs `change` on a staged copy and again on the live list.
  `*guard = stage;` after the reply applies the change once. Check first that `AllowList::clone`
  doesn't share state through an `Arc`. The three `lock().map_err(PoisonedLockError)` calls (57, 78,
  104) can share one helper.
- **`PingHelper` (`ping_helper.rs`):**
  - `new` (29-57) writes the 30/120 second defaults twice. `PingConfig` already derives `Default`.
  - `check_if_dispatchers_timed_out` (124-145) and `send_liveness_message_to_dispatchers` (166-195)
    collect the keys and then call `get_mut`, with an `else { continue }` that can't happen. Copy
    `ping_timeout` to a local and use `iter_mut`.
- **`CommsMessageType::to_bytes` (`comms_helper.rs:237-243`):** every variant is in `KIND_MAP`, so the
  `Result` can't be `Err`, and `MessageConstructionError::UnsupportedMessageType` is unreachable from
  `construct_message`. A `match` makes it infallible. Keep the byte values.
- **`ProgramContext::new` (`types/mod.rs:154-180`):** 11 positional parameters, with one production
  caller and one in `test_utils`. Every field is `pub` or `pub(crate)`, so both callers can use a
  struct literal.
- **`run_bitvmx` in `main.rs:86`:** the `tx: Option<Sender<()>>` parameter is always `None` (206), so
  the `CaughtUp` arm is dead in the binary. The function is private, so drop the parameter.
- **`Throttle` (`throttle.rs:31-78`):** the `initialized` flag exists only so `current_interval` can
  `unwrap` `init_interval`. Clearing the `Option` on the first busy call removes both.
  `ThrottleConfig::new` (16-22) has no caller.

## Small cleanups

`program/program.rs`:

- `ProgramState` has a hand-written `Default` (58-62). Use `#[derive(Default)]` with `#[default]`.
- `is_active` (65) is true only for `SettingUp`, and `process_programs` uses it to decide what to
  tick. `WaitingData` is a live setup that doesn't need ticks. A name such as `needs_tick` says that.
- `save` clones the `Rc` to read it (372-375). `as_ref()` is enough.
- The `start_monitoring` comment "Only register monitoring if not already done (idempotent)" (511)
  describes a guard that doesn't exist.
- `get_tx_by_id` (951-955) turns any error, storage included, into `InvalidMessage("Transaction not
  found")`.
- `msg_type.clone()` on a `Copy` type (930), and comments that restate the next line (289, 304-305,
  315).

`program/setup/`:

- `setup_step.rs:21-26`: the doc of a removed type ("Result of validating a contribution...") is stuck
  on top of `decode_contribution`'s doc.
- `SetupStep::verify_async` (`setup_step.rs:207`) has no production reader. Only a garbler test reads
  it (`garbler_step.rs:823`).
- The `"participant_{idx}_{step}"` key is built three times (`setup_step.rs:218, 229, 247`).
- `setup_engine.rs:835` logs `info!("Wasted")` for every tick in `WaitingForParticipants`.
- Log prefixes name the wrong function: `process_produced_data` logs as `tick()` (897-919) but is also
  called from `receive_dispatcher_result`. `send_broadcast_data_to_non_leaders` logs as
  `receive_setup_data()` (725-743). `try_advance_current_step` logs the same event twice (515-525).
- `msg_type.clone()` on a `Copy` type (`setup_engine.rs:344, 352`).
- `keys_step.rs`: the "Validate that keys were generated" comment (165) sits above a block that only
  logs. `collect_participant_keys` uses `.enumerate().map(|(idx, _)| ..)` where `0..len` reads
  better. `std::collections::HashMap` is spelled out twice (57, 67).
- `signatures_step.rs:135-155`: `is_err()`, then `as_ref().err().unwrap()`, then `unwrap()`. Use
  `match`.
- `garbler_step.rs`: `result.clone()` before `from_value` (175, 243), and `output_dir.clone()` (117,
  630), are both unneeded. `!&data.is_null()` (291). `(role == Prover && your_data) || (!your_data &&
  role == Verifier)` (282) is `(role == Prover) == your_data`. "Total deduped commitments" (501)
  dedupes nothing.

`program/participant.rs`, `program/variables/shared.rs`, `types/shared.rs` (mirrored files):

- `ParticipantKeyDeclaration::new` (176-202) repeats the uniqueness loops of the two deserializers
  (125-173).
- `ParticipantKeys::empty` (252) returns a `Result` that can't be `Err`.
- `wrong_key_type` (290-301) repeats the type names of the `EXPECTED` constants. A
  `PublicKeyType::type_name()` would serve both.
- `CommsAddress::from_str` (424) can use `split_once`.
- `VariableTypes` getters clone `Copy` values (`shared.rs:55, 121, 128`), and the block comment at
  14-19 is stale.
- `OutgoingBitVMXApiMessages::from_string` (338-341) duplicates `FromStr` (500-507). Nothing in this
  repo calls the 40-arm `name()` (444-497), and `ExecutionResult()` (301) is an empty, unused
  variant.

`errors.rs`:

- No code constructs or matches these non-`#[from]` variants: `DirectoryCreationError`,
  `InvalidSignature`, `MessageReconstructionError`, `VerificationKeyHashMismatch`,
  `VerificationKeyFingerprintMismatch`, `ProgramNotReady`, `ProtocolNotFound`,
  `JobDispatcherNotResponding`, `CommsCommunicationError`, `InvalidCommsAddress`,
  `MessageProcessingError`, `MissingBlockInfo`, `NoncesNotFound`, `PartialSignaturesNotFound`,
  `MissingPartialSignatures`, `MissingPublicNonces`, `ChallengeIdxNotFound` and `RomDataNotFound`.
  The whole `ParseError` enum, and `ProgramError::InvalidProgramStoragePath` and
  `FailedToBuildDisputeResolutionProtocol`, are unused too. `BitVMXError` is public, so check the
  sibling repos before deleting.
- Typos: "storagge" (137) and "configuation" (429). `InvalidParameter` says "in configuration" but
  `SetupEngine::new` uses it for step and participant counts.
- `map_err(|_| BitVMXError::SerializationError)` drops the cause (`comms_helper.rs:126, 351, 359`).
  `SerdeSerializationError` already converts with `?`.

Others:

- `spv_proof.rs` (mirrored): `next_power_of_two` (87-96) reimplements `usize::next_power_of_two`, and
  `to_swapped_bytes32` (78-85) is a copy plus `reverse()`. The `witness` parameter of
  `build_merkle_tree_store` is always `false` (53). `&Vec` parameters (170, 209) can be slices.
- `comms_helper.rs`: `deserialize_msg` prints the whole payload in its error (400), and clones `msg`
  (473) where `take()` would do.
- `client.rs`: `serialize_key` (326-328) returns its input, and the comment "BitVMX instance uses ID 1
  by convention" (236) is stale.
- `bitvmx.rs`: the comms key file is decrypted twice (177, 186). `pubkey_hash` (296) returns a
  `Result` that can't be `Err`. The `SetupStep` comment (63) calls the sub-step optional, but it is a
  `String`.
- `bitvmx/peer_messages.rs:320-329`: `process_pending_messages` calls `is_empty()` and then
  `pop_front()`, which already returns `None` on an empty queue.
- `witness.rs:19-37`: the `processed` counter loop is `for _ in 0..size`.
- Info-level logs print whole values: the ZKP input (`api.rs:542`), the transaction
  (`api.rs:751`), and the dispatcher result (`job_handler.rs:255`).

## Tests

- **Weak assertions in `program.rs`:**
  - `test_transaction_api_reports_unsupported_aggregated_key_operations` calls `notify_news` (1758-1766)
    without asserting anything, and checks `dispatch_transaction_name` with `is_err()` only (1746).
  - `test_aggregated_key_monitoring_registers_nothing_and_suppresses_completion` (1825-1834) asserts
    `send_setup_completed()`, which is a protocol constant. Assert that L2 received no
    `SetupCompleted` (`env.l2_messages()`).
- **Impossible states:** `generation_and_advance_require_the_expected_states` (`setup_engine.rs:1236`)
  and `test_engine_completion` (1011) set `StepState::Completed` with `all_steps_completed == false`,
  which `restore_state` rejects. They test a state the engine can't reach.
- **A second storage per test:** many tests create a `TestProgramContextEnv` and then a separate
  `TestStorageDir` only for the protocol (`program.rs:1176-1177`, `setup_engine.rs:1018-1019`, every
  step test). Check whether the env's storage can be reused.
- **Missing coverage:** possible bugs 1 to 3 below have no test. Each fix should come with one that
  fails before it.

## Traps: tempting changes that alter behavior

- **Mirrored files:** `participant.rs`, `variables/shared.rs`, `types/shared.rs` and `spv_proof.rs` are
  copied into `rust-bitvmx-client-types`. Their serde shapes are the public API.
- **Wire format in `comms_helper.rs`:** the frame is a JSON array of byte numbers, the signature is a
  number array, and the signed string uses sorted keys. Peers depend on all three, so don't
  "optimize" them. `CommsMessageType` names and `as_str` values are storage keys (see the comment at
  178-187).
- **`GC_COMMITMENTS` as `VecNumber` (`garbler_step.rs:621-625`):** it stores bytes widened to `u32`.
  It looks wasteful, but it is a persisted variable that other code reads.
- **`receive_current_step_data` returns `Success` for the node's own data again
  (`setup_engine.rs:427-430`):** it looks like it should be `NoOp`. The boundary classifier already
  turns that case into `ContributionAlreadyAccepted`, so only direct callers reach it, and the leader
  doesn't broadcast twice because the broadcast clears the stored originals.
- **API errors propagate on purpose:** `GetTransaction`, `GetSPVProof` and `SetFundingUtxo` (`api.rs:736,
  920, 989`) return coordinator errors as `Err`, so the input rolls back and is retried.
  `mocked_transaction_query_failure_propagates` asserts this for infrastructure failures. Don't turn
  them into replies without separating request faults from outages.
- **The allow-list mutation runs before commit:** the live list changes inside the API transaction,
  before it commits. A failed commit is fatal and the node exits, so a restart reloads the persisted
  list. It isn't an inconsistency to fix.

## Possible bugs (separate from this cleanup)

These are behavior questions, so they are out of scope for a behavior-preserving refactor.

1. **A deferred leader message can block itself
   (`bitvmx/peer_messages.rs:86-107`, `leader_broadcast.rs:193-198`):** the leader stores a non-leader's
   original before `process_comms_message` decides what to do with it. Suppose a non-leader's
   `PublicNonces` arrives while the leader is still on the keys step:
   - the original is stored, the engine returns `Retry(SetupNotReady)`, and the deferral commits with
     the stored original;
   - each later retry finds that original already stored, so `store_original_message` returns `false`
     and the message is retried again, without reaching the engine;
   - it only unblocks when another participant's message completes the set and the broadcast clears
     storage.

   If the slowest participant takes longer than the retry budget, the message is dropped and setup
   fails with `MessageLost` against a sender that did nothing wrong. With two participants the
   leader's own contribution completes the set, so this needs three or more. The same order also
   lets the leader broadcast an original it never verified for the active step.

   **Fixed:** the leader still stores the original before the engine runs, because the engine
   broadcasts once every original for the step is stored. When the engine returns anything but
   `Success`, the original is removed again, so a stored original always means the engine
   accepted it. A duplicate of an accepted contribution is already consumed by
   `classify_setup_message` as `ContributionAlreadyAccepted`. Covered by
   `leader_does_not_keep_original_of_deferred_message`.

2. **Nonce and signature entries aren't bound to the sender
   (`nonces_step.rs:158-223`, `signatures_step.rs:171-268`):** each entry carries a participant public
   key, and nothing checks it against the key the sender declared in the keys step
   (`participant_{idx}_keys`). A participant can submit entries under another participant's key:
   - everyone else hits "Received duplicate nonces from participant key" in `on_step_complete`
     (nonces 286, signatures 334). That is an `InvalidMessage` error, so setup fails with no peer
     named, instead of a fault against the sender;
   - the impersonated participant skips its own index, so it hands the key manager a foreign nonce
     for its own key.

   Requiring the entry key to equal the sender's declared key in `verify_received_impl` turns this
   into `InvalidSetupContribution` against the sender. The key manager may reject some of these
   cases. This crate doesn't check.

3. **Every program ever created is read on every tick (`bitvmx.rs:438-467`, `api.rs:35-48, 95-98`):**
   the registry is one value, `bitvmx/program/list`, holding a `ProgramStatus` for every program.
   `process_programs` loads it on each application tick and opens a transaction per program to read
   its state, including `Ready` and `Failed` programs forever. `program_exists` and
   `add_new_program` read the whole list, and the second also rewrites it. The cost grows with the
   node's lifetime program count. This is the same shape as the expected-job ID list that
   `SUPPORT_MODULES_CLEANUP.md` fixed. Programs to tick could live under a prefix keyed by state, and
   `program_exists` could be a `has_key` on the program key. `ProgramStatus` would then have no use.

4. **A caught panic exits with status 0 (`main.rs:164-169`):** the comment says so. A supervisor or
   CI sees a clean exit after a panic. Returning an error gives a non-zero exit.

5. **Two reply accessors return a random id (`types/shared.rs:383-399`):**
   `OutgoingBitVMXApiMessages::transaction_info` and `hashed_message` return `Uuid::new_v4()` instead
   of the request id in the message. Nothing in this repo calls them, but they are public in
   `rust-bitvmx-client-types`, so a client that correlates replies with them gets the wrong id.

6. **Secret bytes in error text (`variables/shared.rs:43-45`):** `VariableTypes::err()` formats the
   whole value with `{:?}`, and every getter puts it into `InvalidVariableType`. Calling a getter on
   a `Secret` puts the secret bytes into the error, which reaches logs and the `NonFatal` report sent
   to L2. Printing the variant name only avoids it.

7. **`BitVMXClient::get_message` hides receive errors (`client.rs:270-279`):** `if let
   Ok(Some(..)) = recv()` turns every receive error, fatal broker errors included, into `Ok(None)`, so
   `wait_message` reports `MessageTimeout` instead of the cause.

8. **Locally failed nonces or signatures are skipped silently (`nonces_step.rs:124-136`,
   `signatures_step.rs:135-146`):** any key-manager error for one aggregated key is logged and skipped,
   storage errors included. Only a completely empty result is an error. Peers accept the partial
   contribution, because validation only checks that the keys present are expected, not that all of
   them are.

9. **Authorization is checked for one API message only (`api.rs:572`):** `DiscardDispatcherJob`
   requires the sender to be the configured L2. `Shutdown`, `Backup`, the allow-list mutations,
   `GetKeyPair` (which returns a private key), `SendFunds` and `Decrypt` accept any sender the
   services broker routes, so they depend on the routing table alone. Either document that the
   routing table is the boundary, or check the sender in one place.

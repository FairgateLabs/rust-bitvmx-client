# Leader Broadcast: Crash Consistency and Duplicate-Delivery Analysis

Analysis of whether the leader broadcast mechanism can produce inconsistent
state or harmful duplicates across crashes. Conclusion up front: **the design
is sound.** Storage atomicity is guaranteed by the per-tick global
transaction, the wire gives at-least-once delivery, and the receiver-side
guards make duplicates harmless. Verified 2026-07-16.

## 1. Design decision: all-or-nothing broadcast

A whole `BroadcastedMessage` is rejected if any single contained
`OriginalMessage` fails validation or signature verification. There is no
recovery path from a malicious participant or broadcaster — with a malicious
party in the set the multiparty protocol cannot complete anyway, so salvaging
the honest subset has no value.

`process_broadcasted_message` (`src/leader_broadcast.rs`) enforces this
atomically in two phases: phase 1 verifies and reconstructs every original
message; only if all pass does phase 2 queue them. Nothing from a rejected
broadcast enters the system. (The `MissingVerificationKey` case still queues —
that is a missing key, not a bad signature, and `process_msg` re-verifies on
pop.)

## 2. Storage atomicity: the per-tick global transaction

The original concern: leader crashes between enqueueing the broadcast to the
comms out-queue and `clear_original_messages` → on restart it re-broadcasts →
duplicates. This state is **not persistable**. Three facts combine:

1. **One storage instance.** The comms `QueueChannel` (`bitvmx.rs`, built with
   `store.clone()`), `LeaderBroadcastHelper`, and `MessageQueue` all share the
   same `Rc<Storage>` that `BitVMX::tick()` transacts on.
2. **All writes route into the transaction.** `enqueue_out_msg` writes with
   `transaction_id: None` (`rust-bitvmx-broker/src/channel/queue_channel.rs`),
   and `Storage::set`/`remove`/`partial_compare` with `None` silently redirect
   into the global transaction whenever one is active
   (`rust-bitvmx-storage-backend/src/storage.rs`). Reads route the same way,
   so a tick sees its own uncommitted writes.
3. **The tick is the atomic unit.** `begin_global_transaction` at the top of
   `BitVMX::tick()`, `commit_global_transaction` at the bottom. A crash
   mid-tick drops the uncommitted RocksDB transaction — the entire tick's
   writes vanish together. Either the broadcast was enqueued AND the originals
   cleared, or neither happened.

## 3. The wire is outside the transaction: at-least-once delivery

The physical network send in `process_out_queue` happens mid-transaction and
cannot be rolled back. Ordering inside one tick: `process_programs` (may
enqueue a broadcast) runs before `process_comms_messages` → `comms.tick()`,
and since reads see uncommitted writes, the broadcast can be physically sent
in the same tick it was enqueued.

Consequence: crash after bytes hit the wire but before commit → the tick
rolls back → stored originals are restored → on restart the leader
re-broadcasts → peers receive the same `BroadcastedMessage` twice.

This is inherent to any design with a network send inside a transaction, not
a flaw: the system is **at-least-once, not exactly-once**. Receiver-side
idempotency is the required safety net.

## 4. Receiver-side idempotency: three layered guards

A duplicated `BroadcastedMessage` re-queues its original messages
(`process_broadcasted_message` has no dedupe, by design). Each duplicate then
hits, in order:

1. **Program level** (`program.rs`, `receive_setup_data`): once setup
   finished, `ProgramState::Ready` short-circuits — setup data is never
   processed again.
2. **Engine level** (`setup_engine.rs`, `receive_setup_data`):
   `is_complete()` ignores messages after the setup engine finished (also
   covers the case of a non-leader receiving the echo of its own message).
3. **Step level** (`setup_engine.rs`, `receive_current_step_data`):
   `has_participant_completed(participant_idx)` rejects a second message from
   the same sender within a step — this catches the crash-resend scenario. A
   duplicate of one's own message returns consumed and is dropped immediately.

Unconsumed duplicates are pushed back to the `MessageQueue`, where `push_back`
→ `record_attempt` → `is_exhausted` drops them after `max_send_attempts`
(`message_queue.rs`). Duplicates can neither corrupt state nor accumulate.

Leader side additionally: `store_original_message` validates at the boundary
and skips duplicate senders (storage key includes the sender's pubkey hash, so
at most one message per sender can exist — see the unique-sender invariant
test in `leader_broadcast.rs`).

## 5. Known caveats (accepted, not bugs)

1. **Duplicates are retried before being dropped.** `Ok(false)` conflates
   "not ready, retry later" with "duplicate, never processable". A duplicate
   bounces through the retry queue until exhaustion, then dies with a generic
   "Dropping message after N attempts" warning that reads like a failure.
   Wasted cycles and misleading logs only. Possible improvement: tri-state
   result (consumed / retry / discard).

2. **Implicit invariant: one message type per setup step.** The step-level
   guard resets when the engine advances. A stale duplicate arriving in a
   later step is only rejected because `verify_received` checks the message
   type against the step's expected type. If any setup flow ever had two
   steps expecting the same `CommsMessageType`, a replayed message from the
   earlier step would carry a genuine signature and could be accepted as the
   later step's data. Currently every step uses a distinct type; nothing
   enforces this. Worth an assertion or comment in the setup engine if steps
   are ever added.

3. **Transaction hygiene depends on tick errors being fatal.** Nothing calls
   `rollback_global_transaction`; if `tick()` errors mid-way (or takes the
   shutdown early-return after `begin`), the transaction is left active.
   Today `main.rs` treats any tick error as fatal and exits, so the
   uncommitted transaction dies with the process. If error handling is ever
   softened to "log and continue", the next `begin_global_transaction`
   returns `GlobalTransactionAlreadyActiveError` and every subsequent tick
   fails until restart. Either add a rollback on error paths or keep tick
   errors fatal.

4. **`CommsMessageType` is a compatibility surface.** Variant names are
   persisted in storage keys (Debug format) and exchanged on the wire (serde
   JSON), and `KIND_MAP` fixes the 2-byte header. Renaming or removing
   variants breaks cross-version compatibility; appending new ones is safe.
   (Documented on the enum in `comms_helper.rs`.)

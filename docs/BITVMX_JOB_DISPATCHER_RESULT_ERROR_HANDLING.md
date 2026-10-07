# BitVMX job-dispatcher result error-handling action plan

## Scope

This plan covers all service messages routed by sender identity in
`BitVMX::process_one_api_message`:

- Garbler results;
- Emulator results;
- ZKP prover results;
- dispatcher `PingMessage` control traffic.

The ZKP prover uses a separate handler today, but it is a job dispatcher and
must follow the same ingress rules. The broker/TLS identity identifies the
configured service; the payload still must be treated as fallible service
output.

## Current transaction model

One broker service message is removed and handled inside one shared-storage
transaction. On success, its state changes and outgoing messages commit with
inbox consumption. On error, inbox consumption rolls back.

This is correct for transient storage and broker failures. It is unsafe for
permanent result errors because the same item returns to the front of the
shared service inbox, where it can block dispatcher, prover, and ordinary API
messages indefinitely.

Important current gaps are:

1. `ResultMessage::is_error` is ignored. Dispatcher failures commonly contain a
   plain error string rather than JSON, so `result_as_value()` fails and the
   input retries forever.
2. malformed `ResultMessage`, malformed job context, wrong context kind, and
   invalid result payloads generally propagate as `Severity::Other`, also
   causing endless retry;
3. runtime `ProgramStep` errors have no terminal job-failure outcome;
4. setup results use `SetupAttemptFailed`, which is suitable for terminal setup
   failure, but the classification is broad and not specific to dispatcher
   outcomes;
5. ZKP handling silently truncates/culls invalid byte-array elements and treats
   missing correlation state as a retryable generic format error;
6. Garbler and Emulator support at-least-once deduplication in some paths, but
   source/context compatibility is not enforced centrally.

## Implementation status

The first control-flow foundation is implemented:

- `DispatcherResultDisposition` has `Processed`,
  `DiscardNoOp(DispatcherNoOpReason)`, and a terminal `FailJob` outcome;
- Garbler, Emulator, and ZKP handlers return this typed disposition;
- `BitVMX::process_one_api_message` applies service dispositions centrally while
  the inbox transaction is active;
- a result for a missing program is consumed as `Orphaned`;
- results for failed programs and setup results delivered after setup completion
  are consumed as `Stale`;
- `Duplicate` exists as a no-op reason but no dispatcher path emits it yet;
- `Program::is_setup_complete` and `Program::is_stale_setup_result` centralize
  the corresponding lifecycle checks;
- Garbler, Emulator, and ZKP ingress share one envelope decoder that distinguishes
  `PingMessage` from `ResultMessage` without parsing the result payload;
- malformed service envelopes are logged and consumed as
  `DiscardNoOp(MalformedEnvelope)`, so they cannot poison the shared inbox;
- `is_error` is handled before result payload parsing: setup failures use the
  existing rollback-then-settle path, runtime failures atomically mark the whole
  program failed and emit a scoped `JobFailed` report, and ZKP failures persist a
  `FAILED` reason and notify the saved requester;
- malformed job ids and missing ZKP correlation are consumed as uncorrelatable or
  orphaned results rather than retried indefinitely;
- authenticated dispatcher routes are checked against the job context before protocol
  dispatch: Garbler accepts `SetupStep` and `ProgramStep`, Emulator accepts only
  `ProgramStep`, and ZKP accepts request UUIDs through its separate handler;
- a dispatcher-labelled success with a non-JSON payload is routed through the same
  terminal setup/job failure path rather than returned as a retryable parse error;
- an incompatible context attributable to active setup uses the existing
  rollback-then-settle setup failure path, while one attributable to a ready program
  produces `FailJob`; failed programs remain stale no-ops.

`FailSetup` is deliberately **not** an enum variant: setup keeps the existing
`SetupAttemptFailed` two-transaction settlement so partially staged effects are
rolled back before terminal state is recorded. `FailJob` was added together with
its producer, terminal program transition, scoped notification, and tests.

Malformed successful result payloads, ZKP byte conversion, expected-job tracking,
and finer-grained runtime-job recovery are still unresolved.

## Desired contract

The currently implemented contract is:

```rust
pub enum DispatcherResultDisposition {
    Processed,
    DiscardNoOp(DispatcherNoOpReason),
    FailJob { program_id: Uuid, job_id: String, reason: String },
}
```

Handlers return `Result<DispatcherResultDisposition, BitVMXError>`.

- `Processed`: result effects were staged successfully;
- `DiscardNoOp`: a stale, orphaned, or malformed uncorrelatable service message
  is intentionally consumed; the `Duplicate` reason is defined but is not emitted
  by a dispatcher path yet;
- `Err`: processing rolls back. Until error classification is narrowed in later
  steps, this still includes both infrastructure errors and some permanent
  dispatcher-controlled errors.

The setup path intentionally does not use an in-transaction `FailSetup` variant.
It rolls back partial effects, records terminal setup state and the existing L2
notification in a new transaction, then consumes the restored result through the
failed-program lifecycle gate. `FailJob` marks the whole owning program failed,
emits a scoped L2 `JobFailed` report, and consumes the input atomically.

If setup failure still needs the existing two-transaction settlement, preserve
`SetupAttemptFailed`: roll back partial result effects, record failed setup in a
new transaction, and let the restored result be consumed by the failed-program
lifecycle gate on its next delivery.

## Processing pipeline

### 1. Authenticate the service route

Continue routing by the broker-authenticated `Identifier`, not by a payload
field. Keep separate configured identities for Garbler, Emulator, and ZKP.
Messages from all other identities remain API messages under the existing API
contract.

### 2. Decode control messages and result envelopes

- a valid `Pong` updates liveness and is consumed;
- an unexpected `Ping` is logged and consumed;
- otherwise decode `ResultMessage`;
- a completely malformed envelope has no trustworthy job correlation, so log a
  service fault, optionally emit a node-scoped dispatcher report, and consume
  it; do not retry it forever;
- storage/broker failure while recording or reporting the disposition remains
  `Err`.

A malformed service frame should not be allowed to poison the shared API inbox.
If auditability beyond logs is required, add a bounded service dead-letter
queue; do not model malformed input as an unbounded rollback loop.

### 3. Honor `ResultMessage::is_error` before parsing the result

When `is_error == true`, `result` is an error description and is not guaranteed
to be JSON.

- parse the job id/context only far enough to identify its owner;
- setup job: terminal `FailSetup`;
- runtime program job: terminal `FailJob` scoped to the program;
- ZKP job: store failed status/reason and send
  `ProofGenerationError(request_id, reason)` to the saved requester;
- uncorrelatable job id: consume and report a node/service-scoped fault.

Never call `result_as_value()` first on an error result.

### 4. Validate source/context compatibility

Apply a strict routing table before invoking protocol code:

| Source | Allowed job id/context |
|---|---|
| Garbler | `SetupStep` for garbler setup work; `ProgramStep` for GC runtime work |
| Emulator | `ProgramStep` for dispute execution work |
| ZKP prover | request UUID used by `GenerateZKP` |

Reject `ProgramId`, `RequestId`, `Protocol`, or cross-dispatcher contexts unless
a concrete producer requires and documents them. A context attributable to an
active setup becomes `FailSetup`; a malformed or unsupported runtime context
becomes `FailJob`/service fault and is consumed.

For stronger protection, persist expected job metadata when dispatching:
`job_id`, dispatcher identity, program/request owner, job kind, and state. Then
a result can be checked against the job that was actually issued rather than
only against strings encoded in `Context`.

### 5. Apply lifecycle and deduplication gates

- missing program: stale/orphaned `DiscardNoOp`, unless expected-job storage
  proves this is an unresolved active job;
- failed program: stale `DiscardNoOp`;
- completed setup plus `SetupStep`: stale `DiscardNoOp`;
- earlier setup step or already-completed local contribution: duplicate/stale
  `DiscardNoOp`;
- already-completed `ProgramStep`: duplicate `DiscardNoOp` using the durable
  `job_done:<step>` marker;
- active expected job: validate payload and process.

Deduplication state must be committed atomically with result effects. Job ids
must be unique for distinct executions; a reusable step name is not sufficient
if the same protocol step can be issued more than once.

### 6. Validate successful payloads narrowly

Payload/schema/semantic failures produced by the dispatcher are terminal job
outcomes, not infrastructure retries:

- malformed Garbler result, wrong message type, unknown sub-step, role mismatch,
  invalid proof, or inaccessible declared artifact;
- malformed Emulator result, mismatched round/job type, or invalid execution
  result;
- malformed ZKP status/journal/seal data.

Map these to `FailSetup` or `FailJob` according to context. Preserve as `Err`
only failures such as shared storage, broker outbox, key-store infrastructure,
poisoned locks, or a genuinely transient local resource outage. Use narrow
errors/outcomes rather than globally classifying `InvalidMessage`.

For Garbler results that reference filesystem artifacts, distinguish malformed
or missing dispatcher output from transient local I/O. Setup may fail
terminally for a missing promised artifact, while a temporary resource outage
may be retried under an explicit bounded policy.

### 7. Complete or fail atomically

For successful runtime jobs, stage protocol state, downstream dispatcher work,
coordinator dispatch registration, and the durable dedup marker in the same
transaction as inbox consumption.

For failed runtime jobs, add a durable terminal job state so the protocol does
not wait forever or redispatch accidentally. Report it at program scope. Define
whether each protocol itself remains usable, transitions to a runtime failed
state, or can request a replacement job.

For ZKP:

- validate every journal/seal item as an integer in `0..=255`; reject instead of
  filtering or truncating;
- on success, store proof, journal, and `OK`, then enqueue `ProofReady`;
- on dispatcher or payload failure, store `FAILED` plus the reason and enqueue
  `ProofGenerationError`;
- decide that missing `ZKPFrom` is either fatal local corruption or an orphaned
  terminal result that is consumed and reported. It must not retry forever.

## Liveness control-message caveat

`PingHelper` mutates in-memory timestamps/latches while the broker input is
inside a storage transaction. A final commit failure is fatal, so the process
will not continue with diverged durable input and live liveness state. Recovery
reports are currently best effort and can be lost after the in-memory latch is
cleared; this is acceptable only if liveness reporting is explicitly
observational. If delivery is required, return a fallible result and enqueue the
state-change report before changing the latch, or persist liveness state.

Outbound job dispatch can also fail into a broker dead-letter path. Peer
outbound dead letters are handled for setup, but service/job dead letters are
not currently correlated to jobs. Add expected-job tracking or a service
send-failure/dead-letter callback so a job that never reaches a dispatcher can
be failed or retried under a bounded policy rather than waiting forever.

## Implementation plan

1. **Create typed dispatcher dispositions** and apply them centrally at the
   service-inbox transaction boundary. **Partially complete:** `Processed` and
   `DiscardNoOp` are wired centrally; terminal failure variants are deferred
   until their behavior exists.
2. **Unify envelope parsing** for Garbler, Emulator, and ZKP while retaining
   dispatcher-specific payload handlers. **Complete:** malformed envelopes are
   logged and consumed with the explicit `MalformedEnvelope` no-op reason.
3. **Handle `is_error` first** and map it to setup, runtime-job, or ZKP terminal
   failure. **Complete:** plain-text dispatcher failures are handled without
   result payload parsing; runtime failure currently terminates the whole program.
4. **Enforce the source/context routing table** before invoking protocol code.
   **Complete:** cross-dispatcher and unsupported contexts are rejected through terminal
   setup/job outcomes; malformed successful JSON is classified through that terminal
   path; request contexts on Garbler/Emulator routes are consumed as uncorrelatable.
5. **Introduce expected-job records** with stable unique ids, owner, dispatcher,
   kind, and pending/completed/failed status.
6. **Make runtime job failure explicit.** Add protocol callbacks/state for
   terminal `ProgramStep` failure and scoped reporting.
7. **Narrow setup classification.** Keep storage/system failures as `Err`; make
   dispatcher-declared and dispatcher-payload failures terminal setup outcomes.
8. **Harden ZKP parsing and correlation.** Eliminate byte filtering/truncation
   and persist a useful failed status.
9. **Audit deduplication ids.** Ensure `job_done:<step>` cannot alias distinct
   jobs or rounds.
10. **Handle service delivery dead letters/timeouts** through expected-job state
    and a bounded retry/failure policy.
11. **Document liveness semantics** and decide whether recovery/down reports are
    best effort or durable.

## Required tests

1. `is_error=true` with a plain-text result is consumed and produces the correct
   setup/job/ZKP failure without calling `result_as_value()`.
2. A malformed result envelope is consumed and does not block the following API
   message in the shared inbox.
3. Wrong source/context combinations are terminal and do not invoke protocol
   handlers.
4. Missing, failed, ready, and completed programs produce the documented stale
   or failure outcomes.
5. Duplicate setup and runtime results are no-ops and do not repeat transaction
   dispatch or state mutation.
6. A successful result, its dedup marker, downstream outbox/coordinator work,
   and inbox consumption commit atomically.
7. Storage, broker, key-store, and coordinator infrastructure failures roll back
   inbox consumption and all staged result effects.
8. A malformed successful Garbler/Emulator payload fails the owning setup/job
   once instead of retrying forever.
9. ZKP arrays reject non-numeric, fractional, negative, and greater-than-255
   elements; no value is silently dropped or truncated.
10. ZKP dispatcher failure stores `FAILED`, notifies the original requester, and
    remains queryable through `GetZKPExecutionResult`.
11. Missing ZKP correlation follows the chosen fatal/orphan policy without an
    endless retry.
12. A service delivery dead letter or terminal liveness timeout moves the
    expected job to its bounded retry/failure path.
13. A commit failure after a Pong is fatal, preserving the in-memory-state
    safety assumption.

## Core invariant

> A dispatcher result is processed at most once in durable protocol state and
> may be delivered at least once by transport. Duplicate and stale results are
> consumed idempotently. Dispatcher-declared failures and invalid result payloads
> terminate the owning setup/job/request instead of poisoning the shared inbox.
> Only local or infrastructure failures roll back for retry.

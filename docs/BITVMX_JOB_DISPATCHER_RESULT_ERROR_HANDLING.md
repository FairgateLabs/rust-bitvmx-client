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
  `DiscardNoOp(DispatcherNoOpReason)`, and a `JobFailed` outcome;
- Garbler, Emulator, and ZKP handlers return this typed disposition;
- `BitVMX::process_one_api_message` applies service dispositions centrally while
  the inbox transaction is active;
- a result for a missing program is consumed as `Orphaned`;
- results for setup-failed programs are consumed as `SetupFailed`, while setup results
  delivered after setup completion are consumed as `Stale`; these typed dispositions
  drive expected-job settlement without a separate handler-side lifecycle check;
- results for non-pending expected jobs are consumed as `Duplicate`;
- `Program::is_setup_complete` and `Program::is_stale_setup_result` centralize
  the corresponding lifecycle checks;
- Garbler, Emulator, and ZKP ingress share `dispatcher_result_message`, which
  distinguishes control messages, encoded results, and settled malformed input without
  using an error return for normal control flow or parsing the result payload. A
  source-specific `FnOnce` resolves owner and semantic context from the expected-job
  id, after which validation is applied centrally before either result handler receives
  the message;
- malformed service envelopes are logged and consumed as
  `DiscardNoOp(MalformedEnvelope)`, so they cannot poison the shared inbox;
- `is_error` is handled before result payload parsing: setup failures use the
  existing rollback-then-settle path, runtime failures leave the program active while
  atomically moving the expected job to `RetryPending` and emitting a scoped `JobFailed`
  report, and ZKP failures persist a `FAILED` reason and notify the saved requester;
- malformed job ids and missing ZKP correlation are consumed as uncorrelatable or
  orphaned results rather than retried indefinitely;
- authenticated dispatcher routes are checked against the job context before protocol
  dispatch: Garbler accepts `SetupStep` and `ProgramStep`, Emulator accepts only
  `ProgramStep`, and ZKP accepts request UUIDs through its separate handler;
- a dispatcher-labelled success with a non-JSON payload is routed through the same
  terminal setup/job failure path rather than returned as a retryable parse error;
- an incompatible context attributable to active setup uses the existing
  rollback-then-settle setup failure path, while one attributable to a ready program
  produces `JobFailed` without changing program lifecycle; setup-failed programs
  remain stale no-ops;
- every Garbler, Emulator, and ZKP dispatch now persists an expected-job record in
  the same transaction as the broker outbox write, including its job id, authenticated
  dispatcher, program/request owner, setup/program/ZKP kind, and status;
- ingress requires a matching pending expected job; cross-dispatcher results are
  consumed as uncorrelatable without changing the real job, non-pending records are
  consumed as duplicates, and results transition atomically to `Completed`,
  `RetryPending`, `Discarded`, or `Failed`;
- registration is idempotent for an existing job with matching immutable metadata,
  regardless of status, and the dispatcher request is not sent again. This prevents
  replayed API/news input from blocking the inbox or repeating completed work;
- Garbler and Emulator use their serialized semantic `Context` as the stable wire id.
  Protocols are responsible for assigning a distinct step identifier to every logical
  execution, including rounds where applicable; repeated dispatch of that context is an
  idempotent no-op. ZKP keeps its already-unique request UUID;
- retry is deliberately separate from registration: the future scheduler must move an
  existing `RetryPending` record back to `Pending` and resend the same job id;
- ZKP success payloads deserialize directly into `zk_result::ResultType`, so malformed
  payloads and non-`u8` journal/seal values become consumed, reported failures rather
  than being silently filtered or truncated;
- ZKP requester correlation and proof/journal output are stored in one typed domain
  record, while the expected-job record is the single source of truth for dispatcher
  lifecycle and failure state. Both are updated in the inbox transaction.

`FailSetup` is deliberately **not** an enum variant: setup keeps the existing
`SetupAttemptFailed` two-transaction settlement so partially staged effects are
rolled back before terminal state is recorded. `JobFailed` records the expected job as
retry-pending and emits a scoped notification, but never changes a ready program to
`ProgramState::Failed`.

Malformed successful Garbler/Emulator result payloads, service delivery failure handling,
and finer-grained runtime-job recovery are still unresolved. Current protocol dispatch
sites use execution-specific semantic step names (including rounds where applicable);
any future repeatable protocol operation must supply a distinct semantic execution key.

## Planned dispatcher-specific failure policy (not implemented)

The current implementation records a runtime Garbler or Emulator `ProgramStep`
failure as `RetryPending` without terminating the program, but does not yet schedule
redispatch; it also marks a failed ZKP request terminal. That is temporary.
The intended policy is dispatcher-specific:

- a Garbler failure during setup is terminal for that setup and must continue to use
  rollback-then-settle plus the existing setup error report;
- a runtime Garbler `GarbledJobType::Evaluate` failure from
  `src/program/protocols/gc_drp.rs` follows the runtime retry policy rather than the
  setup policy: it must not fail the owning program and must retry indefinitely with
  backoff until operator intervention or explicit discard;
- an Emulator job failure has the same runtime policy: it must not fail the owning
  program. The failed result should be consumed, the job should remain unresolved,
  and dispatch should retry indefinitely with backoff until an operator fixes the
  underlying problem or explicitly discards the job;
- ZKP generation is intended to follow the same indefinite retry/manual-discard model,
  rather than becoming terminal after the first prover failure. This ZKP behavior is
  recorded here for future work and must not be implemented as part of the current ID
  work.

Indefinite retry must be durable and must not retain the failed result at the front of
shared inbox. Expected-job state therefore needs retry metadata and the dispatched job
payload (or enough information to reconstruct it), plus an explicit operator discard
operation. A retry reuses the same unique job correlation id; creating a fresh id for
each retry would allow delayed results to affect the wrong execution.

Remaining expected-job work also includes an iterable retry index and retention/cleanup
for terminal records. Program dispatch call sites now pass the dispatcher explicitly
instead of inferring it by comparing destination identities. The expected-job status is
the transport correlation/deduplication gate; existing protocol `job_done` markers
remain a domain-level effect guard.

## Desired contract

The currently implemented contract is:

```rust
pub enum DispatcherResultDisposition {
    Processed,
    DiscardNoOp(DispatcherNoOpReason),
    JobFailed {
        program_id: Uuid,
        expected_job_id: String,
        job_id: String,
        reason: String,
    },
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
failed-program lifecycle gate. `JobFailed` leaves the owning program active, moves the
expected job to `RetryPending`, emits a scoped L2 report, and consumes the input
atomically.

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
- setup Garbler job: terminal `FailSetup`;
- runtime Garbler `Evaluate` job: consume the failed result and durably schedule the
  same job for indefinite retry with backoff; only an explicit operator action
  discards it;
- Emulator runtime job: use the same indefinite retry/manual-discard policy;
- ZKP job: currently store failed status/reason and send
  `ProofGenerationError(request_id, reason)` to the saved requester. The future policy
  is the same indefinite retry/manual-discard behavior as Emulator;
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
a concrete producer requires and documents them. A wrong authenticated dispatcher is
consumed as an uncorrelatable service fault and must not change the expected job or
owning setup. For failures from the correct dispatcher, a context attributable to an
active setup becomes `FailSetup`; a malformed or unsupported runtime context becomes
`JobFailed`/service fault and is consumed without failing the program.

Persist expected job metadata when dispatching: `job_id`, dispatcher identity,
program/request owner, job kind, and state. Garbler and Emulator use the serialized
semantic `Context` as their stable unique `job_id`; protocols must make each logical
execution distinguishable in that context. The ZKP request UUID is already unique and
remains its correlation id. A result is checked against the expected-job record that was
actually issued rather than trusted solely because its id decodes as a `Context`.

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

Payload/schema/semantic failures produced by the dispatcher are attributable job
outcomes, not infrastructure transaction retries:

- malformed Garbler result, wrong message type, unknown sub-step, role mismatch,
  invalid proof, or inaccessible declared artifact;
- malformed Emulator result, mismatched round/job type, or invalid execution
  result;
- malformed ZKP status/journal/seal data.

Map setup failures to `FailSetup`; runtime Garbler `Evaluate` and Emulator failures
must leave the program active and eventually enter durable redispatch. Preserve as `Err`
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

For failed runtime jobs, keep the protocol and owning program active. Consume and
report the failed attempt atomically, then durably retry the same expected job with
backoff until success or explicit operator discard. The current implementation records
`RetryPending` and reports the failed attempt but still lacks the retry scheduler and
manual-discard operation.

For ZKP:

- validate every journal/seal item as an integer in `0..=255`; reject instead of
  filtering or truncating;
- on success, store proof, journal, and `OK`, then enqueue `ProofReady`;
- on dispatcher or payload failure, store `FAILED` plus the reason and enqueue
  `ProofGenerationError`;
- a missing ZKP execution record/requester is treated as an orphaned terminal result
  that is consumed and recorded. It must not retry forever.

ZKP persistence now separates responsibilities between two durable typed records. The
expected-job record owns dispatcher lifecycle, failure reasons, and future retry
metadata. The ZKP domain record owns requester correlation and optional proof/journal
output. Queries combine them, treating a completed expected job without output as
inconsistent state; result settlement updates both in the same transaction.

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
not currently correlated to jobs. Add a service send-failure/dead-letter callback
that applies the job-specific policy: terminal failure for Garbler setup jobs,
and durable indefinite retry with backoff/manual discard for Garbler runtime
`Evaluate`, Emulator, and later ZKP jobs.

## Implementation plan

1. **Create typed dispatcher dispositions** and apply them centrally at the
   service-inbox transaction boundary. **Complete for current behavior:** `Processed`,
   `DiscardNoOp`, and non-program-terminal `JobFailed` are wired centrally.
2. **Unify envelope parsing** for Garbler, Emulator, and ZKP while retaining
   dispatcher-specific payload handlers. **Complete:** malformed envelopes are
   logged and consumed with the explicit `MalformedEnvelope` no-op reason.
3. **Handle `is_error` first** and map it to setup, runtime-job, or ZKP failure.
   **Complete for current behavior:** plain-text dispatcher failures are handled
   without result payload parsing, and runtime failure leaves the program active.
4. **Enforce the source/context routing table** before invoking protocol code.
   **Complete:** cross-dispatcher and unsupported contexts are rejected through setup
   failure or job-failure outcomes; malformed successful JSON follows the same path;
   request contexts on Garbler/Emulator routes are consumed as uncorrelatable.
5. **Introduce expected-job records** with stable unique ids, owner, dispatcher,
   kind, and pending/retry-pending/completed/discarded/failed status. **Complete:** all
   dispatch paths persist and validate the record atomically; repeated registration
   with matching metadata is an idempotent no-op.
6. **Make runtime job failure explicit.** **Complete for the current retry-pending
   policy:** runtime failure is durably scoped to its expected job, reported, and does
   not terminate the owning program.
7. **Narrow setup classification.** Keep storage/system failures as `Err`; make
   dispatcher-declared and dispatcher-payload failures terminal setup outcomes.
8. **Harden ZKP parsing and correlation.** **Complete for current failure policy:**
   deserialize the shared typed result, reject invalid bytes without filtering or
   truncation, persist a useful failed status, and consume malformed prover output.
9. **Unify ZKP persistence.** **Complete for the current terminal failure policy:**
   `ZKPFrom`, `ZKPStatus`, `ZKPProof`, and `ZKPJournal` were replaced by a typed ZKP
   domain record. The expected-job record authoritatively owns lifecycle and failure
   state, avoiding duplicate status tracking; retry metadata will be added there with
   the future ZKP retry policy.
10. **Audit context-derived ids and deduplication.** **Complete for current protocol
   operations:** Garbler/Emulator use their semantic context as the stable correlation
   id, current round-dependent operations include the round in their step identifier,
   and ZKP uses its unique request UUID. Protocols own the invariant that distinct
   executions have distinct contexts; future repeatable operations must provide a new
   execution discriminator so expected-job registration and `job_done:<step>` do not
   alias executions.
11. **Handle service delivery dead letters/timeouts** through expected-job state
    and the dispatcher-specific terminal-or-indefinite-retry policy documented above.
12. **Document liveness semantics** and decide whether recovery/down reports are
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
8. A malformed successful setup Garbler payload fails the owning setup once;
   malformed runtime Garbler `Evaluate` and Emulator output is consumed and moves
   the same job into its durable retry path without failing the program.
9. ZKP arrays reject non-numeric, fractional, negative, and greater-than-255
   elements; no value is silently dropped or truncated.
10. Under the current behavior, a ZKP dispatcher failure stores `FAILED`, notifies
    the original requester, and remains queryable through `GetZKPExecutionResult`;
    future retry work replaces this with retry/manual-discard semantics.
11. Missing ZKP correlation follows the chosen fatal/orphan policy without an
    endless retry.
12. A service delivery dead letter or terminal liveness timeout applies the
    documented dispatcher-specific setup-failure or indefinite-retry path.
13. A commit failure after a Pong is fatal, preserving the in-memory-state
    safety assumption.

## Core invariant

> A dispatcher result is processed at most once in durable protocol state and
> may be delivered at least once by transport. Duplicate and stale results are
> consumed idempotently. Dispatcher-declared failures and invalid result payloads
> are consumed rather than poisoning the shared inbox: setup failures terminate,
> while runtime Garbler `Evaluate`, Emulator, and eventually ZKP failures remain
> durable unresolved jobs under retry/manual-discard control. Only local or
> infrastructure failures roll back inbox processing for immediate retry.

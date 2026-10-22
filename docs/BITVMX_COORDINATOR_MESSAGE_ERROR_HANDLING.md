# BitVMX coordinator-message error-handling action plan

## Scope

This plan covers both classes of events returned by
`BitcoinCoordinatorApi::get_news()`:

- `MonitorNews`: chain observations produced by the transaction monitor;
- `CoordinatorNews`: terminal or noteworthy outcomes produced by the transaction
  coordinator.

It also covers the `tick`, `get_news`, and `ack_news` calls surrounding those
events. API calls *into* the coordinator are covered by
[`BITVMX_API_ERROR_HANDLING.md`](BITVMX_API_ERROR_HANDLING.md).

## Current implementation status

The transaction boundary and most coordinator-business reporting described by
this plan are now implemented. The remaining work is concentrated at the
protocol monitor-news boundary, persisted-context validation, invariant news,
and tests.

Implemented behavior:

- coordinator tick, wallet tick, readiness check, and news fetch run in one
  global storage transaction;
- every `MonitorNews` and `CoordinatorNews` item is handled and acknowledged in
  its own transaction;
- a handler, broker-outbox, or acknowledgement failure rolls back the shared
  storage effects for that item;
- a failed nonfatal item does not roll back or prevent independently processed
  items from the same fetched batch;
- missing-program monitor news is logged and acknowledged as stale;
- coordinator business outcomes are reported with request, program, or node
  scope where their context permits it;
- Bitcoin RPC transport failures are classified separately from ordinary RPC
  rejections, and outage/recovery reports are deduplicated in memory;
- storage write/read/commit failures, fatal broker failures, poisoned locks,
  and rollback failures stop processing.

Remaining gaps:

- successful protocol observations and program-owned exceptional Bitcoin
  outcomes are not yet separated: `Program::notify_news` and protocol
  `notify_news` implementations still return only `Result<(), BitVMXError>`,
  cannot distinguish replay, stale input, terminal protocol failure, local
  corruption, and transient infrastructure failure, and there is no dedicated
  `handle_bitcoin_outcome` hook;
- an unreadable persisted monitor context is a generic serialization error and
  can be retried and reported forever;
- `resent_due_to_reorg` is ignored;
- `InvalidStateTransition` and `TxNotFound` are logged and acknowledged without
  a durable diagnostic;
- `InvalidCancel` still drops the context received by the coordinator;
- `send_new_block_news` turns global-setting read/type errors into `false`, so a
  storage problem can suppress a notification and still allow acknowledgement;
- the wallet is a separate persistence domain and cannot participate in the
  shared client/coordinator transaction;
- direct event-path tests and coordinator acknowledgement failure injection are
  still missing.

Protocol confirmation thresholds also do not yet universally satisfy the
production policy below. `ProtocolHandler::requested_confirmations` currently
falls back to one confirmation, and the Union reject-pegin default/example also
uses one. Those values must be replaced before the finality policy can be
relied upon.

## Transaction model

`BitVMX::process_bitcoin_updates` has three transaction boundaries:

1. coordinator tick, wallet tick, readiness check, and news fetch run in one
   global storage transaction;
2. every `MonitorNews` item is handled and acknowledged in its own transaction;
3. every `CoordinatorNews` item is handled and acknowledged in its own
   transaction.

This is the correct basic structure and must be preserved. A notification or
error report enqueued through the broker outbox is committed atomically with
the corresponding acknowledgement. A handler or acknowledgement failure rolls
both back. Actual broker delivery remains at least once.

The global transaction covers the shared storage used by the client,
coordinator, monitor, and broker outbox. It cannot roll back Bitcoin RPC side
effects, live memory, or the wallet's separate SQLite domain.

`run_step` catches nonfatal errors after rollback. Therefore a deterministic
error leaves its event unacknowledged and causes it to be retried and reported
on every coordinator cycle. Explicit terminal outcomes are required to avoid
that loop.

## Desired contract

The most important typed boundary is protocol monitor-news handling. Introduce
a disposition, or an equivalent typed contract, such as:

```rust
pub enum ProtocolNewsDisposition {
    Applied,
    DiscardStale(ProtocolNewsNoOpReason),
}
```

The handler returns `Result<ProtocolNewsDisposition, BitVMXError>`.

- `Applied`: protocol state changes and outgoing notifications were staged;
- `DiscardStale`: the event was already applied or can no longer affect the
  program and is intentionally consumed;
- `Err`: processing did not complete. Transient infrastructure errors remain
  unacknowledged; typed corruption or terminal program errors follow their
  explicit stop/quarantine policy.

### Separate successful and exceptional outcome paths

`ProtocolHandler::notify_news` is reserved for successful blockchain
observations. Coordinator warnings/failures and exceptional monitor outcomes
must use a separate protocol hook. A single outcome hook keeps related Bitcoin
conditions together while preserving their severity:

```rust
pub enum ProtocolBitcoinOutcome {
    Warning(ProtocolBitcoinWarning),
    Failure(ProtocolBitcoinFailure),
}

pub enum ProtocolBitcoinWarning {
    TransactionStuckInMempool { txid: Txid },
    MaxFeeRateReached {
        txid: Txid,
        effective_fee_rate: u64,
    },
}

pub enum ProtocolBitcoinFailure {
    DispatchFailed { txid: Txid },
    SpeedupDispatchFailed { txid: Txid },
    DeepReorg {
        txid: Txid,
        status: TransactionStatus,
    },
}

fn handle_bitcoin_outcome<BC: BitcoinCoordinatorApi>(
    &self,
    outcome: &ProtocolBitcoinOutcome,
    program_context: &ProgramContext<BC>,
) -> Result<(), BitVMXError>;
```

`MaxFeeRateReached` is a warning and a terminal condition only for further fee
boosting. The transaction may still confirm, so this outcome must not
implicitly fail the transaction or protocol. `TransactionStuckInMempool` is
also advisory unless a particular protocol explicitly defines a stronger
reaction.

The default `handle_bitcoin_outcome` implementation logs warnings at warning
level, failures at error level, and returns `Ok(())`. This intentionally
consumes outcomes that a protocol does not need to specialize. Individual
protocols may override the method to record a terminal state, emit a
protocol-specific notification, or perform another safe, idempotent reaction.
The outer router should not emit a second copy of the same program-scoped log;
centralized durable reporting remains separate.

Protocols receive the client-owned `ProtocolBitcoinOutcome` abstraction rather
than raw `CoordinatorNews`. This prevents protocol implementations from needing
to handle request-scoped or node-scoped coordinator bookkeeping and keeps the
coordinator crate's representation out of the protocol contract.

The routing rules are:

- ordinary successful `MonitorNews` is delivered to `notify_news`;
- an exceptional, program-owned monitor outcome such as a deep-reorganization
  resend is delivered to `handle_bitcoin_outcome`, never to `notify_news`;
- program-scoped coordinator warnings and failures are mapped to
  `ProtocolBitcoinOutcome` and delivered to `handle_bitcoin_outcome`;
- request-scoped outcomes are reported to the originating requester;
- node-scoped outcomes remain in centralized client reporting;
- operational errors returned by coordinator or monitor calls (`tick`,
  `get_news`, `ack_news`, and similar APIs) are not protocol events. They lack a
  reliable program owner and continue to propagate to the transaction/tick
  error classifier.

Returning `Ok(())` from `handle_bitcoin_outcome` means the event was handled or
intentionally discarded and may be acknowledged. An override should return
`Err` only when processing did not complete, normally because of a transient
infrastructure failure. A deterministic protocol failure must be persisted as a
terminal state and return `Ok(())`; otherwise the same event will be retried
forever.

At the outer event boundary, successful handling, intentional no-op handling,
protocol outcome handling, and coordinator business reporting all end in
`ack_news`. Acknowledgement must remain centralized after the selected action
has succeeded.

Do not add a generic `RetryLater` disposition. Coordinator storage already is
the retry queue: returning `Err` leaves the item unacknowledged. Retry is valid
only for transient infrastructure errors. Persistently malformed local state
must be fatal or explicitly quarantined, not retried forever.

## Reorganization and confirmation-finality policy

Protocol-owned transaction notifications must be registered with a confirmation
trigger in the **6–10 block range**. The exact value is protocol/configuration
specific, but a protocol must not rely on the current one-confirmation fallback.
This policy applies to protocol setup and to subscriptions created later by
runtime protocol paths.

`TransactionNews::resent_due_to_reorg == true` means that the same monitored
transaction previously reached its trigger, was affected by a reorganization,
and later reached the trigger again in another block. With a 6–10 block
trigger, this represents a deep reorganization beyond BitVMX's assumed Bitcoin
finality and should not occur during normal production operation.

The client policy for such an event is:

1. log it at **error** level with the transaction ID, context, confirmation
   count, and block information available in the status;
2. treat it as an exceptional duplicate after assumed finality;
3. for a protocol-owned (`ProgramId`) notification, do not invoke
   `notify_news` again and do not repeat irreversible protocol actions or
   successful-event notifications;
4. deliver a `ProtocolBitcoinFailure::DeepReorg` through the protocol's
   dedicated outcome hook, whose reaction must be safe and idempotent;
5. acknowledge the protocol-owned event atomically after the outcome hook
   succeeds so it does not create a permanent retry loop.

Request-owned API subscriptions are not governed by the protocol finality
threshold; their caller-selected trigger and redelivery contract must be handled
separately. The protocol rule must not silently suppress a `RequestId` event.

This is an alert-and-contain policy, not automatic deep-reorg recovery. A deep
reorganization may invalidate assumptions spanning several protocol actions;
replaying one notification is not a safe repair mechanism. Operational alerting
and intervention are required if this error appears in production.

The finality policy does not remove the need for ordinary handler idempotency.
A rollback before acknowledgement, broker at-least-once delivery, or duplicate
non-reorg input must still not repeat irreversible effects.

## Event classification

### Coordinator calls

| Operation/failure | Outcome |
|---|---|
| `tick`, `is_ready`, or `get_news` succeeds | Continue normally |
| Bitcoin RPC transport outage | Propagate; report the outage once per in-memory outage period; retry later |
| shared/coordinator storage, broker, lock, or rollback failure | Propagate; fatal when state integrity is uncertain |
| deterministic RPC rejection or node misconfiguration | Add typed classification; do not leave it as generic `Other` |
| `ack_news` failure | Propagate and roll back the staged notification/report |

Transport outage detection exists. The taxonomy still needs to distinguish a
terminal operation rejection from an incompatible or misconfigured Bitcoin
node.

### `MonitorNews`

| Event/path | Outcome |
|---|---|
| `Transaction` / `SpendingUTXOTransaction` with `ProgramId` and an existing program | Apply `Program::notify_news`, then ack |
| same event for a program that no longer exists | Log/return typed stale no-op, then ack |
| same event with `RequestId` | Enqueue the API notification to the recorded requester, then ack atomically |
| protocol-owned `Transaction` with `resent_due_to_reorg == true` | Skip `notify_news`, deliver `ProtocolBitcoinFailure::DeepReorg` through the outcome hook, then ack after it succeeds |
| output-pattern or RSK pegin event | Enqueue the L2 notification(s), then ack atomically |
| new-block event | Read the setting fallibly, enqueue the configured notification if enabled, then ack atomically |
| ordinary duplicate already applied by protocol state | Typed no-op, then ack |
| unreadable persisted context | Local invariant/corruption: stop or quarantine explicitly; never retry as generic `Other` forever |
| impossible protocol state transition or corrupt local data | Typed fatal/program-terminal decision; do not use an untyped `InvalidMessage` retry loop |
| storage or broker-outbox failure | Propagate without ack |

A runtime blockchain event must not use setup's `SetupAttemptFailed` path. If a
protocol needs a terminal runtime failure state, define it explicitly rather
than silently acknowledging the event or retrying indefinitely.

### `CoordinatorNews`

These are persisted terminal facts, not commands. The normal outcome is
"report/log and acknowledge," not rollback for business conditions.

| Variant | Current status and required action |
|---|---|
| `DispatchError` | Scoped report and ack are implemented. For program context, also deliver `DispatchFailed`; keep wallet cleanup idempotent. |
| `SpeedupDispatchError` | Scoped report and ack are implemented. For program context, also deliver `SpeedupDispatchFailed`. |
| `TransactionStuckInMempool` | Scoped report and ack are implemented. For program context, also deliver `TransactionStuckInMempool`. |
| `MaxFeeRateReached` | Scoped report and ack are implemented. For program context, also deliver `MaxFeeRateReached`. |
| `EstimateFeerateTooHigh` | Node-scoped report and ack are implemented; add context only if the coordinator can identify one owner. |
| `InsufficientFunds` | Node-scoped report and ack are implemented. |
| `FundingNotAvailable` | Node-scoped report and ack are implemented. |
| `InvalidFundingUtxo` | Node-scoped report and ack are implemented; add source context if available. |
| `TransactionEvicted` | Expected bookkeeping; debug log and ack are implemented. |
| `InvalidCancel` | Currently warning and ack only. Add its original context, report to the request/program, then ack. |
| `InvalidStateTransition` | Currently silently consumed after an error log. Emit a narrow node-scoped invariant diagnostic, quarantine by acknowledging, and alert operators. |
| `TxNotFound` | Currently silently consumed after an error log. Emit a narrow node-scoped invariant diagnostic, quarantine by acknowledging, and alert operators. |

Quarantine is preferred for invariant news over leaving the same persisted fact
unacknowledged across every restart. The diagnostic must make the loss of the
normal coordinator invariant visible before the item is consumed.

Where the coordinator knows the originating context, carry it in the news enum.
In particular, `cancel_transactions` receives a context but
`CoordinatorNews::InvalidCancel` currently drops it. Funding and fee news may
legitimately be node-scoped when a speedup combines or serves multiple parent
transactions, but that must be an explicit design decision.

## Non-transactional concerns

`DispatchError` calls wallet lookup/cancellation before enqueueing the report
and acknowledging the news. The wallet uses a separate SQLite domain, so a
later broker or coordinator failure can cause cancellation to run again.
Pending wallet replacement, cancellation must be idempotent and this exception
must remain documented. In a redesign, move cleanup behind an idempotent
operation key or into the same durable workflow as the coordinator outcome.

The same caveat applies to `wallet.tick()` in the initial update transaction:
a later failure can roll back shared client/coordinator state but not wallet
state. Bitcoin RPC and network side effects are likewise not rollbackable and
must be safe under retry.

## Implementation plan

1. **Enforce finality thresholds.** Require every protocol-owned monitor
   registration to use a configured 6–10 block trigger. Remove the generic
   one-confirmation fallback and update the reject-pegin defaults/examples.
2. **Separate successful and exceptional outcomes.** Keep `notify_news` for
   successful monitor observations. Add severity-preserving
   `ProtocolBitcoinOutcome` types and a default
   `ProtocolHandler::handle_bitcoin_outcome` implementation that logs warnings
   and failures at the corresponding level and returns `Ok(())`. Route only
   program-owned outcomes to this hook.
3. **Handle protocol reorg resends at the event boundary.** Error-log
   `resent_due_to_reorg`, skip `ProgramId` `notify_news` redelivery, invoke the
   dedicated outcome hook, and acknowledge after it succeeds. Preserve the
   separate `RequestId` subscription contract.
4. **Type protocol news outcomes.** Add applied and stale/already-applied
   outcomes and identify every deterministic protocol failure.
5. **Tighten context handling.** Keep missing programs stale, but treat an
   undecodable persisted context as corruption rather than retryable input.
6. **Quarantine coordinator invariants visibly.** Add a node-scoped invariant
   report for `InvalidStateTransition` and `TxNotFound`, then ack.
7. **Improve coordinator news context.** Add context to `InvalidCancel` and to
   other variants where one owner is known.
8. **Make new-block configuration reads fallible.** Storage/type failures must
   prevent acknowledgement rather than silently disabling notifications.
9. **Refine Bitcoin error classification.** Separate transport outage,
   operation rejection, and incompatible/misconfigured node outcomes.
10. **Isolate wallet cleanup.** Preserve current behavior only with an
   idempotency guarantee until wallet redesign.
11. **Remove panic paths from event handlers.** Replace `todo!`, unchecked
    indexing, and event-path `unwrap` calls with typed outcomes.
12. **Keep per-item transactions.** Do not merge an entire news batch into one
    transaction; independent events must continue when one item fails.

## Required tests

1. A monitor notification and its broker response commit atomically with the
   acknowledgement.
2. Broker enqueue or ack failure rolls back both effects and leaves the event
   available for retry.
3. Missing-program monitor news is acknowledged as stale.
4. An unreadable context does not enter an endless nonfatal retry loop.
5. Every protocol-owned monitor registration uses a trigger between 6 and 10
   confirmations, including runtime registrations.
6. A protocol-owned `resent_due_to_reorg` transaction is error-logged, enters
   `handle_bitcoin_outcome` rather than `notify_news`, does not repeat
   successful outgoing effects, and is acknowledged after the outcome hook
   succeeds;
   request-owned behavior is tested separately.
7. An ordinary duplicate is handled as a typed idempotent no-op.
8. Every `CoordinatorNews` business variant is reported/logged once and acked;
   program-scoped warning and failure variants also reach
   `handle_bitcoin_outcome` with the correct severity.
9. `InvalidCancel` is routed to its originating request/program after context is
   added.
10. Coordinator invariant news emits its quarantine diagnostic and is acked.
11. One failed news item does not roll back or prevent independent items in the
    same fetched batch.
12. Bitcoin transport loss retries without ack and emits only one outage report;
    recovery emits one recovery report.
13. Reprocessing `DispatchError` cannot corrupt wallet state or produce a
    non-idempotent cancellation.
14. A new-block setting read failure rolls back and leaves the event available
    for retry.
15. The default `handle_bitcoin_outcome` logs and consumes an unhandled
    program-owned outcome at the correct severity; an infrastructure failure
    returned by an override rolls back and leaves the event unacknowledged.
16. Coordinator/monitor API call errors are classified centrally and are never
    passed to a protocol as event notifications.

The existing generic transaction-boundary tests are useful but do not replace
direct tests through `process_monitor_news` and `process_coordinator_news`. The
coordinator mock should support injected `get_news` and `ack_news` failures.

## Core invariant

> A coordinator business outcome is reported and acknowledged exactly once in
> durable client state, with at-least-once network delivery. A stale or ordinary
> duplicate chain event is acknowledged as a no-op. A reorg resend beyond the
> configured 6–10 block finality threshold is error-logged, contained without
> replaying protocol effects, and acknowledged. Only transient infrastructure
> failure remains unacknowledged for retry; corrupt local state and coordinator
> invariants stop or enter an explicit, visible quarantine path instead of
> retrying forever or being silently consumed.

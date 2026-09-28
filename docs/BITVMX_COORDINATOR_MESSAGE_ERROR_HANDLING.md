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

## Current transaction model

`BitVMX::process_bitcoin_updates` currently has three transaction boundaries:

1. coordinator tick, wallet tick, readiness check, and news fetch run in one
   global storage transaction;
2. every `MonitorNews` item is handled and acknowledged in its own transaction;
3. every `CoordinatorNews` item is handled and acknowledged in its own
   transaction.

This is the correct basic structure. A notification or error report enqueued
through the broker outbox is committed atomically with the corresponding
acknowledgement. A handler or acknowledgement failure rolls both back, and one
bad item does not roll back independently processed items from the same batch.
Actual broker delivery remains at least once.

`run_step` currently catches nonfatal errors after rollback. Therefore a
deterministic error leaves its event unacknowledged and causes it to be retried
and reported on every coordinator cycle. Explicit terminal dispositions are
needed to avoid that loop.

## Desired contract

Introduce a coordinator-event disposition, or an equivalent typed contract:

```rust
pub enum CoordinatorEventDisposition {
    Processed,
    DiscardStale(CoordinatorNoOpReason),
    ReportAndAck(ErrorReport),
}
```

The handler still returns `Result<CoordinatorEventDisposition, BitVMXError>`.
The transaction owner applies the disposition and acknowledges the event in one
place.

- `Processed`: the event's state change or outgoing notification was staged;
- `DiscardStale`: the event cannot affect current state and is intentionally
  consumed;
- `ReportAndAck`: the event is a terminal coordinator outcome; enqueue its
  scoped report and consume it;
- `Err`: local/infrastructure processing did not complete, so roll back and
  leave the event unacknowledged.

Do not add a generic `RetryLater` disposition. Coordinator storage already is
the retry queue: returning `Err` leaves the item unacknowledged. Retry is valid
only for transient infrastructure errors. Persistently malformed local state
must be fatal or explicitly quarantined, not retried forever.

## Event classification

### Coordinator calls

| Operation/failure | Outcome |
|---|---|
| `tick`, `is_ready`, or `get_news` succeeds | Continue normally |
| Bitcoin RPC transport outage | Propagate; report the outage once; retry later |
| shared/coordinator storage, broker, lock, or rollback failure | Propagate; fatal when state integrity is uncertain |
| deterministic RPC rejection or node misconfiguration | Use a new typed classification; do not leave it as generic `Other` forever |
| `ack_news` failure | Propagate and roll back the staged notification/report |

The Bitcoin error taxonomy still needs the distinction already identified by
the API audit: retryable outage, terminal operation rejection, and fatal node
misconfiguration.

### `MonitorNews`

| Event/path | Outcome |
|---|---|
| `Transaction` / `SpendingUTXOTransaction` with `ProgramId` and an existing program | Apply `Program::notify_news`, then ack |
| same event for a program that no longer exists | `DiscardStale`, then ack |
| same event with `RequestId` | Enqueue the API notification to the recorded requester, then ack atomically |
| output-pattern or RSK pegin event | Enqueue the L2 notification(s), then ack atomically |
| new-block event | Enqueue the configured notification if enabled, then ack atomically |
| duplicate/reorg event that protocol state has already applied | Explicit protocol no-op, then ack |
| unreadable persisted context | Local invariant/corruption: stop as fatal, or quarantine explicitly; never retry as generic `Other` forever |
| protocol says event is stale or already applied | Typed no-op, then ack |
| protocol rejects an impossible state transition or corrupt local data | Typed fatal/program-terminal decision; do not use an untyped `InvalidMessage` retry loop |
| storage or broker-outbox failure | Propagate without ack |

`Program::notify_news` currently returns only `Result<(), BitVMXError>`. Audit
all protocol implementations and give them enough typing to distinguish an
idempotent replay from local corruption and transient infrastructure failure.
A runtime blockchain event should not use setup's `SetupAttemptFailed` path.
If protocols require a terminal runtime failure state, define it explicitly
rather than silently acknowledging the event or retrying indefinitely.

The ignored `resent_due_to_reorg` flag also needs an explicit policy. Either
protocol handlers are fully idempotent for reorg redelivery, or the flag must
be passed to them so they can reverse/re-evaluate prior state safely.

### `CoordinatorNews`

These are already persisted terminal facts, not commands. The normal outcome is
"report/log and acknowledge," not rollback for business conditions.

| Variant | Recommended action |
|---|---|
| `DispatchError` | Report `TransactionDispatchFailed` to the context scope; perform only idempotent wallet cleanup; ack |
| `SpeedupDispatchError` | Report scoped failure; ack |
| `TransactionStuckInMempool` | Report scoped warning; ack |
| `MaxFeeRateReached` | Report scoped warning; ack |
| `EstimateFeerateTooHigh` | Report node-scoped configuration/fee condition unless a context is added; ack |
| `InsufficientFunds` | Report node-scoped funding condition unless a context is added; ack |
| `FundingNotAvailable` | Report node-scoped funding condition unless a context is added; ack |
| `InvalidFundingUtxo` | Report node/request scope if source context can be added; otherwise node scope; ack |
| `TransactionEvicted` | Expected bookkeeping; log/debug and ack |
| `InvalidCancel` | Terminal caller rejection. Add its original context so it can be reported to the program/request, then ack |
| `InvalidStateTransition` | Coordinator invariant violation. Return a narrow fatal error rather than logging and silently acknowledging |
| `TxNotFound` | Coordinator bookkeeping invariant violation. Return a narrow fatal error, or a deliberately quarantined terminal diagnostic; do not silently consume it |

Where the coordinator knows the originating context, carry it in the news enum.
In particular, `cancel_transactions` receives a context but
`CoordinatorNews::InvalidCancel` currently drops it. Funding and fee news may
legitimately be node-scoped when a speedup combines or serves multiple parent
transactions, but that should be an explicit design decision.

## Non-transactional concern

`DispatchError` currently calls wallet lookup/cancellation before enqueueing the
report and acknowledging the news. The wallet uses a separate SQLite domain, so
a later broker or coordinator failure can cause cancellation to run again.
Pending wallet replacement, require cancellation to be idempotent and document
this exception. In a redesign, move cleanup behind an idempotent operation key
or into the same durable workflow as the coordinator outcome.

## Implementation plan

1. **Add typed event dispositions.** Centralize report/no-op/application and
   acknowledgement in `src/bitvmx.rs`.
2. **Audit `Program::notify_news`.** Add typed replay/stale outcomes and identify
   every deterministic protocol failure. Introduce a runtime program-failure
   transition if the protocol needs one.
3. **Tighten context handling.** Treat a missing program as stale, but treat an
   undecodable persisted context as local corruption rather than a retryable
   input error.
4. **Use `resent_due_to_reorg`.** Pass it through to protocol handling or prove
   and test that all handlers are safely idempotent without it.
5. **Improve coordinator news context.** Update the sibling coordinator enum and
   producers, starting with `InvalidCancel`, so reports reach the responsible
   request/program where possible.
6. **Promote invariant news.** Map `InvalidStateTransition` and `TxNotFound` to
   narrow local-invariant errors classified as fatal (or implement an explicit
   quarantine policy).
7. **Refine Bitcoin error classification.** Separate transport outage,
   operation rejection, and incompatible/misconfigured node outcomes.
8. **Isolate wallet cleanup.** Preserve the current behavior only with an
   idempotency guarantee until wallet redesign.
9. **Keep per-item transactions.** Do not merge an entire news batch into one
   transaction; independent events should continue even when one item fails.

## Required tests

1. A monitor notification and its broker response commit atomically with the
   acknowledgement.
2. Broker enqueue or ack failure rolls back both effects and leaves the event
   available for retry.
3. Missing-program monitor news is acknowledged as stale.
4. An unreadable context does not enter an endless nonfatal retry loop.
5. Duplicate and reorg monitor notifications do not repeat irreversible
   protocol actions.
6. Every `CoordinatorNews` business variant is reported/logged once and acked.
7. `InvalidCancel` is routed to its originating request/program after context is
   added.
8. Coordinator invariant news stops or quarantines according to the selected
   policy.
9. One failed news item does not roll back or prevent independent items in the
   same fetched batch.
10. Bitcoin transport loss retries without ack and emits only one outage report;
    recovery emits one recovery report.
11. Reprocessing `DispatchError` cannot corrupt wallet state or produce a
    non-idempotent cancellation.

## Core invariant

> A coordinator business outcome is reported and acknowledged exactly once in
> durable client state, with at-least-once network delivery. A stale or duplicate
> chain event is acknowledged as a no-op. Only transient infrastructure failure
> remains unacknowledged for retry; corrupt local state or coordinator invariants
> stop or enter an explicit quarantine path instead of retrying forever.

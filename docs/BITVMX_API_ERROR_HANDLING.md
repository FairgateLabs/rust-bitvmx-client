# BitVMX API error handling

## Purpose

This document records the intended error-handling model for the BitVMX API, the decisions applied to `src/bitvmx_api.rs`, and the remaining risks and follow-up work.

The primary goals are:

- return useful request-specific failures to API clients;
- preserve rollback and retry behavior for system and storage failures;
- keep response delivery centralized and predictable;
- avoid disguising infrastructure failures as business-level responses;
- make it clear when an operation has no immediate response.

## Handler contract

The incoming API message match should produce:

```rust
Result<Option<OutgoingBitVMXApiMessages>, BitVMXError>
```

The meanings are:

- `Ok(Some(response))`: the request completed with an API response, including expected request-level failures such as `ApiError`;
- `Ok(None)`: the request completed successfully but has no immediate API response;
- `Err(error)`: processing did not complete and the error must propagate to the transaction boundary.

After the complete match, the response is sent in one place:

```rust
match result {
    Ok(Some(response)) => self.reply(reply_to, response),
    Ok(None) => Ok(()),
    Err(error) => Err(error),
}
```

This keeps response transport out of individual operation handlers. Handlers that produce responses should return `OutgoingBitVMXApiMessages` rather than calling `reply` or `send_service` themselves.

### Intentional exception: allow-list mutation

`mutate_allow_list` intentionally retains its internal reply callback. Its ordering is important:

1. stage the allow-list change;
2. persist the staged value;
3. send the success response;
4. apply the change to the live in-memory allow list.

Refactoring it into the general return mechanism without preserving this ordering could leave persisted and in-memory state inconsistent, particularly when response delivery fails. It should only be changed as part of a deliberate redesign of that transaction sequence.

### Outbound service messages are not API replies

Not every `send_service` call is an API response. For example, `generate_zkp` sends a job to the prover. Such calls remain inside the operation because they are outbound protocol actions, not responses to the requesting API client.

`send_service` does not immediately transmit the message. It enqueues the message in the broker out queue using the same shared `Storage`, so calls made inside `run_transaction` participate in that transaction and are rolled back with it.

## Error categories

### Request and business errors

Expected failures caused by request data or current business state should:

1. create an appropriate outgoing API response;
2. log the same client-facing message;
3. return `Ok(Some(response))` so the request is considered handled.

When no more specific response exists, use:

```rust
OutgoingBitVMXApiMessages::ApiError(id, message)
```

Examples include:

- invalid signing payloads;
- missing programs;
- invalid setup participants or leader indexes;
- duplicate program identifiers;
- key-manager failures that are not storage failures;
- protocol visualization failures.

Existing domain-specific responses can remain when they communicate the failure more accurately, such as:

- `NotFound`;
- `WalletNotReady`;
- `WalletError`;
- `ProofGenerationError`;
- `BackupResult`.

These responses must not be used to conceal system or storage failures.

### Storage and system errors

Storage, system-resource, poisoned-lock, rollback, broker, and infrastructure failures must propagate as `Err`.

The reason is operational rather than cosmetic. Propagation allows the enclosing storage transaction to:

1. roll back changes;
2. leave the incoming message available for retry;
3. stop or restart the node when required;
4. retry once the unavailable resource recovers.

Converting such an error into `ApiError`, `NotFound`, or another successful outgoing response would cause the transaction to commit and consume the request, preventing rollback and retry.

### Bitcoin node availability

Bitcoin RPC transport failures are system availability failures even though they are classified separately from fatal errors. They should propagate so the current request rolls back and can be retried after the node recovers.

They must not be converted into `NotFound` or an empty proof response.

### Classification ownership

General error classification and reporting belongs at the transaction/tick boundary, not in the API dispatcher. The API dispatcher should return the error produced by the matched operation.

Expected request-level failures should already have been converted into outgoing responses by the relevant operation. Remaining errors should reach `run_transaction` and the tick-level reporter.

Localized checks remain appropriate when an operation intentionally distinguishes business errors from rollback-worthy errors. Current examples are:

- `setup` and `setup_key`, which use `is_fatal` for errors from `Program::new`;
- key-manager operations, which use `KeyManagerError::is_storage_error` so storage failures propagate while ordinary key-manager failures become `ApiError`.

These checks should not become a second general-purpose reporting layer.

## Current implementation decisions

The following behavior has been standardized:

- key-manager API handlers return outgoing messages;
- only key-manager errors identified by `KeyManagerError::is_storage_error` propagate; other key-manager errors become `ApiError`;
- signing, encryption, and decryption request failures return `ApiError`;
- setup handlers return optional outgoing messages;
- fatal setup errors propagate;
- handlers that load programs return `NotFound` without sending it internally;
- wallet API logic is isolated in dedicated functions that return outgoing messages;
- variable, witness, transaction, aggregated-key, ZKP-result, ping, and SPV handlers return outgoing messages;
- `GetTransaction` preserves the coordinator's typed `TransactionStatus::NotFound` response and propagates all coordinator errors;
- every incoming match arm now returns `Result<Option<OutgoingBitVMXApiMessages>, BitVMXError>`;
- the dispatcher performs one normal API reply after the match;
- local request error-report classification was removed from the dispatcher so operation errors propagate to the transaction boundary.

## Remaining issues

### 1. `GetSPVProof` hides coordinator failures

`get_spv_proof` currently returns `SPVProof(txid, None)` for every error returned while retrieving transaction information.

This incorrectly makes an unavailable Bitcoin node look like a transaction without a proof.

Recommended direction:

- propagate coordinator and Bitcoin RPC errors;
- return `SPVProof(txid, None)` only when transaction information was retrieved successfully but confirmed block information is genuinely absent;
- continue propagating failures while constructing the proof itself.

The request now carries a UUID, so a terminal request-level failure can use the current
`ApiError(Uuid, String)` shape. Coordinator and Bitcoin RPC availability failures should still
propagate rather than being converted into an API response.

### 2. `Backup` may hide storage failures

The backup match currently converts every failure into `BackupResult(id, false, error)`.

Some backup failures are valid terminal request failures, such as an invalid path or password. Storage backend failures, however, should propagate so the operation can roll back and retry.

Recommended direction:

- identify typed user/configuration backup errors and return `BackupResult(false, ...)` for them;
- propagate fatal storage and system errors.

### 3. Wallet error classification is deferred

Wallet calls have been moved into dedicated handlers, but wallet errors have intentionally not yet been classified.

Current concerns:

- `receive_address` converts every error into `WalletError`;
- `create_tx` converts every error into `WalletError`;
- storage-backed wallet failures may therefore be consumed instead of rolled back;
- `update_with_tx` already propagates errors.

Recommended direction:

- add or use typed wallet error classification;
- return `WalletError` for request/business failures such as invalid destinations or insufficient funds;
- propagate wallet storage and system failures.

### 4. Inconsistent ZKP data can retry indefinitely

`GetZKPExecutionResult` propagates `InconsistentZKPData` when status says that generation succeeded but the proof or journal is missing.

Because this may represent permanent corruption rather than a transient resource failure, blindly retrying can keep the same request at the front of the queue indefinitely.

Recommended direction:

- classify inconsistent persisted state as fatal if it indicates corruption; or
- return a terminal `ProofGenerationError`/`ApiError` if the node can safely continue.

### 5. Malformed aggregated keys appear not ready

`GetAggregatedPubkey` returns `AggregatedPubkeyNotReady` when the stored variable exists but cannot be decoded as a public key.

This can cause clients to poll forever for data that is corrupt rather than pending.

Recommended direction:

- reserve `AggregatedPubkeyNotReady` for an absent value;
- propagate corrupt persisted data or return a terminal `ApiError`, depending on whether corruption should stop the node.

### 6. Permanent unhandled errors can block retries

All remaining `Err` values now propagate and roll back the incoming message. This is necessary for transient system failures, but a permanent request error that was not converted into an outgoing response can be retried forever and block later messages.

Therefore every expected validation and business failure must be explicitly converted into a terminal response. `Err` should mean that retrying later may succeed, or that the node must stop.

## Transaction and delivery behavior

### API replies are transactionally enqueued

Although `reply` is called before `run_transaction` commits, it does not deliver the response over the network at that point. `reply` calls `broker_channel.send_service`, and `send_service` appends the message to the broker out queue in the shared `Storage`.

The incoming queue removal, API state changes, and outgoing response enqueue therefore belong to the same global storage transaction:

- if the handler or `reply` returns an error, the transaction rolls back and the response is not queued;
- if the final commit fails, the response enqueue is not committed;
- if the transaction commits, consuming the request, changing persisted state, and queuing the response become visible together;
- broker queue processing delivers the committed response later.

The broker out queue already acts as the transactional outbox. The earlier concern that a client could receive the API response before the API transaction commits does not apply to this implementation.

Centralizing `reply` after the match remains useful for consistency, but it is not what provides commit safety. Commit safety comes from the broker queue sharing the same transactional storage.

### Delivery is at least once

Actual broker delivery occurs later in `process_broker_queues`, after outgoing work has committed. Network delivery itself cannot be rolled back. If transport sends a message and then fails before its queue update commits, the queue item can be retried and delivered more than once.

Consumers should therefore tolerate duplicate responses and protocol messages, preferably by using their request or job identifiers as idempotency keys.

### Most apparent external actions are staged

Several API operations that look external are also staged in shared storage:

- prover dispatch through `send_service` queues a broker message transactionally;
- Bitcoin coordinator dispatch registers a transaction for later dispatch;
- Bitcoin monitor subscriptions are registered through coordinator/monitor state.

These should still be checked individually to confirm that every implementation uses the shared transactional `Storage` and does not perform an irreversible network action before returning. Stable request, transaction, and job identifiers remain valuable for retry safety.

### Live in-memory state is not transactional

Rollback only restores storage. It does not restore mutations already applied to live Rust objects. Areas requiring care include:

- the live comms allow list;
- wallet state changed in memory;
- setup/program state changed in memory;
- the `shutdown` flag;
- any dependency that combines a storage write with an in-memory mutation.

The allow-list helper's ordering resolves the practical in-memory consistency problem:

1. it applies the change to a staged clone;
2. it writes that staged value through the transactional storage;
3. it transactionally enqueues the response;
4. only then does it apply the same change to the live allow list.

A storage-write or response-enqueue failure therefore returns before the live value is modified, and the enclosing transaction rolls back the staged writes. After the live value is modified, the only remaining transactional step is the final commit. A commit failure is classified as fatal, so the node stops rather than continuing with divergent live state; restart reconstructs the allow list from committed storage.

This reasoning relies on commit failures remaining fatal and on the mutation closure being deterministic and free of external side effects, because it is invoked once for the staged clone and once for the live value.

## API request correlation

All production incoming API message variants now carry a UUID. The UUID was added to `SetFundingUtxo`,
`SubscribeToOutputPattern`, `SubscribeToRskPegin`, `GetSPVProof`, and `Shutdown` so future terminal
request failures can use `ApiError(Uuid, String)` consistently.

This is a wire-format compatibility break: callers must include the UUID even for fire-and-forget
operations and operations whose successful response is an asynchronous event. The README API table
and `docs/CHANGELOG.md` record the new shapes.

## No-response operations

Several successful operations currently return `Ok(None)`, including variable updates, witness updates, subscriptions, and transaction dispatches.

This may be intentional for asynchronous operations, but clients cannot distinguish successful acceptance from a missing response. Each operation should be documented as one of:

- synchronous with a response;
- asynchronous with a later event;
- fire-and-forget.

If acknowledgement is required, add a specific outgoing response rather than using a generic success string.

## Logging guidance

For terminal request errors:

- construct one message;
- log that exact message;
- place the same message in `ApiError` or the applicable domain response.

For propagated errors:

- avoid repeatedly logging and reclassifying at each layer;
- add operation context only where useful;
- let the transaction/tick boundary perform final severity reporting.

This avoids duplicate reports while preserving the original error source chain for classification.

## Recommended next steps

1. Fix `GetSPVProof` so coordinator/RPC failures propagate.
2. Separate terminal backup request errors from storage/system failures.
3. Add wallet error classification and propagate wallet storage failures.
4. Decide whether inconsistent ZKP and malformed aggregated-key data are fatal corruption or terminal API failures.
5. Audit every remaining `Err` path to ensure permanent request errors cannot poison the retry queue.
6. Audit in-memory mutations and any dependency calls that may bypass the shared transactional storage.
7. Verify idempotency of broker consumers because transport delivery is at least once.
8. Update the README API response table for all newly documented `ApiError` outcomes.
9. Add tests covering:
   - request errors atomically consuming the input and enqueuing the response;
   - storage failures rolling back both the incoming request and outgoing response;
   - Bitcoin RPC unavailability rolling back for retry;
   - response-enqueue failure rolling back storage;
   - duplicate broker delivery handling;
   - allow-list write and response-enqueue failures leaving the live value unchanged;
   - commit failures stopping the node before divergent live allow-list state can continue operating.

# BitVMX peer-message error handling

## Purpose

This document proposes an error-handling model for messages received from other
BitVMX operators. It focuses on:

- `src/signature_verifier.rs`;
- `src/leader_broadcast.rs`;
- `src/bitvmx.rs`;
- `src/message_queue.rs`;
- the setup engine and setup steps under `src/program/setup/`;
- the TLS identity and allow-list enforcement provided by the sibling
  `rust-bitvmx-broker` repository.

The central requirement is to distinguish between:

1. a message that is legitimate but cannot be processed yet;
2. a message that can never become legitimate and must be discarded;
3. a local or infrastructure failure that must propagate and roll back.

This follows the same general principle as
[`BITVMX_API_ERROR_HANDLING.md`](BITVMX_API_ERROR_HANDLING.md): expected input
failures must terminate at the input boundary, while failures for which rollback
or retry may help must remain errors.

## Broker trust guarantees

The broker provides the first authentication layer.

For peer connections, the broker:

1. performs a mutual TLS handshake;
2. obtains the public-key fingerprint from the peer certificate;
3. checks that fingerprint against the allow list, optionally including an IP
   restriction;
4. constructs the sender `Identifier` from the authenticated TLS fingerprint.

The broker does not accept a caller-supplied sender public-key hash. Its RPC
implementation constructs the sender itself:

```rust
let from = Identifier {
    pubkey_hash: self.client_pubkey_hash.clone(),
    id: from_id,
};
```

Consequently, an `Identifier.pubkey_hash` delivered by the broker identifies
the TLS-authenticated connection that submitted the message.

The client currently uses `config.comms.priv_key` both to create its broker TLS
certificate and to import the RSA key used for application-level message
signatures. The TLS identity and application signing identity are therefore
intended to represent the same operator.

### What TLS and the allow list guarantee

They establish that:

- the connection possesses the private key corresponding to the authenticated
  fingerprint;
- the fingerprint is permitted by the local allow list;
- a sender cannot simply claim another `pubkey_hash` in a broker request;
- direct transport confidentiality and integrity are protected by TLS.

### What TLS and the allow list do not guarantee

They do not establish that:

- the peer participates in a particular program;
- the peer is the leader of that program;
- the message is valid for the current setup step;
- the payload is correctly constructed;
- an allowed peer behaves honestly;
- an embedded message forwarded by a leader was authored by its claimed
  original sender.

An allow-listed peer is authorized to establish a connection. It is not
automatically authorized for every program or every message type.

## Trust layers

Peer-message processing should explicitly preserve three trust layers.

### 1. Broker/TLS authentication

The broker supplies the authenticated immediate sender through `Identifier`.
The client should treat that identifier as transport-authenticated rather than
as an untrusted field parsed from the payload.

### 2. Program authorization

The client must independently verify that:

- the authenticated sender belongs to `program.participants`;
- the sender has the role required by the operation;
- a `Broadcasted` envelope came from the configured leader;
- the message type is permitted for the program and current setup state.

### 3. Application signatures

For direct messages, RSA verification overlaps with TLS authentication. It
still provides defense in depth and protects messages that pass through broker
storage or are persisted for later processing.

For leader broadcasts, application signatures are essential. TLS authenticates
the immediate sender, which is the leader, but each
`OriginalMessage.sender_pubkey_hash` is a claim carried inside the envelope.
The embedded signature proves that the claimed original participant authored
that original message.

## Desired processing contract

Incoming peer-message handlers should produce:

```rust
Result<InboundMessageDisposition, BitVMXError>
```

A proposed disposition is:

```rust
pub enum InboundMessageDisposition {
    Processed,
    RetryLater(RetryReason),
    Discard(DiscardReason),
}
```

The meanings are:

- `Processed`: the message was accepted and applied;
- `RetryLater`: the unchanged message may become processable after temporary
  prerequisites arrive;
- `Discard`: the message is permanently invalid, unauthorized, stale, or
  redundant and must be consumed without retry;
- `Err`: local processing did not complete and the enclosing transaction must
  roll back.

A first incremental implementation may add a reason-free `Discarded` variant
to the existing `MessageDisposition`. Typed reasons are preferable because they
make policy, logging, and tests explicit.

## Error categories

### Retryable peer-message conditions

Use `RetryLater` only when waiting can make the same message processable:

- the sender's application verification key has not arrived yet;
- the program has not yet been installed locally;
- the message arrived before the setup step that consumes it;
- an earlier protocol state is still being produced;
- another explicitly identified temporary prerequisite is absent.

Retryable messages must use the bounded retry queue. Retry state must survive
requeueing, and only retryable conditions should consume retry attempts.

### Permanently rejected peer messages

Use `Discard` when waiting cannot make the message valid:

- malformed outer encoding or JSON structure;
- unsupported version or message type;
- malformed RSA signature encoding;
- RSA signature mismatch;
- malformed verification-key announcement;
- verification-key fingerprint mismatch;
- authenticated sender is not a participant in the program;
- a broadcast sender is not the configured leader;
- an embedded original sender is not a participant;
- invalid embedded original signature;
- embedded message type is not permitted;
- malformed or cryptographically invalid setup contribution;
- duplicate contribution;
- stale contribution for an already completed step.

Discarding means logging the rejection and returning success to the enclosing
transaction so the broker input is consumed. It must not mean propagating an
error that restores the same deterministic failure to the front of the queue.

A discard may also produce a scoped peer-fault record or metric. Such
observability must not turn the rejection into a node-level processing error.

### Local and infrastructure failures

These remain `Err` and must propagate:

- storage read, write, or commit failure;
- broker queue failure;
- poisoned locks;
- key-manager internal or storage failures;
- failure to persist a retryable message;
- corrupt or incompatible local program state;
- transaction rollback failure;
- other local resource or infrastructure failures.

Propagation lets `run_transaction` roll back the input removal and any staged
state changes.

## Current behavior and risks

### Invalid signatures propagate

`SignatureVerifier::verify_and_get_key` currently distinguishes a missing key
from an invalid signature through `BitVMXError` variants. `BitVMX` converts
`MissingVerificationKey` to `Ok(false)`, but propagates `InvalidSignature`.

Because comms processing is transactional, propagation restores the invalid
input. The same bad signature can then be retried indefinitely and repeatedly
reported as a node error.

Invalid signatures are authenticated peer faults and should produce `Discard`,
not `Err`.

### `Broadcasted` envelopes bypass normal signature verification

`BitVMX::process_msg` dispatches `CommsMessageType::Broadcasted` before the
normal application-signature verification path.

TLS already authenticates the immediate sender, so this is not an unauthenticated
network path. Nevertheless, the current behavior is inconsistent because:

- every serialized message carries an application signature;
- comments in `leader_broadcast.rs` state that the leader signature was already
  verified;
- direct non-broadcast messages are application-signature verified;
- application verification protects against modification outside the live TLS
  connection.

At minimum, the authenticated sender must be checked against the configured
program leader. Preferably, the outer application signature should also be
verified for consistency and defense in depth.

### Verification-key bootstrap

A `VerificationKey` announcement currently bypasses normal message-signature
verification. The client instead checks:

```text
hash(announced application key) == authenticated sender fingerprint
```

Given that the TLS and application identities use the same RSA private key,
this is a valid bootstrap design if both sides calculate the fingerprint from
the same canonical public-key representation. TLS has already proved possession
of the corresponding private key.

Self-signature verification of the announcement may be retained as defense in
depth, but it is not the fundamental bootstrap requirement. The essential
invariant is the fingerprint comparison against the broker-authenticated
identifier.

A compatibility test must prove that these produce identical values:

- broker `Cert::get_pubk_hash()`;
- client `compute_pubkey_hash()` applied to the announced public key.

A future broker API could expose the authenticated peer public key or
certificate with received messages. Since the TLS and application keys are the
same, this could remove the verification-key announcement race. The current
broker interface exposes only the authenticated fingerprint, so announcements
remain necessary for now.

`VerificationKeyRequest` may remain unsigned as an explicit bootstrap
exception, provided its authenticated sender is a participant in the referenced
program and its payload is structurally valid.

### Ambiguous boolean results

Several APIs encode different meanings as `bool`:

- signature verification uses `false` for an invalid signature;
- original-message verification uses `false` for a missing key;
- setup-step `verify_received` uses `false` for data that did not verify;
- setup-step `can_advance` uses `false` for a temporary not-ready state.

These meanings must not share one control-flow representation. In particular,
an invalid contribution and an absent key require opposite handling: discard
versus retry.

### Broadcast processing conflates temporary and permanent failures

Current broadcast processing:

- queues an embedded original when its verification key is missing;
- propagates malformed structures and known invalid signatures;
- rejects the whole broadcast transaction when one embedded message is invalid;
- uses `push_new` for embedded messages, creating fresh retry state.

The comments in `tests/leader_broadcast_test.rs` that describe missing-key
originals being silently dropped are stale relative to the current source. The
current implementation queues such originals, and the test documentation should
be updated.

### Deterministic duplicates are retried

Some duplicate or already-processed setup contributions return `RetryLater`.
These messages cannot become useful by waiting. They consume retry attempts and
may eventually trigger setup failure even though they should simply be consumed
as duplicates.

### `InvalidMessage` is too broad

`BitVMXError::InvalidMessage` currently covers untrusted malformed payloads,
invalid setup contributions, corrupt persisted state, local invariant failures,
and some lookup failures.

It is therefore unsafe to classify every `InvalidMessage` globally as
Discard. Classification must be explicit at the peer-input boundary, using
typed outcomes or dedicated narrow errors rather than string matching.

## Authentication outcome

Signature verification should return an explicit result instead of
`Result<bool, BitVMXError>`:

```rust
pub enum AuthenticationOutcome {
    Verified,
    MissingKey { peer: PubkHash },
    Rejected(AuthenticationRejection),
}

pub fn authenticate_message(
    /* message context */
) -> Result<AuthenticationOutcome, BitVMXError>;
```

Expected mappings are:

- key found and signature valid: `Verified`;
- key not yet stored: `MissingKey`;
- malformed signature or mismatch: `Rejected`;
- storage or key-manager failure: `Err`.

This also allows key retrieval and signature verification to be performed once
rather than through overlapping helper calls.

## Recommended processing pipeline

`BitVMX::process_msg` should use the following stages.

### 1. Decode the outer envelope

- malformed input: `Discard`;
- local/system failure: `Err`.

Pure decoding must happen before effectful state changes.

### 2. Load the program and resolve the authenticated sender

- program may legitimately appear later: bounded `RetryLater`;
- sender is not a program participant: `Discard`;
- local program-state read or deserialization failure: `Err`.

### 3. Authenticate the application message

For messages requiring application signatures:

- key absent: request the key and return `RetryLater`;
- invalid signature: `Discard`;
- valid signature: continue;
- storage/key-manager failure: `Err`.

This stage should include `Broadcasted` envelopes.

### 4. Handle verification bootstrap messages

For `VerificationKey`:

1. deserialize the announcement;
2. compute the announced key fingerprint;
3. compare it with the broker-authenticated sender fingerprint;
4. optionally verify its self-signature for defense in depth;
5. store the key only after validation succeeds.

For `VerificationKeyRequest`, apply the documented unsigned bootstrap exception
but still validate program membership and payload structure.

### 5. Enforce message-specific authorization

- `Broadcasted` must come from the configured leader;
- regular setup messages must come from participants;
- unexpected message kinds or roles are discarded.

### 6. Validate and process the payload

- temporary ordering/readiness issue: `RetryLater`;
- malformed or cryptographically invalid peer contribution: `Discard`;
- local/system failure: `Err`.

### 7. Apply the disposition centrally

- `Processed`: commit;
- `Discard`: log and commit;
- `RetryLater`: enqueue with preserved bounded retry state and commit;
- `Err`: roll back.

## Leader-broadcast processing

After authenticating the outer leader envelope, each embedded original should
be evaluated against the program.

For each `OriginalMessage`:

1. confirm the claimed sender is a program participant;
2. confirm the embedded type is allowed and agrees with the envelope type;
3. retrieve the claimed sender's application verification key;
4. defer if the key is missing;
5. discard if the original signature or structure is invalid;
6. queue or process if valid;
7. propagate only local or infrastructure failures.

Embedded `VerificationKey`, `VerificationKeyRequest`, and `Broadcasted` message
types should not be accepted as normal originals.

### Independent versus atomic policy

The recommended policy is to process embedded originals independently:

- valid originals progress;
- missing-key originals are deferred;
- invalid originals are discarded.

This prevents one bad contribution from blocking valid siblings.

If protocol security requires all-or-nothing acceptance, that policy must be
explicitly documented. Even in that model, a permanently invalid broadcast
must be consumed as `Discard`, not propagated and retried forever.

### Retry accounting

Repeated processing must not create fresh retry budgets through unrestricted
`MessageQueue::push_new` calls. The implementation should either:

- preserve the existing `QueuedMessage.retry_state`;
- provide a `push_deferred` API that records subsequent attempts correctly; or
- retry the original envelope atomically while preventing duplicate processing
  of already accepted originals.

Missing-key requests should be deduplicated or throttled so each retry does not
produce an unnecessary new request.

## Setup-step outcomes

`SetupStep::verify_received` should not return `Result<bool, BitVMXError>`.
Use an explicit result such as:

```rust
pub enum SetupMessageOutcome {
    Accepted,
    NotReady(SetupRetryReason),
    Rejected(SetupRejectReason),
}
```

`receive_current_step_data` should map these outcomes as follows:

- `Accepted`: store data and mark the participant complete;
- `NotReady`: return `RetryLater`;
- `Rejected`: return `Discard`;
- `Err`: propagate local or infrastructure failures.

The setup steps requiring audit include:

- `keys_step.rs`;
- `nonces_step.rs`;
- `signatures_step.rs`;
- `garbler_step.rs`;
- related aggregated-key processing.

Malformed values, bad proofs, inconsistent declarations, and invalid
cryptographic contributions are rejections. Missing earlier state and genuine
step-order races are retryable. Storage failures and local invariant corruption
remain errors.

A rejected peer message should not automatically become
`SetupAttemptFailed`. Whether repeated authenticated peer faults should produce
a separate terminal program-failure policy is a protocol decision, but it must
not be implemented by rolling back and retrying the same invalid input.

## Peer-fault observability

Since the broker authenticates the immediate sender, discard logs can safely
attribute direct faults to that fingerprint.

A useful structure is:

```rust
pub struct PeerMessageFault {
    pub authenticated_peer: PubkHash,
    pub program_id: Option<Uuid>,
    pub message_type: Option<CommsMessageType>,
    pub reason: PeerMessageFaultReason,
}
```

For embedded originals, logs should distinguish:

- the authenticated forwarding leader;
- the claimed original sender;
- whether rejection occurred before or after original-signature verification.

Peer faults may be counted or reported through a dedicated scoped mechanism.
They should not be reported as generic node-level nonfatal errors.

## File-by-file implementation plan

### `src/types/mod.rs`

Extend `MessageDisposition` with `Discard`, preferably with typed retry and
discard reasons.

### `src/signature_verifier.rs`

- introduce `AuthenticationOutcome`;
- represent missing keys as a retry outcome rather than a general error;
- represent malformed or invalid signatures as rejection outcomes;
- preserve storage and key-manager failures as `Err`;
- centralize key-request behavior;
- integrate or remove the currently separate
  `handle_missing_verification_key` path;
- remove or correct `known_count`, which is currently reported as zero;
- document the TLS fingerprint binding used by key announcements.

### `src/bitvmx.rs`

- authenticate and authorize `Broadcasted` before special dispatch;
- resolve the sender against program participants;
- confirm the broadcast sender is the configured leader;
- apply message dispositions centrally;
- consume rejected peer input;
- queue only genuinely retryable messages;
- preserve bounded retry state.

### `src/leader_broadcast.rs`

- return explicit per-original outcomes;
- validate embedded senders against program participants;
- validate embedded message types;
- distinguish missing keys from invalid signatures;
- discard invalid peer content without propagating it;
- preserve storage errors as `Err`;
- implement and document the independent or atomic policy;
- avoid resetting retry budgets.

### `src/program/setup/setup_step.rs`

Replace `verify_received -> Result<bool, BitVMXError>` with a typed setup-message
outcome.

### `src/program/setup/setup_engine.rs`

- reserve retry for genuine readiness conditions;
- discard deterministic invalid data;
- discard duplicate and stale contributions;
- prevent peer-validation failures from being converted into generic setup
  transaction failures.

### `src/message_queue.rs`

- add a clear API for deferring an existing message while preserving retry
  state;
- optionally persist retry reasons;
- increment attempts only for retryable conditions;
- support deduplication or throttling of verification-key requests.

### `src/errors.rs`

Do not solve the classification problem by globally reclassifying
`InvalidMessage`. If error wrappers are necessary, keep them narrow and typed.
Control-flow outcomes should preferably remain dispositions rather than general
`BitVMXError` variants.

### `tests/leader_broadcast_test.rs`

Update stale comments describing missing-key originals as silently dropped.
The current source queues those originals, although retry accounting and error
classification still need improvement.

## Required tests

### Broker identity and fingerprint compatibility

1. Prove that the broker derives the sender from the TLS certificate rather
   than caller-controlled message data.
2. Prove that a caller cannot submit a message under another fingerprint.
3. Prove that a non-allow-listed certificate is rejected before application
   processing.
4. Prove that broker `Cert::get_pubk_hash()` and client
   `compute_pubkey_hash()` agree for the same RSA key.

### Direct messages

1. A missing verification key queues the message, requests the key, and later
   permits processing.
2. An invalid signature is consumed and is not queued.
3. A malformed payload is consumed and is not queued.
4. An allow-listed but non-participant sender is discarded.
5. A storage failure during verification rolls back input consumption.
6. A duplicate contribution is discarded without consuming retry attempts.

### Verification-key messages

1. A valid announcement whose fingerprint matches the TLS-authenticated sender
   is stored.
2. A fingerprint mismatch is discarded and not stored.
3. A malformed announcement is discarded.
4. A verification-key request is accepted only from a participant in the
   referenced program.
5. A storage failure while storing a valid key propagates and rolls back.
6. If self-signature verification is retained, an invalid self-signature is
   discarded.

### Broadcast messages

1. A broadcast is accepted only from the configured leader.
2. An allow-listed participant that is not the leader cannot send a broadcast.
3. The outer application signature is verified if that defense-in-depth policy
   is retained.
4. A malformed envelope is consumed.
5. A missing embedded key defers the original.
6. An invalid embedded signature is discarded.
7. A leader cannot forge an embedded original from another participant.
8. A mixed broadcast handles valid, deferred, and invalid originals according
   to the documented policy.
9. A queue or storage failure rolls back all staged queue changes.
10. Repeated missing-key processing respects the retry budget.

### Transaction behavior

Tests should verify both the handler result and storage effects:

- terminal rejection removes the broker inbox item;
- retryable input atomically removes the inbox item and adds a pending entry;
- infrastructure failure leaves the inbox item available for retry;
- rejected peer input does not generate a generic node-level error report;
- retry exhaustion follows the explicit setup-failure policy.

## Recommended implementation order

1. Introduce explicit authentication outcomes.
2. Add `Discard` to peer-message disposition and centralize its handling.
3. Convert direct malformed/signature failures from `Err` to `Discard`.
4. Enforce participant and leader authorization using the TLS-authenticated
   sender identifier.
5. Bring the outer broadcast path under the normal authentication pipeline.
6. Refactor embedded-original processing to distinguish verified, missing-key,
   rejected, and system-error outcomes.
7. Preserve retry state and deduplicate key requests.
8. Refactor setup-step boolean verification results.
9. Add broker-integrated and transaction-level tests.
10. Update stale reliability documentation and test comments.

## Core invariant

The intended invariant is:

> TLS and the allow list establish which permitted network peer submitted a
> message. Program authorization determines whether that authenticated peer may
> perform the requested action. Application validation determines whether the
> message is legitimate. A missing temporary prerequisite causes bounded retry;
> invalid data from an authenticated peer is consumed as a discardable peer
> fault; and only local or infrastructure failures propagate for rollback.

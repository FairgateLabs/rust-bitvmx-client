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

Peer protocol messages are meaningful only while the program is in its setup
phase. Once setup is complete, all subsequently delivered peer protocol
messages are stale and must be consumed without further protocol processing.

During setup, the central requirement is to distinguish between:

1. a message that is legitimate but cannot be processed yet;
2. a repeated or otherwise redundant delivery caused by the broker's
   at-least-once semantics, which must be consumed idempotently;
3. a non-replay peer fault that makes setup untrustworthy and must fail the
   program setup and notify L2;
4. a local or infrastructure failure that must propagate and roll back.

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
    DiscardNoOp(NoOpReason),
    FailSetup(PeerSetupFault),
}
```

The meanings are:

- `Processed`: the message was accepted and applied;
- `RetryLater`: the unchanged message may become processable after temporary
  prerequisites arrive;
- `DiscardNoOp`: processing the message cannot change program state because the
  participant contribution was already accepted, or because setup is already
  complete or failed; it must be consumed idempotently;
- `FailSetup`: an authenticated setup participant supplied a non-replay invalid
  message; setup must enter its terminal failed state and L2 must be notified;
- `Err`: local processing did not complete and the enclosing transaction must
  roll back.

A generic `Discard` is too broad for setup traffic because it would hide the
important distinction between harmless no-op delivery and a protocol fault.
Inputs that cannot be associated safely with a program, such as an undecodable
outer frame, may still be dropped at the transport boundary because there is no
trustworthy setup context to fail.

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

### Harmless repeated, redundant, and stale messages

Use `DiscardNoOp` when processing the message cannot alter program state:

- that participant's contribution for the relevant setup step was already
  accepted;
- the relevant leader envelope or embedded participant contribution was already
  handled;
- setup is already complete, so all peer protocol messages are stale;
- setup is already failed, so later deliveries cannot change its terminal
  state.

The implementation does not need to prove byte-for-byte replay identity when
that is not straightforward. If setup state already records the participant as
completed for the relevant step and another message from that participant would
not be applied, consume it as `DiscardNoOp`, even if its payload differs. This
preserves idempotency without adding message hashes or replay records to
storage.

The no-op decision must happen before parsing or validating payload portions
that are no longer relevant. It logs at debug or info level and commits
consumption of the broker input. It must not consume retry attempts, mutate the
program, or notify L2 of another setup failure.

### Peer faults that fail setup

During active setup, use `FailSetup` when an expected participant whose
contribution is still pending submits a message that cannot become valid later:

- unsupported version or message type in an otherwise attributable message;
- malformed RSA signature encoding;
- RSA signature mismatch;
- malformed verification-key announcement;
- verification-key fingerprint mismatch;
- a participant sends a leader-only broadcast but is not the configured
  leader;
- invalid embedded original signature;
- an embedded sender is not valid for the program;
- embedded message type is not permitted;
- malformed or cryptographically invalid setup contribution;
- another authenticated participant protocol violation makes setup state
  untrustworthy.

`FailSetup` must consume the offending event, persist the program's terminal
failed state, and enqueue the existing setup-failure notification to L2. It
must not propagate the peer-validation error through `run_transaction`, because
that would replay the same deterministic failure forever.

An authenticated sender that is not a participant should normally be rejected
at the authorization boundary without allowing it to fail somebody else's
program. This prevents an unrelated allow-listed peer from causing a setup
denial of service. The rejection should be logged and consumed. If project
policy requires reporting such attempts, use a separate security event rather
than a program setup failure.

Completely malformed outer input that cannot be associated reliably with a
program or participant is likewise consumed at the transport boundary. There
is no trustworthy program context to mark failed.

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

### Invalid signatures still propagate at the caller boundary

`SignatureVerifier::authenticate_message` now distinguishes `Verified`,
`MissingKey`, and `Rejected` outcomes. Missing keys are therefore no longer
represented as general errors in the authentication path, and malformed
signatures, signature mismatches, and message-reconstruction failures are typed
authentication rejections.

The direct-message and embedded-original callers have been migrated to this
API. As an intermediate state, however, they still convert `Rejected` back into
`BitVMXError::InvalidSignature`. Because comms processing is transactional,
propagation restores the invalid input. The same bad signature can therefore
still be retried indefinitely and repeatedly reported as a node error until the
`FailSetup` disposition is implemented.

During active setup, an invalid signature from an expected participant whose
contribution is still pending should produce `FailSetup`, not `Err`. The event
is consumed, setup is marked failed, and L2 is notified. If that participant's
contribution was already accepted and another message cannot alter state, it is
instead `DiscardNoOp` without requiring exact replay comparison.

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

Several APIs still encode different meanings as `bool`:

- the leader-broadcast adapter currently converts an embedded original's
  `MissingKey` authentication outcome to `false`;
- setup-step `verify_received` uses `false` for data that did not verify;
- setup-step `can_advance` uses `false` for a temporary not-ready state.

Top-level signature authentication no longer uses a boolean result. The
remaining meanings must not share one control-flow representation. In
particular, an invalid contribution and an absent key require opposite handling:
fail setup versus retry.

### Broadcast processing conflates temporary and permanent failures

Current broadcast processing:

- queues an embedded original when its verification key is missing;
- propagates malformed structures and known invalid signatures;
- rejects the whole broadcast transaction when one embedded message is invalid;
- uses `push_new` for embedded messages, creating fresh retry state.

The stale comments in `tests/leader_broadcast_test.rs` that described
missing-key originals as silently dropped have been updated to match the current
queueing behavior.

### Redundant deliveries are retried

Some duplicate or already-processed setup contributions return `RetryLater`.
Once setup state records that participant's contribution as accepted, another
message for that same participant and step cannot become useful by waiting and
should be consumed as `DiscardNoOp`.

No byte-for-byte comparison or persisted message fingerprint is required. The
important property is that the repeated message cannot be applied or mutate the
program.

### `InvalidMessage` is too broad

`BitVMXError::InvalidMessage` currently covers untrusted malformed payloads,
invalid setup contributions, corrupt persisted state, local invariant failures,
and some lookup failures.

It is therefore unsafe to classify every `InvalidMessage` globally as a replay,
setup fault, or infrastructure failure. Classification must be explicit at the
peer-input boundary, using typed outcomes or dedicated narrow errors rather
than string matching.

## Authentication outcome

The first implementation step is complete. Signature authentication now returns
an explicit result instead of `Result<bool, BitVMXError>`:

```rust
pub enum AuthenticationOutcome {
    Verified,
    MissingKey { peer: PubkHash },
    Rejected(AuthenticationRejection),
}

pub enum AuthenticationRejection {
    MessageReconstruction { reason: String },
    MalformedSignature,
    SignatureMismatch,
}

pub fn authenticate_message(
    /* message context */
) -> Result<AuthenticationOutcome, BitVMXError>;
```

The implemented mappings are:

- key found and signature valid: `Verified`;
- key not yet stored: `MissingKey`;
- malformed signature, signature mismatch, or message-reconstruction failure:
  `Rejected`;
- storage or key-manager failure: `Err`;
- `VerificationKey` and `VerificationKeyRequest`: `Verified` as bootstrap
  exceptions, with announcement fingerprint validation performed separately.

`construct_message` now returns the narrow `MessageConstructionError` rather
than `BitVMXError`. Its failures depend only on message input and cannot carry a
storage or infrastructure error, so authentication can classify every
construction failure as `Rejected` without matching broad `BitVMXError`
variants. Outbound message construction converts this narrow error back to the
corresponding `BitVMXError` where needed.

`BitVMX::process_msg` and embedded-original verification call
`SignatureVerifier::authenticate_message` directly. The previous
`verify_and_get_key` helper and the forwarding authentication method on
`BitVMX` have been removed. Key retrieval and signature verification therefore
happen once in the authentication path.

The remaining work is for callers to map `Rejected` to `FailSetup` only after
establishing that the message is attributable to an expected participant in an
actively setting-up program. This prevents unrelated allow-listed peers from
failing a program.

## Recommended processing pipeline

`BitVMX::process_msg` should use the following stages.

### 1. Decode the outer envelope

- completely undecodable input with no trustworthy program context: consume at
  the transport boundary;
- decodable program and sender context followed by malformed setup content:
  classify after the lifecycle and participant checks, normally as
  `FailSetup`;
- local/system failure: `Err`.

Pure decoding must happen before effectful state changes. Where possible,
decoding should preserve enough trusted envelope context to attribute a
malformed setup payload without treating arbitrary bytes as a program fault.

### 2. Load the program and apply the lifecycle gate

- program may legitimately appear later: bounded `RetryLater`;
- setup complete or already failed: `DiscardNoOp` without further protocol
  processing;
- setup active: continue;
- local program-state read or deserialization failure: `Err`.

Then resolve the authenticated sender and check whether the message can still
change setup state:

- sender is a program participant with a pending contribution: continue;
- sender's relevant direct contribution was already accepted: `DiscardNoOp`
  before unnecessary payload validation;
- sender is not a participant: consume and log as an unauthorized attempt, but
  do not let it fail another program;
- local lookup/storage failure: `Err`.

### 3. Authenticate the application message

For messages requiring application signatures:

- key absent: request the key and return `RetryLater`;
- invalid signature from an expected active-setup participant: `FailSetup`;
- valid signature: continue;
- storage/key-manager failure: `Err`.

This stage should include `Broadcasted` envelopes. A broadcast cannot be
classified as a no-op merely because the leader's own contribution was already
accepted: it may carry still-pending contributions from other participants. A
broadcast is a no-op only when setup is terminal or every relevant embedded
contribution is already represented in setup state.

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

- `Broadcasted` from the configured leader: continue;
- `Broadcasted` from another expected participant: `FailSetup`;
- regular setup messages from participants: continue;
- traffic from a non-participant: consume as an unauthorized attempt without
  failing the program;
- unexpected kind or role from an expected participant: `FailSetup`.

### 6. Validate and process the payload

- temporary ordering/readiness issue: `RetryLater`;
- delivery that cannot change already accepted state: `DiscardNoOp`;
- malformed or cryptographically invalid contribution from an
  expected participant: `FailSetup`;
- local/system failure: `Err`.

### 7. Apply the disposition centrally

- `Processed`: commit;
- `DiscardNoOp`: log as idempotent/stale handling and commit;
- `RetryLater`: enqueue with preserved bounded retry state and commit;
- `FailSetup`: persist terminal setup failure, enqueue the L2 notification, and
  consume the offending input;
- `Err`: roll back.

The setup-failure transition and L2 notification should be transactional with
each other. If existing setup processing has already staged mutations that must
be rolled back before recording failure, retain the existing two-phase
`SetupAttemptFailed` settlement pattern: roll back the failed attempt, then use
a separate transaction to persist `ProgramState::Failed` and enqueue the L2
notification. The restored offending input is harmless only if the failed-state
lifecycle gate consumes it on its next delivery.

## Leader-broadcast processing

After authenticating the outer leader envelope, each embedded original should
be evaluated against the program.

For each `OriginalMessage`:

1. confirm the claimed sender is a program participant;
2. confirm the embedded type is allowed and agrees with the envelope type;
3. retrieve the claimed sender's application verification key;
4. defer if the key is missing;
5. consume it idempotently if that participant's relevant contribution was
   already accepted and the message cannot alter state;
6. fail setup if its signature, structure, or content is invalid while the
   contribution is still pending;
7. queue or process it if valid;
8. propagate only local or infrastructure failures.

Embedded `VerificationKey`, `VerificationKeyRequest`, and `Broadcasted` message
types should not be accepted as normal originals.

### Independent versus atomic policy

The recommended policy is to process embedded originals independently only for
successful and temporarily deferred contributions:

- valid originals progress;
- missing-key originals are deferred;
- repeated originals that cannot alter accepted state are consumed
  idempotently without exact content comparison;
- any non-replay invalid original in an active setup fails setup and triggers
  the L2 notification.

Valid and temporarily deferred originals may be handled independently, but a
single invalid original makes the overall setup untrustworthy and terminal.

If protocol security requires all-or-nothing acceptance, that policy must be
explicitly documented. In either model, an invalid participant contribution
must become a terminal setup failure rather than a propagated error that is
retried forever.

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
    NoOp(NoOpReason),
    Rejected(SetupRejectReason),
}
```

`receive_current_step_data` should map these outcomes as follows:

- `Accepted`: store data and mark the participant complete;
- `NotReady`: return `RetryLater`;
- `NoOp`: return `DiscardNoOp`;
- `Rejected`: return `FailSetup`;
- `Err`: propagate local or infrastructure failures.

The setup steps requiring audit include:

- `keys_step.rs`;
- `nonces_step.rs`;
- `signatures_step.rs`;
- `garbler_step.rs`;
- related aggregated-key processing.

Malformed values, bad proofs, inconsistent declarations, and invalid
cryptographic contributions are setup-failing rejections while the
participant's contribution is pending. Missing earlier state and genuine
step-order races are retryable. Messages that cannot alter already accepted
state are harmless no-ops. Storage failures and local invariant corruption
remain errors.

A rejected message attributable to an expected participant during active setup
should use the existing setup-failure machinery and notify L2. It must not be
implemented by repeatedly rolling back the same invalid input.

## Logging without persistent observability state

No replay, rejection, peer-fault, audit, or observability records should be
added to the database. In particular, the implementation should not persist
message hashes merely to distinguish exact replays.

Use normal `tracing` logs for diagnostics. For embedded originals, logs should
distinguish the authenticated forwarding leader from the claimed original
sender and state whether rejection happened before or after original-signature
verification.

The only durable writes associated with a peer fault are protocol state that is
already required by behavior: the terminal failed program state and the broker
outbox entry used to notify L2. The L2 notification is a protocol action, not an
observability record. Peer faults should not additionally generate generic
node-level nonfatal reports.

## File-by-file implementation plan

### `src/types/mod.rs`

Extend `MessageDisposition` with `DiscardNoOp` and `FailSetup`, with typed
retry, no-op, and peer-fault reasons.

### `src/signature_verifier.rs`

Completed in the first implementation step:

- introduced `AuthenticationOutcome` and `AuthenticationRejection`;
- represented missing keys as an authentication outcome rather than a general
  error in the active authentication path;
- represented malformed signatures, signature mismatches, and reconstruction
  failures as rejection outcomes;
- preserved storage and key-manager failures as `Err`;
- removed `verify_and_get_key` and the overlapping key lookup during signature
  verification;
- removed the inaccurate `known_count` field;
- documented the TLS fingerprint binding used by key announcements.

Remaining:

- map rejection outcomes to `FailSetup` at the authorized active-setup boundary;
- centralize key-request behavior;
- integrate or remove the currently separate
  `handle_missing_verification_key` path.

### `src/bitvmx.rs`

- authenticate and authorize `Broadcasted` before special dispatch;
- resolve the sender against program participants;
- confirm the broadcast sender is the configured leader;
- apply message dispositions centrally;
- discard all peer protocol messages once setup is complete or failed;
- consume repeated messages that cannot alter state idempotently, without
  storing replay fingerprints;
- turn attributable non-replay validation failures into terminal setup failure
  and L2 notification;
- queue only genuinely retryable messages;
- preserve bounded retry state.

### `src/leader_broadcast.rs`

- return explicit per-original outcomes;
- validate embedded senders against program participants;
- validate embedded message types;
- distinguish missing keys, state-level no-op deliveries, and invalid
  signatures;
- map invalid active-setup participant content to terminal setup failure without
  propagating the validation error;
- preserve storage errors as `Err`;
- implement and document the independent or atomic policy;
- avoid resetting retry budgets.

### `src/program/setup/setup_step.rs`

Replace `verify_received -> Result<bool, BitVMXError>` with a typed setup-message
outcome.

### `src/program/setup/setup_engine.rs`

- reserve retry for genuine readiness conditions;
- detect from setup state when another delivery for a participant cannot alter
  the program;
- consume those redundant deliveries and post-setup messages idempotently;
- classify invalid pending participant contributions as terminal setup
  failures;
- route those failures through the existing setup-failure and L2 notification
  mechanism rather than generic transaction errors.

### `src/message_queue.rs`

- add a clear API for deferring an existing message while preserving retry
  state;
- keep retry reasons in control flow and logs rather than adding observability
  records to storage;
- increment attempts only for retryable conditions;
- support deduplication or throttling of verification-key requests.

### `src/errors.rs`

Do not solve the classification problem by globally reclassifying
`InvalidMessage`. If error wrappers are necessary, keep them narrow and typed.
Control-flow outcomes should preferably remain dispositions rather than general
`BitVMXError` variants.

### `tests/leader_broadcast_test.rs`

Completed: updated the stale comments that described missing-key originals as
silently dropped. The current source queues those originals, although retry
accounting and error classification still need improvement.

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
2. An invalid signature from an expected participant fails active setup,
   notifies L2, and is not queued.
3. A malformed attributable payload fails active setup and is not retried.
4. An allow-listed but non-participant sender is consumed without being able to
   fail another program.
5. A storage failure during verification rolls back input consumption.
6. Once a participant contribution is accepted, another message for that
   participant and step is consumed without exact comparison, retry attempts,
   mutation, or another L2 failure notification.
7. Once setup completes, all peer protocol messages are consumed without
   changing program state.

### Verification-key messages

1. A valid announcement whose fingerprint matches the TLS-authenticated sender
   is stored.
2. A fingerprint mismatch from an expected active-setup participant fails
   setup and is not stored.
3. A malformed attributable announcement fails setup.
4. A verification-key request is accepted only from a participant in the
   referenced program.
5. A storage failure while storing a valid key propagates and rolls back.
6. If self-signature verification is retained, an invalid self-signature from
   an expected active-setup participant fails setup.

### Broadcast messages

1. A broadcast is accepted only from the configured leader.
2. An allow-listed setup participant that is not the leader cannot send a
   broadcast; the attempt fails setup.
3. The outer application signature is verified if that defense-in-depth policy
   is retained.
4. A malformed envelope attributable to the expected leader fails setup, while
   a completely undecodable frame is consumed at the transport boundary.
5. A missing embedded key defers the original.
6. An invalid embedded signature fails active setup and notifies L2.
7. A leader cannot forge an embedded original from another participant; the
   attempt fails setup.
8. A mixed broadcast handles valid, deferred, and invalid originals according
   to the documented policy.
9. A queue or storage failure rolls back all staged queue changes.
10. Repeated missing-key processing respects the retry budget.

### Transaction behavior

Tests should verify both the handler result and storage effects:

- a repeated message that cannot alter accepted state removes the broker inbox
  item without changing setup state or adding a replay record;
- post-setup peer traffic is consumed as stale;
- retryable input atomically removes the inbox item and adds a pending entry;
- an attributable participant fault results in persisted terminal setup failure
  and an L2 notification without indefinite redelivery;
- an unrelated allow-listed peer cannot fail another program;
- infrastructure failure leaves the inbox item available for retry;
- peer faults do not generate a generic node-level error report in place of the
  scoped setup-failure notification;
- retry exhaustion follows the explicit setup-failure policy.

## Recommended implementation order

1. **Completed:** introduce explicit authentication outcomes. Direct and
   embedded-original authentication use the typed outcome; callers temporarily
   preserve the old propagated-error behavior for `Rejected` until step 4.
2. **Completed:** added typed retry, no-op, and peer-fault reasons plus
   `DiscardNoOp` and `FailSetup` to the peer-message disposition, and centralized
   disposition handling in `BitVMX`.
3. **Completed:** added the program lifecycle gate so peer messages are processed
   only during setup. Messages for completed or failed programs are consumed before
   authentication, verification-key handling, or broadcast payload processing.
4. Convert attributable malformed/signature failures from generic `Err` into
   terminal setup failure while pending, while redundant no-op deliveries
   remain harmless.
5. Enforce participant and leader authorization using the TLS-authenticated
   sender identifier.
6. Bring the outer broadcast path under the normal authentication pipeline.
7. Refactor embedded-original processing to distinguish verified, missing-key,
   state-level no-op, setup-failing rejection, and system-error outcomes.
8. Preserve retry state and deduplicate key requests.
9. Refactor setup-step boolean verification results and identify redundant
   messages from existing setup state without persistent replay tracking.
10. Add broker-integrated and transaction-level tests.
11. Update stale reliability documentation and test comments.

## Core invariant

The intended invariant is:

> TLS and the allow list establish which permitted network peer submitted a
> message. Peer protocol messages are processed only during setup. A repeated
> delivery that cannot alter accepted state is consumed idempotently without
> persistent replay tracking, and a temporary prerequisite
> causes bounded retry. Any other invalid contribution attributable to an
> expected setup participant terminates setup and notifies L2 without indefinite
> message redelivery. After setup completes or fails, all further peer protocol
> messages are stale. Only local or infrastructure failures propagate for
> rollback.

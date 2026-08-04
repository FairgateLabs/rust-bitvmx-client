# Union setup: skipped MuSig2 nonces and partial signatures

## Status

**Open investigation / handoff document.**

The generic setup flow deliberately tolerates some aggregated keys for which the
local key manager has no public nonces or partial signatures:

- `src/program/setup/steps/nonces_step.rs` — `NoncesStep::generate_data`
  logs `No nonces for aggregated key ..., skipping` and continues.
- `src/program/setup/steps/signatures_step.rs` —
  `SignaturesStep::generate_data` warns that signature generation failed and
  continues.

Do not replace either `continue` with an unconditional error until the Union
protocol cases described here have been identified and covered by tests. Both
behaviors predate the current validation work and were restored because they
handle at least one known-but-not-yet-documented Union setup case.

This document is intended to let a new agent investigate the behavior, identify
which Union protocol and aggregate trigger it, and replace broad error
suppression with an explicit required/optional signing-key model.

## What the code does today

After `KeysStep` completes, `my_keys.computed_aggregated` contains both:

1. MuSig2 keys computed from the keys exchanged in the current setup; and
2. keys returned by `ProtocolHandler::get_pregenerated_aggregated_keys`.

`NoncesStep` iterates every value in that combined map and calls:

```text
KeyManager::get_my_pub_nonces(aggregated_key, protocol_name)
```

If that lookup fails, the aggregate is omitted from the outgoing nonce message.
The step errors only when no aggregate produced any nonces.

`SignaturesStep` similarly calls:

```text
KeyManager::get_my_partial_signatures(aggregated_key, protocol_name)
```

A failed lookup is logged and omitted. The step errors only when no aggregate
produced any partial signatures.

Received messages still reject empty payloads, unknown aggregate keys, duplicate
aggregate entries, empty per-aggregate data, and duplicate message IDs. They
intentionally allow a valid subset of `computed_aggregated`, because requiring
full coverage would indirectly defeat the two skip paths above.

## Likely trigger

The leading hypothesis is that `computed_aggregated` is currently overloaded:
it is both a registry of keys used anywhere by a protocol and the implicit list
of keys that must participate in nonce/signature exchange.

Those sets are not necessarily identical in Union.

Several Union handlers import existing committee keys through
`get_pregenerated_aggregated_keys`:

- `src/program/protocols/union/accept_pegin.rs`
- `src/program/protocols/union/dispute_core.rs`
- `src/program/protocols/union/full_penalization.rs`
- `src/program/protocols/union/user_take.rs`

The most likely candidates are `DisputeCoreProtocol` and
`FullPenalizationProtocol`, because they import both the committee take and
dispute aggregated keys. `UserTakeProtocol` and `AcceptPeginProtocol` should
also be checked.

A pregenerated aggregate may be needed only as an output/internal/verifying key,
or only by one transaction branch. It may not have a message to sign in the
current protocol session. In that case the protocol builder never generates a
nonce for `(aggregated key, current protocol name)`.

Nonce generation is driven by transaction construction in
`rust-bitvmx-protocol-builder/src/types/output.rs`:

- aggregate script-path signing calls `KeyManager::generate_nonce`;
- aggregate key-path signing calls `KeyManager::generate_nonce`;
- merely using an aggregate as a locking or verification key does not
  necessarily generate a nonce.

A second possible trigger is participant role. A process may know a pregenerated
aggregate but may not own a participant key or be expected to sign for that
aggregate in this subprotocol.

A third possible trigger is session identity. Key-manager nonce and signature
lookups include `protocol.context().protocol_name`. A key generated in an
earlier committee protocol may exist while no messages/nonces exist under the
current Union subprotocol name.

These are hypotheses, not confirmed conclusions. The investigation must record
the exact protocol, aggregate logical name, participant role, key-manager error,
and transaction/signing path.

## Why earlier reliability checks do not resolve this

`docs/LEADER_BROADCAST_RELIABILITY.md` establishes transport atomicity,
authenticated senders, harmless duplicate delivery, and one message per sender.
Those guarantees do not establish that every aggregate in a participant's
payload is required, or that every required aggregate is present.

The leader can therefore receive a correctly signed and non-duplicated message
that intentionally or accidentally omits one aggregate. This is a semantic
setup issue, not a leader-broadcast reliability issue.

## Security assessment

### No known direct key-compromise or forgery issue

Skipping an unavailable aggregate does not expose secret nonces or private keys.
It also does not let an attacker forge a MuSig2 signature. The key manager later
validates participant counts, message IDs, and partial signatures for aggregates
that are processed.

The skip path does not itself regenerate or reuse a secret nonce. Any proposed
fix must preserve that property: retrying setup must never regenerate a nonce
for the same key/session/message tuple.

### Confirmed class of risk: availability and incomplete setup

The setup engine tracks whether each participant supplied a step message, not
whether each payload covered every aggregate that the eventual protocol needs.
If a required aggregate is omitted, a step may complete and the failure may be
delayed until transaction signing or execution. A malicious participant may be
able to exploit the accepted-subset behavior to stall the protocol.

In a multiparty protocol a malicious signer can generally refuse to cooperate
anyway, so this is primarily a denial-of-service/liveness risk. However, early
and attributable failure is still preferable to recording setup as complete and
failing later.

### Risk requiring investigation: optional versus security-critical branches

It must be verified that an omitted aggregate is truly unused by the current
protocol, rather than required only in a less common dispute, timeout,
penalization, or recovery branch. If setup completes without material needed by
such a branch, the impact could be more serious than immediate availability:
the omission might only become visible when funds need the safety branch.

No exploit of that form is currently established. Treat it as an open security
question until every skipped aggregate is mapped to all transaction branches.

### Broad error suppression hides unexpected failures

The skip currently treats every key-manager error as "not applicable." It may
also suppress storage errors, corrupted state, missing MuSig2 sessions,
incomplete nonce aggregation, invalid participant state, or programming bugs.
This makes operational diagnosis difficult and can turn a real setup failure
into an apparently successful partial setup.

## Investigation plan

### 1. Capture the real trigger without changing behavior

Temporarily improve diagnostics while retaining both `continue` statements.
For each skipped aggregate, log or collect:

- protocol type and `protocol_name`;
- program/protocol UUID;
- participant index and role;
- logical aggregate name from `my_keys.computed_aggregated`;
- aggregate public key;
- whether it came from current key aggregation or
  `get_pregenerated_aggregated_keys`;
- exact `KeyManagerError` variant;
- known message IDs for that aggregate/session, if available.

The nonce path currently discards its error with `Err(_)`; exposing that error
in the diagnostic log is a safe first investigation change as long as the
continue behavior remains unchanged.

### 2. Reproduce through Union flows

Exercise, at minimum:

1. accept peg-in;
2. user take / peg-out acceptance;
3. dispute core setup;
4. full penalization;
5. timeout, challenge, and penalization branches that are not taken in a happy
   path.

The ignored Union integration tests and `examples/union` are likely starting
points. Follow the repository test instructions in `AGENTS.md`; these tests may
require release mode, Docker bitcoind, and the BitVMX CPU emulator. Do not run
them casually in a constrained environment.

For each flow, produce a table like:

| Protocol | Participant role | Aggregate name | Pregenerated? | Nonce present? | Signature present? | Transaction/branch using it | Required in this setup? |
|---|---:|---|---:|---:|---:|---|---:|

### 3. Trace why each nonce exists or does not exist

Start at each Union handler's `build` implementation and follow protocol-builder
calls into `rust-bitvmx-protocol-builder/src/types/output.rs`. Record every
aggregate-signing input that invokes `KeyManager::generate_nonce` and its
`MessageId`.

Distinguish these uses:

- aggregate must sign in the current setup;
- aggregate is only a locking/internal/verifying key;
- aggregate signs only in another protocol/session;
- aggregate signs only for a subset of participant roles;
- aggregate is unused or stale.

Also inspect `UserTakeProtocol::send_pegout_accepted`, which explicitly loads
public nonces and partial signatures for `take_aggregated_key` and therefore
provides one concrete example where omission is not acceptable.

### 4. Add regression tests before changing semantics

Create a focused test reproducing each legitimate skip. A useful test must prove
why the aggregate is optional, not merely assert that setup currently succeeds.
Also add negative tests proving that:

- a missing required aggregate fails setup immediately;
- an optional/non-signing aggregate may have no nonce or signature;
- participants cannot disagree about which aggregates are required;
- an unknown or duplicated aggregate is rejected;
- required material for dispute/timeout/penalization branches is prepared even
  when those branches are not executed in the happy path.

## Preferred redesign

Do not infer signing requirements from whether a key-manager lookup happens to
succeed. Make the distinction explicit in the protocol API.

One possible design is for `ProtocolHandler` to expose metadata such as:

```rust
struct SetupAggregatedKey {
    name: String,
    key: PublicKey,
    exchange: AggregateExchange,
}

enum AggregateExchange {
    Required,
    NotRequired,
}
```

Alternatively, add a method that returns the exact aggregate keys required for
nonce/signature exchange in the current protocol and participant role. Keep
`computed_aggregated` as the complete key registry, but have `NoncesStep` and
`SignaturesStep` iterate only the declared exchange set.

Required properties of the final design:

1. Missing nonce/signature material for a **required** aggregate errors
   immediately with protocol, aggregate, participant, and key-manager context.
2. A **non-signing** aggregate is skipped by declaration, not by catching an
   arbitrary key-manager error.
3. All participants deterministically agree on the required aggregate set, or
   setup rejects the mismatch.
4. Required/optional status accounts for participant role and all safety
   branches, including disputes, timeouts, and penalization.
5. Wire payload validation compares against the declared required set while
   permitting only explicitly non-required omissions.
6. Existing nonce uniqueness and no-regeneration guarantees remain intact.
7. Leader-broadcast duplicate and crash behavior remains unchanged.

A smaller acceptable fix is a protocol method returning
`required_setup_signing_keys(...)`, plus strict errors for those keys. Avoid an
error whitelist based solely on current `KeyManagerError` variants unless the
protocol also declares that the aggregate is non-signing; otherwise real state
corruption could still be hidden.

## Completion criteria

This investigation is complete only when:

- the exact Union trigger(s) for both skip paths are documented by protocol,
  aggregate, role, and transaction branch;
- each legitimate omission has a regression test;
- required versus non-signing aggregates are explicit rather than inferred
  from lookup failure;
- arbitrary key-manager failures are no longer swallowed;
- missing required material fails during setup with an actionable error;
- Union happy-path and dispute/penalization integration tests pass; and
- this document is updated with the final design and security conclusion.

Until then, preserve both skip-and-continue paths.

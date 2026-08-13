# Union protocols

This document describes the role, setup requirements, automatic dispatch hooks, and shared-variable interfaces of the Union protocols. It intentionally does not document each transaction's inputs, outputs, or scripts.

The examples under `examples/union` are the reference for orchestration. Protocol IDs are deterministic, so every participant must use the same committee ID, member ordering, and slot numbering.

## DisputeCoreProtocol

### Purpose

`DisputeCoreProtocol` is the long-lived dispute covenant for a single committee member. A committee with `N` members creates `N` dispute-core instances, and every participant builds the same set of instances. The instance identifies the member being monitored; whether that member acts as an operator or a watchtower determines which parts of the covenant are active.

The protocol coordinates the reimbursement dispute lifecycle. It checks whether a reimbursement corresponds to funds registered as advanced, opens challenges when it does not, connects the challenge to the corresponding DRP instance, and routes successful claims or already-known penalizations through `FullPenalizationProtocol`. It also exposes the covenant outputs that per-slot `AcceptPegin` instances need for operator-take and operator-won paths.

The protocol ID is derived as:

```text
get_dispute_core_pid(committee_id, monitored_member.take_key)
```

### Setup

The setup order used by `examples/union` is:

1. Establish every member's take and dispute keys.
2. Aggregate the committee take keys and dispute keys.
3. Establish a pairwise dispute key for every operator/watchtower pair.
4. Fund one protocol UTXO per member.
5. Store the global `UnionSettings`.
6. Set up all dispute-core instances.
7. Set up the DRP dispute channels and `FullPenalizationProtocol`, which consume data prepared by dispute core.

For each participant, setup stores the shared `Committee` under `committee_id`, then loops over the members and stores one `DisputeCoreData` value under each derived dispute-core ID before calling `BitVMXClient::setup` with `PROGRAM_TYPE_DISPUTE_CORE`.

The participant list and communication-address list must use the same stable ordering. `member_index` and the protocol's local `my_idx` refer to positions in those lists.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `GLOBAL_SETTINGS_UUID` | `union_settings` | JSON-encoded `UnionSettings` | Union application/configuration | Per-denomination timelocks. There must be a `StreamSettings` entry for the committee's `stream_denomination`. |
| `committee_id` | `committee` | JSON-encoded `Committee` | Union setup | Ordered members and roles, aggregated take/dispute keys, packet size, stream denomination, and pegin/pegout confirmation settings. |
| `committee_id` | `PAIRWISE_DISPUTE_KEY_<min>_<max>` | `PubKey` | Pairwise key setup | Aggregated dispute key for each operator/watchtower pair. Watchtower/watchtower pairs are not required. |
| dispute-core ID | `dispute_core_data` | JSON-encoded `DisputeCoreData` | Union setup | The committee ID, monitored member index, and that member's protocol-funding UTXO. |

`DisputeCoreData.funding_utxo` must include the transaction ID, output index, amount, and output description needed to spend it. The example obtains these UTXOs from `Committee::init_funds` and keys the map by each member's take public key.

The following values are passed directly to `BitVMXClient::setup`, rather than stored as globals:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_DISPUTE_CORE` |
| Participants | All committee communication addresses, in committee order |
| Setup leader index | `0`, selecting the first address in the participant list as setup leader |

The aggregated take and dispute keys are declared as pregenerated aggregated keys. Protocol setup does not aggregate them again.

### Variables received while running

These values are not prerequisites for building the protocol. They are written later by other Union components and are read when the corresponding runtime path is reached.

| Scope | Name | Producer | Use in dispute core |
| --- | --- | --- | --- |
| Selected operator's dispute-core ID | `PEGOUT_ID_<slot>` | `AdvanceFundsProtocol` during build | Supplies the pegout ID committed by the operator when constructing the reimbursement kickoff. The Union example also has a direct setter for manual reimbursement testing. |
| `committee_id` | `ADVANCED_FUNDS_<slot>` | Contract/event integration, represented by `AdvanceFundsRegistered` in the example | Records the registered advance-funds transaction, pegout ID, and selected operator. Dispute core compares it with the reimbursement witness. Missing data, a different operator, or a different pegout ID makes the reimbursement challengeable. |
| `committee_id` | `OPERATOR_PENALIZED_<member>` | `FullPenalizationProtocol` | Avoids starting a new challenge against an operator already penalized and dispatches the applicable disabler instead. |
| `committee_id` | `WATCHTOWER_PENALIZED_<member>` | `FullPenalizationProtocol` | Avoids the normal cosign path for an already-penalized watchtower and dispatches the applicable disablers instead. |

The distinction between the first two values is intentional: `PEGOUT_ID_<slot>` is protocol-local data supplied by `AdvanceFundsProtocol`, whereas `ADVANCED_FUNDS_<slot>` represents the independently registered contract event used to validate that claim.

### Variables produced for other protocols

During setup, dispute core stores references to its generated covenant outputs. Consumers use these references to compose their own protocol graphs without rebuilding dispute-core transactions.

| Scope | Name | Consumer |
| --- | --- | --- |
| Operator dispute-core ID | `OPERATOR_TAKE_ENABLER_<slot>` | `AcceptPeginProtocol` and `FullPenalizationProtocol` |
| Operator dispute-core ID | `OPERATOR_WON_ENABLER_<slot>` | `AcceptPeginProtocol` and `FullPenalizationProtocol` |
| Operator dispute-core ID | `OP_INITIAL_DEPOSIT_TXID` | `FullPenalizationProtocol` |
| Operator dispute-core ID | `OP_INITIAL_DEPOSIT_AMOUNT` | `FullPenalizationProtocol` |
| Operator dispute-core ID | `OP_INITIAL_DEPOSIT_OUT_SCRIPT_<slot>` | `FullPenalizationProtocol` |
| Operator dispute-core ID | `OP_DISABLER_DIRECTORY_UTXO` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `WT_DISABLER_DIRECTORY_UTXO` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `WT_INIT_CHALLENGE_UTXOS` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `WT_INIT_CHALLENGE_UTXOS` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `FullPenalizationProtocol` |
| DRP ID | `program_input_prev_protocol(4)` | DRP input 4: points back to the dispute-core instance carrying the cosigned pegout ID |
| DRP ID | `program_input_prev_prefix(4)` | DRP input 4: prefix for the operator cosign pegout-ID witness words |
| DRP ID | `program_input_prev_protocol(5)` | DRP input 5: points back to the dispute-core instance carrying the cosigned slot ID |
| DRP ID | `program_input_prev_prefix(5)` | DRP input 5: prefix for the operator cosign slot-ID witness |

Dispute core also stores the corresponding Winternitz public keys and later-captured witnesses in its own scope so DRP can resolve inputs 4 and 5 through the `program_input_prev_*` references.

Some values such as generated slot/pegout keys, `MY_IDX`, speedup keys, and `REVEAL_IN_PROGRESS` are internal setup or state-machine data. They are not external configuration. `OP_COSIGN_UTXOS` is currently stored as an internal setup artifact and has no cross-protocol reader.

### Automatic dispatch hooks

The protocol is event driven. The following describes dispatch behavior without detailing transaction structure:

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Only for the dispute-core instance owned by the local participant, dispatches protocol funding and the watchtower start enabler. The latter should eventually be dispatched only when a challenge needs it. |
| Reimbursement kickoff observed | The monitored operator schedules its operator-take path after the long timelock. Other members validate the registered advance-funds data and either schedule a challenge after the short timelock or route to a disabler if the operator is already penalized. An SPV notification is also sent to the configured L2 component. |
| Challenge observed | The challenged operator cancels its pending operator-take dispatch and reveals the committed input. Other members schedule the input-not-revealed fallback. |
| Reveal observed | The operator schedules its operator-won path. Watchtowers cancel input-not-revealed and start the watchtower/operator challenge handshake, unless penalization state requires a disabler. A second concurrent reveal triggers the double-reveal penalization path. |
| Watchtower challenge handshake observed | Schedules the operator no-cosign timeout; the challenged operator can cosign and, once the cosign is observed, the owning watchtower starts the matching DRP challenge. The operator also schedules the watchtower no-challenge timeout. Competing events cancel the corresponding pending timeout. |
| DRP `START_CH` observed as external news | Cancels the watchtower no-challenge timeout for that operator/watchtower pair. |
| DRP prover/verifier win observed as external news | Starts the appropriate operator or watchtower claim gate. |
| Claim-gate progress observed | Schedules success after its timelock for the claimant, lets other parties stop the claim, and dispatches the relevant penalization directory when success is observed. |
| No-cosign or no-challenge timeout observed | Starts the claim gate for the party entitled to claim. |

Two automatic routes load transactions owned by other protocol handlers:

- Operator-take and operator-won actions are obtained from the per-slot `AcceptPeginProtocol`.
- Penalization and disabler actions are obtained from `FullPenalizationProtocol`.

For this reason, those protocols must be set up before the corresponding runtime event can occur.

## AcceptPegin

The Rust implementation is named `AcceptPegInProtocol`.

### Purpose

`AcceptPegInProtocol` represents the committee's acceptance of one peg-in request and reserves that peg-in for one Union slot. There is one protocol instance per `(committee, slot)`, shared by all committee members.

Besides accepting the external peg-in request, the protocol connects the accepted funds to the alternative ways in which an operator can later receive them after advancing funds: the normal operator-take path and the operator-won-after-dispute path. The conditions that enable those paths come from each operator's `DisputeCoreProtocol`; dispute core later decides when to dispatch them.

The protocol ID is derived as:

```text
get_accept_pegin_pid(committee_id, slot_index)
```

### Setup

`examples/union` sets up this protocol when a peg-in request is accepted. On every committee member it:

1. Derives the same protocol ID from the committee ID and slot index.
2. Builds `operator_indexes` from committee members whose role is `Prover`.
3. Stores a `PegInRequest` under the protocol ID.
4. Calls `BitVMXClient::setup` for all committee addresses.
5. Waits for setup to complete before the accept transaction is dispatched.

The committee's dispute-core instances must already be set up. For every operator, this protocol imports the take and won enablers for the selected slot. The slot must therefore be within the dispute core's configured `packet_size`.

The participant list must use the same ordering as `Committee.members`. That ordering determines `my_idx`, operator indices, signing leaves, and ownership of per-member speedup keys.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `GLOBAL_SETTINGS_UUID` | `union_settings` | JSON-encoded `UnionSettings` | Union application/configuration | Provides the stream settings selected by the committee's denomination, including the request-peg-in, operator-take, and operator-won timelocks. |
| `committee_id` | `committee` | JSON-encoded `Committee` | Dispute-core/committee setup | Supplies the ordered members, roles, dispute keys, stream denomination, and required peg-in confirmations. |
| accept-pegin ID | `pegin_request` | JSON-encoded `PegInRequest` | Peg-in acceptance orchestration | Describes the external peg-in and the Union slot accepting it. |
| Each operator's dispute-core ID | `OPERATOR_TAKE_ENABLER_<slot>` | `Utxo` | `DisputeCoreProtocol` | Connects the slot's normal reimbursement path to that operator's take action. |
| Each operator's dispute-core ID | `OPERATOR_WON_ENABLER_<slot>` | `Utxo` | `DisputeCoreProtocol` | Connects the slot's successful dispute/reveal path to that operator's won action. |

`PegInRequest` contains:

| Field | Requirement |
| --- | --- |
| `committee_id` | ID of the committee accepting the peg-in. |
| `slot_index` | Slot reserved for this peg-in. It must match the protocol ID and an available dispute-core slot. |
| `txid` | Transaction ID of the external request-peg-in transaction. |
| `amount` | Value committed by that request and used to size the accepted funds. |
| `take_aggregated_key` | Committee take key, already aggregated before this setup. It is registered as a pregenerated aggregate key. |
| `operator_indexes` | Indices of the committee members allowed to act as operators. The example derives these from members with role `Prover`. |
| `rootstock_address` | Rootstock destination encoded as exactly 20 bytes of hexadecimal data. |
| `reimbursement_pubkey` | User key used by the request timeout/refund path and the accept speedup output. |
| `accept_pegin_sighash` | Sighash supplied by the external orchestration. This field is stored in the current implementation but is not read while building or running the protocol; setup computes and reports its own accept-peg-in sighash. |

The values passed directly to `BitVMXClient::setup` are:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_ACCEPT_PEGIN` |
| Participants | All committee communication addresses, in committee order |
| Setup leader index | `0`, selecting the first participant as setup leader |

### Variables received while running

| Scope | Name | Producer | Use in accept pegin |
| --- | --- | --- | --- |
| Winning operator's dispute-core ID | `REVEAL_IN_PROGRESS` | `DisputeCoreProtocol` | When an operator-won action is observed, accept pegin clears this marker if it belongs to this slot. This completes dispute core's reveal lifecycle without clearing a marker for another slot. |

The operator-take and operator-won dispatch requests themselves are runtime calls from `DisputeCoreProtocol`, not globals. Dispute core loads these transactions from this protocol instance and asks the Bitcoin coordinator to dispatch them under the accept-pegin protocol ID.

### Variables and notifications produced for other components

| Scope/destination | Name | Consumer | Meaning |
| --- | --- | --- | --- |
| `committee_id` | `ACCEPT_PEGIN_TX_<slot>` | `UserTakeProtocol` and `AdvanceFundsProtocol` | Slot-scoped accepted-peg-in UTXO used as their upstream protocol reference. |
| `committee_id` | `CANCEL_TAKE0_TX_<slot>` | `UserTakeProtocol` | Slot-scoped cancellation enabler associated with the accepted peg-in. |
| `committee_id` | `LAST_OPERATOR_TAKE_UTXO` | `AdvanceFundsProtocol` | Reimbursement output saved when the local operator's take or won action is observed. This value is committee-scoped and unindexed, so a later operator reimbursement replaces the previous value. |
| L2 broker destination | `pegin_accepted` | Union L2/contract integration | Sent by each participant after setup. It contains the accept transaction ID and sighash, that participant's nonce and partial signature, and—for operators—their take and won sighashes. |
| L2 broker destination | `union_spv_notification` | Union L2/contract integration | Sent when an operator-take or operator-won action is observed; identifies the committee, slot, action type, transaction ID, and SPV proof when available. |

The protocol also generates and stores `SPEEDUP_KEY` under its own ID. This is internal setup data, not an externally supplied variable.

### Automatic dispatch hooks

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Sends `pegin_accepted` to the configured L2 component. It does **not** automatically dispatch the accept transaction. |
| Operator-take observed | If this participant is the operator named by the action, saves the resulting reimbursement UTXO as `LAST_OPERATOR_TAKE_UTXO`. Every participant sends an operator-take SPV notification to L2. |
| Operator-won observed | Clears the matching `REVEAL_IN_PROGRESS` marker in that operator's dispute core. If this participant is the winning operator, saves the resulting reimbursement UTXO as `LAST_OPERATOR_TAKE_UTXO`. Every participant sends an operator-won SPV notification to L2. |

The initial `ACCEPT_PEGIN_TX` dispatch is an external orchestration action. In `examples/union`, a committee member requests the transaction by name and dispatches it after all participants report setup completion. `CANCEL_TAKE0_TX_<operator>` is likewise exposed for explicit dispatch and has no automatic hook in this protocol.

`OPERATOR_TAKE_TX_<operator>` and `OPERATOR_WON_TX_<operator>` are dispatched automatically by `DisputeCoreProtocol` when reimbursement or dispute events make the corresponding path eligible.

## UserTake

The Rust implementation is named `UserTakeProtocol`.

### Purpose

`UserTakeProtocol` prepares the committee-authorized peg-out transaction that transfers the value reserved in an accepted peg-in slot to the user. There is one protocol instance per `(committee, slot)`, shared by all committee members.

Its main integrity check is agreement on the transaction sighash. The peg-out orchestration supplies the sighash it expects, every member independently builds the same protocol, and setup fails if the locally computed user-take sighash differs. After successful setup, each member sends its nonce and partial signature to the configured L2 component.

The protocol ID is derived as:

```text
get_user_take_pid(committee_id, slot_index)
```

### Setup

`examples/union` sets up this protocol when a peg-out is requested. On every committee member it:

1. Derives the same protocol ID from the committee ID and slot index.
2. Stores a `PegOutRequest` under that protocol ID.
3. Calls `BitVMXClient::setup` for all committee addresses.
4. Waits for setup to complete before explicitly dispatching the user-take transaction.

The corresponding `AcceptPegInProtocol` must already be set up for the slot. User take imports both the accepted-funds UTXO and its cancellation enabler from committee-scoped storage.

The participant list must use the same ordering as `Committee.members`. Although this protocol generates no protocol-specific participant keys, that ordering remains part of the shared multiparty setup and signing context.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `committee_id` | `committee` | JSON-encoded `Committee` | Dispute-core/committee setup | Supplies the required peg-out confirmation count and the participant context. |
| user-take ID | `pegout_request` | JSON-encoded `PegOutRequest` | Peg-out orchestration | Identifies the committee and slot, user, expected sighash, peg-out ID, amount, and aggregate take key. |
| `committee_id` | `ACCEPT_PEGIN_TX_<slot>` | `Utxo` | `AcceptPegInProtocol` | The accepted funds reserved for this slot. It also determines the value transferred by user take. |
| `committee_id` | `CANCEL_TAKE0_TX_<slot>` | `Utxo` | `AcceptPegInProtocol` | The slot's cancellation enabler, which is also consumed by the user-take path. |

`PegOutRequest` contains:

| Field | Requirement |
| --- | --- |
| `committee_id` | ID of the committee processing the peg-out. |
| `slot_index` | Accepted peg-in slot assigned to the peg-out. It must match the protocol ID and the two slot-scoped UTXOs above. |
| `user_pubkey` | Compressed Bitcoin public key that receives the peg-out and controls its speedup output. |
| `pegout_sighash` | Expected sighash of the user-take transaction. Setup recomputes it and rejects the protocol if it does not match. |
| `take_aggregated_key` | Committee take key, already aggregated before setup. It is registered as a pregenerated aggregate key and authorizes the user-take path. |
| `amount` | Peg-out amount supplied by orchestration. The current implementation stores this field but does not use it when building or validating the transaction; the output value is derived from `ACCEPT_PEGIN_TX_<slot>`. |
| `pegout_id` | Peg-out identifier supplied by orchestration. The current `UserTakeProtocol` stores it but does not otherwise read or validate it. |

The example computes `pegout_sighash` from the expected user-take transaction before setup, representing the value that should come from the contract integration.

The values passed directly to `BitVMXClient::setup` are:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_USER_TAKE` |
| Participants | All committee communication addresses, in committee order |
| Setup leader index | `0`, selecting the first participant as setup leader |

### Validation and failure reporting

After building the protocol, each participant recomputes the sighash for the user-take action and compares it with `PegOutRequest.pegout_sighash`.

If they differ, setup:

- sends a `ProtocolError` with `InvalidSighash` to the configured L2 component;
- includes both the expected and locally computed hashes; and
- fails without reporting the peg-out as accepted.

This check is the protocol's principal link between the peg-out authorized externally and the transaction graph independently constructed by each committee member.

### Variables and notifications produced for other components

`UserTakeProtocol` does not write a global variable consumed by another Union protocol.

After successful setup, each participant sends the following notification:

| Destination | Name | Consumer | Meaning |
| --- | --- | --- | --- |
| L2 broker destination | `pegout_accepted` | Union L2/contract integration | Contains the committee ID, user-take transaction ID and sighash, and that participant's public nonce and partial signature. |

### Automatic dispatch hooks

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Sends `pegout_accepted` to the configured L2 component. It does **not** dispatch the user-take transaction. |
| User-take observed | Logs the transaction and confirmation count. It does not update shared variables, emit an SPV notification, or dispatch a follow-up transaction. |

The `USER_TAKE_TX` dispatch is an external orchestration action. In `examples/union`, a committee member requests the transaction by name and dispatches it after every participant reports setup completion. The user may then separately accelerate it using the transaction's speedup output.

## AdvanceFunds

The Rust implementation is named `AdvanceFundsProtocol`.

### Purpose

`AdvanceFundsProtocol` lets the operator selected for a peg-out pay the user before that operator can claim the funds reserved in the corresponding accepted peg-in slot. It is a single-participant protocol: only the selected operator sets it up, signs it, and runs its hooks.

The protocol uses the operator's advance-funds liquidity and, when available, the reimbursement output from a previous slot. After advancing the funds, it automatically starts the selected operator's reimbursement path in `DisputeCoreProtocol`. It also passes the peg-out ID to dispute core so watchtowers can compare the later reimbursement commitment with the independently registered contract event.

There is one deterministic protocol ID per `(committee, slot)`:

```text
get_advance_funds_pid(committee_id, slot_index)
```

### Setup

`examples/union` calls the setup helper for every committee member, but the helper compares `operator_pubkey` with each member's `my_take_pubkey`. Non-selected members return without creating a protocol. The selected operator:

1. Derives the protocol ID from the committee ID and slot index.
2. Stores an `AdvanceFundsRequest` under that protocol ID.
3. Calls `BitVMXClient::setup` with only its own communication address.
4. Runs only the setup key step; there is no multiparty nonce or signature exchange.
5. Automatically dispatches the advance-funds transaction when setup completes.

The corresponding `AcceptPegInProtocol` and the selected operator's `DisputeCoreProtocol` must already be set up. Advance funds reads the accepted slot value while building and loads dispute-core transactions after the advance is confirmed.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `committee_id` | `committee` | JSON-encoded `Committee` | Dispute-core/committee setup | Supplies member take/dispute keys and the confirmation threshold used by this protocol. |
| advance-funds ID | `advance_funds_request` | JSON-encoded `AdvanceFundsRequest` | Advance-funds orchestration | Identifies the selected operator, user, committee, slot, peg-out ID, and fee. |
| `committee_id` | `ACCEPT_PEGIN_TX_<slot>` | `Utxo` | `AcceptPegInProtocol` | Supplies the accepted slot value used to determine how much the operator advances to the user. |
| `committee_id` | `ADVANCE_FUNDS_INPUT` | `Utxo` | Operator wallet/funding orchestration | Operator-owned liquidity used to fund the advance. The example initializes it from the dedicated advance-funds output created by `Member::init_funds`. |

`AdvanceFundsRequest` contains:

| Field | Requirement |
| --- | --- |
| `committee_id` | ID of the committee processing the peg-out. |
| `slot_index` | Accepted peg-in slot being advanced. It must match the protocol ID and `ACCEPT_PEGIN_TX_<slot>`. |
| `user_pubkey` | Compressed Bitcoin public key that receives the advanced funds. |
| `my_take_pubkey` | Take key of the selected operator. It identifies both the committee member and that member's dispute-core instance. |
| `pegout_id` | Peg-out identifier committed by the advance and copied into the selected operator's dispute core. |
| `fee` | Fee charged for advancing the funds and included in the operator's change calculation. |

The values passed directly to `BitVMXClient::setup` are:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_ADVANCE_FUNDS` |
| Participants | A one-element list containing only the selected operator's communication address |
| Setup leader index | `0`, the selected operator itself |

### Optional variables received while running

| Scope | Name | Producer | Use in advance funds |
| --- | --- | --- | --- |
| `committee_id` | `LAST_OPERATOR_TAKE_UTXO` | `AcceptPegInProtocol` | If present in the selected operator's storage, it is added as a second input. This rolls a previous reimbursement back into the operator's advance-funds liquidity. |
| `committee_id` | `OP_INITIAL_DEPOSIT_FLAG` | An earlier `AdvanceFundsProtocol` runtime hook | Indicates whether advance funds has already dispatched an operator initial deposit for this committee. Missing is treated as `false`. |

`LAST_OPERATOR_TAKE_UTXO` and `OP_INITIAL_DEPOSIT_FLAG` are committee-scoped rather than slot-scoped. In the current implementation, the former holds only the latest locally observed operator reimbursement, while the latter is one boolean for the entire committee.

### Variables produced for other protocols and future advances

| Scope | Name | Consumer | Meaning |
| --- | --- | --- | --- |
| Selected operator's dispute-core ID | `PEGOUT_ID_<slot>` | `DisputeCoreProtocol` | Peg-out ID that the operator commits in the reimbursement kickoff. Dispute core later compares its revealed value with `ADVANCED_FUNDS_<slot>`. |
| `committee_id` | `OP_INITIAL_DEPOSIT_FLAG` | Later `AdvanceFundsProtocol` instances | Set to `true` after this protocol dispatches the operator initial-deposit transaction. |
| `committee_id` | `ADVANCE_FUNDS_INPUT` | Later `AdvanceFundsProtocol` instances | Replaced with the advance transaction's operator-change output when that output exists, allowing liquidity to roll into a later advance. |

The rollover update assumes the operator change is output index `2`. If the transaction has fewer than three outputs because no change output was created, the existing `ADVANCE_FUNDS_INPUT` value is left unchanged.

### Contract registration versus protocol-local data

The protocol does **not** write `ADVANCED_FUNDS_<slot>`. That variable represents `AdvanceFundsRegistered`, an independent event from the contract integration containing the registered operator, peg-out ID, and transaction ID. `examples/union` simulates the event by writing it to every member's committee scope.

Both handoffs are required for reimbursement validation:

- `AdvanceFundsProtocol` writes `PEGOUT_ID_<slot>` into the selected operator's dispute core.
- Contract/event orchestration writes `ADVANCED_FUNDS_<slot>` under the committee ID.

When reimbursement starts, each watchtower decodes the committed peg-out ID and checks it against the registered event and selected operator. A missing or inconsistent registration makes the reimbursement challengeable.

### Notifications produced for L2

| When | Name | Meaning |
| --- | --- | --- |
| Immediately after setup dispatches the transaction | `funds_advanced` | Contains the advance transaction ID, committee ID, slot, and peg-out ID. This confirms dispatch, not Bitcoin confirmation. |
| When the transaction is reported by the Bitcoin coordinator | `funds_advance_spv` | Contains the same identifiers and an SPV proof when it can be retrieved. |

Both notifications are sent only by the selected operator because it is the sole participant in this protocol.

### Automatic dispatch hooks

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Signs and immediately dispatches `ADVANCE_FUNDS_TX`, then sends `funds_advanced` to L2 with its txid. No external dispatch call is required. |
| Advance-funds transaction observed | Sends `funds_advance_spv` to L2. If `OP_INITIAL_DEPOSIT_FLAG` is false, loads the selected operator's `DisputeCoreProtocol`, dispatches its initial deposit, and sets the flag. It then dispatches `REIMBURSEMENT_KICKOFF_TX_<slot>` from the same dispute-core instance and rolls the operator change into `ADVANCE_FUNDS_INPUT` when present. |

For the first reimbursement, the kickoff is scheduled one block after the observed advance-funds block so the newly dispatched initial deposit can precede it. If the initial-deposit flag was already set, the reimbursement kickoff is dispatched without that additional scheduled block.

## FullPenalization

The Rust implementation is named `FullPenalizationProtocol`.

### Purpose

`FullPenalizationProtocol` is the committee-wide enforcement layer for members that lose a claim. It links a successful claim against an operator or watchtower to a directory of disablers covering that member's remaining covenant paths.

The protocol does not decide whether a member should be penalized. `DisputeCoreProtocol` interprets reimbursement, challenge, DRP, and claim-gate events and selects the appropriate full-penalization action. Once a disabler directory is confirmed, `FullPenalizationProtocol` records the penalized member at committee scope and automatically fans out the remaining disablers.

There is one full-penalization instance per committee:

```text
get_full_penalization_pid(committee_id)
```

### Setup

`examples/union` sets up the same full-penalization instance on every committee member after all dispute-core and DRP instances have completed setup. On each member it:

1. Derives the protocol ID from the committee ID.
2. Stores `FullPenalizationData` under that protocol ID.
3. Calls `BitVMXClient::setup` with all committee addresses.
4. Waits for setup completion before proceeding.

This ordering is required because full penalization does not recreate the upstream covenants. It imports transaction references, UTXOs, scripts, and claim-success outputs saved by every `DisputeCoreProtocol` instance.

The participant list must use the same ordering as `Committee.members`. Operator, watchtower, and challenger indices embedded in penalization names all refer to this ordering.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `GLOBAL_SETTINGS_UUID` | `union_settings` | JSON-encoded `UnionSettings` | Union application/configuration | Supplies the stream settings used for penalization paths, including the short timelock. |
| `committee_id` | `committee` | JSON-encoded `Committee` | Dispute-core/committee setup | Supplies the ordered members and roles, packet size, aggregated keys, stream denomination, and confirmation threshold. |
| full-penalization ID | `full_penalization_data` | JSON-encoded `FullPenalizationData` | Full-penalization setup | Identifies the committee whose members and dispute cores are covered. |

The committee's aggregated take and dispute keys are registered as pregenerated aggregate keys. This protocol does not aggregate them again.

For every operator, setup reads these values from that operator's dispute-core ID:

| Name | Type | Use |
| --- | --- | --- |
| `OP_INITIAL_DEPOSIT_TXID` | `String` containing a txid | Identifies the operator's initial-deposit transaction. |
| `OP_INITIAL_DEPOSIT_AMOUNT` | `Amount` | Reconstructs the per-slot initial-deposit references. |
| `OP_INITIAL_DEPOSIT_OUT_SCRIPT_<slot>` | JSON-encoded script collection | Reconstructs each slot's initial-deposit output. |
| `OPERATOR_TAKE_ENABLER_<slot>` | `Utxo` | Connects penalization to the slot's reimbursement path. |
| `OPERATOR_WON_ENABLER_<slot>` | `Utxo` | Connects penalization to the slot's reveal/operator-won path. |
| `OP_DISABLER_DIRECTORY_UTXO` | `Utxo` | Funds the operator-disabler directory. |

For every member acting as a watchtower against an operator, setup reads these values from that member's dispute-core ID:

| Name | Type | Use |
| --- | --- | --- |
| `WT_DISABLER_DIRECTORY_UTXO` | `Utxo` | Funds the watchtower-disabler directory. |
| `WT_INIT_CHALLENGE_UTXOS` | JSON-encoded `Vec<Option<WtInitChallengeUtxos>>` | Supplies the per-operator cosign and stopper references that must be disabled after a watchtower penalty. Entries that do not represent a valid watchtower/operator pair are `None`. |
| `WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `Utxo` | Authorizes the operator-disabler directory after the watchtower wins its claim. |
| `OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `Utxo` | Authorizes the watchtower-disabler directory after the operator wins its claim. |

All per-slot collections must match `Committee.packet_size`, and all per-member collections and indices must match the stable committee ordering.

The values passed directly to `BitVMXClient::setup` are:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_FULL_PENALIZATION` |
| Participants | All committee communication addresses, in committee order |
| Setup leader index | `0`, selecting the first participant as setup leader |

### Variables received while running

Full penalization has no additional external variable that must be supplied after setup. Runtime actions arrive as transaction requests from `DisputeCoreProtocol` and as Bitcoin notifications for transactions belonging to this protocol.

Dispute core requests full-penalization actions in two situations:

- a claim gate succeeds and the losing member's disabler directory becomes eligible; or
- a later event encounters a member already recorded as penalized and must disable another still-live covenant path.

### Variables produced for other protocols

When a disabler directory is observed, full penalization stores one `PenalizedMember` under the committee ID:

| Name | Written after | Value |
| --- | --- | --- |
| `OPERATOR_PENALIZED_<op>` | `OP_DISABLER_DIRECTORY_TX_<wt>_<op>` | Operator index, `Prover` role, and the watchtower index that successfully challenged it. |
| `WATCHTOWER_PENALIZED_<wt>` | `WT_DISABLER_DIRECTORY_TX_<wt>_<op>` | Watchtower index, `Verifier` role, and the operator index that successfully challenged it. |

`DisputeCoreProtocol` reads these committee-scoped markers before starting later challenge/cosign paths. If the relevant member is already penalized, dispute core skips the normal path and requests the applicable disabler from this protocol instead.

These markers are not slot-scoped. Penalization applies to the member across the committee's packet of slots, and a later write for the same member replaces the previous stored record.

Full penalization sends no direct L2 notification and does not publish SPV proofs.

### Automatic dispatch hooks

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Logs completion only. It does not dispatch a penalization transaction. |
| Operator-disabler directory observed | Stores `OPERATOR_PENALIZED_<op>`. Every participant other than the penalized operator attempts to dispatch, for every slot, the operator disabler, the path that prevents a later operator-won action, and the lazy-operator disabler. If a lazy disabler cannot be signed because its one-time witness was already used, that item is skipped without aborting the rest of the batch. |
| Watchtower-disabler directory observed | Stores `WATCHTOWER_PENALIZED_<wt>`. Every participant other than the penalized watchtower attempts to dispatch the watchtower disabler for each operator path covered by that watchtower. |
| Other full-penalization transaction observed | Logs the notification only; no additional shared state or fan-out is triggered. |

The first directory transaction is dispatched by `DisputeCoreProtocol` after the corresponding claim gate succeeds. Individual disablers may also be requested by dispute core when it detects an already-penalized member during reimbursement, reveal, or cosign processing.

### Current implementation note

`DisputeCoreProtocol` can request `STOP_OP_WON_TX_<wt>_<op>_<slot>` directly when it encounters an operator already penalized during reveal processing. `FullPenalizationProtocol` builds this action and uses it in its automatic directory fan-out, but its current `get_transaction_by_name` dispatcher does not include the `STOP_OP_WON_TX` prefix. Consequently, that direct cross-protocol request currently returns `InvalidTransactionName`; the directory-triggered fan-out remains available because it calls the internal builder directly.

## RejectPegin

The Rust implementation is named `RejectPegInProtocol`.

### Purpose

`RejectPegInProtocol` lets one committee member reject an external peg-in request before it is accepted into a Union slot. It uses that member's individual authorization path from the request transaction, so it is a single-participant protocol rather than a committee-wide signing protocol.

The protocol is short lived: the selected member sets it up for one request-peg-in transaction, and setup completion immediately dispatches the rejection.

There is currently no deterministic reject-peg-in ID helper. The example creates a fresh random UUID for each rejection:

```text
Uuid::new_v4()
```

The chosen ID only needs to be used consistently for the stored `RejectPeginData` and the subsequent setup call on the selected member.

### Setup

Unlike accept pegin, reject pegin is set up only on the member performing the rejection. `examples/union`:

1. Selects a committee member and its `member_index`.
2. Generates a fresh protocol ID.
3. Stores `RejectPeginData` under that protocol ID.
4. Calls `BitVMXClient::setup` with only the selected member's communication address.
5. Waits for setup completion; the protocol itself dispatches the rejection during that hook.

The committee and request-peg-in transaction must already exist, but no `AcceptPegInProtocol`, dispute core, or other per-slot protocol is required for the rejection graph.

### Variables required before setup

| Scope | Name | Type | Supplied by | Meaning |
| --- | --- | --- | --- | --- |
| `committee_id` | `committee` | JSON-encoded `Committee` | Dispute-core/committee setup | Supplies the ordered members, their dispute keys, the aggregate take key, and the rejection confirmation threshold. |
| reject-pegin ID | `reject_pegin_data` | JSON-encoded `RejectPeginData` | Rejection orchestration | Identifies the request transaction, committee, and member authorization path used to reject it. |

`RejectPeginData` contains:

| Field | Requirement |
| --- | --- |
| `txid` | Transaction ID of the external request-peg-in transaction being rejected. |
| `committee_id` | ID of the committee that can accept or reject the request. |
| `member_index` | Index of the rejecting member in `Committee.members`. It selects that member's authorization path in the request transaction and must correspond to the sole setup participant. |

The values passed directly to `BitVMXClient::setup` are:

| Value | Requirement |
| --- | --- |
| Protocol type | `PROGRAM_TYPE_REJECT_PEGIN` |
| Participants | A one-element list containing only the rejecting member's communication address |
| Setup leader index | `0`, the rejecting member itself |

The protocol generates a `SPEEDUP_KEY` during setup and stores it under its own ID. This is internal setup state, not an externally supplied variable.

`Committee.reject_pegin_confirmations` becomes the confirmation threshold passed to the Bitcoin coordinator for the rejection. In `examples/union`, committee setup currently hardcodes this value to `1` and notes that it should come from the contracts.

### Variables and notifications produced for other components

`RejectPegInProtocol` does not write variables for another Union protocol. It also sends no L2 acceptance/rejection message and no SPV notification.

Its only stored output is the internally generated `SPEEDUP_KEY`, used to describe the speedup output returned with the rejection transaction.

### Automatic dispatch hooks

| Hook | Automatic behavior |
| --- | --- |
| Setup completed | Signs and immediately dispatches `REJECT_PEGIN_TX` through the Bitcoin coordinator, including its speedup data. No external dispatch call is required. |
| Rejection transaction observed | Logs the transaction ID and confirmation count. It does not update shared variables, send an L2 notification, or dispatch a follow-up transaction. |

The rejection competes with acceptance for an output of the external request-peg-in transaction. Orchestration must therefore start reject pegin before that request has already been consumed by the accept path.

## DRP

_To be documented._

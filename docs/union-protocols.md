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
| Watchtower dispute-core ID | `CLAIM_INIT_UTXOS` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `FullPenalizationProtocol` |
| Watchtower dispute-core ID | `OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO_<wt>_<op>` | `FullPenalizationProtocol` |
| DRP ID | `program_input_prev_protocol(4)` | DRP input 4: points back to the dispute-core instance carrying the cosigned pegout ID |
| DRP ID | `program_input_prev_prefix(4)` | DRP input 4: prefix for the operator cosign pegout-ID witness words |
| DRP ID | `program_input_prev_protocol(5)` | DRP input 5: points back to the dispute-core instance carrying the cosigned slot ID |
| DRP ID | `program_input_prev_prefix(5)` | DRP input 5: prefix for the operator cosign slot-ID witness |

Dispute core also stores the corresponding Winternitz public keys and later-captured witnesses in its own scope so DRP can resolve inputs 4 and 5 through the `program_input_prev_*` references.

Some values such as generated slot/pegout keys, `MY_IDX`, speedup keys, claim-init collections, and `REVEAL_IN_PROGRESS` are internal setup or state-machine data. They are not external configuration. `OP_COSIGN_UTXOS` is currently stored as an internal setup artifact and has no cross-protocol reader.

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

_To be documented._

## UserTake

_To be documented._

## AdvanceFunds

_To be documented._

## FullPenalization

_To be documented._

## RejectPegin

_To be documented._

## DRP

_To be documented._

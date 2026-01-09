# Changelog

All notable changes to this Union protocols project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [Unreleased]

### Added

- `PenalizedMember` struct to store penalized operators and watchtowers and dispatch disabler transactions if needed.
- `RejectPegin` protocol to allow the committee to reject a pegin request.
- `CANCEL_TAKE0_TX` transactions to consume `ACCEPT_PEGIN_TX` output enabler.
- `request_pegin_timelock` to `StreamSettings`. It defines the time the user block funds while the committee accepts the pegin request.
- `UnionSPVNotification` message to notify Union Client about SPV proofs related to advance funds and challenge transactions.

### Changed

- Update `ACCEPT_PEGIN_TX`:
  - Add enabler input connected to request pegin tx.
  - Add enabler output with operator dispute keys.
- Update `USER_TAKE_TX`: Add enabler input connected to `ACCEPT_PEGIN_TX` enabler output.


## [v0.3.0] - 2025-12-15

### Added

- Dispute Resolution Protocol (DRP) support.
- DisputeCommitment blocks inside DisputeCore protocol.
- Send `FundsAdvanceSPV` after advance funds TX is mined.
- `claim_gate_timelock`, `input_not_revealed_timelock`, `op_no_cosign_timelock` and `wt_no_challenge_timelock` to `StreamSettings`
- Automatic dispatch of `OPERATOR_WON_TX`.
- This `CHANGELOG.md` file.

### Changed

- KeyManager update on BitVMXClient core functionality. (Should not affect Union functionality).
- In `PegInAccepted`, `operator_take_sighash` and `operator_won_sighash` are now optional.
- `FullPenalizationProtocol` to support current DRP implementation.


## [v0.2.0] - 2025-11-28

### Added

- TLS communication support


## [v0.1.4-alpha] - 2025-11-25

### Added

- ReimbursementResult message after funds advance is completed.


## [v0.1.3-alpha] - 2025-10-17

### Fixed

- Add speedup output to USER_TAKE_TX to be consistent with contracts.


## [v0.1.2-alpha] - 2025-09-25

### Supports

- Committee setup.
- UserTake Protocol setup.
- AdvanceFunds Protocol setup.

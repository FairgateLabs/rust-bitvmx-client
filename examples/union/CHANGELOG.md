# Changelog

All notable changes to this Union protocols project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [Unreleased]

### Added

- `cancel_take0` example to demonstrate the use of `CANCEL_TAKE0_TX` transaction.
- `reject_pegin` example to demonstrate the use of `RejectPegin` protocol.
- `Member.reject_pegin` function to execute the `RejectPegin` protocol.

### Changed 

- Renamed `watchtower_disabler` example to `wt_disabler`.
- `User.request_pegin` to support new request pegin tx structure. It now receive dispute keys as parameters.

### Removed

- Removed unused parameters from `UserTakeSetup`: `stream_id`, `packet_number`, `pegout_signature_hash` and `pegout_signature_message`.

### Fixed

- `wt_disabler` example. Updated to works with current DRP implementation.


## [v0.3.0] - 2025-12-15

### Added

- This `CHANGELOG.md` file.
- Dispute Channel setup inside `setup_dispute_channel` function.
- `challenge` example. It cover both cases where operator and watchtower wins.
- `input_not_revealed` example. Where the operator does not reveal the input to the challenge.
- `op_no_cosign` example. Where an Operator does not colaborate to initialize the challenge.
- `wt_no_challenge` example. Where a Watchtower does not start to a challenge.
- `claim_gate_timelock`, `input_not_revealed_timelock`, `op_no_cosign_timelock` and `wt_no_challenge_timelock` to `StreamSettings`
- Send `FundsAdvanceSPV` after advance funds TX is mined.

### Changed

- `DisputeChannelSetup::setup` to support current DRP implementation.
- `Member.make_pairwise_keys` to set pairwise key variable in storage.
- `Committe.get_funding_wt_disabler_directory_value` to match new disablers structure.
- KeyManager update on BitVMXClient core functionality. (Should not affect Union functionality).
- In `PegInAccepted`, `operator_take_sighash` and `operator_won_sighash` are now optional.
- `FullPenalizationProtocol` to support current DRP implementation.

### Removed

- `operator_disabler` example. It's part of `challenge` example now.
- Deprecated examples from `run-all.sh` script.


## [v0.2.0] - 2025-11-28 (Last undocumented examples version)

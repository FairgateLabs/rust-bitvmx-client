# Changelog

All notable changes to this Union protocols project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

## [Unreleased]

### Added

- This `CHANGELOG.md` file.
- Dispute Channel setup inside `setup_dispute_channel` function.
- `challenge` example. It cover both cases where operator and watchtower wins.
- `input_not_revealed` example. Where the operator does not reveal the input to the challenge.
- `op_no_cosign` example. Where an Operator does not colaborate to initialize the challenge.
- `wt_no_challenge` example. Where a Watchtower does not start to a challenge.

### Removed

- `operator_disabler` and `watchtower_disabler` examples. Both are part of `challenge` example now.
- Remove deprecated examples from `run-all.sh` script.

### Fixed

- `DisputeChannelSetup::setup` to support current DRP implementation.

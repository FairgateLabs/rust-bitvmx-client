# Changelog

This file records user-visible changes to the BitVMX client API. The project is pre-release and may
introduce breaking changes between versions.

## Unreleased

### Changed

- **BREAKING**: Removed the `ProofReady` request and response, along with `BitVMXClient::proof_ready`.
  When a `GenerateZKP` job succeeds, the requester now receives `ZKPResult(uuid, proof, journal)`
  directly, so no follow-up request is needed. Use `GetZKPExecutionResult(uuid)` to query a job's
  status or result, which answers `ZKPResult`, `ProofNotReady`, `ProofGenerationError`, or `ApiError`.
- **BREAKING**: Added operation-specific timeout arguments. `Setup` and `SetupKey` now accept an optional overall
  setup timeout in seconds, `GenerateZKP` accepts an optional prover execution timeout in seconds,
  `Program::new` accepts an optional setup `Duration`, and protocol `execute_job` accepts an optional
  per-attempt job `Duration`. `None` currently falls back to one hour for setup and 900 seconds for dispatcher jobs. Protocol implementations are required to
  select explicit, operation-appropriate timeouts for production use rather than relying on these
  compatibility defaults.
- Added `DiscardDispatcherJob(request_id, job_id, reason)`, available to the configured L2 operator,
  to stop automatic retries for unresolved runtime Garbler and Emulator jobs. Successful and
  repeated idempotent requests return `JobDiscarded(request_id, job_id)`; unsupported job types or
  states return `ApiError(request_id, error)`.
- Following rust-bitvmx-storage-backend PR #43, `StorageConfig` has a `sync_writes` option, on by
  default, that fsyncs every write, including transaction commits. The `storage` and `key_storage`
  sections of the client config accept `sync_writes: false` to turn it off. `StorageConfig` has a
  new field, so direct storage-backend consumers must build it with `StorageConfig::new`.
- Following the same PR, `StorageError::ReadError` carries the RocksDB message,
  `StorageError::MissingCurrent` is returned when a database directory has no CURRENT file, and
  `Storage::repair` returns a `RepairReport`. The storage-backend CLI exits with 2 when a repair
  lost files and with 1 on errors.
- `SetVar`, `GetVar`, `SetWitness` and `GetWitness` with an invalid key, and `GenerateZKP` reusing a
  job id with a different timeout, now return `ApiError(uuid, error)`. They used to block every
  later API request and dispatcher result.
- **BREAKING (stored data)**: Expected dispatcher job records moved from `bitvmx/expected_job/<digest>`,
  indexed by the `bitvmx/expected_job/ids` list, to `bitvmx/expected_job/active/<digest>` while a
  result is expected and `bitvmx/expected_job/finished/<digest>` once terminal. The ID list is no
  longer written.

## 0.8.7

- Following [rust-bitvmx-storage-backend change `87f690e`](https://github.com/FairgateLabs/rust-bitvmx-storage-backend/commit/87f690e866bdea521dafdb7ed8b37044fc12df6a),
  the `KeyValueStore` `get`, `set`, `remove`, and `update` methods, as well as `Storage::has_key`,
  now require a structured `StorageKey` instead of raw string keys. This is a breaking API change for
  direct storage-backend consumers. `StorageKey` validates key segments, uses `/` as the shared
  separator, and provides an unambiguous prefix for child-key scans.
- Migrated client storage keys to `StorageKey` and standardized them under the `bitvmx/` component
  namespace.

## 0.8.6

- Following [rust-bitvmx-broker change `cb664c5`](https://github.com/FairgateLabs/rust-bitvmx-broker/commit/cb664c55b5190cc6ab03b28e95ff2239f339a036),
  service messages queued with `BrokerNode::send_service` are sent only when the broker is ticked.
  A message queued while processing a tick is delivered on a subsequent tick. This also applies to
  projects using the broker independently of the BitVMX client.
- Added a request UUID to the incoming `SetFundingUtxo`, `SubscribeToOutputPattern`,
  `SubscribeToRskPegin`, `GetSPVProof`, and `Shutdown` messages. This is a breaking wire-format
  change; producers must serialize the UUID as the first variant field.
- Updated the corresponding `BitVMXClient` subscription and SPV-proof methods to accept a request
  UUID. `BitVMXClient::shutdown` creates a UUID internally because shutdown has no response.
- Enabled these requests to be correlated with `ApiError(uuid, message)` as their error handling is
  refined.

## 0.8.5

- Baseline version when API change tracking began.

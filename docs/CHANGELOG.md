# Changelog

This file records user-visible changes to the BitVMX client API. The project is pre-release and may
introduce breaking changes between versions.

## Unreleased

### Changed

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

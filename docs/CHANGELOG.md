# Changelog

This file records user-visible changes to the BitVMX client API. The project is pre-release and may
introduce breaking changes between versions.

## Unreleased

### Added

- `comms.public_address` is an optional config setting with the address `GetCommInfo` returns, for
  nodes whose listen `comms.address` peers cannot reach (Docker, NAT). The node still listens on
  `comms.address`, and `GetCommInfo` returns it when `public_address` is not set. It must be a
  literal `IP:port`; hostnames fail config parsing.
- BitVMX refuses to start when the address it would return from `GetCommInfo` (`comms.public_address`,
  or `comms.address` when unset) has an unspecified IP (`0.0.0.0`, `::`) or port 0, since no peer can
  dial it. Set `comms.public_address` when listening on `0.0.0.0`.
- BitVMX also refuses to start when that address is loopback, private (`10/8`, `172.16/12`,
  `192.168/16`), shared/CGNAT (`100.64/10`), link-local, multicast, broadcast, benchmarking
  (`198.18/15`), reserved (`240/4`) or a documentation range, or the IPv6 equivalents. Set
  `comms.allow_private_address: true` when every peer shares that network (local tests, Docker, a
  VPC or VPN). This is a breaking change: existing configs with such an address need the flag. The
  bundled regtest and testnet configs set it.

### Changed

- Following rust-bitvmx-storage-backend PR #43, `StorageConfig` has a `sync_writes` option, on by
  default, that fsyncs every write, including transaction commits. The `storage` and `key_storage`
  sections of the client config accept `sync_writes: false` to turn it off. `StorageConfig` has a
  new field, so direct storage-backend consumers must build it with `StorageConfig::new`.
- Following the same PR, `StorageError::ReadError` carries the RocksDB message,
  `StorageError::MissingCurrent` is returned when a database directory has no CURRENT file, and
  `Storage::repair` returns a `RepairReport`. The storage-backend CLI exits with 2 when a repair
  lost files and with 1 on errors.
- `CommsAddress` has a new `pubkey_pem` field with the participant's full comms RSA public key
  (PEM). `CommsAddress::new` and `CommsAddress::try_new` take it as a third argument. This is a
  breaking change for `rust-bitvmx-client-types` consumers.
- `Setup` and `SetupKey` must give each participant a
  `pubkey_pem` that hashes to its `pubkey_hash`. A missing, invalid, or mismatched key is rejected.
  The node stores these keys as the participants' verification keys and no longer sends them a
  `VerificationKeyRequest`.
- `CommInfo` now returns the node's `pubkey_pem` inside its `CommsAddress`, so L2 can forward it
  to the other participants.
- `CommsAddress` no longer implements `FromStr`. Build it with `CommsAddress::try_new` or serde.
- `Config::comms_address()` is removed: it returned the listen address, not the one peers dial. Use
  `CommsConfig::public_address()` or `BitVMX::comms_address()`.
- `CommsAddress` equality, ordering, and hashing use `address` and `pubkey_hash` only and ignore
  `pubkey_pem`. Addresses stored before this field existed deserialize with an empty `pubkey_pem`.

### Added

- `ErrorReportKind::DecryptFailed`. A `Decrypt` request that has a bad ciphertext or names a
  public key this node has no private key for is answered with an `Error` scoped to that request,
  instead of stopping the node. Key store failures still stop it.

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

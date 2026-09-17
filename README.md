# BitVMX Client

The BitVMX Client provides the core functionality for interacting with the BitVMX protocol and the Bitcoin blockchain.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Installation

Clone the repository and initialize the submodules:

```bash
git clone git@github.com:FairgateLabs/rust-bitvmx-client.git
```

## Build

```bash
cargo build
```

Release build with debug symbols:

```bash
cargo build --profile release-with-debug
```


## Security
To use encrypted configuration files read the setting [README.md](https://github.com/FairgateLabs/rust-bitvmx-settings/blob/bb216227310a714293aa60dc84107304b336b83f/README.md#security)


## Testing

### Client test

NOTE: BitVMX-CPU release binary should be built beforehand
```bash
cd BitVMX-CPU
cargo build --release
```

Run the client tests:

```bash
RUST_BACKTRACE=1 cargo test --release -- --ignored test_all
```

### Integration test

If you are running a bitcoin node, you should stop it before running the integration test (as it handles its own node).

```bash
RUST_BACKTRACE=1 cargo test --release -- --ignored test_full
```

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---

## BitVMX API Message

Documentation for the BitVMX client API message system and request/response patterns. The API uses JSON RPC over the BitVMX broker.

### Message Request/Response Pairs

This table shows the mapping between request messages and their expected response messages based on the correlation ID system used in the BitVMX client, organized by functional categories.

#### General Information

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `Ping(uuid)` | `Pong(uuid)` | Basic connectivity test |
| `GetCommInfo(uuid)` | `CommInfo(uuid, coms_address)` | Get communication information |

#### Program Management

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `Setup(uuid, program_type, participants, leader_idx)` | `SetupCompleted(uuid)` or `ApiError(uuid, error)` | Setup the program; returns `ApiError` for duplicate identifiers and non-fatal setup failures |
| `SetVar(uuid, key, value)` | `Variable(uuid, key, value)` | Set a variable in the program |
| `GetVar(uuid, key)` | `Variable(uuid, key, value)` or `NotFound(uuid, key)` | Get variable value |
| `SetWitness(uuid, address, witness)` | `Witness(uuid, key, witness)` | Set witness data |
| `GetWitness(uuid, address)` | `Witness(uuid, key, witness)` or `NotFound(uuid, key)` | Get witness data |
| `GetHashedMessage(uuid, name, vout, leaf)` | `HashedMessage(uuid, name, vout, leaf, _)`, `NotFound(uuid, error)`, or `ApiError(uuid, error)` | Get hashed message; returns `NotFound` when the program is absent and `ApiError` for non-fatal lookup failures |
| `GetProtocolVisualization(uuid)` | `ProtocolVisualization(uuid, visualization)`, `NotFound(uuid, error)`, or `ApiError(uuid, error)` | Get protocol visualization; returns `NotFound` when the program is absent and `ApiError` for non-fatal visualization failures |

#### Transaction Management

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GetTransaction(uuid, txid)` | `Transaction(uuid, transaction_status, name)` | Get transaction details |
| `GetTransactionInfoByName(uuid, name)` | `TransactionInfo(uuid, name, transaction)` | Get transaction by name |
| `DispatchTransaction(uuid, transaction, confirmation_threshold, stuck_in_mempool_blocks)` | `Transaction(uuid, transaction_status, name)` or `ApiError(uuid, error)` | Dispatch a transaction; returns `ApiError` for an invalid confirmation threshold |
| `DispatchTransactionName(uuid, name)` | `Transaction(uuid, transaction_status, name)`, `NotFound(uuid, error)`, or `ApiError(uuid, error)` | Dispatch transaction by name; returns `NotFound` when the program is absent and `ApiError` for an invalid or missing transaction name |
| `GetSPVProof(uuid, txid)` | `SPVProof(txid, spv_proof)` | Get SPV proof for transaction |

#### Subscriptions

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SubscribeToTransaction(uuid, txid, confirmation_threshold)` | `Transaction(uuid, transaction_status, name)` or `ApiError(uuid, error)` | Subscribe to transaction updates; returns `ApiError` for an invalid confirmation threshold |
| `SubscribeToSpendingUTXO(uuid, txid, vout, confirmation_threshold)` | `SpendingUTXOTransactionFound(uuid, txid, vout, transaction_status)` or `ApiError(uuid, error)` | Track a UTXO and notify when it is spent; returns `ApiError` for an invalid confirmation threshold |
| `SubscribeToOutputPattern(uuid, filter, confirmation_threshold)` | `OutputPatternTransactionFound(txid, transaction_status, tag)` or `ApiError(uuid, error)` | Subscribe to matching transaction outputs; returns `ApiError` for an invalid confirmation threshold |
| `SubscribeToRskPegin(uuid, confirmation_threshold)` | `PeginTransactionFound(txid, transaction_status)` or `ApiError(uuid, error)` | Subscribe to RSK pegin transactions; returns `ApiError` for an invalid confirmation threshold |

#### Speed up

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SetFundingUtxo(uuid, utxo)` | N/A | Set funding UTXO (no direct response) |

#### Wallet Operations

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GetFundingBalance(uuid)` | `FundingBalance(uuid, balance)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Get funding balance |
| `GetFundingAddress(uuid)` | `FundingAddress(uuid, address)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Get funding address |
| `SendFunds(uuid, destination, fee)` | `FundsSent(uuid, txid)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Send funds |

#### Key Management

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SetupKey(uuid, addresses, operator_keys, leader_idx)` | `ApiError(uuid, error)` on failure; otherwise N/A | Setup keys; returns `ApiError` for invalid participants, duplicate identifiers, or other non-fatal setup failures, and has no direct success response |
| `GetAggregatedPubkey(uuid)` | `AggregatedPubkey(uuid, aggregated_pubkey)`, `AggregatedPubkeyNotReady(uuid)`, or `ApiError(uuid, error)` | Get aggregated public key; returns `ApiError` when the stored value is not a public key |
| `GetKeyPair(uuid)` | `KeyPair(uuid, private_key, public_key)` or `ApiError(uuid, error)` | Generate key pair; returns `ApiError` when the aggregated key is missing or invalid, or for a non-storage key-manager failure |
| `GetPubKey(uuid, new_key)` | `PubKey(uuid, pub_key)` or `ApiError(uuid, error)` | Get public key; returns `ApiError` when an existing aggregated key is missing or invalid, or for a non-storage key-manager failure |
| `GetEvenPubKey(uuid)` | `PubKey(uuid, pub_key)` or `ApiError(uuid, error)` | Generate an adjusted public key; returns `ApiError` for a non-storage key-manager failure |
| `SignMessage(uuid, payload_to_sign, public_key_to_use)` | `SignedMessage(uuid, signature_r, signature_s, recovery_id)` or `ApiError(uuid, error)` | Sign a message; returns `ApiError` for an invalid payload or a non-storage key-manager failure |

#### Encryption

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `Encrypt(uuid, payload_to_encrypt, public_key_to_use)` | `Encrypted(uuid, encrypted_message)` or `ApiError(uuid, error)` | Encrypt a message; returns `ApiError` for a non-storage key-manager failure |
| `Decrypt(uuid, payload_to_decrypt, public_key_to_use)` | `Decrypted(uuid, decrypted_message)` or `ApiError(uuid, error)` | Decrypt a message; returns `ApiError` for a non-storage key-manager failure |

#### Zero-Knowledge Proofs

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GenerateZKP(uuid, payload_to_sign, name)` | `ProofReady(uuid)` or `ProofNotReady(uuid)` or `ProofGenerationError(uuid, error)` | Generate zero-knowledge proof |
| `ProofReady(uuid)` | `ProofReady(uuid)` | Check if proof is ready |
| `GetZKPExecutionResult(uuid)` | `ZKPResult(uuid, zkp_result, zkp_proof)` or `ApiError(uuid, error)` | Get ZKP execution result; returns `ApiError` when a successful job is missing its proof or journal |

### Special Cases

#### Transaction Name

- Named transactions dispatched internally by the protocols will be sent to all protocol participants as response message `Transaction` without needing to request a `GetTransaction` message

#### Subscription Messages

- Successful subscription requests have no direct response; they generate events when relevant transactions are found. An invalid confirmation threshold produces an immediate `ApiError(uuid, error)` response.
- `Shutdown(uuid)` requests a node shutdown and has no direct response

#### Error Handling

Errors come in two shapes.

**Reply-style** errors answer a request and carry its UUID: `ApiError`, `NotFound`,
`WalletNotReady`, `WalletError`, and `ProofGenerationError`. `ApiError` represents request validation
or business-state failures that do not have a more specific response type. The UUID ensures that
responses are matched to the correct request even in error cases. These appear in the tables above.

**Push-style** errors are unprompted — the client detected something and is telling you. There is
exactly one such message, and because it answers no request it appears in no table:

```
Error(ErrorReport { scope, kind, detail })
```

`scope` says who it concerns: `Node` (the client itself), `Program(uuid)`, or `Request(uuid)`.
A `Request`-scoped report is delivered to whoever issued that request, not to L2.

`kind` says what happened:

| Kind | Meaning |
|---|---|
| `SetupFailed { step, peer, reason }` | A setup cannot complete. Terminal: no further messages for that program, and its id cannot be reused. |
| `JobDispatcherUnresponsive(which)` | A job dispatcher stopped answering pings within the timeout. It may be gone, or far enough behind on its inbox to look that way, so treat it as a warning about job progress rather than proof the process died. |
| `JobDispatcherRecovered(which)` | That dispatcher is answering again. |
| `BitcoinRpcUnavailable` | The bitcoin node is unreachable. The client keeps running and retrying. |
| `BitcoinRpcRecovered` | The bitcoin node is reachable again. |
| `Fatal` | The client cannot continue and is exiting — storage or the message broker failed. Best-effort: it may not arrive. |
| `NodeStopping` | The client is stopping on an error that does not indicate corrupted state. It exits zero, unlike `Fatal`, so it is not asking to be restarted. Carrying on past these is not implemented yet. |
| `TransactionDispatchFailed { txid }` | Dispatch retries exhausted; the transaction will never confirm. |
| `SpeedupDispatchFailed { txid }` | A CPFP/RBF speedup could not be dispatched. |
| `TransactionStuckInMempool { txid }` | A transaction has sat in the mempool past its threshold. |
| `FeeRateTooHigh { estimated, max }` | The estimated fee rate exceeded the configured cap; nothing was dispatched. |
| `MaxFeeRateReached { txid, effective_fee_rate }` | A speedup hit the fee cap. No further boosts will be applied. |
| `InsufficientFunds { available, required }` | A funding UTXO could not cover a speedup fee. |
| `FundingNotAvailable` | No funding UTXO is available at all. |
| `InvalidFundingUtxo { amount, min_required }` | A funding UTXO was provided but is unusable. |

`detail` is optional free text for logs and operators; never match on it.

The liveness kinds are reported on change, not repeatedly: one message when the condition starts,
one when it clears.

### Notes

- All correlation IDs are generated using the `request_to_correlation_id()` and `response_to_correlation_id()` functions
- UUID-based correlation IDs ensure that multiple concurrent operations can be tracked independently
- Some operations (like `SetFundingUtxo`, `SetupKey`) don't have direct response messages
- The system supports both named and unnamed transaction dispatching with different correlation ID patterns

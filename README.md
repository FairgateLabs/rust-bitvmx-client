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
| `Setup(uuid, program_type, participants, leader_idx)` | `SetupCompleted(uuid)` | Setup the program |
| `SetVar(uuid, key, value)` | `Variable(uuid, key, value)` | Set a variable in the program |
| `GetVar(uuid, key)` | `Variable(uuid, key, value)` or `NotFound(uuid, key)` | Get variable value |
| `SetWitness(uuid, address, witness)` | `Witness(uuid, key, witness)` | Set witness data |
| `GetWitness(uuid, address)` | `Witness(uuid, key, witness)` or `NotFound(uuid, key)` | Get witness data |
| `GetHashedMessage(uuid, name, vout, leaf)` | `HashedMessage(uuid, name, vout, leaf, _)` | Get hashed message |
| `GetProtocolVisualization(uuid)` | `ProtocolVisualization(uuid, visualization)` | Get protocol visualization |

#### Transaction Management

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GetTransaction(uuid, txid)` | `Transaction(uuid, transaction_status, name)` | Get transaction details |
| `GetTransactionInfoByName(uuid, name)` | `TransactionInfo(uuid, name, transaction)` | Get transaction by name |
| `DispatchTransaction(uuid, transaction)` | `Transaction(uuid, transaction_status, name)` | Dispatch a transaction |
| `DispatchTransactionName(uuid, name)` | `Transaction(uuid, transaction_status, name)` | Dispatch transaction by name |
| `GetSPVProof(txid)` | `SPVProof(txid, spv_proof)` | Get SPV proof for transaction |

#### Subscriptions

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SubscribeToTransaction(uuid, txid)` | `Transaction(uuid, transaction_status, name)` | Subscribe to transaction updates |
| `SubscribeToSpendingUTXO(uuid, txid, vout, confirmation_threshold)` | `SpendingUTXOTransactionFound(uuid, txid, vout, transaction_status)` | Track a UTXO and notify when it is spent |
| `SubscribeToRskPegin()` | `PeginTransactionFound(txid, transaction_status)` | Subscribe to RSK pegin transactions |

#### Speed up

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SetFundingUtxo(utxo)` | N/A | Set funding UTXO (no direct response) |

#### Wallet Operations

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GetFundingBalance(uuid)` | `FundingBalance(uuid, balance)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Get funding balance |
| `GetFundingAddress(uuid)` | `FundingAddress(uuid, address)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Get funding address |
| `SendFunds(uuid, destination, fee)` | `FundsSent(uuid, txid)` or `WalletNotReady(uuid)` or `WalletError(uuid, error)` | Send funds |

#### Key Management

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `SetupKey(uuid, addresses, operator_key, funding_key)` | N/A | Setup keys (no direct response) |
| `GetAggregatedPubkey(uuid)` | `AggregatedPubkey(uuid, aggregated_pubkey)` or `AggregatedPubkeyNotReady(uuid)` | Get aggregated public key |
| `GetKeyPair(uuid)` | `KeyPair(uuid, private_key, public_key)` | Generate key pair |
| `GetPubKey(uuid, new_key)` | `PubKey(uuid, pub_key)` | Get public key |
| `SignMessage(uuid, payload_to_sign, public_key_to_use)` | `SignedMessage(uuid, signature_r, signature_s, recovery_id)` | Sign a message |

#### Encryption

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `Encrypt(uuid, payload_to_encrypt, public_key_to_use)` | `Encrypted(uuid, encrypted_message)` | Encrypt a message |
| `Decrypt(uuid, payload_to_decrypt)` | `Decrypted(uuid, decrypted_message)` | Decrypt a message |

#### Zero-Knowledge Proofs

| Request Message | Expected Response Message | Notes |
|---|---|---|
| `GenerateZKP(uuid, payload_to_sign, name)` | `ProofReady(uuid)` or `ProofNotReady(uuid)` or `ProofGenerationError(uuid, error)` | Generate zero-knowledge proof |
| `ProofReady(uuid)` | `ProofReady(uuid)` | Check if proof is ready |
| `GetZKPExecutionResult(uuid)` | `ZKPResult(uuid, zkp_result, zkp_proof)` | Get ZKP execution result |

### Special Cases

#### Transaction Name

- Named transactions dispatched internally by the protocols will be sent to all protocol participants as response message `Transaction` without needing to request a `GetTransaction` message

#### Subscription Messages

- `SubscribeToRskPegin()` is a subscription message that doesn't have direct request/response pairs
- It generates events when relevant transactions are found

#### Error Handling

Errors come in two shapes.

**Reply-style** errors answer a request and carry its UUID: `NotFound`, `WalletNotReady`,
`WalletError`, `ProofGenerationError`. The UUID ensures that responses are matched to the correct
request even in error cases. These appear in the tables above.

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

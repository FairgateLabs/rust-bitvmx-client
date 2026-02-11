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

- Some operations can return error responses like `NotFound`, `WalletNotReady`, or `WalletError`
- The UUID ensures that responses are matched to the correct request even in error cases

### Notes

- All correlation IDs are generated using the `request_to_correlation_id()` and `response_to_correlation_id()` functions
- UUID-based correlation IDs ensure that multiple concurrent operations can be tracked independently
- Some operations (like `SetFundingUtxo`, `SetupKey`) don't have direct response messages
- The system supports both named and unnamed transaction dispatching with different correlation ID patterns

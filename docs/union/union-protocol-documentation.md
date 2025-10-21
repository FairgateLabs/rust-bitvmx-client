# Union Protocol Documentation

## Overview

The Union protocol is a Bitcoin-based bridge system that enables users to move funds between Bitcoin and Rootstock through a committee of operators. The protocol consists of three main processes that work together to facilitate secure, trust-minimized cross-chain transactions.

## Protocol Processes

### 1. Initial Setup Process

**Purpose**: Establishes the committee infrastructure and enables the bridge system to operate.

**Components**: Init Protocol ([`init.rs`](../../src/program/protocols/union/init.rs))

**User Interaction**: Committee members and operators interact with this process to set up the initial infrastructure.

#### Key Variables Set by User

- `InitData`: Contains committee information and watchtower UTXO
- `Committee`: Defines the committee structure with members and their roles

#### Setup Process

1. **Committee Creation**: Users create a committee with multiple members (operators)
2. **Key Generation**: Each member generates cryptographic keys (take, dispute, speedup)
3. **Watchtower Setup**: A designated watchtower member creates the initial deposit
4. **Start Enabler Creation**: Creates enabler transactions for each committee member

#### User Commands

```rust
// From main.rs - Committee setup
let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
committee.setup_keys()?;
committee.setup_dispute_protocols()?;

// Watchtower initialization
watchtowers_init(&mut committee)?;
```

#### Key Transactions

- `WATCHTOWER_SETUP_TX`: Initial funding transaction
- `WATCHTOWER_START_ENABLER_TX`: Enables committee members to start operations

---

### 2. Accept PegIn Process

**Purpose**: Handles the acceptance of peg-in requests from users, creating the necessary Bitcoin transactions to lock funds on Bitcoin.

**Components**: AcceptPegIn Protocol ([`accept_pegin.rs`](../../src/program/protocols/union/accept_pegin.rs))

**User Interaction**: Users trigger this process by sending a peg-in request with their Bitcoin transaction details.

#### Key Variables Set by User

- `PegInRequest`: Contains user's peg-in transaction details
- `Committee`: Committee information for multi-signature operations

#### Setup Process

1. **PegIn Request**: User creates a Bitcoin transaction and requests peg-in
2. **Committee Acceptance**: Committee members sign the accept peg-in transaction
3. **Operator Take Setup**: Creates transactions for operators to claim funds
4. **Speedup Integration**: Adds speedup transactions for faster processing

#### User Commands

```rust
// From main.rs - Request and accept peg-in
let (request_pegin_txid, amount) = request_pegin(committee.public_key()?, user)?;
committee.accept_pegin(
    committee.committee_id(),
    request_pegin_txid,
    amount,
    accept_pegin_sighash,
    slot_index,
    rootstock_address,
    reimbursement_pubkey,
    false,
)?;
```

#### Key Transactions

- `ACCEPT_PEGIN_TX`: Main transaction that locks user funds

---

### 3. PegOut Process

The PegOut process has two paths depending on committee member participation:

#### 3a. User Take (Optimistic Path)

**Purpose**: The preferred method where users directly claim their funds when all committee members have signed the pegout.

**Components**: UserTake Protocol ([`user_take.rs`](../../src/program/protocols/union/user_take.rs))

**User Interaction**: Users trigger this when they have the required committee signatures.

#### Key Variables Set by User

- `PegOutRequest`: Contains user's claim details and aggregated key information
- `Committee`: Committee information for signature verification

#### Setup Process

1. **PegOut Request**: User requests to claim their locked funds
2. **Signature Verification**: Committee verifies user's claim
3. **Fund Release**: User receives their Bitcoin funds directly
4. **Speedup Processing**: Optional speedup transaction for faster confirmation

#### User Commands

```rust
// From main.rs - Request pegout (optimistic path)
let user_take_utxo = committee.request_pegout(
    user_pubkey,
    slot_index,
    stream_id,
    packet_number,
    amount,
    pegout_id,
    pegout_signature_hash,
    pegout_signature_message,
)?;
```

#### Key Transactions

- `USER_TAKE_TX`: Main transaction that releases funds to user

#### 3b. Advance Funds (Fallback Path)

**Purpose**: The fallback method when not all committee members have signed the pegout. An operator advances funds to the user.

**Components**: AdvanceFunds Protocol ([`advance_funds.rs`](../../src/program/protocols/union/advance_funds.rs))

**User Interaction**: Users receive funds through an operator when committee consensus is not achieved.

#### Key Variables Set by User

- `AdvanceFundsRequest`: Contains user details and pegout information
- `Committee`: Committee information for fund advancement

#### Setup Process

1. **Fund Advancement**: Operator advances funds to user's address
2. **Pegout ID Storage**: Stores the L2 transaction ID for tracking
3. **Reimbursement Setup**: Sets up operator reimbursement
4. **Initial Deposit**: Creates initial deposit for dispute resolution

#### User Commands

```rust
// From main.rs - Advance funds (fallback path)
committee.advance_funds(
    slot_index,
    user_pubkey,
    pegout_id,
    selected_operator_pubkey,
    get_advance_funds_fee()?,
)?;
```

#### Key Transactions

- `ADVANCE_FUNDS_TX`: Main transaction that sends funds to user
- `OP_INITIAL_DEPOSIT_TX`: Creates initial deposit for dispute resolution
- `REIMBURSEMENT_KICKOFF_TX`: Initiates operator reimbursement
- `OPERATOR_TAKE_TX`: Allows operators to claim their portion
- `OPERATOR_WON_TX`: Alternative path for operator claims

---

## Complete User Workflow

### Phase 1: Initial Setup

```rust
// Create committee and setup keys
let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
committee.setup_keys()?;

// Initialize watchtowers
watchtowers_init(&mut committee)?;
```

### Phase 2: Accept PegIn Process

```rust
// User requests peg-in
let (request_pegin_txid, amount) = request_pegin(committee.public_key()?, user)?;

// Committee accepts peg-in
committee.accept_pegin(
    committee.committee_id(),
    request_pegin_txid,
    amount,
    accept_pegin_sighash,
    slot_index,
    rootstock_address,
    reimbursement_pubkey,
    false,
)?;
```

### Phase 3: PegOut Process

The PegOut process has two possible paths:

#### Path A: User Take (Optimistic Path)

*Used when all committee members have signed the pegout*

```rust
// User directly claims their funds
let user_take_utxo = committee.request_pegout(
    user_pubkey,
    slot_index,
    stream_id,
    packet_number,
    amount,
    pegout_id,
    pegout_signature_hash,
    pegout_signature_message,
)?;
```

#### Path B: Advance Funds (Fallback Path)

*Used when not all committee members have signed the pegout*

```rust
// Operator advances funds to user
committee.advance_funds(
    slot_index,
    user_pubkey,
    pegout_id,
    selected_operator_pubkey,
    get_advance_funds_fee()?,
)?;
```

## Key Features

### Security

- **Multi-signature**: All transactions require committee consensus
- **Dispute Resolution**: Built-in mechanisms for handling disputes
- **Timelock Protection**: Time-based security for fund recovery

### Efficiency

- **Speedup Transactions**: Optional faster confirmation
- **Batch Processing**: Multiple operations in single transactions
- **Fee Optimization**: Efficient fee structure for users

### Flexibility

- **Multiple Operators**: Committee-based approach for decentralization
- **Configurable Parameters**: Adjustable timeouts and fees
- **Network Support**: Works with regtest, testnet, and mainnet

## Error Handling

The protocol includes comprehensive error handling for:

- **Invalid Signatures**: Rejects transactions with invalid signatures
- **Insufficient Funds**: Prevents transactions with insufficient balance
- **Timelock Violations**: Enforces time-based security constraints
- **Committee Disagreement**: Handles cases where committee members disagree

## Monitoring and Logging

All protocols include extensive logging for:

- **Transaction Status**: Real-time transaction monitoring
- **Committee Actions**: Tracking of committee member activities
- **Error Conditions**: Detailed error reporting and recovery
- **Performance Metrics**: Latency and throughput monitoring

This documentation provides a comprehensive overview of the Union protocol from a user's perspective, focusing on the practical aspects of interacting with the system through the various protocol components.

# Union Bridge Architecture - C4 Diagrams

## Level 1: System Context Diagram

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ffffff', 'primaryTextColor': '#000000', 'primaryBorderColor': '#000000', 'lineColor': '#000000', 'secondaryColor': '#ffffff', 'tertiaryColor': '#ffffff'}}}%%

C4Context
    Person(user, "User", "End user performing Bitcoin-RBTC peg operations")
    Person(committee, "Committee Members", "Operators and Watchtowers who sign transactions")
    
    System(bitcoin, "Bitcoin Network", "Bitcoin blockchain for BTC transactions")
    System(rsk, "RSK Network", "Rootstock blockchain hosting smart contracts")
    
    System(union_bridge, "Union Bridge System", "Cross-chain bridge between Bitcoin and RSK")
    
    Rel(user, union_bridge, "Peg operations", "HTTPS")
    Rel(committee, union_bridge, "Signs", "HTTPS")
    Rel(union_bridge, bitcoin, "Monitors", "Bitcoin RPC")
    Rel(union_bridge, rsk, "Interacts", "EVM RPC")
    Rel(user, bitcoin, "Sends BTC", "Bitcoin")
    Rel(user, rsk, "Receives RBTC", "EVM")
    
    UpdateElementStyle(user, $fontColor="#ffffff", $bgColor="#1976d2")
    UpdateElementStyle(committee, $fontColor="#ffffff", $bgColor="#7b1fa2")
    UpdateElementStyle(bitcoin, $fontColor="#ffffff", $bgColor="#f57c00")
    UpdateElementStyle(rsk, $fontColor="#ffffff", $bgColor="#388e3c")
    UpdateElementStyle(union_bridge, $fontColor="#ffffff", $bgColor="#d32f2f")
```

## Level 2: Container Diagram

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ffffff', 'primaryTextColor': '#000000', 'primaryBorderColor': '#000000', 'lineColor': '#000000', 'secondaryColor': '#ffffff', 'tertiaryColor': '#ffffff'}}}%%

C4Container
    Person(user, "User", "End user")
    Person(committee, "Committee Members", "Operators and Watchtowers")
    
    System_Ext(bitcoin, "Bitcoin Network", "Bitcoin blockchain")
    System_Ext(rsk, "RSK Network", "Rootstock blockchain")
    
    Container_Boundary(union_system, "Union Bridge System") {
        Container(union_client, "Union Bridge Client", "Rust", "Orchestrates bridge operations")
        Container(bitvmx, "BitVMX Services", "Rust", "Bitcoin transaction verification")
        Container(smart_contracts, "Smart Contracts", "Solidity", "Bridge logic on RSK")
    }
    
    Rel(user, union_client, "Peg ops", "HTTPS")
    Rel(committee, union_client, "Signs", "HTTPS")
    Rel(union_client, smart_contracts, "Calls", "EVM RPC")
    Rel(union_client, bitvmx, "Executes", "RPC")
    Rel(union_client, bitcoin, "Monitors", "Bitcoin RPC")
    Rel(union_client, rsk, "Interacts", "EVM RPC")
    Rel(bitvmx, bitcoin, "Verifies", "Bitcoin RPC")
    Rel(smart_contracts, rsk, "Deployed", "EVM")
    
    UpdateElementStyle(user, $fontColor="#ffffff", $bgColor="#2563eb")
    UpdateElementStyle(committee, $fontColor="#ffffff", $bgColor="#7c3aed")
    UpdateElementStyle(bitcoin, $fontColor="#ffffff", $bgColor="#ea580c")
    UpdateElementStyle(rsk, $fontColor="#ffffff", $bgColor="#059669")
    UpdateElementStyle(union_client, $fontColor="#1f2937", $bgColor="#dbeafe")
    UpdateElementStyle(bitvmx, $fontColor="#1f2937", $bgColor="#fed7aa")
    UpdateElementStyle(smart_contracts, $fontColor="#1f2937", $bgColor="#e9d5ff")
```

## Level 3: Component Diagram - Union Bridge Client

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ffffff', 'primaryTextColor': '#000000', 'primaryBorderColor': '#000000', 'lineColor': '#000000', 'secondaryColor': '#ffffff', 'tertiaryColor': '#ffffff'}}}%%

C4Component
    Person(user, "User", "End user")
    Person(committee, "Committee Members", "Operators and Watchtowers")
    
    System_Ext(bitcoin, "Bitcoin Network", "Bitcoin blockchain")
    System_Ext(rsk, "RSK Network", "Rootstock blockchain")
    System_Ext(bitvmx, "BitVMX Services", "Bitcoin verification")
    System_Ext(contracts, "Smart Contracts", "Bridge contracts on RSK")
    
    Container_Boundary(union_client, "Union Bridge Client") {
        Component(user_api, "User API", "Rust", "User interface")
        Component(coordinator, "Coordinator", "Rust", "Orchestrates operations")
        Component(block_indexer, "Block Indexer", "Rust", "Monitors RSK blocks")
        Component(log_indexer, "Log Indexer", "Rust", "Monitors contract events")
        Component(tx_dispatcher, "Transaction Dispatcher", "Rust", "Broadcasts transactions")
    }
    
    Rel(user, user_api, "Peg ops", "HTTPS")
    Rel(user_api, coordinator, "Requests", "Internal")
    Rel(committee, coordinator, "Signs", "HTTPS")
    Rel(coordinator, contracts, "Calls", "EVM RPC")
    Rel(coordinator, bitvmx, "Executes", "RPC")
    Rel(coordinator, tx_dispatcher, "Broadcasts", "Internal")
    Rel(block_indexer, rsk, "Monitors", "EVM RPC")
    Rel(log_indexer, rsk, "Monitors", "EVM RPC")
    Rel(coordinator, block_indexer, "Gets data", "Internal")
    Rel(coordinator, log_indexer, "Gets events", "Internal")
    Rel(tx_dispatcher, bitcoin, "Broadcasts", "Bitcoin RPC")
    
    UpdateElementStyle(user, $fontColor="#ffffff", $bgColor="#2563eb")
    UpdateElementStyle(committee, $fontColor="#ffffff", $bgColor="#7c3aed")
    UpdateElementStyle(bitcoin, $fontColor="#ffffff", $bgColor="#ea580c")
    UpdateElementStyle(rsk, $fontColor="#ffffff", $bgColor="#059669")
    UpdateElementStyle(bitvmx, $fontColor="#ffffff", $bgColor="#dc2626")
    UpdateElementStyle(contracts, $fontColor="#ffffff", $bgColor="#7c3aed")
    UpdateElementStyle(user_api, $fontColor="#1f2937", $bgColor="#dbeafe")
    UpdateElementStyle(coordinator, $fontColor="#1f2937", $bgColor="#fecaca")
    UpdateElementStyle(block_indexer, $fontColor="#1f2937", $bgColor="#bbf7d0")
    UpdateElementStyle(log_indexer, $fontColor="#1f2937", $bgColor="#dbeafe")
    UpdateElementStyle(tx_dispatcher, $fontColor="#1f2937", $bgColor="#fed7aa")
```

## Level 3: Component Diagram - BitVMX Services

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ffffff', 'primaryTextColor': '#000000', 'primaryBorderColor': '#000000', 'lineColor': '#000000', 'secondaryColor': '#ffffff', 'tertiaryColor': '#ffffff'}}}%%

C4Component

    System_Ext(union_client, "Union Bridge Client", "Orchestrates operations")
    System_Ext(committee, "Committee Members", "Transaction signers")
    System_Ext(bitcoin, "Bitcoin Network", "Bitcoin blockchain")
    
    Container_Boundary(bitvmx_system, "BitVMX Services") {
        Component(bitvmx_client, "BitVMX Client", "Rust", "Core client with monitor & broker")
        Component(job_dispatcher, "Job Dispatcher", "Rust", "Dispatches verification jobs")
        Component(bitvmx_cpu, "BitVMX CPU", "Rust", "Executes BitVM computations")
    }
    
    Rel(union_client, bitvmx_client, "Executes", "RPC")
    Rel(committee, bitvmx_client, "Signs", "HTTPS")
    Rel(bitvmx_client, job_dispatcher, "Dispatches", "Internal")
    Rel(job_dispatcher, bitvmx_cpu, "Executes", "Internal")
    Rel(bitvmx_client, bitcoin, "Monitors", "Bitcoin RPC")
    
    UpdateElementStyle(union_client, $fontColor="#ffffff", $bgColor="#2563eb")
    UpdateElementStyle(committee, $fontColor="#ffffff", $bgColor="#7c3aed")
    UpdateElementStyle(bitcoin, $fontColor="#ffffff", $bgColor="#ea580c")
    UpdateElementStyle(bitvmx_client, $fontColor="#1f2937", $bgColor="#fed7aa")
    UpdateElementStyle(job_dispatcher, $fontColor="#1f2937", $bgColor="#fed7aa")
    UpdateElementStyle(bitvmx_cpu, $fontColor="#1f2937", $bgColor="#e9d5ff")
```

## Level 3: Component Diagram - Smart Contracts

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor': '#ffffff', 'primaryTextColor': '#000000', 'primaryBorderColor': '#000000', 'lineColor': '#000000', 'secondaryColor': '#ffffff', 'tertiaryColor': '#ffffff'}}}%%

C4Component

    System_Ext(user, "User", "Initiates operations")
    System_Ext(union_client, "Union Bridge Client", "Interacts with contracts")
    System_Ext(bitcoin, "Bitcoin Network", "Verifies transactions")
    
    Container_Boundary(rsk_contracts, "Smart Contracts on RSK") {
        Component(powpeg, "PowPeg Bridge", "Solidity", "Main bridge contract")
        Component(peg_mgr, "Peg Manager", "Solidity", "Peg operations")
        Component(committee_reg, "Committee Registry", "Solidity", "Manages committee")
        Component(member_reg, "Member Registry", "Solidity", "Manages members")
    }
    
    Rel(user, peg_mgr, "Pegout", "EVM RPC")
    Rel(union_client, powpeg, "Register", "EVM RPC")
    Rel(union_client, peg_mgr, "Peg-out", "EVM RPC")
    Rel(union_client, committee_reg, "Store", "EVM RPC")
    Rel(union_client, member_reg, "Manage", "EVM RPC")
    Rel(powpeg, bitcoin, "Verify", "Bitcoin RPC")
    Rel(peg_mgr, bitcoin, "Verify", "Bitcoin RPC")
    
    UpdateElementStyle(user, $fontColor="#ffffff", $bgColor="#2563eb")
    UpdateElementStyle(union_client, $fontColor="#ffffff", $bgColor="#2563eb")
    UpdateElementStyle(bitcoin, $fontColor="#ffffff", $bgColor="#ea580c")
    UpdateElementStyle(powpeg, $fontColor="#1f2937", $bgColor="#fecaca")
    UpdateElementStyle(peg_mgr, $fontColor="#1f2937", $bgColor="#e9d5ff")
    UpdateElementStyle(committee_reg, $fontColor="#1f2937", $bgColor="#e9d5ff")
    UpdateElementStyle(member_reg, $fontColor="#1f2937", $bgColor="#e9d5ff")
```

## Sequence Diagrams

### Peg-In Flow Sequence

```mermaid
---
config:
    rightAngles: true
---
sequenceDiagram
    participant U as User
    participant BC as Bitcoin Network
    participant UC as Union Client
    participant BV as BitVMX
    participant SC as Smart Contracts
    participant C as Committee

    U->>BC: 1. Creates Bitcoin TX
    BC->>BV: 2. Transaction detected
    BV->>UC: 3. PeginTransactionFound RPC
    UC->>SC: 4. Register peg-in
    SC->>UC: 5. Emits event
    UC->>BV: 6. SetVar & Setup
    BV->>C: 7. Request signatures
    C->>BV: 8. Sign transaction
    BV->>BC: 9. Broadcast TX
    BC->>BV: 10. TX mined
    BV->>UC: 11. Transaction message
    UC->>BC: 12. Request SPV proof
    BC->>UC: 13. SPV proof
    UC->>SC: 14. Present proof
    SC->>U: 15. Mint RBTC
```

### Peg-Out Flow Sequence (Optimistic - User take)

```mermaid
---
config:
    rightAngles: true
---
sequenceDiagram
    participant U as User
    participant SC as Smart Contracts
    participant UC as Union Client
    participant BV as BitVMX
    participant BC as Bitcoin Network
    participant C as Committee

    U->>SC: 1. tryPegout call
    SC->>UC: 2. Burn RBTC & emit event
    UC->>BV: 3. SetVar & Setup
    BV->>C: 4. Request signatures
    C->>BV: 5. Sign transaction
    BV->>SC: 6. Store signatures
    BV->>BC: 7. Broadcast TX
    BC->>U: 8. User receives BTC
```

### Peg-Out Flow Sequence (Fallback - Operator take)

```mermaid
---
config:
    rightAngles: true
---
sequenceDiagram
    participant UC as Union Client
    participant SC as Smart Contracts
    participant BV as BitVMX
    participant BC as Bitcoin Network
    participant U as User

    UC->>SC: 1. Report incomplete signatures
    SC->>UC: 2. Select operator event
    UC->>BV: 3. SetVar & Setup (operator take)
    BV->>BC: 4. Create & broadcast TX
    BC->>BV: 5. TX mined
    BC->>U: 6. User receives BTC
    BV->>UC: 7. Transaction message
    UC->>BC: 8. Wait for challenge period
    UC->>SC: 9. Present proof
    SC->>SC: 10. Mark as paid (internal)
```

## Detailed Component Interactions

### Peg-In Flow

1. **User** creates Bitcoin transaction with OP_RETURN data and sends to **Bitcoind**
2. **BitVMX Monitor** (inside BitVMX Client) detects the transaction
3. **BitVMX Client** sends RPC message `PeginTransactionFound` to **Union Coordinator**
4. **Union Coordinator** registers peg-in in **PowPeg Bridge** smart contract (emits event)
5. **Union Coordinator** starts accept peg-in protocol in BitVMX:

   - Sends `SetVar` message to set variables
   - Sends `Setup` message to run the protocol

6. **Committee members** sign the accept peg-in Bitcoin transaction
7. **BitVMX Client** broadcasts signed transaction to **Bitcoind**
8. Once mined, **BitVMX Client** sends `Transaction` message to **Union Coordinator**
9. **Union Coordinator** requests SPV proof from **Bitcoind** and presents it to **PowPeg Bridge**
10. **PowPeg Bridge** validates the transaction and SPV proof, verifies it has enough confirmations, then mints RBTC to the user

### Peg-Out Flow (Optimistic Path - User Take)

1. **User** calls `tryPegout` on **Peg Manager** smart contract
2. **Peg Manager** burns RBTC and emits event
3. **Union Coordinator** picks up event and sends to **BitVMX Client**:

   - `SetVar` message to set variables
   - `Setup` message to start user take protocol (optimistic pegout)

4. **Committee members** sign the transaction:

   - **Union Coordinator** stores signatures in **Committee Registry**
   - If all committee members sign: **BitVMX Client** broadcasts transaction to **Bitcoind**
   - Once mined: **User** receives BTC

### Peg-Out Flow (Fallback Path - Operator Take)

1. If not all members sign after timeout:

   - **Union Coordinator** calls **Peg Manager** to report incomplete signatures
   - **Peg Manager** verifies not all signatures are present and selects operator to advance funds (emits event)

2. **Union Coordinator** listens to operator selection event and triggers BitVMX operator take protocol:

   - Sends `SetVar` and `Setup` messages

3. **Operator** creates Bitcoin transaction and sends funds to **User**
4. Once mined, **User** receives BTC
5. **BitVMX Client** sends `Transaction` message to **Union Coordinator**
6. **Union Coordinator** waits for challenge period
7. If no challenge, **Union Coordinator** presents proof to **Peg Manager** to mark as paid (internal smart contract operation)

## Key Components

### Core Infrastructure

- **Bitcoind**: Bitcoin node handling Bitcoin network operations
- **RSK**: Rootstock EVM-compatible blockchain hosting smart contracts

### Smart Contracts (on RSK)

- **PowPeg Bridge**: Main bridge contract handling RBTC minting/burning and Bitcoin transaction verification
- **Committee Registry**: Manages committee information and signatures
- **Member Registry**: Manages member information and registration
- **Peg Manager**: Manages peg-in/peg-out operations

### Union Bridge Client Services

- **Coordinator**: Orchestrates communication between Union and BitVMX
- **Block Indexer**: Monitors Rootstock blockchain blocks
- **Log Indexer**: Monitors smart contract events
- **User API**: Provides user-facing API interface
- **Transaction Dispatcher**: Handles transaction broadcasting

### BitVMX Services

- **BitVMX Client**: Core client with monitor and broker functionality
- **BitVMX Job Dispatcher**: Dispatches verification jobs
- **BitVMX CPU**: Executes BitVM computations

### Actors

- **User**: Initiates peg-in/peg-out operations
- **Committee Members**: Operators and Watchtowers who sign transactions

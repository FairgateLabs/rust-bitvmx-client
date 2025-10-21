# BitVMX Client Architecture - C4 Diagram

## System Context Diagram

```mermaid
graph TB
    User[User/Operator] --> BitVMXClient[BitVMX Client]
    L2[L2 System] --> BitVMXClient
    BitcoinNetwork[Bitcoin Network] --> BitVMXClient
    OtherOperators[Other Operators] --> BitVMXClient
    Prover[ZKP Prover] --> BitVMXClient
    Emulator[CPU Emulator] --> BitVMXClient
    
    BitVMXClient --> BitcoinNetwork
    BitVMXClient --> L2
    BitVMXClient --> OtherOperators
    BitVMXClient --> Prover
    BitVMXClient --> Emulator
```

## Container Diagram

```mermaid
graph TD
    %% Main application entry point
    Main[Main Application<br/>main.rs]
    
    %% Core system components
    BitVMX[BitVMX Core<br/>bitvmx.rs]
    API[API Layer<br/>api.rs]
    Config[Configuration<br/>config.rs]
    
    %% Key management components
    KeyChain[Key Manager<br/>keychain.rs]
    Wallet[Bitcoin Wallet<br/>bitvmx-wallet]
    
    %% Communication components
    Comms[Operator Communications<br/>bitvmx-operator-comms]
    Broker[Message Broker<br/>bitvmx-broker]
    BitcoinCoord[Bitcoin Coordinator<br/>bitcoin-coordinator]
    
    %% Program management components
    Program[Program Manager<br/>program.rs]
    Protocol[Protocol Handler<br/>protocol_handler.rs]
    State[Program State<br/>state.rs]
    Variables[Variables & Witness<br/>variables.rs, witness.rs]
    
    %% Protocol implementation components
    Cardinal[Cardinal Protocol<br/>cardinal/]
    Union[Union Protocol<br/>union/]
    Dispute[Dispute Protocol<br/>dispute/]
    Claim[Claim Protocol<br/>claim.rs]
    
    %% Storage and utility components
    Storage[Storage Backend<br/>storage-backend]
    SPV[SPV Proof<br/>spv_proof.rs]
    Shutdown[Graceful Shutdown<br/>shutdown.rs]
    
    %% External systems
    BitcoinRPC[Bitcoin RPC<br/>bitvmx-bitcoin-rpc]
    ProtocolBuilder[Protocol Builder<br/>protocol-builder]
    KeyManager[Key Manager<br/>key-manager]
    JobDispatcher[Job Dispatcher<br/>job-dispatcher]
    CPUEmulator[CPU Emulator<br/>emulator]
    ZKPProver[ZKP Prover<br/>prover]
    
    %% Main flow connections
    Main --> BitVMX
    BitVMX --> API
    BitVMX --> Config
    BitVMX --> KeyChain
    BitVMX --> Wallet
    BitVMX --> Comms
    BitVMX --> Broker
    BitVMX --> BitcoinCoord
    BitVMX --> Program
    BitVMX --> Storage
    BitVMX --> SPV
    BitVMX --> Shutdown
    
    %% Program management flow
    Program --> Protocol
    Program --> State
    Program --> Variables
    
    %% Protocol implementation flow
    Protocol --> Cardinal
    Protocol --> Union
    Protocol --> Dispute
    Protocol --> Claim
    
    %% External system connections
    BitcoinCoord --> BitcoinRPC
    Protocol --> ProtocolBuilder
    KeyChain --> KeyManager
    API --> JobDispatcher
    JobDispatcher --> CPUEmulator
    JobDispatcher --> ZKPProver
```

## Component Diagram - BitVMX Core

```mermaid
graph TB
    subgraph "BitVMX Core (bitvmx.rs)"
        BitVMXCore[BitVMX Main Class]
        
        subgraph "Core State"
            Config[Configuration]
            Store[Storage Backend]
            Count[Message Counter]
            PendingMsgs[Pending Messages]
            NotifiedReqs[Notified Requests]
            BitcoinUpdate[Bitcoin Update State]
        end
        
        subgraph "Program Context"
            KeyChain[Key Chain]
            Comms[Operator Communications]
            BitcoinCoord[Bitcoin Coordinator]
            BrokerChannel[Broker Channel]
            Globals[Global Variables]
            Witness[Witness Variables]
            Components[Components Config]
        end
        
        subgraph "External Services"
            Broker[Message Broker]
            Wallet[Bitcoin Wallet]
        end
    end
    
    BitVMXCore --> Config
    BitVMXCore --> Store
    BitVMXCore --> Count
    BitVMXCore --> PendingMsgs
    BitVMXCore --> NotifiedReqs
    BitVMXCore --> BitcoinUpdate
    
    BitVMXCore --> KeyChain
    BitVMXCore --> Comms
    BitVMXCore --> BitcoinCoord
    BitVMXCore --> BrokerChannel
    BitVMXCore --> Globals
    BitVMXCore --> Witness
    BitVMXCore --> Components
    
    BitVMXCore --> Broker
    BitVMXCore --> Wallet
```

## Component Diagram - Program Management

```mermaid
graph TB
    subgraph "Program Management System"
        ProgramManager[Program Manager]
        
        subgraph "Program Lifecycle"
            Setup[Program Setup]
            KeyExchange[Key Exchange]
            NonceExchange[Nonce Exchange]
            SignatureExchange[Signature Exchange]
            Monitoring[Transaction Monitoring]
        end
        
        subgraph "Protocol Types"
            ProtocolHandler[Protocol Handler]
            CardinalProtocol[Cardinal Protocol]
            UnionProtocol[Union Protocol]
            DisputeProtocol[Dispute Protocol]
            ClaimProtocol[Claim Protocol]
        end
        
        subgraph "State Management"
            ProgramState[Program State]
            ParticipantData[Participant Data]
            MessageHandling[Message Handling]
        end
        
        subgraph "Communication"
            CommsMessages[Communication Messages]
            ACKHandling[ACK Handling]
            RetryLogic[Retry Logic]
        end
    end
    
    ProgramManager --> Setup
    ProgramManager --> KeyExchange
    ProgramManager --> NonceExchange
    ProgramManager --> SignatureExchange
    ProgramManager --> Monitoring
    
    ProgramManager --> ProtocolHandler
    ProtocolHandler --> CardinalProtocol
    ProtocolHandler --> UnionProtocol
    ProtocolHandler --> DisputeProtocol
    ProtocolHandler --> ClaimProtocol
    
    ProgramManager --> ProgramState
    ProgramManager --> ParticipantData
    ProgramManager --> MessageHandling
    
    ProgramManager --> CommsMessages
    ProgramManager --> ACKHandling
    ProgramManager --> RetryLogic
```

## Component Diagram - Communication Layer

```mermaid
graph TB
    subgraph "Communication Layer"
        subgraph "Operator Communications"
            OperatorComms[Operator Communications]
            AllowList[Allow List]
            RoutingTable[Routing Table]
            MessageHandler[Message Handler]
        end
        
        subgraph "Message Broker"
            BrokerSync[Broker Sync]
            BrokerStorage[Broker Storage]
            BrokerConfig[Broker Config]
            LocalChannel[Local Channel]
        end
        
        subgraph "Bitcoin Coordinator"
            BitcoinCoord[Bitcoin Coordinator]
            TransactionMonitor[Transaction Monitor]
            NewsHandler[News Handler]
            DispatchHandler[Dispatch Handler]
        end
        
        subgraph "External Communication"
            BitcoinRPC[Bitcoin RPC]
            L2Communication[L2 Communication]
            ProverCommunication[Prover Communication]
            EmulatorCommunication[Emulator Communication]
        end
    end
    
    OperatorComms --> AllowList
    OperatorComms --> RoutingTable
    OperatorComms --> MessageHandler
    
    BrokerSync --> BrokerStorage
    BrokerSync --> BrokerConfig
    BrokerSync --> LocalChannel
    
    BitcoinCoord --> TransactionMonitor
    BitcoinCoord --> NewsHandler
    BitcoinCoord --> DispatchHandler
    
    BitcoinCoord --> BitcoinRPC
    BrokerSync --> L2Communication
    BrokerSync --> ProverCommunication
    BrokerSync --> EmulatorCommunication
```

## Key Components and Their Responsibilities

### Core Components

1. **BitVMX Core (bitvmx.rs)**
   - Main orchestrator of the system
   - Manages program lifecycle
   - Handles Bitcoin updates and wallet synchronization
   - Coordinates between all subsystems

2. **Program Manager (program.rs)**
   - Manages individual programs and their state
   - Handles key exchange, nonce exchange, and signature exchange
   - Manages participant data and communication
   - Implements retry logic and message handling

3. **Protocol Handler (protocol_handler.rs)**
   - Manages different protocol types (Cardinal, Union, Dispute, Claim)
   - Handles protocol-specific logic and state transitions
   - Manages protocol visualization and execution

### Communication Components

4. **Operator Communications (bitvmx-operator-comms)**
   - Handles P2P communication between operators
   - Manages allow lists and routing tables
   - Implements secure message exchange

5. **Message Broker (bitvmx-broker)**
   - Manages internal message routing
   - Handles communication with external services (L2, Prover, Emulator)
   - Implements message queuing and delivery

6. **Bitcoin Coordinator (bitcoin-coordinator)**
   - Monitors Bitcoin transactions and blocks
   - Handles transaction dispatch and status updates
   - Manages Bitcoin RPC communication

### Supporting Components

7. **Key Manager (keychain.rs)**
   - Manages cryptographic keys (ECDSA, Winternitz, RSA)
   - Handles key derivation and storage
   - Implements MuSig2 signature aggregation

8. **Storage Backend (storage-backend)**
   - Provides persistent storage for programs and state
   - Implements transaction support
   - Handles backup and recovery

9. **Bitcoin Wallet (bitvmx-wallet)**
   - Manages Bitcoin wallet operations
   - Handles address generation and transaction creation
   - Implements wallet synchronization

### External Dependencies

10. **Protocol Builder (protocol-builder)**
    - Builds and manages protocol definitions
    - Handles protocol visualization
    - Manages protocol execution context

11. **Job Dispatcher (job-dispatcher)**
    - Manages ZKP proof generation jobs
    - Coordinates with CPU emulator and ZKP prover
    - Handles job queuing and result processing

12. **Settings Manager (bitvmx-settings)**
    - Manages configuration loading and validation
    - Handles environment-specific settings
    - Provides configuration to all components

## Data Flow

1. **Initialization**: Main application loads configuration and initializes BitVMX core
2. **Program Setup**: Programs are created with participants and protocol types
3. **Key Exchange**: Participants exchange public keys for aggregated signatures
4. **Nonce Exchange**: Participants exchange nonces for MuSig2 signing
5. **Signature Exchange**: Participants exchange partial signatures
6. **Protocol Execution**: Protocols are built and signed
7. **Transaction Monitoring**: Bitcoin transactions are monitored for state changes
8. **Message Processing**: Incoming messages are processed and routed appropriately
9. **State Updates**: Program state is updated based on Bitcoin events and messages

## Key Features

- **Multi-Protocol Support**: Cardinal, Union, Dispute, and Claim protocols
- **Secure Communication**: P2P communication with allow lists and routing
- **Bitcoin Integration**: Full Bitcoin transaction monitoring and dispatch
- **Key Management**: Advanced cryptographic key management with MuSig2
- **State Persistence**: Robust storage backend with transaction support
- **Graceful Shutdown**: Coordinated shutdown of all components
- **Error Handling**: Comprehensive error handling and recovery
- **ZKP Integration**: Zero-knowledge proof generation and verification

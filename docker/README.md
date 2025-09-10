# Guide to start dockerized BitVMX client services

## Prerequisites

1. **Configure your local SSH Key**  
   You should have access to private GitHub Repos.

2. **Ensure operator config files exist**  
   Config files should be present in `config/` directory:
   - `config/op_1.yaml` (broker_port: 22222)
   - `config/op_2.yaml` (broker_port: 33333)
   - `config/op_3.yaml` (broker_port: 44444)

3. **Docker BuildKit enabled**  
   If your Docker does not have BuildKit activated by default:
   ```bash
   export DOCKER_BUILDKIT=1
   ```

## Quick Start

### Build the Docker images:
```bash
# Build all images
./start.sh build

# Build specific service
./start.sh build bitvmx-client
./start.sh build bitvmx-emulator
./start.sh build bitvmx-zkp
```

## Starting Services

### Standard BitVMX client (without ZKP):
```bash
# Start operator 1 (includes bitcoind)
./start.sh op_1 up

# Start operator 2 (uses op_1's bitcoind) - in another terminal
./start.sh op_2 up -d

# Start operator 3 (uses op_1's bitcoind) - in another terminal
./start.sh op_3 up --build
```

### With ZKP Dispatcher (Zero-Knowledge Proofs):
```bash
# Start operator 1 with ZKP support
./start.sh op_1 up --zkp

# Start multiple operators with ZKP
./start.sh op_2 up --zkp -d
./start.sh op_3 up --zkp
```

### Stop services:
```bash
# Stop operator 1
./start.sh op_1 down

# Stop ZKP services specifically
./start.sh op_1 down --zkp

# Stop with volume cleanup
./start.sh op_2 down --volumes

# Stop and remove orphaned containers
./start.sh op_3 down --remove-orphans
```

## Advanced Usage

### Multiple operators simultaneously:
```bash
# Terminal 1: Start operator 1 with ZKP (includes bitcoind on port 18443)
./start.sh op_1 up --zkp

# Terminal 2: Start operator 2 with ZKP (broker on port 33333)
./start.sh op_2 up --zkp

# Terminal 3: Start operator 3 with ZKP (broker on port 44444)
./start.sh op_3 up --zkp
```

### Development workflow:
```bash
# Rebuild and start with logs
./start.sh op_1 up --build --force-recreate --zkp

# Watch logs during development
./start.sh op_1 logs -f bitvmx-client --zkp
./start.sh op_1 logs -f bitvmx-zkp --zkp

# Quick restart specific service
./start.sh op_1 restart bitvmx-client --zkp
./start.sh op_1 restart bitvmx-zkp --zkp

# Check service status
./start.sh op_1 ps --zkp
```

### ZKP-specific commands:
```bash
# Start only ZKP dispatcher (requires healthy client)
./start.sh op_1 start bitvmx-zkp --zkp

# Stop only ZKP dispatcher
./start.sh op_1 stop bitvmx-zkp --zkp

# View ZKP logs with diagnostics
./start.sh op_1 logs -f bitvmx-zkp --zkp
```

## Architecture & Configuration

### Service Components:
- **BitVMX Client**: Core broker and P2P networking
- **Emulator Dispatcher**: BitVM execution environment  
- **ZKP Dispatcher**: Zero-Knowledge proof generation (optional)
- **Bitcoind**: Bitcoin regtest node (shared across operators)

### Dynamic port configuration:
- The `start.sh` script automatically reads broker ports from `config/${OPERATOR}.yaml`
- **No manual port synchronization needed** between `.env` and config files
- Each operator uses its configured port automatically

### Bitcoin node sharing:
- **op_1**: Starts its own bitcoind instance (port 18443)
- **op_2, op_3**: Connect to op_1's bitcoind via `host.docker.internal:18443`
- **Single blockchain**: All operators share the same regtest blockchain

### Container naming:
- **Client**: `bitvmx-${PROJECT}-bitvmx-client-1` (e.g., `bitvmx-op_1-bitvmx-client-1`)
- **Emulator**: `bitvmx-${PROJECT}-bitvmx-emulator-1` (e.g., `bitvmx-op_1-bitvmx-emulator-1`)
- **ZKP**: `bitvmx-${PROJECT}-bitvmx-zkp-1` (e.g., `bitvmx-op_1-bitvmx-zkp-1`)
- **Bitcoind**: `bitvmx-op_1-bitcoind-1` (only for op_1)

### Network architecture:
- **Emulator & ZKP**: Share network namespace with client (`network_mode: service:bitvmx-client`)
- **Direct communication**: Dispatchers connect to broker via `127.0.0.1:${BROKER_PORT}`
- **Cross-operator**: Uses `host.docker.internal` for bitcoind access
- **Isolated projects**: Each operator has its own Docker Compose project

### ZKP Dispatcher Features:
- **RISC Zero integration**: Supports cargo-risczero toolchain
- **Docker-in-Docker**: Privileged container with Docker socket access
- **Automatic discovery**: Reads broker port from operator config
- **Health monitoring**: Depends on healthy BitVMX client
- **Development mode**: RISC0_DEV_MODE=1 for faster iteration

### Port allocation:
| Operator | Broker Port | Bitcoin Port | Container Project | ZKP Support |
|----------|-------------|--------------|-------------------|-------------|
| op_1     | 22222       | 18443        | bitvmx-op_1       | ✅          |
| op_2     | 33333       | 18443*       | bitvmx-op_2       | ✅          |
| op_3     | 44444       | 18443*       | bitvmx-op_3       | ✅          |

*\*op_2 and op_3 connect to op_1's bitcoind*

## Environment Variables

The script automatically manages these variables:
- `CLIENT_OP`: Operator identifier (op_1, op_2, op_3, etc.)
- `BROKER_PORT`: Dynamically read from `config/${CLIENT_OP}.yaml`
- `BITCOIND_URL`: Automatically set based on operator:
  - op_1: `http://bitcoind:18443` (internal)
  - op_2+: `http://host.docker.internal:18443` (shared)
- `RISC0_DEV_MODE`: Set to 1 for ZKP development (faster proving)

## Troubleshooting

### Common Issues:

#### ZKP Dispatcher not starting:
```bash
# Check if client is healthy
./start.sh op_1 ps --zkp

# View detailed logs
./start.sh op_1 logs bitvmx-zkp --zkp

# Restart in correct order
./start.sh op_1 down --zkp
./start.sh op_1 up --zkp
```

#### Client unhealthy (can't connect to bitcoind):
```bash
# Ensure bitcoind is running
./start.sh op_1 logs bitcoind --zkp

# Check if port 18443 is accessible
docker exec bitvmx-op_1-bitvmx-client-1 nc -z bitcoind 18443
```

#### Permission issues with Docker socket:
```bash
# Verify Docker socket access in ZKP container
docker exec bitvmx-op_1-bitvmx-zkp-1 docker info
```

### Health Checks:
The system uses health checks to ensure proper startup order:
- **Client health check**: `nc -z localhost ${BROKER_PORT}` (every 5s)
- **ZKP dependency**: Waits for client to be healthy before starting
- **Emulator dependency**: Waits for client to be healthy before starting
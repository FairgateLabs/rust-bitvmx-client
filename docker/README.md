# Guide to start dockerized BitVMX client services

## Prerequisites

1. **Configure your local SSH Key**  
   You should have access to private GitHub Repos.

2. **Docker BuildKit enabled**  
   If your Docker does not have BuildKit activated by default:
   ```bash
   export DOCKER_BUILDKIT=1
   ```

## Quick Start

### Build the Docker images:
```bash
# Build all images for operator 1
./start.sh op_1 build

# Or build specific service
./start.sh op_1 build bitvmx-client
./start.sh op_1 build bitvmx-emulator
```

## Starting Services

### Start with different operators:

```bash
# Start operator 1 (includes bitcoind)
./start.sh op_1 up

# Start operator 2 (uses op_1's bitcoind) - in another terminal
./start.sh op_2 up -d

# Start operator 3 (uses op_1's bitcoind) - in another terminal
./start.sh op_3 up --build
```

### Stop services:

```bash
# Stop operator 1
./start.sh op_1 down

# Stop with volume cleanup
./start.sh op_2 down --volumes

# Stop and remove orphaned containers
./start.sh op_3 down --remove-orphans
```

## Advanced Usage

### Multiple operators simultaneously:
```bash
# Terminal 1: Start operator 1 (includes bitcoind on port 18443)
./start.sh op_1 up

# Terminal 2: Start operator 2 (broker on port 33333)
./start.sh op_2 up

# Terminal 3: Start operator 3 (broker on port 44444)
./start.sh op_3 up
```

### Development workflow:
```bash
# Rebuild and start with logs
./start.sh op_1 up --build --force-recreate

# Watch logs during development
./start.sh op_1 logs -f bitvmx-client

# Quick restart specific service
./start.sh op_1 restart bitvmx-client

# Update and restart
./start.sh op_2 pull && ./start.sh op_2 up -d
```

## Architecture & Configuration

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
- **Bitcoind**: `bitvmx-op_1-bitcoind-1` (only for op_1)

### Network architecture:
- **Emulator**: Shares network namespace with client (`network_mode: service:bitvmx-client`)
- **Direct communication**: Emulator connects to broker via `127.0.0.1:${BROKER_PORT}`
- **Cross-operator**: Uses `host.docker.internal` for bitcoind access
- **Isolated projects**: Each operator has its own Docker Compose project

### Port allocation:
| Operator | Broker Port | Bitcoin Port | Container Project |
|----------|-------------|--------------|-------------------|
| op_1     | 22222       | 18443        | bitvmx-op_1       |
| op_2     | 33333       | 18443*       | bitvmx-op_2       |
| op_3     | 44444       | 18443*       | bitvmx-op_3       |

*\*op_2 and op_3 connect to op_1's bitcoind*


## Environment Variables

The script automatically manages these variables:
- `CLIENT_OP`: Operator identifier (op_1, op_2, op_3, etc.)
- `BROKER_PORT`: Dynamically read from `config/${CLIENT_OP}.yaml`
- `BITCOIND_URL`: Automatically set based on operator:
  - op_1: `http://bitcoind:18443` (internal)
  - op_2+: `http://host.docker.internal:18443` (shared)

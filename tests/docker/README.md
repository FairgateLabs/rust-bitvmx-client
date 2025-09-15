# Docker Test Environment

This directory contains all Docker-related files for running Bitcoin Core regtest in tests.

## Files

- **`docker-compose.yml`**: Docker Compose configuration for bitcoind container
- **`Dockerfile`**: Bitcoin Core image definition (version 24.0.1)
- **`entrypoint.sh`**: Container initialization script (creates wallet, mines blocks)
- **`cleanup.sh`**: Graceful bitcoind shutdown script

## Usage

### Start bitcoind for testing:
```bash
cd tests/docker
docker-compose up -d
```

### Stop bitcoind:
```bash
cd tests/docker
docker-compose down --volumes
```

### View logs:
```bash
docker logs bitcoind -f
```

## Configuration

- **Network**: regtest
- **RPC Port**: 18443
- **RPC User**: foo
- **RPC Password**: rpcpassword
- **Wallet**: test_wallet (pre-funded with 50 BTC from 101 mined blocks)

## Notes

- The entrypoint script automatically creates a funded test wallet
- 101 blocks are mined on startup to ensure mature coinbase outputs
- All configuration matches the local test setup for consistency

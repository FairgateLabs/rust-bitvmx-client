#!/bin/bash

# Script de prueba rápida para un solo test aislado
# Útil para debug

set -e

TEST_NAME=${1:-"fulltest"}
BASE_PORT=18443

echo "=== Testing single isolated test: $TEST_NAME ==="

# Configurar variables de entorno
export CI=true
export GITHUB_ACTIONS=true
export TEST_ISOLATION_ID="quick_test_${TEST_NAME}_$$"
export BITCOIN_PORT=$((BASE_PORT))
export BITCOIN_RPC_PORT=$((BASE_PORT + 1))
export BITCOIN_RPC_URL="http://127.0.0.1:$((BASE_PORT + 1))/"
export BROKER_PORT=$((8080))

echo "Using ports: Bitcoin=$BITCOIN_PORT, RPC=$BITCOIN_RPC_PORT, Broker=$BROKER_PORT"
echo "Isolation ID: $TEST_ISOLATION_ID"

# Limpiar ambiente
echo "=== Cleaning environment ==="
docker-compose -f tests/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
docker container prune -f 2>/dev/null || true

# Crear docker-compose temporal
cat > tests/docker-compose-quick.yml << EOF
version: '3.8'
services:
  bitcoind:
    image: ruimarinho/bitcoin-core:27.0-alpine
    container_name: bitcoind-quick-test
    ports:
      - "${BITCOIN_PORT}:${BITCOIN_PORT}"
      - "${BITCOIN_RPC_PORT}:${BITCOIN_RPC_PORT}"
    environment:
      BITCOIN_DATA: /home/bitcoin/.bitcoin
    volumes:
      - bitcoind_data_quick:/home/bitcoin/.bitcoin
    command: >
      bitcoind
      -regtest
      -server
      -rpcallowip=0.0.0.0/0
      -rpcbind=0.0.0.0:${BITCOIN_RPC_PORT}
      -rpcuser=foo
      -rpcpassword=rpcpassword
      -port=${BITCOIN_PORT}
      -fallbackfee=0.0002
      -minrelaytxfee=0.00001
      -blockmintxfee=0.00008
      -debug=1
      -txindex=1

volumes:
  bitcoind_data_quick:
    driver: local
EOF

# Iniciar servicios
echo "=== Starting services ==="
docker-compose -f tests/docker-compose-quick.yml up -d

# Esperar que esté listo
echo "=== Waiting for services ==="
for i in {1..30}; do
  if curl -s -u foo:rpcpassword -X POST -H "Content-Type: application/json" \
     -d '{"method":"getblockchaininfo"}' \
     http://127.0.0.1:${BITCOIN_RPC_PORT}/ > /dev/null 2>&1; then
    echo "Services ready after $i attempts"
    break
  fi
  echo "Attempt $i/30: Waiting for bitcoind..."
  sleep 2
done

# Ejecutar test
echo "=== Running test: $TEST_NAME ==="
cargo test --release --features regtest $TEST_NAME -- --test-threads=1 --nocapture

# Limpiar
echo "=== Cleaning up ==="
docker-compose -f tests/docker-compose-quick.yml down --volumes
rm -f tests/docker-compose-quick.yml

echo "=== Quick test completed ==="

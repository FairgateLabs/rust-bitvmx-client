#!/bin/bash
set -e

NET_ARG="-regtest"
RPC_USER="foo"
RPC_PASS="rpcpassword"
RPC_PORT="18443"
CLI_CMD="bitcoin-cli ${NET_ARG} -rpcuser=${RPC_USER} -rpcpassword=${RPC_PASS} -rpcport=${RPC_PORT}"

# Start bitcoind with all config via flags (matching local test configuration)
mkdir -p /logs
bitcoind ${NET_ARG} \
  -fallbackfee=0.0002 \
  -minrelaytxfee=0.00001 \
  -blockmintxfee=0.00008 \
  -debug=1 \
  -datadir=/app/data \
  -rpcuser=${RPC_USER} \
  -rpcpassword=${RPC_PASS} \
  -rpcport=${RPC_PORT} \
  -rpcbind=0.0.0.0:${RPC_PORT} \
  -rpcallowip=0.0.0.0/0 \
  -server \
  -txindex \
  > /logs/bitcoind.log 2>&1 &

echo "Waiting for bitcoind to accept RPC connections..."
until ${CLI_CMD} -rpcwait getblockchaininfo > /dev/null 2>&1; do
  sleep 1
done

echo "✅ bitcoind is ready!"

echo "Creating test wallet 'test_wallet'..."
${CLI_CMD} createwallet "test_wallet" false false "" false false true > /dev/null 2>&1 || echo "Wallet already exists or creation failed, continuing..."

echo "Getting address from test wallet..."
DEFAULT_ADDRESS=$(${CLI_CMD} -rpcwallet=test_wallet getnewaddress "" "bech32")
echo "Test wallet address: $DEFAULT_ADDRESS"

echo " Mining 101 blocks to test wallet address to ensure mature coinbase outputs..."
${CLI_CMD} generatetoaddress 101 $DEFAULT_ADDRESS > /dev/null

echo "Checking test wallet balance..."
BALANCE=$(${CLI_CMD} -rpcwallet=test_wallet getbalance)
echo "Test wallet balance: $BALANCE BTC"

FINAL_BALANCE=$(${CLI_CMD} -rpcwallet=test_wallet getbalance)
echo "✅ Setup complete! Test wallet final balance: $FINAL_BALANCE BTC"

BLOCKCHAIN_INFO=$(${CLI_CMD} getblockchaininfo | grep -E '"blocks":|"chain":')
echo "Blockchain status: $BLOCKCHAIN_INFO"

echo "🚀 bitcoind is fully initialized and ready for testing!"

tail -f /logs/bitcoind.log

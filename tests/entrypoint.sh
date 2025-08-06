#!/bin/bash
set -e

NET_ARG="-regtest"

# Start bitcoind
mkdir -p /logs
bitcoind ${NET_ARG} -fallbackfee=0.0001 -datadir=/app/data -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} -conf=${CONFIG_FILE} > /logs/bitcoind.log 2>&1 &

# Wait for bitcoind to be ready for RPC
echo "Waiting for bitcoind to accept RPC connections..."
until bitcoin-cli ${NET_ARG} -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} -rpcwait getblockchaininfo > /dev/null 2>&1; do
  sleep 1
done

tail -f /logs/bitcoind.log
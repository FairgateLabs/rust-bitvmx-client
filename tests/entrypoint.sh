#!/bin/bash
set -e

NET_ARG="-regtest"

# Start bitcoind with all config via flags
mkdir -p /logs
bitcoind ${NET_ARG} \
  -fallbackfee=0.0001 \
  -datadir=/app/data \
  -rpcuser=foo \
  -rpcpassword=rpcpassword \
  -rpcport=18443 \
  -rpcbind=0.0.0.0:18443 \
  -rpcallowip=0.0.0.0/0 \
  -server \
  -txindex \
  > /logs/bitcoind.log 2>&1 &

# Wait for bitcoind to be ready for RPC
echo "Waiting for bitcoind to accept RPC connections..."
until bitcoin-cli ${NET_ARG} -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 -rpcwait getblockchaininfo > /dev/null 2>&1; do
  sleep 1
done

tail -f /logs/bitcoind.log
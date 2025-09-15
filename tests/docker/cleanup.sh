#!/bin/bash
# We must stop the bitcoind gracefully in order to keep the DB consistent.
bitcoin-cli -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} stop

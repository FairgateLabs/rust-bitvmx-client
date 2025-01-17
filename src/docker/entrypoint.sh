#!/bin/bash

#select config file
if [ "${BITCOIND_RPC_NETWORK}" = "regtest" ]
then
  CONFIG_FILE=/app/regtest.conf
elif [ "${BITCOIND_RPC_NETWORK}" = "testnet" ]
then

  CONFIG_FILE=/app/testnet.conf
elif [ "${BITCOIND_RPC_NETWORK}" = "mainnet" ]
then
  CONFIG_FILE=/app/mainnet.conf
fi

# Start bitcoind
mkdir /logs
bitcoind -datadir=/app/data -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} -conf=${CONFIG_FILE} > /logs/bitcoind.log &

# Wait for bitcoind start and create wallet
while
  echo "Attempting to create & load default wallet..."
  sleep 2
  bitcoin-cli -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} createwallet default || bitcoin-cli -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} loadwallet default
  [ $? -ne 0 ]
do
  :
done
echo "Created & loaded default wallet"

if [ "${BITCOIND_RPC_NETWORK}" = "regtest" ]
then

  INITIAL_BLOCKS=101

  # Get new address to send coinbase bitcoin to.
  MINER_ADDRESS=$(bitcoin-cli -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} -rpcwallet=default getnewaddress)
  export MINER_ADDRESS
  echo "Miner address: $MINER_ADDRESS"

  # Mine enough blocks to start off with mature (spendable) btc.
  bitcoin-cli -rpcuser=${BITCOIND_RPC_USERNAME} -rpcpassword=${BITCOIND_RPC_PASSWORD} -rpcport=${BITCOIND_RPC_PORT} generatetoaddress ${INITIAL_BLOCKS} $MINER_ADDRESS

fi

tail -f /logs/bitcoind.log

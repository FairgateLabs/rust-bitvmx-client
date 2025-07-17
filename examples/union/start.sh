#!/bin/bash

# we go to the root of the project to avoid relative path issues
CURRENT_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$CURRENT_PATH/../.."

CONTAINER_NAME=bitcoin-regtest
# stop and remove the bitcoin-regtest container if it exists
if [ -n "$(docker ps -a -f name="^$CONTAINER_NAME$" -q)" ]; then
    echo "Stopping and remove $CONTAINER_NAME container"
    docker rm -f $CONTAINER_NAME
fi

# remove bitvmx client tmp data
rm -rf /tmp/broker_p2p_6118* 
rm -rf /tmp/op_*  

# set rust backtrace on
RUST_BACKTRACE=1
# start bitcoin-regtest container
cargo run --example union setup_bitcoin_node
# start 4 bitvmx client nodes
cargo run all

#!/usr/bin/env bash

# Runs a specific union example
# Usage: ./run-example.sh <example>
# Example: ./run-example.sh committee
# NOTE: This script setup a fresh regtest environment for each run
# It removes previous logs and data in /tmp/broker_p2p_6118* and /tmp/regtest/
# It also kills all existing bitvmx-client processes
# Logs are stored in logs/examples/<example>/

set -euo pipefail

# Ensure exactly one argument is passed
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <example>"
  echo "Example: $0 committee"
  exit 1
fi

name="$1"
LOGS_DIR="logs/examples/$name"
rm -rf $LOGS_DIR
mkdir -p $LOGS_DIR
echo "Setting up example: $name"

# Clean up previous logs and data
rm -rf /tmp/broker_p2p_6118*
rm -rf /tmp/regtest/

# Kill all bitvmx-client process
pkill -f bitvmx-client || true

# Setup Bitcoin regtest node
echo "Setting up Bitcoin regtest node..."
cargo run --release --example union setup_bitcoin_node
echo "Bitcoin regtest node setup complete."

# Run the BitVMX clients and log output, stripping ANSI color codes
echo "Running BitVMX clients on regtest..."
RUST_BACKTRACE=full cargo run --release all --fresh 2>&1 | sed -u -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})*)?[mGKHF]//g" > $LOGS_DIR/bitvmx.log &

echo "Waiting for BitVMX clients to initialize..."
sleep 10s

printf "\nRunning union example: $name...\n\n\n"
RUST_BACKTRACE=full cargo run --release --example union $name 2>&1 | sed -u -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})*)?[mGKHF]//g" > $LOGS_DIR/example.log
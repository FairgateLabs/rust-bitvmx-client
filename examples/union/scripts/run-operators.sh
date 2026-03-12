#!/usr/bin/env bash

# Runs a specific union example
# Usage: ./run-example.sh <example> [optional <challenge-winner>]
# Example: ./run-example.sh committee 4
# NOTE: This script setup a fresh regtest environment for each run
# It removes previous logs and data in /tmp/regtest/
# It also kills all existing bitvmx-client processes
# Logs are stored in logs/examples/<example>/

set -euo pipefail

if [ "$#" -gt 1 ]; then
  echo "Usage: $0"
  echo "Example: $0"
  exit 1
fi

# Date pieces
timestamp_date=$(date +%y%m%d)
timestamp_time=$(date +%H%M)

LOGS_DIR="logs/${timestamp_date}/${timestamp_time}"
rm -rf "$LOGS_DIR"
mkdir -p "$LOGS_DIR"

# Clean up previous logs and data
rm -rf /tmp/regtest/

# Kill all bitvmx-client process
pkill -f bitvmx-client || true

# Setup Bitcoin regtest node
echo "Setting up Bitcoin regtest node..."
cargo run --release --example union setup_bitcoin_node
echo "Bitcoin regtest node setup complete."

# Ensure cleanup of bitvmx-client processes on script exit
function cleanup() {
  pkill -f bitvmx-client || true
}
trap cleanup EXIT

# Run the BitVMX clients and log output, stripping ANSI color codes
echo "Running BitVMX clients on regtest..."

# Number of operator instances to start. Run them in separate background processes
OP_COUNT=4
for i in $(seq 1 $OP_COUNT); do
  op_name="op_${i}"
  RUST_BACKTRACE=full cargo run --release "$op_name" --fresh 2>&1 \
    | sed -u -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})*)?[mGKHF]//g" > "$LOGS_DIR/bitvmx_$op_name.log" &
done

echo "Waiting for BitVMX clients to initialize..."
sleep 10s

echo "Type something to kill the clients and exit..."
read INPUT

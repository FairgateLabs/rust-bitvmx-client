#!/usr/bin/env bash

# Runs a specific union example
# Usage: ./run-example.sh <example>
# Example: ./run-example.sh committee
# NOTE: This script setup a fresh regtest environment for each run
# It removes previous logs and data in /tmp/regtest/
# It also kills all existing bitvmx-client processes
# Logs are stored in logs/examples/<example>/

set -euo pipefail

# Ensure exactly one argument is passed
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <example>"
  echo "Example: $0 committee"
  echo "Available examples:"
  cargo run -q --release --example union
  exit 1
fi

name="$1"
LOGS_DIR="logs/examples/$name"
rm -rf "$LOGS_DIR"
mkdir -p "$LOGS_DIR"
echo "Setting up example: $name"
EXAMPLE_LOG_FILE="$LOGS_DIR/example.log"

# Clean up previous logs and data
rm -rf /tmp/regtest/

# Kill all bitvmx-client process
pkill -f bitvmx-client || true

# Setup Bitcoin regtest node
echo "Setting up Bitcoin regtest node..."
cargo run --release --example union setup_bitcoin_node
echo "Bitcoin regtest node setup complete."

# Initialize log file
echo "" > "$EXAMPLE_LOG_FILE"

# Open log in VS Code if available
if command -v code >/dev/null 2>&1; then
  # Open log in VS Code
  code --reuse-window "$EXAMPLE_LOG_FILE" &
else
  echo "VS Code not found. Open logs manually at:"
  echo "  $EXAMPLE_LOG_FILE"
  echo ""
fi

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
sleep 20s

printf "\nRunning union example: $name...\n\n\n"
RUST_BACKTRACE=full cargo run --release --example union $name 2>&1 | sed -u -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})*)?[mGKHF]//g" > "$EXAMPLE_LOG_FILE"

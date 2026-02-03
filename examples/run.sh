#!/usr/bin/env bash

set -euo pipefail

# Ensure 1 or 2 arguments are passed
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <example>"
  echo "Example: $0 light-drp"
  echo "Available examples:"
  cargo run -q --release --example light-drp
  exit 1
fi

name="$1"

LOGS_DIR="logs/${name}"
mkdir -p "$LOGS_DIR"

# Move previous logs to .old files
for logfile in "$LOGS_DIR"/*.log; do
  [ -f "$logfile" ] && mv "$logfile" "${logfile}.old"
done

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
  RUST_BACKTRACE=full cargo run --release "$op_name" --fresh 2>&1 > "$LOGS_DIR/bitvmx_$op_name.log" &
done

echo "Waiting for BitVMX clients to initialize..."
sleep 10s

printf "\nRunning $name...\n\n\n"
RUST_BACKTRACE=full cargo run --release --example $name 2>&1 > "$EXAMPLE_LOG_FILE"

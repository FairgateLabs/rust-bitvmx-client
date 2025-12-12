#!/usr/bin/env bash
set -euo pipefail

# Run all union examples sequentially using run-example.sh
# Use: ./run-all.sh

# list of example names
examples=(
    request_pegout
    advance_funds_twice
)

cargo build --release
cargo build --release --example union

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for ex in "${examples[@]}"; do
    bash "${SCRIPT_DIR}/run-example.sh" "$ex"
done
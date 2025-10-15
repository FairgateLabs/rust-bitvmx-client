#!/bin/bash
set -euo pipefail

echo "Building BitVMX-CPU emulator..."

if [ ! -d "../BitVMX-CPU" ]; then
    echo "❌ Error: BitVMX-CPU directory not found"
    exit 1
fi

echo "Found BitVMX-CPU directory"
cd ../BitVMX-CPU

if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Cargo.toml not found in BitVMX-CPU"
    exit 1
fi

echo "🔨 Building emulator..."
cargo build --release --bin emulator

if [ ! -f "target/release/emulator" ]; then
    echo "❌ Error: Emulator binary not found after build"
    exit 1
fi

echo "✅ Emulator built successfully"
#!/bin/bash
set -e

echo "Starting bitvmx-risczero-dispatcher..."
echo "CLIENT_OP: ${CLIENT_OP:-unknown}"

CONFIG_FILE="config/${CLIENT_OP}.yaml"
if [ -f "$CONFIG_FILE" ]; then
    BROKER_PORT=$(grep "broker_port:" "$CONFIG_FILE" | awk '{print $2}' | tr -d ' ')
    echo "✅ Using broker port $BROKER_PORT from $CONFIG_FILE"
    echo "🚀 Connecting to 127.0.0.1:$BROKER_PORT"
else
    echo "❌ Config file $CONFIG_FILE not found"
    echo "Available files:"
    ls -la config/ || echo "No config directory"
    exit 1
fi

cd /app/bitvmx-workspace-root/rust-bitvmx-job-dispatcher

echo "🔍 Checking Risc Zero installation..."
if cargo risczero --version >/dev/null 2>&1; then
    echo "✅ cargo risczero available"
    cargo risczero --version
else
    echo "⚠️  cargo risczero not available, but continuing..."
fi

echo "🐳 Checking Docker requirements..."
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "✅ Docker daemon accessible"
else
    echo "⚠️  Docker may not be accessible, but continuing..."
fi

# checking if the risczero-dispatcher binary exists
echo "🔍 Checking risczero-dispatcher binary..."
if [ -f "./target/release/bitvmx-risczero-dispatcher" ]; then
    echo "✅ Binary exists"
    ls -la ./target/release/bitvmx-risczero-dispatcher
else
    echo "❌ Binary not found"
    echo "Available binaries:"
    ls -la ./target/release/ || echo "No release directory"
    exit 1
fi

export PATH="/root/.risc0/bin:${PATH}"
export RISC0_DEV_MODE=1

echo "📋 Starting risczero-dispatcher..."
echo "   Binary: ./target/release/bitvmx-risczero-dispatcher"
echo "   Working dir: $(pwd)"
echo "   Config: $CONFIG_FILE"
echo "   Port: $BROKER_PORT"
echo "   RISC0_DEV_MODE: ${RISC0_DEV_MODE}"

# Execute the risczero dispatcher with proper arguments
exec ./target/release/bitvmx-risczero-dispatcher --port "$BROKER_PORT"
#!/bin/sh
set -e

echo "Starting bitvmx-emulator-dispatcher..."
echo "CLIENT_OP: $CLIENT_OP"

if [ -n "$CLIENT_OP" ]; then
    CONFIG_FILE="config/${CLIENT_OP}.yaml"
    echo "Looking for config file: $CONFIG_FILE"
    
    if [ -f "$CONFIG_FILE" ]; then
        BROKER_PORT=$(grep "broker_port:" "$CONFIG_FILE" | awk '{print $2}' | tr -d ' ')
        
        if [ -n "$BROKER_PORT" ] && [ "$BROKER_PORT" != "" ]; then
            echo "✅ Using broker port $BROKER_PORT from $CONFIG_FILE"
            echo "🚀 Connecting to 127.0.0.1:$BROKER_PORT"
            exec /app/bitvmx-workspace-root/rust-bitvmx-job-dispatcher/target/release/bitvmx-emulator-dispatcher --ip 127.0.0.1 --port "$BROKER_PORT"
        else
            echo "⚠️  Could not extract broker_port from $CONFIG_FILE"
        fi
    else
        echo "⚠️  Config file $CONFIG_FILE not found"
    fi
else
    echo "⚠️  CLIENT_OP environment variable not set"
fi
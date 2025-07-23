#!/bin/bash
set -e

CLIENT_OP=${1:-$(grep "^CLIENT_OP=" .env 2>/dev/null | cut -d'=' -f2)}

if [ -z "$CLIENT_OP" ]; then
    echo "❌ CLIENT_OP not specified"
    echo "Usage: ./start.sh <operator> [docker-compose-args]"
    echo "   Examples: ./start.sh op_1 up"
    echo "             ./start.sh op_2 up -d"
    echo "             ./start.sh op_3 down"
    exit 1
fi

CONFIG_FILE="config/${CLIENT_OP}.yaml"
if [ -f "$CONFIG_FILE" ]; then
    BROKER_PORT=$(grep "broker_port:" "$CONFIG_FILE" | awk '{print $2}' | tr -d ' ')
    
    if [ -z "$BROKER_PORT" ]; then
        echo "❌ Could not extract broker_port from $CONFIG_FILE"
        exit 1
    fi
    
    echo "🚀 Starting BitVMX with:"
    echo "   Operator: $CLIENT_OP"
    echo "   Config: $CONFIG_FILE" 
    echo "   Broker Port: $BROKER_PORT"
    echo "   Container: bitvmx-client-$CLIENT_OP"
    echo ""
    
    export CLIENT_OP="$CLIENT_OP"
    export BROKER_PORT="$BROKER_PORT"
    export BITVMX_CLIENT_CONTAINER_NAME="bitvmx-client-${CLIENT_OP}"
    
    exec docker-compose "${@:2}"
else
    echo "❌ Config file $CONFIG_FILE not found"
    exit 1
fi

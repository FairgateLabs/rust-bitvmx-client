#!/bin/bash
set -e

if [ "$1" = "build" ]; then
    echo "🔨 Building BitVMX Docker images..."
    echo "   Images built will work for any operator (op_1, op_2, op_3, etc.)"
    echo ""    
    
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
    fi
    
    export BROKER_PORT=${BROKER_PORT:-22222} # Default broker port just for building purposes.
    
    exec docker-compose build "${@:2}"
fi

CLIENT_OP=${1:-$(grep "^CLIENT_OP=" .env 2>/dev/null | cut -d'=' -f2)}

if [ -z "$CLIENT_OP" ]; then
    echo "❌ CLIENT_OP not specified"
    echo "Usage: ./start.sh <operator> [docker-compose-args]"
    echo "       ./start.sh build [build-args]"
    echo ""
    echo "   Examples: ./start.sh op_1 up"
    echo "             ./start.sh op_2 up -d"
    echo "             ./start.sh op_3 down"
    echo "             ./start.sh build"
    echo "             ./start.sh build bitvmx-client"
    echo "             ./start.sh build --no-cache"
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
    echo "   Project: bitvmx-$CLIENT_OP"
    
    # Set dynamic BITCOIND_URL based on the operator you want to run
    if [ "$CLIENT_OP" = "op_1" ]; then
        echo "   Bitcoind: Starting new instance (internal network)"
        export BITCOIND_URL="http://bitcoind:18443"
    else
        echo "   Bitcoind: Using shared instance from op_1 (host network)"
        export BITCOIND_URL="http://host.docker.internal:18443"
    fi
    echo "   Bitcoin URL: $BITCOIND_URL"
    echo ""
    
    export CLIENT_OP="$CLIENT_OP"
    export BROKER_PORT="$BROKER_PORT"
    
    # Include bitcoind profile only for op_1
    if [ "$CLIENT_OP" = "op_1" ]; then
        exec docker-compose --project-name "bitvmx-${CLIENT_OP}" --profile bitcoind "${@:2}"
    else
        exec docker-compose --project-name "bitvmx-${CLIENT_OP}" "${@:2}"
    fi
else
    echo "❌ Config file $CONFIG_FILE not found"
    exit 1
fi
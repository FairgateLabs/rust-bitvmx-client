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
    echo "       ./start.sh <operator> up [--zkp]"
    echo ""
    echo "   Examples: ./start.sh op_1 up"
    echo "             ./start.sh op_2 up -d"
    echo "             ./start.sh op_3 down"
    echo "             ./start.sh op_1 up --zkp        # Include ZKP dispatcher"
    echo "             ./start.sh build"
    echo "             ./start.sh build bitvmx-client"
    echo "             ./start.sh build bitvmx-zkp"
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
    
    ZKP_ENABLED=false
    FILTERED_ARGS=()
    for arg in "${@:2}"; do
        if [ "$arg" = "--zkp" ]; then
            ZKP_ENABLED=true
        else
            FILTERED_ARGS+=("$arg")
        fi
    done
    
    echo "🚀 Starting BitVMX with:"
    echo "   Operator: $CLIENT_OP"
    echo "   Config: $CONFIG_FILE" 
    echo "   Broker Port: $BROKER_PORT"
    echo "   Project: bitvmx-$CLIENT_OP"
    
    if [ "$ZKP_ENABLED" = true ]; then
        echo "   ZKP Dispatcher: ✅ ENABLED"
    else
        echo "   ZKP Dispatcher: ❌ DISABLED (use --zkp to enable)"
    fi
    
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
    
    PROFILES=()
    if [ "$CLIENT_OP" = "op_1" ]; then
        PROFILES+=("--profile" "bitcoind")
    fi
    
    if [ "$ZKP_ENABLED" = true ]; then
        PROFILES+=("--profile" "zkp")
    fi
    
    COMPOSE_CMD=(docker-compose --project-name "bitvmx-${CLIENT_OP}")
    COMPOSE_CMD+=("${PROFILES[@]}")
    COMPOSE_CMD+=("${FILTERED_ARGS[@]}")
    
    echo "🔧 Command: ${COMPOSE_CMD[*]}"
    echo ""
    
    exec "${COMPOSE_CMD[@]}"
else
    echo "❌ Config file $CONFIG_FILE not found"
    exit 1
fi
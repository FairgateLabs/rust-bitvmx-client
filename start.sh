#!/bin/bash

CLIENT_OP=${1:-op_1}

if [ -z "$CLIENT_OP" ]; then
    echo "Usage: ./start.sh <config_name> [docker-compose-args]"
    echo "Examples:"
    echo "  ./start.sh testnet_op_1 up --zkp"
    echo "  ./start.sh op_1 up"
    exit 1
fi

# Use CLIENT_OP directly as config file name  
CONFIG_FILE="config/${CLIENT_OP}.yaml"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Configuration file $CONFIG_FILE does not exist"
    exit 1
fi

# Extract broker port from config
BROKER_PORT=$(grep "broker_port:" "$CONFIG_FILE" | awk '{print $2}' | tr -d ' ')
if [ -z "$BROKER_PORT" ]; then
    echo "❌ Could not extract broker_port from $CONFIG_FILE"
    exit 1
fi

# Extract Bitcoin URL from config file
BITCOIN_URL=$(grep "url:" "$CONFIG_FILE" | awk '{print $2}' | tr -d ' "')
if [ -z "$BITCOIN_URL" ]; then
    echo "❌ Bitcoin URL not found in $CONFIG_FILE"
    exit 1
fi

# Process arguments for ZKP and other options
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
echo "   Config: $CONFIG_FILE"
echo "   Broker Port: $BROKER_PORT"

if [ "$ZKP_ENABLED" = true ]; then
    echo "   ZKP Dispatcher: ✅ ENABLED"
else
    echo "   ZKP Dispatcher: ❌ DISABLED (use --zkp to enable)"
fi

# Determine profile based on URL - external if contains external domains
if [[ "$BITCOIN_URL" == *"bitcoind-testnet"* ]] || [[ "$BITCOIN_URL" == *"external"* ]] || [[ "$BITCOIN_URL" == *"alphanet"* ]]; then
    PROFILE_BITCOIN="external"
    echo "   Bitcoin: External instance"
else
    PROFILE_BITCOIN="bitcoind"  
    echo "   Bitcoin: Local instance"
fi

echo "   Bitcoin URL: $BITCOIN_URL"

# Set environment variables
export CLIENT_OP="$CLIENT_OP"
export BROKER_PORT="$BROKER_PORT"
export BITCOIND_URL="$BITCOIN_URL"

# Build profiles array
PROFILES=()
if [ "$PROFILE_BITCOIN" = "bitcoind" ]; then
    PROFILES+=("--profile" "bitcoind")
fi
if [ "$ZKP_ENABLED" = true ]; then
    PROFILES+=("--profile" "zkp")
fi

# Build final command
COMPOSE_CMD=(docker-compose --project-name "bitvmx-${CLIENT_OP}")
COMPOSE_CMD+=("${PROFILES[@]}")
COMPOSE_CMD+=("${FILTERED_ARGS[@]}")

echo ""
echo "🔧 Command: ${COMPOSE_CMD[*]}"
echo ""

exec "${COMPOSE_CMD[@]}"
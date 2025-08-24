#!/bin/bash
set -euo pipefail

NIGHTLY="${1:-false}"
DOCKER_COMPOSE_PATH="${2:-docker-compose.test.yml}"

echo "🚀 Starting test execution..."
echo "📋 Nightly mode: $NIGHTLY"
echo "🐳 Docker compose file: $DOCKER_COMPOSE_PATH"

# Función para reiniciar Bitcoin Core
restart_bitcoin() {
    echo "🔄 Restarting Bitcoin Core..."
    if [ -f "$DOCKER_COMPOSE_PATH" ]; then
        docker-compose -f "$DOCKER_COMPOSE_PATH" restart bitcoin
        sleep 15
        echo "✅ Bitcoin Core restarted"
        return 0
    else
        echo "⚠️ Docker compose file not found: $DOCKER_COMPOSE_PATH"
        return 1
    fi
}

if [[ "$NIGHTLY" == "true" ]]; then
    echo "🌙 Running nightly tests with Bitcoin Core restart between tests..."
    
    # Cleanup inicial
    echo "🧹 Initial cleanup..."
    if [ -f "$DOCKER_COMPOSE_PATH" ]; then
        docker-compose -f "$DOCKER_COMPOSE_PATH" down --volumes || true
        docker-compose -f "$DOCKER_COMPOSE_PATH" up -d bitcoin
        sleep 15
    fi
    
    # Lista de todos los tests regtest
    REGTEST_TESTS=(
        "test_drp:20m"
        "test_aggregation:15m" 
        "test_full:25m"
        #"test_transfer:15m"
        "test_lock:15m"
        "test_send_lockreq_tx:10m"
        "test_prepare_bitcoin:5m"
        "test_slot_and_drp:20m"
        "test_slot_only:15m"
    )
    
    for test_spec in "${REGTEST_TESTS[@]}"; do
        test_name="${test_spec%%:*}"
        timeout_duration="${test_spec##*:}"
        
        echo ""
        echo "🧪 Running test: $test_name (timeout: $timeout_duration)"
        echo "=================================================="
        
        if timeout "$timeout_duration" cargo test "$test_name" --release --features regtest -- --exact --test-threads=1 --nocapture; then
            echo "✅ Test $test_name PASSED"
        else
            echo "❌ Test $test_name FAILED"
            exit 1
        fi
        
        # Restart Bitcoin Core después de cada test (excepto el último)
        if [[ "$test_name" != "test_slot_only" ]]; then
            restart_bitcoin || echo "⚠️ Bitcoin restart failed, continuing..."
        fi
    done
    
    echo ""
    echo "🎉 All regtest tests completed successfully!"
    
else
    echo "☀️ Running regular tests..."
    cargo test --release --features regtest -- --test-threads=1
    #cargo test --release --features regtest -- test_drp
fi
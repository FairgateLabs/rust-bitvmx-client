#!/bin/bash
set -euo pipefail

NIGHTLY="${1:-false}"
DOCKER_COMPOSE_PATH="${2:-docker-compose.yml}"

echo "🚀 Starting test execution..."
echo "📋 Nightly mode: $NIGHTLY"
echo "🐳 Docker compose file: $DOCKER_COMPOSE_PATH"

if [[ "$NIGHTLY" == "true" ]]; then
    echo "🌙 Running nightly tests with Bitcoin Core restart between tests..."
    
    # Lista de todos los tests regtest
    REGTEST_TESTS=(
        "test_full:35m"
        "test_drp:35m"
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
        
    done
    
    echo ""
    echo "🎉 All regtest tests completed successfully!"
    
else
    echo "☀️ Running regular tests..."
    cargo test --release --features regtest -- --test-threads=1
    #cargo test --release --features regtest -- test_drp
fi
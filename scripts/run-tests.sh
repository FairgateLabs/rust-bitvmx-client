#!/bin/bash
set -euo pipefail

NIGHTLY="${1:-false}"
DOCKER_COMPOSE_PATH="${2:-docker-compose.yml}"

echo "🚀 Starting test execution..."
echo "Nightly mode: $NIGHTLY"
echo "Docker compose file: $DOCKER_COMPOSE_PATH"

if [[ "$NIGHTLY" == "true" ]]; then
    echo "🌙 Running nightly tests with Bitcoin Core restart between tests..."
    
    if [[ -f "run_sequential_tests.sh" ]] && [[ -z "$CI" ]] && [[ -z "$GITHUB_ACTIONS" ]]; then
        echo "🚀 Using run_sequential_tests.sh (proven solution for local)"
        chmod +x run_sequential_tests.sh
        ./run_sequential_tests.sh
    else
        echo "⚠️  Using CI-compatible restart logic"
        
        export GITHUB_ACTIONS=true
        
        REGTEST_TESTS=(
            "test_full:35m"
            "test_drp:35m"
        )
        
        restart_bitcoind() {
            echo "🔄 Restarting bitcoind container (proven solution)..."
            
            if docker ps --format "{{.Names}}" | grep -q "^bitcoind$"; then
                echo "🛑 Stopping bitcoind container..."
                if docker stop bitcoind > /dev/null 2>&1; then
                    echo "🚀 Starting bitcoind container..."
                    if docker start bitcoind > /dev/null 2>&1; then
                        echo "⏳ Waiting for bitcoind to be ready (including entrypoint.sh setup)..."
                        sleep 15
                        
                        local ready=false
                        for i in {1..30}; do
                            if docker exec bitcoind bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 -rpcwallet=test_wallet getbalance > /dev/null 2>&1; then
                                ready=true
                                echo "✅ bitcoind is ready and test_wallet is funded"
                                break
                            fi
                            sleep 3
                        done
                        
                        if [[ "$ready" == "true" ]]; then
                            echo "✅ bitcoind container restarted successfully"
                            return 0
                        else
                            echo "❌ bitcoind failed to become ready after restart"
                            return 1
                        fi
                    fi
                fi
            fi
            
            echo "⚠️  Container restart failed, trying docker-compose restart..."
            local original_pwd=$(pwd)
            if [[ -f "tests/docker/docker-compose.yml" ]]; then
                cd tests/docker
                if docker-compose restart bitcoind > /dev/null 2>&1; then
                    echo "⏳ Waiting for docker-compose restart..."
                    sleep 15
                    cd "$original_pwd"
                    echo "✅ bitcoind restarted via docker-compose"
                    return 0
                else
                    echo "❌ docker-compose restart failed"
                    cd "$original_pwd"
                    return 1
                fi
            fi
            
            echo "❌ Could not restart bitcoind - this may cause test failures"
            return 1
        }
        
        test_count=0
        total_tests=${#REGTEST_TESTS[@]}
        
        for test_spec in "${REGTEST_TESTS[@]}"; do
            test_name="${test_spec%%:*}"
            timeout_duration="${test_spec##*:}"
            
            test_count=$((test_count + 1))
            
            echo ""
            echo "Running test $test_count/$total_tests: $test_name (timeout: $timeout_duration)"
            echo "=================================================="
            
            if timeout "$timeout_duration" cargo test "$test_name" --release -- --exact --test-threads=1 --nocapture --ignored; then
                echo "✅ Test $test_name PASSED"
            else
                echo "❌ Test $test_name FAILED"
                exit 1
            fi
            
            if [[ $test_count -lt $total_tests ]]; then
                echo "🔄 Restarting bitcoind between tests (matching proven local solution)..."
                restart_bitcoind
            fi
        done
        
        echo ""
        echo "🎉 All regtest tests completed successfully!"
    fi
    
else
    echo "Running regular tests..."
    cargo test --release -- --test-threads=1
fi
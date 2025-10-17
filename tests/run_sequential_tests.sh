#!/bin/bash
set -e

echo "🚀 Starting sequential test execution..."
echo "================================================"

# Set CI mode to emulate how tests run in GitHub Actions
export GITHUB_ACTIONS=true
echo "🤖 Emulating CI environment (GITHUB_ACTIONS=true) to match CI behavior"

# Function to clean mempool between tests
clean_mempool_between_tests() {
    echo ""
    echo "🧹 Cleaning mempool between tests..."
    
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        # In CI: clean mempool via RPC (bitcoind already running from workflow)
        echo "CI mode: Cleaning mempool via docker exec..."
        
        # Use docker exec to generate blocks (Bitcoin Core 29.1 requires generatetoaddress)
        BITCOIND_CONTAINER=$(docker ps --filter "name=bitcoind" --format "{{.Names}}" | head -1)
        if [[ -n "$BITCOIND_CONTAINER" ]]; then
            # First, check mempool size
            MEMPOOL_SIZE=$(docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 getmempoolinfo | grep -o '"size": [0-9]*' | grep -o '[0-9]*' || echo "0")
            echo "Current mempool size: $MEMPOOL_SIZE transactions"
            
            # Get address from test_wallet
            ADDR=$(docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 -rpcwallet=test_wallet getnewaddress 2>/dev/null)
            if [[ -n "$ADDR" ]]; then
                # Generate blocks until mempool is empty
                MAX_ATTEMPTS=20
                for i in $(seq 1 $MAX_ATTEMPTS); do
                    docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 generatetoaddress 1 "$ADDR" > /dev/null 2>&1
                    MEMPOOL_SIZE=$(docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 getmempoolinfo | grep -o '"size": [0-9]*' | grep -o '[0-9]*' || echo "0")
                    if [[ "$MEMPOOL_SIZE" -eq 0 ]]; then
                        echo "✅ Mempool cleared after $i blocks"
                        break
                    fi
                    if [[ $i -eq $MAX_ATTEMPTS ]]; then
                        echo "⚠️  Warning: Mempool not empty after $MAX_ATTEMPTS blocks (size: $MEMPOOL_SIZE)"
                    fi
                done
                
                # Generate a few more blocks for safety (to ensure all confirmations)
                docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword -rpcport=18443 generatetoaddress 10 "$ADDR" > /dev/null 2>&1
                echo "✅ Generated 10 additional blocks for safety"
            else
                echo "❌ Could not get address from wallet - continuing anyway"
            fi
        else
            echo "❌ Could not find bitcoind container - continuing anyway"
        fi
        
        # Longer delay for RPC calls to settle and state to be cleaned
        echo " Waiting for blockchain state to settle..."
        sleep 5
    else
        # Local mode: restart docker-compose (original proven solution)
        echo " Local mode: Restarting bitcoind container..."
        cd docker && docker-compose down && docker-compose up -d && cd ..
        echo " Waiting for bitcoind to be ready..."
        sleep 10
    fi
}
run_test() {
    local test_file=$1
    local test_name=$2
    local description=$3
    
    echo ""
    echo "🧪 Running $description ($test_name from $test_file)..."
    echo "------------------------------------------------"
    
    if cargo test --release --test "$test_file" "$test_name" -- --test-threads 1 --nocapture --ignored; then
        echo "✅ $description completed successfully!"
    else
        echo "❌ $description failed!"
        exit 1
    fi
}

# Start docker-compose for bitcoind (only in local mode)
if [[ -z "${GITHUB_ACTIONS:-}" ]]; then
    echo "Starting bitcoind container (local mode)..."
    cd docker && docker-compose up -d && cd ..
    
    # Wait a bit for bitcoind to be ready
    echo "Waiting for bitcoind to be ready..."
    sleep 10
else
    echo "CI mode: Using bitcoind container started by GitHub Actions workflow"
    
    # Wait for bitcoind container to be healthy
    echo "Waiting for bitcoind to be healthy..."
    timeout=120
    elapsed=0
    while [ $elapsed -lt $timeout ]; do
        health_status=$(docker inspect --format='{{.State.Health.Status}}' bitcoind 2>/dev/null || echo "not_found")
        if [ "$health_status" = "healthy" ]; then
            echo "✅ Bitcoind is healthy and ready!"
            break
        fi
        echo "   Status: $health_status (waiting...)"
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    if [ $elapsed -ge $timeout ]; then
        echo "❌ Timeout waiting for bitcoind to be healthy"
        docker logs bitcoind --tail 50
        exit 1
    fi
fi

# Run tests sequentially
run_test "fulltest" "test_full" "Full Integration Test"

# Clean mempool between tests to avoid RBF conflicts
clean_mempool_between_tests

run_test "integration" "test_drp" "Dispute Resolution Protocol Test"

# Cleanup (only in local mode)
if [[ -z "${GITHUB_ACTIONS:-}" ]]; then
    echo ""
    echo "🧹 Cleaning up resources (local mode)..."
    cd docker && docker-compose down && cd ..
else
    echo ""
    echo "CI mode: Leaving bitcoind cleanup to GitHub Actions workflow"
fi

echo ""
echo "🎉 All tests completed successfully!"
echo "================================================"
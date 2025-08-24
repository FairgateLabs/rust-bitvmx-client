# #!/bin/bash
# set -euo pipefail

# NIGHTLY="${1:-false}"
# DOCKER_COMPOSE_PATH="${2:-docker-compose.test.yml}"

# echo "🚀 Starting test execution..."
# echo "📋 Nightly mode: $NIGHTLY"
# echo "🐳 Docker compose file: $DOCKER_COMPOSE_PATH"

# # Función para reiniciar Bitcoin Core
# restart_bitcoin() {
#     echo "🔄 Restarting Bitcoin Core..."
#     if [ -f "$DOCKER_COMPOSE_PATH" ]; then
#         docker-compose -f "$DOCKER_COMPOSE_PATH" restart bitcoin
#         sleep 15
#         echo "✅ Bitcoin Core restarted"
#         return 0
#     else
#         echo "⚠️ Docker compose file not found: $DOCKER_COMPOSE_PATH"
#         return 1
#     fi
# }

# if [[ "$NIGHTLY" == "true" ]]; then
#     echo "🌙 Running nightly tests with Bitcoin Core restart between tests..."
    
#     # Cleanup inicial
#     echo "🧹 Initial cleanup..."
#     if [ -f "$DOCKER_COMPOSE_PATH" ]; then
#         docker-compose -f "$DOCKER_COMPOSE_PATH" down --volumes || true
#         docker-compose -f "$DOCKER_COMPOSE_PATH" up -d bitcoin
#         sleep 15
#     fi
    
#     # Lista de todos los tests regtest
#     REGTEST_TESTS=(
#         "test_drp:20m"
#         "test_aggregation:15m" 
#         "test_full:25m"
#         "test_transfer:15m"
#         "test_lock:15m"
#         "test_send_lockreq_tx:10m"
#         "test_prepare_bitcoin:5m"
#         "test_slot_and_drp:20m"
#         "test_slot_only:15m"
#     )
    
#     for test_spec in "${REGTEST_TESTS[@]}"; do
#         test_name="${test_spec%%:*}"
#         timeout_duration="${test_spec##*:}"
        
#         echo ""
#         echo "🧪 Running test: $test_name (timeout: $timeout_duration)"
#         echo "=================================================="
        
#         if timeout "$timeout_duration" cargo test "$test_name" --release --features regtest -- --exact --test-threads=1 --nocapture; then
#             echo "✅ Test $test_name PASSED"
#         else
#             echo "❌ Test $test_name FAILED"
#             exit 1
#         fi
        
#         # Restart Bitcoin Core después de cada test (excepto el último)
#         if [[ "$test_name" != "test_slot_only" ]]; then
#             restart_bitcoin || echo "⚠️ Bitcoin restart failed, continuing..."
#         fi
#     done
    
#     echo ""
#     echo "🎉 All regtest tests completed successfully!"
    
# else
#     echo "☀️ Running regular tests..."
#     cargo test --release --features regtest -- --test-threads=1
#     #cargo test --release --features regtest -- test_drp
# fi




#!/bin/bash
set -euo pipefail
echo "🟢 run-tests.sh versión ACTUALIZADA"
NIGHTLY="${1:-false}"
DOCKER_COMPOSE_PATH="${2:-docker-compose.yml}"

# Limpia directorios temporales de tests (ajusta los paths según tu proyecto)
cleanup_test_dirs() {
    echo "🧹 Cleaning up test directories..."
    rm -rf test_data/ || true
    rm -rf /tmp/bitvmx_* || true
    rm -rf /tmp/op_* || true
    rm -rf /tmp/bitcoin_regtest_* || true
    rm -rf /tmp/storage.db || true
    rm -rf /tmp/*.db || true
    rm -rf /tmp/*.sqlite || true
    # Agrega aquí otros directorios/archivos temporales relevantes
}

# Limpia wallets de bitcoind (requiere bitcoin-cli en PATH y credenciales correctas)
cleanup_bitcoin_wallets() {
    echo "🧹 Cleaning up bitcoin wallets..."
    # Elimina todas las wallets conocidas (sin usar jq)
    wallets=$(bitcoin-cli -regtest listwallets | tr -d '[]" ,' | tr '\n' ' ')
    for wallet in $wallets; do
        if [ -n "$wallet" ]; then
            bitcoin-cli -regtest unloadwallet "$wallet" || true
            bitcoin-cli -regtest -named createwallet wallet_name="$wallet" descriptors=true || true
        fi
    done
    # Opcional: elimina archivos de wallets si se usan rutas personalizadas
    rm -rf /tmp/regtest/wallets/* || true
}

if [[ "$NIGHTLY" == "true" ]]; then
    echo "🌙 Running nightly tests with Bitcoin Core reset between tests..."
    
    # Cleanup inicial
    reset_bitcoin
    cleanup_test_dirs
    cleanup_bitcoin_wallets

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

        # Limpiar estado después de cada test (excepto el último)
        if [[ "$test_name" != "test_slot_only" ]]; then
            reset_bitcoin || echo "⚠️ Bitcoin reset failed, continuing..."
            cleanup_test_dirs
            cleanup_bitcoin_wallets
        fi
    done
    
    echo ""
    echo "🎉 All regtest tests completed successfully!"
    
else
    echo "☀️ Running regular tests..."
    cargo test --release --features regtest -- --test-threads=1
fi

echo "✅ Test execution completed"
#!/bin/bash

# Script para ejecutar tests con aislamiento completo
# Cada test se ejecuta en su propio ambiente Docker limpio

set -e

echo "=== Starting isolated test execution ==="

# Lista de tests a ejecutar en orden específico
# Los tests más estables primero, luego los problemáticos
TESTS=(
    "fulltest"
    "test_aggregation" 
    "slottest"
)

# Puertos base que se incrementarán para cada test
BASE_BITCOIN_PORT=18443
BASE_BROKER_PORT=8080
BASE_P2P_PORT=9000

# Función para limpiar completamente el ambiente
cleanup_environment() {
    local test_name=$1
    echo "=== Cleaning up environment for $test_name ==="
    
    # Parar y remover todos los containers relacionados con el test
    docker-compose -f tests/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
    
    # Remover containers huérfanos que puedan haber quedado
    docker container prune -f 2>/dev/null || true
    
    # Remover volúmenes no utilizados
    docker volume prune -f 2>/dev/null || true
    
    # Limpiar archivos de estado local
    rm -rf target/debug/deps/test_data_* 2>/dev/null || true
    rm -rf /tmp/bitvmx_test_* 2>/dev/null || true
    
    # Limpiar bases de datos de tests anteriores
    find . -name "*.db" -type f -delete 2>/dev/null || true
    find . -name "*.db-*" -type f -delete 2>/dev/null || true
    
    echo "=== Environment cleaned for $test_name ==="
}

# Función para configurar puertos únicos para el test
setup_test_ports() {
    local test_index=$1
    local test_name=$2
    
    # Calcular puertos únicos para este test
    export BITCOIN_PORT=$((BASE_BITCOIN_PORT + test_index * 10))
    export BITCOIN_RPC_PORT=$((BASE_BITCOIN_PORT + test_index * 10 + 1))
    export BROKER_PORT=$((BASE_BROKER_PORT + test_index * 10))
    export P2P_PORT=$((BASE_P2P_PORT + test_index * 10))
    
    echo "=== Ports for $test_name ==="
    echo "Bitcoin Port: $BITCOIN_PORT"
    echo "Bitcoin RPC Port: $BITCOIN_RPC_PORT" 
    echo "Broker Port: $BROKER_PORT"
    echo "P2P Port: $P2P_PORT"
    
    # Crear docker-compose temporal con puertos únicos
    create_isolated_docker_compose $test_index $test_name
}

# Función para crear docker-compose con puertos únicos
create_isolated_docker_compose() {
    local test_index=$1
    local test_name=$2
    
    cat > tests/docker-compose-${test_name}.yml << EOF
version: '3.8'
services:
  bitcoind:
    image: ruimarinho/bitcoin-core:24-alpine
    container_name: bitcoind-${test_name}
    ports:
      - "${BITCOIN_PORT}:${BITCOIN_PORT}"
      - "${BITCOIN_RPC_PORT}:${BITCOIN_RPC_PORT}"
    environment:
      BITCOIN_DATA: /home/bitcoin/.bitcoin
    volumes:
      - bitcoind_data_${test_name}:/home/bitcoin/.bitcoin
    command: >
      bitcoind
      -regtest
      -server
      -rpcallowip=0.0.0.0/0
      -rpcbind=0.0.0.0:${BITCOIN_RPC_PORT}
      -rpcuser=foo
      -rpcpassword=rpcpassword
      -port=${BITCOIN_PORT}
      -fallbackfee=0.0002
      -minrelaytxfee=0.00001
      -blockmintxfee=0.00008
      -debug=1
      -txindex=1
      -zmqpubrawblock=tcp://0.0.0.0:28332
      -zmqpubrawtx=tcp://0.0.0.0:28333
    healthcheck:
      test: ["CMD", "bitcoin-cli", "-regtest", "-rpcuser=foo", "-rpcpassword=rpcpassword", "-rpcport=${BITCOIN_RPC_PORT}", "getblockchaininfo"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  bitcoind_data_${test_name}:
    driver: local
EOF

    echo "=== Created isolated docker-compose for $test_name ==="
}

# Función para esperar que los servicios estén listos
wait_for_services() {
    local test_name=$1
    local max_attempts=30
    local attempt=1
    
    echo "=== Waiting for services to be ready for $test_name ==="
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -u foo:rpcpassword -X POST -H "Content-Type: application/json" \
           -d '{"method":"getblockchaininfo"}' \
           http://127.0.0.1:${BITCOIN_RPC_PORT}/ > /dev/null 2>&1; then
            echo "=== Services ready for $test_name after $attempt attempts ==="
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: Services not ready yet..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "ERROR: Services failed to start for $test_name after $max_attempts attempts"
    return 1
}

# Función para actualizar configuración del test
update_test_config() {
    local test_name=$1
    
    # Crear configuración temporal con puertos únicos
    mkdir -p config/temp_${test_name}
    
    # Copiar y modificar configuración base
    cp config/development.yaml config/temp_${test_name}/development.yaml
    
    # Actualizar puertos en la configuración (si es necesario)
    sed -i "s/18443/${BITCOIN_RPC_PORT}/g" config/temp_${test_name}/development.yaml 2>/dev/null || true
    sed -i "s/8080/${BROKER_PORT}/g" config/temp_${test_name}/development.yaml 2>/dev/null || true
    
    echo "=== Updated configuration for $test_name ==="
}

# Función para ejecutar un test individual
run_isolated_test() {
    local test_index=$1
    local test_name=$2
    
    echo ""
    echo "=========================================="
    echo "=== RUNNING TEST: $test_name ($(($test_index + 1))/${#TESTS[@]}) ==="
    echo "=========================================="
    
    # Paso 1: Limpiar ambiente completamente
    cleanup_environment $test_name
    
    # Paso 2: Configurar puertos únicos
    setup_test_ports $test_index $test_name
    
    # Paso 3: Actualizar configuración
    update_test_config $test_name
    
    # Paso 4: Asegurar que la imagen de Bitcoin esté disponible
    echo "=== Pulling Bitcoin Core image for $test_name ==="
    docker pull ruimarinho/bitcoin-core:24-alpine
    
    # Paso 5: Iniciar servicios con docker-compose aislado
    echo "=== Starting isolated services for $test_name ==="
    docker-compose -f tests/docker-compose-${test_name}.yml up -d
    
    # Paso 6: Esperar que los servicios estén listos
    if ! wait_for_services $test_name; then
        echo "ERROR: Failed to start services for $test_name"
        cleanup_environment $test_name
        return 1
    fi
    
    # Paso 7: Ejecutar el test específico
    echo "=== Executing test: $test_name ==="
    
    # Configurar variables de entorno para el test
    export CI=true
    export BITCOIN_RPC_URL="http://127.0.0.1:${BITCOIN_RPC_PORT}/"
    export TEST_ISOLATION_ID="isolated_${test_name}_$$"
    
    # Ejecutar el test con timeout
    local test_result=0
    timeout 1600 cargo test --release --features regtest $test_name -- --test-threads=1 --nocapture || test_result=$?
    
    # Paso 8: Limpiar después del test
    echo "=== Test $test_name completed with result: $test_result ==="
    cleanup_environment $test_name
    
    # Limpiar archivo de docker-compose temporal
    rm -f tests/docker-compose-${test_name}.yml
    rm -rf config/temp_${test_name}
    
    if [ $test_result -eq 0 ]; then
        echo "✅ TEST PASSED: $test_name"
    elif [ $test_result -eq 124 ]; then
        echo "⏰ TEST TIMEOUT: $test_name (exceeded 10 minutes)"
    else
        echo "❌ TEST FAILED: $test_name (exit code: $test_result)"
    fi
    
    return $test_result
}

# Función principal
main() {
    echo "=== Isolated Test Runner Started ==="
    echo "Tests to run: ${TESTS[*]}"
    
    local failed_tests=()
    local passed_tests=()
    local total_tests=${#TESTS[@]}
    
    # Ejecutar cada test en aislamiento completo
    for i in "${!TESTS[@]}"; do
        local test_name="${TESTS[$i]}"
        
        if run_isolated_test $i $test_name; then
            passed_tests+=("$test_name")
        else
            failed_tests+=("$test_name")
        fi
        
        # Pausa entre tests para asegurar limpieza completa
        echo "=== Waiting 10 seconds before next test ==="
        sleep 10
    done
    
    # Resumen final
    echo ""
    echo "=========================================="
    echo "=== FINAL RESULTS ==="
    echo "=========================================="
    echo "Total tests: $total_tests"
    echo "Passed: ${#passed_tests[@]}"
    echo "Failed: ${#failed_tests[@]}"
    
    if [ ${#passed_tests[@]} -gt 0 ]; then
        echo "✅ Passed tests: ${passed_tests[*]}"
    fi
    
    if [ ${#failed_tests[@]} -gt 0 ]; then
        echo "❌ Failed tests: ${failed_tests[*]}"
        echo "=========================================="
        return 1
    else
        echo "🎉 All tests passed!"
        echo "=========================================="
        return 0
    fi
}

# Ejecutar función principal
main "$@"

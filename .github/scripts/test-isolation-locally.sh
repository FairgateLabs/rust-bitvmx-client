#!/bin/bash

# Script para probar el aislamiento de tests localmente
# Este script simula lo que hará el workflow con ACT

set -e

echo "=== Testing isolated test execution locally ==="

# Cambiar al directorio del cliente
cd "$(dirname "$0")/../.."

# Verificar que estamos en el directorio correcto
if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Not in rust-bitvmx-client directory"
    exit 1
fi

# Configurar variables de entorno como lo haría el workflow
export CI=true
export GITHUB_ACTIONS=true

# Limpiar estado previo
echo "=== Cleaning previous state ==="
docker-compose -f tests/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
docker container prune -f 2>/dev/null || true
docker volume prune -f 2>/dev/null || true

# Ejecutar el script de tests aislados
echo "=== Running isolated tests ==="
chmod +x .github/scripts/run-isolated-tests.sh
./.github/scripts/run-isolated-tests.sh

echo "=== Local isolated test execution completed ==="

#!/bin/sh
set -e

OPERATOR="${CLIENT_OP:-op_1}"

if [ -n "$BITCOIND_URL" ]; then
  sed -i "s|^\([[:space:]]*url:\).*|\1 $BITCOIND_URL|" "/app/rust-bitvmx-workspace/rust-bitvmx-client/config/${OPERATOR}.yaml"
fi

echo "Starting bitvmx-client with $OPERATOR..."
exec /app/rust-bitvmx-workspace/rust-bitvmx-client/target/release/bitvmx-client "$OPERATOR"
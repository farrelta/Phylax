#!/bin/sh
# Start Phylax on the container's loopback and relay the published port to it.
set -e

PORT="${PHYLAX_PORT:-8765}"
DB="${PHYLAX_DB:-/data/phylax.db}"

if [ "${PHYLAX_DEMO:-0}" = "1" ]; then
    DB=/data/demo/phylax-demo.db
    if [ ! -f "$DB" ]; then
        echo "Preparing demo data in /data/demo ..."
        rm -rf /data/demo
        python scripts/prepare_release_demo.py --output-dir /data/demo
    fi
fi

python -m phylax --db "$DB" serve --host 127.0.0.1 --port "$PORT" &
APP=$!

# The relay listens on the container's own network address (not loopback, which
# Phylax uses) so Docker's published port reaches it.
ADDRESS="$(hostname -i | awk '{print $1}')"
socat "TCP-LISTEN:${PORT},bind=${ADDRESS},reuseaddr,fork" "TCP:127.0.0.1:${PORT}" &
RELAY=$!

trap 'kill "$APP" "$RELAY" 2>/dev/null' INT TERM
echo "Phylax is ready: open http://localhost:${PORT} on this computer."
wait "$APP"

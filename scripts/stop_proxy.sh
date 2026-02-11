#!/usr/bin/env bash
set -e

# Stop tesla-http-proxy

NEW_DEFAULT="$HOME/.openclaw/tesla-fleet-api/proxy"
OLD_DEFAULT="$HOME/.moltbot/tesla-fleet-api/proxy"
DEFAULT_PROXY_DIR="$NEW_DEFAULT"
if [ -d "$OLD_DEFAULT" ] && [ ! -d "$NEW_DEFAULT" ]; then
  DEFAULT_PROXY_DIR="$OLD_DEFAULT"
fi
PROXY_DIR="${TESLA_PROXY_DIR:-$DEFAULT_PROXY_DIR}"
PID_FILE="${PROXY_DIR}/proxy.pid"

if [ ! -f "${PID_FILE}" ]; then
    echo "Proxy is not running (no PID file found)"
    exit 0
fi

PROXY_PID=$(cat "${PID_FILE}")

if ! ps -p "${PROXY_PID}" > /dev/null 2>&1; then
    echo "Proxy is not running (stale PID file)"
    rm -f "${PID_FILE}"
    exit 0
fi

echo "Stopping tesla-http-proxy (PID: ${PROXY_PID})..."
kill "${PROXY_PID}"

# Wait for process to exit
for i in {1..10}; do
    if ! ps -p "${PROXY_PID}" > /dev/null 2>&1; then
        rm -f "${PID_FILE}"
        echo "✓ Proxy stopped"
        exit 0
    fi
    sleep 0.5
done

# Force kill if still running
if ps -p "${PROXY_PID}" > /dev/null 2>&1; then
    echo "Force killing proxy..."
    kill -9 "${PROXY_PID}"
    rm -f "${PID_FILE}"
fi

echo "✓ Proxy stopped"

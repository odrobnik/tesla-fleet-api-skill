#!/usr/bin/env bash
set -e

# Tesla Fleet API - HTTP Proxy Setup
# This script installs Go (if needed), builds tesla-http-proxy, and generates TLS certs.

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEW_DEFAULT="$HOME/.openclaw/tesla-fleet-api/proxy"
OLD_DEFAULT="$HOME/.moltbot/tesla-fleet-api/proxy"
DEFAULT_PROXY_DIR="$NEW_DEFAULT"
if [ -d "$OLD_DEFAULT" ] && [ ! -d "$NEW_DEFAULT" ]; then
  DEFAULT_PROXY_DIR="$OLD_DEFAULT"
fi
PROXY_DIR="${TESLA_PROXY_DIR:-$DEFAULT_PROXY_DIR}"
GO_BIN="$(go env GOPATH 2>/dev/null)/bin"
if [ -z "$GO_BIN" ] || [ "$GO_BIN" = "/bin" ]; then
  GO_BIN="${HOME}/go/bin"
fi

# Pin vehicle-command version to reduce supply-chain risk.
# Override only if you *explicitly* want a different version.
TESLA_VEHICLE_COMMAND_VERSION_DEFAULT="v0.4.1"
TESLA_VEHICLE_COMMAND_VERSION="${TESLA_VEHICLE_COMMAND_VERSION:-$TESLA_VEHICLE_COMMAND_VERSION_DEFAULT}"

echo "==> Tesla Fleet API Proxy Setup"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is required to build tesla-http-proxy, but was not found." >&2
    echo "Install Go and re-run this script. (On macOS: 'brew install go')" >&2
    exit 1
else
    echo "✓ Go is already installed: $(go version)"
fi

# Create proxy directory
mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

# Build tesla-http-proxy if not already present
if [ ! -f "${GO_BIN}/tesla-http-proxy" ]; then
    echo ""
    echo "==> Building tesla-http-proxy..."
    
    # Prefer go install with a pinned version over an unpinned git clone.
    # This uses the Go module checksum database to detect tampering/tag rewriting.
    echo "Installing tesla-http-proxy from vehicle-command @ ${TESLA_VEHICLE_COMMAND_VERSION}"

    mkdir -p "${GO_BIN}"
    GOBIN="${GO_BIN}" go install "github.com/teslamotors/vehicle-command/cmd/tesla-http-proxy@${TESLA_VEHICLE_COMMAND_VERSION}"

    echo "✓ Installed tesla-http-proxy to ${GO_BIN}/tesla-http-proxy"
else
    echo "✓ tesla-http-proxy already installed"
fi

# Generate TLS certificates if not present
cd "${PROXY_DIR}"
if [ ! -f tls-cert.pem ] || [ ! -f tls-key.pem ]; then
    echo ""
    echo "==> Generating self-signed TLS certificate for localhost..."
    openssl req -x509 -newkey rsa:4096 -keyout tls-key.pem -out tls-cert.pem -days 365 -nodes -subj "/CN=localhost" > /dev/null 2>&1
    chmod 600 tls-key.pem
    echo "✓ Generated TLS certificates in ${PROXY_DIR}"
else
    echo "✓ TLS certificates already exist"
fi

echo ""
echo "==> Setup complete!"
echo ""
echo "Next steps:"
echo "1. Make sure you have a Tesla private key (ECDSA P-256)"
echo "2. Start the proxy with:"
echo "   ${SKILL_DIR}/scripts/start_proxy.sh /path/to/private-key.pem"
echo ""

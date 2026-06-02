#!/usr/bin/env bash
# Installation et démarrage du proxy chiffreur (une instance par VM, port 8400).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

PROXY_CONFIG="${PROXY_CONFIG:-config/proxy_config.json}"
BINARY="${ROOT_DIR}/target/release/proxy_chiffreur"

SKIP_BUILD=false
for arg in "$@"; do
    case "${arg}" in
        --skip-build) SKIP_BUILD=true ;;
        -h|--help)
            echo "Usage: ./install.sh [--skip-build]"
            echo "  PROXY_CONFIG=config/proxy_config.101.json ./install.sh"
            exit 0
            ;;
    esac
done

mkdir -p data config
if [[ ! -f "${PROXY_CONFIG}" ]] && [[ -f config/proxy_config.example.json ]]; then
    cp config/proxy_config.example.json "${PROXY_CONFIG}"
    echo "[INFO] Copie config/proxy_config.example.json → ${PROXY_CONFIG}"
fi

if [[ "${SKIP_BUILD}" != true ]]; then
    cargo build --release
fi

echo "[INFO] Démarrage proxy — PROXY_CONFIG=${PROXY_CONFIG}"
exec env PROXY_CONFIG="${PROXY_CONFIG}" "${BINARY}"

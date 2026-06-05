#!/usr/bin/env bash
# Génère les paquets .deb agent + proxy (machine de build : Rust + cargo-deb).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v cargo-deb >/dev/null 2>&1; then
    echo "[INFO] Installation de cargo-deb..."
    cargo install cargo-deb
fi

echo "=== Agent central ==="
cd "${ROOT}/agent_chiffreur"
cargo deb --profile release -- --bin agent_chiffreur

echo ""
echo "=== Proxy VM ==="
cd "${ROOT}/proxy_chiffreur"
cargo deb --profile release

echo ""
echo "=== Paquets produits ==="
find "${ROOT}" -path '*/target/debian/*.deb' -printf '%p\n' 2>/dev/null \
    || find "${ROOT}" -path '*/target/debian/*.deb' -print 2>/dev/null

echo ""
echo "Sur une autre machine Debian/Ubuntu (une commande par paquet) :"
echo "  sudo apt install ./agent-chiffreur_*.deb"
echo "  sudo apt install ./proxy-chiffreur_*.deb"

#!/usr/bin/env bash
# =============================================================================
# install.sh — Proxy Chiffreur ENSPY (une instance par VM)
#   • build release ou paquet .deb autonome (cargo-deb)
#   • démarrage arrière-plan (nohup) ou systemd
# =============================================================================
#
# Usage :
#   ./install.sh
#   PROXY_CONFIG=config/proxy_config.101.json ./install.sh
#   ./install.sh --systemd
#   ./install.sh --deb
#   ./install.sh --deb-build
#   ./install.sh --stop | --status
#   ./install.sh --skip-build | --foreground
#
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

PROXY_CONFIG="${PROXY_CONFIG:-config/proxy_config.json}"
SERVICE_NAME="proxy_chiffreur"
BINARY="${ROOT_DIR}/target/release/proxy_chiffreur"
PID_FILE="${ROOT_DIR}/data/proxy_chiffreur.pid"
LOG_FILE="${ROOT_DIR}/data/proxy_chiffreur.log"
UNIT_LOCAL="/etc/systemd/system/${SERVICE_NAME}.service"
UNIT_DEV_TEMPLATE="${ROOT_DIR}/debian/${SERVICE_NAME}.service.dev"

SKIP_BUILD=false
USE_SYSTEMD=false
BUILD_DEB=false
INSTALL_DEB=false
DO_STOP=false
DO_STATUS=false
FOREGROUND=false

for arg in "$@"; do
    case "${arg}" in
        --skip-build)  SKIP_BUILD=true ;;
        --systemd)     USE_SYSTEMD=true ;;
        --deb)         BUILD_DEB=true; INSTALL_DEB=true; USE_SYSTEMD=true ;;
        --deb-build)   BUILD_DEB=true ;;
        --stop)        DO_STOP=true ;;
        --status)      DO_STATUS=true ;;
        --foreground)  FOREGROUND=true ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) error "Option inconnue : ${arg}" ;;
    esac
done

have_systemctl() { command -v systemctl >/dev/null 2>&1; }

stop_process() {
    if have_systemctl && systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
        info "Arrêt systemd ${SERVICE_NAME}.service"
        sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        return
    fi
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        if kill -0 "${pid}" 2>/dev/null; then
            kill -TERM "${pid}" 2>/dev/null || true
            sleep 1
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        rm -f "${PID_FILE}"
    fi
}

show_status() {
    if have_systemctl && systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
        systemctl status "${SERVICE_NAME}.service" --no-pager || true
        return
    fi
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        info "En cours PID=$(cat "${PID_FILE}") — log : ${LOG_FILE}"
    else
        warn "Proxy non démarré."
    fi
}

if [[ "${DO_STOP}" == true ]]; then
    stop_process
    exit 0
fi

if [[ "${DO_STATUS}" == true ]]; then
    show_status
    exit 0
fi

echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Proxy Chiffreur ENSPY — Installation / service           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

if [[ "${BUILD_DEB}" == true ]]; then
    section "Paquet Debian (cargo-deb)"
    command -v cargo >/dev/null 2>&1 || error "Rust/cargo requis pour construire le .deb."
    if ! cargo deb --version >/dev/null 2>&1; then
        info "Installation de cargo-deb..."
        cargo install cargo-deb --locked
    fi
    info "cargo deb --release ..."
    cargo deb --release
    DEB="$(ls -1t target/debian/proxy-chiffreur_*.deb 2>/dev/null | head -1)"
    [[ -n "${DEB}" ]] || error "Fichier .deb introuvable dans target/debian/"
    info "Paquet généré : ${DEB}"
    if [[ "${INSTALL_DEB}" == true ]]; then
        sudo dpkg -i "${DEB}" || sudo apt-get install -f -y
        sudo systemctl daemon-reload
        sudo systemctl enable --now "${SERVICE_NAME}.service"
        info "Service : systemctl status ${SERVICE_NAME}"
        exit 0
    fi
    exit 0
fi

section "Configuration"
mkdir -p data config
if [[ ! -f "${PROXY_CONFIG}" ]] && [[ -f config/proxy_config.example.json ]]; then
    cp config/proxy_config.example.json "${PROXY_CONFIG}"
    info "Copie example → ${PROXY_CONFIG}"
fi
[[ -f "${PROXY_CONFIG}" ]] || error "Fichier config absent : ${PROXY_CONFIG}"

section "Prérequis"
command -v cargo >/dev/null 2>&1 || error "Cargo requis ou utilisez --deb."

if [[ "${SKIP_BUILD}" != true ]]; then
    section "Compilation"
    cargo build --release
    [[ -x "${BINARY}" ]] || error "Binaire absent : ${BINARY}"
else
    [[ -x "${BINARY}" ]] || error "Binaire absent"
fi

stop_process

export RUST_LOG="${RUST_LOG:-info}"
if [[ "${PROXY_CONFIG}" = /* ]]; then
    export PROXY_CONFIG
else
    export PROXY_CONFIG="${ROOT_DIR}/${PROXY_CONFIG#./}"
fi

if [[ "${USE_SYSTEMD}" == true ]]; then
    section "Systemd (développement)"
    have_systemctl || error "systemctl introuvable."
    TMP_UNIT="$(mktemp)"
    sed -e "s|@WORKDIR@|${ROOT_DIR}|g" \
        -e "s|@BINARY@|${BINARY}|g" \
        -e "s|@PROXY_CONFIG@|${PROXY_CONFIG}|g" \
        "${UNIT_DEV_TEMPLATE}" > "${TMP_UNIT}"
    sudo cp "${TMP_UNIT}" "${UNIT_LOCAL}"
    rm -f "${TMP_UNIT}"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "${SERVICE_NAME}.service"
    info "Service démarré — PROXY_CONFIG=${PROXY_CONFIG}"
    exit 0
fi

if [[ "${FOREGROUND}" == true ]]; then
    exec env PROXY_CONFIG="${PROXY_CONFIG}" "${BINARY}"
fi

section "Démarrage arrière-plan (nohup)"
nohup env PROXY_CONFIG="${PROXY_CONFIG}" "${BINARY}" >> "${LOG_FILE}" 2>&1 &
echo $! > "${PID_FILE}"
info "PID $(cat "${PID_FILE}") — log : ${LOG_FILE}"
info "Arrêt : ./install.sh --stop"

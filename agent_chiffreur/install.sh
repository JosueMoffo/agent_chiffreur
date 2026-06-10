#!/usr/bin/env bash
# =============================================================================
# install.sh — Agent Chiffreur ENSPY
#   • build release ou paquet .deb (cargo-deb, binaire autonome)
#   • démarrage en arrière-plan (nohup) ou via systemd
# =============================================================================
#
# Usage :
#   ./install.sh                    # init + build + démarrage arrière-plan (nohup)
#   ./install.sh --systemd          # unité systemd locale (répertoire source)
#   ./install.sh --deb              # build .deb + installation système + systemd
#   ./install.sh --deb-build        # génère le .deb uniquement (target/debian/)
#   ./install.sh --stop             # arrêt (nohup ou systemd)
#   ./install.sh --status           # état du processus / service
#   ./install.sh --force-init       # regénère agent_config.json
#   ./install.sh --skip-build       # pas de compilation
#   ./install.sh --init-only        # configuration seulement
#   ./install.sh --foreground       # premier plan (debug)
#
# Paquet .deb : aucune installation de Rust requise sur la machine cible.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

SERVICE_NAME="agent_chiffreur"
BINARY="${ROOT_DIR}/target/release/agent_chiffreur"
PID_FILE="${ROOT_DIR}/data/agent_chiffreur.pid"
LOG_FILE="${ROOT_DIR}/data/agent_chiffreur.log"
UNIT_LOCAL="/etc/systemd/system/${SERVICE_NAME}.service"
UNIT_DEV_TEMPLATE="${ROOT_DIR}/debian/${SERVICE_NAME}.service.dev"

FORCE_INIT=false
SKIP_BUILD=false
INIT_ONLY=false
USE_SYSTEMD=false
BUILD_DEB=false
INSTALL_DEB=false
DO_STOP=false
DO_STATUS=false
FOREGROUND=false

for arg in "$@"; do
    case "${arg}" in
        --force-init)   FORCE_INIT=true ;;
        --skip-build)   SKIP_BUILD=true ;;
        --init-only)    INIT_ONLY=true ;;
        --systemd)      USE_SYSTEMD=true ;;
        --deb)          BUILD_DEB=true; INSTALL_DEB=true; USE_SYSTEMD=true ;;
        --deb-build)    BUILD_DEB=true ;;
        --stop)         DO_STOP=true ;;
        --status)       DO_STATUS=true ;;
        --foreground)   FOREGROUND=true ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) error "Option inconnue : ${arg} (./install.sh --help)" ;;
    esac
done

have_systemctl() { command -v systemctl >/dev/null 2>&1; }

stop_process() {
    if have_systemctl && systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
        info "Arrêt systemd ${SERVICE_NAME}.service"
        sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || systemctl --user stop "${SERVICE_NAME}.service" 2>/dev/null || true
        return
    fi
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        if kill -0 "${pid}" 2>/dev/null; then
            info "Arrêt processus PID ${pid}"
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
        info "En cours (nohup) PID=$(cat "${PID_FILE}") — log : ${LOG_FILE}"
    else
        warn "Agent non démarré."
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
echo "║     Agent Chiffreur ENSPY — Installation / service           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Paquet .deb ───────────────────────────────────────────────────────────────
if [[ "${BUILD_DEB}" == true ]]; then
    section "Paquet Debian (cargo-deb)"
    command -v cargo >/dev/null 2>&1 || error "Rust/cargo requis pour construire le .deb."
    if ! cargo deb --version >/dev/null 2>&1; then
        info "Installation de cargo-deb..."
        cargo install cargo-deb --locked
    fi
    info "cargo deb --release (binaire autonome, depends=\$auto)..."
    cargo deb --release --bin agent_chiffreur
    DEB="$(ls -1t target/debian/agent-chiffreur_*.deb 2>/dev/null | head -1)"
    [[ -n "${DEB}" ]] || error "Fichier .deb introuvable dans target/debian/"
    info "Paquet généré : ${DEB}"
    if [[ "${INSTALL_DEB}" == true ]]; then
        section "Installation du paquet"
        command -v dpkg >/dev/null 2>&1 || error "dpkg requis pour installer le .deb."
        sudo dpkg -i "${DEB}" || sudo apt-get install -f -y
        sudo systemctl daemon-reload
        sudo systemctl enable --now "${SERVICE_NAME}.service"
        info "Service actif : systemctl status ${SERVICE_NAME}"
        exit 0
    fi
    exit 0
fi

# ── Prérequis développement ───────────────────────────────────────────────────
section "Prérequis"
command -v cargo >/dev/null 2>&1 || error "Rust/Cargo introuvable (https://rustup.rs/) ou utilisez --deb."
command -v openssl >/dev/null 2>&1 || error "openssl requis."
command -v python3 >/dev/null 2>&1 || error "python3 requis."

section "Initialisation"
INIT_ARGS=()
[[ "${FORCE_INIT}" == true ]] && INIT_ARGS+=(--force)
bash "${ROOT_DIR}/scripts/init_config.sh" "${INIT_ARGS[@]}"
mkdir -p "${ROOT_DIR}/data"

[[ "${INIT_ONLY}" == true ]] && { info "--init-only : terminé."; exit 0; }

# ── Compilation ───────────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" != true ]]; then
    section "Compilation"
    cargo build --release --bin agent_chiffreur
    [[ -x "${BINARY}" ]] || error "Binaire absent : ${BINARY}"
    info "Binaire : ${BINARY}"
else
    [[ -x "${BINARY}" ]] || error "Binaire absent (--skip-build)"
fi

AGENT_PORT="$(python3 -c "
import json
with open('${ROOT_DIR}/config/agent_config.json') as f:
    print(json.load(f).get('agent_port', 5004))
" 2>/dev/null || echo "5004")"

stop_process

export RUST_LOG="${RUST_LOG:-info}"
export AGENT_CONFIG="${ROOT_DIR}/config/agent_config.json"

# ── Systemd (dev, chemins source) ─────────────────────────────────────────────
if [[ "${USE_SYSTEMD}" == true ]]; then
    section "Systemd (développement)"
    have_systemctl || error "systemctl introuvable."
    [[ -f "${UNIT_DEV_TEMPLATE}" ]] || error "Template absent : ${UNIT_DEV_TEMPLATE}"
    TMP_UNIT="$(mktemp)"
    sed -e "s|@WORKDIR@|${ROOT_DIR}|g" \
        -e "s|@BINARY@|${BINARY}|g" \
        "${UNIT_DEV_TEMPLATE}" > "${TMP_UNIT}"
    sudo cp "${TMP_UNIT}" "${UNIT_LOCAL}"
    rm -f "${TMP_UNIT}"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "${SERVICE_NAME}.service"
    info "Service ${SERVICE_NAME}.service démarré (WorkingDirectory=${ROOT_DIR})"
    info "Santé : curl -s http://localhost:${AGENT_PORT}/health"
    exit 0
fi

# ── Arrière-plan (nohup) ──────────────────────────────────────────────────────
if [[ "${FOREGROUND}" == true ]]; then
    section "Démarrage premier plan"
    exec "${BINARY}"
fi

section "Démarrage arrière-plan (nohup)"
nohup "${BINARY}" >> "${LOG_FILE}" 2>&1 &
echo $! > "${PID_FILE}"
info "PID $(cat "${PID_FILE}") — log : ${LOG_FILE}"
info "HTTP  : http://0.0.0.0:${AGENT_PORT}/health"
info "Arrêt : ./install.sh --stop"

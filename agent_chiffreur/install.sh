#!/usr/bin/env bash
# =============================================================================
# install.sh — Installation et démarrage Agent Chiffreur ENSPY (production)
# =============================================================================
#
# En une commande :
#   - Vérifie les prérequis (cargo, openssl, python3)
#   - Exécute scripts/init_config.sh (config + data/session.json)
#   - Compile le binaire release (agent_chiffreur uniquement, pas la simulation)
#   - Lance l'agent HTTP sur le port défini dans config/agent_config.json
#
# Usage :
#   ./install.sh                 # init (si besoin) + build + démarrage
#   ./install.sh --force-init    # regénère le token dans agent_config.json
#   ./install.sh --skip-build    # démarre sans recompiler (binaire déjà présent)
#   ./install.sh --init-only     # initialisation uniquement, sans lancer l'agent
#
# Arrêt : Ctrl+C ou SIGTERM
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

FORCE_INIT=false
SKIP_BUILD=false
INIT_ONLY=false

for arg in "$@"; do
    case "${arg}" in
        --force-init) FORCE_INIT=true ;;
        --skip-build) SKIP_BUILD=true ;;
        --init-only)  INIT_ONLY=true ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            error "Option inconnue : ${arg} (voir ./install.sh --help)"
            ;;
    esac
done

BINARY="${ROOT_DIR}/target/release/agent_chiffreur"

echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Agent Chiffreur ENSPY — Installation / production      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Prérequis ─────────────────────────────────────────────────────────────────
section "Prérequis"

command -v cargo >/dev/null 2>&1 || error "Rust/Cargo introuvable. Installez : https://rustup.rs/"
command -v openssl >/dev/null 2>&1 || error "openssl introuvable (requis par init_config.sh)."
command -v python3 >/dev/null 2>&1 || error "python3 introuvable (requis par init_config.sh)."

info "cargo  : $(cargo --version 2>/dev/null || echo '?')"
info "openssl: $(openssl version 2>/dev/null || echo '?')"
info "python : $(python3 --version 2>/dev/null || echo '?')"

# ── Initialisation (config + session.json) ────────────────────────────────────
section "Initialisation"

INIT_ARGS=()
[[ "${FORCE_INIT}" == true ]] && INIT_ARGS+=(--force)

bash "${ROOT_DIR}/scripts/init_config.sh" "${INIT_ARGS[@]}"

if [[ ! -f "${ROOT_DIR}/config/agent_config.json" ]]; then
    error "config/agent_config.json absent après init_config.sh"
fi

# Port affiché (lecture rapide via python3)
AGENT_PORT="$(python3 -c "
import json
with open('${ROOT_DIR}/config/agent_config.json') as f:
    print(json.load(f).get('agent_port', 5004))
" 2>/dev/null || echo "5004")"

info "Configuration prête (port HTTP prévu : ${AGENT_PORT})"

if [[ "${INIT_ONLY}" == true ]]; then
    info "Mode --init-only : arrêt sans démarrage de l'agent."
    exit 0
fi

# ── Compilation release (binaire agent uniquement) ────────────────────────────
section "Compilation"

if [[ "${SKIP_BUILD}" == true ]]; then
    [[ -x "${BINARY}" ]] || error "Binaire absent : ${BINARY} (retirez --skip-build ou compilez)"
    info "Compilation ignorée (--skip-build)."
else
    info "cargo build --release --bin agent_chiffreur ..."
    cargo build --release --bin agent_chiffreur
    [[ -x "${BINARY}" ]] || error "Échec : binaire non trouvé après compilation."
    info "Binaire : ${BINARY}"
fi

# ── Démarrage ─────────────────────────────────────────────────────────────────
section "Démarrage de l'agent"

info "Écoute sur http://0.0.0.0:${AGENT_PORT}"
info "Santé    : curl -s http://localhost:${AGENT_PORT}/health"
info "Arrêt    : Ctrl+C ou SIGTERM"
echo ""

export RUST_LOG="${RUST_LOG:-info}"

exec "${BINARY}"

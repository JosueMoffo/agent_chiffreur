#!/usr/bin/env bash
# =============================================================================
# Simulation.sh — Lance la simulation d'intégration HTTP (Agent Chiffreur ENSPY)
# =============================================================================
#
# Démarre un serveur HTTP local dédié (port dans tests/simulation_scenarios.json),
# exécute les scénarios A→L contre les vrais endpoints, puis écrit :
#   - data/sim_session.json
#   - data/sim_blobs.json
#   - data/sim_agent_blobs.json
#
# N'utilise pas install.sh ni config/agent_config.json de production.
#
# Usage :
#   ./Simulation.sh              # compile (release) + lance la simulation
#   ./Simulation.sh --skip-build # utilise le binaire déjà compilé
#
# Prérequis : Rust/Cargo
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

SKIP_BUILD=false

for arg in "$@"; do
    case "${arg}" in
        --skip-build) SKIP_BUILD=true ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            error "Option inconnue : ${arg} (voir ./Simulation.sh --help)"
            ;;
    esac
done

SCENARIOS_FILE="${ROOT_DIR}/tests/simulation_scenarios.json"
BINARY="${ROOT_DIR}/target/release/simulation_tests"

echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Agent Chiffreur ENSPY — Simulation HTTP (scénarios)     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

section "Vérifications"

command -v cargo >/dev/null 2>&1 || error "Rust/Cargo introuvable. Installez : https://rustup.rs/"
[[ -f "${SCENARIOS_FILE}" ]] || error "Fichier absent : ${SCENARIOS_FILE}"

SIM_PORT="$(python3 -c "
import json
with open('${SCENARIOS_FILE}') as f:
    print(json.load(f).get('port_simulation', 15004))
" 2>/dev/null || echo "15004")"

info "cargo     : $(cargo --version 2>/dev/null || echo '?')"
info "scénarios : ${SCENARIOS_FILE}"
info "port sim. : ${SIM_PORT} (serveur local éphémère)"

section "Compilation"

if [[ "${SKIP_BUILD}" == true ]]; then
    [[ -x "${BINARY}" ]] || error "Binaire absent : ${BINARY} (retirez --skip-build)"
    info "Compilation ignorée (--skip-build)."
else
    info "cargo build --release --bin simulation_tests ..."
    cargo build --release --bin simulation_tests
    [[ -x "${BINARY}" ]] || error "Échec : binaire non trouvé après compilation."
fi

section "Exécution"

mkdir -p "${ROOT_DIR}/data"
info "Lancement de la simulation (sortie ci-dessous)..."
echo ""

export RUST_LOG="${RUST_LOG:-warn}"

"${BINARY}"
EXIT_CODE=$?

echo ""
if [[ "${EXIT_CODE}" -eq 0 ]]; then
    info "Simulation terminée avec succès."
    info "Artefacts : data/sim_session.json, data/sim_blobs.json, data/sim_agent_blobs.json"
else
    warn "Simulation terminée avec le code de sortie : ${EXIT_CODE}"
fi

exit "${EXIT_CODE}"

#!/usr/bin/env bash
# =============================================================================
# scripts/init_config.sh — Initialisation sécurisée — Agent Chiffreur ENSPY
# =============================================================================
#
# Ce script remplace init_secrets.sh.
# Il crée le fichier JSON de configuration `config/agent_config.json`
# avec des permissions Unix strictes (600) et génère les secrets aléatoires.
#
# Usage :
#   bash scripts/init_config.sh             # initialisation standard
#   bash scripts/init_config.sh --force     # regénère token et clé même si déjà définis
#
# Prérequis : bash ≥ 4, openssl, python3 (ou jq optionnel)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="${PROJECT_DIR}/config"
CONFIG_FILE="${CONFIG_DIR}/agent_config.json"
DATA_DIR="${PROJECT_DIR}/data"
SESSIONS_FILE="${DATA_DIR}/session.json"

FORCE=false
[[ "${1:-}" == "--force" ]] && FORCE=true

echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Agent Chiffreur ENSPY — Initialisation configuration    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Étape 1 : Répertoires ─────────────────────────────────────────────────────
section "Étape 1 : Répertoires"

mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"
info "config/ → mode 700"

mkdir -p "${DATA_DIR}"
chmod 700 "${DATA_DIR}"
info "data/ → mode 700"

# .gitignore dans data/
cat > "${DATA_DIR}/.gitignore" << 'GITIGNORE'
# Sessions VM et blobs — contiennent des clés AES — ne jamais versionner
session.json
blobs_store.json
sim_*.json
*.json
GITIGNORE
info "data/.gitignore créé"

# ── Étape 2 : Créer config/agent_config.json ──────────────────────────────────
section "Étape 2 : Fichier de configuration JSON"

# Générer les secrets
AGENT_TOKEN=$(openssl rand -hex 32)
AGENT_TOKEN_DISPLAY="$(echo "${AGENT_TOKEN}" | head -c 8)...$(echo "${AGENT_TOKEN}" | tail -c 5)"

if [[ -f "${CONFIG_FILE}" ]] && [[ "${FORCE}" == false ]]; then
    info "config/agent_config.json déjà présent — conservé (utiliser --force pour regénérer)."
    # Relire le token existant pour l'affichage
    AGENT_TOKEN_DISPLAY="(existant, masqué)"
else
    # Créer le fichier JSON avec python3 pour garantir le format
    python3 - << PYEOF
import json, sys

config = {
    "_commentaire": "Configuration Agent Chiffreur ENSPY — SECURITY: fichier en mode 600",
    "agent_port": 5004,
    "agent_token": "${AGENT_TOKEN}",
    "intervalle_rotation_sec": 300,
    "old_key_grace_sec": 60,
    "agent_rotation_autorise": "Decideur",
    "intervalle_supervision_sec": 10,
    "seuil_entropie": 256,
    "chemin_session": "data/session.json",
    "agent_auditeur_url": None,
    "agents_connus": {
        "Decideur": "http://localhost:5003",
        "auditeur":  "http://localhost:8500"
    }
}

with open("${CONFIG_FILE}", "w") as f:
    json.dump(config, f, indent=2)
print("config/agent_config.json créé.")
PYEOF

    info "config/agent_config.json généré avec token aléatoire."
fi

# ── Étape 3 : Permissions strictes sur config/agent_config.json ───────────────
section "Étape 3 : Permissions"

chmod 600 "${CONFIG_FILE}"
PERMS=$(stat -c "%a" "${CONFIG_FILE}" 2>/dev/null || stat -f "%OLp" "${CONFIG_FILE}" 2>/dev/null || echo "?")
if [[ "${PERMS}" == "600" ]]; then
    info "✔ config/agent_config.json → mode 600 (lecture/écriture propriétaire uniquement)"
else
    warn "Permissions : ${PERMS} (attendu 600)"
fi

# ── Étape 4 : Créer data/session.json vide ───────────────────────────────
section "Étape 4 : Store sessions VM"

if [[ ! -f "${SESSIONS_FILE}" ]]; then
    python3 - << PYEOF
import json
from datetime import datetime, timezone

store = {
    "_commentaire": "Sessions actives des VMs — SECURITY: fichier en mode 600 — contient les clés AES",
    "schema_version": "1.0",
    "sessions": {},
    "derniere_mise_a_jour": datetime.now(timezone.utc).isoformat()
}

with open("${SESSIONS_FILE}", "w") as f:
    json.dump(store, f, indent=2)
print("data/session.json initialisé (vide).")
PYEOF
    chmod 600 "${SESSIONS_FILE}"
    info "✔ data/session.json → mode 600 (initialisé vide)"
else
    info "data/session.json déjà présent — conservé."
    chmod 600 "${SESSIONS_FILE}"
    info "Permissions forcées à 600."
fi

# ── Étape 5 : Vérification .gitignore ─────────────────────────────────────────
section "Étape 5 : Sécurité git"

GITIGNORE_ROOT="${PROJECT_DIR}/.gitignore"

if [[ -f "${GITIGNORE_ROOT}" ]]; then
    if ! grep -qE '^config/agent_config\.json$' "${GITIGNORE_ROOT}"; then
        echo -e "\n# Configuration Agent Chiffreur — secrets\nconfig/agent_config.json\ndata/session.json\ndata/*.json" >> "${GITIGNORE_ROOT}"
        info "config/agent_config.json et data/*.json ajoutés au .gitignore"
    else
        info "config/agent_config.json déjà dans .gitignore ✔"
    fi
else
    cat > "${GITIGNORE_ROOT}" << 'GITIGNORE_CONTENT'
# Secrets — ne jamais committer
config/agent_config.json
data/session.json
data/*.json

# Binaires Rust
/target/
GITIGNORE_CONTENT
    info ".gitignore créé"
fi

# Vérifier que config n'est pas traqué
if command -v git &>/dev/null && git -C "${PROJECT_DIR}" rev-parse --git-dir &>/dev/null 2>&1; then
    if git -C "${PROJECT_DIR}" ls-files --error-unmatch "${CONFIG_FILE}" &>/dev/null 2>&1; then
        error "ALERTE : config/agent_config.json est traqué par git !"
        error "→ git rm --cached config/agent_config.json && git commit -m 'Remove config from tracking'"
    else
        info "config/agent_config.json n'est pas traqué par git ✔"
    fi
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
section "Résumé"

echo ""
echo -e "  ${GREEN}config/agent_config.json${RESET} : mode 600"
echo -e "  ${GREEN}data/session.json${RESET}    : mode 600"
echo -e "  ${GREEN}config/${RESET}                  : mode 700"
echo -e "  ${GREEN}data/${RESET}                    : mode 700"
echo ""
echo -e "  ${YELLOW}AGENT_TOKEN${RESET}           : ${BOLD}${AGENT_TOKEN_DISPLAY}${RESET}"
echo -e "  ${YELLOW}intervalle_rotation_sec${RESET}: 300 (5 min)"
echo -e "  ${YELLOW}old_key_grace_sec${RESET}      : 60 (1 min)"
echo ""
echo -e "  ${GREEN}✔ Initialisation terminée.${RESET}"
echo ""
echo -e "  Démarrer l'agent (production) :"
echo -e "  ${BOLD}  ./install.sh${RESET}"
echo -e "  ou : ${BOLD}cargo build --release --bin agent_chiffreur && ./target/release/agent_chiffreur${RESET}"
echo ""
echo -e "  Enregistrer une VM :"
echo -e "  ${BOLD}  curl -X POST http://localhost:5004/vm/session/register \\${RESET}"
echo -e "  ${BOLD}    -H 'X-Agent-Token: <token>' \\${RESET}"
echo -e "  ${BOLD}    -d '{\"vm_id\":\"vm-001\",\"vm_pub_key_hex\":\"<64 hex>\",\"url_notification\":\"http://vm:9000/key-update\"}'${RESET}"
echo ""

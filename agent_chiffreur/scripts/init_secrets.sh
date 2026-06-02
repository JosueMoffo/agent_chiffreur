#!/usr/bin/env bash
# =============================================================================
# scripts/init_secrets.sh — Initialisation sécurisée des secrets ENSPY
# =============================================================================
#
# Ce script :
#   1. Copie .env.example vers .env si .env est absent
#   2. Génère une clé AES-256 aléatoire si AGENT_AES_KEY_HEX n'est pas définie
#   3. Génère un token fort si AGENT_TOKEN est encore à sa valeur par défaut
#   4. Applique des permissions Unix strictes sur .env (mode 600)
#   5. Crée le répertoire data/ avec permissions 700
#   6. Vérifie que .env n'est pas traqué par git
#
# Usage :
#   bash scripts/init_secrets.sh
#   bash scripts/init_secrets.sh --force   # Regénère AES_KEY et TOKEN même si déjà définis
#
# Prérequis : bash, openssl, stat (GNU ou BSD)
# =============================================================================

set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# ── Chemin du script (toujours relatif à la racine du projet) ─────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_DIR}/.env"
ENV_EXAMPLE="${PROJECT_DIR}/.env.example"
DATA_DIR="${PROJECT_DIR}/data"

FORCE=false
[[ "${1:-}" == "--force" ]] && FORCE=true

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Agent Chiffreur ENSPY — Initialisation des secrets ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Étape 1 : Créer .env depuis .env.example si absent ───────────────────────
section "Étape 1 : Fichier .env"

if [[ ! -f "${ENV_FILE}" ]]; then
    if [[ ! -f "${ENV_EXAMPLE}" ]]; then
        error ".env.example introuvable dans ${PROJECT_DIR}"
        exit 1
    fi
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    info ".env créé depuis .env.example"
else
    info ".env déjà présent — contenu préservé (utiliser --force pour regénérer)"
fi

# ── Étape 2 : Permissions strictes sur .env ───────────────────────────────────
section "Étape 2 : Permissions Unix"

chmod 600 "${ENV_FILE}"
info ".env → mode 600 (lecture/écriture propriétaire uniquement)"

# Vérification
PERMS=$(stat -c "%a" "${ENV_FILE}" 2>/dev/null || stat -f "%OLp" "${ENV_FILE}" 2>/dev/null || echo "?")
if [[ "${PERMS}" == "600" ]]; then
    info "✔ Permissions vérifiées : ${PERMS}"
else
    warn "Permissions actuelles : ${PERMS} (attendu : 600)"
fi

# ── Étape 3 : Générer le token AGENT_TOKEN si par défaut ─────────────────────
section "Étape 3 : Token inter-agents"

TOKEN_ACTUEL=$(grep -E '^AGENT_TOKEN=' "${ENV_FILE}" | cut -d= -f2- | tr -d '"' | tr -d "'")
TOKEN_DEFAUT="ENSPY-TOKEN-2026"

if [[ "${TOKEN_ACTUEL}" == "${TOKEN_DEFAUT}" ]] || [[ "${FORCE}" == true ]]; then
    NOUVEAU_TOKEN=$(openssl rand -hex 32)
    # Remplacer la ligne AGENT_TOKEN dans .env
    if grep -q '^AGENT_TOKEN=' "${ENV_FILE}"; then
        sed -i.bak "s|^AGENT_TOKEN=.*|AGENT_TOKEN=${NOUVEAU_TOKEN}|" "${ENV_FILE}" && rm -f "${ENV_FILE}.bak"
    else
        echo "AGENT_TOKEN=${NOUVEAU_TOKEN}" >> "${ENV_FILE}"
    fi
    info "✔ AGENT_TOKEN généré aléatoirement (64 hex chars)"
    warn "IMPORTANT : Distribuez ce token à tous les agents du SMA via un canal sécurisé."
else
    info "AGENT_TOKEN déjà personnalisé — conservé."
fi

# ── Étape 4 : Générer la clé AES-256 si absente ───────────────────────────────
section "Étape 4 : Clé AES-256"

# Vérifier si AGENT_AES_KEY_HEX est commentée ou absente
if grep -qE '^#?\s*AGENT_AES_KEY_HEX=' "${ENV_FILE}"; then
    CURRENT_AES=$(grep -E '^AGENT_AES_KEY_HEX=' "${ENV_FILE}" | cut -d= -f2- | tr -d '"' | tr -d "'" || echo "")
    if [[ -z "${CURRENT_AES}" ]] || [[ "${FORCE}" == true ]]; then
        NOUVELLE_CLE=$(openssl rand -hex 32)
        # Remplacer ou décommenter la ligne
        if grep -q '^AGENT_AES_KEY_HEX=' "${ENV_FILE}"; then
            sed -i.bak "s|^AGENT_AES_KEY_HEX=.*|AGENT_AES_KEY_HEX=${NOUVELLE_CLE}|" "${ENV_FILE}" && rm -f "${ENV_FILE}.bak"
        elif grep -q '^#.*AGENT_AES_KEY_HEX=' "${ENV_FILE}"; then
            # Décommenter et remplacer
            sed -i.bak "s|^#.*AGENT_AES_KEY_HEX=.*|AGENT_AES_KEY_HEX=${NOUVELLE_CLE}|" "${ENV_FILE}" && rm -f "${ENV_FILE}.bak"
        else
            echo "AGENT_AES_KEY_HEX=${NOUVELLE_CLE}" >> "${ENV_FILE}"
        fi
        info "✔ AGENT_AES_KEY_HEX générée (mode clé persistante activé)"
    else
        info "AGENT_AES_KEY_HEX déjà définie — conservée."
    fi
else
    # Absent du fichier → ajouter
    NOUVELLE_CLE=$(openssl rand -hex 32)
    echo "AGENT_AES_KEY_HEX=${NOUVELLE_CLE}" >> "${ENV_FILE}"
    info "✔ AGENT_AES_KEY_HEX ajoutée et générée"
fi

# ── Étape 5 : Répertoire data/ ────────────────────────────────────────────────
section "Étape 5 : Répertoire data/"

mkdir -p "${DATA_DIR}"
chmod 700 "${DATA_DIR}"
info "data/ → mode 700 (accès propriétaire uniquement)"

# Créer un .gitignore dans data/ pour ne pas versionner les blobs
cat > "${DATA_DIR}/.gitignore" << 'GITIGNORE'
# Blobs de session — ne pas versionner
session_store.json
*.json
GITIGNORE
info "data/.gitignore créé"

# ── Étape 6 : Vérification .gitignore ────────────────────────────────────────
section "Étape 6 : Sécurité git"

GITIGNORE_ROOT="${PROJECT_DIR}/.gitignore"
PROBLEME_GIT=false

# Vérifier que .env est dans .gitignore
if [[ -f "${GITIGNORE_ROOT}" ]]; then
    if ! grep -qE '^\.env$|^\.env$' "${GITIGNORE_ROOT}"; then
        warn ".env n'est PAS dans .gitignore — ajout automatique..."
        echo -e "\n# Secrets — ne jamais committer\n.env\n.env.*\n!.env.example" >> "${GITIGNORE_ROOT}"
        info ".env ajouté au .gitignore"
    else
        info ".env est déjà dans .gitignore ✔"
    fi
else
    warn ".gitignore absent — création..."
    cat > "${GITIGNORE_ROOT}" << 'GITIGNORE_CONTENT'
# Secrets
.env
.env.*
!.env.example

# Données de session
data/session_store.json
data/*.json

# Binaires Rust
/target/
GITIGNORE_CONTENT
    info ".gitignore créé"
fi

# Vérifier que .env n'est pas déjà traqué
if command -v git &>/dev/null && git -C "${PROJECT_DIR}" rev-parse --git-dir &>/dev/null; then
    if git -C "${PROJECT_DIR}" ls-files --error-unmatch "${ENV_FILE}" &>/dev/null 2>&1; then
        error "ALERTE SÉCURITÉ : .env est actuellement traqué par git !"
        error "Exécutez : git rm --cached .env && git commit -m 'Remove .env from tracking'"
        PROBLEME_GIT=true
    else
        info ".env n'est pas traqué par git ✔"
    fi
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
section "Résumé"

echo -e "  ${GREEN}Fichier .env${RESET}     : ${ENV_FILE}"
echo -e "  ${GREEN}Permissions${RESET}      : $(stat -c "%a" "${ENV_FILE}" 2>/dev/null || stat -f "%OLp" "${ENV_FILE}" 2>/dev/null)"
echo -e "  ${GREEN}Répertoire data/${RESET} : ${DATA_DIR} (mode 700)"
echo ""
echo -e "  ${YELLOW}Variables configurées :${RESET}"
for VAR in AGENT_PORT AGENT_TOKEN AGENT_ROTATION_SEC AGENT_ROTATION_AUTORISE; do
    VAL=$(grep -E "^${VAR}=" "${ENV_FILE}" | cut -d= -f2- || echo "(non définie)")
    if [[ "${VAR}" == "AGENT_TOKEN" ]]; then
        VAL="$(echo "${VAL}" | head -c 8)...$(echo "${VAL}" | tail -c 5) (masqué)"
    fi
    echo -e "    ${CYAN}${VAR}${RESET} = ${VAL}"
done
if grep -q '^AGENT_AES_KEY_HEX=' "${ENV_FILE}"; then
    echo -e "    ${CYAN}AGENT_AES_KEY_HEX${RESET} = (définie, masquée)"
else
    echo -e "    ${CYAN}AGENT_AES_KEY_HEX${RESET} = (absente → mode éphémère)"
fi

echo ""
if [[ "${PROBLEME_GIT}" == true ]]; then
    echo -e "  ${RED}⚠ ACTION REQUISE : retirer .env du suivi git (voir ci-dessus)${RESET}"
else
    echo -e "  ${GREEN}✔ Initialisation terminée avec succès.${RESET}"
fi
echo ""
echo -e "  Démarrer l'agent :"
echo -e "  ${BOLD}  cargo build --release && ./target/release/agent_chiffreur${RESET}"
echo ""

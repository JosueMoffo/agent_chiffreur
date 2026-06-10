#!/usr/bin/env bash
# Génère les certificats agents signés par la CA GANDAL (dossier ca/).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="${ROOT}/ca"
CERTS_DIR="${ROOT}/certs"
DAYS=825

mkdir -p "${CERTS_DIR}"

if [[ ! -f "${CA_DIR}/ca.crt" ]] || [[ ! -f "${CA_DIR}/ca.key" ]]; then
  echo "[ERROR] CA absente : ${CA_DIR}/ca.crt et ca.key requis."
  exit 1
fi

gen_agent() {
  local cn="$1"
  local out_crt="${CERTS_DIR}/${cn}.crt"
  local out_key="${CERTS_DIR}/${cn}.key"
  local csr="${CERTS_DIR}/${cn}.csr"

  openssl genrsa -out "${out_key}" 2048 2>/dev/null
  openssl req -new -key "${out_key}" -out "${csr}" -subj "/CN=${cn}/O=GANDAL/OU=ENSPY" 2>/dev/null
  openssl x509 -req -in "${csr}" -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial -out "${out_crt}" -days "${DAYS}" \
    -extensions v3_req -extfile <(printf '%s\n' \
      "[v3_req]" \
      "subjectAltName=DNS:${cn},DNS:localhost,IP:127.0.0.1") 2>/dev/null
  rm -f "${csr}"
  chmod 600 "${out_key}"
  echo "[OK] ${cn} → ${out_crt}"
}

gen_agent chiffreur
gen_agent proxy
gen_agent decideur
gen_agent auditeur

echo ""
echo "Certificats dans ${CERTS_DIR}/ — CN strict (document GANDAL)."
echo "  export GANDAL_CA=${CA_DIR}/ca.crt"
echo "  export GANDAL_CERT=${CERTS_DIR}/chiffreur.crt"
echo "  export GANDAL_KEY=${CERTS_DIR}/chiffreur.key"

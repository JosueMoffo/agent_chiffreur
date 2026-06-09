# Documentation de Test — Agent Chiffreur ENSPY

**Projet :** SMA ENSPY — Agent Chiffreur  
**Version :** 1.2.0  
**Date :** 2026-06-08  
**Environnement :** Datacenter K8s (Emir) + VM Omega + Filtreur

---

> **Note d'utilisation :** Ce document est la source de vérité unique pour tous les tests du système.
> Il couvre 6 niveaux de test, du sanity-check d'infrastructure jusqu'aux scénarios bout-en-bout.
> Chaque test précise la commande exacte, le résultat attendu, et le diagnostic en cas d'échec.

---

## Table des matières

1. [Carte réseau et prérequis](#1-carte-réseau-et-prérequis)
2. [Niveau 1 — Validation de l'infrastructure](#2-niveau-1--validation-de-linfrastructure)
3. [Niveau 2 — Tests automatisés (Simulation intégrée)](#3-niveau-2--tests-automatisés-simulation-intégrée)
4. [Niveau 3 — Tests API HTTP manuels](#4-niveau-3--tests-api-http-manuels)
5. [Niveau 4 — Tests gRPC et mTLS](#5-niveau-4--tests-grpc-et-mtls)
6. [Niveau 5 — Tests de sécurité avancés](#6-niveau-5--tests-de-sécurité-avancés)
7. [Niveau 6 — Scénarios bout-en-bout (E2E)](#7-niveau-6--scénarios-bout-en-bout-e2e)
8. [Niveau 7 — Tests de résilience et performance](#8-niveau-7--tests-de-résilience-et-performance)
9. [Script de test automatique global](#9-script-de-test-automatique-global)
10. [Matrice de diagnostic rapide](#10-matrice-de-diagnostic-rapide)

---

## 1. Carte réseau et prérequis

### 1.1 Topologie du datacenter

| Machine | IP | Rôle |
|---|---|---|
| **Emir (K8s)** | `192.168.123.110` | Cluster K8s — 5 agents + serveur .deb |
| **Filtreur (VM Linux)** | `192.168.123.200` | Capture réseau + blocage IP |
| **pfSense** | `192.168.123.1` | Routeur / Passerelle Internet |
| **VM Omega** | `192.168.123.50` | proxy-analyseur + proxy-chiffreur |

### 1.2 Matrice des services

| Agent | IP:Port gRPC | IP:Port HTTP | Notes |
|---|---|---|---|
| **Analyseur** | `110:5002` (mTLS agent-auditeur) | `110:5009` | Port `5012` plain pour Proxy |
| **Décideur** | `110:5003` (mTLS) | `110:5013` | |
| **Chiffreur** | `110:5004` (mTLS) | `110:5014` | **Agent de référence de ce document** |
| **agent-auditeur** | `110:5005` (mTLS) | — | |
| **Simulateur** | `110:5006` (mTLS) | `110:5016` (UI) | |
| **Filtreur** | `200:5001` (mTLS) | — | Token requis |
| **proxy-analyseur** | — | `VM:5012` (plain) | Port proxy vers analyseur |
| **proxy-chiffreur** | — | `VM:8400` | Crypto locale par VM |

### 1.3 Prérequis outils (depuis la machine de test Kali)

```bash
sudo apt-get install -y curl jq netcat-openbsd grpcurl python3 \
  python3-grpcio python3-grpcio-tools
```

### 1.4 Variables d'environnement — à définir avant tout test

```bash
export EMIR=192.168.123.110
export FILTREUR=192.168.123.200
export VM=192.168.123.50
export TOKEN="ENSPY-TOKEN-2026"
export CERTS=/tmp/gandal-certs
```

### 1.5 Récupération des certificats mTLS

```bash
mkdir -p $CERTS
scp root@$EMIR:/tmp/gandal-certs/* $CERTS/
```

**Structure attendue dans `$CERTS` :**

| Fichier | Usage |
|---|---|
| `ca.crt` | CA racine de confiance |
| `decideur.crt` / `decideur.key` | Cert Décideur (appels vers Chiffreur, Filtreur) |
| `analyseur.crt` / `analyseur.key` | Cert Analyseur (appels vers Décideur) |
| `agent-auditeur.crt` / `agent-auditeur.key` | Cert agent-auditeur |
| `simulateur.crt` / `simulateur.key` | Cert Simulateur |

---

## 2. Niveau 1 — Validation de l'infrastructure

### TEST-INFRA-01 : État des pods Kubernetes

**Objectif :** S'assurer que tous les agents sont `Running`.  
**Exécution :** Sur `Emir` (accès SSH ou kubectl configuré).

```bash
kubectl get pods -n gandal -o wide
```

**Résultat attendu :**

```
NAME                        READY   STATUS    RESTARTS   AGE
agent-analyseur-xxxx        1/1     Running   0          ...
agent-auditeur-xxxx         1/1     Running   0          ...
agent-chiffreur-xxxx        1/1     Running   0          ...
agent-decideur-xxxx         1/1     Running   0          ...
agent-simulateur-xxxx       1/1     Running   0          ...
deb-server-xxxx             1/1     Running   0          ...
```

**Échec → Diagnostic :**
```bash
kubectl describe pod -n gandal <nom-du-pod>
kubectl logs -n gandal <nom-du-pod> --previous
```

---

### TEST-INFRA-02 : Services NodePort exposés

```bash
kubectl get svc -n gandal
```

**Résultat attendu :** NodePorts `5002–5006`, `5009`, `5012–5016`, `8000` présents et `CLUSTER-IP` attribué.

---

### TEST-INFRA-03 : Matrice TCP de connectivité (depuis Kali)

```bash
echo "=== Ports Emir ==="
for p in 5002 5003 5004 5005 5006 5009 5012 5013 5014 5016 8000; do
  nc -z -w2 $EMIR $p 2>/dev/null \
    && echo "  ✅ $EMIR:$p OUVERT" \
    || echo "  ❌ $EMIR:$p FERMÉ/TIMEOUT"
done

echo "=== Port Filtreur ==="
nc -z -w2 $FILTREUR 5001 2>/dev/null \
  && echo "  ✅ $FILTREUR:5001 OUVERT" \
  || echo "  ❌ $FILTREUR:5001 FERMÉ/TIMEOUT"
```

**Résultat attendu :** Tous les ports affichés `OUVERT`.  
**Échec → Diagnostic :** Vérifier `iptables` sur Emir, `kubectl get svc`, ou règles pfSense.

---

## 3. Niveau 2 — Tests automatisés (Simulation intégrée)

La simulation intégrée lance un serveur agent_chiffreur + proxy_chiffreur **locaux** sur des ports de test (`15004`, `18400`) et exécute 13 scénarios couvrant l'ensemble de l'API.

### TEST-AUTO-01 : Tests unitaires Rust

```bash
cd /home/ghost/Documents/Chiffreur/agent_chiffreur/agent_chiffreur
cargo test
```

**Résultat attendu :**
```
test result: ok. X passed; 0 failed; 0 ignored
```

---

### TEST-AUTO-02 : Simulation HTTP intégrée complète

```bash
cd /home/ghost/Documents/Chiffreur/agent_chiffreur/agent_chiffreur
./Simulation.sh
# Équivalent: cargo run --bin simulation_tests
```

**Scénarios exécutés automatiquement :**

| ID | Opération | Entrée | Résultat attendu |
|---|---|---|---|
| **0** | `POST /encrypt` sans token | `vm_id=101` | `HTTP 200` — token optionnel |
| **A** | `POST /secret/strength` | Secret faible `"abc"` | `score < 60` |
| **B** | `POST /secret/strength` | Secret fort `"Tr0ub4dor&3_ENSPY!2026#"` | `score ≥ 60` |
| **C** | `POST /encrypt` | Plaintext long, VM 101 | `ciphertext` + `iv` + `auth_tag` Base64 |
| **D** | `POST /decrypt` | Données de C | Plaintext original identique |
| **E** | `POST /ecdh/initiate` | Clé X25519 pair fictif | Secrets ECDH identiques des deux côtés |
| **F1** | `POST /password/generate` | `longueur=16`, tous groupes | MDP 16 chars, 4 classes de caractères |
| **F2** | `POST /password/generate` | `longueur=32`, `exclure_ambigus=true` | Aucun char `0 O l 1 I \|` |
| **F3** | `POST /password/generate` | `longueur=8`, `symboles=false` | Aucun symbole ASCII |
| **G** | Falsification GCM | `ciphertext` modifié d'1 octet | `HTTP 400` — `CRYPTO_ERROR` |
| **H** | `POST /vm/session/register` | VMs 101, 102, 103 | `HTTP 201`, `rotation_count=0`, `old_key=null` |
| **I** | `POST /credential/rotate` | Header `X-Agent-Name` incorrect | `HTTP 403` — `FORBIDDEN` |
| **J** | `POST /credential/rotate` | Agent autorisé + vérif. old/new key | `rotation_count` incrémenté, `old_key` présente |
| **K** | Timer de grâce `old_key` | Déchiffrement avec ancienne clé | `HTTP 200`, `key_used: "old"` puis purge |
| **L** | Double rotation | 2 cycles `credential/rotate` | `rotation_count ≥ 2` |

**Lecture du rapport final :**
```
Résultat : X OK / Y FAIL
```
`Y` doit être **0** pour valider le environnement.

**Artefacts générés après la simulation :**

| Fichier | Contenu |
|---|---|
| `data/sim_session.json` | Sessions VM : `public_key`, `new_key`, `old_key` |
| `data/sim_blobs.json` | Export fusionné de tous les flux crypto |
| `data/sim_agent_blobs.json` | Trousseau agent interne (legacy) |

---

## 4. Niveau 3 — Tests API HTTP manuels

### 4.1 Endpoints publics (sans authentification)

#### TEST-HTTP-01 : Health Check — Agent Chiffreur central

```bash
curl -s http://$EMIR:5014/health | jq .
```

**Résultat attendu :**
```json
{
  "status": "ok",
  "agent": "chiffreur",
  "uptime_sec": <N>,
  "version": "1.2.0",
  "sessions_actives": <N>
}
```

---

#### TEST-HTTP-02 : Métriques runtime

```bash
curl -s http://$EMIR:5014/metrics | jq .
```

**Résultat attendu :** JSON avec `requetes_traitees`, `erreurs`, `vms_en_session`.

---

#### TEST-HTTP-03 : Clé publique X25519

```bash
curl -s http://$EMIR:5014/public-key | jq .
```

**Résultat attendu :**
```json
{
  "public_key_hex": "<64 caractères hex>",
  "algorithm": "X25519"
}
```

---

#### TEST-HTTP-04 : Statut registre des proxies

```bash
curl -s http://$EMIR:5014/registry/status | jq .
```

**Résultat attendu :** Liste des proxies enregistrés (peut être vide si aucune VM annoncée).

---

#### TEST-HTTP-05 : Health Check — Analyseur

```bash
curl -s http://$EMIR:5009/health | jq .
```
**Attendu :** `"status":"ok"`, `"agent":"analyseur"`.

---

#### TEST-HTTP-06 : Health Check — Décideur

```bash
curl -s http://$EMIR:5013/health | jq .
```
**Attendu :** JSON avec statut opérationnel du Décideur.

---

#### TEST-HTTP-07 : Métriques Décideur

```bash
curl -s http://$EMIR:5013/metrics | jq .
```

---

#### TEST-HTTP-08 : UI Simulateur

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$EMIR:5016/
```
**Attendu :** `200` ou `302`.

---

#### TEST-HTTP-09 : Serveur .deb (cloud-init)

```bash
curl -s http://$EMIR:8000/ | head -20
```
**Attendu :** Listing HTML avec `proxy-analyseur.deb`, `proxy-chiffreur.deb`.

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$EMIR:8000/proxy-chiffreur.deb
```
**Attendu :** `200` et taille du fichier `.deb` non nulle.

---

### 4.2 Endpoints authentifiés (avec `X-Agent-Token`)

#### TEST-HTTP-10 : Enregistrement d'une session VM

```bash
curl -s -X POST http://$EMIR:5014/vm/session/register \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{
    "vm_id": 9101,
    "public_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    "url_notification": "http://'"$VM"':8400/key-update"
  }' | jq .
```

**Résultat attendu :**
```json
{
  "status": "success",
  "vm_id": 9101,
  "rotation_count": 0,
  "agent_ephemeral_public_key_hex": "<64 chars hex>",
  "new_key_id": "..."
}
```
**Échec :** `VM_ID_INVALID` si `vm_id ≤ 100`. Valeur Proxmox doit être `> 100`.

---

#### TEST-HTTP-11 : Lister les sessions VM actives

```bash
curl -s http://$EMIR:5014/vm/sessions \
  -H "X-Agent-Token: $TOKEN" | jq .
```

**Résultat attendu :** `count` ≥ 1 si TEST-HTTP-10 réussi.

---

#### TEST-HTTP-12 : Chiffrement d'un message (VM enregistrée)

```bash
curl -s -X POST http://$EMIR:5014/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 9101, "plaintext": "Message test ENSPY SMA 2026"}' | jq .
```

**Résultat attendu :**
```json
{
  "status": "success",
  "vm_id": 9101,
  "ciphertext": "<Base64>",
  "iv": "<Base64>",
  "auth_tag": "<Base64>",
  "new_key_id": "..."
}
```
**⚠️ Conserver `ciphertext`, `iv`, `auth_tag` pour le test suivant.**

---

#### TEST-HTTP-13 : Déchiffrement (roundtrip)

Remplacer `CIPHERTEXT`, `IV`, `AUTH_TAG` par les valeurs du test précédent :

```bash
curl -s -X POST http://$EMIR:5014/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{
    "vm_id": 9101,
    "ciphertext": "CIPHERTEXT",
    "iv": "IV",
    "auth_tag": "AUTH_TAG"
  }' | jq .
```

**Résultat attendu :**
```json
{
  "status": "success",
  "plaintext": "Message test ENSPY SMA 2026",
  "key_used": "new",
  "vm_id": 9101
}
```

---

#### TEST-HTTP-14 : Échange ECDH X25519

```bash
curl -s -X POST http://$EMIR:5014/ecdh/initiate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{
    "peer_agent_id": "agent-decideur",
    "peer_public_key_hex": "b2c4d6e8f0a1234567890abcdef1234567890abcdef1234567890abcdef123456"
  }' | jq .
```

**Résultat attendu :**
```json
{
  "agent_ephemeral_public_key_hex": "<64 chars>",
  "shared_secret_hex": "<64 chars>"
}
```

---

#### TEST-HTTP-15 : Évaluation de force d'un secret

```bash
# Secret faible — attendu : score < 60
curl -s -X POST http://$EMIR:5014/secret/strength \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"secret": "abc"}' | jq .score

# Secret fort — attendu : score >= 60
curl -s -X POST http://$EMIR:5014/secret/strength \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"secret": "Tr0ub4dor&3_ENSPY!2026#"}' | jq .score
```

---

#### TEST-HTTP-16 : Génération de mot de passe

```bash
# Variante 1 : 24 chars, tous groupes
curl -s -X POST http://$EMIR:5014/password/generate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{
    "longueur": 24,
    "majuscules": true,
    "minuscules": true,
    "chiffres": true,
    "symboles": true,
    "exclure_ambigus": true
  }' | jq .password

# Variante 2 : 32 chars, sans symboles
curl -s -X POST http://$EMIR:5014/password/generate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"longueur": 32, "symboles": false}' | jq .password
```

---

#### TEST-HTTP-17 : Rotation globale des clés (autorisée)

```bash
curl -s -X POST http://$EMIR:5014/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: agent-decideur" \
  -d '{"request_id": "test-rotation-001"}' | jq .
```

**Résultat attendu :**
```json
{
  "status": "success",
  "rotation_id": "...",
  "vms_total": <N>,
  "vms_reussies": <N>,
  "vms_echecs": 0
}
```

---

#### TEST-HTTP-18 : Rotation refusée (agent non autorisé)

```bash
curl -s -X POST http://$EMIR:5014/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: intrus" \
  -d '{}' | jq .
```

**Résultat attendu :** `HTTP 403` + `"error": "FORBIDDEN"`.

---

#### TEST-HTTP-19 : Annonce proxy → Registre central

```bash
curl -s -X POST http://$EMIR:5014/registry/proxy/announce \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{
    "vm_id": 9101,
    "proxy_url": "http://'"$VM"':8400",
    "public_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  }' | jq .
```

**Résultat attendu :** `"status":"ok"`.

---

#### TEST-HTTP-20 : Purge des old_key expirées

```bash
curl -s -X POST http://$EMIR:5014/vm/sessions/purge-expired \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{}' | jq .
```

**Résultat attendu :** Rapport de purge (nombre de `old_key` supprimées).

---

#### TEST-HTTP-21 : Suppression de session VM

```bash
curl -s -X POST http://$EMIR:5014/vm/session/delete \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 9101}' | jq .
```

**Résultat attendu :** `"status": "ok"`.  
**Vérification :** Re-executer TEST-HTTP-11 → `count` décrémenté de 1.

---

### 4.3 Tests de gestion des erreurs HTTP

#### TEST-HTTP-22 : Déchiffrement avec données falsifiées (intégrité GCM)

```bash
# 1. Chiffrer un message
RESULT=$(curl -s -X POST http://$EMIR:5014/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 9101, "plaintext": "Test intégrité"}')
CT=$(echo $RESULT | jq -r .ciphertext)
IV=$(echo $RESULT | jq -r .iv)
TAG=$(echo $RESULT | jq -r .auth_tag)

# 2. Falsifier le premier octet du ciphertext (A→B)
CT_FALSIFIE=$(echo $CT | sed 's/^A/B/;t;s/^/A/')

# 3. Tenter le déchiffrement avec le ciphertext falsifié
curl -s -X POST http://$EMIR:5014/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d "{\"vm_id\": 9101, \"ciphertext\": \"$CT_FALSIFIE\", \"iv\": \"$IV\", \"auth_tag\": \"$TAG\"}" | jq .
```

**Résultat attendu :** `HTTP 400` + `"error": "CRYPTO_ERROR"`.

---

#### TEST-HTTP-23 : VM non enregistrée

```bash
curl -s -X POST http://$EMIR:5014/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 99999, "plaintext": "test"}' | jq .
```

**Résultat attendu :** `HTTP 404` + `"error": "VM_NOT_FOUND"`.

---

#### TEST-HTTP-24 : vm_id invalide (≤ 100)

```bash
curl -s -X POST http://$EMIR:5014/vm/session/register \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 50, "public_key": "aabbccdd..."}' | jq .
```

**Résultat attendu :** `HTTP 400` + `"error": "INVALID_REQUEST"`.

---

## 5. Niveau 4 — Tests gRPC et mTLS

### TEST-GRPC-01 : Chiffreur `GetHealth` (port 5004)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  $EMIR:5004 agents.AgentChiffreur/GetHealth
```

**Attendu :** `{ "statut": "ok", "uptime": <N> }`

---

### TEST-GRPC-02 : Chiffreur `RotateSecret` via gRPC

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  -H "x-agent-token: $TOKEN" \
  -d '{"request_id":"rot-grpc-001","agent_id":"decideur","reason":"test validation"}' \
  $EMIR:5004 agents.AgentChiffreur/RotateSecret
```

**Attendu :** Réponse OK avec statut de rotation.

---

### TEST-GRPC-03 : Décideur `GetHealth` (port 5003)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/analyseur.crt -key $CERTS/analyseur.key \
  $EMIR:5003 decideur.AgentDecideur/GetHealth
```

**Attendu :** Statut opérationnel.

---

### TEST-GRPC-04 : Analyseur `EnvoyerLog` — Port plain 5012 (Proxy)

```bash
grpcurl -plaintext \
  -H "x-agent-token: $TOKEN" \
  -d '{
    "srcip":"192.168.123.50",
    "dstip":"8.8.8.8",
    "protocol":"TCP",
    "port":"443",
    "vm_id":"9101",
    "timestamp": 1710000000.0
  }' \
  $EMIR:5012 analyseur.AgentAnalyseur/EnvoyerLog
```

**Attendu :** `"statut":"ok"` ou détail d'anomalie. **Jamais `UNAUTHENTICATED`.**

**Si `UNAUTHENTICATED` :**
```bash
kubectl exec -n gandal deploy/agent-analyseur -- \
  cat /opt/gandal/proxy_token 2>/dev/null
```
Le token affiché doit correspondre à `$TOKEN`.

---

### TEST-GRPC-05 : Analyseur `EnvoyerLog` — Port mTLS 5002 (agent-auditeur)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/agent-auditeur.crt -key $CERTS/agent-auditeur.key \
  -d '{"srcip":"192.168.123.50","dstip":"8.8.8.8","protocol":"TCP","port":"80","vm_id":"9101","timestamp":1710000000.0}' \
  $EMIR:5002 analyseur.AgentAnalyseur/EnvoyerLog
```

**Attendu :** OK avec cert `agent-auditeur`. Si échec mTLS → vérifier SAN du cert.

---

### TEST-GRPC-06 : Analyseur `ReloadAnomalies`

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/agent-auditeur.crt -key $CERTS/agent-auditeur.key \
  -d '{"demandeur":"agent-auditeur-test"}' \
  $EMIR:5002 analyseur.AgentAnalyseur/ReloadAnomalies
```

---

### TEST-GRPC-07 : Simulateur `GetHealth` (port 5006)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  $EMIR:5006 agents.AgentSimulateur/GetHealth
```

**Attendu :** `"statut":"ok"`.

---

### TEST-GRPC-08 : agent-auditeur `GetHealth` (port 5005)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  $EMIR:5005 agents.AgentAuditeur/GetHealth
```

---

### TEST-GRPC-09 : Filtreur `GetHealth` (port 5001)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  -H "x-agent-token: $TOKEN" \
  $FILTREUR:5001 agents.AgentFiltreur/GetHealth
```

**Attendu :** `"statut":"ok"`, `"uptime"` > 0.

---

### TEST-GRPC-10 : Filtreur `BlockIp` (blocage d'une IP)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  -H "x-agent-token: $TOKEN" \
  -d '{
    "order_id":"TEST-BLOCK-001",
    "incident_id":"INC-001",
    "ip":"192.168.123.99",
    "raison":"test manuel doc",
    "duree":300,
    "priority":1,
    "revert_condition":"manual"
  }' \
  $FILTREUR:5001 agents.AgentFiltreur/BlockIp
```

**Attendu :** `"statut":"APPLIQUE"`.

**Vérification de la règle iptables :**
```bash
ssh root@$FILTREUR "iptables -L INPUT -n | grep 192.168.123.99"
```
**Attendu :** Règle DROP présente.

---

### TEST-GRPC-11 : Filtreur `UnblockIp` (déblocage)

```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  -H "x-agent-token: $TOKEN" \
  -d '{
    "order_id":"TEST-UNBLOCK-001",
    "incident_id":"INC-001",
    "ip":"192.168.123.99",
    "raison":"fin de test",
    "authorized_by":"admin"
  }' \
  $FILTREUR:5001 agents.AgentFiltreur/UnblockIp
```

**Attendu :** `"statut":"DEBLOQUE"`.  
**Vérification :** `iptables -L INPUT -n | grep 192.168.123.99` → règle supprimée.

---

## 6. Niveau 5 — Tests de sécurité avancés

### TEST-SEC-01 : Rejet mTLS sans certificat client

```bash
grpcurl -cacert $CERTS/ca.crt \
  $EMIR:5004 agents.AgentChiffreur/GetHealth
```

**Attendu :** Erreur TLS handshake — connexion refusée (pas de cert client).

---

### TEST-SEC-02 : Rejet mTLS avec certificat non signé par la CA

```bash
# Générer un certificat auto-signé non reconnu
openssl req -x509 -newkey rsa:2048 -keyout /tmp/fake.key \
  -out /tmp/fake.crt -days 1 -nodes \
  -subj "/CN=intrus"

grpcurl -cacert $CERTS/ca.crt \
  -cert /tmp/fake.crt -key /tmp/fake.key \
  $EMIR:5004 agents.AgentChiffreur/GetHealth
```

**Attendu :** Erreur TLS — certificat non reconnu par la CA.

---

### TEST-SEC-03 : Vérification des logs — absence de données sensibles

```bash
kubectl logs -n gandal deploy/agent-chiffreur --since=5m | \
  grep -iE "(shared_secret|plaintext|new_key|x-agent-token)" | \
  grep -v "grep"
```

**Attendu :** **Aucune ligne** — les secrets ne doivent jamais apparaître dans les logs.

---

### TEST-SEC-04 : Règle anti-SCP active (Filtreur)

```bash
ssh root@$FILTREUR "iptables -L FORWARD -n -v | grep 'tcp dpt:22'"
```

**Attendu :** Règle DROP sur `192.168.123.0/24` sortant port 22.

---

### TEST-SEC-05 : Blocage SCP effectif

```bash
ssh root@$VM \
  "timeout 5 scp -o StrictHostKeyChecking=no /etc/hostname root@8.8.8.8:/tmp/ 2>&1 || true"
```

**Attendu :** Timeout ou connexion refusée (trafic bloqué par le Filtreur).

---

### TEST-SEC-06 : Validation SAN du certificat Décideur

```bash
openssl x509 -in $CERTS/decideur.crt -text | grep -A2 "Subject Alternative Name"
```

**Attendu :** SAN inclut `IP:192.168.123.110` ou `DNS:agent-decideur` (selon la config PKI).

---

## 7. Niveau 6 — Scénarios bout-en-bout (E2E)

### SCENARIO-E2E-A : VM Proxy → Analyseur → Décideur

**Objectif :** Vérifier le flux complet de collecte de logs depuis une VM.

**Étapes :**

1. Ouvrir les logs en parallèle :
```bash
kubectl logs -n gandal deploy/agent-analyseur -f &
kubectl logs -n gandal deploy/agent-decideur -f &
```

2. Générer du trafic depuis la VM :
```bash
ssh root@$VM "curl -s http://example.com > /dev/null"
```

3. Vérifier que le proxy-analyseur collecte et envoie :
```bash
ssh root@$VM "journalctl -u gandal-proxy --since '2 min ago' | tail -20"
```

**Résultat attendu :**
- Logs proxy : lignes `-> example.com:80 TCP` sans `Analyseur gRPC indisponible`
- Logs analyseur : requête `EnvoyerLog` reçue
- Logs décideur : éventuellement `ReceiveAlert` si anomalie détectée

**Prérequis :** `ANALYSEUR_HOST=$EMIR` et `ANALYSEUR_PORT=5012` dans `/etc/gandal-proxy/proxy.env`.

---

### SCENARIO-E2E-B : Filtreur détecte une anomalie → Décideur reçoit l'alerte

**Objectif :** Vérifier la remontée d'alertes réseau au Décideur.

1. Simuler du trafic suspect depuis la VM :
```bash
ssh root@$VM "curl -s --max-time 3 http://malware.test.eicar.org 2>&1 || true"
```

2. Vérifier les logs du Filtreur :
```bash
ssh root@$FILTREUR "journalctl -u agent-filtreur --since '2 min ago' | \
  grep -E 'Alerte|Décideur|ReceiveAlert'"
```

3. Vérifier réception côté Décideur :
```bash
kubectl logs -n gandal deploy/agent-decideur --since=5m | grep -i alert
```

**Résultat attendu :** Alerte visible dans les deux logs.

---

### SCENARIO-E2E-C : Décideur ordonne l'isolation d'une VM

**Objectif :** Vérifier le flux d'isolation réseau complet.

> ⚠️ **Attention :** Ce test coupe réellement le réseau de la VM cible. À exécuter en environnement de test.

1. Vérifier que le proxy écoute sur `5007` :
```bash
ssh root@$VM "ss -tlnp | grep 5007"
```

2. Déclencher `IsolerVM` via gRPC depuis la VM :
```bash
ssh root@$VM 'python3 - << "PY"
import grpc, controleur_pb2, controleur_pb2_grpc

PKI = "/etc/gandal-proxy/pki"
with open(f"{PKI}/ca/ca.crt","rb") as f: ca = f.read()
with open(f"{PKI}/simulateur/simulateur.crt","rb") as f: crt = f.read()
with open(f"{PKI}/simulateur/simulateur.key","rb") as f: key = f.read()

creds = grpc.ssl_channel_credentials(ca, key, crt)
ch = grpc.secure_channel("127.0.0.1:5007", creds)
stub = controleur_pb2_grpc.ControleProxyStub(ch)
rep = stub.IsolerVM(controleur_pb2.OrdreIsolation(
    alert_id="test-e2e-iso-001", vm_id="", raison="test E2E GANDAL"))
print(rep.status, rep.detail)
PY'
```

3. Vérifier l'état d'isolation :
```bash
ssh root@$VM 'python3 - << "PY"
import grpc, controleur_pb2, controleur_pb2_grpc
PKI = "/etc/gandal-proxy/pki"
with open(f"{PKI}/ca/ca.crt","rb") as f: ca = f.read()
with open(f"{PKI}/simulateur/simulateur.crt","rb") as f: crt = f.read()
with open(f"{PKI}/simulateur/simulateur.key","rb") as f: key = f.read()
creds = grpc.ssl_channel_credentials(ca, key, crt)
ch = grpc.secure_channel("127.0.0.1:5007", creds)
stub = controleur_pb2_grpc.ControleProxyStub(ch)
rep = stub.VerifierSante(controleur_pb2.RequeteSante())
print("status:", rep.status, "| isolee:", rep.isolee)
PY'
```

**Résultat attendu :** `status: ok | isolee: True`.

---

### SCENARIO-E2E-D : Rotation globale des clés de chiffrement

**Objectif :** Vérifier que la rotation des clés se propage jusqu'au proxy VM et que les messages chiffrés avec l'ancienne clé sont encore déchiffrables pendant le timer de grâce.

1. Chiffrer un message AVANT la rotation :
```bash
RESULT_AVANT=$(curl -s -X POST http://$EMIR:5014/encrypt \
  -H "Content-Type: application/json" -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 9101, "plaintext": "Message avant rotation"}')
echo $RESULT_AVANT | jq .
```

2. Déclencher la rotation via gRPC :
```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  -H "x-agent-token: $TOKEN" \
  -d '{"request_id":"e2e-rot-001","agent_id":"decideur","reason":"test E2E"}' \
  $EMIR:5004 agents.AgentChiffreur/RotateSecret
```

3. Vérifier la notification reçue par le proxy VM :
```bash
ssh root@$VM "curl -s -X POST http://127.0.0.1:8400/credential/rotate \
  -H 'Content-Type: application/json' \
  -d '{\"vm_id\":9101}' | jq ."
```

4. Déchiffrer le message APRÈS la rotation (via `old_key` pendant la grâce) :
```bash
CT=$(echo $RESULT_AVANT | jq -r .ciphertext)
IV=$(echo $RESULT_AVANT | jq -r .iv)
TAG=$(echo $RESULT_AVANT | jq -r .auth_tag)

curl -s -X POST http://$EMIR:5014/decrypt \
  -H "Content-Type: application/json" -H "X-Agent-Token: $TOKEN" \
  -d "{\"vm_id\": 9101, \"ciphertext\": \"$CT\", \"iv\": \"$IV\", \"auth_tag\": \"$TAG\"}" | jq .
```

**Résultat attendu :** `"key_used": "old"` et `"plaintext": "Message avant rotation"`.

---

### SCENARIO-E2E-E : Provisionnement VM via cloud-init (.deb)

**Objectif :** Simuler ce que fait `create-omega-vm.sh` — récupération des packages depuis le serveur deb.

```bash
curl -s -o /tmp/proxy-chiffreur.deb http://$EMIR:8000/proxy-chiffreur.deb \
  && ls -lh /tmp/proxy-chiffreur.deb \
  && echo "✅ proxy-chiffreur.deb téléchargé" \
  || echo "❌ Échec téléchargement"

curl -s -o /tmp/proxy-analyseur.deb http://$EMIR:8000/proxy-analyseur.deb \
  && ls -lh /tmp/proxy-analyseur.deb \
  && echo "✅ proxy-analyseur.deb téléchargé" \
  || echo "❌ Échec téléchargement"
```

**Résultat attendu :** Fichiers `.deb` de taille non nulle et code HTTP `200`.

---

## 8. Niveau 7 — Tests de résilience et performance

### TEST-RESIL-01 : Redémarrage de l'agent chiffreur (persistance des sessions)

```bash
# 1. Enregistrer une VM et noter rotation_count
curl -s http://$EMIR:5014/vm/sessions \
  -H "X-Agent-Token: $TOKEN" | jq .

# 2. Redémarrer le pod
kubectl rollout restart -n gandal deploy/agent-chiffreur

# 3. Attendre que le pod soit ready
kubectl rollout status -n gandal deploy/agent-chiffreur

# 4. Vérifier que les sessions sont restorées depuis data/session.json
curl -s http://$EMIR:5014/vm/sessions \
  -H "X-Agent-Token: $TOKEN" | jq .count
```

**Résultat attendu :** Le `count` de sessions est identique avant et après le redémarrage (persistance via `data/session.json`).

---

### TEST-RESIL-02 : Comportement avec clé AES éphémère vs persistante

```bash
# Mode éphémère (défaut) — les sessions créées avant le restart seront perdues
kubectl exec -n gandal deploy/agent-chiffreur -- \
  sh -c 'echo $AGENT_AES_KEY_HEX'
```

**Si la variable est vide :** Mode éphémère actif. Après restart, les données chiffrées dans la session précédente seront illisibles. Utiliser `AGENT_AES_KEY_HEX` pour la production.

---

### TEST-RESIL-03 : Comportement du Décideur sans accès au Filtreur

```bash
# Simuler l'indisponibilité du Filtreur
ssh root@$FILTREUR "systemctl stop agent-filtreur"

# Vérifier les logs du Décideur — doit logguer un timeout mais pas crasher
kubectl logs -n gandal deploy/agent-decideur --since=2m | \
  grep -E "filtreur|timeout|health"

# Remettre le Filtreur en ligne
ssh root@$FILTREUR "systemctl start agent-filtreur"
```

**Résultat attendu :** Le Décideur reste opérationnel (health check OK) même si le Filtreur est temporairement indisponible.

---

### TEST-RESIL-04 : Supervision de l'entropie

```bash
kubectl logs -n gandal deploy/agent-chiffreur --since=5m | \
  grep -iE "(entropie|entropy|seuil|pool)"
```

**Résultat attendu :** Logs de supervision périodique. Alerte si pool d'entropie simulé < `AGENT_ENTROPIE_SEUIL` (défaut: 256 octets).

---

### TEST-PERF-01 : Test de charge HTTP basique

```bash
# 100 requêtes successives sur /health
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{time_total}\n" http://$EMIR:5014/health
done | awk '{sum+=$1; n++} END {printf "Moyenne: %.3f s | Total: %d requêtes\n", sum/n, n}'
```

**Résultat attendu :** Temps de réponse moyen < `50ms`.

---

### TEST-PERF-02 : Charge sur l'endpoint chiffrement

```bash
# Nécessite une VM enregistrée (vm_id=9101)
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}:%{time_total}\n" \
    -X POST http://$EMIR:5014/encrypt \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: $TOKEN" \
    -d '{"vm_id": 9101, "plaintext": "Test charge '"$i"'"}' &
done
wait
```

**Résultat attendu :** Tous les codes HTTP `200`, pas d'erreur `500`.

---

## 9. Script de test automatique global

Ce script réunit les vérifications de base en un seul exécutable à lancer depuis **Kali**. Il génère un rapport `✅/❌` et retourne le code de sortie `0` si tout est OK, `1` sinon.

```bash
#!/usr/bin/env bash
# gandal-test-all.sh — Test Suite GANDAL SMA ENSPY
set -uo pipefail

EMIR=${EMIR:-192.168.123.110}
FILTREUR=${FILTREUR:-192.168.123.200}
TOKEN=${TOKEN:-ENSPY-TOKEN-2026}
CERTS=${CERTS:-/tmp/gandal-certs}
PASS=0; FAIL=0

ok()  { echo "  ✅ $1"; PASS=$((PASS+1)); }
ko()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

check_tcp() {
  nc -z -w2 "$1" "$2" 2>/dev/null && ok "TCP $1:$2" || ko "TCP $1:$2"
}
check_http() {
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$1")
  [[ "$code" =~ ^2 ]] && ok "HTTP $1 → $code" || ko "HTTP $1 → $code"
}
check_grpc() {
  local desc="$1"; shift
  grpcurl "$@" >/dev/null 2>&1 && ok "$desc" || ko "$desc"
}

echo "════════════════════════════════════════════════"
echo "  GANDAL TEST SUITE — $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════"

echo ""
echo "=== [1] Connectivité TCP Emir ==="
for p in 5002 5003 5004 5005 5006 5009 5012 5013 5014 5016 8000; do
  check_tcp "$EMIR" "$p"
done
check_tcp "$FILTREUR" 5001

echo ""
echo "=== [2] Endpoints HTTP ==="
check_http "http://$EMIR:5014/health"
check_http "http://$EMIR:5014/metrics"
check_http "http://$EMIR:5014/public-key"
check_http "http://$EMIR:5009/health"
check_http "http://$EMIR:5013/health"
check_http "http://$EMIR:5016/"
check_http "http://$EMIR:8000/"

echo ""
echo "=== [3] Tests gRPC mTLS ==="
check_grpc "Chiffreur GetHealth" \
  -cacert "$CERTS/ca.crt" -cert "$CERTS/decideur.crt" -key "$CERTS/decideur.key" \
  "$EMIR:5004" agents.AgentChiffreur/GetHealth

check_grpc "Simulateur GetHealth" \
  -cacert "$CERTS/ca.crt" -cert "$CERTS/decideur.crt" -key "$CERTS/decideur.key" \
  "$EMIR:5006" agents.AgentSimulateur/GetHealth

check_grpc "agent-auditeur GetHealth" \
  -cacert "$CERTS/ca.crt" -cert "$CERTS/decideur.crt" -key "$CERTS/decideur.key" \
  "$EMIR:5005" agents.AgentAuditeur/GetHealth

check_grpc "Filtreur GetHealth" \
  -cacert "$CERTS/ca.crt" -cert "$CERTS/decideur.crt" -key "$CERTS/decideur.key" \
  -H "x-agent-token: $TOKEN" \
  "$FILTREUR:5001" agents.AgentFiltreur/GetHealth

echo ""
echo "=== [4] Proxy → Analyseur (port 5012, plain) ==="
grpcurl -plaintext \
  -H "x-agent-token: $TOKEN" \
  -d '{"srcip":"10.0.0.1","dstip":"8.8.8.8","protocol":"TCP","port":"443","vm_id":"test-auto","timestamp":1710000000}' \
  "$EMIR:5012" analyseur.AgentAnalyseur/EnvoyerLog >/dev/null 2>&1 \
  && ok "Proxy→Analyseur EnvoyerLog OK" || ko "Proxy→Analyseur EnvoyerLog FAIL"

echo ""
echo "════════════════════════════════════════════════"
echo "  Résultat : $PASS ✅ OK  /  $FAIL ❌ FAIL"
echo "════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

**Utilisation :**
```bash
# Sauvegarder et rendre exécutable
cp /chemin/vers/ce/script /tmp/gandal-test-all.sh
chmod +x /tmp/gandal-test-all.sh

# Lancer avec les variables exportées
export EMIR=192.168.123.110
export FILTREUR=192.168.123.200
export TOKEN="ENSPY-TOKEN-2026"
export CERTS=/tmp/gandal-certs
/tmp/gandal-test-all.sh
```

---

## 10. Matrice de diagnostic rapide

| Symptôme | Cause probable | Commande de diagnostic |
|---|---|---|
| Pod `CrashLoopBackOff` | OOM ou panic Rust | `kubectl logs -n gandal <pod> --previous` |
| `connection refused` sur 5014 | Service K8s `svc-chiffreur` absent | `kubectl get svc -n gandal` |
| `UNAUTHENTICATED` sur 5012 | Token proxy ≠ token agent analyseur | `kubectl exec -n gandal deploy/agent-analyseur -- cat /opt/gandal/proxy_token` |
| `UNAVAILABLE` sur 5002 | proxy.env : `ANALYSEUR_PORT=5002` au lieu de `5012` | `grep ANALYSEUR_PORT /etc/gandal-proxy/proxy.env` |
| mTLS handshake fail | SAN cert incorrect ou CA différente | `openssl x509 -in $CERTS/decideur.crt -text \| grep DNS` |
| `VM_NOT_FOUND` à `/encrypt` | VM non enregistrée | `GET /vm/sessions` pour lister |
| `FORBIDDEN` à `/credential/rotate` | Header `X-Agent-Name` manquant ou incorrect | Doit être `X-Agent-Name: agent-decideur` |
| `CRYPTO_ERROR` au déchiffrement | Données corrompues ou `old_key` expirée | Vérifier `key_used` et `rotation_count` |
| `IsolerVM` → erreur Proxmox | Token Proxmox absent | `grep PROXMOX /etc/gandal-proxy/proxy.env` |
| `.deb` → `404` | Serveur deb vide | `ls /opt/gandal-debs/` sur Emir |
| Entropie pool faible | Alerte supervision | `kubectl logs deploy/agent-chiffreur \| grep entropie` |
| `old_key` toujours présente | Timer de grâce non expiré | Attendre ou appeler `POST /vm/sessions/purge-expired` |
| proxy-chiffreur ne joigne pas l'agent central | URL `agent_central_url` incorrecte | `grep agent_central_url /etc/gandal-proxy/proxy-chiffreur.env` → doit être `http://192.168.123.110:5014` |

---

## Point critique — Configuration proxy avant les tests

Avant tout test impliquant les VMs proxy, vérifier **sur chaque VM** :

```bash
# Doit afficher ANALYSEUR_PORT=5012 (et non 5002)
grep ANALYSEUR_PORT /etc/gandal-proxy/proxy.env

# Correction si nécessaire
sed -i 's/ANALYSEUR_PORT=5002/ANALYSEUR_PORT=5012/' /etc/gandal-proxy/proxy.env
systemctl restart gandal-proxy
journalctl -u gandal-proxy -f
```

Et dans `/opt/gandal/proxy_token` du pod analyseur, le token doit correspondre à `$TOKEN`.

---

*Documentation générée pour ENSPY SMA 2025-2026 — Agent Chiffreur v1.2.0*

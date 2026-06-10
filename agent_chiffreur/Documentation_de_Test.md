# Documentation de Test — Agent Chiffreur & Proxy ENSPY

**Projet :** SMA ENSPY — Agent Chiffreur & Proxy Chiffreur  
**Version :** 1.2.0  
**Date :** 2026-06-08  
**Environnement :** Datacenter K8s (Emir) + VM Omega + Filtreur

---

> **Note d'utilisation :** Ce document est la source de vérité unique pour tous les tests du système.
> Il couvre l'architecture distribuée : **Agent Central** (registre, port 5004/5014) et **Proxy VM** (crypto locale, port 8400).

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
| **Emir (K8s)** | `192.168.123.110` | Cluster K8s — Agent central Chiffreur, Décideur, Auditeur |
| **Filtreur (VM Linux)** | `192.168.123.200` | Capture réseau + blocage IP |
| **pfSense** | `192.168.123.1` | Routeur / Passerelle Internet |
| **VM Omega** | `192.168.123.50` | Proxy Chiffreur local, proxy-analyseur |

### 1.2 Matrice des services

| Agent | IP:Port gRPC | IP:Port HTTP | Notes |
|---|---|---|---|
| **Chiffreur Central** | `110:5004` (mTLS) | `110:5014` | Registre, propagation rotation |
| **Proxy Chiffreur** | — | `VM:8400` | Crypto locale (AES-GCM, ECDH) |
| **Analyseur** | `110:5002` (mTLS) | `110:5009` | Port `5012` plain pour Proxy |
| **Décideur** | `110:5003` (mTLS) | `110:5013` | |
| **Auditeur** | `110:5005` (mTLS) | — | |
| **Filtreur** | `200:5001` (mTLS) | — | |

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

---

## 2. Niveau 1 — Validation de l'infrastructure

### TEST-INFRA-01 : État des pods Kubernetes

**Objectif :** S'assurer que tous les agents sont `Running`.

```bash
kubectl get pods -n gandal -o wide
```

### TEST-INFRA-03 : Matrice TCP de connectivité

```bash
echo "=== Ports Emir (Central) ==="
for p in 5002 5003 5004 5005 5006 5009 5012 5013 5014 5016 8000; do
  nc -z -w2 $EMIR $p 2>/dev/null && echo "  ✅ $EMIR:$p OUVERT" || echo "  ❌ $EMIR:$p FERMÉ"
done

echo "=== Port VM (Proxy) ==="
nc -z -w2 $VM 8400 2>/dev/null && echo "  ✅ $VM:8400 OUVERT" || echo "  ❌ $VM:8400 FERMÉ"
```

---

## 3. Niveau 2 — Tests automatisés (Simulation intégrée)

### TEST-AUTO-01 : Tests unitaires Rust

```bash
cd agent_chiffreur
cargo test
cd ../proxy_chiffreur
cargo test
```

### TEST-AUTO-02 : Simulation HTTP intégrée complète

```bash
cd agent_chiffreur
./Simulation.sh
```
*(Lance une simulation locale sur les ports 15004 pour l'agent et 18400 pour le proxy).*

---

## 4. Niveau 3 — Tests API HTTP manuels

### 4.1 Agent Central (Port 5014 sur K8s / 5004 local)

#### TEST-HTTP-01 : Health Check Central
```bash
curl -s http://$EMIR:5014/health | jq .
```

#### TEST-HTTP-02 : Métriques Central
```bash
curl -s http://$EMIR:5014/metrics | jq .
```

#### TEST-HTTP-03 : Statut registre des proxies
```bash
curl -s http://$EMIR:5014/registry/status | jq .
```

#### TEST-HTTP-04 : Rotation globale (Décideur → Central)
```bash
curl -s -X POST http://$EMIR:5014/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: agent-decideur" \
  -d '{"request_id": "test-rotation-001"}' | jq .
```
*(Doit retourner `vms_total` et le nombre de proxies notifiés).*

#### TEST-HTTP-05 : Annonce proxy → Registre central
```bash
curl -s -X POST http://$EMIR:5014/registry/proxy/announce \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $TOKEN" \
  -d '{"vm_id": 9101, "proxy_url": "http://'"$VM"':8400", "public_key": "aabbcc..."}' | jq .
```

---

### 4.2 Proxy VM (Port 8400)

**Toute la cryptographie se passe ici.**

#### TEST-HTTP-06 : Health & Clé publique Proxy
```bash
curl -s http://$VM:8400/health | jq .
curl -s http://$VM:8400/public-key | jq .
```

#### TEST-HTTP-07 : Enregistrement d'une session VM
```bash
curl -s -X POST http://$VM:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 9101,
    "public_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    "url_notification": "http://127.0.0.1:19001/key-update"
  }' | jq .
```
**Attendu :** `new_key_id` et `agent_ephemeral_public_key_hex` générés.

#### TEST-HTTP-08 : Lister les sessions actives (Proxy)
```bash
curl -s http://$VM:8400/vm/sessions | jq .
```

#### TEST-HTTP-09 : Chiffrement d'un message
```bash
curl -s -X POST http://$VM:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 9101, "plaintext": "Message test ENSPY SMA 2026"}' | jq .
```
**⚠️ Conserver `ciphertext`, `iv`, `auth_tag` pour le test suivant.**

#### TEST-HTTP-10 : Déchiffrement (roundtrip)
```bash
curl -s -X POST http://$VM:8400/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 9101,
    "ciphertext": "CIPHERTEXT",
    "iv": "IV",
    "auth_tag": "AUTH_TAG"
  }' | jq .
```

#### TEST-HTTP-11 : Échange ECDH X25519 (Générique)
```bash
curl -s -X POST http://$VM:8400/ecdh/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "peer_agent_id": "app-client",
    "peer_public_key_hex": "b2c4d6e8f0a1234567890abcdef1234567890abcdef1234567890abcdef123456"
  }' | jq .
```

#### TEST-HTTP-12 : Évaluation de force d'un secret
```bash
curl -s -X POST http://$VM:8400/secret/strength \
  -H "Content-Type: application/json" \
  -d '{"secret": "Tr0ub4dor&3_ENSPY!2026#"}' | jq .score
```

#### TEST-HTTP-13 : Relais P2P inter-VM
```bash
curl -s -X POST http://$VM:8400/proxy/relay \
  -H "Content-Type: application/json" \
  -d '{
    "dest_vm_id": 9102,
    "request": {"message": "bonjour"}
  }' | jq .
```
*(Échouera si la VM 9102 n'est pas connue du réseau, mais teste le parsing proxy).*

---

### 4.3 Tests de gestion des erreurs HTTP

#### TEST-HTTP-14 : Déchiffrement avec données falsifiées (intégrité GCM)
Modifiez un octet du `ciphertext` de l'étape TEST-HTTP-09 et envoyez au proxy (port 8400).
**Attendu :** `HTTP 400` + `"error": "CRYPTO_ERROR"`.

#### TEST-HTTP-15 : Rotation refusée (agent non autorisé sur Central)
Envoyer `X-Agent-Name: intrus` sur l'agent central (port 5014).
**Attendu :** `HTTP 403` + `"error": "FORBIDDEN"`.

---

## 5. Niveau 4 — Tests gRPC et mTLS

*(Identiques à la version monolithique pour les autres agents de l'écosystème : Décideur, Auditeur, Filtreur).*

### TEST-GRPC-01 : Chiffreur `GetHealth` (port 5004)
```bash
grpcurl -cacert $CERTS/ca.crt \
  -cert $CERTS/decideur.crt -key $CERTS/decideur.key \
  $EMIR:5004 agents.AgentChiffreur/GetHealth
```

---

## 6. Niveau 5 — Tests de sécurité avancés

### TEST-SEC-01 : Vérification des logs — absence de données sensibles
```bash
# Vérifier l'Agent Central
kubectl logs -n gandal deploy/agent-chiffreur --since=5m | grep -iE "(shared_secret|new_key)"

# Vérifier le Proxy sur la VM
ssh root@$VM "journalctl -u proxy-chiffreur --since '5m' | grep -iE '(shared_secret|new_key)'"
```
**Attendu :** **Aucune ligne**. Les clés et secrets ne sont jamais loggués.

---

## 7. Niveau 6 — Scénarios bout-en-bout (E2E)

### SCENARIO-E2E-A : Rotation globale des clés et timer de grâce

**Objectif :** Vérifier que la rotation ordonnée au centre se propage au proxy local et que l'ancienne clé marche encore pendant 60s.

1. **Chiffrer** un message AVANT la rotation (sur le proxy) :
```bash
RESULT_AVANT=$(curl -s -X POST http://$VM:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 9101, "plaintext": "Message avant rotation"}')
echo $RESULT_AVANT | jq .
```

2. **Déclencher la rotation globale** (sur l'agent central) :
```bash
curl -s -X POST http://$EMIR:5014/credential/rotate \
  -H "Content-Type: application/json" -H "X-Agent-Name: agent-decideur" \
  -d '{"request_id":"e2e-rot-001"}'
```

3. **Déchiffrer** le message APRÈS la rotation (sur le proxy) :
```bash
CT=$(echo $RESULT_AVANT | jq -r .ciphertext)
IV=$(echo $RESULT_AVANT | jq -r .iv)
TAG=$(echo $RESULT_AVANT | jq -r .auth_tag)

curl -s -X POST http://$VM:8400/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"vm_id\": 9101, \"ciphertext\": \"$CT\", \"iv\": \"$IV\", \"auth_tag\": \"$TAG\"}" | jq .
```
**Résultat attendu :** `"key_used": "old"` et `"plaintext": "Message avant rotation"`.

---

## 8. Niveau 7 — Tests de performance

### TEST-PERF-01 : Charge sur l'endpoint chiffrement du Proxy
```bash
# Nécessite une VM enregistrée (vm_id=9101)
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}:%{time_total}\n" \
    -X POST http://$VM:8400/encrypt \
    -H "Content-Type: application/json" \
    -d '{"vm_id": 9101, "plaintext": "Test charge '"$i"'"}' &
done
wait
```
**Attendu :** Tous les codes HTTP `200`, temps moyen très faible sur la VM.

---

## 9. Matrice de diagnostic rapide

| Symptôme | Cause probable | Action de remédiation |
|---|---|---|
| `connection refused` sur 5014 | Agent Central éteint ou Service K8s défaillant | `kubectl get svc -n gandal` |
| `connection refused` sur 8400 | Proxy Chiffreur non lancé sur la VM | `systemctl status proxy-chiffreur` |
| `FORBIDDEN` à `/credential/rotate` | Header `X-Agent-Name` incorrect (central) | Remplacer par `agent-decideur` |
| `VM_NOT_FOUND` à `/encrypt` | Session absente sur le proxy | Refaire un `POST /vm/session/register` |
| Proxy n'apparaît pas dans `/registry/status` | Échec de synchro entre Proxy et Central | Vérifier `agent_central_url` dans `proxy_config.json` |
| `CRYPTO_ERROR` au déchiffrement | Données altérées ou clé `old_key` expirée (grâce > 60s) | Vérifier le payload JSON ou forcer une rotation |

---

*Documentation générée pour ENSPY SMA 2025-2026 — Architecture Distribuée Central/Proxy v1.2.0*

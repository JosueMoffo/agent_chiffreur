# Documentation de Test — Agent Chiffreur & Proxy ENSPY

**Projet :** SMA ENSPY — Agent Chiffreur & Proxy Chiffreur (Architecture gRPC)  
**Version :** 1.2.0  
**Date :** 2026-06-10  
**Environnement :** Datacenter K8s (Emir) + VM Omega + Filtreur

---

> **Note d'utilisation :** Ce document est la source de vérité unique pour tous les tests du système gRPC/HTTP hybride.
> Il couvre l'architecture distribuée : **Agent Central** (registre gRPC, port 5004) et **Proxy VM** (crypto locale HTTP 8400, administration gRPC 18400).

---

## 1. Carte réseau et prérequis

### 1.1 Topologie du datacenter

| Machine | IP | Rôle |
|---|---|---|
| **Emir (K8s)** | `192.168.123.110` | Cluster K8s — Agent central Chiffreur, Décideur, Auditeur |
| **VM Omega** | `192.168.123.50` | Proxy Chiffreur local, proxy-analyseur |

### 1.2 Matrice des services

| Agent | IP:Port gRPC mTLS | IP:Port HTTP | Notes |
|---|---|---|---|
| **Chiffreur Central** | `110:5004` | — | Registre, propagation rotation |
| **Proxy Chiffreur** | `VM:18400` | `VM:8400` | Crypto locale (HTTP), écoute ordres (gRPC) |
| **Auditeur** | `110:5005` | — | Cible des événements d'audit |
| **Décideur** | `110:5003` | `110:5013` | Initie la rotation |

### 1.3 Prérequis outils (depuis la machine de test Kali)

```bash
sudo apt-get install -y curl jq netcat-openbsd grpcurl
```

### 1.4 Variables d'environnement — à définir avant tout test

```bash
export EMIR=192.168.123.110
export VM=192.168.123.50
export CERTS=/etc/gandal/pki
```

---

## 2. Niveau 1 — Validation de l'infrastructure

### TEST-INFRA-01 : Matrice TCP de connectivité

```bash
echo "=== Port Emir (Central gRPC) ==="
nc -z -w2 $EMIR 5004 2>/dev/null && echo "  ✅ $EMIR:5004 OUVERT" || echo "  ❌ $EMIR:5004 FERMÉ"

echo "=== Ports VM (Proxy HTTP & gRPC) ==="
nc -z -w2 $VM 8400 2>/dev/null && echo "  ✅ $VM:8400 (HTTP) OUVERT" || echo "  ❌ $VM:8400 FERMÉ"
nc -z -w2 $VM 18400 2>/dev/null && echo "  ✅ $VM:18400 (gRPC) OUVERT" || echo "  ❌ $VM:18400 FERMÉ"
```

---

## 3. Niveau 2 — Tests gRPC mTLS (Administration)

L'Agent Central et l'interface d'administration du proxy fonctionnent **exclusivement** en gRPC mTLS.
Les commandes utilisent `grpcurl` avec les certificats locaux appropriés pour contourner les contrôles CN.

### TEST-GRPC-01 : Health Check Central (port 5004)
```bash
grpcurl -cacert $CERTS/ca/ca.crt \
  -cert $CERTS/decideur/decideur.crt -key $CERTS/decideur/decideur.key \
  $EMIR:5004 gandal.v1.ChiffreurService/Health
```

### TEST-GRPC-02 : Statut du registre Central (port 5004)
```bash
grpcurl -cacert $CERTS/ca/ca.crt \
  -cert $CERTS/decideur/decideur.crt -key $CERTS/decideur/decideur.key \
  $EMIR:5004 gandal.v1.ChiffreurService/RegistryStatus
```

### TEST-GRPC-03 : Annonce manuelle d'un Proxy (Simulée)
*Requiert un certificat avec CN=proxy pour réussir.*
```bash
grpcurl -cacert $CERTS/ca/ca.crt \
  -cert $CERTS/proxy/proxy.crt -key $CERTS/proxy/proxy.key \
  -d '{"vm_id": 9101, "proxy_http_url": "http://'"$VM"':8400", "proxy_grpc_addr": "'"$VM"':18400", "public_key_hex": "aabbcc"}' \
  $EMIR:5004 gandal.v1.ChiffreurService/AnnounceProxy
```

### TEST-GRPC-04 : Refus mTLS CN - Tentative de rotation sans les bons droits
*Le certificat `proxy.crt` (CN=proxy) n'a pas le droit de lancer `RotateCredentials` (CN=decideur requis).*
```bash
grpcurl -cacert $CERTS/ca/ca.crt \
  -cert $CERTS/proxy/proxy.crt -key $CERTS/proxy/proxy.key \
  -d '{"request_id": "test-hack"}' \
  $EMIR:5004 gandal.v1.ChiffreurService/RotateCredentials
```
**Attendu :** Erreur gRPC `PermissionDenied`.

---

## 4. Niveau 3 — Tests API HTTP manuels (Proxy VM)

**Toute la cryptographie se passe ici, en local sur la VM, en HTTP standard.**

### TEST-HTTP-01 : Health & Clé publique Proxy
```bash
curl -s http://$VM:8400/health | jq .
curl -s http://$VM:8400/public-key | jq .
```

### TEST-HTTP-02 : Enregistrement d'une session VM
*Initialise l'ECDH local et contacte ensuite automatiquement l'Agent Central via gRPC SyncVm.*
```bash
curl -s -X POST http://$VM:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 9101,
    "public_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    "url_notification": "http://127.0.0.1:19001/key-update"
  }' | jq .
```

### TEST-HTTP-03 : Chiffrement d'un message
```bash
curl -s -X POST http://$VM:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 9101, "plaintext": "Message test ENSPY SMA 2026"}' | jq .
```
**⚠️ Conserver `ciphertext`, `iv`, `auth_tag` pour le test suivant.**

### TEST-HTTP-04 : Déchiffrement (roundtrip)
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

### TEST-HTTP-05 : Évaluation de force d'un secret
```bash
curl -s -X POST http://$VM:8400/secret/strength \
  -H "Content-Type: application/json" \
  -d '{"secret": "Tr0ub4dor&3_ENSPY!2026#"}' | jq .score
```

---

## 5. Niveau 4 — Scénarios bout-en-bout (E2E)

### SCENARIO-E2E-A : Rotation globale déclenchée via gRPC (Décideur → Central → Proxy)

**Objectif :** Vérifier que la rotation ordonnée au centre se propage au proxy local via gRPC et que l'ancienne clé marche encore pendant 60s sur HTTP.

1. **Chiffrer** un message AVANT la rotation (HTTP sur le proxy) :
```bash
RESULT_AVANT=$(curl -s -X POST http://$VM:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 9101, "plaintext": "Message avant rotation"}')
echo $RESULT_AVANT | jq .
```

2. **Déclencher la rotation globale** (gRPC sur l'agent central avec certificat Décideur) :
```bash
grpcurl -cacert $CERTS/ca/ca.crt \
  -cert $CERTS/decideur/decideur.crt -key $CERTS/decideur/decideur.key \
  -d '{"request_id": "e2e-rot-001", "initiateur": "decideur"}' \
  $EMIR:5004 gandal.v1.ChiffreurService/RotateCredentials
```
*(Vous devriez voir `succes: true` pour votre `proxy_vm_id`).*

3. **Déchiffrer** le message APRÈS la rotation (HTTP sur le proxy) :
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

## 6. Matrice de diagnostic rapide

| Symptôme | Cause probable | Action de remédiation |
|---|---|---|
| `connection refused` sur 5004 | Agent Central éteint ou Service K8s défaillant | `kubectl get svc -n gandal` |
| `connection refused` sur 8400 | Proxy Chiffreur HTTP non lancé sur la VM | `systemctl status proxy_chiffreur` |
| gRPC `PermissionDenied` | Certificat utilisé n'a pas le bon `CN` | Utiliser les bons certificats (`CN=decideur` pour la rotation) |
| gRPC `Unauthenticated` | Tentative gRPC sans configurer le TLS/mTLS | Ajouter `-cacert`, `-cert`, `-key` dans la commande `grpcurl` |
| `VM_NOT_FOUND` à `/encrypt` | Session absente sur le proxy | Refaire un HTTP `POST /vm/session/register` |
| Proxy n'apparaît pas dans `RegistryStatus` | Échec de synchro entre Proxy et Central au démarrage | Vérifier `agent_central_grpc` dans `proxy_config.json` et les certificats locaux de la VM. |
| `CRYPTO_ERROR` au déchiffrement | Données altérées ou clé `old_key` expirée (grâce > 60s) | Vérifier le payload JSON ou forcer une rotation |

---

*Documentation générée pour ENSPY SMA 2025-2026 — Architecture Distribuée mTLS gRPC v1.2.0*

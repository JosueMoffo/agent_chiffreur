# Guide des endpoints — Agent Chiffreur & Proxy ENSPY

Ce guide récapitule l'ensemble des requêtes HTTP pour l'**agent central** (port **5004**) et les **proxies VM** (port **8400**).

> **Important** : L'agent central (5004) ne gère **aucune opération de chiffrement**. Toute requête `/encrypt`, `/decrypt`, ou session ECDH doit être adressée au **proxy** de la VM concernée (8400).

**Authentification (`X-Agent-Token`) :**
Pour les requêtes le demandant, l'en-tête `X-Agent-Token` est un *pass-through* (toute valeur est acceptée dans l'implémentation actuelle, bien qu'il soit recommandé d'utiliser celle de la configuration).

**Autorisation (`X-Agent-Name`) :**
Seul l'agent défini par `agent_rotation_autorise` (défaut : `agent-decideur`) peut déclencher la rotation globale sur l'agent central via l'en-tête `X-Agent-Name: agent-decideur`.

---

## 🏛️ 1. Agent Central (Port 5004)

### GET `/health`
Vérifie que l'agent central est en ligne (uptime, version, nb de sessions).
```bash
curl -s http://localhost:5004/health
```

### GET `/metrics`
Métriques d'exécution de l'agent central (requêtes, erreurs).
```bash
curl -s http://localhost:5004/metrics
```

### GET `/registry/status`
Affiche le registre central de tous les proxies et VMs connus.
```bash
curl -s http://localhost:5004/registry/status
```

### POST `/registry/proxy/announce`
Utilisé par les proxies pour s'annoncer au démarrage.
```bash
curl -s -X POST http://localhost:5004/registry/proxy/announce \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 101, "proxy_url": "http://127.0.0.1:8400", "public_key": "..."}'
```

### POST `/credential/rotate`
**Ordre global de rotation.** L'agent central le propage à tous les proxies.
```bash
curl -s -X POST http://localhost:5004/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: agent-decideur" \
  -d '{"request_id": "rot-001"}'
```

---

## 🔐 2. Proxy Chiffreur Local (Port 8400)

Les requêtes suivantes s'exécutent **sur la VM**, auprès du proxy local. Convention : `vm_id` > 100.

### GET `/health`
Vérifie la santé du proxy.
```bash
curl -s http://localhost:8400/health
```

### GET `/public-key`
Clé publique X25519 statique du proxy.
```bash
curl -s http://localhost:8400/public-key
```

### POST `/vm/session/register`
Enregistre la VM locale. Génère une paire éphémère X25519 et la clé AES `new_key`.
```bash
curl -s -X POST http://localhost:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 101,
    "public_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
    "url_notification": "http://127.0.0.1:19001/key-update"
  }'
```

### GET `/vm/sessions`
Liste les sessions VM actives gérées par ce proxy (aperçus).
```bash
curl -s http://localhost:8400/vm/sessions
```

### POST `/encrypt`
Chiffre un message avec la `new_key` AES-256-GCM.
```bash
curl -s -X POST http://localhost:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 101,
    "plaintext": "Message confidentiel"
  }'
```

### POST `/decrypt`
Déchiffre un message (tente `new_key`, puis `old_key` en période de grâce).
```bash
curl -s -X POST http://localhost:8400/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 101,
    "ciphertext": "...",
    "iv": "...",
    "auth_tag": "..."
  }'
```

### POST `/vm/sessions/purge-expired`
Purge les anciennes clés dont le délai de grâce est expiré.
```bash
curl -s -X POST http://localhost:8400/vm/sessions/purge-expired \
  -H "Content-Type: application/json" \
  -d '{}'
```

### POST `/vm/session/delete`
Supprime une session VM locale.
```bash
curl -s -X POST http://localhost:8400/vm/session/delete \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 101}'
```

---

## 🛠️ 3. Outils Cryptographiques (Proxy Port 8400)

### POST `/ecdh/initiate`
Initie un échange ECDH générique. Génère une paire éphémère à chaque appel.
```bash
curl -s -X POST http://localhost:8400/ecdh/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "peer_agent_id": "vm-client",
    "peer_public_key_hex": "b2c4d6e8f0..."
  }'
```

### POST `/secret/strength`
Évalue la force d'un secret selon le barème ENSPY (/100).
```bash
curl -s -X POST http://localhost:8400/secret/strength \
  -H "Content-Type: application/json" \
  -d '{"secret": "Tr0ub4dor&3_ENSPY!2026#"}'
```

### POST `/password/generate`
Génère un mot de passe fort aléatoire.
```bash
curl -s -X POST http://localhost:8400/password/generate \
  -H "Content-Type: application/json" \
  -d '{
    "longueur": 24,
    "majuscules": true,
    "minuscules": true,
    "chiffres": true,
    "symboles": true,
    "exclure_ambigus": false
  }'
```

---

## 🔄 4. Relais Inter-VM (Proxy Port 8400)

### POST `/proxy/relay`
Demande au proxy de chiffrer et relayer un message vers une autre VM.
```bash
curl -s -X POST http://localhost:8400/proxy/relay \
  -H "Content-Type: application/json" \
  -d '{
    "dest_vm_id": 102,
    "request": { "hello": "world" }
  }'
```

### GET `/proxy/sessions`
Liste les sessions P2P établies avec d'autres proxies du cluster.
```bash
curl -s http://localhost:8400/proxy/sessions
```

---

## ⚠️ 5. Codes d'erreur HTTP courants

| Code HTTP | `error` | Contexte |
|-----------|---------|----------|
| 400 | `INVALID_REQUEST` | Champ manquant ou invalide |
| 400 | `CRYPTO_ERROR` | Échec de l'intégrité GCM (falsification détectée) |
| 403 | `FORBIDDEN` | `X-Agent-Name` incorrect sur `/credential/rotate` de l'agent central |
| 404 | `VM_NOT_FOUND` | `vm_id` inconnu dans la session |
| 500 | `CRYPTO_ERROR` / `STORE_ERROR` | Erreur interne de chiffrement ou I/O disque |

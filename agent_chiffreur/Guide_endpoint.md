# Guide des Interfaces — Agent Chiffreur & Proxy ENSPY

Ce guide récapitule l'ensemble des interfaces de communication pour l'**agent central** (gRPC port **5004**) et les **proxies VM** (HTTP port **8400** / gRPC port **18400**).

> **Important** : L'agent central (5004) ne gère **aucune opération de chiffrement**. Toute logique cryptographique locale (ex. `POST /encrypt`) se fait en HTTP sur le **proxy** de la VM concernée (8400).

---

## 🏛️ 1. Agent Central (gRPC mTLS, Port 5004)

Toutes les communications vers l'agent central utilisent le protocole **gRPC** sur le service `gandal.v1.ChiffreurService`.
L'authentification est stricte et se fait par **mTLS** avec vérification du certificat client (Common Name - CN).

### `rpc Health(Empty) returns (HealthResponse)`
Vérifie que l'agent central est en ligne. *Aucune restriction stricte sur le CN.*

### `rpc RegistryStatus(Empty) returns (RegistryStatusResponse)`
Affiche le compte des proxies et VMs actuellement enregistrés dans le registre central.

### `rpc AnnounceProxy(ProxyAnnounceRequest) returns (ProxyAnnounceResponse)`
Utilisé par les proxies pour s'annoncer au démarrage.
**Sécurité** : Exige un certificat client avec **`CN=proxy`**.

### `rpc SyncVm(VmSyncRequest) returns (VmSyncResponse)`
Synchronise les informations d'une VM spécifique avec le registre.
**Sécurité** : Exige un certificat client avec **`CN=proxy`**.

### `rpc RotateCredentials(RotateRequest) returns (RotateResponse)`
**Ordre global de rotation.** L'agent central propage ensuite cet ordre à tous les proxies via gRPC.
**Sécurité** : Exige un certificat client avec **`CN=decideur`**. (Le Décideur est le seul habilité).

---

## 🔐 2. Proxy Chiffreur Local (HTTP Port 8400 / gRPC Port 18400)

Le proxy dispose de deux interfaces :
- **gRPC (Port 18400)** : Pour recevoir les ordres du datacenter (Agent central).
- **HTTP (Port 8400)** : Pour servir les applications de la VM locale. Convention : `vm_id` > 100.

### Interface gRPC (`gandal.v1.ProxyChiffreurService`, Port 18400)

- `rpc Health(Empty) returns (HealthResponse)` : Vérifie la santé gRPC du proxy.
- `rpc RotateCredentials(RotateRequest) returns (RotateResponse)` : Appelé par l'Agent Central pour forcer la rotation des clés des VMs hébergées par ce proxy.

### Interface HTTP Publique (Port 8400)

Les requêtes suivantes s'exécutent **en HTTP REST sur la VM**, auprès du proxy local.

#### GET `/health`
Vérifie la santé HTTP du proxy.
```bash
curl -s http://localhost:8400/health
```

#### GET `/public-key`
Clé publique X25519 statique du proxy.
```bash
curl -s http://localhost:8400/public-key
```

#### POST `/vm/session/register`
Enregistre la VM locale. Génère une paire éphémère X25519 et la clé AES `new_key`.
```bash
curl -s -X POST http://localhost:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 101,
    "public_key": "...",
    "url_notification": "http://127.0.0.1:19001/key-update"
  }'
```

#### GET `/vm/sessions`
Liste les sessions VM actives gérées par ce proxy.
```bash
curl -s http://localhost:8400/vm/sessions
```

#### POST `/encrypt`
Chiffre un message avec la `new_key` AES-256-GCM.
```bash
curl -s -X POST http://localhost:8400/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "vm_id": 101,
    "plaintext": "Message confidentiel"
  }'
```

#### POST `/decrypt`
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

---

## 🛠️ 3. Outils Cryptographiques (Proxy HTTP Port 8400)

#### POST `/ecdh/initiate`
Initie un échange ECDH générique (génère une paire éphémère à chaque appel).

#### POST `/secret/strength`
Évalue la force d'un secret selon le barème ENSPY (/100).

#### POST `/password/generate`
Génère un mot de passe fort aléatoire.

---

## 🔄 4. Relais Inter-VM (Proxy HTTP Port 8400)

#### POST `/proxy/relay`
Demande au proxy local d'encapsuler et relayer un message vers une autre VM distante (tunnel transparent).
```bash
curl -s -X POST http://localhost:8400/proxy/relay \
  -H "Content-Type: application/json" \
  -d '{
    "dest_vm_id": 102,
    "request": { "hello": "world" }
  }'
```

---

## ⚠️ 5. Erreurs gRPC et HTTP

| Code HTTP / gRPC Status | Contexte |
|-----------|----------|
| HTTP 400 | Champ manquant ou invalide (JSON) |
| HTTP 400 (`CRYPTO_ERROR`) | Échec de l'intégrité GCM (falsification détectée) |
| HTTP 404 | `vm_id` inconnu dans la session |
| gRPC `PermissionDenied` | Tentative d'appel RPC avec un certificat au CN non autorisé |
| gRPC `Unauthenticated` | Absence de certificat client mTLS valide |

# Agent Chiffreur — Racine de confiance cryptographique du SMA ENSPY

## Présentation

L'**Agent Chiffreur** est le processus **central** du SMA ENSPY (port **5004**) : registre des proxies VM, propagation de rotation, interface avec le **Décideur**. Le chiffrement opérationnel est délégué au crate sibling **`proxy_chiffreur/`** (port **8400**, une instance par VM). Voir [Guide_proxy.md](Guide_proxy.md).

**Technologies utilisées :**
- **Rust** (édition 2021) — sécurité mémoire et performance
- **axum 0.7** + **Tokio** — serveur HTTP asynchrone
- **AES-256-GCM** (`aes-gcm`) — chiffrement authentifié
- **X25519 / Curve25519** (`x25519-dalek`) — échange de clé ECDH
- **Argon2id** (`argon2`) — hachage de secrets humains
- **reqwest 0.12** — client HTTP sortant (notifications inter-agents)
- **zeroize** — effacement sécurisé de la mémoire

---

## Architecture (deux modules)

```
Décideur ──► agent_chiffreur :5004  (registry, /credential/rotate, /decideur/forward)
                  ▲
                  │ announce / vm sync
proxy_chiffreur :8400  (encrypt, decrypt, /vm/session/register, /proxy/relay)
                  ▲
                  └── Application VM locale
```

| Crate | Port | Rôle |
|-------|------|------|
| `agent_chiffreur/` | 5004 | Central — registre proxies, rotation globale, Décideur |
| `../proxy_chiffreur/` | 8400 | Par VM — crypto locale, relais inter-VM |

---

## Prérequis

- **Rust ≥ 1.75** (édition 2021)
- Accès réseau pour télécharger les dépendances (build uniquement)
- Variables d'environnement optionnelles (voir tableau ci-dessous)

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `AGENT_PORT` | `5004` | Port HTTP agent central |
| `AGENT_TOKEN` | `ENSPY-TOKEN-2026` | Token d'auth inter-agents |
| `AGENT_AES_KEY_HEX` | *(éphémère)* | Clé AES-256 persistante (64 hex chars = 32 octets) |
| `AGENT_SUPERVISION_SEC` | `10` | Intervalle supervision entropie (secondes) |
| `AGENT_ENTROPIE_SEUIL` | `256` | Seuil critique pool entropie (octets) |
| `AGENT_AUDITEUR_URL` | *(absent)* | URL HTTP de l'agent auditeur |
| `AGENT_CONNUS` | *(absent)* | Autres agents : `"nom1=url1,nom2=url2"` |
| `AGENT_SESSION_FILE` | `data/session.json` | Base de données des clés VM |

---

## Compilation et démarrage

```bash
# Compilation optimisée
cargo build --release

# Démarrage du serveur (port 5004 par défaut)
./target/release/agent_chiffreur

# Avec clé AES persistante et agent auditeur configuré
AGENT_AES_KEY_HEX="a1b2c3...64chars..." \
AGENT_AUDITEUR_URL="http://localhost:8500/alert" \
./target/release/agent_chiffreur

# Simulation intégration HTTP (scénarios 0–L, endpoints réels, port 15004)
./target/release/simulation_tests
```

---

## API Reference

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/encrypt` | ✅ Token | Chiffrement AES-256-GCM avec `new_key` de la VM (`vm_id`) |
| `POST` | `/decrypt` | ✅ Token | Déchiffrement VM (`new_key`, puis `old_key` si grâce) |
| `POST` | `/credential/rotate` | ✅ Token | Rotation credentials |
| `POST` | `/ecdh/initiate` | ✅ Token | Échange clé ECDH X25519 |
| `POST` | `/password/generate` | ✅ Token | Génération mot de passe fort |
| `POST` | `/secret/strength` | ✅ Token | Évaluation force d'un secret |
| `POST` | `/vm/session/register` | ✅ Token | Enregistrer VM (vm_id > 100) |
| `POST` | `/vm/session/delete` | ✅ Token | Supprimer session VM |
| `GET` | `/vm/sessions` | ✅ Token | Lister sessions actives |
| `POST` | `/vm/sessions/purge-expired` | ✅ Token | Purger les old_key expirées |
| `POST` | `/credential/rotate` | `X-Agent-Name` | Rotation ECDH toutes VMs |
| `GET` | `/public-key` | ❌ Public | Clé publique X25519 |
| `GET` | `/health` | ❌ Public | Statut + uptime |
| `GET` | `/metrics` | ❌ Public | Métriques runtime |

### Exemples curl

```bash
TOKEN="ENSPY-TOKEN-2026"

# POST /encrypt (clé AES = new_key de la VM 101)
curl -X POST http://localhost:5004/encrypt \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 101, "plaintext": "Message secret ENSPY 2026"}'

# POST /decrypt (new_key, ou old_key si période de grâce après rotation)
curl -X POST http://localhost:5004/decrypt \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vm_id": 101, "ciphertext": "...", "iv": "...", "auth_tag": "..."}'

# POST /credential/rotate
curl -X POST http://localhost:5004/credential/rotate \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# GET /public-key (sans token)
curl http://localhost:5004/public-key

# POST /ecdh/initiate
curl -X POST http://localhost:5004/ecdh/initiate \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"peer_agent_id": "Decideur", "peer_public_key_hex": "b2c4...64chars..."}'

# POST /password/generate
curl -X POST http://localhost:5004/password/generate \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "longueur": 24,
    "majuscules": true,
    "minuscules": true,
    "chiffres": true,
    "symboles": true,
    "exclure_ambigus": true
  }'

# GET /health (sans token)
curl http://localhost:5004/health

# GET /metrics (sans token)
curl http://localhost:5004/metrics
```

---

## Flux d'intégration inter-agents

Un agent qui veut communiquer de façon sécurisée avec l'Agent Chiffreur suit ce flux :

### 1. Récupérer la clé publique

```bash
GET /public-key
# Réponse : { "public_key_hex": "a3f8...64 chars...", "algorithm": "X25519" }
```

### 2. Initier un échange ECDH

```bash
POST /ecdh/initiate
X-Agent-Token: ENSPY-TOKEN-2026
{ "peer_agent_id": "Decideur", "peer_public_key_hex": "<votre_clé_publique_hex>" }
# Réponse : { "shared_secret_hex": "f1e2...64 chars..." }
```

### 3. Utiliser le secret partagé pour chiffrer

Le `shared_secret_hex` (32 octets) peut être utilisé directement comme clé AES-256 ou comme entrée HKDF pour dériver des sous-clés.

```bash
POST /encrypt
X-Agent-Token: ENSPY-TOKEN-2026
{ "plaintext": "Données confidentielles..." }
# Réponse : { "ciphertext": "...", "iv": "...", "auth_tag": "..." }
```

### 4. Header `X-Agent-Token` (optionnel)

Les endpoints POST acceptent le header `X-Agent-Token` s'il est présent, mais **ne le vérifient pas** : toute valeur est acceptée, y compris l'absence du header.

---

## Sécurité

### Mode clé éphémère vs persistante

- **Éphémère (défaut)** : une nouvelle clé AES-256 est générée à chaque démarrage. Les données chiffrées lors d'une session précédente ne peuvent plus être déchiffrées après un redémarrage.
- **Persistante** (`AGENT_AES_KEY_HEX`) : la clé est réutilisée entre les redémarrages. Permet la continuité du service mais nécessite une gestion sécurisée de la variable d'environnement.

### Politique de logs

- Le `shared_secret_hex` ECDH n'est **jamais loggué** (commentaire `// SECURITY: ne pas logguer`)
- Le token `X-Agent-Token` n'est **jamais loggué**
- Les plaintexts ne sont **jamais loggués**
- Les clés privées ne sont **jamais loggués**

### Recommandations de production

- Changer `AGENT_TOKEN` depuis la valeur par défaut `ENSPY-TOKEN-2026`
- Utiliser TLS (terminaison nginx/Caddy devant le port 5004)
- Définir `AGENT_AES_KEY_HEX` uniquement via des secrets manager (Vault, K8s secrets)
- Effectuer une rotation régulière du token inter-agents

---

## Tests

```bash
# Tests unitaires Rust
cargo test

# Simulation complète avec affichage coloré (7 scénarios)
cargo run --bin simulation_tests
```

### Scénarios de simulation

| Scénario | Opération | Entrée | Résultat attendu |
|---|---|---|---|
| **0** | Sans token | n/a | HTTP 200 — token optionnel (toute valeur acceptée) |
| **A** | TEST_STRENGTH | secret faible `"abc"` | score=0, alerte MEDIUM à l'auditeur |
| **B** | TEST_STRENGTH | secret fort `"Tr0ub4dor&3_ENSPY!2026#"` | score ≥ 60, aucune alerte |
| **C** | ENCRYPT_DATA | texte long (237 chars) | `ciphertext` + `iv` + `auth_tag` Base64 |
| **D** | DECRYPT_DATA | résultat scénario C | texte original récupéré à l'identique |
| **E** | ECDH_REQUEST | clé publique pair fictif | secrets ECDH identiques côté agent et pair |
| **F1** | PASSWORD_GENERATE | longueur=16, tous groupes | mot de passe 16 chars, 4 classes |
| **F2** | PASSWORD_GENERATE | longueur=32, exclure_ambigus | aucun caractère `0 O l 1 I \|` |
| **F3** | PASSWORD_GENERATE | longueur=8, sans symboles | aucun symbole ASCII |
| **G** | DECRYPT_DATA falsifié | ciphertext modifié d'1 octet | `CRYPTO_ERROR` — falsification détectée |

---

## Structure du projet

```
agent_chiffreur/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs              # Point d'entrée, serveur axum, tâches async
    ├── agent_http.rs        # Handlers HTTP + middleware token
    ├── config.rs            # Configuration depuis variables d'env
    ├── crypto_moteur.rs     # AES-256-GCM, X25519, Argon2id, génération MDP
    ├── error.rs             # Types d'erreurs structurées
    ├── models.rs            # Structs requêtes/réponses JSON
    ├── notificateur.rs      # Client HTTP sortant (reqwest)
    ├── xmpp_sim.rs          # Simulation XMPP in-memory (canaux Tokio)
    └── simulation_tests.rs  # Binaire de simulation (9 scénarios)
```

---

## Base `data/session.json`

Chaque VM connectée (VMID entier **> 100**, style Proxmox) possède :

- `public_key` — clé publique X25519 (hex 64 chars)
- `new_key` — clé AES-256 active
- `old_key` — ancienne clé (pendant le timer de grâce, puis `null`)

Le fichier est mis à jour à chaque `POST /vm/session/register` et `POST /credential/rotate`.

---

*ENSPY SMA 2025-2026 — Agent Chiffreur v1.2.0*

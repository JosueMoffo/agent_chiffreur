# Guide d'intégration — Secrets, Rotation et Tests
## Agent Chiffreur ENSPY SMA 2025-2026

---

## Table des matières

1. [Gestion des secrets via `.env`](#1-gestion-des-secrets-via-env)
2. [Script d'initialisation `init_secrets.sh`](#2-script-dinitialisation)
3. [Versionnage des secrets et rotation](#3-versionnage-des-secrets-et-rotation)
4. [Format des données chiffrées (en-tête versionné)](#4-format-des-données-chiffrées)
5. [Déclenchement de la rotation — endpoint `/credential/rotate`](#5-endpoint-credentialrotate)
6. [Rotation automatique toutes les 5 minutes](#6-rotation-automatique)
7. [Migration des données historiques](#7-migration-des-données-historiques)
8. [Tests avec le fichier mock](#8-tests-avec-le-fichier-mock)

---

## 1. Gestion des secrets via `.env`

### Principe

Tous les secrets de l'agent sont centralisés dans un unique fichier `.env` à la racine du projet. Ce fichier **ne doit jamais être commité dans git** — seul `.env.example` (sans valeurs sensibles) est versionné.

### Structure du fichier `.env`

```bash
# Secrets d'authentification
AGENT_TOKEN=<64 hex chars générés par init_secrets.sh>
AGENT_AES_KEY_HEX=<64 hex chars générés par init_secrets.sh>

# Rotation des clés
AGENT_ROTATION_SEC=300            # 5 minutes — modifiable sans recompilation
AGENT_ROTATION_AUTORISE=Decideur # seul cet agent peut appeler /credential/rotate

# Serveur
AGENT_PORT=5004
AGENT_SUPERVISION_SEC=10
AGENT_ENTROPIE_SEUIL=256
AGENT_SESSION_STORE=data/session_store.json
```

### Permissions Unix appliquées

| `.env` | `600` | Lecture/écriture propriétaire uniquement |
| `data/` | `700` | Accès propriétaire uniquement |

Rust charge `.env` via `dotenvy::dotenv()` **avant** toute lecture de config, avec priorité aux variables système si elles existent déjà (utile pour les overrides en CI/CD).

---

## 2. Script d'initialisation

### Utilisation

```bash
# Première initialisation (crée .env depuis .env.example, génère les secrets)
bash scripts/init_secrets.sh

# Forcer la régénération des secrets (rotation manuelle du token et de la clé)
bash scripts/init_secrets.sh --force
```

### Ce que fait le script

```
Étape 1 : Copie .env.example → .env si absent
Étape 2 : chmod 600 .env
Étape 3 : Génère AGENT_TOKEN aléatoire (openssl rand -hex 32) si par défaut
Étape 4 : Génère AGENT_AES_KEY_HEX aléatoire si absente
Étape 5 : mkdir -p data/ && chmod 700 data/
Étape 6 : Vérifie .gitignore — ajoute .env s'il est absent
```

### Vérification manuelle après initialisation

```bash
# Vérifier les permissions
stat .env
# Attendu : 600 — -rw-------

stat data/
# Attendu : 700 — drwx------

# Vérifier que .env n'est pas traqué par git
git ls-files .env
# Attendu : aucune sortie (fichier non traqué)
```

---

## 3. Versionnage des secrets et rotation

### Concept de version de clé

Chaque clé AES-256 porte un **identifiant unique** (`key_id`) et un **numéro de version** incrémental :

```
Version 1 : key_id = k_a3f8b2c1  (clé initiale)
Version 2 : key_id = k_d4e5f6a7  (après 1ère rotation)
Version 3 : key_id = k_b8c9d0e1  (après 2ème rotation)
```

Le `key_id` est dérivé des premiers octets de la clé (format `k_<hex4>`), ce qui garantit son unicité sans jamais exposer le matériel de clé.

### Trousseau de clés (`Trousseau`)

```
┌─────────────────────────────────────────────────┐
│  TROUSSEAU                                      │
│                                                 │
│  active   → EntreeCle { key_id: k_d4e5, v:3 }  │  ← chiffrement
│                                                 │
│  archivees:                                     │
│    k_a3f8 → EntreeCle { v:1 }                  │  ← déchiffrement historique
│    k_b8c9 → EntreeCle { v:2 }                  │  ← déchiffrement historique
└─────────────────────────────────────────────────┘
```

Le trousseau conserve jusqu'à **10 clés archivées** (constante `MAX_CLES_ARCHIVEES`). Les plus anciennes sont expurgées automatiquement quand la limite est atteinte.

---

## 4. Format des données chiffrées

### Structure d'un `BlobVersionne`

Chaque donnée chiffrée est un `BlobVersionne` contenant :

```json
{
  "entete": "{\"key_id\":\"k_d4e5f6a7\",\"version\":3,\"created_at\":\"2026-05-30T12:00:00Z\",\"algo\":\"AES-256-GCM\"}",
  "ciphertext": "<base64 URL-safe>",
  "iv":         "<base64 URL-safe, 12 octets>",
  "auth_tag":   "<base64 URL-safe, 16 octets>",
  "key_id":     "k_d4e5f6a7",
  "version":    3
}
```

### Rôle de l'en-tête

Le champ `entete` est un JSON sérialisé embarqué dans le blob. Il permet à n'importe quel agent de savoir **avec quelle version de clé déchiffrer** sans avoir à essayer toutes les clés. Le `key_id` est aussi dupliqué au niveau racine du blob pour un routing rapide sans parsing de l'en-tête.

### Flux de déchiffrement avec routing par `key_id`

```
Requête POST /decrypt
  → extraire blob.key_id
  → si key_id == trousseau.active.key_id → déchiffrer avec clé active
  → sinon → chercher dans trousseau.archivees[key_id] → déchiffrer avec clé archivée
  → si key_id introuvable → retourner CleHexInvalide
```

### Exemple de requête `/decrypt`

```bash
curl -X POST http://localhost:5004/decrypt \
  -H "X-Agent-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "k_d4e5f6a7",
    "version": 3,
    "entete": "{\"key_id\":\"k_d4e5f6a7\",\"version\":3,...}",
    "ciphertext": "...",
    "iv": "...",
    "auth_tag": "..."
  }'
```

---

## 5. Endpoint `/credential/rotate`

### Mécanisme d'authentification

L'endpoint `POST /credential/rotate` **ne nécessite pas** le token standard `X-Agent-Token`. Il utilise à la place un contrôle d'identité par nom d'agent via le header `X-Agent-Name`.

**Seul l'agent dont le nom correspond à `AGENT_ROTATION_AUTORISE`** (défaut: `"Decideur"`) peut déclencher la rotation.

### Pourquoi ce choix de design ?

- Le token standard est partagé par tous les agents → n'importe quel agent pourrait déclencher une rotation.
- Le nom d'agent est un identifiant fonctionnel : seul l'agent Decideur, qui a une vue d'ensemble du SMA, est légitime pour déclencher la rotation des clés.
- Ce mécanisme évite de créer un "super-token" séparé qui serait un secret supplémentaire à gérer.

### Appel depuis l'agent Decideur

```bash
# Rotation avec génération automatique d'une nouvelle clé aléatoire
curl -X POST http://localhost:5004/credential/rotate \
  -H "X-Agent-Name: Decideur" \
  -H "Content-Type: application/json" \
  -d '{"request_id": "rot-001"}'

# Rotation avec une clé spécifique (pour tests ou restauration)
curl -X POST http://localhost:5004/credential/rotate \
  -H "X-Agent-Name: Decideur" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "rot-002",
    "nouvelle_cle_hex": "a1b2c3d4e5f6...64chars"
  }'
```

### Réponse de rotation

```json
{
  "request_id": "rot-001",
  "message_type": "credential_rotate_response",
  "status": "success",
  "ancien_key_id": "k_a3f8b2c1",
  "nouveau_key_id": "k_d4e5f6a7",
  "blobs_migres": 12,
  "blobs_echecs": 0,
  "blobs_total": 12,
  "timestamp": "2026-05-30T12:05:00Z"
}
```

### Réponse en cas d'agent non autorisé

```json
{
  "error": "FORBIDDEN",
  "description": "Seul l'agent 'Decideur' est autorisé à déclencher la rotation."
}
```

---

## 6. Rotation automatique

### Configuration

L'intervalle de rotation automatique est défini dans `.env` :
```bash
AGENT_ROTATION_SEC=300   # 5 minutes (valeur de production)
```

Cette valeur est intentionnellement stockée dans le fichier de configuration et non codée en dur dans le binaire, afin de pouvoir l'ajuster sans recompilation.

### Fonctionnement

Au démarrage de l'agent, une tâche Tokio asynchrone est lancée :

```
Tâche tache_rotation_automatique
  ├─ tick() ignoré (premier tick immédiat sauté)
  ├─ attente 300s
  ├─ gestionnaire.effectuer_rotation(None)  ← clé aléatoire générée
  ├─ log : "Rotation auto : k_xxx → k_yyy | 12 blobs migrés"
  └─ répéter ...
```

### Interaction entre rotation manuelle et automatique

La rotation manuelle (via `POST /credential/rotate`) et la rotation automatique utilisent le **même `GestionnaireRotation`** partagé via `Arc`. Les deux opèrent sur le même `RwLock<Trousseau>`, garantissant la thread-safety :

- Une rotation manuelle réinitialise le compteur d'intervalle de la tâche automatique (le prochain tick se produira 5 minutes après la rotation manuelle).
- Une rotation automatique pendant un chiffrement attend que le `RwLock` soit libéré.

### Statut en temps réel

```bash
# Voir la version de clé active et les clés archivées
curl http://localhost:5004/keystore/status
# ou
curl http://localhost:5004/health  # inclut key_id_actif et version_cle
```

---

## 7. Migration des données historiques

### Séquence complète d'une rotation

```
1. Lire les blobs du store (data/session_store.json)
2. Appeler trousseau.tourner(nouvelle_cle_hex)
   → l'ancienne clé active est archivée
   → la nouvelle clé devient active
3. Pour chaque blob dans le store :
   a. Si blob.key_id == nouvelle_clé_active → skip (migre=false)
   b. Sinon :
      i.  Déchiffrer avec la clé archivée correspondante
      ii. Re-chiffrer immédiatement avec la nouvelle clé active
      iii. Remplacer le blob dans le store
4. Sauvegarder le store mis à jour
5. Retourner le RapportRotation
```

### Propriétés de sécurité de la migration

- **Atomicité partielle** : si une migration échoue sur un blob, les autres continuent. Le rapport indique `blobs_echecs > 0`.
- **Pas de fenêtre d'exposition** : le déchiffrement et le re-chiffrement se font en mémoire, sans écriture intermédiaire de plaintext sur disque.
- **Zéroïsation** : les matériaux de clé sont zéroïsés à la destruction (`ZeroizeOnDrop`).
- **Conservation des anciennes clés** : les clés archivées restent en mémoire jusqu'à l'expurgation (après `MAX_CLES_ARCHIVEES = 10` rotations). Cela permet de déchiffrer des blobs reçus avec délai.

### Vérifier l'état du store après rotation

```bash
cat data/session_store.json | python3 -m json.tool | head -30
# Tous les blobs doivent avoir le même key_id (celui de la clé active)
```

---

## 8. Tests avec le fichier mock

### Fichier `tests/mock_blobs.json`

Ce fichier JSON statique définit des données fixes pour les tests de simulation :

```
tests/mock_blobs.json
  ├─ trousseau_initial      → définition de la clé v1 de test
  ├─ scenarios_rotation     → 3 plaintexts fixes à chiffrer/migrer
  │   ├─ mock_rot_001       → blob court, attendu migré
  │   ├─ mock_rot_002       → blob long (données SMA réelles), attendu migré
  │   └─ mock_rot_003       → blob "déjà actif", attendu non migré (migre=false)
  ├─ scenarios_acces        → 3 cas de contrôle d'accès à la rotation
  │   ├─ mock_acc_001       → agent "Decideur" → HTTP 200
  │   ├─ mock_acc_002       → agent "intrus" → HTTP 403 FORBIDDEN
  │   └─ mock_acc_003       → header absent → HTTP 403 FORBIDDEN
  ├─ assertions_versionnage → 5 règles de cohérence à vérifier
  └─ config_test            → constantes de test (intervalle=1s, agent autorisé)
```

### Lancer la simulation

```bash
# Compilation puis simulation complète
cargo build --release
./target/release/simulation_tests

# Ou directement avec cargo
cargo run --bin simulation_tests
```

### Scénarios couverts

| Scénario | Description | Données mock |
|---|---|---|
| `0` | Accès sans token | — |
| `A` | Force secrète faible `"abc"` | — |
| `B` | Force secrète forte | — |
| `C` | Chiffrement avec en-tête versionné | — |
| `D` | Déchiffrement roundtrip | résultat de C |
| `E` | ECDH X25519 complet | — |
| `F` | Génération mot de passe (3 variantes) | — |
| `G` | Intégrité GCM (falsification) | — |
| `H` | **Rotation par agent autorisé** | `mock_acc_001` |
| `I` | **Rotation refusée** (agents non autorisés) | `mock_acc_002`, `mock_acc_003` |
| `J` | **Versionnage + migration complète** | `mock_rot_001..003`, `assertions_versionnage` |
| `K` | **Rotation automatique** (1s × 2 cycles) | `config_test.intervalle_rotation_sec_test` |

### Modifier les données de test

Pour ajouter un scénario de rotation, éditer `tests/mock_blobs.json` :

```json
{
  "scenarios_rotation": [
    {
      "id": "mock_rot_004",
      "description": "Mon nouveau scénario",
      "plaintext": "Données à chiffrer et migrer",
      "deja_actif": false
    }
  ]
}
```

La simulation lit ce fichier dynamiquement — pas besoin de recompiler.

---

## Checklist de déploiement

```
[ ] bash scripts/init_secrets.sh          → .env créé avec permissions 600
[ ] Vérifier : stat .env → 600            → permissions OK
[ ] Vérifier : git ls-files .env → vide   → .env non traqué
[ ] Vérifier : cat .env | grep AGENT_TOKEN ≠ ENSPY-TOKEN-2026
[ ] Vérifier : cat .env | grep AGENT_AES_KEY_HEX → 64 hex chars
[ ] cargo build --release                  → compilation OK
[ ] cargo run --bin simulation_tests       → tous les scénarios ✔
[ ] ./target/release/agent_chiffreur &    → agent démarré
[ ] curl http://localhost:5004/health      → {"status":"ok"}
[ ] curl http://localhost:5004/keystore/status → version_active: 1
[ ] Attendre 5 min → curl /keystore/status → version_active: 2 (rotation auto)
```

---

*ENSPY SMA 2025-2026 — Agent Chiffreur v1.1.0*

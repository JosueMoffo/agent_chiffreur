# Guide des endpoints — Agent Chiffreur ENSPY

Récapitulatif HTTP — **agent central** port **5004**, **proxy VM** port **8400** (exemples curl ci-dessous ; crypto VM → proxy).

**Agent central :** `http://localhost:5004` — **Proxy VM :** `http://localhost:8400`

**Token :** en-tête `X-Agent-Token` optionnel (toute valeur acceptée). Exemple ci-dessous : `ENSPY-TOKEN-2026` (valeur par défaut du code ; si vous utilisez `config/agent_config.json`, remplacez par la valeur du champ `agent_token`).

**Rotation :** `POST /credential/rotate` exige l’en-tête `X-Agent-Name: Decideur` (ou la valeur de `agent_rotation_autorise` dans la config).

---

## Démarrage rapide (production)

```bash
./install.sh
```

Initialise la configuration (`scripts/init_config.sh`), compile l’agent central et démarre sur `http://localhost:5004`. Sur chaque VM : `cd ../proxy_chiffreur && ./install.sh`.

Options : `./install.sh --help`

---

## 1. Surveillance (sans authentification)

### GET `/health`

Vérifie que l’agent est en ligne : uptime, version, nombre de VMs en session.

```bash
curl -s http://localhost:8400/health
```

### GET `/metrics`

Métriques runtime : requêtes traitées, erreurs, mémoire, CPU, VMs en session.

```bash
curl -s http://localhost:8400/metrics
```

### GET `/keystore/status`

Résumé du trousseau interne (legacy) et des sessions VM chargées depuis `data/session.json`.

```bash
curl -s http://localhost:8400/keystore/status
```

### GET `/public-key`

Clé publique X25519 **statique** de l’agent (legacy). Pour les sessions VM, préférer `agent_ephemeral_public_key_hex` renvoyé par l’enregistrement ou la rotation.

```bash
curl -s http://localhost:8400/public-key
```

---

## 2. Sessions VM (`data/session.json`)

Convention : `vm_id` entier **strictement supérieur à 100** (style Proxmox).

### POST `/vm/session/register`

Enregistre une VM : génère une paire X25519 **éphémère** côté agent, calcule le secret ECDH avec la clé publique VM, stocke `new_key` (AES-256) et `agent_public_key`.

```bash
curl -s -X POST http://localhost:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "vm_id": 101,
    "public_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
    "url_notification": "http://127.0.0.1:19001/key-update"
  }'
```

Champs optionnels : `url_notification` (POST de notification après rotation), `request_id`.

Réponse utile : `agent_ephemeral_public_key_hex`, `new_key_id`, `rotation_count`.

### GET `/vm/sessions`

Liste les sessions actives (aperçus de clés, pas les secrets complets).

```bash
curl -s http://localhost:8400/vm/sessions \
  -H "X-Agent-Token: ENSPY-TOKEN-2026"
```

### POST `/vm/session/delete`

Supprime une session VM du fichier `session.json`.

```bash
curl -s -X POST http://localhost:8400/vm/session/delete \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{"vm_id": 101}'
```

### POST `/vm/sessions/purge-expired`

Purge les `old_key` dont le timer de grâce (`old_key_grace_sec`) est expiré.

```bash
curl -s -X POST http://localhost:8400/vm/sessions/purge-expired \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{}'
```

---

## 3. Chiffrement applicatif (clés VM)

Les messages sont chiffrés en **AES-256-GCM** (Base64 URL-safe sans padding pour `ciphertext`, `iv`, `auth_tag`).

### POST `/encrypt`

Chiffre avec la **`new_key`** de la VM indiquée. La VM doit être enregistrée au préalable.

```bash
curl -s -X POST http://localhost:8400/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "vm_id": 101,
    "plaintext": "Message confidentiel ENSPY 2026"
  }'
```

Réponse : `ciphertext`, `iv`, `auth_tag`, `new_key_id`, `vm_id`.

### POST `/decrypt`

Déchiffre avec `new_key` ; en cas d’échec GCM, tente **`old_key`** si encore dans la période de grâce après une rotation.

Remplacez `CIPHERTEXT`, `IV` et `AUTH_TAG` par les valeurs renvoyées par `/encrypt` :

```bash
curl -s -X POST http://localhost:8400/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "vm_id": 101,
    "ciphertext": "CIPHERTEXT",
    "iv": "IV",
    "auth_tag": "AUTH_TAG"
  }'
```

Réponse : `plaintext`, `key_used` (`"new"` ou `"old"`), `vm_id`.

---

## 4. Rotation des clés VM (ECDH)

### POST `/credential/rotate`

Pour **chaque** VM enregistrée : nouvelle paire éphémère agent, nouveau ECDH, `old_key` ← ancienne `new_key`, notification HTTP optionnelle vers `url_notification`.

**Autorisation :** en-tête `X-Agent-Name` doit correspondre à `agent_rotation_autorise` (défaut : `Decideur`).

```bash
curl -s -X POST http://localhost:5004/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: Decideur" \
  -d '{"request_id": "rotation-manuelle-001"}'
```

Réponse : `rotation_id`, `vms_total`, `vms_reussies`, `vms_echecs`, `resultats[]` (par VM).

Exemple de corps envoyé à la VM (notification) : `agent_ephemeral_public_key_hex`, `new_key_hex`, `event: KEY_ROTATION`.

---

## 5. Outils cryptographiques

### POST `/ecdh/initiate`

Échange ECDH générique : nouvelle paire éphémère agent à chaque appel, secret partagé avec la clé publique du pair.

```bash
curl -s -X POST http://localhost:8400/ecdh/initiate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "peer_agent_id": "vm-client",
    "peer_public_key_hex": "b2c4d6e8f0a1234567890abcdef1234567890abcdef1234567890abcdef123456"
  }'
```

Réponse : `agent_ephemeral_public_key_hex`, `shared_secret_hex`.

### POST `/secret/strength`

Évalue la force d’un secret (barème ENSPY /100 : longueur, diversité, entropie).

```bash
curl -s -X POST http://localhost:8400/secret/strength \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{"secret": "Tr0ub4dor&3_ENSPY!2026#"}'
```

### POST `/password/generate`

Génère un mot de passe fort selon les options.

```bash
curl -s -X POST http://localhost:8400/password/generate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
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

## 6. Parcours de test recommandé

Enchaînement minimal pour valider le flux VM de bout en bout :

```bash
# 1. Santé
curl -s http://localhost:8400/health

# 2. Enregistrer la VM 101
curl -s -X POST http://localhost:8400/vm/session/register \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "vm_id": 101,
    "vm_pub_key_hex": "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
  }'

# 3. Chiffrer
curl -s -X POST http://localhost:8400/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{"vm_id": 101, "plaintext": "Test bout en bout"}'

# 4. Coller ciphertext / iv / auth_tag dans la commande decrypt suivante
curl -s -X POST http://localhost:8400/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{
    "vm_id": 101,
    "ciphertext": "CIPHERTEXT",
    "iv": "IV",
    "auth_tag": "AUTH_TAG"
  }'

# 5. Rotation (agent autorisé)
curl -s -X POST http://localhost:5004/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: Decideur" \
  -d '{}'

# 6. Lister les sessions
curl -s http://localhost:8400/vm/sessions \
  -H "X-Agent-Token: ENSPY-TOKEN-2026"
```

---

## 7. Fonctionnalités hors HTTP (tâches de fond)

| Fonctionnalité | Description |
|----------------|-------------|
| Rotation automatique | Toutes les `intervalle_rotation_sec` (config), si activée au démarrage |
| Purge automatique | Suppression périodique des `old_key` expirées |
| Supervision entropie | Alerte si le pool d’entropie simulé est sous le seuil |
| Dispatch XMPP simulé | Canal interne `mpsc` pour requêtes type message (hors REST) |
| Persistance | `data/session.json` (clés VM), `data/blobs_store.json` (trousseau legacy) |

---

## 8. Codes d’erreur HTTP courants

| Code HTTP | `error` | Contexte |
|-----------|---------|----------|
| 400 | `INVALID_REQUEST` | Champ manquant ou invalide |
| 400 | `CRYPTO_ERROR` | Échec GCM (intégrité) au déchiffrement |
| 403 | `FORBIDDEN` | `X-Agent-Name` incorrect sur `/credential/rotate` |
| 404 | `VM_NOT_FOUND` | `vm_id` absent de `session.json` |
| 404 | `NOT_FOUND` | Session à supprimer introuvable |
| 500 | `CRYPTO_ERROR` / `STORE_ERROR` | Erreur interne crypto ou écriture disque |

Format erreur :

```json
{
  "request_id": "...",
  "message_type": "error_response",
  "status": "error",
  "error": "CODE",
  "description": "Message lisible",
  "timestamp": "..."
}
```

---

## 9. Simulation intégrée

Pour exécuter tous les scénarios HTTP automatisés (serveur local dédié, hors production) :

```bash
./Simulation.sh
```

Équivalent manuel : `cargo build --release --bin simulation_tests && ./target/release/simulation_tests`

## 10. Proxy VM (trafic inter-VM)

Chaque VM exécute **`proxy_chiffreur`** (port **8400**). Crypto (`/encrypt`, `/vm/session/register`, …) : base `http://localhost:8400`. Rotation globale : `POST http://localhost:5004/credential/rotate`. Voir [Guide_proxy.md](Guide_proxy.md).

Voir aussi : [Guide_des_secrets.md](Guide_des_secrets.md), [README.md](README.md).

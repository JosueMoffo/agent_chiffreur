Il y a deux chemins distincts pour obtenir une clé AES dans votre agent. Le flux « VM / client » est celui que la simulation met en avant.

## 1. Deux familles de clés AES dans le projet

| Usage | Comment la clé est créée | Où elle vit |
|-------|--------------------------|-------------|
| `POST /encrypt` + `vm_id` | Chiffrement avec la **`new_key`** de la VM | `session.json` |
| `POST /decrypt` + `vm_id` | Déchiffrement avec **`new_key`**, puis **`old_key`** si timer de grâce actif | `session.json` |
| Trousseau interne (legacy) | 32 octets aléatoires au démarrage | RAM + `blobs_store.json` (hors `/encrypt` HTTP) |
| `POST /vm/session/register` (par VM) | ECDH X25519 avec **nouvelle paire éphémère agent** à chaque register/rotate | `session.json` → `agent_public_key`, `new_key` / `old_key` |

Ce qui suit décrit surtout le flux VM, puis le trousseau.

## 2. Création de la clé AES pour une VM (flux principal)

### Étape par étape

1. VM : génère paire X25519 (`priv_VM`, `pub_VM`)
2. `POST /vm/session/register` avec `public_key` (64 hex)
3. **Agent** : génère une **nouvelle paire X25519 éphémère** → `agent_ephemeral_public_key_hex`
4. ECDH(`priv_éphémère_agent`, `pub_VM`) → secret 32 octets → `new_key` (hex)
5. Persistance : `session.json` (`public_key`, `agent_public_key`, `new_key`)
6. VM : ECDH(`priv_VM`, `agent_ephemeral_public_key_hex`) → **même** secret 32 octets
7. Utilisation de ce secret comme clé AES-256-GCM

La clé privée éphémère de l’agent **n’est pas stockée** ; seule sa clé publique (`agent_public_key` dans `session.json`) permet à la VM de recalculer le secret.

### Côté agent (`handle_vm_register`, `rotation_vm`)

À chaque enregistrement ou rotation, l’agent appelle `ecdh_session_ephemere(&vm_pub_bytes)` :

- `StaticSecret::random_from_rng` → paire éphémère
- ECDH avec la clé publique VM enregistrée
- `new_key` = hex(secret 32 octets)
- Réponse HTTP : `agent_ephemeral_public_key_hex`

`POST /ecdh/initiate` suit le même mécanisme (une paire éphémère par appel).

### Clé statique `/public-key`

`GET /public-key` expose encore la clé publique **statique** du trousseau (legacy). Elle **ne sert plus** au flux VM : utiliser `agent_ephemeral_public_key_hex` renvoyé par register, rotate (notification) ou `/ecdh/initiate`.

## 3. Utilisation de la clé : chiffrement / déchiffrement

Une fois `new_key` connue des deux côtés :

- Clé : 32 octets (`new_key` décodée depuis hex)
- Nonce (IV) : 12 octets aléatoires par message
- AES-256-GCM : ciphertext + tag d’authentification (16 octets)

GCM apporte confidentialité et intégrité (scénario G de la simulation).

## 4. Rotation : cycle `new_key` / `old_key`

Lors de `POST /credential/rotate` :

1. **Nouvelle paire éphémère agent** + ECDH avec la `public_key` VM inchangée
2. Ancienne `new_key` → `old_key` (timer de grâce)
3. Nouveau secret ECDH → nouvelle `new_key`
4. `agent_public_key` mis à jour dans `session.json`
5. Notification HTTP (si URL) : `agent_ephemeral_public_key_hex` + `new_key_hex`

## 5. Chiffrement applicatif (`POST /encrypt` / `POST /decrypt`)

Corps minimal :

```json
{ "vm_id": 101, "plaintext": "..." }
{ "vm_id": 101, "ciphertext": "...", "iv": "...", "auth_tag": "..." }
```

- **Encrypt** : utilise toujours la `new_key` active de la VM.
- **Decrypt** : essaie `new_key` ; en cas d’échec GCM, essaie `old_key` si encore valide (`old_key_grace_sec`).
- Réponse decrypt : champ `key_used` = `"new"` ou `"old"`.

Le trousseau interne (`blobs_store.json`) reste pour d’autres usages legacy, pas pour ces endpoints HTTP.

## 6. Sécurité

| Mécanisme | Rôle |
|-----------|------|
| X25519 éphémère par session/rotation | Forward secrecy partielle : compromission future de la clé statique agent n’expose pas les secrets passés dérivés d’anciennes paires éphémères |
| ECDH | Secret partagé calculé localement ; pas d’envoi de la clé AES sur le réseau |
| AES-256-GCM | Confidentialité + intégrité |
| Clé privée VM / privée éphémère agent | Ne quittent pas leur hôte ; seules les clés publiques circulent |
| Pas de log des secrets | `new_key`, secrets ECDH non loggués |

Un attaquant passif voit les clés publiques (VM + éphémère agent) mais ne dérive pas le secret sans une clé privée correspondante.

## Résumé

La clé AES d’une VM est le résultat d’un ECDH avec une **paire X25519 éphémère générée à chaque** `POST /vm/session/register`, `POST /credential/rotate` et `POST /ecdh/initiate`. La VM utilise `agent_ephemeral_public_key_hex` (réponse HTTP ou `session.json`) pour retrouver le même `new_key`.

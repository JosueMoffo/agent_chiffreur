# Agent Chiffreur — Pair central du SMA ENSPY (port 5004)

## Présentation

L'**Agent Chiffreur** est le **pair central** du SMA ENSPY installé dans le conteneur du datacenter aux côtés des agents **Décideur** et **Auditeur** (port **5004**).

Son rôle se limite à **trois responsabilités** :
1. **Registre** — maintenir la liste de tous les proxies et VMs actifs du cluster
2. **Orchestration de rotation** — recevoir l'ordre du Décideur et le propager à chaque proxy
3. **Audit** — envoyer les événements de rotation à l'agent Auditeur

> ⚠️ **L'Agent Chiffreur ne fait aucun chiffrement/déchiffrement.**
> Toute la logique cryptographique est déléguée au crate sibling **`proxy_chiffreur/`** (port **8400**), une instance par VM du cluster. Voir [Guide_proxy.md](Guide_proxy.md).

**Technologies utilisées :**
- **Rust** (édition 2021) — sécurité mémoire et performance
- **axum 0.7** + **Tokio** — serveur HTTP asynchrone
- **reqwest 0.12** — client HTTP sortant (propagation rotation, notifications auditeur)
- **rustls / axum-server** — TLS/mTLS inter-agents
- **serde / serde_json** — sérialisation JSON des registres persistants

---

## Architecture du système

```
┌──────────────────────────── Conteneur Datacenter ────────────────────────────┐
│                                                                               │
│   [Agent Décideur]                                                            │
│        │  POST /credential/rotate                                             │
│        │  Header: X-Agent-Name: agent-decideur                               │
│        ▼                                                                      │
│   [Agent Chiffreur :5004]  ──── POST /log_event ────►  [Agent Auditeur]      │
│        │  (registre proxies + propagation)                                    │
│        │                                                                      │
└────────│──────────────────────────────────────────────────────────────────────┘
         │
         │  POST /credential/rotate  (pour chaque proxy enregistré)
         │
    ┌────┴────┐           ┌──────────────┐
    │         │           │              │
    ▼         ▼           ▼              ▼
[Proxy :8400] [Proxy :8400] ...   [Proxy :8400]
   VM 101       VM 102               VM 10N
(chiffre/déchiffre localement pour les VMs du cluster)
```

| Composant | Emplacement | Port | Rôle |
|---|---|---|---|
| `agent_chiffreur/` | Conteneur datacenter | **5004** | Registre, orchestration rotation, interface Décideur/Auditeur |
| `proxy_chiffreur/` | Chaque VM du cluster | **8400** | Tout le chiffrement/déchiffrement, sessions ECDH, relais inter-VM |

---

## Endpoints exposés par l'agent central (port 5004)

### Endpoints publics (sans authentification)

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | État de santé + nb proxies/VMs enregistrés + uptime |
| `GET` | `/metrics` | Compteurs de requêtes et erreurs |

### Endpoints protégés (token `X-Agent-Token`)

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/registry/proxy/announce` | Un proxy s'annonce avec son `vm_id` et son `proxy_url` |
| `POST` | `/registry/vm/sync` | Synchronise une VM dans le registre central |
| `GET` | `/registry/status` | Liste tous les proxies et VMs connus |
| `POST` | `/decideur/forward` | Relais générique vers l'agent Décideur |

### Endpoint de rotation (header `X-Agent-Name`)

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/credential/rotate` | `X-Agent-Name: agent-decideur` | Propage la rotation à **tous** les proxies enregistrés + audit vers l'Auditeur |

> **Important :** seul l'agent dont le nom correspond à `agent_rotation_autorise` dans la config (défaut : `"agent-decideur"`) peut déclencher une rotation. Toute autre valeur retourne HTTP 403.

---

## Ce que l'agent central NE fait PAS

Les endpoints suivants appartiennent **exclusivement au proxy** (port 8400) :

| Endpoint | Appartient à |
|---|---|
| `POST /encrypt` | Proxy :8400 |
| `POST /decrypt` | Proxy :8400 |
| `POST /vm/session/register` | Proxy :8400 |
| `POST /vm/session/delete` | Proxy :8400 |
| `GET /vm/sessions` | Proxy :8400 |
| `POST /credential/rotate` (local) | Proxy :8400 |
| `POST /ecdh/initiate` | Proxy :8400 |
| `POST /secret/strength` | Proxy :8400 |
| `POST /password/generate` | Proxy :8400 |
| `GET /public-key` | Proxy :8400 |
| `POST /proxy/relay` | Proxy :8400 |
| `POST /proxy/inbound` | Proxy :8400 |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `AGENT_PORT` | `5004` | Port HTTP de l'agent central |
| `AGENT_TOKEN` | `ENSPY-TOKEN-2026` | Token d'auth inter-agents |
| `AGENT_ROTATION_AUTORISE` | `agent-decideur` | Nom de l'agent autorisé à déclencher la rotation |
| `AGENT_SUPERVISION_SEC` | `10` | Intervalle surveillance entropie (secondes) |
| `AGENT_ENTROPIE_SEUIL` | `256` | Seuil critique pool entropie (octets) |
| `AGENT_AUDITEUR_URL` | *(absent)* | URL de l'agent Auditeur pour les alertes |
| `AGENT_SESSION_FILE` | `data/session.json` | Base de données des sessions VM |
| `AGENT_CA_CERT_PATH` | `certs/ca.crt` | Certificat CA pour mTLS |
| `AGENT_CERT_PATH` | `certs/agent-chiffreur.crt` | Certificat de l'agent |
| `AGENT_KEY_PATH` | `certs/agent-chiffreur.key` | Clé privée de l'agent |

> La map `agents_connus` (URLs des autres agents) est configurée uniquement via `config/agent_config.json` — il n'existe pas de variable d'environnement dédiée.

---

## Configuration (`config/agent_config.json`)

```json
{
  "agent_port": 5004,
  "agent_token": "ENSPY-TOKEN-2026",
  "agent_rotation_autorise": "agent-decideur",
  "intervalle_rotation_sec": 300,
  "old_key_grace_sec": 60,
  "intervalle_supervision_sec": 10,
  "seuil_entropie": 256,
  "chemin_session": "data/session.json",
  "chemin_registry": "data/central_registry.json",
  "agent_auditeur_url": "http://agent-auditeur:5005/log",
  "agents_connus": {
    "agent-decideur": "http://agent-decideur:5003"
  },
  "ca_cert_path": "certs/ca.crt",
  "agent_cert_path": "certs/agent-chiffreur.crt",
  "agent_key_path": "certs/agent-chiffreur.key"
}
```

Priorité de chargement (du plus fort au plus faible) :
1. Variables d'environnement du processus
2. Fichier `config/agent_config.json`
3. Valeurs par défaut compilées

---

## Compilation et démarrage

```bash
# Compilation optimisée
cargo build --release

# Démarrage (port 5004 par défaut)
./target/release/agent_chiffreur

# Avec TLS activé
AGENT_CERT_PATH="certs/agent-chiffreur.crt" \
AGENT_KEY_PATH="certs/agent-chiffreur.key" \
AGENT_AUDITEUR_URL="http://agent-auditeur:5005/log" \
./target/release/agent_chiffreur

# Simulation intégrée (tests HTTP locaux sur ports 15004/18400)
./target/release/simulation_tests
```

---

## Flux de rotation complet

Lorsque le Décideur envoie `POST /credential/rotate` :

```
1. Décideur  ──► POST /credential/rotate
                 Header: X-Agent-Name: agent-decideur
                 Body:   { "request_id": "rot-001" }
                                │
2. Agent vérifie X-Agent-Name == agent_rotation_autorise
                                │
3. Pour chaque proxy dans central_registry.json :
   Agent ──► POST {proxy_url}/credential/rotate
             Body: { "request_id": "rot-001", "initiateur": "agent_central" }
                                │
4. Chaque proxy effectue la rotation ECDH localement
   pour toutes ses VMs (new_key ↔ old_key)
                                │
5. Agent ──► POST {agent_auditeur_url}
             Body: { "event_type": "CREDENTIAL_ROTATION_SUMMARY", ... }

6. Agent répond au Décideur :
   { "proxies_total": N, "proxies_reussis": N, "resultats": [...] }
```

---

## Tâches de fond

| Tâche | Description | Intervalle |
|---|---|---|
| Supervision entropie | Lit `/proc/sys/kernel/random/entropy_avail`, alerte l'Auditeur si < seuil | `intervalle_supervision_sec` (défaut 10s) |
| Purge clés expirées | Supprime les `old_key` dont le timer de grâce est dépassé | Gérée par le proxy, pas l'agent central |

---

## Persistance

| Fichier | Contenu |
|---|---|
| `data/central_registry.json` | Liste des proxies enregistrés (`vm_id`, `proxy_url`, `public_key_preview`) |
| `data/session.json` | Sessions VM (clés AES `new_key`/`old_key`) — partagé avec les proxies |
| `config/agent_config.json` | Configuration de l'agent central |
| `certs/` | Certificats TLS/mTLS (CA, agent-chiffreur, proxy, décideur, auditeur) |

---

## Structure du code source

```
agent_chiffreur/src/
├── main.rs                  # Point d'entrée, choix HTTP/HTTPS, graceful shutdown
├── app.rs                   # Routeur Axum de production (6 routes centrales)
├── central_http.rs          # Handlers HTTP de l'agent central (production)
├── central_registry.rs      # Registre JSON des proxies/VMs
├── config.rs                # Chargement config JSON + surcharges env
├── supervision.rs           # Tâche fond : surveillance entropie + audit
├── notificateur.rs          # Client HTTP sortant (alertes auditeur)
├── tls_utils.rs             # Configuration mTLS (rustls)
├── sessions_vm.rs           # Base sessions VM (data/session.json)
├── models.rs                # Structs requêtes/réponses JSON
├── error.rs                 # Types d'erreurs structurées
├── crypto_moteur.rs         # Moteur crypto (partagé avec proxy — AES-GCM, X25519, Argon2id)
│
│   ── Modules legacy / simulation (non utilisés en production centrale) ──
├── agent_http.rs            # Anciens handlers monolithiques (utilisés par simulation_tests)
├── gestionnaire_rotation.rs # Trousseau legacy
├── rotation_vm.rs           # Rotation locale (utilisée par simulation_tests)
├── trousseau.rs             # Trousseau de clés versionné (legacy)
├── sim_export.rs            # Export JSON pour simulation
├── simulation_tests.rs      # Binaire de tests d'intégration (port 15004/18400)
└── xmpp_sim.rs              # Canal interne mpsc pour simulation
```

---

## Codes d'erreur API

| HTTP | `error` | Contexte |
|---|---|---|
| `400` | `INVALID_REQUEST` | Champ manquant ou invalide (`vm_id`, `proxy_url`) |
| `403` | `FORBIDDEN` | `X-Agent-Name` ne correspond pas à `agent_rotation_autorise` |
| `500` | `STORE_ERROR` | Erreur écriture `central_registry.json` |
| `502` | `FORWARD_ERROR` | Échec relais vers le Décideur |
| `503` | `DECIDEUR_UNAVAILABLE` | URL Décideur absente de `agents_connus` |

---

## Exemples curl (agent central :5004)

```bash
# Health check
curl -s http://localhost:5004/health | jq .

# Statut du registre (proxies + VMs connus)
curl -s http://localhost:5004/registry/status | jq .

# Annonce d'un proxy
curl -s -X POST http://localhost:5004/registry/proxy/announce \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ENSPY-TOKEN-2026" \
  -d '{"vm_id": 101, "proxy_url": "http://192.168.1.50:8400", "public_key": "a1b2..."}'

# Rotation globale déclenchée par le Décideur
curl -s -X POST http://localhost:5004/credential/rotate \
  -H "Content-Type: application/json" \
  -H "X-Agent-Name: agent-decideur" \
  -d '{"request_id": "rot-manuel-001"}'
```

---

## Installation (.deb)

```bash
# Sur le serveur datacenter (conteneur)
sudo apt install ./agent-chiffreur_1.2.0-1_amd64.deb
sudo systemctl status agent-chiffreur
curl -s http://localhost:5004/health

# Sur chaque VM du cluster → installer le proxy
sudo apt install ./proxy-chiffreur_1.2.0-1_amd64.deb
sudo systemctl status proxy-chiffreur
curl -s http://localhost:8400/health
```

---

*ENSPY SMA 2025-2026 — Agent Chiffreur v1.2.0*

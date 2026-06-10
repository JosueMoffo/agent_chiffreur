# Agent Chiffreur — Pair central du SMA ENSPY (gRPC mTLS, port 5004)

## Présentation

L'**Agent Chiffreur** est le **pair central** du SMA ENSPY installé dans le conteneur du datacenter aux côtés des agents **Décideur** et **Auditeur**.

Son rôle se limite à **trois responsabilités** :
1. **Registre** — maintenir la liste de tous les proxies et VMs actifs du cluster
2. **Orchestration de rotation** — recevoir l'ordre du Décideur et le propager à chaque proxy via gRPC
3. **Audit** — envoyer les événements de rotation à l'agent Auditeur via gRPC

> ⚠️ **L'Agent Chiffreur ne fait aucun chiffrement/déchiffrement.**
> Toute la logique cryptographique est déléguée au crate sibling **`proxy_chiffreur/`** (installé sur chaque VM), avec qui il communique de façon sécurisée via **gRPC mTLS**. Voir [Guide_proxy.md](Guide_proxy.md).

**Technologies utilisées :**
- **Rust** (édition 2021) — sécurité mémoire et performance
- **Tonic / Prost** — framework gRPC asynchrone hautes performances
- **mTLS (rustls)** — Authentification mutuelle "Zero Trust" basée sur le Common Name (CN) des certificats
- **Tokio** — runtime asynchrone

---

## Architecture du système (Full gRPC)

```text
┌──────────────────────────── Conteneur Datacenter ────────────────────────────┐
│                                                                               │
│   [Agent Décideur]                                                            │
│        │  gRPC: RotateCredentials()                                           │
│        │  (Authentifié via CN=decideur)                                       │
│        ▼                                                                      │
│   [Agent Chiffreur :5004]  ── gRPC: PublishEvent() ──►  [Agent Auditeur]     │
│        │  (registre proxies + propagation)                                    │
│        │                                                                      │
└────────│──────────────────────────────────────────────────────────────────────┘
         │
         │  gRPC: RotateCredentials() (pour chaque proxy enregistré)
         │
    ┌────┴────┐           ┌──────────────┐
    │         │           │              │
    ▼         ▼           ▼              ▼
[Proxy :18400] [Proxy :18400] ...  [Proxy :18400]
   VM 101       VM 102               VM 10N
(chiffre/déchiffre localement pour les VMs sur HTTP :8400)
```

| Composant | Emplacement | Ports | Rôle |
|---|---|---|---|
| `agent_chiffreur/` | Conteneur datacenter | **5004 (gRPC)** | Registre, orchestration rotation, interface Décideur/Auditeur |
| `proxy_chiffreur/` | Chaque VM du cluster | **8400 (HTTP)**<br>**18400 (gRPC)** | Crypto locale (HTTP), sessions ECDH, écoute les ordres du central (gRPC) |

---

## Sécurité gRPC et mTLS (Zero Trust)

L'Agent Central n'utilise plus de simples requêtes HTTP. Tout passe par **gRPC sécurisé par mTLS**.
La sécurité repose sur la vérification stricte du **Common Name (CN)** du certificat client lors de chaque appel :

| Service gRPC | RPC | CN Autorisé | Description |
|---|---|---|---|
| `ChiffreurService` | `RotateCredentials` | **`CN=decideur`** | Seul l'agent Décideur peut déclencher une rotation globale. |
| `ChiffreurService` | `AnnounceProxy` | **`CN=proxy`** | Seul un proxy légitime peut s'enregistrer dans le registre central. |
| `ChiffreurService` | `SyncVm` | **`CN=proxy`** | Seul un proxy légitime peut synchroniser les informations d'une VM. |

Toute tentative de connexion sans certificat valide, ou avec un certificat dont le CN ne correspond pas au rôle attendu, est immédiatement rejetée (Erreur gRPC `PermissionDenied` ou `Unauthenticated`).

---

## Configuration (`config/agent_config.json`)

```json
{
  "agent_port": 5004,
  "agent_rotation_autorise": "agent-decideur",
  "intervalle_rotation_sec": 300,
  "chemin_registry": "data/central_registry.json"
}
```

> **Note PKI** : Les chemins vers les certificats TLS (CA, clé privée, certificat) sont désormais gérés par le crate commun `gandal_common` (par défaut dans `/etc/gandal/pki/`).

---

## Compilation et démarrage

```bash
# Compilation optimisée
cargo build --release

# L'agent nécessite que la PKI soit présente dans /etc/gandal/pki/
# ou définie via les variables d'environnement GANDAL_CA_CRT, GANDAL_AGENT_CRT, GANDAL_AGENT_KEY.
./target/release/agent_chiffreur
```

---

## Ce que l'agent central NE fait PAS

Tout ce qui touche au chiffrement AES, au calcul ECDH, ou à l'API HTTP locale (`/encrypt`, `/decrypt`, `/password/generate`) appartient **exclusivement au proxy**. L'Agent Central ne manipule jamais la donnée chiffrée.

---

## Installation (.deb)

```bash
# Sur le serveur datacenter (conteneur)
sudo apt install ./agent-chiffreur_1.2.0-1_amd64.deb
sudo systemctl status agent_chiffreur
```

---

*ENSPY SMA 2025-2026 — Agent Chiffreur v1.2.0 (Migration gRPC)*

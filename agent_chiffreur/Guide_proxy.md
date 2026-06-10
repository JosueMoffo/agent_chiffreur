# Guide — Proxy Chiffreur (`proxy_chiffreur/`)

Le système est scindé en deux crates déployés à des endroits différents de l'infrastructure :

| Composant | Emplacement | Ports | Rôle |
|-----------|-------------|-------|------|
| **Agent central** (`agent_chiffreur`) | Conteneur central | **5004 (gRPC)** | Registre des proxies, interface (mTLS) avec l'agent Décideur et Auditeur, orchestration des ordres de rotation gRPC. |
| **Proxy VM** (`proxy_chiffreur`) | Chaque VM du cluster | **8400 (HTTP)**<br>**18400 (gRPC)** | Toute la logique de chiffrement/déchiffrement local (HTTP), gestion des sessions ECDH, relais inter-VM, écoute des ordres de rotation gRPC. |

## Architecture : le proxy comme véritable moteur crypto hybride

```text
┌────────────────────────────────────────────────────────┐
│                      Agent Central                     │
│                        (Port 5004)                     │
│ [Registre] ◄────── [Ordres de rotation du Décideur]   │
└──────────────────────┬─────────────────────────────────┘
                       │
          (gRPC: RotateCredentials())
                       │
                       ▼
┌────────────────────────────────────────────────────────┐
│                      Proxy de la VM                    │
│                 (Port gRPC mTLS 18400)                 │
│                                                        │
│  [Moteur AES-GCM] ─── [Échange ECDH éphémère X25519]   │
│  [Stockage Clés] ──── [Relais Inter-VM]                │
│                                                        │
│                  (Port HTTP REST 8400)                 │
└──────────────────────┬─────────────────────────────────┘
                       │
     (POST /encrypt, POST /decrypt, POST /vm/session/register)
                       │
                       ▼
┌────────────────────────────────────────────────────────┐
│                   Application de la VM                 │
└────────────────────────────────────────────────────────┘
```

## Démarrage

```bash
# 1. Copier la PKI dans /etc/gandal/pki/ sur la VM (pour le gRPC)
# 2. Installer le proxy sur la VM
cd proxy_chiffreur
PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

## Fichiers proxy locaux

| Fichier | Description |
|---------|-------------|
| `config/proxy_config.json` | Configure le `local_vm_id`, le port HTTP `8400`, le port gRPC `18400`, l'`agent_central_grpc` (vers le port 5004), et la table `peers`. |
| `data/session.json` | Contient les clés AES (new_key, old_key) des VMs gérées par ce proxy. |
| `data/proxy_session.json` | Sessions de proxy à proxy pour le relais de messages. |
| `data/proxy_vm_secret.json` | Clé privée X25519 du proxy pour son identité P2P. |

## Endpoints principaux du Proxy

Le proxy mixe du gRPC sécurisé pour l'administration et du HTTP simple pour les applications locales.

### Interface réseau interne VM (HTTP - Port 8400)
L'application hébergée sur la VM interagit **exclusivement** avec son proxy local pour la sécurité.

| Méthode | Route | Rôle |
|---------|-------|------|
| POST | `/encrypt`, `/decrypt` | Chiffrement/déchiffrement avec la clé de la session de la VM. |
| POST | `/vm/session/register` | Initialise l'échange ECDH éphémère et crée la clé de session AES, puis synchronise le registre central via gRPC. |
| POST | `/proxy/relay` | Demande au proxy d'encapsuler et relayer un message vers une autre VM. |

### Interface d'Administration Cluster (gRPC mTLS - Port 18400)
| Service | RPC | Rôle |
|---------|-----|------|
| `ProxyChiffreurService` | `RotateCredentials` | Exécute la rotation (reçoit l'ordre de l'agent central). |
| `ProxyChiffreurService` | `Health` | Sondage de santé. |

## Processus de Rotation

1. Le Décideur ordonne une rotation via gRPC `RotateCredentials` sur `http://<agent_central>:5004` (authentifié avec `CN=decideur`).
2. L'Agent central identifie tous les proxies connus dans son registre.
3. L'Agent central relaie l'ordre en appelant gRPC `RotateCredentials` sur chaque proxy (`<proxy_vm>:18400`).
4. **Le proxy** génère de nouvelles paires ECDH éphémères, archive les `old_key`, installe les `new_key`.
5. **Le proxy** notifie les applications locales (via `url_notification` HTTP).
6. L'Agent central consolide les résultats et envoie un résumé gRPC à l'Agent Auditeur.

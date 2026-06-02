# Guide — Proxy Chiffreur (`proxy_chiffreur/`)

Le dépôt est scindé en deux crates au même niveau :

| Composant | Dossier | Port | Rôle |
|-----------|---------|------|------|
| **Agent central** | `agent_chiffreur/` | **5004** (gRPC mTLS) | SMA : Décideur + Auditeur ; registre proxies |
| **Proxy VM** | `proxy_chiffreur/` | **8400** HTTP + **18400** gRPC | Crypto VM, relais inter-proxy **HTTP** |

## Architecture

```
Décideur :5003 ──gRPC mTLS RotateCredentials──► Agent central :5004
Agent central ──gRPC mTLS PublishEvent──► Auditeur :5005
                ▲ gRPC AnnounceProxy / SyncVm (CN=proxy)
Proxy :18400 gRPC ─┘
Proxy :8400 HTTP  ──► relais inter-proxy + applications VM
```

Le proxy n’appelle pas le Décideur ni l’Auditeur : seul l’agent central est sur le bus SMA.

## Démarrage

```bash
# 1. Agent central (une fois par datacenter)
cd agent_chiffreur && ./install.sh

# 2. Proxy sur chaque VM
cd ../proxy_chiffreur
PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

## Fichiers proxy

| Fichier | Description |
|---------|-------------|
| `config/proxy_config.json` | `local_vm_id`, `listen_port` 8400, `grpc_port` 18400, `agent_central_grpc`, table `peers` (HTTP) |
| `data/session.json` | Clés AES des VMs enregistrées sur ce proxy |
| `data/proxy_session.json` | Sessions pair à pair (handshake inter-proxy) |
| `data/proxy_vm_secret.json` | Clé X25519 locale du proxy |

Exemples : `config/proxy_config.101.json`, `config/proxy_config.102.json`

## Endpoints principaux (proxy :8400)

| Méthode | Route | Rôle |
|---------|-------|------|
| POST | `/encrypt`, `/decrypt` | Crypto avec clés VM locales |
| POST | `/vm/session/register` | Enregistrement VM + sync central |
| POST | `/credential/rotate` | Rotation locale (appelé par l’agent central) |
| POST | `/proxy/relay` | Relais vers une VM distante (`request` JSON préservé) |
| POST | `/proxy/inbound` | Réception depuis un proxy pair |

## Relais inter-VM

```json
POST /proxy/relay
{
  "dest_vm_id": 102,
  "request": { "...": "corps JSON original de l'app VM, inchangé" }
}
```

Le proxy chiffre le champ `request` pour le transport, le proxy cible déchiffre et transmet à `local_deliver_url` sans altérer la structure.

## Rotation

Seul le **Décideur** déclenche `POST /credential/rotate` sur le port **5004** avec **`X-Agent-Token`**. L’agent propage la rotation à chaque proxy (également protégé par token), puis journalise sur l’auditeur (`POST /events`).

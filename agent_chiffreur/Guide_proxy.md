# Guide — Proxy Chiffreur (`proxy_chiffreur/`)

Le système est scindé en deux crates déployés à des endroits différents de l'infrastructure :

| Composant | Emplacement | Port | Rôle |
|-----------|-------------|------|------|
| **Agent central** (`agent_chiffreur`) | Conteneur central | **5004** | Registre des proxies, interface avec l'agent Décideur et Auditeur, orchestration des ordres de rotation. |
| **Proxy VM** (`proxy_chiffreur`) | Chaque VM du cluster | **8400** | Toute la logique de chiffrement/déchiffrement local, gestion des sessions ECDH, relais inter-VM. |

## Architecture : le proxy comme véritable moteur crypto

```
┌────────────────────────────────────────────────────────┐
│                      Agent Central                     │
│                        (Port 5004)                     │
│ [Registre] ◄────── [Ordres de rotation du Décideur]   │
└──────────────────────┬─────────────────────────────────┘
                       │
          (propage l'ordre de rotation)
                       │
                       ▼
┌────────────────────────────────────────────────────────┐
│                      Proxy de la VM                    │
│                        (Port 8400)                     │
│                                                        │
│  [Moteur AES-GCM] ─── [Échange ECDH éphémère X25519]   │
│  [Stockage Clés] ──── [Relais Inter-VM]                │
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
# 1. Installer le proxy sur la VM
cd proxy_chiffreur
PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

## Fichiers proxy locaux

| Fichier | Description |
|---------|-------------|
| `config/proxy_config.json` | Configure le `local_vm_id`, le port `8400`, l'`agent_central_url` (vers le port 5004), et la table `peers`. |
| `data/session.json` | Contient les clés AES (new_key, old_key) des VMs gérées par ce proxy. |
| `data/proxy_session.json` | Sessions de proxy à proxy pour le relais de messages. |
| `data/proxy_vm_secret.json` | Clé privée X25519 du proxy pour son identité P2P. |

## Endpoints principaux du Proxy (port 8400)

L'application hébergée sur la VM interagit **exclusivement** avec son proxy local pour la sécurité.

| Méthode | Route | Rôle |
|---------|-------|------|
| POST | `/encrypt`, `/decrypt` | Chiffrement/déchiffrement avec la clé de la session de la VM. |
| POST | `/vm/session/register` | Initialise l'échange ECDH éphémère et crée la clé de session AES, puis synchronise le registre central. |
| POST | `/credential/rotate` | Exécute la rotation (reçoit l'ordre de l'agent central). |
| POST | `/proxy/relay` | Demande au proxy d'encapsuler et relayer un message vers une autre VM. |
| POST | `/ecdh/initiate` | Échange cryptographique brut (génère un secret partagé X25519). |
| POST | `/password/generate`, `/secret/strength` | Outils de génération et évaluation de secrets. |

## Relais inter-VM

Le proxy sert également de tunnel chiffré entre les applications des différentes VMs. L'application envoie un JSON clair au proxy, qui se charge du transport :

```json
POST http://localhost:8400/proxy/relay
{
  "dest_vm_id": 102,
  "request": { "...": "corps JSON original de l'app VM, inchangé" }
}
```

Le proxy local chiffre le champ `request`, l'envoie au proxy de la VM 102 (sur son port `/proxy/inbound`), qui déchiffre le message et le livre à l'application cible sans avoir altéré la structure JSON.

## Processus de Rotation

1. Le Décideur (situé dans les conteneurs centraux) ordonne une rotation via `POST http://<agent_central>:5004/credential/rotate`.
2. L'Agent central identifie tous les proxies connus dans son registre.
3. L'Agent central relaie l'ordre en appelant `POST http://<proxy_vm>:8400/credential/rotate` sur chaque proxy.
4. **Le proxy** génère de nouvelles paires ECDH éphémères, archive les `old_key`, installe les `new_key`.
5. **Le proxy** notifie les applications locales (via `url_notification`).
6. L'Agent central consolide les résultats et envoie un résumé à l'Agent Auditeur.

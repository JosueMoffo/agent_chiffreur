# Proxy Chiffreur — Le Moteur Cryptographique Local (Port 8400)

Crate sibling de [`agent_chiffreur`](../agent_chiffreur/). Dans l'architecture distribuée du SMA ENSPY, ce proxy est installé sur **chaque VM** du Data Center.

Contrairement à l'Agent Central (qui sert de simple registre et relai d'ordres), c'est le **Proxy Chiffreur** qui gère la **véritable logique de chiffrement et de déchiffrement** pour sécuriser les communications.

## Responsabilités du Proxy

- **Chiffrement/Déchiffrement (`/encrypt`, `/decrypt`)** : Exécute l'algorithme AES-256-GCM pour protéger les données de la VM locale.
- **Gestion des Sessions (`/vm/session/register`)** : Établit les clés partagées via ECDH X25519 avec les applications VM et synchronise son existence avec l'Agent Central.
- **Exécution des Rotations (`/credential/rotate`)** : Applique localement les ordres de rotation dictés par l'Agent Central, gère le cycle de vie `new_key`/`old_key`.
- **Tunneling Inter-VM (`/proxy/relay`)** : Encapsule, chiffre et relaie le trafic JSON d'une VM vers une autre, de manière totalement transparente pour les applications.

## Démarrage rapide

```bash
# Configuration initiale (remplacer l'ID par celui de la VM Proxmox)
cp config/proxy_config.example.json config/proxy_config.101.json

# Ajuster "agent_central_url" pour pointer vers l'Agent Central (port 5004)
# Aligner agent_token avec agent_chiffreur/config/agent_config.json

# Installation et démarrage
PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

La documentation détaillée de l'architecture et des endpoints se trouve dans le crate principal :
- [Guide_proxy.md](../agent_chiffreur/Guide_proxy.md) : Explication du fonctionnement proxy-VM.
- [Guide_endpoint.md](../agent_chiffreur/Guide_endpoint.md) : Liste de toutes les routes HTTP.
- [Guide_des_secrets.md](../agent_chiffreur/Guide_des_secrets.md) : Fonctionnement de la cryptographie locale.

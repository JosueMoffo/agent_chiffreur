# Proxy Chiffreur — Le Moteur Cryptographique Local (HTTP 8400 / gRPC 18400)

Crate sibling de [`agent_chiffreur`](../agent_chiffreur/). Dans l'architecture distribuée du SMA ENSPY, ce proxy est installé sur **chaque VM** du Data Center.

Contrairement à l'Agent Central (qui sert de simple registre et relai d'ordres d'administration), c'est le **Proxy Chiffreur** qui gère la **véritable logique de chiffrement et de déchiffrement** pour sécuriser les communications.

Depuis la migration gRPC, le proxy opère en mode hybride avec deux interfaces réseau :
1. **Une API d'administration globale (gRPC mTLS - Port 18400)** : Le proxy écoute les ordres de rotation de clés envoyés par l'Agent Central, de manière hautement sécurisée. Il utilise lui-même un client gRPC pour s'annoncer au démarrage.
2. **Une API d'application locale (HTTP REST - Port 8400)** : Destinée aux services tournant sur la même VM, très simple à consommer pour chiffrer/déchiffrer des données locales sans se soucier des certificats mTLS.

## Responsabilités du Proxy

- **Chiffrement/Déchiffrement (HTTP `/encrypt`, `/decrypt`)** : Exécute l'algorithme AES-256-GCM pour protéger les données de la VM locale.
- **Gestion des Sessions (HTTP `/vm/session/register`)** : Établit les clés partagées via ECDH X25519 avec les applications VM.
- **Exécution des Rotations (gRPC `RotateCredentials`)** : Applique localement les ordres de rotation dictés par l'Agent Central, gère le cycle de vie `new_key`/`old_key`.
- **Tunneling Inter-VM (HTTP `/proxy/relay`)** : Encapsule, chiffre et relaie le trafic JSON d'une VM vers une autre, de manière totalement transparente pour les applications.

## Démarrage rapide

```bash
# 1. Placer les certificats de la PKI Gandal dans /etc/gandal/pki/
# (Le proxy a besoin de la CA et d'un certificat avec CN=proxy)

# 2. Configuration initiale (remplacer l'ID par celui de la VM Proxmox)
cp config/proxy_config.example.json config/proxy_config.101.json

# Ajuster "agent_central_grpc" pour pointer vers l'Agent Central (ex: "192.168.123.110:5004")

# 3. Installation et démarrage
PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

La documentation détaillée de l'architecture et des interfaces (HTTP/gRPC) se trouve dans le crate principal :
- [Guide_proxy.md](../agent_chiffreur/Guide_proxy.md) : Explication du fonctionnement proxy-VM hybride.
- [Guide_endpoint.md](../agent_chiffreur/Guide_endpoint.md) : Liste de toutes les routes HTTP et méthodes gRPC mTLS.
- [Guide_des_secrets.md](../agent_chiffreur/Guide_des_secrets.md) : Fonctionnement de la cryptographie locale (ECDH/AES) au sein de la nouvelle enveloppe mTLS.

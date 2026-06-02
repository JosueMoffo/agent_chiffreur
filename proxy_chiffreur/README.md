# Proxy Chiffreur — une instance par VM (port 8400)

Crate sibling de [`agent_chiffreur`](../agent_chiffreur/). Sur chaque VM, le proxy :

- chiffre / déchiffre via `/encrypt` et `/decrypt` (clés dans `data/session.json`) ;
- enregistre les VMs (`POST /vm/session/register`) et synchronise l’agent central (`:5004`) ;
- relaie le trafic inter-VM (`POST /proxy/relay`) **sans modifier** le JSON `request` d’origine.

## Démarrage rapide

```bash
cp config/proxy_config.example.json config/proxy_config.json
# Aligner agent_token avec agent_chiffreur/config/agent_config.json
./install.sh
# ou : PROXY_CONFIG=config/proxy_config.101.json ./install.sh
```

Documentation détaillée : [../agent_chiffreur/Guide_proxy.md](../agent_chiffreur/Guide_proxy.md).

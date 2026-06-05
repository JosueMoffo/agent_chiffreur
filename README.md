Chiffreur


2. Sur l’autre machine (installation en une commande)
Agent central (serveur datacenter) :

sudo apt install ./agent-chiffreur_1.2.0-1_amd64.deb
Proxy (chaque VM) :

sudo apt install ./proxy-chiffreur_1.2.0-1_amd64.deb
apt install ./fichier.deb gère les dépendances système (libc, openssl, etc.) automatiquement.

Vérification :

curl -s http://localhost:5004/health   # agent
curl -s http://localhost:8400/health   # proxy
systemctl status agent-chiffreur
systemctl status proxy-chiffreur
3. Après install du proxy (une seule étape manuelle)
Le proxy a besoin du même token que l’agent et de son local_vm_id / peers :


sudo nano /etc/proxy-chiffreur/proxy_config.json
# agent_central_url → IP du serveur central
# agent_token → même valeur que /etc/agent-chiffreur/agent_config.json
sudo systemctl restart proxy-chiffreur
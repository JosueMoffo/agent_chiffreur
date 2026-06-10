# Guide des Secrets et Flux Cryptographiques

L'architecture cryptographique repose sur une séparation stricte des rôles : l'**Agent Central** (gRPC port 5004) n'a jamais accès aux clés de chiffrement de données. C'est le **Proxy local** (HTTP port 8400) déployé sur chaque VM qui gère la logique d'établissement de clés et de chiffrement.

## 1. Familles de clés AES

| Usage | Gestionnaire | Rôle et Stockage |
|-------|--------------|-------------|
| `POST /encrypt` + `vm_id` | **Proxy VM** | Chiffrement avec la **`new_key`** de la VM (stockée dans le `session.json` local du proxy). |
| `POST /decrypt` + `vm_id` | **Proxy VM** | Déchiffrement avec **`new_key`**, puis **`old_key`** si timer de grâce actif. |
| `POST /vm/session/register` | **Proxy VM** | Échange ECDH X25519 avec une **nouvelle paire éphémère proxy** pour dériver une clé AES (`new_key`). |
| Transport Inter-Agents | **mTLS (Tonic)**| Sécurisation asymétrique X.509 gérée au niveau transport (gRPC) pour l'Agent Central et l'interface gRPC du Proxy (port 18400). Les secrets d'application AES-GCM (ci-dessus) transitent à l'intérieur de ce tunnel sécurisé si nécessaire (ex. relais inter-VM). |

## 2. Établissement de la Clé AES (Flux Proxy-VM)

Le proxy local et l'application VM négocient une clé secrète via l'algorithme d'échange de clés Diffie-Hellman sur courbes elliptiques (ECDH), spécifiquement `X25519`.

### Étape par étape :

1. L'application VM génère une paire de clés X25519 (`priv_VM`, `pub_VM`).
2. L'application appelle HTTP `POST http://localhost:8400/vm/session/register` sur son proxy local, en fournissant `pub_VM`.
3. Le proxy génère une **nouvelle paire X25519 éphémère** (`priv_éphémère_proxy`, `pub_éphémère_proxy`).
4. Le proxy effectue `ECDH(priv_éphémère_proxy, pub_VM)` pour dériver un secret partagé de 32 octets. Ce secret devient la clé AES `new_key`.
5. Le proxy persiste ces informations dans `session.json`.
6. Le proxy annonce sa nouvelle VM à l'Agent Central via **l'appel gRPC sécurisé `SyncVm`** (port 5004).
7. L'Agent central est synchronisé pour tenir son registre, mais **il ne reçoit jamais la `new_key` ni le secret**.

> **Important :** La clé privée éphémère du proxy **n'est pas stockée**. Elle est supprimée de la mémoire (via `zeroize`) juste après le calcul du secret partagé.

## 3. Utilisation de la clé : Chiffrement / Déchiffrement

Le chiffrement des messages est assuré par l'algorithme de chiffrement authentifié **AES-256-GCM**.

- La clé de session (`new_key`) est utilisée comme clé AES.
- Pour chaque message, un **nonce (IV) aléatoire de 12 octets** est généré.
- GCM garantit la confidentialité et calcule un **tag d'authentification (16 octets)** assurant l'intégrité des données.

Les requêtes `POST /encrypt` et `POST /decrypt` s'exécutent **strictement sur le proxy local** de la VM via HTTP (port 8400).

## 4. Rotation des Clés Commanditée (Cycle `new_key` / `old_key`)

L'Agent Central agit en tant que chef d'orchestre pour la rotation via le réseau gRPC mTLS.

1. **Ordre Central :** Le Décideur appelle la méthode gRPC `RotateCredentials` sur l'Agent Central (port 5004). L'agent vérifie le certificat client (`CN=decideur`).
2. **Propagation :** L'Agent Central appelle la méthode gRPC `RotateCredentials` sur chaque proxy connu (port 18400).
3. **Rotation Locale (Sur le proxy) :**
    - Le proxy génère une **nouvelle paire éphémère proxy** + effectue ECDH avec la `public_key` VM (toujours la même).
    - L'ancienne `new_key` est archivée en tant que `old_key` (début du timer de grâce).
    - Le nouveau secret ECDH devient la nouvelle `new_key`.
4. **Notification :** Le proxy notifie l'application VM (via appel HTTP sur `url_notification`) pour qu'elle dérive sa nouvelle clé.

## 5. Propriétés de Sécurité et Garanties

| Mécanisme | Rôle |
|-----------|------|
| **Architecture Distribuée** | L'Agent central (exposé aux autres agents via gRPC) ne manipule ni ne stocke les clés de chiffrement de données AES. |
| **mTLS CN Validation** | L'identité des agents sur le réseau gRPC est garantie par une vérification cryptographique stricte du Common Name (ex: `CN=proxy`, `CN=decideur`). |
| **X25519 éphémère (Forward Secrecy)** | La génération d'une paire éphémère à chaque enregistrement/rotation garantit que même si l'appareil est compromis dans le futur, les communications passées (s'appuyant sur des clés éphémères effacées) restent sécurisées. |
| **Zéro Transport de Clés Privées** | Les clés privées (`priv_VM`, `priv_éphémère_proxy`) ne quittent jamais leur hôte respectif. Seules les clés publiques circulent sur le réseau. |
| **Zeroize** | Les buffers en RAM contenant les secrets et les clés privées sont explicitement écrasés de zéros avant libération mémoire. |

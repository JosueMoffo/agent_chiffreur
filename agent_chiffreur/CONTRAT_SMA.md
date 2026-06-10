# Contrat SMA — Agent Chiffreur (GANDAL mTLS + gRPC)

Conforme à `documentGandal.txt` : **pas de HTTP entre agents** ; **mTLS obligatoire** avec la CA du dossier `ca/`.

## Périmètre de communication

| Lien | Protocole | Port | CN certificat |
|------|-----------|------|----------------|
| Décideur → Chiffreur | **gRPC mTLS** | 5004 | `decideur` → `chiffreur` |
| Chiffreur → Auditeur | **gRPC mTLS** | 5005 | `chiffreur` → `auditeur` |
| Chiffreur ↔ Proxy | **gRPC mTLS** | proxy: `grpc_port` (déf. 18400) | `chiffreur` ↔ `proxy` |
| Proxy ↔ Proxy (relais) | **HTTP** | 8400 | — (inchangé) |
| Application → Proxy | **HTTP** | 8400 | — (crypto locale) |

## Services protobuf (`gandal_common/proto/gandal.proto`)

- `ChiffreurService` — `RotateCredentials`, `AnnounceProxy`, `SyncVm`, `Health`, `RegistryStatus`
- `ProxyChiffreurService` — `RotateCredentials`, `Health`
- `AuditeurService` — `PublishEvent`

## PKI (dossier racine)

```bash
bash scripts/gen_gandal_certs.sh
export GANDAL_CA=ca/ca.crt
export GANDAL_CERT=certs/chiffreur.crt   # ou certs/proxy.crt
export GANDAL_KEY=certs/chiffreur.key
```

## Démarrage

```bash
# Agent central (gRPC 5004)
cd agent_chiffreur && ./install.sh

# Proxy (gRPC + HTTP 8400)
cd proxy_chiffreur && ./install.sh
```

## Rotation

Le **Décideur** appelle `ChiffreurService.RotateCredentials` (plus de `POST /credential/rotate` HTTP).

L’agent propage via `ProxyChiffreurService.RotateCredentials` puis `AuditeurService.PublishEvent`.

//! Serveur gRPC GANDAL — agent chiffreur central (port 5004, mTLS).

use std::sync::Arc;
use std::time::Instant;

use gandal_common::tls::{exiger_cn_client, CN_CHIFFREUR, CN_DECIDEUR};
use gandal_common::{
    ChiffreurService, Empty, HealthResponse, ProxyAnnounceRequest, ProxyAnnounceResponse,
    RegistryStatusResponse, RotateRequest, RotateResponse, VmSyncRequest, VmSyncResponse,
};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::central_http::SharedCentralState;
use crate::central_rotation::{executer_rotation_central, TypeRotation};

pub struct ChiffreurGrpc {
    pub state: SharedCentralState,
}

#[tonic::async_trait]
impl ChiffreurService for ChiffreurGrpc {
    async fn health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<HealthResponse>, Status> {
        let reg = self.state.registry.resume().await;
        let _ = reg;
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            role: "agent_chiffreur".into(),
            uptime_sec: self.state.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    async fn rotate_credentials(
        &self,
        request: Request<RotateRequest>,
    ) -> Result<Response<RotateResponse>, Status> {
        exiger_cn_client(&request, CN_DECIDEUR, "RotateCredentials")?;
        let inner = request.into_inner();
        let request_id = if inner.request_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            inner.request_id
        };

        let rapport = executer_rotation_central(
            &self.state,
            request_id.clone(),
            TypeRotation::Ordonnee,
            Some(self.state.config.agent_rotation_autorise.clone()),
        )
        .await;

        let resultats = rapport
            .resultats
            .iter()
            .filter_map(|v| {
                let vm_id = v.get("proxy_vm_id")?.as_u64()? as u32;
                let succes = v.get("succes")?.as_bool()?;
                let detail = v
                    .get("detail")
                    .or_else(|| v.get("erreur"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(gandal_common::RotateProxyResult {
                    proxy_vm_id: vm_id,
                    succes,
                    detail,
                })
            })
            .collect();

        Ok(Response::new(RotateResponse {
            request_id,
            status: "success".into(),
            type_rotation: TypeRotation::Ordonnee.as_str().into(),
            proxies_total: rapport.proxies_total as u32,
            proxies_reussis: rapport.proxies_reussis,
            resultats,
        }))
    }

    async fn announce_proxy(
        &self,
        request: Request<ProxyAnnounceRequest>,
    ) -> Result<Response<ProxyAnnounceResponse>, Status> {
        exiger_cn_client(&request, gandal_common::tls::CN_PROXY, "AnnounceProxy")?;
        let r = request.into_inner();
        if r.vm_id <= 100 {
            return Err(Status::invalid_argument("vm_id doit être > 100"));
        }
        if r.proxy_http_url.is_empty() || r.proxy_grpc_addr.is_empty() {
            return Err(Status::invalid_argument(
                "proxy_http_url et proxy_grpc_addr obligatoires",
            ));
        }

        self.state
            .registry
            .enregistrer_proxy(
                r.vm_id,
                r.proxy_http_url,
                r.proxy_grpc_addr,
                &r.public_key_hex,
            )
            .await
            .map_err(|e| Status::internal(e))?;

        info!("[gRPC] proxy VM {} annoncé", r.vm_id);
        Ok(Response::new(ProxyAnnounceResponse {
            request_id: Uuid::new_v4().to_string(),
            status: "success".into(),
            vm_id: r.vm_id,
        }))
    }

    async fn sync_vm(
        &self,
        request: Request<VmSyncRequest>,
    ) -> Result<Response<VmSyncResponse>, Status> {
        exiger_cn_client(&request, gandal_common::tls::CN_PROXY, "SyncVm")?;
        let r = request.into_inner();
        self.state
            .registry
            .sync_vm(r.vm_id, &r.public_key_hex, r.heberge_par_proxy_vm_id)
            .await
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(VmSyncResponse {
            status: "success".into(),
            vm_id: r.vm_id,
        }))
    }

    async fn registry_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<RegistryStatusResponse>, Status> {
        let reg = self.state.registry.resume().await;
        Ok(Response::new(RegistryStatusResponse {
            status: "ok".into(),
            proxies_count: reg.proxies.len() as u32,
            vms_count: reg.vms.len() as u32,
        }))
    }
}

/// Démarre le serveur gRPC mTLS sur `grpc_addr` (ex. `0.0.0.0:5004`).
pub async fn demarrer_serveur_grpc(
    state: SharedCentralState,
    grpc_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use gandal_common::tls::{server_tls_config, GandalPkiPaths};
    use gandal_common::ChiffreurServiceServer;

    let pki = GandalPkiPaths::for_chiffreur();
    gandal_common::tls::warn_if_missing(&pki);
    let tls = server_tls_config(&pki)?;

    let svc = ChiffreurGrpc { state };
    info!(
        "[gRPC] ChiffreurService mTLS sur {} (CN={})",
        grpc_addr, CN_CHIFFREUR
    );

    tonic::transport::Server::builder()
        .tls_config(tls)?
        .add_service(ChiffreurServiceServer::new(svc))
        .serve(grpc_addr)
        .await?;

    Ok(())
}

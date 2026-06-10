//! Serveur gRPC GANDAL du proxy (mTLS) — agent central uniquement.

use std::sync::Arc;
use gandal_common::tls::CN_PROXY;

use gandal_common::tls::{exiger_cn_client, CN_CHIFFREUR};
use gandal_common::{
    Empty, HealthResponse, ProxyChiffreurService, RotateRequest, RotateResponse,
};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::proxy_http::SharedProxyState;
use crate::rotation_vm::{effectuer_rotation_toutes_vms, RapportRotationVms};

pub struct ProxyGrpc {
    pub state: SharedProxyState,
}

#[tonic::async_trait]
impl ProxyChiffreurService for ProxyGrpc {
    async fn health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            role: format!("proxy-{}", self.state.config.local_vm_id),
            uptime_sec: self.state.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    async fn rotate_credentials(
        &self,
        request: Request<RotateRequest>,
    ) -> Result<Response<RotateResponse>, Status> {
        exiger_cn_client(&request, CN_CHIFFREUR, "RotateCredentials")?;
        let inner = request.into_inner();
        let rid = if inner.request_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            inner.request_id
        };

        info!("[gRPC] rotation demandée par l'agent central (rid={rid})");
        let rapport: RapportRotationVms = effectuer_rotation_toutes_vms(
            Arc::clone(&self.state.sessions_vm),
            &self.state.config.agent_token,
        )
        .await;

        Ok(Response::new(RotateResponse {
            request_id: rid,
            status: "success".into(),
            type_rotation: "propagation".into(),
            proxies_total: rapport.vms_total as u32,
            proxies_reussis: rapport.vms_reussies as u32,
            resultats: rapport
                .resultats
                .iter()
                .map(|r| gandal_common::RotateProxyResult {
                    proxy_vm_id: r.vm_id,
                    succes: r.succes,
                    detail: r.erreur.clone().unwrap_or_default(),
                })
                .collect(),
        }))
    }
}

pub async fn demarrer_serveur_grpc_proxy(
    state: SharedProxyState,
    grpc_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use gandal_common::tls::{server_tls_config, GandalPkiPaths};
    use gandal_common::ProxyChiffreurServiceServer;

    let pki = GandalPkiPaths::for_proxy();
    gandal_common::tls::warn_if_missing(&pki);
    let tls = server_tls_config(&pki)?;

    info!(
        "[gRPC] ProxyChiffreurService mTLS sur {} (CN={})",
        grpc_addr, CN_PROXY
    );

    tonic::transport::Server::builder()
        .tls_config(tls)?
        .add_service(ProxyChiffreurServiceServer::new(ProxyGrpc { state }))
        .serve(grpc_addr)
        .await?;

    Ok(())
}

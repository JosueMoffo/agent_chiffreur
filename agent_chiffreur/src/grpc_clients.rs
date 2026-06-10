//! Clients gRPC GANDAL — auditeur et proxies (mTLS).

use gandal_common::tls::{client_tls_config, domain_from_cn, grpc_uri, GandalPkiPaths, CN_AUDITEUR};
use gandal_common::{
    AuditeurEvent, AuditeurServiceClient, ProxyChiffreurServiceClient, RotateRequest,
};
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::config::Config;

async fn connect_mtls(uri: String, pki: &GandalPkiPaths, domain: &str) -> Result<Channel, String> {
    let tls = client_tls_config(pki, domain).map_err(|e| e.to_string())?;
    Channel::from_shared(uri)
        .map_err(|e| e.to_string())?
        .tls_config(tls)
        .map_err(|e| e.to_string())?
        .connect()
        .await
        .map_err(|e| format!("connexion gRPC {domain} : {e}"))
}

/// Publie un événement vers l'auditeur (`AuditeurService.PublishEvent`, port 5005).
pub async fn publier_evenement_auditeur(
    config: &Config,
    event: AuditeurEvent,
) -> Result<(), String> {
    let Some((host, port)) = config.adresse_grpc_auditeur() else {
        return Err("auditeur gRPC non configuré".into());
    };

    let pki = GandalPkiPaths::for_chiffreur();
    let uri = grpc_uri(&host, port);
    let mut client = AuditeurServiceClient::new(
        connect_mtls(uri, &pki, domain_from_cn(CN_AUDITEUR)).await?,
    );

    match client.publish_event(event).await {
        Ok(rep) => {
            info!(
                "[gRPC] Auditeur PublishEvent — {}",
                rep.into_inner().status
            );
            Ok(())
        }
        Err(e) => {
            warn!("[gRPC] Auditeur indisponible : {e}");
            Err(e.to_string())
        }
    }
}

/// Déclenche la rotation sur un proxy via gRPC.
pub async fn rotation_proxy_grpc(
    proxy_grpc_addr: &str,
    request_id: &str,
) -> Result<(), String> {
    let pki = GandalPkiPaths::for_chiffreur();
    let uri = if proxy_grpc_addr.starts_with("https://") {
        proxy_grpc_addr.to_string()
    } else {
        format!("https://{proxy_grpc_addr}")
    };

    let mut client = ProxyChiffreurServiceClient::new(
        connect_mtls(uri, &pki, domain_from_cn(gandal_common::tls::CN_PROXY)).await?,
    );

    client
        .rotate_credentials(RotateRequest {
            request_id: request_id.to_string(),
            initiateur: "agent_central".into(),
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

//! Client gRPC vers l'agent chiffreur central (mTLS GANDAL).

use gandal_common::tls::{client_tls_config, domain_from_cn, GandalPkiPaths, CN_CHIFFREUR};
use gandal_common::{
    ChiffreurServiceClient, ProxyAnnounceRequest, VmSyncRequest,
};
use tonic::transport::Channel;
use tracing::debug;

use crate::config::ProxyConfig;

#[derive(Clone)]
pub struct ClientCentral {
    endpoint: String,
}

impl ClientCentral {
    pub fn new(config: &ProxyConfig) -> Self {
        Self {
            endpoint: config.agent_central_grpc.clone(),
        }
    }

    fn endpoint_uri(&self) -> String {
        let ep = self.endpoint.trim();
        if ep.starts_with("https://") {
            ep.to_string()
        } else {
            format!(
                "https://{}",
                ep.trim_start_matches("http://")
            )
        }
    }

    async fn channel(&self) -> Result<Channel, String> {
        let pki = GandalPkiPaths::for_proxy();
        let uri = self.endpoint_uri();
        let tls = client_tls_config(&pki, domain_from_cn(CN_CHIFFREUR))
            .map_err(|e| e.to_string())?;
        Channel::from_shared(uri)
            .map_err(|e| e.to_string())?
            .tls_config(tls)
            .map_err(|e| e.to_string())?
            .connect()
            .await
            .map_err(|e| format!("agent central gRPC : {e}"))
    }

    /// Annonce ce proxy auprès de l'agent central (gRPC mTLS).
    pub async fn annoncer_proxy(
        &self,
        vm_id: u32,
        proxy_http_url: &str,
        proxy_grpc_addr: &str,
        public_key_hex: &str,
    ) -> Result<(), String> {
        let mut client = ChiffreurServiceClient::new(self.channel().await?);
        client
            .announce_proxy(ProxyAnnounceRequest {
                vm_id,
                proxy_http_url: proxy_http_url.to_string(),
                proxy_grpc_addr: proxy_grpc_addr.to_string(),
                public_key_hex: public_key_hex.to_string(),
            })
            .await
            .map_err(|e| e.to_string())?;
        debug!("[gRPC] proxy vm_id={vm_id} annoncé au central");
        Ok(())
    }

    /// Synchronise une VM vers le registre central.
    pub async fn sync_vm_session(
        &self,
        vm_id: u32,
        public_key_hex: &str,
        heberge_par_proxy_vm_id: u32,
    ) -> Result<(), String> {
        let mut client = ChiffreurServiceClient::new(self.channel().await?);
        client
            .sync_vm(VmSyncRequest {
                vm_id,
                public_key_hex: public_key_hex.to_string(),
                heberge_par_proxy_vm_id,
            })
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

//! Client HTTP vers l'agent chiffreur **central** (port 5004).

use reqwest::Client;
use serde_json::{json, Value};
use tracing::debug;

use crate::config::ProxyConfig;

#[derive(Clone)]
pub struct ClientCentral {
    http: Client,
    base: String,
    token: String,
}

impl ClientCentral {
    pub fn new(config: &ProxyConfig) -> Self {
        Self {
            http: Client::new(),
            base: config.agent_central_url.trim_end_matches('/').to_string(),
            token: config.agent_token.clone(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path);
        let res = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Agent-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("agent central {path} : {e}"))?;
        let status = res.status();
        let rep: Value = res.json().await.map_err(|e| format!("JSON : {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "HTTP {} : {}",
                status.as_u16(),
                rep["description"].as_str().unwrap_or("erreur")
            ));
        }
        Ok(rep)
    }

    /// Annonce ce proxy auprès de l'agent central au démarrage.
    pub async fn annoncer_proxy(
        &self,
        vm_id: u32,
        proxy_url: &str,
        public_key_hex: &str,
    ) -> Result<(), String> {
        self.post(
            "/registry/proxy/announce",
            json!({
                "vm_id": vm_id,
                "proxy_url": proxy_url,
                "public_key": public_key_hex,
            }),
        )
        .await?;
        debug!("[Central] proxy vm_id={vm_id} annoncé");
        Ok(())
    }

    /// Synchronise l'enregistrement d'une VM (pair) vers le registre central.
    pub async fn sync_vm_session(
        &self,
        vm_id: u32,
        public_key_hex: &str,
        heberge_par_proxy_vm_id: u32,
    ) -> Result<(), String> {
        self.post(
            "/registry/vm/sync",
            json!({
                "vm_id": vm_id,
                "public_key": public_key_hex,
                "heberge_par_proxy_vm_id": heberge_par_proxy_vm_id,
            }),
        )
        .await?;
        Ok(())
    }
}

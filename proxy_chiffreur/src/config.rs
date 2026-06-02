//! Configuration du proxy chiffreur (une instance par VM, port 8400).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::info;

pub const CHEMIN_CONFIG_PROXY_DEFAUT: &str = "config/proxy_config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub local_vm_id: u32,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// URL de l'agent chiffreur central (port 5004).
    #[serde(default = "default_agent_central_url", alias = "agent_url")]
    pub agent_central_url: String,
    #[serde(default)]
    pub agent_token: String,
    /// Clés AES / ECDH des VMs (pairs) — ancienne logique agent, locale au proxy.
    #[serde(default = "default_chemin_session")]
    pub chemin_session: String,
    #[serde(default = "default_grace_sec")]
    pub old_key_grace_sec: u64,
    #[serde(default = "default_chemin_cle")]
    pub chemin_cle_privee: String,
    #[serde(default = "default_deliver_url")]
    pub local_deliver_url: String,
    /// VMID distant → URL de base du proxy pair (ex. `http://10.0.0.102:8400`)
    #[serde(default)]
    pub peers: HashMap<String, String>,
}

fn default_listen_port() -> u16 {
    8400
}
fn default_agent_central_url() -> String {
    "http://127.0.0.1:5004".to_string()
}
fn default_grace_sec() -> u64 {
    60
}
fn default_chemin_session() -> String {
    "data/session.json".to_string()
}
fn default_chemin_cle() -> String {
    "data/proxy_vm_secret.json".to_string()
}
fn default_deliver_url() -> String {
    "http://127.0.0.1:8080/deliver".to_string()
}

impl ProxyConfig {
    pub fn charger(chemin: Option<&str>) -> Self {
        let chemin = chemin.unwrap_or(CHEMIN_CONFIG_PROXY_DEFAUT);
        if Path::new(chemin).exists() {
            let contenu = std::fs::read_to_string(chemin)
                .unwrap_or_else(|e| panic!("Lecture {chemin} : {e}"));
            serde_json::from_str(&contenu)
                .unwrap_or_else(|e| panic!("JSON proxy config invalide : {e}"))
        } else {
            info!("[ProxyConfig] '{chemin}' absent — configuration par défaut (vm_id=101).");
            Self {
                local_vm_id: 101,
                listen_port: default_listen_port(),
                agent_central_url: default_agent_central_url(),
                agent_token: "ENSPY-TOKEN-2026".to_string(),
                chemin_session: default_chemin_session(),
                old_key_grace_sec: default_grace_sec(),
                chemin_cle_privee: default_chemin_cle(),
                local_deliver_url: default_deliver_url(),
                peers: HashMap::new(),
            }
        }
    }

    pub fn url_proxy_peer(&self, dest_vm_id: u32) -> Option<String> {
        self.peers
            .get(&dest_vm_id.to_string())
            .cloned()
            .or_else(|| self.peers.get(&format!("vm-{dest_vm_id}")).cloned())
    }
}

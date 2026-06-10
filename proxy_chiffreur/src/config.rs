//! Configuration du proxy chiffreur (HTTP 8400 apps + gRPC mTLS agent).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::info;

pub const CHEMIN_CONFIG_PROXY_DEFAUT: &str = "config/proxy_config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub local_vm_id: u32,
    /// Port HTTP (applications VM, relais inter-proxy).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Adresse gRPC de l'agent central (`host:port`, port 5004).
    #[serde(default = "default_agent_central_grpc", alias = "agent_central_url", alias = "agent_url")]
    pub agent_central_grpc: String,
    /// Port gRPC mTLS (agent central ↔ ce proxy).
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
    #[serde(default = "default_grpc_host")]
    pub grpc_listen_host: String,
    #[serde(default)]
    pub agent_token: String,
    #[serde(default = "default_chemin_session")]
    pub chemin_session: String,
    #[serde(default = "default_grace_sec")]
    pub old_key_grace_sec: u64,
    #[serde(default = "default_chemin_cle")]
    pub chemin_cle_privee: String,
    #[serde(default = "default_advertise_host")]
    pub advertise_host: String,
    #[serde(default = "default_deliver_url")]
    pub local_deliver_url: String,
    /// VMID distant → URL HTTP du proxy pair (relais inter-VM).
    #[serde(default)]
    pub peers: HashMap<String, String>,
}

fn default_listen_port() -> u16 {
    8400
}
fn default_grpc_port() -> u16 {
    18400
}
fn default_grpc_host() -> String {
    "0.0.0.0".to_string()
}
fn default_advertise_host() -> String {
    "127.0.0.1".to_string()
}
fn default_agent_central_grpc() -> String {
    "127.0.0.1:5004".to_string()
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
        let mut config = if Path::new(chemin).exists() {
            let contenu = std::fs::read_to_string(chemin)
                .unwrap_or_else(|e| panic!("Lecture {chemin} : {e}"));
            serde_json::from_str(&contenu)
                .unwrap_or_else(|e| panic!("JSON proxy config invalide : {e}"))
        } else {
            info!("[ProxyConfig] '{chemin}' absent — configuration par défaut (vm_id=101).");
            Self {
                local_vm_id: 101,
                listen_port: default_listen_port(),
                agent_central_grpc: default_agent_central_grpc(),
                grpc_port: default_grpc_port(),
                grpc_listen_host: default_grpc_host(),
                agent_token: "ENSPY-TOKEN-2026".to_string(),
                chemin_session: default_chemin_session(),
                old_key_grace_sec: default_grace_sec(),
                chemin_cle_privee: default_chemin_cle(),
                advertise_host: default_advertise_host(),
                local_deliver_url: default_deliver_url(),
                peers: HashMap::new(),
            }
        };

        if let Ok(v) = std::env::var("PROXY_ADVERTISE_HOST") {
            config.advertise_host = v;
        }

        if config.advertise_host == "127.0.0.1" || config.advertise_host == "localhost" {
            tracing::warn!("⚠️  [PRODUCTION] L'adresse d'annonce (advertise_host) du proxy est configurée sur '{}'. L'Agent Central ne pourra pas le joindre depuis une autre machine !", config.advertise_host);
            tracing::warn!("⚠️  Configurez 'advertise_host' dans le JSON ou via la variable d'environnement PROXY_ADVERTISE_HOST avec l'IP publique/LAN de cette VM.");
        }

        config
    }

    pub fn grpc_socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.grpc_listen_host, self.grpc_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], self.grpc_port)))
    }

    pub fn grpc_advertise_addr(&self) -> String {
        format!("{}:{}", self.advertise_host, self.grpc_port)
    }

    pub fn url_proxy_peer(&self, dest_vm_id: u32) -> Option<String> {
        self.peers
            .get(&dest_vm_id.to_string())
            .cloned()
            .or_else(|| self.peers.get(&format!("vm-{dest_vm_id}")).cloned())
    }
}

//! Registre central des proxies et des VMs (agent port 5004).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRecord {
    pub vm_id: u32,
    /// URL HTTP du proxy (relais inter-VM, inchangé).
    #[serde(alias = "proxy_url")]
    pub proxy_http_url: String,
    /// Adresse gRPC `host:port` (agent central ↔ proxy).
    #[serde(default)]
    pub proxy_grpc_addr: String,
    pub public_key_preview: String,
    pub annonce_a: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRegistryRecord {
    pub vm_id: u32,
    pub public_key_preview: String,
    pub heberge_par_proxy_vm_id: u32,
    pub sync_a: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CentralRegistryStore {
    #[serde(default = "default_schema")]
    pub schema_version: String,
    #[serde(default)]
    pub proxies: HashMap<String, ProxyRecord>,
    #[serde(default)]
    pub vms: HashMap<String, VmRegistryRecord>,
}

fn default_schema() -> String {
    "1.0".to_string()
}

impl CentralRegistryStore {
    pub fn charger(chemin: &str) -> Self {
        match std::fs::read_to_string(chemin) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn sauvegarder(&self, chemin: &str) -> Result<(), String> {
        if let Some(p) = Path::new(chemin).parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let j = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(chemin, j).map_err(|e| e.to_string())
    }
}

pub struct GestionnaireRegistry {
    pub store: RwLock<CentralRegistryStore>,
    pub chemin: String,
}

impl GestionnaireRegistry {
    pub fn nouveau(chemin: &str) -> Arc<Self> {
        let store = CentralRegistryStore::charger(chemin);
        info!(
            "[Registry] {} proxy(s), {} VM(s) — '{}'",
            store.proxies.len(),
            store.vms.len(),
            chemin
        );
        Arc::new(Self {
            store: RwLock::new(store),
            chemin: chemin.to_string(),
        })
    }

    pub async fn enregistrer_proxy(
        &self,
        vm_id: u32,
        proxy_http_url: String,
        proxy_grpc_addr: String,
        public_key: &str,
    ) -> Result<(), String> {
        let preview = format!("{}...", &public_key[..16.min(public_key.len())]);
        let mut s = self.store.write().await;
        s.proxies.insert(
            vm_id.to_string(),
            ProxyRecord {
                vm_id,
                proxy_http_url,
                proxy_grpc_addr,
                public_key_preview: preview,
                annonce_a: Utc::now(),
            },
        );
        s.sauvegarder(&self.chemin)
    }

    pub async fn sync_vm(
        &self,
        vm_id: u32,
        public_key: &str,
        heberge_par: u32,
    ) -> Result<(), String> {
        let preview = format!("{}...", &public_key[..16.min(public_key.len())]);
        let mut s = self.store.write().await;
        s.vms.insert(
            vm_id.to_string(),
            VmRegistryRecord {
                vm_id,
                public_key_preview: preview,
                heberge_par_proxy_vm_id: heberge_par,
                sync_a: Utc::now(),
            },
        );
        s.sauvegarder(&self.chemin)
    }

    /// Adresses gRPC des proxies (rotation agent → proxy).
    pub async fn addrs_grpc_proxies(&self) -> Vec<(u32, String)> {
        let s = self.store.read().await;
        s.proxies
            .values()
            .map(|p| (p.vm_id, p.proxy_grpc_addr.clone()))
            .filter(|(_, a)| !a.is_empty())
            .collect()
    }

    /// URLs HTTP des proxies (relais inter-proxy).
    pub async fn urls_http_proxies(&self) -> Vec<(u32, String)> {
        let s = self.store.read().await;
        s.proxies
            .values()
            .map(|p| (p.vm_id, p.proxy_http_url.clone()))
            .collect()
    }

    pub async fn resume(&self) -> CentralRegistryStore {
        self.store.read().await.clone()
    }
}

//! Sessions pair à pair du proxy (`data/proxy_session.json`).
//!
//! Indique avec quelles VMs distantes une session de communication a été établie
//! (handshake `/vm/session/register` vers le proxy cible).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use crate::sessions_vm::valider_vm_id;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPeerSession {
    pub vm_id: u32,
    pub peer_proxy_url: String,
    pub public_key_preview: String,
    pub established_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxySessionStore {
    #[serde(default = "default_schema")]
    pub schema_version: String,
    pub local_vm_id: u32,
    #[serde(default)]
    pub peers: HashMap<String, ProxyPeerSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derniere_mise_a_jour: Option<DateTime<Utc>>,
}

fn default_schema() -> String {
    "1.0".to_string()
}

impl ProxySessionStore {
    pub fn charger(chemin: &str, local_vm_id: u32) -> Self {
        match std::fs::read_to_string(chemin) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| Self::vide(local_vm_id)),
            Err(_) => Self::vide(local_vm_id),
        }
    }

    pub fn vide(local_vm_id: u32) -> Self {
        Self {
            schema_version: default_schema(),
            local_vm_id,
            peers: HashMap::new(),
            derniere_mise_a_jour: None,
        }
    }

    pub fn sauvegarder(&mut self, chemin: &str) -> Result<(), String> {
        self.derniere_mise_a_jour = Some(Utc::now());
        if let Some(parent) = Path::new(chemin).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {} : {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("sérialisation proxy_session : {e}"))?;
        std::fs::write(chemin, json).map_err(|e| format!("écriture {chemin} : {e}"))?;
        Ok(())
    }

    pub fn a_peer(&self, vm_id: u32) -> bool {
        self.peers.contains_key(&vm_id.to_string())
    }
}

pub struct GestionnaireProxySessions {
    pub store: RwLock<ProxySessionStore>,
    pub chemin: String,
}

impl GestionnaireProxySessions {
    pub fn nouveau(chemin: &str, local_vm_id: u32) -> Arc<Self> {
        let store = ProxySessionStore::charger(chemin, local_vm_id);
        info!(
            "[ProxySession] local_vm_id={} — {} pair(s) dans '{}'",
            local_vm_id,
            store.peers.len(),
            chemin
        );
        Arc::new(Self {
            store: RwLock::new(store),
            chemin: chemin.to_string(),
        })
    }

    pub async fn enregistrer_peer(
        &self,
        vm_id: u32,
        peer_proxy_url: String,
        public_key_hex: &str,
    ) -> Result<(), String> {
        valider_vm_id(vm_id)?;
        let preview = format!("{}...", &public_key_hex[..16.min(public_key_hex.len())]);
        let mut store = self.store.write().await;
        store.peers.insert(
            vm_id.to_string(),
            ProxyPeerSession {
                vm_id,
                peer_proxy_url,
                public_key_preview: preview,
                established_at: Utc::now(),
            },
        );
        store.sauvegarder(&self.chemin)
    }

    pub async fn a_session_peer(&self, vm_id: u32) -> bool {
        self.store.read().await.a_peer(vm_id)
    }

    pub async fn lister_peers(&self) -> Vec<ProxyPeerSession> {
        let store = self.store.read().await;
        let mut v: Vec<_> = store.peers.values().cloned().collect();
        v.sort_by_key(|p| p.vm_id);
        v
    }
}

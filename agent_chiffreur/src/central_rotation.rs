//! Propagation de rotation vers les proxies et notification à l'agent auditeur.

use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use gandal_common::AuditeurEvent;

use crate::central_http::SharedCentralState;
use crate::config::Config;
use crate::grpc_clients::{publier_evenement_auditeur, rotation_proxy_grpc};

/// Type de déclenchement de la rotation (journalisation auditeur).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeRotation {
    /// Rotation périodique (tâche de fond, `intervalle_rotation_sec`).
    Automatique,
    /// Rotation ordonnée par le Décideur (`ChiffreurService.RotateCredentials`, mTLS CN=decideur).
    Ordonnee,
}

impl TypeRotation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Automatique => "automatique",
            Self::Ordonnee => "ordonnee",
        }
    }
}

/// Rapport agrégé après propagation vers les proxies.
#[derive(Debug, Clone)]
pub struct RapportPropagationProxies {
    pub request_id: String,
    pub proxies_total: usize,
    pub proxies_reussis: u32,
    pub resultats: Vec<Value>,
}

/// Propage la rotation à chaque proxy via gRPC mTLS (`ProxyChiffreurService`).
pub async fn propager_rotation_proxies(
    st: &SharedCentralState,
    request_id: &str,
) -> RapportPropagationProxies {
    let proxies = st.registry.addrs_grpc_proxies().await;
    let mut resultats = Vec::new();
    let mut ok_count = 0u32;

    for (vm_id, grpc_addr) in &proxies {
        match rotation_proxy_grpc(grpc_addr, request_id).await {
            Ok(()) => {
                ok_count += 1;
                resultats.push(json!({
                    "proxy_vm_id": vm_id,
                    "succes": true,
                    "grpc_addr": grpc_addr
                }));
            }
            Err(e) => {
                warn!("[Central] rotation proxy {vm_id} gRPC : {e}");
                resultats.push(json!({
                    "proxy_vm_id": vm_id,
                    "succes": false,
                    "erreur": e
                }));
            }
        }
    }

    RapportPropagationProxies {
        request_id: request_id.to_string(),
        proxies_total: proxies.len(),
        proxies_reussis: ok_count,
        resultats,
    }
}

/// Envoie un événement de rotation à l'agent auditeur (best-effort).
pub async fn notifier_auditeur_rotation(
    config: &Config,
    token: &str,
    type_rotation: TypeRotation,
    rapport: &RapportPropagationProxies,
    ordonne_par: Option<&str>,
) {
    let data = json!({
        "type_rotation": type_rotation.as_str(),
        "ordonne_par": ordonne_par,
        "agent_port": 5004,
        "proxies_total": rapport.proxies_total,
        "proxies_reussis": rapport.proxies_reussis,
        "proxies_echecs": rapport.proxies_total.saturating_sub(rapport.proxies_reussis as usize),
        "resultats": rapport.resultats,
    });

    let event = AuditeurEvent {
        request_id: rapport.request_id.clone(),
        source_agent: "agent_chiffreur".into(),
        event_type: "CREDENTIAL_ROTATION".into(),
        timestamp: Utc::now().to_rfc3339(),
        payload_json: data.to_string(),
    };

    let _ = token;
    info!(
        "[gRPC] Auditeur PublishEvent — rotation {}",
        type_rotation.as_str()
    );
    if let Err(e) = publier_evenement_auditeur(config, event).await {
        warn!("[Auditeur] gRPC : {e}");
    }
}

/// Exécute une rotation complète : proxies puis auditeur.
pub async fn executer_rotation_central(
    st: &SharedCentralState,
    request_id: String,
    type_rotation: TypeRotation,
    ordonne_par: Option<String>,
) -> RapportPropagationProxies {
    info!(
        "[Central] rotation {} (request_id={})",
        type_rotation.as_str(),
        request_id
    );

    let rapport = propager_rotation_proxies(st, &request_id).await;

    notifier_auditeur_rotation(
        &st.config,
        &st.config.agent_token,
        type_rotation,
        &rapport,
        ordonne_par.as_deref(),
    )
    .await;

    rapport
}

/// Tâche de fond : rotation automatique périodique vers tous les proxies.
pub async fn tache_rotation_automatique_central(st: Arc<SharedCentralState>, intervalle_sec: u64) {
    info!(
        "[Central] Rotation automatique activée — intervalle={intervalle_sec}s"
    );
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(intervalle_sec));
    interval.tick().await;

    loop {
        interval.tick().await;
        let request_id = Uuid::new_v4().to_string();
        let rapport = executer_rotation_central(
            &st,
            request_id,
            TypeRotation::Automatique,
            None,
        )
        .await;

        if rapport.proxies_total == 0 {
            info!("[Central] Rotation automatique — aucun proxy enregistré.");
        } else {
            info!(
                "[Central] Rotation automatique — {}/{} proxy(s) OK",
                rapport.proxies_reussis, rapport.proxies_total
            );
        }
    }
}

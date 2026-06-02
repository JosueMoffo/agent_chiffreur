//! Démarrage de l'agent chiffreur **central** (gRPC mTLS port 5004).

use std::sync::Arc;

use tracing::info;

use crate::central_grpc::demarrer_serveur_grpc;
use crate::central_http::CentralState;
use crate::central_registry::GestionnaireRegistry;
use crate::central_rotation::tache_rotation_automatique_central;
use crate::config::Config;

/// Prépare l'état partagé et lance les tâches de fond.
pub async fn preparer_agent(config: Config) -> Arc<CentralState> {
    let registry = GestionnaireRegistry::nouveau(&config.chemin_registry);

    let state = Arc::new(CentralState {
        config: config.clone(),
        registry,
        requetes: std::sync::atomic::AtomicU64::new(0),
        erreurs: std::sync::atomic::AtomicU64::new(0),
        start_time: std::time::Instant::now(),
    });

    if config.intervalle_rotation_sec > 0 {
        let st_auto = Arc::clone(&state);
        let intervalle = config.intervalle_rotation_sec;
        tokio::spawn(async move {
            tache_rotation_automatique_central(st_auto, intervalle).await;
        });
        info!(
            "[Agent central] rotation automatique toutes les {}s",
            config.intervalle_rotation_sec
        );
    }

    let auditeur = config
        .adresse_grpc_auditeur()
        .map(|(h, p)| format!("{h}:{p}"))
        .unwrap_or_else(|| "(non configuré)".to_string());

    info!(
        "[Agent central] gRPC mTLS :{} — Décideur + Auditeur ({auditeur})",
        config.agent_port
    );

    state
}

/// Démarre le serveur gRPC (bloquant).
pub async fn executer_serveur_grpc(
    state: Arc<CentralState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = state.config.grpc_socket_addr();
    demarrer_serveur_grpc(state, addr).await
}

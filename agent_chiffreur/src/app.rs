//! Démarrage de l'agent chiffreur **central** (port 5004).

use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tracing::info;

use crate::central_http::{
    handle_decideur_forward, handle_health, handle_metrics, handle_proxy_announce,
    handle_registry_status, handle_rotate, handle_vm_sync, middleware_token, CentralState,
};
use crate::central_registry::GestionnaireRegistry;
use crate::config::Config;

/// Routeur de l'agent central (interface proxies ↔ Décideur).
pub fn build_router(state: Arc<CentralState>) -> Router {
    let api = Router::new()
        .route("/registry/proxy/announce", post(handle_proxy_announce))
        .route("/registry/vm/sync", post(handle_vm_sync))
        .route("/registry/status", get(handle_registry_status))
        .route("/credential/rotate", post(handle_rotate))
        .route("/decideur/forward", post(handle_decideur_forward))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware_token,
        ));

    let public = Router::new()
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics));

    api.merge(public).with_state(state)
}

/// Prépare l'agent central (sans crypto VM locale — déléguée aux proxies).
pub async fn preparer_agent(config: Config) -> (Arc<CentralState>, u16) {
    let registry = GestionnaireRegistry::nouveau(&config.chemin_registry);

    let state = Arc::new(CentralState {
        config: config.clone(),
        registry,
        http: crate::tls_utils::build_mtls_client(&config),
        requetes: std::sync::atomic::AtomicU64::new(0),
        erreurs: std::sync::atomic::AtomicU64::new(0),
        start_time: std::time::Instant::now(),
    });

    info!(
        "[Agent central] port={} — registre proxies, rotation, interface Décideur",
        config.agent_port
    );

    (state, config.agent_port)
}

//! Point d'entrée — Agent Chiffreur ENSPY

use agent_chiffreur::app::{build_router, preparer_agent};
use agent_chiffreur::config::Config;
use tokio::signal;
use tracing::info;
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("=== AgentChiffreur v{} — démarrage ===", VERSION);

    let config = Config::charger(None);
    info!(
        "[Config] port={} rotation={}s grace={}s agent_rotation='{}' session='{}'",
        config.agent_port,
        config.intervalle_rotation_sec,
        config.old_key_grace_sec,
        config.agent_rotation_autorise,
        config.chemin_session,
    );

    let (state, port) = preparer_agent(config, None, true, true).await;
    let app = build_router(state);

    let addr = format!("0.0.0.0:{port}");
    info!("Serveur HTTP sur http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Impossible de lier le port HTTP");

    axum::serve(listener, app)
        .with_graceful_shutdown(signal_arret())
        .await
        .expect("Erreur serveur HTTP");

    info!("Agent Chiffreur arrêté proprement.");
}

async fn signal_arret() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Handler Ctrl+C impossible");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Handler SIGTERM impossible")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => info!("SIGINT reçu."),
        _ = terminate => info!("SIGTERM reçu."),
    }
}

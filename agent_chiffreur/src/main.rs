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

    let config_path = std::env::var("AGENT_CONFIG").ok();
    let config = Config::charger(config_path.as_deref());
    info!(
        "[Config] port central={} decideur='{}' registry='{}'",
        config.agent_port,
        config.agent_rotation_autorise,
        config.chemin_registry,
    );

    let (state, port) = preparer_agent(config.clone()).await;
    let app = build_router(state);

    // Démarrer la supervision de l'entropie en arrière-plan
    tokio::spawn(agent_chiffreur::supervision::tache_supervision_entropie(config));

    let addr = format!("0.0.0.0:{port}");
    
    // Check if TLS is configured
    if !config.agent_cert_path.is_empty() && !config.agent_key_path.is_empty() && std::path::Path::new(&config.agent_cert_path).exists() {
        info!("Démarrage du serveur HTTPS (mTLS/TLS) sur https://{addr}");
        let tls_config = agent_chiffreur::tls_utils::build_server_tls_config(&config)
            .await
            .expect("Erreur configuration TLS/mTLS");
            
        let handle = axum_server::Handle::new();
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            signal_arret().await;
            handle_clone.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });

        axum_server::bind_rustls(addr.parse().unwrap(), tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("Erreur serveur HTTPS");
    } else {
        info!("Serveur HTTP sur http://{addr}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("Impossible de lier le port HTTP");

        axum::serve(listener, app)
            .with_graceful_shutdown(signal_arret())
            .await
            .expect("Erreur serveur HTTP");
    }

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

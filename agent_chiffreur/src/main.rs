//! Point d'entrée — Agent Chiffreur ENSPY (gRPC mTLS GANDAL, port 5004)

use std::sync::Arc;

use agent_chiffreur::app::{executer_serveur_grpc, preparer_agent};
use agent_chiffreur::config::Config;
use gandal_common::tls::{warn_if_missing, GandalPkiPaths};
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

    info!("=== AgentChiffreur v{} — gRPC mTLS GANDAL ===", VERSION);

    warn_if_missing(&GandalPkiPaths::for_chiffreur());

    let config = Config::charger(None);
    info!(
        "[Config] port gRPC={} registry='{}'",
        config.agent_port, config.chemin_registry,
    );

    let state = preparer_agent(config).await;
    let state_grpc = Arc::clone(&state);

    tokio::select! {
        res = executer_serveur_grpc(state_grpc) => {
            if let Err(e) = res {
                tracing::error!("Serveur gRPC arrêté : {e}");
            }
        }
        _ = signal_arret() => {
            info!("Arrêt demandé.");
        }
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

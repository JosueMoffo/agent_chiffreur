//! Proxy Chiffreur — une instance par VM (port 8400 par défaut).

use proxy_chiffreur::app::{build_router, preparer_proxy};
use proxy_chiffreur::config::ProxyConfig;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::var("PROXY_CONFIG").ok();
    let config = ProxyConfig::charger(config_path.as_deref());

    let activer_purge = std::env::var("PROXY_PURGE_AUTO")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let (state, port) = preparer_proxy(config.clone(), activer_purge).await;

    let proxy_url = format!("http://127.0.0.1:{}", port);
    match state
        .central
        .annoncer_proxy(
            config.local_vm_id,
            &proxy_url,
            &state.secret.public_key_hex,
        )
        .await
    {
        Ok(()) => info!(
            "[Proxy] VM {} annoncée auprès de l'agent central {}",
            config.local_vm_id, config.agent_central_url
        ),
        Err(e) => tracing::warn!(
            "[Proxy] annonce central échouée : {e} (l'agent central est-il démarré ?)"
        ),
    }

    let app = build_router(state.clone());
    let addr = format!("0.0.0.0:{port}");
    info!(
        "Proxy Chiffreur VM {} — écoute sur http://{addr} — central {}",
        config.local_vm_id, config.agent_central_url
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind port proxy");
    axum::serve(listener, app)
        .await
        .expect("serveur proxy");
}

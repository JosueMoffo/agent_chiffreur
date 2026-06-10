//! Proxy Chiffreur — HTTP 8400 (apps + relais pair) + gRPC mTLS (agent central).

use std::sync::Arc;

use gandal_common::tls::{warn_if_missing, GandalPkiPaths};
use proxy_chiffreur::app::{build_router, preparer_proxy};
use proxy_chiffreur::config::ProxyConfig;
use proxy_chiffreur::proxy_grpc::demarrer_serveur_grpc_proxy;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    warn_if_missing(&GandalPkiPaths::for_proxy());

    let config_path = std::env::var("PROXY_CONFIG").ok();
    let config = ProxyConfig::charger(config_path.as_deref());

    let activer_purge = std::env::var("PROXY_PURGE_AUTO")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let (state, http_port) = preparer_proxy(config.clone(), activer_purge).await;
    let state_grpc = Arc::clone(&state);

    let proxy_http_url = format!("http://{}:{http_port}", config.advertise_host);
    let proxy_grpc_addr = config.grpc_advertise_addr();

    match state.central.annoncer_proxy(
        config.local_vm_id,
        &proxy_http_url,
        &proxy_grpc_addr,
        &state.secret.public_key_hex,
    )
    .await
    {
        Ok(()) => info!(
            "[Proxy] VM {} annoncée (gRPC central {})",
            config.local_vm_id, config.agent_central_grpc
        ),
        Err(e) => tracing::warn!("[Proxy] annonce gRPC central : {e}"),
    }

    let grpc_addr = config.grpc_socket_addr();
    let app = build_router(state);

    info!(
        "Proxy VM {} — HTTP http://0.0.0.0:{} (pair-à-pair) | gRPC mTLS {}",
        config.local_vm_id, http_port, grpc_addr
    );

    tokio::select! {
        res = demarrer_serveur_grpc_proxy(state_grpc, grpc_addr) => {
            if let Err(e) = res {
                tracing::error!("gRPC proxy : {e}");
            }
        }
        res = async {
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{http_port}"))
                .await
                .expect("bind HTTP");
            axum::serve(listener, app).await
        } => {
            if let Err(e) = res {
                tracing::error!("HTTP proxy : {e}");
            }
        }
    }
}

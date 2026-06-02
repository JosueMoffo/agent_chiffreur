//! Démarrage du proxy chiffreur — routeur Axum et tâches de fond.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    routing::{get, post},
    Router,
};
use reqwest::Client;
use tracing::info;

use crate::central_client::ClientCentral;
use crate::config::ProxyConfig;
use crate::crypto_moteur::CryptoMoteur;
use crate::proxy_cle_vm::ProxyVmSecret;
use crate::proxy_http::{
    assurer_session_locale, handle_decrypt, handle_ecdh_initiate, handle_encrypt,
    handle_generate_password, handle_health, handle_proxy_inbound, handle_proxy_relay,
    handle_proxy_sessions_list, handle_public_key, handle_secret_strength,
    handle_vm_delete, handle_vm_list, handle_vm_purge_expired, handle_vm_session_register,
    ProxyState, SharedProxyState, CHEMIN_PROXY_SESSION_DEFAUT,
};
use crate::proxy_sessions::GestionnaireProxySessions;
use crate::sessions_vm::{tache_purge_cles, GestionnaireSessionsVm};

/// Construit le routeur Axum avec toutes les routes du proxy.
pub fn build_router(state: SharedProxyState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/public-key", get(handle_public_key))
        .route("/vm/session/register", post(handle_vm_session_register))
        .route("/vm/session/delete", post(handle_vm_delete))
        .route("/vm/sessions", get(handle_vm_list))
        .route("/vm/sessions/purge-expired", post(handle_vm_purge_expired))
        .route("/encrypt", post(handle_encrypt))
        .route("/decrypt", post(handle_decrypt))
        .route("/ecdh/initiate", post(handle_ecdh_initiate))
        .route("/password/generate", post(handle_generate_password))
        .route("/secret/strength", post(handle_secret_strength))
        .route("/proxy/relay", post(handle_proxy_relay))
        .route("/proxy/inbound", post(handle_proxy_inbound))
        .route("/proxy/sessions", get(handle_proxy_sessions_list))
        .with_state(state)
}

/// Charge la config, les secrets, les gestionnaires de session et retourne l'état + le port.
pub async fn preparer_proxy(
    config: ProxyConfig,
    activer_purge_auto: bool,
) -> (SharedProxyState, u16) {
    let secret = ProxyVmSecret::charger_ou_creer(&config.chemin_cle_privee, config.local_vm_id)
        .expect("clé X25519 proxy");

    let sessions_vm = GestionnaireSessionsVm::nouveau(
        &config.chemin_session,
        config.old_key_grace_sec,
    );

    let proxy_sessions = GestionnaireProxySessions::nouveau(
        CHEMIN_PROXY_SESSION_DEFAUT,
        config.local_vm_id,
    );

    let state = Arc::new(ProxyState {
        config: config.clone(),
        secret,
        sessions_vm: Arc::clone(&sessions_vm),
        proxy_sessions,
        central: ClientCentral::new(&config),
        http: Client::new(),
        crypto_moteur: CryptoMoteur::new(),
        requetes: AtomicU64::new(0),
        erreurs: AtomicU64::new(0),
        start_time: Instant::now(),
    });

    if let Err(e) = assurer_session_locale(state.as_ref()).await {
        tracing::warn!("[Proxy] session locale : {e}");
    }

    if activer_purge_auto {
        let sessions_purge = Arc::clone(&sessions_vm);
        tokio::spawn(tache_purge_cles(sessions_purge, 30));
        info!("[Proxy] tâche de purge des old_key expirées activée (30s).");
    }

    let port = config.listen_port;
    (state, port)
}

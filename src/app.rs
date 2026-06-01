//! Démarrage du serveur HTTP et des tâches de fond.

use std::sync::Arc;

use axum::{middleware, routing::{get, post}, Router};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::agent_http::{
    handle_decrypt, handle_ecdh_initiate, handle_encrypt, handle_generate_password,
    handle_health, handle_keystore_status, handle_metrics, handle_public_key,
    handle_rotate, handle_secret_strength, handle_vm_delete, handle_vm_list,
    handle_vm_purge_expired, handle_vm_register, middleware_token, AppState,
};
use crate::config::Config;
use crate::gestionnaire_rotation::GestionnaireRotation;
use crate::rotation_vm::tache_rotation_vms_automatique;
use crate::sessions_vm::{tache_purge_cles, GestionnaireSessionsVm};
use crate::trousseau::Trousseau;
use crate::xmpp_sim::EnveloppeMessage;

/// Construit le routeur Axum avec l'état partagé.
pub fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/encrypt", post(handle_encrypt))
        .route("/decrypt", post(handle_decrypt))
        .route("/ecdh/initiate", post(handle_ecdh_initiate))
        .route("/password/generate", post(handle_generate_password))
        .route("/secret/strength", post(handle_secret_strength))
        .route("/vm/session/register", post(handle_vm_register))
        .route("/vm/session/delete", post(handle_vm_delete))
        .route("/vm/sessions", get(handle_vm_list))
        .route("/vm/sessions/purge-expired", post(handle_vm_purge_expired))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware_token,
        ));

    let rotation = Router::new().route("/credential/rotate", post(handle_rotate));

    let public = Router::new()
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/public-key", get(handle_public_key))
        .route("/keystore/status", get(handle_keystore_status));

    protected
        .merge(rotation)
        .merge(public)
        .with_state(state)
}

/// Initialise l'état, les tâches de fond et retourne le routeur + le port d'écoute.
pub async fn preparer_agent(
    config: Config,
    chemin_blobs: Option<&str>,
    activer_rotation_auto: bool,
    activer_purge_auto: bool,
) -> (Arc<AppState>, u16) {
    let trousseau = Trousseau::nouveau(None).expect("Impossible d'initialiser le trousseau");
    let chemin_blobs = chemin_blobs.unwrap_or("data/blobs_store.json");
    let gestionnaire = GestionnaireRotation::nouveau(trousseau, Some(chemin_blobs));

    let sessions_vm = GestionnaireSessionsVm::nouveau(
        &config.chemin_session,
        config.old_key_grace_sec,
    );

    let (requete_tx, requete_rx) = mpsc::channel::<EnveloppeMessage>(64);
    let (alerte_tx, alerte_rx) = mpsc::channel::<String>(64);

    let state = Arc::new(AppState::new(
        config.clone(),
        requete_tx,
        Arc::clone(&gestionnaire),
        Arc::clone(&sessions_vm),
    ));

    let state_d = Arc::clone(&state);
    let alerte_d = alerte_tx.clone();
    let token_dispatch = config.agent_token.clone();
    tokio::spawn(async move {
        let mut rx = requete_rx;
        while let Some(msg) = rx.recv().await {
            let rep_tx = msg.reponse_tx.clone();
            let rep = crate::xmpp_sim::dispatch_requete(
                &msg,
                &state_d.crypto,
                &alerte_d,
                &token_dispatch,
            )
            .await;
            if let Some(tx) = rep_tx {
                let _ = tx.send(rep).await;
            }
        }
    });

    let url_aud = config.agent_auditeur_url.clone();
    let token_aud = config.agent_token.clone();
    tokio::spawn(async move {
        let mut rx = alerte_rx;
        while let Some(alerte) = rx.recv().await {
            warn!("[AUDITEUR] {}", alerte);
            if let Some(ref url) = url_aud {
                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&alerte) {
                    crate::notificateur::notifier_agent(url, &token_aud, payload).await;
                }
            }
        }
    });

    let alerte_sup = alerte_tx.clone();
    tokio::spawn(superviser_entropie(
        config.intervalle_supervision_sec,
        config.seuil_entropie,
        alerte_sup,
    ));

    if activer_rotation_auto {
        let sessions_rot = Arc::clone(&sessions_vm);
        let token_rot = config.agent_token.clone();
        let intervalle_rot = config.intervalle_rotation_sec;
        tokio::spawn(tache_rotation_vms_automatique(
            sessions_rot,
            token_rot,
            intervalle_rot,
        ));
    }

    if activer_purge_auto {
        let sessions_purge = Arc::clone(&sessions_vm);
        tokio::spawn(tache_purge_cles(sessions_purge, 30));
    }

    (state, config.agent_port)
}

async fn superviser_entropie(
    intervalle_sec: u64,
    seuil: u32,
    tx: mpsc::Sender<String>,
) {
    use rand::Rng;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(intervalle_sec));
    loop {
        interval.tick().await;
        let pool: u32 = rand::thread_rng().gen_range(128..=512);
        if pool < seuil {
            warn!("[SUPERVISION] Pool entropie critique : {} octets", pool);
            let _ = tx
                .send(
                    serde_json::json!({
                        "message_type": "log_event",
                        "source_agent": "chiffreur",
                        "event_type": "LOW_ENTROPY_POOL",
                        "data": { "severity": "CRITICAL", "entropy_bytes": pool }
                    })
                    .to_string(),
                )
                .await;
        }
    }
}

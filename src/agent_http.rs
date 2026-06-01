//! # Serveur HTTP — Agent Chiffreur ENSPY (port 5004)
//!
//! | Méthode | Endpoint               | Auth          | Description                      |
//! |---------|------------------------|---------------|----------------------------------|
//! | POST    | `/vm/session/register` | Token         | Enregistrer une VM + clé initiale|
//! | POST    | `/vm/session/delete`   | Token         | Supprimer une session VM         |
//! | GET     | `/vm/sessions`         | Token         | Lister les sessions actives      |
//! | POST    | `/encrypt`             | Token         | Chiffrement AES-256-GCM (clé VM `new_key`) |
//! | POST    | `/decrypt`             | Token         | Déchiffrement VM (`new_key` puis `old_key` si grâce) |
//! | POST    | `/credential/rotate`   | X-Agent-Name  | Rotation ECDH de toutes les VMs  |
//! | POST    | `/ecdh/initiate`       | Token         | Échange ECDH X25519              |
//! | POST    | `/password/generate`   | Token         | Génération mot de passe fort     |
//! | POST    | `/secret/strength`     | Token         | Évaluation force d'un secret     |
//! | POST    | `/vm/sessions/purge-expired` | Token   | Purge des old_key expirées       |
//! | GET     | `/public-key`          | —             | Clé publique X25519              |
//! | GET     | `/health`              | —             | Statut + uptime                  |
//! | GET     | `/metrics`             | —             | Métriques runtime                |
//! | GET     | `/keystore/status`     | —             | Résumé trousseau                 |

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sysinfo::System;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::crypto_moteur::{CryptoMoteur, OptionsMotDePasse};
use crate::gestionnaire_rotation::GestionnaireRotation;
use crate::rotation_vm::{effectuer_rotation_toutes_vms, RapportRotationVms};
use crate::crypto_moteur::{chiffrer_aes_gcm_avec_cle, dechiffrer_aes_gcm_vm, decoder_cle_aes_hex};
use crate::sessions_vm::{parse_vm_id_json, valider_vm_id, GestionnaireSessionsVm};
use crate::xmpp_sim::EnveloppeMessage;

// ── État partagé ──────────────────────────────────────────────────────────────

pub struct AppState {
    pub crypto:       CryptoMoteur,
    pub gestionnaire: Arc<GestionnaireRotation>,
    /// Gestionnaire des sessions VM (nouveau — remplace .env pour les clés AES)
    pub sessions_vm:  Arc<GestionnaireSessionsVm>,
    pub requetes:     std::sync::atomic::AtomicU64,
    pub erreurs:      std::sync::atomic::AtomicU64,
    pub start_time:   Instant,
    pub config:       Config,
    pub requete_tx:   mpsc::Sender<EnveloppeMessage>,
}

impl AppState {
    pub fn new(
        config: Config,
        requete_tx: mpsc::Sender<EnveloppeMessage>,
        gestionnaire: Arc<GestionnaireRotation>,
        sessions_vm: Arc<GestionnaireSessionsVm>,
    ) -> Self {
        let crypto = CryptoMoteur::new();
        Self {
            crypto,
            gestionnaire,
            sessions_vm,
            requetes: std::sync::atomic::AtomicU64::new(0),
            erreurs:  std::sync::atomic::AtomicU64::new(0),
            start_time: Instant::now(),
            config,
            requete_tx,
        }
    }

    pub fn inc_requetes(&self) { self.requetes.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    pub fn inc_erreurs(&self)  { self.erreurs.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
}

pub type SharedState = Arc<AppState>;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn new_rid(body: &Value) -> String {
    body.get("request_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Extrait et valide `vm_id` depuis le corps JSON.
fn extraire_vm_id(body: &Value, rid: &str) -> Result<u32, Response> {
    let raw = match body.get("vm_id") {
        Some(v) => v,
        None => {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                rid,
                "INVALID_REQUEST",
                "Le champ 'vm_id' est obligatoire (entier > 100).",
            ));
        }
    };
    let vm_id = match parse_vm_id_json(raw) {
        Some(id) => id,
        None => {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                rid,
                "INVALID_REQUEST",
                "Le champ 'vm_id' doit être un entier ou une chaîne numérique.",
            ));
        }
    };
    if let Err(e) = valider_vm_id(vm_id) {
        return Err(err_resp(StatusCode::BAD_REQUEST, rid, "INVALID_REQUEST", &e));
    }
    Ok(vm_id)
}

fn err_resp(status: StatusCode, rid: &str, code: &str, desc: &str) -> Response {
    (status, Json(json!({
        "request_id": rid,
        "message_type": "error_response",
        "status": "error",
        "error": code,
        "description": desc,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

// ── Middleware token ──────────────────────────────────────────────────────────

/// Passe-through : `X-Agent-Token` est optionnel et toute valeur est acceptée.
pub async fn middleware_token(
    _state: State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    next.run(request).await
}

// ── POST /vm/session/register ─────────────────────────────────────────────────

/// Enregistre une nouvelle session VM.
///
/// Corps attendu :
/// ```json
/// {
///   "vm_id": 101,
///   "public_key": "<64 hex chars X25519>",
///   "url_notification": "http://10.0.0.1:9000/key-update"
/// }
/// ```
pub async fn handle_vm_register(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            state.inc_erreurs();
            return err_resp(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'vm_id' est obligatoire (entier > 100, style Proxmox).",
            );
        }
    };

    if let Err(msg) = valider_vm_id(vm_id) {
        state.inc_erreurs();
        return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &msg);
    }

    let public_key = match body
        .get("public_key")
        .or_else(|| body.get("vm_pub_key_hex"))
        .and_then(|v| v.as_str())
        .filter(|s| s.len() == 64)
    {
        Some(k) => k.to_owned(),
        None => {
            state.inc_erreurs();
            return err_resp(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'public_key' est obligatoire (64 hex chars = clé X25519 32 octets).",
            );
        }
    };

    let url_notification = body.get("url_notification").and_then(|v| v.as_str()).map(|s| s.to_owned());

    let vm_pub_bytes = match crate::crypto_moteur::decoder_cle_publique_x25519(&public_key) {
        Ok(b) => b,
        Err(e) => {
            state.inc_erreurs();
            return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string());
        }
    };

    // Nouvelle paire éphémère agent + ECDH à chaque enregistrement de session
    let echange = match crate::crypto_moteur::ecdh_session_ephemere(&vm_pub_bytes) {
        Ok(e) => e,
        Err(e) => {
            state.inc_erreurs();
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "CRYPTO_ERROR", &e.to_string());
        }
    };
    // SECURITY: ne pas logguer new_key_hex
    let new_key_hex = hex::encode(echange.shared_secret);
    let agent_ephemeral_pub = echange.agent_public_key_hex;

    match state
        .sessions_vm
        .enregistrer_session(
            vm_id,
            public_key,
            agent_ephemeral_pub.clone(),
            new_key_hex,
            url_notification,
        )
        .await
    {
        Ok(resume) => {
            info!(
                "POST /vm/session/register — vm_id={} enregistrée, paire éphémère agent (rid={})",
                vm_id, rid
            );
            (StatusCode::CREATED, Json(json!({
                "request_id": rid,
                "message_type": "vm_session_register_response",
                "status": "success",
                "vm_id": resume.vm_id,
                "agent_ephemeral_public_key_hex": agent_ephemeral_pub,
                "new_key_id": resume.new_key_id,
                "rotation_count": resume.rotation_count,
                "note": "Nouvelle paire X25519 éphémère agent générée. La VM doit faire ECDH(priv_VM, agent_ephemeral_public_key_hex) pour obtenir new_key.",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))).into_response()
        }
        Err(e) => {
            state.inc_erreurs();
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "STORE_ERROR", &e)
        }
    }
}

// ── POST /vm/session/delete ───────────────────────────────────────────────────

pub async fn handle_vm_delete(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);
    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            return err_resp(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "vm_id obligatoire (entier > 100).",
            );
        }
    };

    let supprimee = state.sessions_vm.supprimer_session(vm_id).await;
    if supprimee {
        info!(
            "POST /vm/session/delete — vm_id={} supprimée (rid={})",
            vm_id, rid
        );
        (StatusCode::OK, Json(json!({
            "request_id": rid, "message_type": "vm_session_delete_response",
            "status": "success", "vm_id": vm_id,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))).into_response()
    } else {
        err_resp(
            StatusCode::NOT_FOUND,
            &rid,
            "NOT_FOUND",
            &format!("VM {vm_id} introuvable."),
        )
    }
}

// ── POST /vm/sessions/purge-expired ───────────────────────────────────────────

pub async fn handle_vm_purge_expired(State(state): State<SharedState>) -> Response {
    state.inc_requetes();
    let nb = state.sessions_vm.purger_cles_expirees().await;
    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "vm_sessions_purge_response",
        "status": "success",
        "cles_purgees": nb,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
    .into_response()
}

// ── GET /vm/sessions ──────────────────────────────────────────────────────────

pub async fn handle_vm_list(State(state): State<SharedState>) -> Response {
    let sessions = state.sessions_vm.lister_sessions().await;
    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "vm_sessions_list_response",
        "status": "ok",
        "count": sessions.len(),
        "sessions": sessions,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

// ── POST /encrypt ─────────────────────────────────────────────────────────────
//
// Chiffre avec la `new_key` AES de la VM identifiée par `vm_id` (session.json).

pub async fn handle_encrypt(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match extraire_vm_id(&body, &rid) {
        Ok(id) => id,
        Err(r) => {
            state.inc_erreurs();
            return r;
        }
    };

    let plaintext = match body.get("plaintext").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        Some(p) => p,
        None => {
            state.inc_erreurs();
            return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST",
                "Le champ 'plaintext' est obligatoire et non vide.");
        }
    };

    let (new_key_hex, _) = match state.sessions_vm.get_cles_aes_vm(vm_id).await {
        Ok(k) => k,
        Err(e) => {
            state.inc_erreurs();
            return err_resp(StatusCode::NOT_FOUND, &rid, "VM_NOT_FOUND", &e);
        }
    };

    let cle = match decoder_cle_aes_hex(&new_key_hex) {
        Ok(k) => k,
        Err(e) => {
            state.inc_erreurs();
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "CRYPTO_ERROR", &e.to_string());
        }
    };

    match chiffrer_aes_gcm_avec_cle(&cle, plaintext) {
        Ok(donnees) => {
            let resume = state.sessions_vm.get_resume_vm(vm_id).await;
            let new_key_id = resume
                .as_ref()
                .map(|r| r.new_key_id.clone())
                .unwrap_or_else(|| format!("k_{}", &new_key_hex[..8.min(new_key_hex.len())]));
            info!("POST /encrypt — vm_id={} chiffré (rid={})", vm_id, rid);
            (StatusCode::OK, Json(json!({
                "request_id": rid,
                "message_type": "encryption_response",
                "status": "success",
                "vm_id": vm_id,
                "new_key_id": new_key_id,
                "ciphertext": donnees.ciphertext,
                "iv": donnees.iv,
                "auth_tag": donnees.auth_tag,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))).into_response()
        }
        Err(e) => {
            state.inc_erreurs();
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "CRYPTO_ERROR", &e.to_string())
        }
    }
}

// ── POST /decrypt ─────────────────────────────────────────────────────────────
//
// Déchiffre avec `new_key`, puis `old_key` si encore dans la période de grâce.

pub async fn handle_decrypt(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match extraire_vm_id(&body, &rid) {
        Ok(id) => id,
        Err(r) => {
            state.inc_erreurs();
            return r;
        }
    };

    let ciphertext = body.get("ciphertext").and_then(|v| v.as_str()).unwrap_or("");
    let iv = body.get("iv").and_then(|v| v.as_str()).unwrap_or("");
    let auth_tag = body.get("auth_tag").and_then(|v| v.as_str()).unwrap_or("");

    if ciphertext.is_empty() || iv.is_empty() || auth_tag.is_empty() {
        state.inc_erreurs();
        return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST",
            "Les champs 'ciphertext', 'iv', 'auth_tag' sont obligatoires.");
    }

    let (new_key_hex, old_key_hex) = match state.sessions_vm.get_cles_aes_vm(vm_id).await {
        Ok(k) => k,
        Err(e) => {
            state.inc_erreurs();
            return err_resp(StatusCode::NOT_FOUND, &rid, "VM_NOT_FOUND", &e);
        }
    };

    match dechiffrer_aes_gcm_vm(
        &new_key_hex,
        old_key_hex.as_deref(),
        ciphertext,
        iv,
        auth_tag,
    ) {
        Ok((plaintext, key_used)) => {
            info!(
                "POST /decrypt — vm_id={} déchiffré avec clé '{}' (rid={})",
                vm_id, key_used, rid
            );
            (StatusCode::OK, Json(json!({
                "request_id": rid,
                "message_type": "decryption_response",
                "status": "success",
                "vm_id": vm_id,
                "key_used": key_used,
                "plaintext": plaintext,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))).into_response()
        }
        Err(crate::error::CryptoError::IntegriteEchouee) => {
            state.inc_erreurs();
            err_resp(StatusCode::BAD_REQUEST, &rid, "CRYPTO_ERROR",
                "Échec de vérification d'intégrité GCM : données corrompues ou falsifiées.")
        }
        Err(e) => {
            state.inc_erreurs();
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "CRYPTO_ERROR", &e.to_string())
        }
    }
}

// ── POST /credential/rotate ───────────────────────────────────────────────────
//
// Nouvelle logique :
//   1. Vérifie que X-Agent-Name == config.agent_rotation_autorise
//   2. Pour chaque VM enregistrée :
//      a. ecdh_partager(vm.vm_pub_key_hex) → nouveau_secret
//      b. vm.old_key ← vm.new_key ; vm.new_key ← nouveau_secret
//      c. Notifie la VM via HTTP POST url_notification
//   3. Retourne le rapport de rotation

pub async fn handle_rotate(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let rid = body.as_ref()
        .and_then(|Json(v)| v.get("request_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Vérification du nom d'agent (pas de super-token)
    let agent_name = headers
        .get("X-Agent-Name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if agent_name != state.config.agent_rotation_autorise {
        warn!("POST /credential/rotate — refusé : agent_name='{}' (attendu='{}')",
            agent_name, state.config.agent_rotation_autorise);
        return err_resp(StatusCode::FORBIDDEN, &rid, "FORBIDDEN",
            &format!("Seul l'agent '{}' est autorisé à déclencher la rotation.",
                state.config.agent_rotation_autorise));
    }

    info!("POST /credential/rotate — rotation ECDH demandée par agent='{}' (rid={})",
        agent_name, rid);

    let rapport: RapportRotationVms = effectuer_rotation_toutes_vms(
        Arc::clone(&state.sessions_vm),
        &state.config.agent_token,
    ).await;

    (StatusCode::OK, Json(json!({
        "request_id": rid,
        "message_type": "credential_rotate_response",
        "status": "success",
        "rotation_id": rapport.rotation_id,
        "vms_total": rapport.vms_total,
        "vms_reussies": rapport.vms_reussies,
        "vms_echecs": rapport.vms_echecs,
        "vms_notifiees": rapport.vms_notifiees,
        "resultats": rapport.resultats,
        "timestamp": rapport.timestamp.to_rfc3339()
    }))).into_response()
}

// ── GET /keystore/status ──────────────────────────────────────────────────────

pub async fn handle_keystore_status(State(state): State<SharedState>) -> Response {
    let resume = state.gestionnaire.resume_trousseau().await;
    let sessions = state.sessions_vm.lister_sessions().await;
    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "keystore_status_response",
        "status": "ok",
        "trousseau": {
            "key_id_actif": resume.key_id_actif,
            "version_active": resume.version_active,
            "nb_cles_archivees": resume.nb_cles_archivees,
        },
        "session_json": {
            "chemin": state.config.chemin_session,
            "count": sessions.len(),
            "sessions": sessions,
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

// ── GET /public-key ───────────────────────────────────────────────────────────

pub async fn handle_public_key(State(state): State<SharedState>) -> Response {
    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "public_key_response",
        "agent_id": "chiffreur",
        "public_key_hex": state.crypto.get_public_key_hex(),
        "algorithm": "X25519",
        "note": "Clé statique legacy. Pour les sessions VM, utiliser agent_ephemeral_public_key_hex renvoyé par POST /vm/session/register ou la notification de rotation.",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

// ── POST /ecdh/initiate ───────────────────────────────────────────────────────

pub async fn handle_ecdh_initiate(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);
    let peer_id = body.get("peer_agent_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_owned();

    let peer_hex = match body.get("peer_public_key_hex").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        Some(h) => h.to_owned(),
        None => {
            state.inc_erreurs();
            return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST",
                "Le champ 'peer_public_key_hex' est obligatoire.");
        }
    };

    let peer_bytes = match crate::crypto_moteur::decoder_cle_publique_x25519(&peer_hex) {
        Ok(b) => b,
        Err(e) => {
            return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string());
        }
    };

    match crate::crypto_moteur::ecdh_session_ephemere(&peer_bytes) {
        Ok(echange) => {
            let shared_hex = hex::encode(echange.shared_secret);
            info!(
                "POST /ecdh/initiate — paire éphémère générée, peer={} (rid={})",
                peer_id, rid
            );
            (StatusCode::OK, Json(json!({
                "request_id": rid,
                "message_type": "ecdh_response",
                "status": "success",
                "peer_agent_id": peer_id,
                "agent_ephemeral_public_key_hex": echange.agent_public_key_hex,
                "shared_secret_hex": shared_hex,
                "note": "Nouvelle paire X25519 éphémère par appel. Utilisez shared_secret_hex comme clé AES-256 ou entrée HKDF.",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))).into_response()
        }
        Err(e) => {
            state.inc_erreurs();
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &rid, "CRYPTO_ERROR", &e.to_string())
        }
    }
}

// ── POST /secret/strength ─────────────────────────────────────────────────────

pub async fn handle_secret_strength(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);

    let secret = match body.get("secret").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            state.inc_erreurs();
            return err_resp(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'secret' est obligatoire.",
            );
        }
    };

    let force = state.crypto.evaluer_force(secret);
    (StatusCode::OK, Json(json!({
        "request_id": rid,
        "message_type": "secret_strength_response",
        "status": "success",
        "score": force.score,
        "details": force.details,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
    .into_response()
}

// ── POST /password/generate ───────────────────────────────────────────────────

pub async fn handle_generate_password(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Response {
    state.inc_requetes();
    let rid = new_rid(&body);

    let longueur     = body.get("longueur").and_then(|v| v.as_u64()).unwrap_or(24) as usize;
    let majuscules   = body.get("majuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let minuscules   = body.get("minuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let chiffres     = body.get("chiffres").and_then(|v| v.as_bool()).unwrap_or(true);
    let symboles     = body.get("symboles").and_then(|v| v.as_bool()).unwrap_or(true);
    let excl_ambigus = body.get("exclure_ambigus").and_then(|v| v.as_bool()).unwrap_or(false);

    if !majuscules && !minuscules && !chiffres && !symboles {
        state.inc_erreurs();
        return err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST",
            "Au moins un groupe de caractères doit être activé.");
    }

    let opts = OptionsMotDePasse { longueur, majuscules, minuscules, chiffres, symboles,
        exclure_ambigus: excl_ambigus };

    match state.crypto.generer_mot_de_passe(&opts) {
        Ok(pwd) => {
            let force = state.crypto.evaluer_force(&pwd);
            (StatusCode::OK, Json(json!({
                "request_id": rid,
                "message_type": "password_generate_response",
                "status": "success",
                "password": pwd,
                "longueur": longueur,
                "score": force.score,
                "details": force.details,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))).into_response()
        }
        Err(e) => {
            state.inc_erreurs();
            err_resp(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string())
        }
    }
}

// ── GET /health ───────────────────────────────────────────────────────────────

pub async fn handle_health(State(state): State<SharedState>) -> Response {
    let resume = state.gestionnaire.resume_trousseau().await;
    let nb_vms = state.sessions_vm.lister_sessions().await.len();
    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "health_response",
        "status": "ok",
        "uptime_sec": state.start_time.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "key_id_actif": resume.key_id_actif,
        "version_cle": resume.version_active,
        "vms_en_session": nb_vms,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

// ── GET /metrics ──────────────────────────────────────────────────────────────

pub async fn handle_metrics(State(state): State<SharedState>) -> Response {
    let mut sys = System::new_all();
    sys.refresh_all();
    let pid = sysinfo::get_current_pid().ok();
    let memory_mb = pid.and_then(|p| sys.process(p))
        .map(|p| p.memory() as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);
    let cpu = sys.global_cpu_info().cpu_usage();
    let resume = state.gestionnaire.resume_trousseau().await;
    let nb_vms = state.sessions_vm.lister_sessions().await.len();

    (StatusCode::OK, Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "metrics_response",
        "status": "ok",
        "requests_handled": state.requetes.load(std::sync::atomic::Ordering::Relaxed),
        "errors_count":     state.erreurs.load(std::sync::atomic::Ordering::Relaxed),
        "memory_mb": (memory_mb * 100.0).round() / 100.0,
        "cpu_percent": cpu,
        "keystore": { "version_active": resume.version_active },
        "vms_en_session": nb_vms,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

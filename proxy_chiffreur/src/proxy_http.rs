//! Serveur HTTP du proxy chiffreur — crypto locale, relais inter-VM (port 8400).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use crate::central_client::ClientCentral;
use crate::config::ProxyConfig;
use crate::crypto_moteur::{
    chiffrer_aes_gcm_avec_cle, dechiffrer_aes_gcm_vm, decoder_cle_aes_hex, decoder_cle_publique_x25519,
    ecdh_session_ephemere, CryptoMoteur, OptionsMotDePasse,
};
use crate::error::CryptoError;
use crate::proxy_cle_vm::ProxyVmSecret;
use crate::proxy_sessions::GestionnaireProxySessions;
use crate::rotation_vm::{effectuer_rotation_toutes_vms, RapportRotationVms};
use crate::sessions_vm::{parse_vm_id_json, valider_vm_id, GestionnaireSessionsVm};

pub const CHEMIN_PROXY_SESSION_DEFAUT: &str = "data/proxy_session.json";

pub struct ProxyState {
    pub config: ProxyConfig,
    pub secret: ProxyVmSecret,
    pub sessions_vm: Arc<GestionnaireSessionsVm>,
    pub proxy_sessions: Arc<GestionnaireProxySessions>,
    pub central: ClientCentral,
    pub http: Client,
    pub crypto_moteur: CryptoMoteur,
    pub requetes: AtomicU64,
    pub erreurs: AtomicU64,
    pub start_time: Instant,
}

impl ProxyState {
    pub fn inc_requetes(&self) {
        self.requetes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_erreurs(&self) {
        self.erreurs.fetch_add(1, Ordering::Relaxed);
    }
}

pub type SharedProxyState = Arc<ProxyState>;

fn new_rid(body: &Value) -> String {
    body.get("request_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn err(status: StatusCode, code: &str, desc: &str) -> Response {
    (
        status,
        Json(json!({
            "status": "error",
            "error": code,
            "description": desc,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

fn err_rid(status: StatusCode, rid: &str, code: &str, desc: &str) -> Response {
    (
        status,
        Json(json!({
            "request_id": rid,
            "message_type": "error_response",
            "status": "error",
            "error": code,
            "description": desc,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

fn extraire_vm_id(body: &Value, rid: &str) -> Result<u32, Response> {
    let raw = match body.get("vm_id") {
        Some(v) => v,
        None => {
            return Err(err_rid(
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
            return Err(err_rid(
                StatusCode::BAD_REQUEST,
                rid,
                "INVALID_REQUEST",
                "Le champ 'vm_id' doit être un entier ou une chaîne numérique.",
            ));
        }
    };
    if let Err(e) = valider_vm_id(vm_id) {
        return Err(err_rid(StatusCode::BAD_REQUEST, rid, "INVALID_REQUEST", &e));
    }
    Ok(vm_id)
}

// ── GET /health ───────────────────────────────────────────────────────────────

pub async fn handle_health(State(st): State<SharedProxyState>) -> impl IntoResponse {
    st.inc_requetes();
    let peers = st.proxy_sessions.lister_peers().await;
    let nb_vms = st.sessions_vm.lister_sessions().await.len();
    Json(json!({
        "status": "ok",
        "message_type": "health_response",
        "local_vm_id": st.config.local_vm_id,
        "agent_central_url": st.config.agent_central_url,
        "peers_count": peers.len(),
        "vms_en_session": nb_vms,
        "uptime_sec": st.start_time.elapsed().as_secs(),
        "requests_handled": st.requetes.load(Ordering::Relaxed),
        "errors_count": st.erreurs.load(Ordering::Relaxed),
        "public_key_preview": format!("{}...", &st.secret.public_key_hex[..16]),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ── POST /vm/session/register ─────────────────────────────────────────────────

pub async fn handle_vm_session_register(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "vm_id obligatoire (entier > 100).",
            );
        }
    };

    if let Err(e) = valider_vm_id(vm_id) {
        st.inc_erreurs();
        return err_rid(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e);
    }

    let public_key = match body
        .get("public_key")
        .or_else(|| body.get("vm_pub_key_hex"))
        .and_then(|v| v.as_str())
        .filter(|s| s.len() == 64)
    {
        Some(k) => k.to_owned(),
        None => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "public_key obligatoire (64 hex).",
            );
        }
    };

    let url_notification = body
        .get("url_notification")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let vm_pub_bytes = match decoder_cle_publique_x25519(&public_key) {
        Ok(b) => b,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string());
        }
    };

    let echange = match ecdh_session_ephemere(&vm_pub_bytes) {
        Ok(e) => e,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::INTERNAL_SERVER_ERROR,
                &rid,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    let new_key_hex = hex::encode(echange.shared_secret);
    let agent_ephemeral_pub = echange.agent_public_key_hex.clone();

    match st
        .sessions_vm
        .enregistrer_session(
            vm_id,
            public_key.clone(),
            agent_ephemeral_pub.clone(),
            new_key_hex,
            url_notification,
        )
        .await
    {
        Ok(resume) => {
            if let Err(e) = st
                .central
                .sync_vm_session(vm_id, &public_key, st.config.local_vm_id)
                .await
            {
                warn!("[Proxy] sync central vm_id={vm_id} : {e}");
            }

            let peer_url = body
                .get("peer_proxy_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !peer_url.is_empty() {
                if let Err(e) = st
                    .proxy_sessions
                    .enregistrer_peer(vm_id, peer_url, &public_key)
                    .await
                {
                    warn!("[Proxy] enregistrement peer local : {e}");
                }
            }

            info!("[Proxy] POST /vm/session/register — vm_id={vm_id} (rid={rid})");
            (
                StatusCode::CREATED,
                Json(json!({
                    "request_id": rid,
                    "message_type": "vm_session_register_response",
                    "status": "success",
                    "vm_id": resume.vm_id,
                    "agent_ephemeral_public_key_hex": agent_ephemeral_pub,
                    "new_key_id": resume.new_key_id,
                    "rotation_count": resume.rotation_count,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Err(e) => {
            st.inc_erreurs();
            err_rid(StatusCode::INTERNAL_SERVER_ERROR, &rid, "STORE_ERROR", &e)
        }
    }
}

// ── POST /vm/session/delete ───────────────────────────────────────────────────

pub async fn handle_vm_delete(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);
    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "vm_id obligatoire (entier > 100).",
            );
        }
    };

    if st.sessions_vm.supprimer_session(vm_id).await {
        info!("[Proxy] POST /vm/session/delete — vm_id={vm_id}");
        (
            StatusCode::OK,
            Json(json!({
                "request_id": rid,
                "message_type": "vm_session_delete_response",
                "status": "success",
                "vm_id": vm_id,
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        )
            .into_response()
    } else {
        st.inc_erreurs();
        err_rid(
            StatusCode::NOT_FOUND,
            &rid,
            "NOT_FOUND",
            &format!("VM {vm_id} introuvable."),
        )
    }
}

// ── GET /vm/sessions ──────────────────────────────────────────────────────────

pub async fn handle_vm_list(State(st): State<SharedProxyState>) -> impl IntoResponse {
    st.inc_requetes();
    let sessions = st.sessions_vm.lister_sessions().await;
    Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "vm_sessions_list_response",
        "status": "ok",
        "count": sessions.len(),
        "sessions": sessions,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ── POST /vm/sessions/purge-expired ───────────────────────────────────────────

pub async fn handle_vm_purge_expired(State(st): State<SharedProxyState>) -> impl IntoResponse {
    st.inc_requetes();
    let nb = st.sessions_vm.purger_cles_expirees().await;
    info!("[Proxy] POST /vm/sessions/purge-expired — {nb} clé(s) purgée(s)");
    Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "vm_sessions_purge_response",
        "status": "success",
        "cles_purgees": nb,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ── POST /encrypt ─────────────────────────────────────────────────────────────

pub async fn handle_encrypt(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match extraire_vm_id(&body, &rid) {
        Ok(id) => id,
        Err(r) => {
            st.inc_erreurs();
            return r;
        }
    };

    let plaintext = match body.get("plaintext").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        Some(p) => p,
        None => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'plaintext' est obligatoire et non vide.",
            );
        }
    };

    let (new_key_hex, _) = match st.sessions_vm.get_cles_aes_vm(vm_id).await {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(StatusCode::NOT_FOUND, &rid, "VM_NOT_FOUND", &e);
        }
    };

    let cle = match decoder_cle_aes_hex(&new_key_hex) {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::INTERNAL_SERVER_ERROR,
                &rid,
                "CRYPTO_ERROR",
                &e.to_string(),
            );
        }
    };

    match chiffrer_aes_gcm_avec_cle(&cle, plaintext) {
        Ok(donnees) => {
            info!("[Proxy] POST /encrypt — vm_id={vm_id} (rid={rid})");
            (
                StatusCode::OK,
                Json(json!({
                    "request_id": rid,
                    "message_type": "encryption_response",
                    "status": "success",
                    "vm_id": vm_id,
                    "ciphertext": donnees.ciphertext,
                    "iv": donnees.iv,
                    "auth_tag": donnees.auth_tag,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Err(e) => {
            st.inc_erreurs();
            err_rid(
                StatusCode::INTERNAL_SERVER_ERROR,
                &rid,
                "CRYPTO_ERROR",
                &e.to_string(),
            )
        }
    }
}

// ── POST /decrypt ─────────────────────────────────────────────────────────────

pub async fn handle_decrypt(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);

    let vm_id = match extraire_vm_id(&body, &rid) {
        Ok(id) => id,
        Err(r) => {
            st.inc_erreurs();
            return r;
        }
    };

    let ciphertext = body.get("ciphertext").and_then(|v| v.as_str()).unwrap_or("");
    let iv = body.get("iv").and_then(|v| v.as_str()).unwrap_or("");
    let auth_tag = body.get("auth_tag").and_then(|v| v.as_str()).unwrap_or("");

    if ciphertext.is_empty() || iv.is_empty() || auth_tag.is_empty() {
        st.inc_erreurs();
        return err_rid(
            StatusCode::BAD_REQUEST,
            &rid,
            "INVALID_REQUEST",
            "Les champs 'ciphertext', 'iv', 'auth_tag' sont obligatoires.",
        );
    }

    let (new_key_hex, old_key_hex) = match st.sessions_vm.get_cles_aes_vm(vm_id).await {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(StatusCode::NOT_FOUND, &rid, "VM_NOT_FOUND", &e);
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
            info!("[Proxy] POST /decrypt — vm_id={vm_id} key_used={key_used} (rid={rid})");
            (
                StatusCode::OK,
                Json(json!({
                    "request_id": rid,
                    "message_type": "decryption_response",
                    "status": "success",
                    "vm_id": vm_id,
                    "key_used": key_used,
                    "plaintext": plaintext,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Err(CryptoError::IntegriteEchouee) => {
            st.inc_erreurs();
            err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "CRYPTO_ERROR",
                "Échec de vérification d'intégrité GCM : données corrompues ou falsifiées.",
            )
        }
        Err(e) => {
            st.inc_erreurs();
            err_rid(
                StatusCode::INTERNAL_SERVER_ERROR,
                &rid,
                "CRYPTO_ERROR",
                &e.to_string(),
            )
        }
    }
}

// ── POST /credential/rotate ─────────────────────────────────────────────────────

pub async fn handle_rotate(
    State(st): State<SharedProxyState>,
    body: Option<Json<Value>>,
) -> Response {
    st.inc_requetes();
    let rid = body
        .as_ref()
        .and_then(|Json(v)| v.get("request_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    info!("[Proxy] POST /credential/rotate (rid={rid})");
    let rapport: RapportRotationVms =
        effectuer_rotation_toutes_vms(Arc::clone(&st.sessions_vm), &st.config.agent_token).await;

    (
        StatusCode::OK,
        Json(json!({
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
        })),
    )
        .into_response()
}

// ── POST /ecdh/initiate ─────────────────────────────────────────────────────────

pub async fn handle_ecdh_initiate(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);
    let peer_id = body
        .get("peer_agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();

    let peer_hex = match body
        .get("peer_public_key_hex")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(h) => h,
        None => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'peer_public_key_hex' est obligatoire.",
            );
        }
    };

    let peer_bytes = match decoder_cle_publique_x25519(peer_hex) {
        Ok(b) => b,
        Err(e) => {
            st.inc_erreurs();
            return err_rid(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string());
        }
    };

    match ecdh_session_ephemere(&peer_bytes) {
        Ok(echange) => {
            let shared_hex = hex::encode(echange.shared_secret);
            info!("[Proxy] POST /ecdh/initiate — peer={peer_id} (rid={rid})");
            (
                StatusCode::OK,
                Json(json!({
                    "request_id": rid,
                    "message_type": "ecdh_response",
                    "status": "success",
                    "peer_agent_id": peer_id,
                    "agent_ephemeral_public_key_hex": echange.agent_public_key_hex,
                    "shared_secret_hex": shared_hex,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Err(e) => {
            st.inc_erreurs();
            err_rid(
                StatusCode::INTERNAL_SERVER_ERROR,
                &rid,
                "CRYPTO_ERROR",
                &e.to_string(),
            )
        }
    }
}

// ── POST /secret/strength ───────────────────────────────────────────────────────

pub async fn handle_secret_strength(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);

    let secret = match body.get("secret").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            st.inc_erreurs();
            return err_rid(
                StatusCode::BAD_REQUEST,
                &rid,
                "INVALID_REQUEST",
                "Le champ 'secret' est obligatoire.",
            );
        }
    };

    let force = st.crypto_moteur.evaluer_force(secret);
    (
        StatusCode::OK,
        Json(json!({
            "request_id": rid,
            "message_type": "secret_strength_response",
            "status": "success",
            "score": force.score,
            "details": force.details,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

// ── POST /password/generate ─────────────────────────────────────────────────────

pub async fn handle_generate_password(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();
    let rid = new_rid(&body);

    let longueur = body.get("longueur").and_then(|v| v.as_u64()).unwrap_or(24) as usize;
    let majuscules = body.get("majuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let minuscules = body.get("minuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let chiffres = body.get("chiffres").and_then(|v| v.as_bool()).unwrap_or(true);
    let symboles = body.get("symboles").and_then(|v| v.as_bool()).unwrap_or(true);
    let excl_ambigus = body
        .get("exclure_ambigus")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !majuscules && !minuscules && !chiffres && !symboles {
        st.inc_erreurs();
        return err_rid(
            StatusCode::BAD_REQUEST,
            &rid,
            "INVALID_REQUEST",
            "Au moins un groupe de caractères doit être activé.",
        );
    }

    let opts = OptionsMotDePasse {
        longueur,
        majuscules,
        minuscules,
        chiffres,
        symboles,
        exclure_ambigus: excl_ambigus,
    };

    match st.crypto_moteur.generer_mot_de_passe(&opts) {
        Ok(pwd) => {
            let force = st.crypto_moteur.evaluer_force(&pwd);
            (
                StatusCode::OK,
                Json(json!({
                    "request_id": rid,
                    "message_type": "password_generate_response",
                    "status": "success",
                    "password": pwd,
                    "longueur": longueur,
                    "score": force.score,
                    "details": force.details,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Err(e) => {
            st.inc_erreurs();
            err_rid(StatusCode::BAD_REQUEST, &rid, "INVALID_REQUEST", &e.to_string())
        }
    }
}

// ── GET /public-key ─────────────────────────────────────────────────────────────

pub async fn handle_public_key(State(st): State<SharedProxyState>) -> impl IntoResponse {
    st.inc_requetes();
    Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "message_type": "public_key_response",
        "status": "success",
        "agent_id": format!("proxy-{}", st.config.local_vm_id),
        "public_key_hex": st.crypto_moteur.get_public_key_hex(),
        "algorithm": "X25519",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ── GET /proxy/sessions ───────────────────────────────────────────────────────────

pub async fn handle_proxy_sessions_list(State(st): State<SharedProxyState>) -> impl IntoResponse {
    st.inc_requetes();
    let peers = st.proxy_sessions.lister_peers().await;
    Json(json!({
        "local_vm_id": st.config.local_vm_id,
        "count": peers.len(),
        "peers": peers,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ── POST /proxy/relay ─────────────────────────────────────────────────────────────

pub async fn handle_proxy_relay(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();

    let dest_vm_id = match body.get("dest_vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "dest_vm_id obligatoire (entier > 100).",
            );
        }
    };

    if dest_vm_id == st.config.local_vm_id {
        st.inc_erreurs();
        return err(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "dest_vm_id ne peut pas être la VM locale.",
        );
    }

    let request_val = match body.get("request") {
        Some(r) => r.clone(),
        None => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Le champ 'request' est obligatoire.",
            );
        }
    };

    let payload = match serde_json::to_string(&request_val) {
        Ok(s) => s,
        Err(e) => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                &format!("request non sérialisable : {e}"),
            );
        }
    };

    if let Err(e) = assurer_session_peer(st.as_ref(), dest_vm_id).await {
        st.inc_erreurs();
        return err(StatusCode::BAD_GATEWAY, "SESSION_ERROR", &e);
    }

    let local_vm_id = st.config.local_vm_id;
    let (new_key_hex, _) = match st.sessions_vm.get_cles_aes_vm(local_vm_id).await {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err(
                StatusCode::NOT_FOUND,
                "VM_NOT_FOUND",
                &format!("Session locale VM {local_vm_id} : {e}"),
            );
        }
    };

    let cle = match decoder_cle_aes_hex(&new_key_hex) {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err(StatusCode::INTERNAL_SERVER_ERROR, "CRYPTO_ERROR", &e.to_string());
        }
    };

    let enc = match chiffrer_aes_gcm_avec_cle(&cle, &payload) {
        Ok(d) => d,
        Err(e) => {
            st.inc_erreurs();
            return err(StatusCode::INTERNAL_SERVER_ERROR, "CRYPTO_ERROR", &e.to_string());
        }
    };

    let peer_base = match st.config.url_proxy_peer(dest_vm_id) {
        Some(u) => u,
        None => {
            st.inc_erreurs();
            return err(
                StatusCode::NOT_FOUND,
                "PEER_NOT_CONFIGURED",
                &format!("Aucune URL proxy pour la VM {dest_vm_id}"),
            );
        }
    };

    let inbound_url = format!("{}/proxy/inbound", peer_base.trim_end_matches('/'));
    let envelope = json!({
        "source_vm_id": local_vm_id,
        "ciphertext": enc.ciphertext,
        "iv": enc.iv,
        "auth_tag": enc.auth_tag,
        "request_id": Uuid::new_v4().to_string(),
    });

    match st.http.post(&inbound_url).json(&envelope).send().await {
        Ok(r) if r.status().is_success() => {
            info!("[Proxy] relay → VM {dest_vm_id}");
            (
                StatusCode::OK,
                Json(json!({
                    "status": "success",
                    "message_type": "proxy_relay_response",
                    "dest_vm_id": dest_vm_id,
                    "source_vm_id": local_vm_id,
                    "encrypted": true,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            )
                .into_response()
        }
        Ok(r) => {
            let code = r.status().as_u16();
            let txt = r.text().await.unwrap_or_default();
            st.inc_erreurs();
            err(
                StatusCode::BAD_GATEWAY,
                "PEER_ERROR",
                &format!("proxy distant HTTP {code} : {txt}"),
            )
        }
        Err(e) => {
            st.inc_erreurs();
            err(StatusCode::BAD_GATEWAY, "PEER_ERROR", &e.to_string())
        }
    }
}

// ── POST /proxy/inbound ───────────────────────────────────────────────────────────

pub async fn handle_proxy_inbound(
    State(st): State<SharedProxyState>,
    Json(body): Json<Value>,
) -> Response {
    st.inc_requetes();

    let source_vm_id = match body.get("source_vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "source_vm_id obligatoire.",
            );
        }
    };

    let ciphertext = body.get("ciphertext").and_then(|v| v.as_str()).unwrap_or("");
    let iv = body.get("iv").and_then(|v| v.as_str()).unwrap_or("");
    let auth_tag = body.get("auth_tag").and_then(|v| v.as_str()).unwrap_or("");

    if ciphertext.is_empty() || iv.is_empty() || auth_tag.is_empty() {
        st.inc_erreurs();
        return err(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "ciphertext, iv, auth_tag obligatoires.",
        );
    }

    let (new_key_hex, old_key_hex) = match st.sessions_vm.get_cles_aes_vm(source_vm_id).await {
        Ok(k) => k,
        Err(e) => {
            st.inc_erreurs();
            return err(StatusCode::NOT_FOUND, "VM_NOT_FOUND", &e);
        }
    };

    let (plaintext, key_used) = match dechiffrer_aes_gcm_vm(
        &new_key_hex,
        old_key_hex.as_deref(),
        ciphertext,
        iv,
        auth_tag,
    ) {
        Ok(p) => p,
        Err(CryptoError::IntegriteEchouee) => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "CRYPTO_ERROR",
                "Échec vérification GCM.",
            );
        }
        Err(e) => {
            st.inc_erreurs();
            return err(StatusCode::INTERNAL_SERVER_ERROR, "CRYPTO_ERROR", &e.to_string());
        }
    };

    info!("[Proxy] inbound vm_id={source_vm_id} key_used={key_used}");

    let request_val: Value = match serde_json::from_str(&plaintext) {
        Ok(v) => v,
        Err(e) => {
            st.inc_erreurs();
            return err(
                StatusCode::BAD_REQUEST,
                "INVALID_PAYLOAD",
                &format!("JSON attendu après déchiffrement : {e}"),
            );
        }
    };

    if let Err(e) = livrer_vers_vm_locale(st.as_ref(), source_vm_id, &request_val).await {
        warn!("[Proxy] livraison locale : {e}");
        st.inc_erreurs();
        return err(StatusCode::BAD_GATEWAY, "DELIVER_ERROR", &e);
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "message_type": "proxy_inbound_response",
            "source_vm_id": source_vm_id,
            "key_used": key_used,
            "delivered": true,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

async fn livrer_vers_vm_locale(
    st: &ProxyState,
    source_vm_id: u32,
    request: &Value,
) -> Result<(), String> {
    let url = &st.config.local_deliver_url;
    st.http
        .post(url)
        .json(&json!({
            "source_vm_id": source_vm_id,
            "request": request,
        }))
        .send()
        .await
        .map_err(|e| format!("POST {url} : {e}"))?
        .error_for_status()
        .map_err(|e| format!("livraison HTTP : {e}"))?;
    Ok(())
}

/// Enregistre la session AES locale (clé proxy) si absente — nécessaire pour `/proxy/relay`.
pub async fn assurer_session_locale(st: &ProxyState) -> Result<(), String> {
    let vm_id = st.config.local_vm_id;
    if st.sessions_vm.get_resume_vm(vm_id).await.is_some() {
        return Ok(());
    }

    let public_key = st.secret.public_key_hex.clone();
    let vm_pub_bytes = decoder_cle_publique_x25519(&public_key)
        .map_err(|e| e.to_string())?;
    let echange = ecdh_session_ephemere(&vm_pub_bytes).map_err(|e| e.to_string())?;
    let new_key_hex = hex::encode(echange.shared_secret);

    st.sessions_vm
        .enregistrer_session(
            vm_id,
            public_key.clone(),
            echange.agent_public_key_hex,
            new_key_hex,
            None,
        )
        .await?;

    if let Err(e) = st
        .central
        .sync_vm_session(vm_id, &public_key, vm_id)
        .await
    {
        warn!("[Proxy] sync central VM locale : {e}");
    }

    info!("[Proxy] session locale VM {vm_id} initialisée.");
    Ok(())
}

/// Handshake pair : POST /vm/session/register vers le proxy cible si absent de proxy_session.json.
pub async fn assurer_session_peer(st: &ProxyState, dest_vm_id: u32) -> Result<(), String> {
    valider_vm_id(dest_vm_id).map_err(|e| e.to_string())?;

    if st.proxy_sessions.a_session_peer(dest_vm_id).await {
        return Ok(());
    }

    let peer_base = st
        .config
        .url_proxy_peer(dest_vm_id)
        .ok_or_else(|| format!("URL proxy absente pour VM {dest_vm_id}"))?;

    let register_url = format!(
        "{}/vm/session/register",
        peer_base.trim_end_matches('/')
    );

    info!(
        "[Proxy] handshake VM {} → {} (pas de session pair)",
        st.config.local_vm_id, dest_vm_id
    );

    let body = json!({
        "vm_id": st.config.local_vm_id,
        "public_key": st.secret.public_key_hex,
        "peer_proxy_url": format!(
            "http://127.0.0.1:{}",
            st.config.listen_port
        ),
    });

    let res = st
        .http
        .post(&register_url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("register vers {register_url} : {e}"))?;

    let status = res.status();
    if !status.is_success() {
        let txt = res.text().await.unwrap_or_default();
        return Err(format!("register pair HTTP {} : {txt}", status.as_u16()));
    }

    st.proxy_sessions
        .enregistrer_peer(
            dest_vm_id,
            peer_base.clone(),
            &st.secret.public_key_hex,
        )
        .await?;

    info!("[Proxy] session pair VM {dest_vm_id} établie.");
    Ok(())
}

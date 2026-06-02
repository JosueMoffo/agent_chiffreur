//! Agent chiffreur **central** (port 5004) — registre des proxies et interface Décideur.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tracing::info;
use uuid::Uuid;

use crate::auth::{autoriser_rotation_decideur, verifier_token};
use crate::central_registry::GestionnaireRegistry;
use crate::central_rotation::{executer_rotation_central, TypeRotation};
use crate::config::Config;
use crate::sessions_vm::parse_vm_id_json;

/// Vérifie `X-Agent-Token` sur les routes protégées (`/credential/rotate` géré à part).
pub async fn middleware_token(
    state: State<SharedCentralState>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/credential/rotate" {
        return next.run(request).await;
    }
    if let Err(resp) = verifier_token(request.headers(), &state.config) {
        return resp;
    }
    next.run(request).await
}

pub struct CentralState {
    pub config: Config,
    pub registry: Arc<GestionnaireRegistry>,
    pub requetes: std::sync::atomic::AtomicU64,
    pub erreurs: std::sync::atomic::AtomicU64,
    pub start_time: Instant,
}

pub type SharedCentralState = Arc<CentralState>;

fn err_resp(status: StatusCode, rid: &str, code: &str, desc: &str) -> Response {
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

fn rid(body: &Value) -> String {
    body.get("request_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

// ── GET /health ───────────────────────────────────────────────────────────────

pub async fn handle_health(State(st): State<SharedCentralState>) -> impl IntoResponse {
    let reg = st.registry.resume().await;
    Json(json!({
        "status": "ok",
        "role": "agent_central",
        "uptime_sec": st.start_time.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "proxies_enregistres": reg.proxies.len(),
        "vms_registrees": reg.vms.len(),
        "agent_port_officiel": 5004,
        "decideur_url": st.config.url_decideur(),
        "auditeur_url": st.config.url_auditeur(),
        "decideur_autorise": st.config.agent_rotation_autorise,
        "rotation_auto_sec": st.config.intervalle_rotation_sec,
        "communication_sma": ["Decideur:5003", "Auditeur:5005"],
    }))
}

// ── GET /metrics ──────────────────────────────────────────────────────────────

pub async fn handle_metrics(State(st): State<SharedCentralState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "role": "agent_central",
        "requests_handled": st.requetes.load(std::sync::atomic::Ordering::Relaxed),
        "errors_count": st.erreurs.load(std::sync::atomic::Ordering::Relaxed),
    }))
}

// ── POST /registry/proxy/announce ─────────────────────────────────────────────

pub async fn handle_proxy_announce(
    State(st): State<SharedCentralState>,
    Json(body): Json<Value>,
) -> Response {
    st.requetes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let r = rid(&body);

    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            return err_resp(StatusCode::BAD_REQUEST, &r, "INVALID_REQUEST", "vm_id obligatoire.");
        }
    };

    let proxy_url = match body.get("proxy_url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => {
            return err_resp(
                StatusCode::BAD_REQUEST,
                &r,
                "INVALID_REQUEST",
                "proxy_url obligatoire.",
            );
        }
    };

    let public_key = body
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let grpc_addr = body
        .get("proxy_grpc_addr")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if let Err(e) = st
        .registry
        .enregistrer_proxy(vm_id, proxy_url.clone(), grpc_addr, public_key)
        .await
    {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &r, "STORE_ERROR", &e);
    }

    info!("[Central] proxy VM {vm_id} annoncé → {proxy_url}");
    (
        StatusCode::OK,
        Json(json!({
            "request_id": r,
            "status": "success",
            "message_type": "proxy_announce_response",
            "vm_id": vm_id,
            "proxy_url": proxy_url,
        })),
    )
        .into_response()
}

// ── POST /registry/vm/sync ──────────────────────────────────────────────────

pub async fn handle_vm_sync(
    State(st): State<SharedCentralState>,
    Json(body): Json<Value>,
) -> Response {
    st.requetes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let r = rid(&body);

    let vm_id = match body.get("vm_id").and_then(parse_vm_id_json) {
        Some(id) => id,
        None => {
            return err_resp(StatusCode::BAD_REQUEST, &r, "INVALID_REQUEST", "vm_id obligatoire.");
        }
    };

    let heberge = body
        .get("heberge_par_proxy_vm_id")
        .and_then(parse_vm_id_json)
        .unwrap_or(0);

    let public_key = body
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Err(e) = st.registry.sync_vm(vm_id, public_key, heberge).await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &r, "STORE_ERROR", &e);
    }

    (
        StatusCode::OK,
        Json(json!({
            "request_id": r,
            "status": "success",
            "message_type": "vm_sync_response",
            "vm_id": vm_id,
        })),
    )
        .into_response()
}

// ── GET /registry/status ──────────────────────────────────────────────────────

pub async fn handle_registry_status(State(st): State<SharedCentralState>) -> impl IntoResponse {
    let reg = st.registry.resume().await;
    Json(json!({
        "status": "ok",
        "proxies": reg.proxies,
        "vms": reg.vms,
    }))
}

// ── POST /credential/rotate — Décideur → tous les proxies ─────────────────────

pub async fn handle_rotate(
    State(st): State<SharedCentralState>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let r = body
        .as_ref()
        .and_then(|Json(v)| v.get("request_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let decideur_id = match autoriser_rotation_decideur(&headers, &st.config) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    info!(
        "[Central] rotation ordonnée par '{}' (Décideur) — propagation proxies + auditeur",
        decideur_id
    );

    let rapport = executer_rotation_central(
        &st,
        r.clone(),
        TypeRotation::Ordonnee,
        Some(decideur_id),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "request_id": r,
            "message_type": "credential_rotate_response",
            "status": "success",
            "role": "agent_central",
            "type_rotation": TypeRotation::Ordonnee.as_str(),
            "proxies_total": rapport.proxies_total,
            "proxies_reussis": rapport.proxies_reussis,
            "resultats": rapport.resultats,
            "auditeur_notifie": st.config.url_auditeur().is_some(),
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}


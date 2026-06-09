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
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use crate::central_registry::GestionnaireRegistry;
use crate::config::Config;
use crate::sessions_vm::{parse_vm_id_json, valider_vm_id};

/// Token optionnel (pass-through).
pub async fn middleware_token(
    _state: State<SharedCentralState>,
    request: Request,
    next: Next,
) -> Response {
    next.run(request).await
}

pub struct CentralState {
    pub config: Config,
    pub registry: Arc<GestionnaireRegistry>,
    pub http: Client,
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
        "decideur_autorise": st.config.agent_rotation_autorise,
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

    if let Err(e) = st
        .registry
        .enregistrer_proxy(vm_id, proxy_url.clone(), public_key)
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

    let agent_name = headers
        .get("X-Agent-Name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if agent_name != st.config.agent_rotation_autorise {
        return err_resp(
            StatusCode::FORBIDDEN,
            &r,
            "FORBIDDEN",
            &format!(
                "Seul '{}' peut déclencher la rotation.",
                st.config.agent_rotation_autorise
            ),
        );
    }

    info!("[Central] rotation demandée par '{agent_name}' — propagation aux proxies");

    let proxies = st.registry.urls_proxies().await;
    let mut resultats = Vec::new();
    let mut ok_count = 0u32;

    for (vm_id, base) in &proxies {
        let url = format!("{}/credential/rotate", base.trim_end_matches('/'));
        match st
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Agent-Name", &st.config.agent_rotation_autorise)
            .json(&json!({ "request_id": r, "initiateur": "agent_central" }))
            .send()
            .await
        {
            Ok(res) if res.status().is_success() => {
                ok_count += 1;
                resultats.push(json!({ "proxy_vm_id": vm_id, "succes": true, "url": url }));
            }
            Ok(res) => {
                let code = res.status().as_u16();
                let txt = res.text().await.unwrap_or_default();
                warn!("[Central] rotation proxy {vm_id} HTTP {code}");
                resultats.push(json!({
                    "proxy_vm_id": vm_id, "succes": false, "http": code, "detail": txt
                }));
            }
            Err(e) => {
                resultats.push(json!({ "proxy_vm_id": vm_id, "succes": false, "erreur": e.to_string() }));
            }
        }
    }

    // Audit de la rotation vers l'agent agent-auditeur
    crate::supervision::auditer_rotation(
        &st.config,
        if ok_count > 0 { "success" } else { "failed" },
        proxies.len(),
        ok_count as usize,
    ).await;

    (
        StatusCode::OK,
        Json(json!({
            "request_id": r,
            "message_type": "credential_rotate_response",
            "status": "success",
            "role": "agent_central",
            "proxies_total": proxies.len(),
            "proxies_reussis": ok_count,
            "resultats": resultats,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

// ── POST /decideur/forward — relais générique vers le Décideur ─────────────────

pub async fn handle_decideur_forward(
    State(st): State<SharedCentralState>,
    Json(body): Json<Value>,
) -> Response {
    let r = rid(&body);
    let decideur_url = match st.config.agents_connus.get(&st.config.agent_rotation_autorise) {
        Some(u) => u.clone(),
        None => {
            return err_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                &r,
                "DECIDEUR_UNAVAILABLE",
                "URL du Décideur absente de agents_connus.",
            );
        }
    };

    let path = body
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", decideur_url.trim_end_matches('/'), path);

    let res = st
        .http
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Agent-Token", &st.config.agent_token)
        .json(body.get("payload").unwrap_or(&body))
        .send()
        .await;

    match res {
        Ok(rep) => {
            let status = rep.status();
            let body: Value = rep.json().await.unwrap_or(json!({}));
            (
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(json!({
                    "request_id": r,
                    "status": "success",
                    "message_type": "decideur_forward_response",
                    "decideur_status": status.as_u16(),
                    "decideur_body": body,
                })),
            )
                .into_response()
        }
        Err(e) => err_resp(
            StatusCode::BAD_GATEWAY,
            &r,
            "FORWARD_ERROR",
            &e.to_string(),
        ),
    }
}

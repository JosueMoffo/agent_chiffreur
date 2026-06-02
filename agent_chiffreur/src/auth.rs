//! Authentification inter-agents SMA (contrat GANDAL/ENSPY).
//!
//! - Standard : en-tête `X-Agent-Token` (token partagé `agent_token` en config).
//! - Rotation : `X-Agent-Token` du Décideur ; rétrocompatibilité `X-Agent-Name` (déprécié).

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::warn;

use crate::config::Config;

/// Vérifie le token SMA sur les routes protégées (hors `/credential/rotate`).
pub fn verifier_token(headers: &HeaderMap, config: &Config) -> Result<(), Response> {
    let recu = headers
        .get("X-Agent-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if recu.is_empty() {
        return Err(reponse_auth(
            StatusCode::UNAUTHORIZED,
            "TOKEN_MISSING",
            "En-tête X-Agent-Token obligatoire.",
        ));
    }

    if recu != config.agent_token {
        return Err(reponse_auth(
            StatusCode::FORBIDDEN,
            "TOKEN_INVALID",
            "X-Agent-Token invalide.",
        ));
    }

    Ok(())
}

/// Autorise `POST /credential/rotate` (appelé par le Décideur, port 5003).
///
/// Priorité : `X-Agent-Token` valide, puis rétrocompatibilité `X-Agent-Name` = `agent_rotation_autorise`.
pub fn autoriser_rotation_decideur(
    headers: &HeaderMap,
    config: &Config,
) -> Result<String, Response> {
    if let Some(token) = headers.get("X-Agent-Token").and_then(|v| v.to_str().ok()) {
        if !token.is_empty() && token == config.agent_token {
            return Ok(config.agent_rotation_autorise.clone());
        }
        if !token.is_empty() {
            return Err(reponse_auth(
                StatusCode::FORBIDDEN,
                "TOKEN_INVALID",
                "X-Agent-Token invalide pour la rotation.",
            ));
        }
    }

    if let Some(name) = headers.get("X-Agent-Name").and_then(|v| v.to_str().ok()) {
        if name == config.agent_rotation_autorise {
            warn!(
                "[Auth] Rotation via X-Agent-Name (déprécié) — préférer X-Agent-Token du Décideur."
            );
            return Ok(name.to_string());
        }
        return Err(reponse_auth(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &format!(
                "Seul '{}' peut déclencher la rotation (X-Agent-Name obsolète).",
                config.agent_rotation_autorise
            ),
        ));
    }

    Err(reponse_auth(
        StatusCode::UNAUTHORIZED,
        "TOKEN_MISSING",
        "X-Agent-Token obligatoire (contrat Décideur ↔ Chiffreur).",
    ))
}

fn reponse_auth(status: StatusCode, code: &str, desc: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "message_type": "error_response",
            "status": "error",
            "error": code,
            "description": desc,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

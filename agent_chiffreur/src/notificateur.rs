//! # Notificateur HTTP sortant — Agent Chiffreur
//!
//! Ce module envoie des notifications JSON aux autres agents du SMA via HTTP POST.
//! En cas d'échec réseau, l'erreur est loggée sans paniquer (best-effort).

use tracing::{error, info};

/// Envoie une notification JSON à un autre agent du SMA via HTTP POST.
///
/// L'URL cible est passée en paramètre (lue depuis la config à l'appel).
/// En cas d'échec réseau, log l'erreur sans paniquer (best-effort).
///
/// # SECURITY: ne pas logguer le payload brut s'il contient des secrets
pub async fn notifier_agent(url: &str, token: &str, payload: serde_json::Value, config: Option<&crate::config::Config>) {
    let client = if let Some(cfg) = config {
        crate::tls_utils::build_mtls_client(cfg)
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    };

    match client
        .post(url)
        .header("X-Agent-Token", token)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            info!(
                "[NOTIFICATEUR] Notification envoyée à {} — statut HTTP {}",
                url,
                resp.status()
            );
        }
        Err(e) => {
            error!(
                "[NOTIFICATEUR] Échec de notification vers {} : {}",
                url, e
            );
        }
    }
}

/// Envoie une alerte/log à l'agent agent-auditeur si `agent_agent-auditeur_url` est configuré.
pub async fn notifier_audit(config: &crate::config::Config, payload: serde_json::Value) {
    if let Some(ref url) = config.agent_auditeur_url {
        notifier_agent(url, &config.agent_token, payload, Some(config)).await;
    }
}

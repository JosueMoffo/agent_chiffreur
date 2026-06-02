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
pub async fn notifier_agent(url: &str, token: &str, payload: serde_json::Value) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("[NOTIFICATEUR] Impossible de créer le client HTTP : {}", e);
            return;
        }
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

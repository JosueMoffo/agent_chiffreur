//! # Supervision — Agent Chiffreur ENSPY
//!
//! Ce module gère les tâches de fond :
//! 1. Supervision du pool d'entropie (sysinfo /proc/sys/kernel/random/entropy_avail).
//! 2. Audits périodiques ou sur événements.

use std::fs;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};
use serde_json::json;
use crate::config::Config;
use crate::notificateur::notifier_audit;

/// Démarre la tâche de supervision de l'entropie.
pub async fn tache_supervision_entropie(config: Config) {
    let mut interval = interval(Duration::from_secs(config.intervalle_supervision_sec));
    info!("[SUPERVISION] Tâche d'entropie démarrée (seuil={} octets, intervalle={}s)", 
        config.seuil_entropie, config.intervalle_supervision_sec);

    loop {
        interval.tick().await;
        
        let entropy = lire_entropie_disponible();
        if entropy < config.seuil_entropie {
            warn!("[SUPERVISION] Alerte : entropie faible ({} < {})", entropy, config.seuil_entropie);
            
            let alerte = json!({
                "request_id": uuid::Uuid::new_v4().to_string(),
                "message_type": "log_event",
                "source_agent": "chiffreur",
                "event_type": "LOW_ENTROPY_DETECTED",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "data": {
                    "severity": "HIGH",
                    "entropy_bytes": entropy,
                    "threshold": config.seuil_entropie,
                    "action": "Veuillez vérifier le driver d'entropie (ex: haveged, rng-tools)"
                }
            });
            
            notifier_audit(&config, alerte).await;
        }
    }
}

/// Lit l'entropie disponible sur Linux via /proc/sys/kernel/random/entropy_avail.
/// Sur les autres systèmes, retourne une valeur élevée fictive.
fn lire_entropie_disponible() -> u32 {
    let path = "/proc/sys/kernel/random/entropy_avail";
    if let Ok(content) = fs::read_to_string(path) {
        content.trim().parse::<u32>().unwrap_or(4096)
    } else {
        // Fallback pour non-linux ou erreur lecture
        4096
    }
}

/// Envoie un log d'audit pour un événement de rotation.
pub async fn auditer_rotation(config: &Config, status: &str, total: usize, reussis: usize) {
    let log = json!({
        "request_id": uuid::Uuid::new_v4().to_string(),
        "message_type": "log_event",
        "source_agent": "chiffreur",
        "event_type": "CREDENTIAL_ROTATION_SUMMARY",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "status": status,
            "proxies_total": total,
            "proxies_reussis": reussis,
            "severity": if status == "success" { "INFO" } else { "CRITICAL" }
        }
    });
    notifier_audit(config, log).await;
}

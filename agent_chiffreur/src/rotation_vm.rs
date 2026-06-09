//! # Rotation des clés AES par VM via ECDH — Agent Chiffreur ENSPY
//!
//! Ce module orchestre la rotation ECDH pour chaque VM en session :
//!
//! ## Séquence complète d'une rotation VM
//!
//! ```text
//! Pour chaque VM enregistrée :
//!
//!   1. Récupérer la clé publique X25519 de la VM
//!      (stockée dans session.json lors de l'enregistrement)
//!
//!   2. Générer une nouvelle paire X25519 éphémère agent + ECDH(vm_pub_key)
//!      → nouveau_secret = secret partagé X25519 (32 octets)
//!
//!   3. Appliquer la rotation dans la session VM :
//!      vm.old_key       ← vm.new_key            (ancienne clé de travail)
//!      vm.new_key       ← nouveau_secret (hex)  (nouvelle clé AES-256)
//!      vm.old_key_expire_at ← now + grace_sec   (timer de grâce)
//!
//!   4. Notifier la VM via HTTP POST sur url_notification :
//!      POST http://<vm>:<port>/key-update
//!      { "vm_id": "...", "new_key_hex": "...", "rotation_id": "..." }
//!
//!   5. Sauvegarder session.json
//!
//! La tâche de purge (tache_purge_cles) supprime les old_key expirées
//! après le timer de grâce configuré (AGENT_OLD_KEY_GRACE_SEC, défaut: 60s).
//! ```

use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto_moteur::ecdh_session_ephemere;
use crate::notificateur::notifier_agent;
use crate::sessions_vm::GestionnaireSessionsVm;

// ── Structures ────────────────────────────────────────────────────────────────

/// Résultat de rotation pour une VM individuelle.
#[derive(Debug, Clone, Serialize)]
pub struct ResultatRotationVm {
    pub vm_id: u32,
    pub rotation_id: String,
    pub succes: bool,
    pub new_key_id: String,
    /// `true` si la notification HTTP a été envoyée avec succès.
    pub notifiee: bool,
    pub erreur: Option<String>,
}

/// Rapport global d'une rotation de toutes les VMs.
#[derive(Debug, Clone, Serialize)]
pub struct RapportRotationVms {
    pub rotation_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub vms_total: usize,
    pub vms_reussies: usize,
    pub vms_echecs: usize,
    pub vms_notifiees: usize,
    pub resultats: Vec<ResultatRotationVm>,
}

// ── Orchestrateur de rotation ─────────────────────────────────────────────────

/// Effectue la rotation ECDH pour toutes les VMs enregistrées.
///
/// Pour chaque VM :
/// 1. Récupère la clé publique X25519 depuis le store
/// 2. Calcule le secret ECDH
/// 3. Applique la rotation (new_key/old_key)
/// 4. Notifie la VM via HTTP POST
///
/// # SECURITY: le `new_key_hex` n'est jamais loggué
pub async fn effectuer_rotation_toutes_vms(
    gestionnaire: Arc<GestionnaireSessionsVm>,
    config: &crate::config::Config,
) -> RapportRotationVms {
    let rotation_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now();

    info!("[ROTATION VMs] Démarrage rotation_id={}", rotation_id);

    // Charger la liste complète des sessions
    let sessions = gestionnaire.lister_sessions().await;
    let vms_total = sessions.len();

    if vms_total == 0 {
        warn!("[ROTATION VMs] Aucune VM en session — rotation ignorée.");
        return RapportRotationVms {
            rotation_id,
            timestamp,
            vms_total: 0,
            vms_reussies: 0,
            vms_echecs: 0,
            vms_notifiees: 0,
            resultats: vec![],
        };
    }

    let mut resultats = Vec::with_capacity(vms_total);

    // Traiter chaque VM
    for resume in &sessions {
        let vm_id = resume.vm_id;
        let res = roter_une_vm(gestionnaire.as_ref(), config, vm_id, &rotation_id).await;
        resultats.push(res);
    }

    let vms_reussies = resultats.iter().filter(|r| r.succes).count();
    let vms_echecs = resultats.iter().filter(|r| !r.succes).count();
    let vms_notifiees = resultats.iter().filter(|r| r.notifiee).count();

    info!(
        "[ROTATION VMs] Terminée rotation_id={} — {}/{} réussies, {} notifiées",
        rotation_id, vms_reussies, vms_total, vms_notifiees
    );

    RapportRotationVms {
        rotation_id,
        timestamp,
        vms_total,
        vms_reussies,
        vms_echecs,
        vms_notifiees,
        resultats,
    }
}

/// Effectue la rotation ECDH pour une VM spécifique.
///
/// # SECURITY: le `nouveau_secret_hex` n'est jamais loggué
async fn roter_une_vm(
    gestionnaire: &GestionnaireSessionsVm,
    config: &crate::config::Config,
    vm_id: u32,
    rotation_id: &str,
) -> ResultatRotationVm {
    let key = vm_id.to_string();
    let (public_key, url_notif) = {
        let store = gestionnaire.store.read().await;
        match store.sessions.get(&key) {
            Some(s) => (s.public_key.clone(), s.url_notification.clone()),
            None => {
                return ResultatRotationVm {
                    vm_id,
                    rotation_id: rotation_id.to_string(),
                    succes: false,
                    new_key_id: String::new(),
                    notifiee: false,
                    erreur: Some(format!("VM {vm_id} introuvable dans session.json")),
                };
            }
        }
    };

    let vm_pub_bytes = match crate::crypto_moteur::decoder_cle_publique_x25519(&public_key) {
        Ok(b) => b,
        Err(e) => {
            return ResultatRotationVm {
                vm_id,
                rotation_id: rotation_id.to_string(),
                succes: false,
                new_key_id: String::new(),
                notifiee: false,
                erreur: Some(format!("public_key vm_id={vm_id}: {e}")),
            };
        }
    };

    // Nouvelle paire éphémère agent à chaque rotation
    let echange = match ecdh_session_ephemere(&vm_pub_bytes) {
        Ok(e) => e,
        Err(e) => {
            return ResultatRotationVm {
                vm_id,
                rotation_id: rotation_id.to_string(),
                succes: false,
                new_key_id: String::new(),
                notifiee: false,
                erreur: Some(format!("ECDH échoué pour vm_id={vm_id}: {e}")),
            };
        }
    };

    let nouveau_secret_hex = hex::encode(echange.shared_secret);
    let agent_ephemeral_pub = echange.agent_public_key_hex;
    let new_key_id = format!("k_{}", &nouveau_secret_hex[..8]);

    if let Err(e) = gestionnaire
        .appliquer_rotation_vm(
            vm_id,
            agent_ephemeral_pub.clone(),
            nouveau_secret_hex.clone(),
        )
        .await
    {
        return ResultatRotationVm {
            vm_id,
            rotation_id: rotation_id.to_string(),
            succes: false,
            new_key_id,
            notifiee: false,
            erreur: Some(format!("Rotation session.json échouée pour vm_id={vm_id}: {e}")),
        };
    }

    info!(
        "[ROTATION VMs] vm_id={} — rotation appliquée — new_key_id={}",
        vm_id, new_key_id
    );

    // Notifier la VM de sa nouvelle clé
    let mut notifiee = false;
    if let Some(ref url) = url_notif {
        // SECURITY: le payload contient new_key_hex — ne logguer que url et vm_id
        let payload = json!({
            "event": "KEY_ROTATION",
            "rotation_id": rotation_id,
            "vm_id": vm_id,
            "agent_ephemeral_public_key_hex": agent_ephemeral_pub,
            // SECURITY: ne pas logguer new_key_hex dans les logs serveur
            "new_key_hex": nouveau_secret_hex,
            "timestamp": Utc::now().to_rfc3339(),
            "message": "Rotation : nouvelle paire éphémère agent. ECDH(priv_VM, agent_ephemeral_public_key_hex) ou utiliser new_key_hex."
        });

        info!("[ROTATION VMs] Notification → vm_id={} url='{}'", vm_id, url);
        notifier_agent(url, &config.agent_token, payload, Some(config)).await;
        notifiee = true;
    } else {
        warn!(
            "[ROTATION VMs] vm_id={} sans url_notification — notification ignorée.",
            vm_id
        );
    }

    ResultatRotationVm {
        vm_id,
        rotation_id: rotation_id.to_string(),
        succes: true,
        new_key_id,
        notifiee,
        erreur: None,
    }
}

// ── Tâche de rotation automatique ────────────────────────────────────────────

/// Tâche de rotation automatique périodique pour toutes les VMs.
///
/// L'intervalle est lu depuis la config (`AGENT_ROTATION_SEC`, défaut 300s).
pub async fn tache_rotation_vms_automatique(
    gestionnaire: Arc<GestionnaireSessionsVm>,
    config: crate::config::Config,
    intervalle_sec: u64,
) {
    info!(
        "[ROTATION AUTO VMs] Tâche démarrée — intervalle={}s.",
        intervalle_sec
    );
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(intervalle_sec));
    interval.tick().await; // sauter le premier tick

    loop {
        interval.tick().await;
        info!("[ROTATION AUTO VMs] Déclenchement rotation automatique...");
        let rapport =
            effectuer_rotation_toutes_vms(Arc::clone(&gestionnaire), &config).await;

        if rapport.vms_total == 0 {
            info!("[ROTATION AUTO VMs] Aucune VM enregistrée — pas de rotation.");
        } else {
            info!(
                "[ROTATION AUTO VMs] rotation_id={} | {}/{} VMs rotatées | {} notifiées",
                rapport.rotation_id,
                rapport.vms_reussies,
                rapport.vms_total,
                rapport.vms_notifiees,
            );
        }
    }
}

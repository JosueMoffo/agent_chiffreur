//! # Simulation XMPP en mémoire
//!
//! Ce module remplace le bus XMPP Prosody par des **canaux Tokio asynchrones**,
//! ce qui permet d'exécuter la simulation sans aucune dépendance réseau.
//!
//! ## Architecture des canaux
//!
//! ```text
//! ┌──────────────────┐   EnveloppeMessage   ┌──────────────────────┐
//! │ FauxAgentDecideur│ ──────────────────▶ │ AgentChiffreur       │
//! │                  │                      │ (dispatch_requete)   │
//! │                  │ ◀────────────────── │                      │
//! └──────────────────┘   EnveloppeMessage   └──────────────────────┘
//!                                                     │ alertes
//!                                                     ▼
//!                                          ┌──────────────────────┐
//!                                          │ FauxAgentAuditeur    │
//!                                          │ (interception)       │
//!                                          └──────────────────────┘
//! ```

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto_moteur::CryptoMoteur;

// ── Token de simulation ───────────────────────────────────────────────────────

/// Token de simulation (remplace une vérification Ed25519 réelle).
pub const VALID_TOKEN: &str = "ENSPY-TOKEN-2026";

// ── Structure de message ──────────────────────────────────────────────────────

/// Enveloppe d'un message inter-agents (analogue à un message XMPP SPADE).
#[derive(Debug, Clone)]
pub struct EnveloppeMessage {
    pub expediteur: String,
    pub token: Option<String>,
    pub body: String,
    pub reponse_tx: Option<mpsc::Sender<String>>,
}

impl EnveloppeMessage {
    /// Construit un message avec token valide.
    pub fn avec_token(expediteur: &str, payload: Value) -> (Self, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(1);
        let msg = Self {
            expediteur: expediteur.to_string(),
            token: Some(VALID_TOKEN.to_string()),
            body: payload.to_string(),
            reponse_tx: Some(tx),
        };
        (msg, rx)
    }

    /// Construit un message SANS token (pour le scénario 0).
    pub fn sans_token(expediteur: &str, payload: Value) -> (Self, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(1);
        let msg = Self {
            expediteur: expediteur.to_string(),
            token: None,
            body: payload.to_string(),
            reponse_tx: Some(tx),
        };
        (msg, rx)
    }
}

// ── Dispatch de l'Agent Chiffreur ─────────────────────────────────────────────

/// Traite un message entrant et retourne la réponse JSON sérialisée.
pub async fn dispatch_requete(
    msg: &EnveloppeMessage,
    crypto: &CryptoMoteur,
    alerte_tx: &mpsc::Sender<String>,
    _agent_token: &str,
) -> String {
    // ── Désérialisation du payload ──
    let payload: Value = match serde_json::from_str(&msg.body) {
        Ok(v) => v,
        Err(e) => {
            let rid = Uuid::new_v4().to_string();
            return json!({
                "request_id": rid,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": format!("JSON invalide : {}", e),
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let message_type = match payload.get("message_type").and_then(|v| v.as_str()) {
        Some(t) => t.to_ascii_uppercase(),
        None => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": "Le champ 'message_type' est obligatoire.",
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    // ── Dispatch ──
    match message_type.as_str() {
        "STRENGTH_TEST_REQUEST" | "TEST_STRENGTH" => {
            traiter_force(&request_id, &payload, crypto, alerte_tx).await
        }
        "ENCRYPTION_REQUEST" | "ENCRYPT_DATA" => {
            traiter_chiffrement(&request_id, &payload, crypto)
        }
        "DECRYPTION_REQUEST" | "DECRYPT_DATA" => {
            traiter_dechiffrement(&request_id, &payload, crypto)
        }
        "ECDH_REQUEST" => {
            traiter_ecdh(&request_id, &payload, crypto)
        }
        "PASSWORD_GENERATE_REQUEST" => {
            traiter_generer_mot_de_passe(&request_id, &payload, crypto)
        }
        other => {
            json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": format!("message_type inconnu : '{}'.", other),
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string()
        }
    }
}

// ── Handlers d'actions ────────────────────────────────────────────────────────

/// Action — Évalue la force d'un secret et envoie une alerte si score < 60.
async fn traiter_force(
    request_id: &str,
    payload: &Value,
    crypto: &CryptoMoteur,
    alerte_tx: &mpsc::Sender<String>,
) -> String {
    let secret = match payload.get("secret").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": "Le champ 'secret' est obligatoire.",
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    let resultat = crypto.evaluer_force(&secret);
    let score = resultat.score;

    info!("Évaluation de force — score={}.", score);

    if score < 60 {
        let alerte = json!({
            "request_id": Uuid::new_v4().to_string(),
            "message_type": "log_event",
            "source_agent": "chiffreur",
            "event_type": "WEAK_SECRET_DETECTED",
            "timestamp": Utc::now().to_rfc3339(),
            "data": {
                "severity": "MEDIUM",
                "score": score,
                "threshold": 60
            }
        })
        .to_string();
        let _ = alerte_tx.send(alerte).await;
    }

    json!({
        "request_id": request_id,
        "message_type": "strength_test_response",
        "status": "success",
        "score": score,
        "details": resultat.details
    })
    .to_string()
}

/// Action — Chiffrement AES-256-GCM.
fn traiter_chiffrement(request_id: &str, payload: &Value, crypto: &CryptoMoteur) -> String {
    let plaintext = match payload.get("plaintext").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p.to_owned(),
        _ => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": "Le champ 'plaintext' est obligatoire et ne doit pas être vide.",
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    match crypto.chiffrer_aes_gcm(&plaintext) {
        Ok(result) => {
            info!("Chiffrement AES-256-GCM effectué avec succès.");
            json!({
                "request_id": request_id,
                "message_type": "encryption_response",
                "status": "success",
                "ciphertext": result.ciphertext,
                "iv": result.iv,
                "auth_tag": result.auth_tag
            })
            .to_string()
        }
        Err(e) => json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "CRYPTO_ERROR",
            "description": e.to_string(),
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string(),
    }
}

/// Action — Déchiffrement AES-256-GCM avec vérification d'intégrité GCM.
fn traiter_dechiffrement(request_id: &str, payload: &Value, crypto: &CryptoMoteur) -> String {
    let get = |field: &str| -> Option<String> {
        payload
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
    };

    let (ct, iv, tag) = match (get("ciphertext"), get("iv"), get("auth_tag")) {
        (Some(c), Some(i), Some(t)) => (c, i, t),
        _ => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": "Les champs 'ciphertext', 'iv' et 'auth_tag' sont obligatoires.",
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    match crypto.dechiffrer_aes_gcm(&ct, &iv, &tag) {
        Ok(plaintext) => {
            info!("Déchiffrement AES-256-GCM effectué avec succès.");
            json!({
                "request_id": request_id,
                "message_type": "decryption_response",
                "status": "success",
                "plaintext": plaintext
            })
            .to_string()
        }
        Err(crate::error::CryptoError::IntegriteEchouee) => json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "CRYPTO_ERROR",
            "description": "Échec de vérification d'intégrité GCM : données corrompues ou falsifiées.",
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string(),
        Err(e) => json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "CRYPTO_ERROR",
            "description": e.to_string(),
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string(),
    }
}

/// Action — Échange ECDH X25519.
///
/// # SECURITY: ne pas logguer le shared_secret_hex
fn traiter_ecdh(request_id: &str, payload: &Value, crypto: &CryptoMoteur) -> String {
    let peer_key_hex = match payload.get("peer_public_key_hex").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": "Le champ 'peer_public_key_hex' est obligatoire.",
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    let peer_key_bytes = match hex::decode(&peer_key_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": format!("peer_public_key_hex doit être 32 octets (64 hex chars), reçu {}", b.len()),
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
        Err(e) => {
            return json!({
                "request_id": request_id,
                "message_type": "error_response",
                "status": "error",
                "error": "INVALID_REQUEST",
                "description": format!("Hex invalide pour peer_public_key_hex : {}", e),
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string();
        }
    };

    match crypto.ecdh_partager(&peer_key_bytes) {
        Ok(shared_secret) => {
            // SECURITY: ne pas logguer shared_secret
            let shared_secret_hex = hex::encode(shared_secret);
            json!({
                "request_id": request_id,
                "message_type": "ecdh_response",
                "status": "success",
                "shared_secret_hex": shared_secret_hex,
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string()
        }
        Err(e) => json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "CRYPTO_ERROR",
            "description": e.to_string(),
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string(),
    }
}

/// Action — Génération de mot de passe fort.
fn traiter_generer_mot_de_passe(request_id: &str, payload: &Value, crypto: &CryptoMoteur) -> String {
    let longueur = payload.get("longueur")
        .and_then(|v| v.as_u64())
        .unwrap_or(24) as usize;
    let majuscules     = payload.get("majuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let minuscules     = payload.get("minuscules").and_then(|v| v.as_bool()).unwrap_or(true);
    let chiffres       = payload.get("chiffres").and_then(|v| v.as_bool()).unwrap_or(true);
    let symboles       = payload.get("symboles").and_then(|v| v.as_bool()).unwrap_or(true);
    let exclure_ambigus = payload.get("exclure_ambigus").and_then(|v| v.as_bool()).unwrap_or(false);

    if !majuscules && !minuscules && !chiffres && !symboles {
        return json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "INVALID_REQUEST",
            "description": "Au moins un groupe de caractères doit être activé.",
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string();
    }

    let options = crate::crypto_moteur::OptionsMotDePasse {
        longueur,
        majuscules,
        minuscules,
        chiffres,
        symboles,
        exclure_ambigus,
    };

    match crypto.generer_mot_de_passe(&options) {
        Ok(password) => {
            let force = crypto.evaluer_force(&password);
            json!({
                "request_id": request_id,
                "message_type": "password_generate_response",
                "status": "success",
                "password": password,
                "longueur": longueur,
                "score": force.score,
                "details": force.details,
                "timestamp": Utc::now().to_rfc3339()
            })
            .to_string()
        }
        Err(e) => json!({
            "request_id": request_id,
            "message_type": "error_response",
            "status": "error",
            "error": "INVALID_REQUEST",
            "description": e.to_string(),
            "timestamp": Utc::now().to_rfc3339()
        })
        .to_string(),
    }
}

//! # Modèles de messages JSON — API ENSPY
//!
//! Ce module définit les structures Rust qui correspondent aux payloads
//! JSON échangés entre les agents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Requêtes entrantes ────────────────────────────────────────────────────────

/// Corps d'une requête générique (dispatch par `message_type`).
#[derive(Debug, Deserialize)]
pub struct RequeteGenerique {
    pub request_id: Option<String>,
    pub message_type: Option<String>,
    pub secret: Option<String>,
    pub plaintext: Option<String>,
    pub ciphertext: Option<String>,
    pub iv: Option<String>,
    pub auth_tag: Option<String>,
}

/// Corps d'une requête HTTP POST /encrypt.
#[derive(Debug, Deserialize)]
pub struct RequeteChiffrement {
    pub request_id: Option<String>,
    pub vm_id: u32,
    pub plaintext: String,
}

/// Corps d'une requête HTTP POST /decrypt.
#[derive(Debug, Deserialize)]
pub struct RequeteDechiffrement {
    pub request_id: Option<String>,
    pub vm_id: u32,
    pub ciphertext: String,
    pub iv: String,
    pub auth_tag: String,
}

/// Corps d'une requête HTTP POST /credential/rotate (corps optionnel).
#[derive(Debug, Deserialize)]
pub struct RequeteRotation {
    pub request_id: Option<String>,
}

/// Corps d'une requête POST /ecdh/initiate.
#[derive(Debug, Deserialize)]
pub struct RequeteEcdh {
    pub request_id: Option<String>,
    pub peer_agent_id: Option<String>,
    pub peer_public_key_hex: String,
}

/// Corps d'une requête POST /password/generate.
#[derive(Debug, Deserialize)]
pub struct RequeteGenerationMotDePasse {
    pub request_id: Option<String>,
    pub longueur: Option<u32>,
    pub majuscules: Option<bool>,
    pub minuscules: Option<bool>,
    pub chiffres: Option<bool>,
    pub symboles: Option<bool>,
    pub exclure_ambigus: Option<bool>,
}

// ── Réponses sortantes ────────────────────────────────────────────────────────

/// Réponse d'erreur standardisée (API ENSPY §1).
#[derive(Debug, Serialize)]
pub struct ReponseErreur {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub error: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

impl ReponseErreur {
    pub fn new(request_id: impl Into<String>, code: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            message_type: "error_response",
            status: "error",
            error: code.into(),
            description: desc.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Réponse à une évaluation de force de secret.
#[derive(Debug, Serialize)]
pub struct ReponseForce {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub score: u32,
    pub details: crate::crypto_moteur::ForceDetails,
}

/// Réponse à une opération de chiffrement.
#[derive(Debug, Serialize)]
pub struct ReponseChiffrement {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub ciphertext: String,
    pub iv: String,
    pub auth_tag: String,
}

/// Réponse à une opération de déchiffrement.
#[derive(Debug, Serialize)]
pub struct ReponseDechiffrement {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub plaintext: String,
}

/// Réponse à une rotation de credentials.
#[derive(Debug, Serialize)]
pub struct ReponseRotation {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub password: String,
    pub access_key: String,
}

/// Réponse health check (GET /health).
#[derive(Debug, Serialize)]
pub struct ReponseHealth {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub uptime_sec: u64,
    pub version: &'static str,
}

/// Réponse métriques (GET /metrics).
#[derive(Debug, Serialize)]
pub struct ReponseMetrics {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub requests_handled: u64,
    pub errors_count: u64,
    pub memory_mb: f64,
    pub cpu_percent: f32,
}

/// Réponse clé publique X25519 (GET /public-key).
#[derive(Debug, Serialize)]
pub struct ReponsePublicKey {
    pub request_id: String,
    pub message_type: &'static str,
    pub agent_id: &'static str,
    pub public_key_hex: String,
    pub algorithm: &'static str,
    pub timestamp: DateTime<Utc>,
}

/// Réponse ECDH (POST /ecdh/initiate).
#[derive(Debug, Serialize)]
pub struct ReponseEcdh {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub peer_agent_id: String,
    // SECURITY: ne pas logguer ce champ
    pub shared_secret_hex: String,
    pub note: &'static str,
    pub timestamp: DateTime<Utc>,
}

/// Réponse génération mot de passe (POST /password/generate).
#[derive(Debug, Serialize)]
pub struct ReponseMotDePasse {
    pub request_id: String,
    pub message_type: &'static str,
    pub status: &'static str,
    pub password: String,
    pub longueur: usize,
    pub score: u32,
    pub details: crate::crypto_moteur::ForceDetails,
    pub timestamp: DateTime<Utc>,
}

// ── Alertes sortantes ─────────────────────────────────────────────────────────

/// Alerte envoyée à l'agent auditeur.
#[derive(Debug, Serialize)]
pub struct AlerteSecretFaible {
    pub request_id: String,
    pub message_type: &'static str,
    pub source_agent: &'static str,
    pub event_type: &'static str,
    pub timestamp: DateTime<Utc>,
    pub data: AlerteSecretFaibleData,
}

#[derive(Debug, Serialize)]
pub struct AlerteSecretFaibleData {
    pub severity: &'static str,
    pub score: u32,
    pub threshold: u32,
}

/// Alerte pool d'entropie faible.
#[derive(Debug, Serialize)]
pub struct AlerteEntropie {
    pub request_id: String,
    pub message_type: &'static str,
    pub source_agent: &'static str,
    pub event_type: &'static str,
    pub timestamp: DateTime<Utc>,
    pub data: AlerteEntropieData,
}

#[derive(Debug, Serialize)]
pub struct AlerteEntropieData {
    pub severity: &'static str,
    pub entropy_bytes: u32,
    pub threshold: u32,
    pub action: &'static str,
}

/// Événement de rotation envoyé à l'auditeur (`POST /events`, port 5005).
#[derive(Debug, Serialize)]
pub struct EvenementRotationAuditeur {
    pub request_id: String,
    pub source_agent: &'static str,
    pub event_type: &'static str,
    pub timestamp: DateTime<Utc>,
    pub data: EvenementRotationAuditeurData,
}

#[derive(Debug, Serialize)]
pub struct EvenementRotationAuditeurData {
    /// `automatique` ou `ordonnee` (ordonnée par le Décideur).
    pub type_rotation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordonne_par: Option<String>,
    pub proxies_total: usize,
    pub proxies_reussis: u32,
    pub proxies_echecs: usize,
}

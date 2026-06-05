//! # Configuration externalisée — Agent Chiffreur ENSPY
//!
//! La configuration est lue depuis :
//! 1. Le fichier `config/agent_config.json` (chargé au démarrage)
//! 2. Les variables d'environnement du processus (priorité sur le JSON)
//!
//! ## Format du fichier `config/agent_config.json`
//!
//! ```json
//! {
//!   "agent_port": 5004,
//!   "agent_token": "...",
//!   "intervalle_rotation_sec": 300,
//!   "old_key_grace_sec": 60,
//!   "agent_rotation_autorise": "Decideur",
//!   "intervalle_supervision_sec": 10,
//!   "seuil_entropie": 256,
//!   "chemin_session": "data/session.json",
//!   "agent_auditeur_url": null,
//!   "agents_connus": { "Decideur": "http://localhost:5003" }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── Chemin par défaut du fichier de configuration ─────────────────────────────
pub const CHEMIN_CONFIG: &str = "config/agent_config.json";

// ── Structure de configuration ────────────────────────────────────────────────

/// Configuration complète de l'Agent Chiffreur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Port du serveur HTTP central (défaut: 5004).
    #[serde(default = "default_port")]
    pub agent_port: u16,

    /// Registre des proxies (`data/central_registry.json`).
    #[serde(default = "default_chemin_registry")]
    pub chemin_registry: String,

    /// Token d'authentification inter-agents.
    #[serde(default = "default_token")]
    pub agent_token: String,

    /// Intervalle de rotation automatique des clés AES (secondes, défaut: 300 = 5 min).
    /// Cette constante est stockée dans le fichier JSON pour être modifiable sans recompilation.
    #[serde(default = "default_rotation_sec")]
    pub intervalle_rotation_sec: u64,

    /// Durée de validité de l'ancienne clé (old_key) après rotation (secondes, défaut: 60).
    /// Pendant ce timer, new_key ET old_key sont valides.
    /// Après expiration, seule new_key reste valide.
    #[serde(default = "default_grace_sec")]
    pub old_key_grace_sec: u64,

    /// Nom de l'agent autorisé à déclencher la rotation (défaut: "Decideur").
    #[serde(default = "default_agent_rotation")]
    pub agent_rotation_autorise: String,

    /// Intervalle de supervision du pool d'entropie (secondes, défaut: 10).
    #[serde(default = "default_supervision_sec")]
    pub intervalle_supervision_sec: u64,

    /// Seuil critique du pool d'entropie en octets (défaut: 256).
    #[serde(default = "default_seuil_entropie")]
    pub seuil_entropie: u32,

    /// Chemin de la base `session.json` (clés VM : public_key, new_key, old_key).
    #[serde(rename = "chemin_session", default = "default_chemin_session", alias = "chemin_sessions_vm")]
    pub chemin_session: String,

    /// URL de l'agent auditeur pour les alertes (optionnel).
    #[serde(default)]
    pub agent_auditeur_url: Option<String>,

    /// Agents connus du SMA (map nom → URL).
    #[serde(default)]
    pub agents_connus: HashMap<String, String>,
}

// ── Valeurs par défaut ────────────────────────────────────────────────────────
fn default_port()           -> u16    { 5004 }
fn default_chemin_registry() -> String { "data/central_registry.json".to_string() }
fn default_token()          -> String { "ENSPY-TOKEN-2026".to_string() }
fn default_rotation_sec()   -> u64    { 300 }
fn default_grace_sec()      -> u64    { 60 }
fn default_agent_rotation() -> String { "Decideur".to_string() }
fn default_supervision_sec()-> u64    { 10 }
fn default_seuil_entropie() -> u32    { 256 }
fn default_chemin_session() -> String {
    crate::sessions_vm::CHEMIN_SESSION_DEFAUT.to_string()
}

// ── Chargement ────────────────────────────────────────────────────────────────

impl Config {
    /// Charge la configuration depuis le fichier JSON, puis surcharge
    /// avec les variables d'environnement si elles sont définies.
    ///
    /// Ordre de priorité (plus haute en premier) :
    ///   1. Variables d'environnement du processus
    ///   2. Fichier `config/agent_config.json`
    ///   3. Valeurs par défaut codées dans le type `Config`
    pub fn charger(chemin: Option<&str>) -> Self {
        let chemin = chemin
            .map(|s| s.to_string())
            .or_else(|| std::env::var("AGENT_CONFIG").ok())
            .unwrap_or_else(|| CHEMIN_CONFIG.to_string());
        let mut cfg = Self::depuis_fichier(&chemin);
        cfg.appliquer_surcharges_env();
        cfg
    }

    /// Charge depuis le fichier JSON. Retourne la config par défaut si absent.
    fn depuis_fichier(chemin: &str) -> Self {
        match std::fs::read_to_string(chemin) {
            Ok(contenu) => {
                match serde_json::from_str::<Self>(&contenu) {
                    Ok(cfg) => {
                        info!("[Config] Chargée depuis '{}'.", chemin);
                        cfg
                    }
                    Err(e) => {
                        warn!("[Config] JSON invalide dans '{}' : {} — config par défaut.", chemin, e);
                        Self::default()
                    }
                }
            }
            Err(_) => {
                warn!("[Config] '{}' absent — config par défaut (créer avec init_config.sh).", chemin);
                Self::default()
            }
        }
    }

    /// Surcharge les champs avec les variables d'environnement si définies.
    fn appliquer_surcharges_env(&mut self) {
        if let Ok(v) = std::env::var("AGENT_PORT") {
            if let Ok(p) = v.parse() { self.agent_port = p; }
        }
        if let Ok(v) = std::env::var("AGENT_TOKEN") {
            self.agent_token = v;
        }
        if let Ok(v) = std::env::var("AGENT_ROTATION_SEC") {
            if let Ok(s) = v.parse() { self.intervalle_rotation_sec = s; }
        }
        if let Ok(v) = std::env::var("AGENT_OLD_KEY_GRACE_SEC") {
            if let Ok(s) = v.parse() { self.old_key_grace_sec = s; }
        }
        if let Ok(v) = std::env::var("AGENT_ROTATION_AUTORISE") {
            self.agent_rotation_autorise = v;
        }
        if let Ok(v) = std::env::var("AGENT_SUPERVISION_SEC") {
            if let Ok(s) = v.parse() { self.intervalle_supervision_sec = s; }
        }
        if let Ok(v) = std::env::var("AGENT_ENTROPIE_SEUIL") {
            if let Ok(s) = v.parse() { self.seuil_entropie = s; }
        }
        if let Ok(v) = std::env::var("AGENT_SESSION_FILE").or_else(|_| std::env::var("AGENT_SESSIONS_VM")) {
            self.chemin_session = v;
        }
        if let Ok(v) = std::env::var("AGENT_AUDITEUR_URL") {
            self.agent_auditeur_url = Some(v);
        }
    }

    /// Sauvegarde la configuration courante dans le fichier JSON.
    pub fn sauvegarder(&self, chemin: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(chemin).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Impossible de créer '{}': {}", parent.display(), e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Sérialisation config : {}", e))?;
        std::fs::write(chemin, json)
            .map_err(|e| format!("Écriture config : {}", e))?;
        info!("[Config] Sauvegardée dans '{}'.", chemin);
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent_port: default_port(),
            chemin_registry: default_chemin_registry(),
            agent_token: default_token(),
            intervalle_rotation_sec: default_rotation_sec(),
            old_key_grace_sec: default_grace_sec(),
            agent_rotation_autorise: default_agent_rotation(),
            intervalle_supervision_sec: default_supervision_sec(),
            seuil_entropie: default_seuil_entropie(),
            chemin_session: default_chemin_session(),
            agent_auditeur_url: None,
            agents_connus: HashMap::new(),
        }
    }
}

// Alias pour rétrocompatibilité avec main.rs
impl Config {
    pub fn depuis_env() -> Self {
        Self::charger(None)
    }
    pub fn http_port(&self) -> u16 { self.agent_port }
    pub fn intervalle_supervision(&self) -> u64 { self.intervalle_supervision_sec }
    pub fn intervalle_rotation_sec(&self) -> u64 { self.intervalle_rotation_sec }
}

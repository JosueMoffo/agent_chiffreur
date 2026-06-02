//! # Base de données des clés VM — `data/session.json`
//!
//! Fichier persistant modifiable à chaque enregistrement de session ou rotation ECDH.
//! Identifiants VM : entiers **> 100** (convention Proxmox).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Chemin par défaut de la base sessions VM.
pub const CHEMIN_SESSION_DEFAUT: &str = "data/session.json";

/// Identifiant VM minimal (Proxmox : VMID > 100).
pub const VM_ID_MIN: u32 = 101;

/// Valide qu'un VMID respecte la convention Proxmox (> 100).
pub fn valider_vm_id(id: u32) -> Result<(), String> {
    if id <= 100 {
        Err(format!(
            "vm_id doit être un entier strictement supérieur à 100 (reçu {id})"
        ))
    } else {
        Ok(())
    }
}

/// Parse `vm_id` depuis un champ JSON (nombre ou chaîne).
pub fn parse_vm_id_json(v: &serde_json::Value) -> Option<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

// ── Structures ────────────────────────────────────────────────────────────────

/// Session active d'une VM dans `session.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionVm {
    pub vm_id: u32,

    /// Clé publique X25519 de la VM (hex, 64 caractères = 32 octets).
    #[serde(alias = "vm_pub_key_hex")]
    pub public_key: String,

    /// Clé publique X25519 **éphémère** de l'agent pour l'epoch courante (hex 64).
    /// Régénérée à chaque register et chaque rotation.
    #[serde(default)]
    pub agent_public_key: String,

    /// Clé AES-256 active (hex, 64 caractères).
    // SECURITY: ne pas logguer
    pub new_key: String,

    /// Ancienne clé pendant le timer de grâce.
    // SECURITY: ne pas logguer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_key_expire_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotation: Option<DateTime<Utc>>,

    pub rotation_count: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_notification: Option<String>,
}

impl SessionVm {
    pub fn nouvelle(
        vm_id: u32,
        public_key: String,
        agent_public_key: String,
        new_key: String,
        url_notification: Option<String>,
    ) -> Self {
        Self {
            vm_id,
            public_key,
            agent_public_key,
            new_key,
            old_key: None,
            old_key_expire_at: None,
            created_at: Utc::now(),
            last_rotation: None,
            rotation_count: 0,
            url_notification,
        }
    }

    pub fn old_key_valide(&self) -> bool {
        match (self.old_key.as_ref(), self.old_key_expire_at) {
            (Some(_), Some(expire)) => Utc::now() < expire,
            _ => false,
        }
    }

    pub fn appliquer_rotation(
        &mut self,
        agent_public_key: String,
        nouveau_secret_hex: String,
        grace_sec: u64,
    ) {
        self.agent_public_key = agent_public_key;
        self.old_key = Some(std::mem::replace(&mut self.new_key, nouveau_secret_hex));
        self.old_key_expire_at = Some(Utc::now() + chrono::Duration::seconds(grace_sec as i64));
        self.last_rotation = Some(Utc::now());
        self.rotation_count += 1;

        info!(
            "[SessionVM] Rotation vm_id={} — rotation_count={} — old_key expire {:?}",
            self.vm_id, self.rotation_count, self.old_key_expire_at
        );
    }

    pub fn purger_old_key_si_expiree(&mut self) -> bool {
        if self.old_key.is_some() && !self.old_key_valide() {
            self.old_key = None;
            self.old_key_expire_at = None;
            info!("[SessionVM] old_key expirée purgée pour vm_id={}", self.vm_id);
            return true;
        }
        false
    }

    pub fn resume_public(&self) -> ResumeSessionVm {
        ResumeSessionVm {
            vm_id: self.vm_id,
            public_key_preview: format!("{}...", &self.public_key[..16.min(self.public_key.len())]),
            agent_public_key_preview: format!(
                "{}...",
                &self.agent_public_key[..16.min(self.agent_public_key.len())]
            ),
            new_key_id: cle_vers_id(&self.new_key),
            old_key_id: self.old_key.as_deref().map(cle_vers_id),
            old_key_expire_at: self.old_key_expire_at,
            created_at: self.created_at,
            last_rotation: self.last_rotation,
            rotation_count: self.rotation_count,
            old_key_valide: self.old_key_valide(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResumeSessionVm {
    pub vm_id: u32,
    pub public_key_preview: String,
    pub agent_public_key_preview: String,
    pub new_key_id: String,
    pub old_key_id: Option<String>,
    pub old_key_expire_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_rotation: Option<DateTime<Utc>>,
    pub rotation_count: u32,
    pub old_key_valide: bool,
}

fn cle_vers_id(hex_str: &str) -> String {
    format!("k_{}", &hex_str[..8.min(hex_str.len())])
}

fn cle_session(vm_id: u32) -> String {
    vm_id.to_string()
}

// ── Store JSON ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreSessionsVm {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub sessions: HashMap<String, SessionVm>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub derniere_mise_a_jour: Option<DateTime<Utc>>,
}

fn default_schema_version() -> String {
    "2.0".to_string()
}

impl StoreSessionsVm {
    pub fn charger(chemin: &str) -> Self {
        match std::fs::read_to_string(chemin) {
            Ok(contenu) => serde_json::from_str(&contenu).unwrap_or_else(|e| {
                warn!("[session.json] JSON invalide dans '{}' : {} — store vide.", chemin, e);
                StoreSessionsVm::default()
            }),
            Err(_) => {
                info!("[session.json] '{}' absent — démarrage avec store vide.", chemin);
                StoreSessionsVm::default()
            }
        }
    }

    pub fn sauvegarder(&mut self, chemin: &str) -> Result<(), String> {
        self.derniere_mise_a_jour = Some(Utc::now());

        if let Some(parent) = Path::new(chemin).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Impossible de créer '{}' : {}", parent.display(), e))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Sérialisation session.json : {}", e))?;

        std::fs::write(chemin, json).map_err(|e| format!("Écriture '{}' : {}", chemin, e))?;
        Ok(())
    }
}

// ── Gestionnaire ──────────────────────────────────────────────────────────────

pub struct GestionnaireSessionsVm {
    pub store: RwLock<StoreSessionsVm>,
    pub chemin: String,
    pub grace_sec: u64,
}

impl GestionnaireSessionsVm {
    pub fn nouveau(chemin: &str, grace_sec: u64) -> Arc<Self> {
        let store = StoreSessionsVm::charger(chemin);
        info!(
            "[GestionnaireSessionsVm] {} VM(s) chargée(s) depuis '{}'.",
            store.sessions.len(),
            chemin
        );
        Arc::new(Self {
            store: RwLock::new(store),
            chemin: chemin.to_string(),
            grace_sec,
        })
    }

    pub async fn enregistrer_session(
        &self,
        vm_id: u32,
        public_key: String,
        agent_public_key: String,
        new_key_hex: String,
        url_notification: Option<String>,
    ) -> Result<ResumeSessionVm, String> {
        valider_vm_id(vm_id)?;

        let mut store = self.store.write().await;
        let session = SessionVm::nouvelle(
            vm_id,
            public_key,
            agent_public_key,
            new_key_hex,
            url_notification,
        );
        let resume = session.resume_public();
        store.sessions.insert(cle_session(vm_id), session);
        store.sauvegarder(&self.chemin)?;
        Ok(resume)
    }

    pub async fn appliquer_rotation_vm(
        &self,
        vm_id: u32,
        agent_public_key: String,
        nouveau_secret_hex: String,
    ) -> Result<ResumeSessionVm, String> {
        let mut store = self.store.write().await;
        let key = cle_session(vm_id);
        let session = store
            .sessions
            .get_mut(&key)
            .ok_or_else(|| format!("VM {vm_id} introuvable dans session.json"))?;

        session.appliquer_rotation(agent_public_key, nouveau_secret_hex, self.grace_sec);
        let resume = session.resume_public();
        store.sauvegarder(&self.chemin)?;
        Ok(resume)
    }

    pub async fn get_new_key(&self, vm_id: u32) -> Option<String> {
        self.store
            .read()
            .await
            .sessions
            .get(&cle_session(vm_id))
            .map(|s| s.new_key.clone())
    }

    pub async fn get_old_key_si_valide(&self, vm_id: u32) -> Option<String> {
        let store = self.store.read().await;
        let session = store.sessions.get(&cle_session(vm_id))?;
        if session.old_key_valide() {
            session.old_key.clone()
        } else {
            None
        }
    }

    /// Clés AES pour chiffrement (`new_key`) et déchiffrement (éventuelle `old_key` en grâce).
    pub async fn get_cles_aes_vm(
        &self,
        vm_id: u32,
    ) -> Result<(String, Option<String>), String> {
        valider_vm_id(vm_id)?;
        let store = self.store.read().await;
        let session = store
            .sessions
            .get(&cle_session(vm_id))
            .ok_or_else(|| format!("VM {vm_id} introuvable — enregistrez-la via POST /vm/session/register"))?;
        let old = if session.old_key_valide() {
            session.old_key.clone()
        } else {
            None
        };
        Ok((session.new_key.clone(), old))
    }

    pub async fn purger_cles_expirees(&self) -> usize {
        let mut store = self.store.write().await;
        let mut nb_purgees = 0usize;

        for session in store.sessions.values_mut() {
            if session.purger_old_key_si_expiree() {
                nb_purgees += 1;
            }
        }

        if nb_purgees > 0 {
            if let Err(e) = store.sauvegarder(&self.chemin) {
                warn!("[GestionnaireSessionsVm] Échec sauvegarde après purge : {}", e);
            }
            info!("[GestionnaireSessionsVm] {} old_key(s) purgée(s).", nb_purgees);
        }

        nb_purgees
    }

    pub async fn supprimer_session(&self, vm_id: u32) -> bool {
        let mut store = self.store.write().await;
        let existe = store.sessions.remove(&cle_session(vm_id)).is_some();
        if existe {
            if let Err(e) = store.sauvegarder(&self.chemin) {
                warn!("[GestionnaireSessionsVm] Échec sauvegarde après suppression : {}", e);
            }
            info!("[GestionnaireSessionsVm] Session vm_id={} supprimée.", vm_id);
        }
        existe
    }

    pub async fn lister_sessions(&self) -> Vec<ResumeSessionVm> {
        let store = self.store.read().await;
        let mut sessions: Vec<ResumeSessionVm> =
            store.sessions.values().map(|s| s.resume_public()).collect();
        sessions.sort_by_key(|s| s.vm_id);
        sessions
    }

    pub async fn get_resume_vm(&self, vm_id: u32) -> Option<ResumeSessionVm> {
        self.store
            .read()
            .await
            .sessions
            .get(&cle_session(vm_id))
            .map(|s| s.resume_public())
    }

    pub async fn get_urls_notification(&self) -> Vec<(u32, String)> {
        let store = self.store.read().await;
        store
            .sessions
            .values()
            .filter_map(|s| {
                s.url_notification
                    .as_ref()
                    .map(|url| (s.vm_id, url.clone()))
            })
            .collect()
    }

    /// Lecture du fichier session.json depuis le disque (vérif. persistance).
    pub fn lire_fichier_session(chemin: &str) -> Result<StoreSessionsVm, String> {
        let contenu = std::fs::read_to_string(chemin)
            .map_err(|e| format!("Lecture '{chemin}' : {e}"))?;
        serde_json::from_str(&contenu).map_err(|e| format!("JSON invalide : {e}"))
    }
}

pub async fn tache_purge_cles(gestionnaire: Arc<GestionnaireSessionsVm>, intervalle_sec: u64) {
    info!(
        "[PURGE] Tâche de purge des clés expirées (intervalle={}s).",
        intervalle_sec
    );
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(intervalle_sec));
    interval.tick().await;

    loop {
        interval.tick().await;
        let n = gestionnaire.purger_cles_expirees().await;
        if n > 0 {
            info!("[PURGE] {} old_key(s) expirée(s) supprimée(s).", n);
        }
    }
}

//! # Gestionnaire de rotation automatique — Agent Chiffreur ENSPY
//!
//! Ce module orchestre :
//!
//! - La **rotation automatique** périodique des clés (intervalle configurable via .env)
//! - Le **re-chiffrement** des données historiques après chaque rotation
//! - Le **stockage persistant** des données de session en JSON
//!
//! ## Fichier de données de session
//!
//! Les blobs chiffrés actifs sont stockés dans `data/session_store.json` :
//!
//! ```json
//! {
//!   "blobs": [ { "entete": "...", "ciphertext": "...", "iv": "...", ... } ],
//!   "derniere_rotation": "2026-05-30T12:00:00Z",
//!   "rotations_effectuees": 3
//! }
//! ```

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::error::CryptoError;
use crate::trousseau::{BlobVersionne, Trousseau};

/// Chemin par défaut du fichier de session.
pub const CHEMIN_SESSION: &str = "data/session_store.json";

// ── Structure de données de session ──────────────────────────────────────────

/// Contenu persisté du store de session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStore {
    /// Blobs chiffrés actifs (mis à jour après chaque rotation).
    pub blobs: Vec<BlobVersionne>,
    /// Date de la dernière rotation.
    pub derniere_rotation: Option<chrono::DateTime<chrono::Utc>>,
    /// Nombre total de rotations effectuées.
    pub rotations_effectuees: u32,
}

impl SessionStore {
    /// Charge le store depuis un fichier JSON. Retourne un store vide si absent.
    pub fn charger(chemin: &str) -> Self {
        match std::fs::read_to_string(chemin) {
            Ok(contenu) => serde_json::from_str(&contenu).unwrap_or_else(|e| {
                warn!("SessionStore : JSON invalide dans '{}' : {}", chemin, e);
                SessionStore::default()
            }),
            Err(_) => {
                info!("SessionStore : '{}' absent — démarrage avec store vide.", chemin);
                SessionStore::default()
            }
        }
    }

    /// Persiste le store sur disque.
    pub fn sauvegarder(&self, chemin: &str) -> Result<(), String> {
        // Créer le répertoire si nécessaire
        if let Some(parent) = Path::new(chemin).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Impossible de créer le répertoire '{}' : {}", parent.display(), e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Sérialisation SessionStore : {}", e))?;
        std::fs::write(chemin, json)
            .map_err(|e| format!("Écriture '{}' : {}", chemin, e))?;
        Ok(())
    }
}

// ── Gestionnaire de rotation ──────────────────────────────────────────────────

/// Gestionnaire de rotation partagé entre les threads.
pub struct GestionnaireRotation {
    pub trousseau: RwLock<Trousseau>,
    pub store: RwLock<SessionStore>,
    pub chemin_session: String,
}

impl GestionnaireRotation {
    /// Crée un nouveau gestionnaire en chargeant le trousseau et le store.
    pub fn nouveau(trousseau: Trousseau, chemin_session: Option<&str>) -> Arc<Self> {
        let chemin = chemin_session.unwrap_or(CHEMIN_SESSION).to_string();
        let store = SessionStore::charger(&chemin);
        info!(
            "GestionnaireRotation : {} blob(s) en session, {} rotation(s) passées.",
            store.blobs.len(),
            store.rotations_effectuees
        );
        Arc::new(Self {
            trousseau: RwLock::new(trousseau),
            store: RwLock::new(store),
            chemin_session: chemin,
        })
    }

    /// Chiffre un plaintext avec la clé active et enregistre le blob en session.
    pub async fn chiffrer_et_enregistrer(
        &self,
        plaintext: &str,
    ) -> Result<BlobVersionne, CryptoError> {
        let blob = {
            let trou = self.trousseau.read().await;
            trou.chiffrer(plaintext)?
        };

        // Enregistrer le blob dans le store
        {
            let mut store = self.store.write().await;
            store.blobs.push(blob.clone());
            if let Err(e) = store.sauvegarder(&self.chemin_session) {
                warn!("SessionStore : échec sauvegarde après chiffrement : {}", e);
            }
        }

        Ok(blob)
    }

    /// Déchiffre un blob en routant vers la bonne clé.
    pub async fn dechiffrer(&self, blob: &BlobVersionne) -> Result<String, CryptoError> {
        let trou = self.trousseau.read().await;
        trou.dechiffrer(blob)
    }

    /// Effectue une rotation complète :
    /// 1. Génère/charge une nouvelle clé
    /// 2. Archive l'ancienne
    /// 3. Re-chiffre tous les blobs historiques
    /// 4. Met à jour le store
    ///
    /// Retourne un rapport de rotation.
    pub async fn effectuer_rotation(
        &self,
        nouvelle_cle_hex: Option<&str>,
    ) -> RapportRotation {
        let debut = Utc::now();
        let mut rapport = RapportRotation {
            timestamp: debut,
            ancien_key_id: String::new(),
            nouveau_key_id: String::new(),
            blobs_total: 0,
            blobs_migres: 0,
            blobs_echecs: 0,
            erreur: None,
        };

        // Récupérer l'ancien key_id
        {
            let trou = self.trousseau.read().await;
            rapport.ancien_key_id = trou.key_id_actif().to_string();
        }

        // Effectuer la rotation dans le trousseau
        let nouveau_key_id = {
            let mut trou = self.trousseau.write().await;
            match trou.tourner(nouvelle_cle_hex) {
                Ok(kid) => kid,
                Err(e) => {
                    rapport.erreur = Some(e.to_string());
                    error!("Rotation échouée : {}", e);
                    return rapport;
                }
            }
        };
        rapport.nouveau_key_id = nouveau_key_id;

        // Re-chiffrer les blobs historiques
        {
            let blobs_anciens: Vec<BlobVersionne> = {
                let store = self.store.read().await;
                store.blobs.clone()
            };

            rapport.blobs_total = blobs_anciens.len();

            let resultats = {
                let trou = self.trousseau.read().await;
                trou.rechiffrer_historique(&blobs_anciens)
            };

            let mut nouveaux_blobs = Vec::with_capacity(resultats.len());
            for r in &resultats {
                if let Some(ref blob) = r.nouveau_blob {
                    nouveaux_blobs.push(blob.clone());
                    if r.migre {
                        rapport.blobs_migres += 1;
                    }
                } else {
                    rapport.blobs_echecs += 1;
                    if let Some(ref err) = r.erreur {
                        warn!("Re-chiffrement échoué pour key_id={} : {}", r.ancien_key_id, err);
                    }
                }
            }

            // Mettre à jour le store
            let mut store = self.store.write().await;
            store.blobs = nouveaux_blobs;
            store.derniere_rotation = Some(debut);
            store.rotations_effectuees += 1;

            if let Err(e) = store.sauvegarder(&self.chemin_session) {
                error!("SessionStore : échec sauvegarde après rotation : {}", e);
            }
        }

        info!(
            "Rotation terminée : {} blobs migrés, {} échecs, nouveau key_id={}",
            rapport.blobs_migres, rapport.blobs_echecs, rapport.nouveau_key_id
        );
        rapport
    }

    /// Retourne le résumé du trousseau courant.
    pub async fn resume_trousseau(&self) -> crate::trousseau::ResumeTrousseau {
        self.trousseau.read().await.resume()
    }
}

/// Rapport détaillé d'une opération de rotation.
#[derive(Debug, Clone, Serialize)]
pub struct RapportRotation {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub ancien_key_id: String,
    pub nouveau_key_id: String,
    pub blobs_total: usize,
    pub blobs_migres: usize,
    pub blobs_echecs: usize,
    pub erreur: Option<String>,
}

// ── Tâche de rotation automatique ────────────────────────────────────────────

/// Démarre la tâche de rotation automatique périodique.
///
/// L'intervalle est lu depuis `AGENT_ROTATION_SEC` (défaut: 300 secondes = 5 min).
/// Cette valeur doit être définie dans le fichier `.env`.
pub async fn tache_rotation_automatique(
    gestionnaire: Arc<GestionnaireRotation>,
    intervalle_sec: u64,
) {
    info!(
        "[ROTATION AUTO] Tâche démarrée — intervalle = {} secondes.",
        intervalle_sec
    );
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(intervalle_sec));

    // Sauter le premier tick immédiat
    interval.tick().await;

    loop {
        interval.tick().await;
        info!("[ROTATION AUTO] Déclenchement rotation automatique...");
        let rapport = gestionnaire.effectuer_rotation(None).await;
        if let Some(ref err) = rapport.erreur {
            error!("[ROTATION AUTO] Échec : {}", err);
        } else {
            info!(
                "[ROTATION AUTO] Rotation {} → {} | {} blobs migrés",
                rapport.ancien_key_id, rapport.nouveau_key_id, rapport.blobs_migres
            );
        }
    }
}

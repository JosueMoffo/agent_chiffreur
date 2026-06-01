//! # Trousseau de clés versionné — Agent Chiffreur ENSPY
//!
//! Ce module gère le cycle de vie des clés AES-256 :
//!
//! - **Versionnage** : chaque clé porte un `key_id` unique et une date de création
//! - **Rotation** : ajout d'une nouvelle clé active, conservation des anciennes
//! - **Re-chiffrement** : migration des données historiques vers la clé active
//! - **En-tête de ciphertext** : chaque blob chiffré embarque le `key_id`
//!
//! ## Format du ciphertext versionné
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  EN-TÊTE (JSON Base64)  │  PAYLOAD AES-GCM (Base64)    │
//! │  { key_id, version,     │  { ciphertext, iv, auth_tag } │
//! │    created_at }         │                               │
//! └─────────────────────────────────────────────────────────┘
//! Format final : "<header_b64>.<ciphertext_b64>.<iv_b64>.<tag_b64>"
//! ```

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// ── Constantes ────────────────────────────────────────────────────────────────

/// Nombre maximum de clés archivées conservées (hors clé active).
pub const MAX_CLES_ARCHIVEES: usize = 10;

// ── Types publics ─────────────────────────────────────────────────────────────

/// En-tête embarqué dans chaque ciphertext versionné.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnteteCiphertext {
    /// Identifiant unique de la clé utilisée (format: "k_<hex8>").
    pub key_id: String,
    /// Numéro de version incrémental (1, 2, 3...).
    pub version: u32,
    /// Date de création de la clé (ISO 8601).
    pub created_at: DateTime<Utc>,
    /// Algorithme utilisé.
    pub algo: String,
}

/// Un enregistrement de clé dans le trousseau.
#[derive(Clone)]
pub struct EntreeCle {
    /// Identifiant unique de la clé.
    pub key_id: String,
    /// Version incrémentale.
    pub version: u32,
    /// Date de création.
    pub created_at: DateTime<Utc>,
    /// Matériel de clé brut (32 octets).
    // SECURITY: ne pas logguer
    key_material: CleAes,
}

/// Wrapper zéroïsable pour le matériel de clé.
#[derive(Clone, ZeroizeOnDrop)]
struct CleAes([u8; 32]);

/// Trousseau de clés versionné — thread-safe via `Arc<RwLock<Trousseau>>`.
pub struct Trousseau {
    /// Clé active (la plus récente).
    active: EntreeCle,
    /// Clés archivées (pour déchiffrement des données historiques).
    /// Clé de la map = key_id.
    archivees: HashMap<String, EntreeCle>,
}

// ── Implémentation ────────────────────────────────────────────────────────────

impl EntreeCle {
    /// Crée une nouvelle entrée de clé depuis des octets bruts.
    pub fn depuis_bytes(key_id: String, version: u32, raw: [u8; 32]) -> Self {
        Self {
            key_id,
            version,
            created_at: Utc::now(),
            key_material: CleAes(raw),
        }
    }

    /// Crée une nouvelle entrée de clé depuis un hex string (64 chars).
    pub fn depuis_hex(key_id: String, version: u32, hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::CleHexInvalide(format!("décodage hex : {e}")))?;
        if bytes.len() != 32 {
            return Err(CryptoError::CleHexInvalide(format!(
                "longueur attendue 32 octets, reçu {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::depuis_bytes(key_id, version, arr))
    }

    /// Génère une nouvelle entrée de clé aléatoire.
    pub fn generer(version: u32) -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let key_id = format!("k_{}", hex::encode(&raw[..4]));
        Self::depuis_bytes(key_id, version, raw)
    }

    /// Retourne l'en-tête associé à cette clé.
    pub fn entete(&self) -> EnteteCiphertext {
        EnteteCiphertext {
            key_id: self.key_id.clone(),
            version: self.version,
            created_at: self.created_at,
            algo: "AES-256-GCM".to_string(),
        }
    }

    /// Chiffre un plaintext et retourne un blob versionné.
    ///
    /// Format : `<entete_b64>.<ciphertext_b64>.<iv_b64>.<tag_b64>`
    pub fn chiffrer(&self, plaintext: &str) -> Result<BlobVersionne, CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key_material.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ct_avec_tag = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::ChiffrementEchoue(e.to_string()))?;

        let (ciphertext, auth_tag) = ct_avec_tag.split_at(ct_avec_tag.len() - 16);

        let entete = self.entete();
        let entete_json = serde_json::to_string(&entete)
            .map_err(|e| CryptoError::ChiffrementEchoue(format!("sérialisation entête : {e}")))?;

        Ok(BlobVersionne {
            entete: entete_json,
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            iv: URL_SAFE_NO_PAD.encode(nonce.as_slice()),
            auth_tag: URL_SAFE_NO_PAD.encode(auth_tag),
            key_id: self.key_id.clone(),
            version: self.version,
        })
    }

    /// Déchiffre un blob dont le `key_id` correspond à cette clé.
    pub fn dechiffrer(
        &self,
        ciphertext_b64: &str,
        iv_b64: &str,
        tag_b64: &str,
    ) -> Result<String, CryptoError> {
        let ciphertext = URL_SAFE_NO_PAD
            .decode(ciphertext_b64)
            .map_err(|e| CryptoError::Base64Invalide(format!("ciphertext : {e}")))?;
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(iv_b64)
            .map_err(|e| CryptoError::Base64Invalide(format!("iv : {e}")))?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag_b64)
            .map_err(|e| CryptoError::Base64Invalide(format!("auth_tag : {e}")))?;

        let mut ct_avec_tag = ciphertext;
        ct_avec_tag.extend_from_slice(&tag);

        let key = Key::<Aes256Gcm>::from_slice(&self.key_material.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes = cipher
            .decrypt(nonce, ct_avec_tag.as_slice())
            .map_err(|_| {
                warn!("Échec GCM pour key_id={}", self.key_id);
                CryptoError::IntegriteEchouee
            })?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| CryptoError::ChiffrementEchoue(format!("UTF-8 invalide : {e}")))
    }
}

/// Blob chiffré avec en-tête de versionnage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobVersionne {
    /// En-tête JSON sérialisé (non encodé, pour lisibilité).
    pub entete: String,
    /// Ciphertext AES-GCM en Base64 URL-safe.
    pub ciphertext: String,
    /// Nonce / IV en Base64 URL-safe.
    pub iv: String,
    /// Tag d'authentification GCM en Base64 URL-safe.
    pub auth_tag: String,
    /// key_id redondant pour routing rapide (sans décodage JSON).
    pub key_id: String,
    /// Version redondante pour tri rapide.
    pub version: u32,
}

impl BlobVersionne {
    /// Sérialise le blob en chaîne transportable.
    /// Format : JSON compact (sérialisable pour stockage ou transport HTTP).
    pub fn serialiser(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Désérialise un blob depuis une chaîne JSON.
    pub fn deserialiser(s: &str) -> Result<Self, CryptoError> {
        serde_json::from_str(s)
            .map_err(|e| CryptoError::Base64Invalide(format!("blob JSON invalide : {e}")))
    }
}

// ── Trousseau ─────────────────────────────────────────────────────────────────

impl Trousseau {
    /// Initialise le trousseau depuis une clé hexadécimale persistante.
    /// Si `hex_opt` est `None`, génère une clé aléatoire (mode éphémère).
    pub fn nouveau(hex_opt: Option<&str>) -> Result<Self, CryptoError> {
        let active = match hex_opt {
            Some(h) => {
                info!("Trousseau : clé v1 chargée depuis AGENT_AES_KEY_HEX");
                EntreeCle::depuis_hex("k_v1_persist".to_string(), 1, h)?
            }
            None => {
                info!("Trousseau : génération d'une clé v1 éphémère");
                EntreeCle::generer(1)
            }
        };
        info!("Trousseau initialisé — clé active : key_id={} v{}", active.key_id, active.version);
        Ok(Self {
            active,
            archivees: HashMap::new(),
        })
    }

    /// Retourne le `key_id` de la clé active.
    pub fn key_id_actif(&self) -> &str {
        &self.active.key_id
    }

    /// Retourne la version de la clé active.
    pub fn version_active(&self) -> u32 {
        self.active.version
    }

    /// Chiffre un plaintext avec la clé active.
    pub fn chiffrer(&self, plaintext: &str) -> Result<BlobVersionne, CryptoError> {
        self.active.chiffrer(plaintext)
    }

    /// Déchiffre un blob en routant vers la bonne clé via `key_id`.
    pub fn dechiffrer(&self, blob: &BlobVersionne) -> Result<String, CryptoError> {
        let cle = if blob.key_id == self.active.key_id {
            &self.active
        } else {
            self.archivees.get(&blob.key_id).ok_or_else(|| {
                CryptoError::CleHexInvalide(format!(
                    "key_id '{}' introuvable dans le trousseau (v{})",
                    blob.key_id, blob.version
                ))
            })?
        };
        cle.dechiffrer(&blob.ciphertext, &blob.iv, &blob.auth_tag)
    }

    /// Effectue une rotation :
    /// 1. Archive la clé active
    /// 2. Active la nouvelle clé
    /// 3. Expurge les archives si `MAX_CLES_ARCHIVEES` est dépassé
    ///
    /// Retourne le `key_id` de la nouvelle clé active.
    pub fn tourner(&mut self, nouvelle_cle_hex: Option<&str>) -> Result<String, CryptoError> {
        let ancienne_version = self.active.version;
        let nouvelle_version = ancienne_version + 1;

        let nouvelle = match nouvelle_cle_hex {
            Some(h) => {
                let kid = format!("k_v{}_persist", nouvelle_version);
                EntreeCle::depuis_hex(kid, nouvelle_version, h)?
            }
            None => EntreeCle::generer(nouvelle_version),
        };

        let nouveau_key_id = nouvelle.key_id.clone();

        // Archiver l'ancienne clé active
        let ancienne = std::mem::replace(&mut self.active, nouvelle);
        info!(
            "Rotation : ancienne clé key_id={} v{} archivée",
            ancienne.key_id, ancienne.version
        );
        self.archivees.insert(ancienne.key_id.clone(), ancienne);

        // Expurger les plus anciennes si trop d'archives
        if self.archivees.len() > MAX_CLES_ARCHIVEES {
            let mut versions: Vec<(u32, String)> = self
                .archivees
                .values()
                .map(|e| (e.version, e.key_id.clone()))
                .collect();
            versions.sort_by_key(|(v, _)| *v);
            // Supprimer la plus ancienne
            if let Some((_, kid_ancien)) = versions.first() {
                self.archivees.remove(kid_ancien);
                warn!("Trousseau : clé ancienne expurgée (limite MAX_CLES_ARCHIVEES atteinte)");
            }
        }

        info!(
            "Rotation terminée — nouvelle clé active : key_id={} v{}",
            self.active.key_id, self.active.version
        );
        Ok(nouveau_key_id)
    }

    /// Re-chiffre une liste de blobs historiques avec la clé active.
    ///
    /// Pour chaque blob :
    /// 1. Déchiffre avec la clé référencée par son `key_id`
    /// 2. Re-chiffre immédiatement avec la clé active
    /// 3. Retourne le nouveau blob
    ///
    /// Les blobs déjà chiffrés avec la clé active sont retournés inchangés.
    pub fn rechiffrer_historique(
        &self,
        blobs: &[BlobVersionne],
    ) -> Vec<ResultatRechiffrement> {
        blobs
            .iter()
            .map(|blob| {
                // Déjà sur la clé active → passer
                if blob.key_id == self.active.key_id {
                    return ResultatRechiffrement {
                        ancien_key_id: blob.key_id.clone(),
                        ancien_version: blob.version,
                        nouveau_blob: Some(blob.clone()),
                        erreur: None,
                        migre: false,
                    };
                }

                // Déchiffrer avec l'ancienne clé
                match self.dechiffrer(blob) {
                    Ok(plaintext) => {
                        // Re-chiffrer avec la clé active
                        match self.active.chiffrer(&plaintext) {
                            Ok(nouveau_blob) => {
                                info!(
                                    "Re-chiffrement : key_id {} v{} → {} v{}",
                                    blob.key_id,
                                    blob.version,
                                    nouveau_blob.key_id,
                                    nouveau_blob.version
                                );
                                ResultatRechiffrement {
                                    ancien_key_id: blob.key_id.clone(),
                                    ancien_version: blob.version,
                                    nouveau_blob: Some(nouveau_blob),
                                    erreur: None,
                                    migre: true,
                                }
                            }
                            Err(e) => ResultatRechiffrement {
                                ancien_key_id: blob.key_id.clone(),
                                ancien_version: blob.version,
                                nouveau_blob: None,
                                erreur: Some(e.to_string()),
                                migre: false,
                            },
                        }
                    }
                    Err(e) => ResultatRechiffrement {
                        ancien_key_id: blob.key_id.clone(),
                        ancien_version: blob.version,
                        nouveau_blob: None,
                        erreur: Some(e.to_string()),
                        migre: false,
                    },
                }
            })
            .collect()
    }

    /// Retourne un résumé du trousseau (sans matériel de clé).
    pub fn resume(&self) -> ResumeTrousseau {
        ResumeTrousseau {
            key_id_actif: self.active.key_id.clone(),
            version_active: self.active.version,
            created_at_active: self.active.created_at,
            nb_cles_archivees: self.archivees.len(),
            versions_archivees: {
                let mut v: Vec<u32> = self.archivees.values().map(|e| e.version).collect();
                v.sort();
                v
            },
        }
    }
}

/// Résultat du re-chiffrement d'un blob historique.
#[derive(Debug, Clone, Serialize)]
pub struct ResultatRechiffrement {
    pub ancien_key_id: String,
    pub ancien_version: u32,
    pub nouveau_blob: Option<BlobVersionne>,
    pub erreur: Option<String>,
    pub migre: bool,
}

/// Résumé public du trousseau (sans secrets).
#[derive(Debug, Clone, Serialize)]
pub struct ResumeTrousseau {
    pub key_id_actif: String,
    pub version_active: u32,
    pub created_at_active: DateTime<Utc>,
    pub nb_cles_archivees: usize,
    pub versions_archivees: Vec<u32>,
}

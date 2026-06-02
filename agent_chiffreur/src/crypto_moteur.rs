//! # Moteur Cryptographique — Agent Chiffreur ENSPY
//!
//! Ce module encapsule tous les services cryptographiques de l'Agent Chiffreur :
//!
//! - Chiffrement / déchiffrement **AES-256-GCM** avec nonce aléatoire
//! - Évaluation de la force d'un secret selon le **barème ENSPY (100 pts)**
//! - Hachage de secrets humains avec **Argon2id** (paramètres ENSPY)
//! - Génération de credentials sécurisés (mot de passe + clé d'accès)
//! - Paire de clés **ECC Curve25519** pour usage ECDH
//! - Génération de mots de passe selon options (étape 7)
//! - **Zeroing mémoire** systématique via `zeroize` sur tous les buffers sensibles

use std::collections::HashSet;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{distributions::Uniform, Rng};
use rand_core::RngCore;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Résultat d'un ECDH avec paire éphémère agent (nouvelle à chaque register / rotate).
#[derive(Debug, Clone)]
pub struct EchangeEphemere {
    /// Clé publique éphémère agent (hex 64) — à fournir à la VM pour recalculer le secret.
    pub agent_public_key_hex: String,
    /// Secret partagé 32 octets (= clé AES-256 pour la session).
    pub shared_secret: [u8; 32],
}

/// Génère une **nouvelle paire X25519 éphémère** et calcule le secret partagé avec `vm_public_key`.
///
/// Utilisé à chaque `POST /vm/session/register` et `POST /credential/rotate`.
///
/// # SECURITY: ne pas logguer `shared_secret`
pub fn ecdh_session_ephemere(vm_public_key: &[u8; 32]) -> Result<EchangeEphemere, CryptoError> {
    let agent_secret = StaticSecret::random_from_rng(OsRng);
    let agent_public = PublicKey::from(&agent_secret);
    let peer_key = PublicKey::from(*vm_public_key);
    let shared = agent_secret.diffie_hellman(&peer_key);
    info!(
        "ECDH session éphémère — agent_pub={}…",
        &hex::encode(agent_public.as_bytes())[..16]
    );
    Ok(EchangeEphemere {
        agent_public_key_hex: hex::encode(agent_public.as_bytes()),
        shared_secret: *shared.as_bytes(),
    })
}

/// Décode une clé publique X25519 hex (64 caractères → 32 octets).
pub fn decoder_cle_publique_x25519(hex_str: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| CryptoError::CleHexInvalide(format!("décodage hex : {e}")))?;
    if bytes.len() != 32 {
        return Err(CryptoError::CleHexInvalide(format!(
            "clé publique : 32 octets attendus, reçu {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Décode une clé AES-256 hex (64 caractères → 32 octets).
pub fn decoder_cle_aes_hex(hex_str: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| CryptoError::CleHexInvalide(format!("clé AES : {e}")))?;
    if bytes.len() != 32 {
        return Err(CryptoError::CleHexInvalide(format!(
            "clé AES : 32 octets attendus, reçu {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Chiffrement AES-256-GCM avec une clé VM (`new_key` hex).
pub fn chiffrer_aes_gcm_avec_cle(
    cle: &[u8; 32],
    plaintext: &str,
) -> Result<DonneesChiffrees, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(cle);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ct_avec_tag = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::ChiffrementEchoue(e.to_string()))?;

    let (ciphertext, auth_tag) = ct_avec_tag.split_at(ct_avec_tag.len().saturating_sub(16));

    Ok(DonneesChiffrees {
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        iv: URL_SAFE_NO_PAD.encode(nonce.as_slice()),
        auth_tag: URL_SAFE_NO_PAD.encode(auth_tag),
    })
}

/// Déchiffrement AES-256-GCM avec une clé VM (`new_key` ou `old_key` hex).
pub fn dechiffrer_aes_gcm_avec_cle(
    cle: &[u8; 32],
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
    let auth_tag = URL_SAFE_NO_PAD
        .decode(tag_b64)
        .map_err(|e| CryptoError::Base64Invalide(format!("auth_tag : {e}")))?;

    let mut ct_avec_tag = ciphertext;
    ct_avec_tag.extend_from_slice(&auth_tag);

    let key = Key::<Aes256Gcm>::from_slice(cle);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(nonce, ct_avec_tag.as_slice())
        .map_err(|_| CryptoError::IntegriteEchouee)?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| CryptoError::ChiffrementEchoue(format!("UTF-8 invalide : {e}")))
}

/// Tente `new_key`, puis `old_key` si la première échoue sur l'intégrité GCM.
pub fn dechiffrer_aes_gcm_vm(
    new_key_hex: &str,
    old_key_hex: Option<&str>,
    ciphertext_b64: &str,
    iv_b64: &str,
    tag_b64: &str,
) -> Result<(String, &'static str), CryptoError> {
    let new_key = decoder_cle_aes_hex(new_key_hex)?;
    match dechiffrer_aes_gcm_avec_cle(&new_key, ciphertext_b64, iv_b64, tag_b64) {
        Ok(p) => return Ok((p, "new")),
        Err(CryptoError::IntegriteEchouee) => {}
        Err(e) => return Err(e),
    }

    if let Some(old_hex) = old_key_hex {
        let old_key = decoder_cle_aes_hex(old_hex)?;
        match dechiffrer_aes_gcm_avec_cle(&old_key, ciphertext_b64, iv_b64, tag_b64) {
            Ok(p) => return Ok((p, "old")),
            Err(CryptoError::IntegriteEchouee) => {}
            Err(e) => return Err(e),
        }
    }

    Err(CryptoError::IntegriteEchouee)
}

// ── Constantes de configuration ──────────────────────────────────────────────

const LONGUEUR_MIN: usize = 12;
const MAX_PTS_LONGUEUR: u32 = 40;
const MAX_PTS_DIVERSITE: u32 = 35;
const MAX_PTS_ENTROPIE: u32 = 20;
const MAX_PTS_STRUCTURE: u32 = 5;
const ENTROPIE_REFERENCE: f64 = 60.0;

// ── Types de retour publics ───────────────────────────────────────────────────

/// Résultat détaillé de l'évaluation de la force d'un secret.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForceDetails {
    pub longueur_pts: u32,
    pub diversite_pts: u32,
    pub entropie_pts: u32,
    pub bonus_structure_pts: u32,
    pub longueur_reelle: usize,
    pub classes_presentes: Vec<String>,
    pub entropie_bits: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raison_refus: Option<String>,
}

/// Score global + détails de l'évaluation de force.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResultatForce {
    pub score: u32,
    pub details: ForceDetails,
}

/// Enveloppe de données chiffrées AES-256-GCM (champs encodés en Base64 URL-safe).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DonneesChiffrees {
    pub ciphertext: String,
    pub iv: String,
    pub auth_tag: String,
}

/// Paire de credentials générée aléatoirement.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Credentials {
    pub password: String,
    pub access_key: String,
}

/// Options de génération d'un mot de passe fort.
#[derive(Debug, Clone)]
pub struct OptionsMotDePasse {
    pub longueur: usize,
    pub majuscules: bool,
    pub minuscules: bool,
    pub chiffres: bool,
    pub symboles: bool,
    pub exclure_ambigus: bool,
}

// ── Structure principale ──────────────────────────────────────────────────────

/// Conteneur interne de la clé AES-256 de session.
#[derive(ZeroizeOnDrop)]
struct AesKey([u8; 32]);

/// Moteur cryptographique de l'Agent Chiffreur.
pub struct CryptoMoteur {
    aes_key: AesKey,
    ecc_public_key: [u8; 32],
    // Étape 5 : StaticSecret remplace EphemeralSecret pour permettre plusieurs échanges ECDH
    ecc_private_key: StaticSecret,
    argon2_params: Params,
}

impl CryptoMoteur {
    /// Crée et initialise le moteur cryptographique avec une clé AES éphémère.
    pub fn new() -> Self {
        Self::new_avec_cle(None).expect("Initialisation du moteur crypto impossible")
    }

    /// Crée et initialise le moteur avec une clé AES optionnelle.
    ///
    /// - `cle_hex` = `Some(s)` → décoder les 64 hex chars en 32 octets (clé persistante)
    /// - `cle_hex` = `None`   → générer aléatoirement (mode éphémère, défaut)
    pub fn new_avec_cle(cle_hex: Option<&str>) -> Result<Self, CryptoError> {
        // ── Clé AES-256 ──
        let raw_key: [u8; 32] = match cle_hex {
            Some(hex_str) => {
                info!("Mode clé AES : PERSISTANTE (depuis env)");
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
                arr
            }
            None => {
                info!("Mode clé AES : ÉPHÉMÈRE (nouvelle à chaque démarrage)");
                let mut arr = [0u8; 32];
                OsRng.fill(&mut arr);
                arr
            }
        };
        info!("Clé AES-256 de session initialisée ({} octets).", raw_key.len());

        // ── Paire ECC Curve25519 (StaticSecret pour ECDH multi-échanges) ──
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let pub_bytes = *public_key.as_bytes();
        info!(
            "Paire ECC Curve25519 générée. Clé publique (hex) : {}",
            hex::encode(pub_bytes)
        );

        // ── Paramètres Argon2id — politique ENSPY ──
        let params = Params::new(65_536, 3, 4, Some(32))
            .expect("Paramètres Argon2id invalides");
        info!("Hasheur Argon2id initialisé (t=3, m=65536, p=4, len=32).");

        Ok(Self {
            aes_key: AesKey(raw_key),
            ecc_public_key: pub_bytes,
            ecc_private_key: private_key,
            argon2_params: params,
        })
    }

    // ── Évaluation de la force d'un secret ───────────────────────────────────

    /// Évalue la force d'un secret selon le barème ENSPY (100 points max).
    pub fn evaluer_force(&self, secret: &str) -> ResultatForce {
        let mut secret_buf = secret.as_bytes().to_vec();
        let longueur = secret.len();

        if longueur < LONGUEUR_MIN {
            secret_buf.zeroize();
            return ResultatForce {
                score: 0,
                details: ForceDetails {
                    longueur_pts: 0,
                    diversite_pts: 0,
                    entropie_pts: 0,
                    bonus_structure_pts: 0,
                    longueur_reelle: longueur,
                    classes_presentes: vec![],
                    entropie_bits: 0.0,
                    raison_refus: Some("Longueur inférieure à 12 caractères.".into()),
                },
            };
        }

        let longueur_pts = MAX_PTS_LONGUEUR.min(10 + (longueur as u32 - 12) * 2);

        let mut classes: Vec<String> = Vec::new();
        if secret.chars().any(|c| c.is_ascii_lowercase()) {
            classes.push("minuscules".into());
        }
        if secret.chars().any(|c| c.is_ascii_uppercase()) {
            classes.push("majuscules".into());
        }
        if secret.chars().any(|c| c.is_ascii_digit()) {
            classes.push("chiffres".into());
        }
        if secret.chars().any(|c| c.is_ascii_punctuation()) {
            classes.push("symboles".into());
        }

        let diversite_pts = match classes.len() {
            4 => 35,
            3 => 26,
            2 => 17,
            1 => 8,
            _ => 0,
        };

        let nb_uniques = secret.chars().collect::<HashSet<_>>().len();
        let entropie_bits = if nb_uniques > 1 {
            (longueur as f64) * (nb_uniques as f64).log2()
        } else {
            0.0
        };

        let entropie_pts = MAX_PTS_ENTROPIE.min(((entropie_bits / ENTROPIE_REFERENCE) * 20.0) as u32);
        let bonus_structure_pts = self.calculer_bonus_structure(secret);
        let score = 100u32.min(longueur_pts + diversite_pts + entropie_pts + bonus_structure_pts);

        secret_buf.zeroize();

        debug!("Évaluation de force : longueur={} score={}", longueur, score);

        ResultatForce {
            score,
            details: ForceDetails {
                longueur_pts,
                diversite_pts,
                entropie_pts,
                bonus_structure_pts,
                longueur_reelle: longueur,
                classes_presentes: classes,
                entropie_bits: (entropie_bits * 100.0).round() / 100.0,
                raison_refus: None,
            },
        }
    }

    // ── Chiffrement AES-256-GCM ───────────────────────────────────────────────

    pub fn chiffrer_aes_gcm(&self, plaintext: &str) -> Result<DonneesChiffrees, CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.aes_key.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ct_avec_tag = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::ChiffrementEchoue(e.to_string()))?;

        let (ciphertext, auth_tag) = ct_avec_tag.split_at(ct_avec_tag.len() - 16);

        info!("Chiffrement AES-256-GCM effectué avec succès ({} octets → {} octets).",
            plaintext.len(), ciphertext.len());

        Ok(DonneesChiffrees {
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            iv:         URL_SAFE_NO_PAD.encode(nonce.as_slice()),
            auth_tag:   URL_SAFE_NO_PAD.encode(auth_tag),
        })
    }

    // ── Déchiffrement AES-256-GCM ─────────────────────────────────────────────

    pub fn dechiffrer_aes_gcm(
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
        let auth_tag = URL_SAFE_NO_PAD
            .decode(tag_b64)
            .map_err(|e| CryptoError::Base64Invalide(format!("auth_tag : {e}")))?;

        let mut ct_avec_tag = ciphertext;
        ct_avec_tag.extend_from_slice(&auth_tag);

        let key = Key::<Aes256Gcm>::from_slice(&self.aes_key.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes = cipher
            .decrypt(nonce, ct_avec_tag.as_slice())
            .map_err(|_| {
                warn!("Échec vérification GCM : données corrompues ou falsifiées.");
                CryptoError::IntegriteEchouee
            })?;

        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|e| CryptoError::ChiffrementEchoue(format!("UTF-8 invalide : {e}")))?;

        info!("Déchiffrement AES-256-GCM effectué avec succès.");
        Ok(plaintext)
    }

    // ── Hachage Argon2id ──────────────────────────────────────────────────────

    pub fn hacher_secret_argon2(&self, secret: &str) -> Result<String, CryptoError> {
        let mut secret_buf = secret.as_bytes().to_vec();
        let sel = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            self.argon2_params.clone(),
        );

        let hash = argon2
            .hash_password(secret.as_bytes(), &sel)
            .map_err(|e| {
                error!("Erreur Argon2id : {}", e);
                secret_buf.zeroize();
                CryptoError::Argon2Echoue(e.to_string())
            })?
            .to_string();

        secret_buf.zeroize();
        Ok(hash)
    }

    pub fn verifier_hash_argon2(&self, hash_str: &str, secret: &str) -> bool {
        let mut secret_buf = secret.as_bytes().to_vec();

        let resultat = PasswordHash::new(hash_str)
            .ok()
            .map(|hash| {
                Argon2::new(
                    argon2::Algorithm::Argon2id,
                    Version::V0x13,
                    self.argon2_params.clone(),
                )
                .verify_password(secret.as_bytes(), &hash)
                .is_ok()
            })
            .unwrap_or(false);

        secret_buf.zeroize();
        resultat
    }

    // ── Génération de credentials ─────────────────────────────────────────────

    pub fn generer_credentials(&self) -> Credentials {
        let alphabet: Vec<char> = (33u8..=126u8).map(|b| b as char).collect();

        let dist = Uniform::from(0..alphabet.len());
        let password: String = rand::thread_rng()
            .sample_iter(dist)
            .take(32)
            .map(|i| alphabet[i])
            .collect();

        let mut key_bytes = [0u8; 8];
        OsRng.fill(&mut key_bytes);
        let access_key = format!("AK-{}", hex::encode(key_bytes).to_uppercase());

        info!("Nouveaux credentials générés (access_key={}).", access_key);
        Credentials { password, access_key }
    }

    // ── ECC Curve25519 / ECDH ─────────────────────────────────────────────────

    /// Retourne la clé publique ECC **statique** (legacy `/public-key`, trousseau).
    pub fn get_public_key_hex(&self) -> String {
        hex::encode(self.ecc_public_key)
    }

    /// ECDH avec la clé **statique** de l'agent (legacy — préférer `ecdh_session_ephemere`).
    ///
    /// # SECURITY: ne pas logguer le résultat
    pub fn ecdh_partager(&self, cle_publique_pair: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let peer_key = PublicKey::from(*cle_publique_pair);
        let shared = self.ecc_private_key.diffie_hellman(&peer_key);
        Ok(*shared.as_bytes())
    }

    // ── Génération de mot de passe ────────────────────────────────────────────

    /// Génère un mot de passe fort selon les options fournies.
    ///
    /// Algorithme :
    /// 1. Construire l'alphabet depuis les groupes activés
    /// 2. Si exclure_ambigus, filtrer ['0','O','l','1','I','|']
    /// 3. Garantir la présence d'au moins 1 caractère de chaque groupe activé
    /// 4. Compléter jusqu'à longueur avec des caractères aléatoires
    /// 5. Mélanger le résultat avec Fisher-Yates (via OsRng)
    pub fn generer_mot_de_passe(&self, options: &OptionsMotDePasse) -> Result<String, CryptoError> {
        if options.longueur < 8 || options.longueur > 128 {
            return Err(CryptoError::OptionsInvalides(
                "La longueur doit être entre 8 et 128.".into(),
            ));
        }

        let ambigus: HashSet<char> = ['0', 'O', 'l', '1', 'I', '|'].into_iter().collect();

        let filtrer = |s: &str| -> Vec<char> {
            s.chars()
                .filter(|c| !options.exclure_ambigus || !ambigus.contains(c))
                .collect()
        };

        let majuscules: Vec<char> = filtrer("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let minuscules: Vec<char> = filtrer("abcdefghijklmnopqrstuvwxyz");
        let chiffres: Vec<char>   = filtrer("0123456789");
        let symboles: Vec<char>   = filtrer("!@#$%^&*()-_=+[]{}|;:,.<>?");

        // Construire l'alphabet complet
        let mut alphabet: Vec<char> = Vec::new();
        if options.majuscules { alphabet.extend_from_slice(&majuscules); }
        if options.minuscules { alphabet.extend_from_slice(&minuscules); }
        if options.chiffres   { alphabet.extend_from_slice(&chiffres); }
        if options.symboles   { alphabet.extend_from_slice(&symboles); }

        if alphabet.is_empty() {
            return Err(CryptoError::OptionsInvalides(
                "Au moins un groupe de caractères doit être activé.".into(),
            ));
        }

        let mut rng = rand::thread_rng();
        let mut resultat: Vec<char> = Vec::with_capacity(options.longueur);

        // Première passe : garantir au moins 1 caractère par groupe activé
        if options.majuscules && !majuscules.is_empty() {
            let idx = rng.gen_range(0..majuscules.len());
            resultat.push(majuscules[idx]);
        }
        if options.minuscules && !minuscules.is_empty() {
            let idx = rng.gen_range(0..minuscules.len());
            resultat.push(minuscules[idx]);
        }
        if options.chiffres && !chiffres.is_empty() {
            let idx = rng.gen_range(0..chiffres.len());
            resultat.push(chiffres[idx]);
        }
        if options.symboles && !symboles.is_empty() {
            let idx = rng.gen_range(0..symboles.len());
            resultat.push(symboles[idx]);
        }

        // Compléter jusqu'à la longueur cible
        let dist = Uniform::from(0..alphabet.len());
        while resultat.len() < options.longueur {
            resultat.push(alphabet[rng.sample(dist)]);
        }

        // Mélange Fisher-Yates via OsRng pour positions non-prédictibles
        use rand::seq::SliceRandom;
        resultat.shuffle(&mut rng);

        let password: String = resultat.into_iter().collect();
        Ok(password)
    }


    /// Clone le moteur pour usage dans une tâche asynchrone dédiée.
    /// Génère une nouvelle paire ECC — le secret ECDH sera différent.
    /// Pour partager la même clé ECC, utiliser Arc<CryptoMoteur>.
    pub fn clone_for_rotation(&self) -> Self {
        CryptoMoteur::new()
    }
    // ── Méthodes privées ──────────────────────────────────────────────────────

    fn calculer_bonus_structure(&self, secret: &str) -> u32 {
        let chars: Vec<char> = secret.chars().collect();
        let mut bonus = MAX_PTS_STRUCTURE as i32;

        for i in 0..chars.len().saturating_sub(2) {
            if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
                bonus -= 2;
                break;
            }
        }

        for i in 0..chars.len().saturating_sub(3) {
            if chars[i] == chars[i + 2] && chars[i + 1] == chars[i + 3] {
                bonus -= 3;
                break;
            }
        }

        bonus.max(0) as u32
    }
}

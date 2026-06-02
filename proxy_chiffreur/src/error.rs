//! # Types d'erreurs de l'Agent Chiffreur
//!
//! Ce module définit les erreurs structurées utilisées dans tout le projet.

use thiserror::Error;

/// Erreurs possibles lors des opérations cryptographiques.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Le chiffrement AES-256-GCM a échoué.
    #[error("Échec du chiffrement AES-256-GCM : {0}")]
    ChiffrementEchoue(String),

    /// La vérification d'intégrité GCM a échoué (données corrompues ou falsifiées).
    #[error("Échec de vérification d'intégrité GCM : données corrompues ou falsifiées.")]
    IntegriteEchouee,

    /// Le décodage Base64 d'un champ a échoué.
    #[error("Données Base64 invalides : {0}")]
    Base64Invalide(String),

    /// Le hachage Argon2id a échoué.
    #[error("Erreur Argon2id : {0}")]
    Argon2Echoue(String),

    /// Clé hexadécimale invalide (ECDH ou AES).
    #[error("Clé hex invalide : {0}")]
    CleHexInvalide(String),

    /// Options de génération de mot de passe invalides.
    #[error("Options mot de passe invalides : {0}")]
    OptionsInvalides(String),
}

/// Erreurs possibles lors du traitement d'une requête JSON.
#[derive(Debug, Error)]
pub enum RequeteError {
    /// Le token X-Agent-Token est absent ou invalide.
    #[error("X-Agent-Token manquant ou invalide.")]
    TokenInvalide,

    /// Le corps de la requête n'est pas un JSON valide.
    #[error("JSON invalide : {0}")]
    JsonInvalide(String),

    /// Un champ obligatoire est absent ou de mauvais type.
    #[error("Champ obligatoire manquant ou invalide : {0}")]
    ChampManquant(String),

    /// Le `message_type` reçu n'est pas reconnu.
    #[error("message_type inconnu : '{0}'.")]
    TypeInconnu(String),

    /// Erreur propagée depuis le moteur cryptographique.
    #[error("Erreur cryptographique : {0}")]
    Crypto(#[from] CryptoError),
}

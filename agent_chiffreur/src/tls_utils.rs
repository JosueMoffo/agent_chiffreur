//! # Utilitaires TLS/mTLS — Agent Chiffreur ENSPY
//!
//! Ce module centralise la configuration du client HTTP (reqwest) et du serveur HTTPS (axum-server)
//! pour supporter le mTLS (Mutual TLS) avec les certificats fournis.

use std::fs;
use std::sync::Arc;
use tracing::{info, warn, error};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use crate::config::Config;

/// Construit un client HTTP `reqwest::Client` configuré pour le mTLS si les chemins
/// sont renseignés dans la configuration.
pub fn build_mtls_client(config: &Config) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10));

    // 1. Ajouter le certificat CA (pour vérifier le serveur distant)
    if !config.ca_cert_path.is_empty() {
        match fs::read(&config.ca_cert_path) {
            Ok(ca_data) => {
                if let Ok(cert) = reqwest::Certificate::from_pem(&ca_data) {
                    builder = builder.add_root_certificate(cert);
                    info!("[TLS] Root CA chargé depuis '{}'", config.ca_cert_path);
                } else {
                    warn!("[TLS] Impossible de décoder le CA PEM dans '{}'", config.ca_cert_path);
                }
            }
            Err(e) => warn!("[TLS] Impossible de lire le CA '{}' : {}", config.ca_cert_path, e),
        }
    }

    // 2. Ajouter l'identité (Certificat + Clé) pour s'authentifier auprès du serveur
    if !config.agent_cert_path.is_empty() && !config.agent_key_path.is_empty() {
        match (fs::read_to_string(&config.agent_cert_path), fs::read_to_string(&config.agent_key_path)) {
            (Ok(cert), Ok(key)) => {
                let pem = format!("{}\n{}", cert, key);
                match reqwest::Identity::from_pem(pem.as_bytes()) {
                    Ok(id) => {
                        builder = builder.identity(id);
                        info!("[TLS] Identité client mTLS chargée (cert+key)");
                    }
                    Err(e) => warn!("[TLS] Échec création Identity mTLS : {}", e),
                }
            }
            _ => warn!("[TLS] Certificat ou clé manquante pour l'identité client."),
        }
    }

    builder.build().unwrap_or_else(|e| {
        error!("[TLS] Erreur critique build reqwest client : {}", e);
        reqwest::Client::new()
    })
}

/// Construit une configuration `rustls::ServerConfig` pour axum-server.
/// Si un CA est fourni, active la vérification obligatoire du certificat client (mTLS).
pub async fn build_server_tls_config(config: &Config) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = &config.agent_cert_path;
    let key_path = &config.agent_key_path;
    let ca_path = &config.ca_cert_path;

    if cert_path.is_empty() || key_path.is_empty() {
        return Err("Chemins de certificat ou clé vides".into());
    }

    // Charger les certificats et la clé pour le serveur
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut server_config = if !ca_path.is_empty() && fs::metadata(ca_path).is_ok() {
        // Mode mTLS : nécessite et vérifie un certificat client
        info!("[TLS] Mode mTLS activé (vérification client via '{}')", ca_path);
        
        let ca_file = fs::File::open(ca_path)?;
        let mut reader = std::io::BufReader::new(ca_file);
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?;

        let mut root_cert_store = rustls::RootCertStore::empty();
        for cert in root_certs {
            root_cert_store.add(cert)?;
        }

        let verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store))
            .build()?;

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        // Mode TLS simple
        info!("[TLS] Mode TLS simple (pas de vérification client)");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config)))
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
}

fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    
    // Version v2 : Les variantes utilisent désormais la nomenclature Pkcs1Key, Pkcs8Key et Sec1Key
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => break,
            _ => continue,
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Aucune clé privée trouvée"))
}
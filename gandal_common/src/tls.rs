//! Configuration mTLS GANDAL (CA centrale, certificats par agent).

use std::path::{Path, PathBuf};

use thiserror::Error;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
use tonic::{Request, Status};
use tracing::{info, warn};

pub const CN_CHIFFREUR: &str = "chiffreur";
pub const CN_PROXY: &str = "proxy";
pub const CN_DECIDEUR: &str = "decideur";
pub const CN_AUDITEUR: &str = "auditeur";

/// Chemins PKI (surchargeables via `GANDAL_CA`, `GANDAL_CERT`, `GANDAL_KEY`).
#[derive(Debug, Clone)]
pub struct GandalPkiPaths {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl GandalPkiPaths {
    /// Résout les chemins depuis l'environnement ou des défauts relatifs au dépôt.
    pub fn resolve(defaut_cert: &str, defaut_key: &str) -> Self {
        let ca = std::env::var("GANDAL_CA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("ca/ca.crt"));
        let cert = std::env::var("GANDAL_CERT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(defaut_cert));
        let key = std::env::var("GANDAL_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(defaut_key));
        Self { ca, cert, key }
    }

    pub fn for_chiffreur() -> Self {
        Self::resolve("certs/chiffreur.crt", "certs/chiffreur.key")
    }

    pub fn for_proxy() -> Self {
        Self::resolve("certs/proxy.crt", "certs/proxy.key")
    }
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("lecture {0}: {1}")]
    Io(String, std::io::Error),
    #[error("configuration TLS : {0}")]
    Config(String),
}

fn lire_fichier(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|e| TlsError::Io(path.display().to_string(), e))
}

/// Configuration serveur gRPC avec mTLS obligatoire (clients doivent présenter un certificat CA).
pub fn server_tls_config(pki: &GandalPkiPaths) -> Result<ServerTlsConfig, TlsError> {
    let ca = Certificate::from_pem(lire_fichier(&pki.ca)?);
    let cert_pem = lire_fichier(&pki.cert)?;
    let key_pem = lire_fichier(&pki.key)?;
    let identity = Identity::from_pem(cert_pem, key_pem);

    Ok(ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca))
}

/// Configuration client gRPC vers un pair (vérifie la CA, présente notre identité).
pub fn client_tls_config(pki: &GandalPkiPaths, domain: &str) -> Result<ClientTlsConfig, TlsError> {
    let ca = Certificate::from_pem(lire_fichier(&pki.ca)?);
    let cert_pem = lire_fichier(&pki.cert)?;
    let key_pem = lire_fichier(&pki.key)?;
    let identity = Identity::from_pem(cert_pem, key_pem);

    Ok(ClientTlsConfig::new()
            .domain_name(domain)
            .ca_certificate(ca)
            .identity(identity))
}

/// Construit une URI tonic `https://host:port` pour un agent SMA.
pub fn grpc_uri(host: &str, port: u16) -> String {
    format!("https://{host}:{port}")
}

/// Hôte attendu pour la validation TLS (CN GANDAL, pas localhost générique).
pub fn domain_from_cn(cn: &str) -> &str {
    cn
}

/// Journalise le CN attendu pour une RPC sensible (validation complète côté PKI).
pub fn log_peer_cn_attendu(operation: &str, cn_attendu: &str) {
    info!(
        "[mTLS] {operation} — certificat client attendu CN='{cn_attendu}' (signé CA GANDAL)"
    );
}

/// Extrait le CN du certificat client présenté en mTLS (premier cert de la chaîne).
pub fn peer_cn_from_request<T>(request: &Request<T>) -> Option<String> {
    let tls = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()?;
    let chain = tls.peer_certs()?;
    let leaf = chain.first()?;
    cn_from_der(leaf.as_ref()).ok()
}

fn cn_from_der(der: &[u8]) -> Result<String, ()> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| ())?;
    for attr in cert.subject().iter_attributes() {
        if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
            if let Ok(cn) = attr.as_str() {
                return Ok(cn.to_string());
            }
        }
    }
    Err(())
}

/// Refuse la RPC si le CN client ne correspond pas (document GANDAL §5).
pub fn exiger_cn_client<T>(request: &Request<T>, cn_attendu: &str, operation: &str) -> Result<(), Status> {
    match peer_cn_from_request(request) {
        Some(cn) if cn == cn_attendu => Ok(()),
        Some(cn) => {
            warn!(
                "[mTLS] {operation} refusé — CN client '{cn}' ≠ '{cn_attendu}' attendu"
            );
            Err(Status::permission_denied(format!(
                "certificat client CN '{cn}' non autorisé pour {operation}"
            )))
        }
        None => {
            warn!("[mTLS] {operation} refusé — aucun certificat client");
            Err(Status::unauthenticated(
                "mTLS : certificat client obligatoire",
            ))
        }
    }
}

/// Avertit si les certificats sont absents (développement).
pub fn warn_if_missing(pki: &GandalPkiPaths) {
    for p in [&pki.ca, &pki.cert, &pki.key] {
        if !p.exists() {
            warn!(
                "[mTLS] Fichier PKI absent : {} — exécuter scripts/gen_gandal_certs.sh",
                p.display()
            );
        }
    }
}

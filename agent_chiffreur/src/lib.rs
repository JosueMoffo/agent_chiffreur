//! Bibliothèque Agent Chiffreur **central** (port 5004) + modules partagés legacy.

pub mod app;
pub mod central_http;
pub mod central_registry;
pub mod config;
pub mod crypto_moteur;
pub mod error;
pub mod models;
pub mod notificateur;
pub mod sessions_vm;
pub mod tls_utils;
pub mod supervision;

// Legacy / simulation (handlers crypto VM — préférer proxy_chiffreur en production)
pub mod agent_http;
pub mod gestionnaire_rotation;
pub mod rotation_vm;
pub mod sim_export;
pub mod trousseau;
pub mod xmpp_sim;

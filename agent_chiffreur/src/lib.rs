//! Bibliothèque Agent Chiffreur **central** (port 5004) + modules partagés legacy.

pub mod app;
pub mod auth;
pub mod central_grpc;
pub mod central_http;
pub mod central_rotation;
pub mod central_registry;
pub mod grpc_clients;
pub mod config;
pub mod crypto_moteur;
pub mod error;
pub mod models;
pub mod notificateur;
pub mod sessions_vm;

// Legacy / simulation (handlers crypto VM — préférer proxy_chiffreur en production)
pub mod agent_http;
pub mod gestionnaire_rotation;
pub mod rotation_vm;
pub mod sim_export;
pub mod trousseau;
pub mod xmpp_sim;

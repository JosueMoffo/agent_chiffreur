//! Proxy Chiffreur — une instance par VM (port 8400).
//! Chiffrement local, relais inter-VM, annonce vers l'agent central (5004).

pub mod app;
pub mod central_client;
pub mod proxy_grpc;
pub mod config;
pub mod crypto_moteur;
pub mod error;
pub mod models;
pub mod notificateur;
pub mod proxy_cle_vm;
pub mod proxy_http;
pub mod proxy_sessions;
pub mod rotation_vm;
pub mod sessions_vm;

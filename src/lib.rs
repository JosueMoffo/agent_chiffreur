//! Bibliothèque Agent Chiffreur — partagée entre le binaire serveur et la simulation.

pub mod agent_http;
pub mod app;
pub mod config;
pub mod crypto_moteur;
pub mod error;
pub mod gestionnaire_rotation;
pub mod models;
pub mod notificateur;
pub mod rotation_vm;
pub mod sim_export;
pub mod sessions_vm;
pub mod trousseau;
pub mod xmpp_sim;

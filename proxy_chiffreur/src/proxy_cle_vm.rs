//! Paire X25519 locale du proxy (identité de la VM sur le réseau SMA).

use aes_gcm::aead::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyVmSecret {
    pub vm_id: u32,
    /// Clé privée X25519 (hex 64) — SECURITY: fichier en mode 600
    pub private_key_hex: String,
    pub public_key_hex: String,
}

impl ProxyVmSecret {
    pub fn generer(vm_id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            vm_id,
            private_key_hex: hex::encode(secret.as_bytes()),
            public_key_hex: hex::encode(public.as_bytes()),
        }
    }

    pub fn charger_ou_creer(chemin: &str, vm_id: u32) -> Result<Self, String> {
        if let Ok(contenu) = std::fs::read_to_string(chemin) {
            let s: Self = serde_json::from_str(&contenu)
                .map_err(|e| format!("JSON clé proxy : {e}"))?;
            if s.vm_id != vm_id {
                return Err(format!(
                    "vm_id config ({vm_id}) ≠ vm_id clé ({})",
                    s.vm_id
                ));
            }
            return Ok(s);
        }

        let s = Self::generer(vm_id);
        if let Some(parent) = std::path::Path::new(chemin).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir : {e}"))?;
        }
        let json = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?;
        std::fs::write(chemin, json).map_err(|e| format!("écriture {chemin} : {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(s)
    }
}

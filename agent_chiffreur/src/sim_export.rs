//! Export persistant des artefacts de simulation (`data/sim_blobs.json`).

use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::gestionnaire_rotation::SessionStore;
use crate::sessions_vm::StoreSessionsVm;

/// Journal cumulé pendant la simulation (flux visibles + opérations).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JournalSimulation {
    pub flux_cles_vm: Vec<FluxVmJournal>,
    pub operations_agent: Vec<OperationAgentJournal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxVmJournal {
    pub vm_id: u32,
    pub etapes: Vec<EtapeFlux>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtapeFlux {
    pub ordre: u32,
    pub scenario: String,
    pub action: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationAgentJournal {
    pub scenario: String,
    pub action: String,
    pub details: Value,
}

impl JournalSimulation {
    pub fn nouvelle_etape_vm(&mut self, vm_id: u32, scenario: &str, action: &str, details: Value) {
        let flux = self
            .flux_cles_vm
            .iter_mut()
            .find(|f| f.vm_id == vm_id)
            .map(|f| &mut f.etapes);

        let etapes = if let Some(e) = flux {
            e
        } else {
            self.flux_cles_vm.push(FluxVmJournal {
                vm_id,
                etapes: Vec::new(),
            });
            &mut self.flux_cles_vm.last_mut().unwrap().etapes
        };

        let ordre = (etapes.len() + 1) as u32;
        etapes.push(EtapeFlux {
            ordre,
            scenario: scenario.to_string(),
            action: action.to_string(),
            details,
        });
    }

    pub fn log_agent(&mut self, scenario: &str, action: &str, details: Value) {
        self.operations_agent.push(OperationAgentJournal {
            scenario: scenario.to_string(),
            action: action.to_string(),
            details,
        });
    }
}

/// Aperçu hex sûr pour l'affichage (ne pas exposer la clé complète en log console si souhaité ;
/// ici on affiche un préfixe pour le flux visible).
pub fn apercu_hex(hex_str: &str, chars: usize) -> String {
    if hex_str.len() <= chars {
        hex_str.to_string()
    } else {
        format!("{}… ({} hex)", &hex_str[..chars], hex_str.len())
    }
}

/// Chiffre / déchiffre avec la clé AES-256 d'une VM (même format que l'agent : AES-GCM + base64 url-safe).
pub fn chiffrer_dechiffrer_avec_cle_vm(
    cle_hex: &str,
    plaintext: &str,
) -> Result<Value, String> {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let key_bytes = hex::decode(cle_hex).map_err(|e| format!("cle_hex invalide : {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!("cle_hex : 32 octets attendus, reçu {}", key_bytes.len()));
    }

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ct_avec_tag = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("chiffrement VM : {e}"))?;

    let (ciphertext, auth_tag) = ct_avec_tag.split_at(ct_avec_tag.len().saturating_sub(16));
    let ciphertext_b64 = URL_SAFE_NO_PAD.encode(ciphertext);
    let iv_b64 = URL_SAFE_NO_PAD.encode(nonce.as_slice());
    let tag_b64 = URL_SAFE_NO_PAD.encode(auth_tag);

    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&iv_b64)
        .map_err(|e| format!("iv : {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct_raw = URL_SAFE_NO_PAD
        .decode(&ciphertext_b64)
        .map_err(|e| format!("ct : {e}"))?;
    let tag_raw = URL_SAFE_NO_PAD
        .decode(&tag_b64)
        .map_err(|e| format!("tag : {e}"))?;
    let mut payload = Vec::with_capacity(ct_raw.len() + tag_raw.len());
    payload.extend_from_slice(&ct_raw);
    payload.extend_from_slice(&tag_raw);

    let plain_recup = cipher
        .decrypt(nonce, payload.as_ref())
        .map_err(|e| format!("déchiffrement VM : {e}"))?;
    let plain_str = String::from_utf8(plain_recup).map_err(|e| format!("utf8 : {e}"))?;

    Ok(json!({
        "plaintext_original": plaintext,
        "ciphertext": ciphertext_b64,
        "iv": iv_b64,
        "auth_tag": tag_b64,
        "plaintext_dechiffre": plain_str,
        "roundtrip_ok": plain_str == plaintext,
    }))
}

/// Fusionne sessions VM, blobs agent et journal dans `data/sim_blobs.json`.
pub fn exporter_sim_blobs(
    chemin_export: &str,
    chemin_session_vm: &str,
    chemin_blobs_agent: &str,
    journal: &JournalSimulation,
) -> Result<(), String> {
    let sessions_vm: StoreSessionsVm = std::fs::read_to_string(chemin_session_vm)
        .map_err(|e| format!("lecture {chemin_session_vm} : {e}"))
        .and_then(|s| {
            serde_json::from_str(&s).map_err(|e| format!("JSON session VM : {e}"))
        })
        .unwrap_or_default();

    let blobs_agent: SessionStore = std::fs::read_to_string(chemin_blobs_agent)
        .map_err(|e| format!("lecture {chemin_blobs_agent} : {e}"))
        .and_then(|s| serde_json::from_str(&s).map_err(|e| format!("JSON blobs agent : {e}")))
        .unwrap_or_default();

    let mut vms_cles_aes = serde_json::Map::new();
    for (vm_id_str, session) in &sessions_vm.sessions {
        let old_key = session.old_key.as_deref();
        vms_cles_aes.insert(
            vm_id_str.clone(),
            json!({
                "vm_id": session.vm_id,
                "public_key": session.public_key,
                "agent_public_key": session.agent_public_key,
                "new_key": session.new_key,
                "old_key": old_key,
                "rotation_count": session.rotation_count,
                "url_notification": session.url_notification,
            }),
        );
    }

    let mut flux_enrichi = journal.flux_cles_vm.clone();
    for flux in &mut flux_enrichi {
        if let Some(s) = sessions_vm.sessions.get(&flux.vm_id.to_string()) {
            flux.etapes.push(EtapeFlux {
                ordre: (flux.etapes.len() + 1) as u32,
                scenario: "EXPORT".into(),
                action: "snapshot_cles_finales".into(),
                details: json!({
                    "agent_public_key": s.agent_public_key,
                    "new_key": s.new_key,
                    "old_key": s.old_key,
                    "rotation_count": s.rotation_count,
                }),
            });
        }
    }

    let export = json!({
        "schema_version": "2.0",
        "description": "Artefacts de simulation — clés AES VM + blobs agent + flux opérationnels",
        "genere_a": Utc::now().to_rfc3339(),
        "fichiers_sources": {
            "sessions_vm": chemin_session_vm,
            "blobs_agent_interne": chemin_blobs_agent,
        },
        "vms_cles_aes": vms_cles_aes,
        "flux_creation_cles_vm": flux_enrichi,
        "operations_chiffrement_agent": journal.operations_agent,
        "blobs_trousseau_agent": {
            "rotations_effectuees": blobs_agent.rotations_effectuees,
            "derniere_rotation": blobs_agent.derniere_rotation,
            "blobs": blobs_agent.blobs,
        },
        "sessions_vm_complet": sessions_vm,
    });

    if let Some(parent) = Path::new(chemin_export).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {} : {e}", parent.display()))?;
    }

    let json_str = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("sérialisation export : {e}"))?;
    std::fs::write(chemin_export, json_str)
        .map_err(|e| format!("écriture {chemin_export} : {e}"))?;

    Ok(())
}

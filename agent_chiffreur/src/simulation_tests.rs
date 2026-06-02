//! # Simulation intégration HTTP — Agent Chiffreur ENSPY
//!
//! Chaque scénario appelle les **vrais endpoints HTTP** d'un serveur démarré en local.
//! En fin de run, les artefacts sont **conservés** :
//! - `data/sim_session.json` — clés VM (public_key, new_key, old_key)
//! - `data/sim_blobs.json` — export fusionné (clés VM + flux + blobs agent)
//! - `data/sim_agent_blobs.json` — store interne trousseau (legacy, non utilisé par /encrypt)
//!
//! | Scénario | Workflow |
//! |----------|----------|
//! | **0** | `POST /encrypt` sans token + `vm_id` → 200 |
//! | **A** | `POST /secret/strength` secret faible → score < 60 |
//! | **B** | `POST /secret/strength` secret fort → score ≥ 60 |
//! | **C** | `POST /encrypt` avec `vm_id` → clé `new_key` VM |
//! | **D** | `POST /decrypt` (données C) → plaintext identique |
//! | **E** | `POST /ecdh/initiate` (paire éphémère) → secrets égaux côté pair |
//! | **F** | `POST /password/generate` (3 variantes) |
//! | **G** | `POST /encrypt` / `decrypt` VM — falsification GCM → CRYPTO_ERROR |
//! | **H** | `POST /vm/session/register` VMs 101–103 + vérif. `session.json` |
//! | **I** | `POST /credential/rotate` contrôle `X-Agent-Name` |
//! | **J** | `POST /credential/rotate` → new_key/old_key dans API + disque |
//! | **K** | Timer grâce : old_key puis `POST /vm/sessions/purge-expired` |
//! | **L** | Deux rotations HTTP → `rotation_count` ≥ 2 sur VMs 201–202 |

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::OsRng;
use agent_chiffreur::app::{build_router as build_router_central, preparer_agent};
use agent_chiffreur::config::Config;
use proxy_chiffreur::app::{build_router as build_router_proxy, preparer_proxy};
use proxy_chiffreur::config::ProxyConfig;
use agent_chiffreur::sessions_vm::GestionnaireSessionsVm;
use agent_chiffreur::sim_export::{
    apercu_hex, chiffrer_dechiffrer_avec_cle_vm, exporter_sim_blobs, JournalSimulation,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tracing_subscriber::EnvFilter;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const RESET: &str = "\x1b[0m";
const ROUGE: &str = "\x1b[91m";
const VERT: &str = "\x1b[92m";
const CYAN: &str = "\x1b[96m";
const BLANC: &str = "\x1b[97m";
const GRAS: &str = "\x1b[1m";
const JAUNE: &str = "\x1b[93m";
const BLEU: &str = "\x1b[94m";

// ── Affichage ─────────────────────────────────────────────────────────────────

fn sep(titre: &str) {
    let l = 66usize;
    let pad = " ".repeat((l.saturating_sub(titre.len() + 2)) / 2);
    println!("\n{GRAS}{CYAN}╔{}╗{RESET}", "═".repeat(l));
    println!("{GRAS}{CYAN}║{pad}  {BLANC}{titre}{CYAN}  {pad}║{RESET}");
    println!("{GRAS}{CYAN}╚{}╝{RESET}", "═".repeat(l));
}

fn etape(k: &str, v: &str) {
    println!("    {BLEU}▶{RESET} {k:<32} : {v}");
}

fn workflow_step(n: u8, desc: &str) {
    println!("    {JAUNE}[{n}]{RESET} {desc}");
}

fn ok(m: &str) {
    println!("  {VERT}✔{RESET} {GRAS}{m}{RESET}");
}

fn ko(m: &str) {
    println!("  {ROUGE}✗ ÉCHEC —{RESET} {GRAS}{m}{RESET}");
}

fn flux_titre(t: &str) {
    println!("\n  {GRAS}{CYAN}── Flux crypto : {t} ──{RESET}");
}

// ── Client HTTP ───────────────────────────────────────────────────────────────

struct ClientHttp {
    base: String,
    token: String,
    http: Client,
}

impl ClientHttp {
    fn new(base: &str, token: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: Client::new(),
        }
    }

    async fn get_public(&self, path: &str) -> (StatusCode, Value) {
        let res = self
            .http
            .get(format!("{}{}", self.base, path))
            .send()
            .await
            .expect("requête GET");
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(json!({}));
        (status, body)
    }

    async fn post_token(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let res = self
            .http
            .post(format!("{}{}", self.base, path))
            .header("X-Agent-Token", &self.token)
            .json(&body)
            .send()
            .await
            .expect("requête POST");
        let status = res.status();
        let rep: Value = res.json().await.unwrap_or(json!({}));
        (status, rep)
    }

    async fn post_sans_token(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let res = self
            .http
            .post(format!("{}{}", self.base, path))
            .json(&body)
            .send()
            .await
            .expect("requête POST sans token");
        let status = res.status();
        let rep: Value = res.json().await.unwrap_or(json!({}));
        (status, rep)
    }

    async fn post_rotate(&self, agent_name: &str, body: Value) -> (StatusCode, Value) {
        let res = self
            .http
            .post(format!("{}/credential/rotate", self.base))
            .header("X-Agent-Name", agent_name)
            .json(&body)
            .send()
            .await
            .expect("requête rotate");
        let status = res.status();
        let rep: Value = res.json().await.unwrap_or(json!({}));
        (status, rep)
    }

    async fn attendre_health(&self, max_sec: u64) -> bool {
        for _ in 0..max_sec * 10 {
            let (st, _) = self.get_public("/health").await;
            if st == StatusCode::OK {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
}

fn generer_paire_vm() -> (EphemeralSecret, String) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, hex::encode(public.as_bytes()))
}

fn charger_scenarios() -> Value {
    let chemin = "tests/simulation_scenarios.json";
    let contenu = std::fs::read_to_string(chemin)
        .unwrap_or_else(|e| panic!("Fichier scénarios introuvable ({chemin}) : {e}"));
    serde_json::from_str(&contenu).expect("simulation_scenarios.json invalide")
}

/// Affiche et journalise le flux ECDH → clé AES VM après enregistrement HTTP.
fn flux_creation_cle_vm(
    journal: &mut JournalSimulation,
    vm_id: u32,
    pub_hex: &str,
    agent_pub_hex: &str,
    shared_vm_hex: &str,
    chemin_session: &str,
) {
    flux_titre(&format!("VM {vm_id} — création clé AES (ECDH)"));
    workflow_step(1, "VM : paire X25519 générée (public_key)");
    etape("public_key", &apercu_hex(pub_hex, 20));
    journal.nouvelle_etape_vm(
        vm_id,
        "H",
        "generation_paire_x25519",
        json!({
            "public_key": pub_hex,
            "public_key_apercu": apercu_hex(pub_hex, 16),
        }),
    );

    workflow_step(2, "Agent : POST /vm/session/register → paire éphémère + ECDH → new_key");
    let sur_disque = session_vm(chemin_session, vm_id).expect("session après register");
    let new_key = sur_disque["new_key"].as_str().unwrap_or("");
    etape("new_key (agent)", &apercu_hex(new_key, 20));
    journal.nouvelle_etape_vm(
        vm_id,
        "H",
        "ecdh_enregistrement_agent",
        json!({
            "new_key": new_key,
            "new_key_apercu": apercu_hex(new_key, 16),
            "old_key": sur_disque["old_key"],
        }),
    );

    workflow_step(3, "VM : recalcul ECDH local (vérification)");
    let coherent = shared_vm_hex == new_key;
    etape("secret VM (ECDH)", &apercu_hex(shared_vm_hex, 20));
    etape("cohérent avec new_key", &coherent.to_string());
    journal.nouvelle_etape_vm(
        vm_id,
        "H",
        "verification_ecdh_cote_vm",
        json!({
            "shared_secret_vm_hex": shared_vm_hex,
            "coherent_avec_new_key": coherent,
        }),
    );
}

/// Chiffrement / déchiffrement visible avec la new_key de la VM.
fn flux_chiffrement_vm(
    journal: &mut JournalSimulation,
    vm_id: u32,
    new_key_hex: &str,
    plaintext: &str,
) -> bool {
    flux_titre(&format!("VM {vm_id} — chiffrement / déchiffrement client"));
    workflow_step(4, "Client VM : chiffrement AES-256-GCM avec new_key");
    etape("plaintext", plaintext);

    match chiffrer_dechiffrer_avec_cle_vm(new_key_hex, plaintext) {
        Ok(details) => {
            etape("ciphertext", &apercu_hex(details["ciphertext"].as_str().unwrap_or(""), 24));
            etape("iv", &apercu_hex(details["iv"].as_str().unwrap_or(""), 16));
            etape("auth_tag", &apercu_hex(details["auth_tag"].as_str().unwrap_or(""), 16));
            workflow_step(5, "Client VM : déchiffrement avec la même new_key");
            let ok_rt = details["roundtrip_ok"].as_bool().unwrap_or(false);
            etape(
                "plaintext récupéré",
                details["plaintext_dechiffre"].as_str().unwrap_or("?"),
            );
            etape("roundtrip OK", &ok_rt.to_string());
            journal.nouvelle_etape_vm(vm_id, "H", "chiffrement_client_aes_gcm", details.clone());
            journal.nouvelle_etape_vm(
                vm_id,
                "H",
                "dechiffrement_client_aes_gcm",
                json!({
                    "plaintext_dechiffre": details["plaintext_dechiffre"],
                    "roundtrip_ok": ok_rt,
                }),
            );
            ok_rt
        }
        Err(e) => {
            etape("erreur", &e);
            journal.nouvelle_etape_vm(
                vm_id,
                "H",
                "erreur_chiffrement_client",
                json!({ "erreur": e }),
            );
            false
        }
    }
}

fn session_vm(chemin: &str, vm_id: u32) -> Option<Value> {
    let store = GestionnaireSessionsVm::lire_fichier_session(chemin).ok()?;
    store.sessions.get(&vm_id.to_string()).map(|s| {
        json!({
            "vm_id": s.vm_id,
            "public_key": s.public_key,
            "new_key": s.new_key,
            "old_key": s.old_key,
            "rotation_count": s.rotation_count,
        })
    })
}

// ── Point d'entrée ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    println!("{GRAS}{CYAN}");
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║   SIMULATION HTTP — Agent Chiffreur ENSPY (endpoints réels)       ║");
    println!("║   Export    : data/sim_blobs.json (conservé en fin de run)         ║");
    println!("╚════════════════════════════════════════════════════════════════════╝{RESET}");

    let meta = charger_scenarios();
    let token = meta["agent_token_test"]
        .as_str()
        .unwrap_or("ENSPY-TOKEN-2026");
    let port_central = meta["port_agent_central"].as_u64().unwrap_or(15004) as u16;
    let port_proxy = meta["port_proxy_simulation"].as_u64().unwrap_or(18400) as u16;
    let grace = meta["old_key_grace_sec_test"].as_u64().unwrap_or(3);
    let chemin_session = meta["chemin_session_test"]
        .as_str()
        .unwrap_or("data/sim_session.json");
    let chemin_sim_blobs = meta["chemin_sim_blobs"]
        .as_str()
        .unwrap_or("data/sim_blobs.json");
    let chemin_blobs_agent = meta["chemin_blobs_agent"]
        .as_str()
        .unwrap_or("data/sim_agent_blobs.json");
    let agent_ok = meta["agent_rotation_autorise"]
        .as_str()
        .unwrap_or("Decideur");

    std::fs::create_dir_all("data").ok();
    std::fs::write(
        chemin_session,
        r#"{"schema_version":"1.0","sessions":{}}"#,
    )
    .expect("init sim_session.json");

    let mut config_central = Config::default();
    config_central.agent_port = port_central;
    config_central.agent_token = token.to_string();
    config_central.agent_rotation_autorise = agent_ok.to_string();
    config_central.chemin_registry = "data/sim_central_registry.json".to_string();

    let mut proxy_cfg = ProxyConfig {
        local_vm_id: 101,
        listen_port: port_proxy,
        agent_central_url: format!("http://127.0.0.1:{port_central}"),
        agent_token: token.to_string(),
        chemin_session: chemin_session.to_string(),
        chemin_cle_privee: "data/sim_proxy_secret.json".to_string(),
        local_deliver_url: "http://127.0.0.1:19999/deliver".to_string(),
        old_key_grace_sec: grace,
        peers: std::collections::HashMap::from([
            ("102".to_string(), format!("http://127.0.0.1:{}", port_proxy + 1)),
            ("103".to_string(), format!("http://127.0.0.1:{}", port_proxy + 2)),
        ]),
    };

    let mut journal = JournalSimulation::default();

    let (state_central, _) = preparer_agent(config_central).await;
    let app_central = build_router_central(Arc::clone(&state_central));
    let addr_central = format!("0.0.0.0:{port_central}");
    let listener_c = tokio::net::TcpListener::bind(&addr_central)
        .await
        .expect("bind agent central");
    let handle_central = tokio::spawn(async move {
        axum::serve(listener_c, app_central)
            .await
            .expect("serveur central");
    });

    let (state_proxy, _) = preparer_proxy(proxy_cfg.clone(), true).await;
    let app_proxy = build_router_proxy(Arc::clone(&state_proxy));
    let addr_proxy = format!("0.0.0.0:{}", proxy_cfg.listen_port);
    let listener_p = tokio::net::TcpListener::bind(&addr_proxy)
        .await
        .expect("bind proxy");
    let handle_proxy = tokio::spawn(async move {
        axum::serve(listener_p, app_proxy)
            .await
            .expect("serveur proxy");
    });

    let base_central = format!("http://127.0.0.1:{port_central}");
    let base_proxy = format!("http://127.0.0.1:{port_proxy}");
    let client = ClientHttp::new(&base_proxy, token);
    let client_central = ClientHttp::new(&base_central, token);

    etape("URL agent central", &base_central);
    etape("URL proxy VM", &base_proxy);
    etape("sessions VM", chemin_session);
    etape("export final", chemin_sim_blobs);

    if !client_central.attendre_health(5).await {
        handle_central.abort();
        handle_proxy.abort();
        panic!("Agent central /health timeout.");
    }
    if !client.attendre_health(5).await {
        handle_central.abort();
        handle_proxy.abort();
        panic!("Proxy /health timeout.");
    }
    ok("Agent central + proxy prêts");

    if let Err(e) = state_proxy
        .central
        .annoncer_proxy(
            proxy_cfg.local_vm_id,
            &base_proxy,
            &state_proxy.secret.public_key_hex,
        )
        .await
    {
        handle_central.abort();
        handle_proxy.abort();
        panic!("Annonce proxy au central : {e}");
    }
    ok("Proxy annoncé dans le registre central");

    let mut nb_ok = 0u32;
    let mut nb_ko = 0u32;
    macro_rules! assert_ok {
        ($cond:expr, $msg:expr) => {
            if $cond {
                ok($msg);
                nb_ok += 1;
            } else {
                ko($msg);
                nb_ko += 1;
            }
        };
    }

    const VM_CRYPTO: u32 = 101;

    // ═══ A — Secret faible ════════════════════════════════════════════════════
    sep("SCÉNARIO A — POST /secret/strength (secret faible)");
    workflow_step(1, "POST /secret/strength { \"secret\": \"abc\" }");
    let (st_a, rep_a) = client
        .post_token("/secret/strength", json!({"secret": "abc"}))
        .await;
    let score_a = rep_a["score"].as_u64().unwrap_or(0);
    etape("score", &score_a.to_string());
    assert_ok!(st_a == StatusCode::OK && score_a < 60, "Score < 60 pour secret faible");

    // ═══ B — Secret fort ══════════════════════════════════════════════════════
    sep("SCÉNARIO B — POST /secret/strength (secret fort)");
    workflow_step(1, "POST /secret/strength avec passphrase ENSPY");
    let (st_b, rep_b) = client
        .post_token(
            "/secret/strength",
            json!({"secret": "Tr0ub4dor&3_ENSPY!2026#"}),
        )
        .await;
    let score_b = rep_b["score"].as_u64().unwrap_or(0);
    assert_ok!(st_b == StatusCode::OK && score_b >= 60, &format!("Score {score_b} ≥ 60"));

    let plaintext_c = "ENSPY SMA 2025-2026 — message confidentiel via HTTP.";

    // ═══ E — ECDH éphémère ═══════════════════════════════════════════════════
    sep("SCÉNARIO E — POST /ecdh/initiate (paire X25519 éphémère agent)");
    workflow_step(1, "Générer paire X25519 côté pair (VM simulée)");
    let (pair_secret, pair_pub) = generer_paire_vm();
    workflow_step(2, "POST /ecdh/initiate → agent_ephemeral_public_key_hex + shared_secret_hex");
    let (st_e, rep_e) = client
        .post_token(
            "/ecdh/initiate",
            json!({
                "peer_agent_id": "vm-simulee",
                "peer_public_key_hex": pair_pub,
            }),
        )
        .await;
    let shared_agent = rep_e["shared_secret_hex"].as_str().unwrap_or("");
    let agent_ephem = rep_e["agent_ephemeral_public_key_hex"]
        .as_str()
        .unwrap_or("");
    assert_ok!(
        !agent_ephem.is_empty(),
        "E — agent_ephemeral_public_key_hex présent dans la réponse"
    );
    let agent_bytes = hex::decode(agent_ephem).expect("hex agent éphémère");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&agent_bytes);
    let shared_pair =
        hex::encode(pair_secret.diffie_hellman(&X25519PublicKey::from(arr)).as_bytes());
    assert_ok!(
        st_e == StatusCode::OK && shared_agent == shared_pair,
        "ECDH HTTP — secrets identiques (pair × clé éphémère agent)"
    );

    // ═══ F — Password generate ════════════════════════════════════════════════
    sep("SCÉNARIO F — POST /password/generate");
    let (st_f1, rep_f1) = client
        .post_token("/password/generate", json!({"longueur": 16}))
        .await;
    let p1 = rep_f1["password"].as_str().unwrap_or("");
    assert_ok!(st_f1 == StatusCode::OK && p1.len() == 16, "F1 — longueur 16");

    let (st_f2, rep_f2) = client
        .post_token(
            "/password/generate",
            json!({"longueur": 32, "exclure_ambigus": true}),
        )
        .await;
    let p2 = rep_f2["password"].as_str().unwrap_or("");
    let ambigus: Vec<char> = p2
        .chars()
        .filter(|c| ['0', 'O', 'l', '1', 'I', '|'].contains(c))
        .collect();
    assert_ok!(st_f2 == StatusCode::OK && ambigus.is_empty(), "F2 — sans ambigus");

    let (st_f3, rep_f3) = client
        .post_token(
            "/password/generate",
            json!({"longueur": 8, "symboles": false}),
        )
        .await;
    let p3 = rep_f3["password"].as_str().unwrap_or("");
    let symbs: Vec<char> = p3.chars().filter(|c| c.is_ascii_punctuation()).collect();
    assert_ok!(st_f3 == StatusCode::OK && symbs.is_empty(), "F3 — sans symboles");

    // ═══ H — Enregistrement VMs + flux clés AES visibles ═══════════════════════
    sep("SCÉNARIO H — POST /vm/session/register + flux clés AES VM (éphémère)");
    let vms_def = meta["vms_a_enregistrer"].as_array().cloned().unwrap_or_default();

    for vm_def in &vms_def {
        let vm_id = vm_def["vm_id"].as_u64().unwrap() as u32;
        workflow_step(
            1,
            &format!("VM {vm_id} : générer public_key X25519 côté VM"),
        );
        let (secret, pub_hex) = generer_paire_vm();

        let mut body = json!({"vm_id": vm_id, "public_key": pub_hex});
        if let Some(url) = vm_def["url_notification"].as_str() {
            body["url_notification"] = json!(url);
        }

        workflow_step(2, &format!("POST /vm/session/register vm_id={vm_id}"));
        let (st_h, rep_h) = client.post_token("/vm/session/register", body).await;
        etape(&format!("VM {vm_id} HTTP"), &st_h.to_string());
        assert_ok!(
            st_h == StatusCode::CREATED && rep_h["rotation_count"] == 0,
            &format!("H/{vm_id} — enregistrée, rotation_count=0")
        );

        let agent_ephem_h = rep_h["agent_ephemeral_public_key_hex"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert_ok!(
            !agent_ephem_h.is_empty(),
            &format!("H/{vm_id} — agent_ephemeral_public_key_hex dans la réponse register")
        );

        let agent_bytes = hex::decode(&agent_ephem_h).expect("agent pub éphémère hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&agent_bytes);
        let shared_vm = hex::encode(secret.diffie_hellman(&X25519PublicKey::from(arr)).as_bytes());

        flux_creation_cle_vm(
            &mut journal,
            vm_id,
            &pub_hex,
            &agent_ephem_h,
            &shared_vm,
            chemin_session,
        );

        let sur_disque = session_vm(chemin_session, vm_id).expect("session disque");
        let new_key = sur_disque["new_key"].as_str().unwrap_or("");
        let msg_test = format!("Donnée confidentielle VM {vm_id} — ENSPY SMA");
        let roundtrip_ok = flux_chiffrement_vm(&mut journal, vm_id, new_key, &msg_test);

        assert_ok!(
            sur_disque["old_key"].is_null() && !new_key.is_empty(),
            &format!("H/{vm_id} — session.json : new_key présente, old_key=null")
        );
        assert_ok!(
            roundtrip_ok,
            &format!("H/{vm_id} — chiffrement/déchiffrement client avec new_key OK")
        );
    }

    let (st_sans, rep_sans) = client.get_public("/vm/sessions").await;
    assert_ok!(
        st_sans == StatusCode::OK && rep_sans["count"].as_u64() == Some(vms_def.len() as u64),
        "GET /vm/sessions sans token accepté"
    );

    let res_list = client
        .http
        .get(format!("{base_proxy}/vm/sessions"))
        .header("X-Agent-Token", token)
        .send()
        .await
        .expect("GET /vm/sessions");
    let rep_list_ok: Value = res_list.json().await.unwrap_or(json!({}));
    assert_ok!(
        rep_list_ok["count"].as_u64() == Some(vms_def.len() as u64),
        &format!(
            "H — GET /vm/sessions : {} VM(s)",
            rep_list_ok["count"].as_u64().unwrap_or(0)
        )
    );

    // ═══ 0 — Encrypt sans token (après enregistrement VM) ═════════════════════
    sep("SCÉNARIO 0 — POST /encrypt sans X-Agent-Token (clé VM)");
    workflow_step(1, "POST /encrypt sans en-tête, vm_id=101");
    let (st0, rep0) = client
        .post_sans_token(
            "/encrypt",
            json!({"vm_id": VM_CRYPTO, "plaintext": "test sans token"}),
        )
        .await;
    etape("HTTP", &st0.to_string());
    assert_ok!(
        st0 == StatusCode::OK && rep0["status"] == "success" && rep0["vm_id"] == VM_CRYPTO,
        "Accès sans token — chiffrement VM OK"
    );

    // ═══ C — Encrypt VM ═══════════════════════════════════════════════════════
    sep("SCÉNARIO C — POST /encrypt (new_key VM)");
    workflow_step(1, &format!("POST /encrypt vm_id={VM_CRYPTO}"));
    let (st_c, rep_c_resp) = client
        .post_token(
            "/encrypt",
            json!({"vm_id": VM_CRYPTO, "plaintext": plaintext_c}),
        )
        .await;
    let ct_c = rep_c_resp["ciphertext"].as_str().unwrap_or("").to_string();
    let iv_c = rep_c_resp["iv"].as_str().unwrap_or("").to_string();
    let tag_c = rep_c_resp["auth_tag"].as_str().unwrap_or("").to_string();
    journal.log_agent(
        "C",
        "post_encrypt_vm",
        json!({
            "vm_id": VM_CRYPTO,
            "new_key_id": rep_c_resp["new_key_id"],
            "ciphertext_apercu": apercu_hex(&ct_c, 24),
            "plaintext": plaintext_c,
        }),
    );
    assert_ok!(
        st_c == StatusCode::OK && !ct_c.is_empty(),
        "Chiffrement HTTP avec clé VM (new_key)"
    );

    // ═══ D — Decrypt roundtrip VM ═════════════════════════════════════════════
    sep("SCÉNARIO D — POST /decrypt (roundtrip C, clé new)");
    flux_titre("Agent — déchiffrement VM (POST /decrypt)");
    workflow_step(1, "POST /decrypt avec vm_id + ciphertext du scénario C");
    let (st_d, rep_d) = client
        .post_token(
            "/decrypt",
            json!({
                "vm_id": VM_CRYPTO,
                "ciphertext": &ct_c,
                "iv": &iv_c,
                "auth_tag": &tag_c,
            }),
        )
        .await;
    let plain_d = rep_d["plaintext"].as_str().unwrap_or("");
    etape("key_used", rep_d["key_used"].as_str().unwrap_or("?"));
    journal.log_agent(
        "D",
        "post_decrypt_vm",
        json!({
            "vm_id": VM_CRYPTO,
            "key_used": rep_d["key_used"],
            "plaintext": plain_d,
            "identique_a_l_original": plain_d == plaintext_c,
        }),
    );
    assert_ok!(
        st_d == StatusCode::OK
            && plain_d == plaintext_c
            && rep_d["key_used"] == "new",
        "Déchiffrement HTTP — new_key, texte identique"
    );

    // ═══ G — Intégrité GCM VM ═════════════════════════════════════════════════
    sep("SCÉNARIO G — Intégrité GCM via HTTP (clé VM)");
    let (st_ge, rep_ge) = client
        .post_token(
            "/encrypt",
            json!({"vm_id": VM_CRYPTO, "plaintext": "Test intégrité GCM"}),
        )
        .await;
    let ct = rep_ge["ciphertext"].as_str().unwrap_or("").to_string();
    let ct_faux = if ct.starts_with('A') {
        format!("B{}", &ct[1..])
    } else {
        format!("A{}", &ct[1..])
    };
    let (st_gd, rep_gd) = client
        .post_token(
            "/decrypt",
            json!({
                "vm_id": VM_CRYPTO,
                "ciphertext": ct_faux,
                "iv": rep_ge["iv"],
                "auth_tag": rep_ge["auth_tag"],
            }),
        )
        .await;
    assert_ok!(
        st_gd == StatusCode::BAD_REQUEST && rep_gd["error"] == "CRYPTO_ERROR",
        "Falsification détectée — CRYPTO_ERROR"
    );

    // ═══ I — Contrôle accès rotation (refus d'abord, succès ensuite) ══════════
    sep("SCÉNARIO I — POST /credential/rotate (X-Agent-Name)");
    for sc in meta["scenarios_acces_rotation"].as_array().unwrap_or(&vec![]) {
        let attendu = sc["attendu_http"].as_u64().unwrap_or(403);
        if attendu == 200 {
            continue;
        }
        let id = sc["id"].as_str().unwrap_or("?");
        let name = sc["agent_name"].as_str().unwrap_or("");
        workflow_step(1, &format!("{id} : X-Agent-Name = '{name}' → HTTP {attendu}"));
        let (st_i, rep_i) = client_central.post_rotate(name, json!({})).await;
        assert_ok!(
            st_i.as_u16() == attendu as u16 && rep_i["error"] == sc["error_code"],
            &format!("I/{id} — accès refusé ({})", sc["error_code"])
        );
    }
    workflow_step(3, "I-ok : agent autorisé → HTTP 200");
    let (st_i_ok, _) = client_central.post_rotate(agent_ok, json!({})).await;
    assert_ok!(st_i_ok == StatusCode::OK, "I/I-ok — rotation autorisée");

    // ═══ J — Rotation ECDH ════════════════════════════════════════════════════
    sep("SCÉNARIO J — POST /credential/rotate (mise à jour session.json)");
    let mut cnt_avant: HashMap<u32, u32> = HashMap::new();
    for vm_def in &vms_def {
        let vm_id = vm_def["vm_id"].as_u64().unwrap() as u32;
        if let Some(s) = session_vm(chemin_session, vm_id) {
            cnt_avant.insert(vm_id, s["rotation_count"].as_u64().unwrap_or(0) as u32);
        }
    }

    let plaintext_avant_rot = "Message à déchiffrer via old_key après rotation J";
    workflow_step(0, "POST /encrypt avant rotation (référence old_key)");
    let (st_je, rep_je) = client
        .post_token(
            "/encrypt",
            json!({"vm_id": VM_CRYPTO, "plaintext": plaintext_avant_rot}),
        )
        .await;
    let ct_avant = rep_je["ciphertext"].as_str().unwrap_or("").to_string();
    let iv_avant = rep_je["iv"].as_str().unwrap_or("").to_string();
    let tag_avant = rep_je["auth_tag"].as_str().unwrap_or("").to_string();
    assert_ok!(
        st_je == StatusCode::OK && !ct_avant.is_empty(),
        "J — chiffrement référence avant rotation"
    );

    workflow_step(1, "POST /credential/rotate central → proxy (cycle old/new)");
    let (st_j, rep_j) = client_central.post_rotate(agent_ok, json!({})).await;
    etape("proxies_reussis", &rep_j["proxies_reussis"].to_string());

    assert_ok!(
        st_j == StatusCode::OK && rep_j["proxies_reussis"].as_u64().unwrap_or(0) >= 1,
        "J — rotation propagée au proxy via agent central"
    );

    for vm_def in &vms_def {
        let vm_id = vm_def["vm_id"].as_u64().unwrap() as u32;
        let apres = session_vm(chemin_session, vm_id).expect("session disque");
        let cnt_apres = apres["rotation_count"].as_u64().unwrap_or(0) as u32;
        let cnt_old = cnt_avant.get(&vm_id).copied().unwrap_or(0);
        assert_ok!(
            cnt_apres == cnt_old + 1,
            &format!("J/{vm_id} — rotation_count {cnt_apres} == {cnt_old} + 1")
        );
        assert_ok!(
            !apres["old_key"].is_null(),
            &format!("J/{vm_id} — old_key renseignée dans session.json (timer grâce)")
        );
        assert_ok!(
            !apres["new_key"].as_str().unwrap_or("").is_empty(),
            &format!("J/{vm_id} — new_key active présente")
        );
        journal.nouvelle_etape_vm(
            vm_id,
            "J",
            "rotation_ecdh_post_credential_rotate",
            json!({
                "rotation_count": cnt_apres,
                "new_key_apercu": apercu_hex(apres["new_key"].as_str().unwrap_or(""), 16),
                "old_key_apercu": apres["old_key"].as_str().map(|k| apercu_hex(k, 16)),
            }),
        );
    }

    sep("SCÉNARIO J — POST /decrypt avec old_key (période de grâce)");
    workflow_step(1, "Déchiffrer le message chiffré juste avant rotation (old_key)");
    let (st_jd, rep_jd) = client
        .post_token(
            "/decrypt",
            json!({
                "vm_id": VM_CRYPTO,
                "ciphertext": ct_avant,
                "iv": iv_avant,
                "auth_tag": tag_avant,
            }),
        )
        .await;
    let plain_jd = rep_jd["plaintext"].as_str().unwrap_or("");
    etape("key_used après rotation", rep_jd["key_used"].as_str().unwrap_or("?"));
    journal.log_agent(
        "J",
        "post_decrypt_old_key_grace",
        json!({
            "vm_id": VM_CRYPTO,
            "key_used": rep_jd["key_used"],
            "plaintext": plain_jd,
        }),
    );
    assert_ok!(
        st_jd == StatusCode::OK
            && rep_jd["key_used"] == "old"
            && plain_jd == plaintext_avant_rot,
        "J — déchiffrement via old_key pendant la grâce"
    );

    // ═══ K — Timer grâce ══════════════════════════════════════════════════════
    sep(&format!("SCÉNARIO K — Timer grâce old_key ({grace}s)"));
    let vm_k = 101u32;
    workflow_step(1, "Vérifier old_key présente juste après rotation J");
    let k1 = session_vm(chemin_session, vm_k).unwrap();
    assert_ok!(!k1["old_key"].is_null(), "K.1 — old_key présente sur disque");

    workflow_step(2, &format!("Attendre {}s (expiration grâce)", grace + 1));
    tokio::time::sleep(Duration::from_secs(grace + 1)).await;

    workflow_step(3, "POST /vm/sessions/purge-expired");
    let (st_kp, rep_kp) = client.post_token("/vm/sessions/purge-expired", json!({})).await;
    etape("clés purgées", &rep_kp["cles_purgees"].to_string());
    assert_ok!(st_kp == StatusCode::OK, "K — purge HTTP OK");

    let k3 = session_vm(chemin_session, vm_k).unwrap();
    assert_ok!(k3["old_key"].is_null(), "K.3 — old_key=null dans session.json");
    assert_ok!(
        !k3["new_key"].as_str().unwrap_or("").is_empty(),
        "K.3 — new_key inchangée"
    );

    // ═══ L — Double rotation ══════════════════════════════════════════════════
    sep("SCÉNARIO L — Deux rotations HTTP (VMs 201–202)");
    for vm_id in [201u32, 202] {
        let (_, pub_hex) = generer_paire_vm();
        client
            .post_token(
                "/vm/session/register",
                json!({"vm_id": vm_id, "public_key": pub_hex}),
            )
            .await;
    }

    workflow_step(1, "Première POST /credential/rotate (central)");
    client_central.post_rotate(agent_ok, json!({})).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    workflow_step(2, "Deuxième POST /credential/rotate (central)");
    client_central.post_rotate(agent_ok, json!({})).await;

    for vm_id in [201u32, 202] {
        let s = session_vm(chemin_session, vm_id).unwrap();
        let cnt = s["rotation_count"].as_u64().unwrap_or(0);
        assert_ok!(cnt >= 2, &format!("L/{vm_id} — rotation_count={cnt} ≥ 2"));
    }

    // ═══ Export persistant ════════════════════════════════════════════════════
    handle_central.abort();
    handle_proxy.abort();

    sep("EXPORT — Persistance data/sim_blobs.json");
    workflow_step(1, "Fusion sim_session.json + sim_agent_blobs.json + journal");
    match exporter_sim_blobs(chemin_sim_blobs, chemin_session, chemin_blobs_agent, &journal) {
        Ok(()) => {
            ok(&format!("Export écrit → {chemin_sim_blobs}"));
            etape("sessions VM", chemin_session);
            etape("conservé", "oui (non supprimé)");
            if let Ok(v) = std::fs::read_to_string(chemin_sim_blobs) {
                if let Ok(j) = serde_json::from_str::<Value>(&v) {
                    let nb_vms = j["vms_cles_aes"].as_object().map(|o| o.len()).unwrap_or(0);
                    let nb_flux = j["flux_creation_cles_vm"].as_array().map(|a| a.len()).unwrap_or(0);
                    etape("VMs dans export", &nb_vms.to_string());
                    etape("flux VM journalisés", &nb_flux.to_string());
                }
            }
        }
        Err(e) => ko(&format!("Export sim_blobs : {e}")),
    }

    let total = nb_ok + nb_ko;
    println!("\n{GRAS}{CYAN}══ RÉSUMÉ ══{RESET}");
    println!("  {VERT}✔ Succès :{RESET} {nb_ok}");
    println!("  {ROUGE}✗ Échecs :{RESET} {nb_ko}");
    println!("  Total    : {total}");
    println!("\n  {GRAS}Fichiers conservés :{RESET}");
    println!("    • {chemin_session}");
    println!("    • {chemin_sim_blobs}");
    println!("    • {chemin_blobs_agent}");

    if nb_ko > 0 {
        std::process::exit(1);
    }
}

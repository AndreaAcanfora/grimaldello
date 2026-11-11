//! grimaldello adapter for webauthn-rs (webauthn-rs-core).
//! Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
//!
//! webauthn-rs always generates its own challenge, so the adapter starts each
//! ceremony normally and then swaps the challenge in the serialized state (the
//! state types are Serialize/Deserialize so applications can persist them).

use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::{json, Value};
use url::Url;
use webauthn_rs_core::proto::{
    COSEAlgorithm, Credential, PublicKeyCredential, RegisterPublicKeyCredential, UserVerificationPolicy,
};
use webauthn_rs_core::WebauthnCore;

const VERSION: &str = "0.5.5";

fn policy(c: &Value) -> UserVerificationPolicy {
    if c["requireUserVerification"].as_bool().unwrap_or(false) {
        UserVerificationPolicy::Required
    } else {
        UserVerificationPolicy::Preferred
    }
}

fn with_challenge<T: serde::Serialize + serde::de::DeserializeOwned>(state: T, challenge: &str) -> Result<T, String> {
    let mut v = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    v["challenge"] = Value::String(challenge.to_string());
    serde_json::from_value(v).map_err(|e| format!("state round-trip: {e}"))
}

fn verify(c: &Value) -> Result<(), String> {
    let rp = &c["rp"];
    let origin = Url::parse(rp["origin"].as_str().unwrap()).map_err(|e| e.to_string())?;
    let core = WebauthnCore::new_unsafe_experts_only(
        rp["name"].as_str().unwrap(),
        rp["id"].as_str().unwrap(),
        vec![origin],
        Duration::from_secs(300),
        None,
        None,
    );
    let algs: Vec<COSEAlgorithm> = c["algorithms"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| COSEAlgorithm::try_from(a.as_i64().unwrap() as i128).ok())
        .collect();
    let builder = core
        .new_challenge_register_builder(b"grimaldello-user-1", "grimaldello", "grimaldello")
        .map_err(|e| format!("{e:?}"))?
        .user_verification_policy(policy(c))
        .credential_algorithms(algs);
    let (_, state) = core.generate_challenge_register(builder).map_err(|e| format!("{e:?}"))?;
    let reg = &c["registration"];
    let state = with_challenge(state, reg["challenge"].as_str().unwrap())?;
    let response: RegisterPublicKeyCredential =
        serde_json::from_value(reg["response"].clone()).map_err(|e| format!("parse: {e}"))?;
    let registered = core.register_credential(&response, &state, None);
    if c["ceremony"] == "registration" {
        return registered.map(|_| ()).map_err(|e| format!("{e:?}"));
    }
    let cred = registered.map_err(|e| format!("setup: registration failed: {e:?}"))?;

    let auth = &c["authentication"];
    let mut cv = serde_json::to_value(&cred).map_err(|e| e.to_string())?;
    cv["counter"] = auth["storedSignCount"].clone();
    let cred: Credential = serde_json::from_value(cv).map_err(|e| e.to_string())?;
    let response: PublicKeyCredential =
        serde_json::from_value(auth["response"].clone()).map_err(|e| format!("parse: {e}"))?;
    // What an application does: look the credential up by the id in the response.
    if response.id != c["registration"]["response"]["id"].as_str().unwrap() {
        return Err("unknown credential".into());
    }
    let builder = core
        .new_challenge_authenticate_builder(vec![cred], Some(policy(c)))
        .map_err(|e| format!("{e:?}"))?;
    let (_, state) = core.generate_challenge_authenticate(builder).map_err(|e| format!("{e:?}"))?;
    let state = with_challenge(state, auth["challenge"].as_str().unwrap())?;
    core.authenticate_credential(&response, &state).map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn main() {
    if std::env::args().any(|a| a == "--info") {
        println!("{}", json!({"library": "webauthn-rs", "version": VERSION, "language": "Rust"}));
        return;
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let c: Value = serde_json::from_str(&line).unwrap();
        let res = match verify(&c) {
            Ok(()) => json!({"id": c["id"], "verdict": "accept"}),
            Err(e) => json!({"id": c["id"], "verdict": "reject", "error": e}),
        };
        writeln!(out, "{res}").unwrap();
        out.flush().unwrap();
    }
}

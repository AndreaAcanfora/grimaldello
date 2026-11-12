//! grimaldello adapter for webauthn-rs, through its public passkey API.
//! Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
//!
//! webauthn-rs generates its own challenge. The cases carry fixed, signed
//! challenges, so the adapter starts each ceremony normally, serialises the
//! state (as an application storing it between requests would), replaces the
//! challenge and nothing else, and finishes the ceremony with that state.
//!
//! The passkey API always requires user verification and offers ES256 and
//! RS256; webauthn-rs 0.6 has no Ed25519 support, so EdDSA cases are reported
//! as unsupported.

use std::io::{BufRead, Write};

use serde_json::{json, Value};
use url::Url;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Uuid,
    WebauthnBuilder,
};

/// The webauthn-rs version actually built, read from the lock file.
fn version() -> String {
    let lock = include_str!("../Cargo.lock");
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line == "name = \"webauthn-rs\"" {
            if let Some(v) = lines.next().and_then(|l| l.strip_prefix("version = ")) {
                return v.trim_matches('"').to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Replace the challenge in a serialised ceremony state.
fn with_challenge<T: serde::Serialize + serde::de::DeserializeOwned>(state: T, key: &str, challenge: &str) -> Result<T, String> {
    let mut v = serde_json::to_value(&state).map_err(|e| e.to_string())?;
    v[key]["challenge"] = Value::String(challenge.to_string());
    serde_json::from_value(v).map_err(|e| format!("state round-trip: {e}"))
}

const USER: Uuid = Uuid::from_u128(0x6772696d_616c_6465_6c6c_6f2d75736572);

fn verify(c: &Value) -> Result<(), String> {
    let rp = &c["rp"];
    let origin = Url::parse(rp["origin"].as_str().unwrap()).map_err(|e| e.to_string())?;
    let webauthn = WebauthnBuilder::new(rp["id"].as_str().unwrap(), &origin)
        .map_err(|e| format!("{e:?}"))?
        .rp_name(rp["name"].as_str().unwrap())
        .build()
        .map_err(|e| format!("{e:?}"))?;

    let reg = &c["registration"];
    let (_, state) = webauthn
        .start_passkey_registration(USER, "grimaldello", "grimaldello", None)
        .map_err(|e| format!("{e:?}"))?;
    let state: PasskeyRegistration = with_challenge(state, "rs", reg["challenge"].as_str().unwrap())?;
    let response: RegisterPublicKeyCredential =
        serde_json::from_value(reg["response"].clone()).map_err(|e| format!("parse: {e}"))?;
    let registered = webauthn.finish_passkey_registration(&response, &state);
    if c["ceremony"] == "registration" {
        return registered.map(|_| ()).map_err(|e| format!("{e:?}"));
    }
    let passkey = registered.map_err(|e| format!("setup: registration failed: {e:?}"))?;

    let auth = &c["authentication"];
    let mut pv = serde_json::to_value(&passkey).map_err(|e| e.to_string())?;
    pv["cred"]["counter"] = auth["storedSignCount"].clone();
    let passkey: Passkey = serde_json::from_value(pv).map_err(|e| e.to_string())?;
    let response: PublicKeyCredential =
        serde_json::from_value(auth["response"].clone()).map_err(|e| format!("parse: {e}"))?;
    // What an application does: look the credential up by the id in the response.
    if response.id != reg["response"]["id"].as_str().unwrap() {
        return Err("unknown credential".into());
    }
    let (_, state) = webauthn
        .start_passkey_authentication(&[passkey])
        .map_err(|e| format!("{e:?}"))?;
    let state: PasskeyAuthentication = with_challenge(state, "ast", auth["challenge"].as_str().unwrap())?;
    webauthn
        .finish_passkey_authentication(&response, &state)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn main() {
    if std::env::args().any(|a| a == "--info") {
        println!("{}", json!({"library": "webauthn-rs", "version": version(), "language": "Rust"}));
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
        let res = if c["alg"] == "EdDSA" {
            json!({"id": c["id"], "verdict": "unsupported"})
        } else {
            match verify(&c) {
                Ok(()) => json!({"id": c["id"], "verdict": "accept"}),
                Err(e) => json!({"id": c["id"], "verdict": "reject", "error": e}),
            }
        };
        writeln!(out, "{res}").unwrap();
        out.flush().unwrap();
    }
}

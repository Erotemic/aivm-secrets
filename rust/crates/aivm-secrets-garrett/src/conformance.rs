//! Explicit test-only crypto adapter. Never served on the broker listener.
use crate::{
    crypto::{Issuer, Verifier},
    json, model, Error, Outcome,
};
use serde_json::{json, Value};
pub fn unhex(text: &str) -> Outcome<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| {
            let v = std::str::from_utf8(x).map_err(|_| Error::InvalidCapability)?;
            u8::from_str_radix(v, 16).map_err(|_| Error::InvalidCapability)
        })
        .collect()
}
fn bytes(v: &Value) -> Outcome<Vec<u8>> {
    unhex(v.as_str().ok_or(Error::InvalidCapability)?)
}
fn text(v: &Value) -> Outcome<&str> {
    v.as_str().ok_or(Error::InvalidCapability)
}
pub fn evaluate(v: &Value) -> Outcome<Value> {
    if v.get("action").and_then(Value::as_str) == Some("attestation") {
        let m = json::keys(
            v,
            &[
                "action",
                "ak_area_hex",
                "ak_qualified_name_hex",
                "challenge_hex",
                "public_area_hex",
                "attestation_hex",
                "signature_hex",
            ],
            &[],
        )?;
        let authority = crate::attestation::Authority::from_trusted_pin(
            &bytes(&m["ak_area_hex"])?,
            &bytes(&m["ak_qualified_name_hex"])?,
        )?;
        let challenge = bytes(&m["challenge_hex"])?
            .try_into()
            .map_err(|_| Error::InvalidCapability)?;
        let area = bytes(&m["public_area_hex"])?;
        let attestation = bytes(&m["attestation_hex"])?;
        let signature = bytes(&m["signature_hex"])?;
        let verified = authority
            .fixture_begin(challenge)
            .verify(crate::attestation::Evidence {
                public_area: &area,
                attestation: &attestation,
                signature: &signature,
            })?;
        let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
        return Ok(
            json!({"ok":true,"spki_der_hex":hex(verified.subject_public_key_info()),"key_name_hex":hex(verified.key_name())}),
        );
    }
    let top = json::keys(
        v,
        &["action"],
        &[
            "seed_hex",
            "state",
            "issuer",
            "audience",
            "subject",
            "lifetime",
            "public_key_hex",
            "encryption_key_hex",
            "kid",
            "claims",
            "inner_capability",
            "nonce_hex",
            "token",
            "certificate_der_hex",
            "expected",
            "now",
        ],
    )?;
    match top["action"].as_str() {
        Some("issue") => {
            let m = json::keys(
                v,
                &[
                    "action",
                    "seed_hex",
                    "encryption_key_hex",
                    "kid",
                    "claims",
                    "inner_capability",
                ],
                &["nonce_hex"],
            )?;
            let issuer = Issuer::new(
                &bytes(&m["seed_hex"])?,
                &bytes(&m["encryption_key_hex"])?,
                text(&m["kid"])?,
            )?;
            let claims = model::claims(&m["claims"])?;
            let inner = text(&m["inner_capability"])?;
            let token = if let Some(n) = m.get("nonce_hex") {
                let nonce: [u8; 12] = bytes(n)?.try_into().map_err(|_| Error::InvalidCapability)?;
                issuer.fixture_issue(&claims, inner.as_bytes(), nonce)?
            } else {
                issuer.issue(&claims, inner.as_bytes())?
            };
            let public_key_hex: String = issuer
                .public_key()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Ok(json!({"ok":true,"token":token,"public_key_hex":public_key_hex}))
        }
        Some("enrollment-issue") => {
            let m = json::keys(
                v,
                &[
                    "action",
                    "seed_hex",
                    "encryption_key_hex",
                    "kid",
                    "state",
                    "issuer",
                    "audience",
                    "subject",
                    "now",
                    "lifetime",
                    "inner_capability",
                ],
                &[],
            )?;
            let issuer = Issuer::new(
                &bytes(&m["seed_hex"])?,
                &bytes(&m["encryption_key_hex"])?,
                text(&m["kid"])?,
            )?;
            let issuer_name = text(&m["issuer"])?;
            let audience = text(&m["audience"])?;
            let registry = model::Registry::parse(&m["state"], issuer_name, audience)?;
            let issued = issuer.issue_for_enrollment(
                &registry,
                issuer_name,
                audience,
                text(&m["subject"])?,
                text(&m["inner_capability"])?.as_bytes(),
                json::integer(&m["now"], 0, i64::MAX)?,
                json::integer(&m["lifetime"], 1, 3600)?,
            )?;
            let token = std::str::from_utf8(&issued.token).map_err(|_| Error::InvalidCapability)?;
            let public_key_hex: String = issuer
                .public_key()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Ok(
                json!({"ok":true,"claims":model::claims_json(&issued.claims)?,"token":token,"public_key_hex":public_key_hex}),
            )
        }
        Some("open") => {
            let m = json::keys(
                v,
                &[
                    "action",
                    "public_key_hex",
                    "encryption_key_hex",
                    "kid",
                    "token",
                    "certificate_der_hex",
                    "expected",
                    "now",
                ],
                &[],
            )?;
            let verifier = Verifier::new(
                &bytes(&m["public_key_hex"])?,
                &bytes(&m["encryption_key_hex"])?,
                text(&m["kid"])?,
            )?;
            verifier.fixture_open(
                text(&m["token"])?,
                &bytes(&m["certificate_der_hex"])?,
                &model::expectation(&m["expected"])?,
                json::integer(&m["now"], 0, i64::MAX)?,
            )
        }
        _ => Err(Error::InvalidCapability),
    }
}

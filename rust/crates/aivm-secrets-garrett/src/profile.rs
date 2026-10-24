//! The read-only release profile, enforced when the bridge is built with the
//! `read-only` feature.
//!
//! The native read proofs cover one configuration: a provider session with
//! `manifest-https-v1` and `writes = "deny"`, no cross-host coordination and
//! no forwarding to a Python broker. The same source supports other
//! configurations, so a release that claims only reads builds the bridge with
//! `--features read-only`, and the bridge then refuses any other
//! configuration at startup instead of relying on the operator to pick the
//! right one. Guest input cannot select a configuration in any build.
use crate::{Error, Outcome};
use serde_json::Value;

/// `Ok` only for the read profile the proofs cover.
pub fn read_only(config: &Value) -> Outcome<()> {
    let object = config.as_object().ok_or(Error::InvalidPolicy)?;
    if object.contains_key("broker_socket") || object.contains_key("public_key_hex") {
        return Err(Error::InvalidPolicy);
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or(Error::InvalidPolicy)?;
    if provider.get("profile").and_then(Value::as_str) != Some("manifest-https-v1")
        || provider.get("writes").and_then(Value::as_str) != Some("deny")
        || provider.contains_key("coordination_file")
    {
        return Err(Error::InvalidPolicy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_only;
    use serde_json::json;

    fn config(provider: serde_json::Value) -> serde_json::Value {
        json!({"schema": 1, "listen": "/run/x.sock", "provider": provider})
    }

    #[test]
    fn only_the_proved_read_profile_starts() {
        let read = json!({"profile": "manifest-https-v1", "writes": "deny"});
        assert!(read_only(&config(read)).is_ok());
        for refused in [
            json!({"profile": "manifest-https-v1", "writes": "allow"}),
            json!({"profile": "manifest-https-v1", "writes": "approve"}),
            json!({"profile": "manifest-https-v1"}),
            json!({"profile": "account-status-v1", "writes": "deny"}),
            json!({"profile": "manifest-https-v1", "writes": "deny", "coordination_file": "/c"}),
        ] {
            assert!(read_only(&config(refused)).is_err());
        }
        assert!(read_only(&json!({"schema": 1, "broker_socket": "/b"})).is_err());
        let mut forwarding = config(json!({"profile": "manifest-https-v1", "writes": "deny"}));
        forwarding["broker_socket"] = json!("/b");
        assert!(read_only(&forwarding).is_err());
    }
}

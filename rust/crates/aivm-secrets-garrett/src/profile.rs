//! The read-only release profile, enforced by the `garrett-bridge-read-only`
//! binary.
//!
//! The native read proofs cover one configuration: a provider session with
//! `manifest-https-v1` and `writes = "deny"`, a file credential, no
//! cross-host coordination and no forwarding to a Python broker. An OAuth
//! source is refused: its token refresh opens its own TLS connection to the
//! token endpoint (`oauth_vault`), outside the one provider transport the
//! read proofs and `NATIVE-SINK-01` cover. Identity must come from an
//! authority root (`garrett-authority`): there a completed revocation drains
//! every use admitted before it, whereas the legacy registry-file mode reads
//! a registry snapshot when a request starts, so a request admitted before a
//! registry update can still send after it. The same source supports other
//! configurations, so a release that claims only reads deploys
//! `garrett-bridge-read-only`, which refuses any other
//! configuration at startup instead of relying on the operator to pick the
//! right one. Guest input cannot select a configuration in any build.
use crate::{Error, Outcome};
use serde_json::Value;

/// `Ok` only for the read profile the proofs cover.
pub fn read_only(config: &Value) -> Outcome<()> {
    let object = config.as_object().ok_or(Error::InvalidPolicy)?;
    if object.contains_key("broker_socket")
        || object.contains_key("public_key_hex")
        || object.contains_key("registry_path")
        || !object.contains_key("authority_root")
    {
        return Err(Error::InvalidPolicy);
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or(Error::InvalidPolicy)?;
    if provider.get("profile").and_then(Value::as_str) != Some("manifest-https-v1")
        || provider.get("writes").and_then(Value::as_str) != Some("deny")
        || provider.contains_key("coordination_file")
        || provider.contains_key("oauth")
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
        json!({"schema": 1, "listen": "/run/x.sock", "authority_root": "/a", "provider": provider})
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
            json!({"profile": "manifest-https-v1", "writes": "deny", "oauth": {"token_file": "/t"}}),
        ] {
            assert!(read_only(&config(refused)).is_err());
        }
        assert!(read_only(&json!({"schema": 1, "broker_socket": "/b"})).is_err());
        let mut forwarding = config(json!({"profile": "manifest-https-v1", "writes": "deny"}));
        forwarding["broker_socket"] = json!("/b");
        assert!(read_only(&forwarding).is_err());
        // Legacy registry-file identity: no immediate revocation fencing.
        let read = json!({"profile": "manifest-https-v1", "writes": "deny"});
        let mut legacy = config(read.clone());
        legacy.as_object_mut().unwrap().remove("authority_root");
        assert!(read_only(&legacy).is_err());
        let mut both = config(read);
        both["registry_path"] = json!("/r");
        assert!(read_only(&both).is_err());
    }
}

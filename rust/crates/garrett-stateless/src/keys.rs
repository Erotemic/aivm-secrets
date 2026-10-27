//! Key-set files (spec section 3) and rotation (section 10). Which entry a
//! token selects, and what makes a key set valid, is the extracted
//! `stateless_token`; this module reads and writes the files and generates
//! key material.
use crate::encoding::{b64url, from_b64url, is_kid, is_text, random};
use crate::error::{config, Error, Result};
use crate::json::{self, Value};
use crate::token::RingKey;
use aivm_secrets_garrett_core::stateless_token::{self, KeySet};
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

pub const BROKER_SCHEMA: &str = "garrett-stateless-v1/broker-keys";
pub const PROXY_SCHEMA: &str = "garrett-stateless-v1/proxy-keys";
pub const MAX_KEYS: usize = 8;

/// One `kid`: the issuer it signs for, its Ed25519 public key, its AES-256-GCM
/// sealing key and, in a broker key set, its Ed25519 seed.
pub struct KeyEntry {
    pub kid: String,
    pub issuer: String,
    pub verify: [u8; 32],
    seal: Zeroizing<[u8; 32]>,
    sign: Option<Zeroizing<[u8; 32]>>,
}

impl KeyEntry {
    pub fn seal_key(&self) -> &[u8; 32] {
        &self.seal
    }
    /// The codec's entry: `kid`, issuer and `ring` key material.
    pub fn core(&self) -> stateless_token::KeyEntry<RingKey> {
        stateless_token::KeyEntry {
            kid: self.kid.as_bytes().to_vec(),
            issuer: self.issuer.as_bytes().to_vec(),
            material: RingKey {
                verify: self.verify,
                seal: self.seal.clone(),
                sign: self.sign.clone(),
            },
        }
    }
    fn public(&self) -> Value {
        json::object([
            ("issuer", json::text(&self.issuer)),
            ("kid", json::text(&self.kid)),
            ("seal", json::text(&b64url(&self.seal[..]))),
            ("verify", json::text(&b64url(&self.verify))),
        ])
    }
}

fn key32(value: Option<&Value>, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| config(format!("{name} missing")))?;
    let bytes =
        Zeroizing::new(from_b64url(text).ok_or_else(|| config(format!("{name} is not b64url")))?);
    let array: [u8; 32] = bytes[..]
        .try_into()
        .map_err(|_| config(format!("{name} is not 32 bytes")))?;
    Ok(Zeroizing::new(array))
}

fn exact_keys(value: &Value, names: &[&str], what: &str) -> Result<()> {
    let map = value
        .as_object()
        .ok_or_else(|| config(format!("{what} is not an object")))?;
    if map.len() != names.len() || !names.iter().all(|n| map.contains_key(*n)) {
        return Err(config(format!("{what} must have exactly {names:?}")));
    }
    Ok(())
}

fn entry_of(value: &Value, broker: bool) -> Result<KeyEntry> {
    let names: &[&str] = if broker {
        &["issuer", "kid", "seal", "sign"]
    } else {
        &["issuer", "kid", "seal", "verify"]
    };
    exact_keys(value, names, "key entry")?;
    let kid = value
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| is_kid(k))
        .ok_or_else(|| config("invalid kid"))?;
    let issuer = value
        .get("issuer")
        .and_then(Value::as_str)
        .filter(|i| is_text(i))
        .ok_or_else(|| config("invalid issuer"))?;
    let seal = key32(value.get("seal"), "seal")?;
    let (verify, sign) = if broker {
        let seed = key32(value.get("sign"), "sign")?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed[..])
            .map_err(|_| config("invalid signing seed"))?;
        let public: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| config("public key"))?;
        (public, Some(seed))
    } else {
        (*key32(value.get("verify"), "verify")?, None)
    };
    Ok(KeyEntry {
        kid: kid.to_owned(),
        issuer: issuer.to_owned(),
        verify,
        seal,
        sign,
    })
}

fn entries_of(value: Option<&Value>, broker: bool) -> Result<Vec<KeyEntry>> {
    let Some(Value::Array(items)) = value else {
        return Err(config("keys must be an array"));
    };
    if items.is_empty() || items.len() > MAX_KEYS {
        return Err(config("between 1 and 8 keys"));
    }
    let entries = items
        .iter()
        .map(|item| entry_of(item, broker))
        .collect::<Result<Vec<_>>>()?;
    let mut seen = std::collections::BTreeSet::new();
    if !entries.iter().all(|e| seen.insert(e.kid.clone())) {
        return Err(config("duplicate kid"));
    }
    Ok(entries)
}

/// The extracted key set of these entries, refused unless it is valid.
pub fn key_set(entries: &[KeyEntry]) -> Result<KeySet<RingKey>> {
    KeySet::new(entries.iter().map(KeyEntry::core).collect()).map_err(|_| config("invalid key set"))
}

/// The keys a proxy needs: verification and sealing keys, no signing seed.
pub struct ProxyKeys {
    pub entries: Vec<KeyEntry>,
}

impl ProxyKeys {
    pub fn key_set(&self) -> Result<KeySet<RingKey>> {
        key_set(&self.entries)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value =
            json::parse(bytes, 65536, 8).map_err(|_| config("key file is not strict JSON"))?;
        exact_keys(&value, &["keys", "schema"], "proxy key file")?;
        if value.get("schema").and_then(Value::as_str) != Some(PROXY_SCHEMA) {
            return Err(config("unsupported proxy key schema"));
        }
        Ok(Self {
            entries: entries_of(value.get("keys"), false)?,
        })
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        Self::parse(&crate::files::read_private(path, 65536)?)
    }
    pub fn to_json(&self) -> Vec<u8> {
        let keys = Value::Array(self.entries.iter().map(KeyEntry::public).collect());
        let mut out = json::canonical(&json::object([
            ("keys", keys),
            ("schema", json::text(PROXY_SCHEMA)),
        ]))
        .expect("canonical key file");
        out.push(b'\n');
        out
    }
}

/// The broker's keys: signing seeds, sealing keys, the active `kid` and the
/// login-state key (never given to proxies).
pub struct BrokerKeys {
    pub active: String,
    pub entries: Vec<KeyEntry>,
    state: Zeroizing<[u8; 32]>,
}

impl BrokerKeys {
    /// A fresh key set with one entry.
    pub fn generate(issuer: &str, kid: &str) -> Result<Self> {
        let mut keys = Self {
            active: String::new(),
            entries: Vec::new(),
            state: Zeroizing::new(random::<32>()?),
        };
        keys.rotate(issuer, kid)?;
        Ok(keys)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value =
            json::parse(bytes, 65536, 8).map_err(|_| config("key file is not strict JSON"))?;
        exact_keys(
            &value,
            &["active", "keys", "schema", "state"],
            "broker key file",
        )?;
        if value.get("schema").and_then(Value::as_str) != Some(BROKER_SCHEMA) {
            return Err(config("unsupported broker key schema"));
        }
        let entries = entries_of(value.get("keys"), true)?;
        let active = value
            .get("active")
            .and_then(Value::as_str)
            .ok_or_else(|| config("active missing"))?;
        if !entries.iter().any(|e| e.kid == active) {
            return Err(config("active kid is not in the key set"));
        }
        Ok(Self {
            active: active.to_owned(),
            entries,
            state: key32(value.get("state"), "state")?,
        })
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        Self::parse(&crate::files::read_private(path, 65536)?)
    }
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        let keys = Value::Array(
            self.entries
                .iter()
                .map(|e| {
                    json::object([
                        ("issuer", json::text(&e.issuer)),
                        ("kid", json::text(&e.kid)),
                        ("seal", json::text(&b64url(&e.seal[..]))),
                        (
                            "sign",
                            json::text(&b64url(&e.sign.as_ref().expect("broker entry")[..])),
                        ),
                    ])
                })
                .collect(),
        );
        let mut out = json::canonical(&json::object([
            ("active", json::text(&self.active)),
            ("keys", keys),
            ("schema", json::text(BROKER_SCHEMA)),
            ("state", json::text(&b64url(&self.state[..]))),
        ]))
        .expect("canonical key file");
        out.push(b'\n');
        Zeroizing::new(out)
    }
    /// Add a fresh entry and make it active. Deploy the exported proxy keys
    /// before the broker signs with it.
    pub fn rotate(&mut self, issuer: &str, kid: &str) -> Result<()> {
        if !is_kid(kid) || !is_text(issuer) {
            return Err(config("invalid kid or issuer"));
        }
        if self.entries.iter().any(|e| e.kid == kid) {
            return Err(config("kid already exists"));
        }
        if self.entries.len() >= MAX_KEYS {
            return Err(config("key set is full; retire a key first"));
        }
        let seed = Zeroizing::new(random::<32>()?);
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed[..])
            .map_err(|_| Error::Io("keygen".into()))?;
        let verify: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::Io("keygen".into()))?;
        self.entries.push(KeyEntry {
            kid: kid.to_owned(),
            issuer: issuer.to_owned(),
            verify,
            seal: Zeroizing::new(random::<32>()?),
            sign: Some(seed),
        });
        self.active = kid.to_owned();
        Ok(())
    }
    /// Remove an inactive entry: every surrogate it signed stops opening
    /// once proxies have the exported key set.
    pub fn retire(&mut self, kid: &str) -> Result<()> {
        if kid == self.active {
            return Err(config("cannot retire the active kid"));
        }
        let before = self.entries.len();
        self.entries.retain(|e| e.kid != kid);
        if self.entries.len() == before {
            return Err(config("unknown kid"));
        }
        Ok(())
    }
    pub fn export_proxy(&self) -> ProxyKeys {
        ProxyKeys {
            entries: self
                .entries
                .iter()
                .map(|e| KeyEntry {
                    kid: e.kid.clone(),
                    issuer: e.issuer.clone(),
                    verify: e.verify,
                    seal: e.seal.clone(),
                    sign: None,
                })
                .collect(),
        }
    }
    pub fn active_entry(&self) -> &KeyEntry {
        self.entries
            .iter()
            .find(|e| e.kid == self.active)
            .expect("validated active kid")
    }
    /// The login-state key (broker only; exposed for conformance tests).
    #[doc(hidden)]
    pub fn state_key(&self) -> &[u8; 32] {
        &self.state
    }
    /// Every entry, for opening surrogates at renewal.
    pub fn verification(&self) -> &[KeyEntry] {
        &self.entries
    }
    pub fn key_set(&self) -> Result<KeySet<RingKey>> {
        key_set(&self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rotate_retire_export() {
        let mut keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
        let again = BrokerKeys::parse(&keys.to_json()).unwrap();
        assert_eq!(again.active, "k1");
        keys.rotate("https://broker.test", "k2").unwrap();
        assert!(keys.retire("k2").is_err());
        let proxy = keys.export_proxy();
        let parsed = ProxyKeys::parse(&proxy.to_json()).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].verify, keys.entries[0].verify);
        keys.retire("k1").unwrap();
        assert_eq!(keys.entries.len(), 1);
        assert!(!String::from_utf8(proxy.to_json()).unwrap().contains("sign"));
    }
}

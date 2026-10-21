//! Bounded, duplicate-rejecting JSON and the reference profile's ASCII encoding.
use crate::{Error, Outcome};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{value::RawValue, Value};
use std::collections::BTreeMap;
use std::fmt;

struct Distinct(BTreeMap<String, Box<RawValue>>);
impl<'de> Deserialize<'de> for Distinct {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Distinct;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("distinct object keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Distinct, M::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if out.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Distinct(out))
            }
        }
        d.deserialize_map(Fields)
    }
}
// Build objects explicitly. Value's generic deserializer recognizes Serde's
// private Number/RawValue marker keys; guest/provider JSON must preserve them.
fn decode(raw: &RawValue, depth: usize) -> Outcome<Value> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => {
            if depth >= 64 {
                return Err(Error::InvalidCapability);
            }
            let fields: Distinct =
                serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?;
            Ok(Value::Object(
                fields
                    .0
                    .into_iter()
                    .map(|(key, value)| Ok((key, decode(&value, depth + 1)?)))
                    .collect::<Outcome<_>>()?,
            ))
        }
        b'[' => {
            if depth >= 64 {
                return Err(Error::InvalidCapability);
            }
            let values: Vec<Box<RawValue>> =
                serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?;
            Ok(Value::Array(
                values
                    .iter()
                    .map(|value| decode(value, depth + 1))
                    .collect::<Outcome<_>>()?,
            ))
        }
        b'"' => Ok(Value::String(
            serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?,
        )),
        b'-' | b'0'..=b'9' => {
            if text.contains(['.', 'e', 'E']) {
                let number: f64 = text.parse().map_err(|_| Error::InvalidCapability)?;
                if !number.is_finite() {
                    return Err(Error::InvalidCapability);
                }
            } else if text.trim_start_matches('-').len() > 4300 {
                return Err(Error::InvalidCapability);
            }
            Ok(Value::Number(
                serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?,
            ))
        }
        b't' => Ok(Value::Bool(true)),
        b'f' => Ok(Value::Bool(false)),
        b'n' => Ok(Value::Null),
        _ => Err(Error::InvalidCapability),
    }
}
pub fn parse(bytes: &[u8], limit: usize) -> Outcome<Value> {
    if bytes.len() > limit {
        return Err(Error::InvalidCapability);
    }
    let raw: Box<RawValue> = serde_json::from_slice(bytes).map_err(|_| Error::InvalidCapability)?;
    decode(&raw, 0)
}
fn string(out: &mut String, value: &str) {
    let values = zeroize::Zeroizing::new(value.chars().map(u32::from).collect::<Vec<_>>());
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    assert!(
        aivm_secrets_garrett_core::json_string::append(&mut encoded, &values),
        "Rust string scalars"
    );
    out.push_str(std::str::from_utf8(&encoded).expect("ASCII JSON string"));
}

fn encode(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(out, v);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(out, k);
                out.push(':');
                encode(out, v);
            }
            out.push('}');
        }
    }
}
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    encode(&mut out, value);
    out.into_bytes()
}

pub fn keys<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Outcome<&'a serde_json::Map<String, Value>> {
    let m = value.as_object().ok_or(Error::InvalidCapability)?;
    if !required.iter().all(|k| m.contains_key(*k))
        || m.keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(Error::InvalidCapability);
    }
    Ok(m)
}
pub fn integer(value: &Value, low: i64, high: i64) -> Outcome<i64> {
    let n = value.as_i64().ok_or(Error::InvalidCapability)?;
    if n < low || n > high {
        return Err(Error::InvalidCapability);
    }
    Ok(n)
}
pub fn word(value: &Value, limit: usize) -> Outcome<String> {
    let s = value.as_str().ok_or(Error::InvalidCapability)?;
    if s.is_empty()
        || s.len() > limit
        || !s.as_bytes()[0].is_ascii_alphanumeric()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":./_-".contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    Ok(s.to_owned())
}
pub fn hex(value: &Value, length: usize) -> Outcome<String> {
    let s = value.as_str().ok_or(Error::InvalidCapability)?;
    if s.len() != length
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    Ok(s.to_owned())
}
pub fn thumbprint(value: &Value) -> Outcome<String> {
    let s = value.as_str().ok_or(Error::InvalidCapability)?;
    if s.len() != 43
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || !b"AEIMQUYcgkosw048".contains(&s.as_bytes()[42])
    {
        return Err(Error::InvalidCapability);
    }
    Ok(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn input_objects_cannot_impersonate_serde_number_tokens() {
        for content in ["1", "not a number"] {
            let value = json!({"$serde_json::private::Number":content});
            let raw = serde_json::to_vec(&value).unwrap();
            assert_eq!(parse(&raw, 65536).unwrap(), value);
        }
    }

    #[test]
    fn raw_value_markers_preserve_objects_and_uninterpreted_text() {
        for content in ["[1,2]", "{\"duplicate\":1,\"duplicate\":2}", "not JSON"] {
            let value = json!({"nested":[{"$serde_json::private::RawValue":content}]});
            let raw = serde_json::to_vec(&value).unwrap();
            assert_eq!(parse(&raw, 65536).unwrap(), value);
        }
    }
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    #[test]
    fn native_canonical_preserves_exact_nested_unicode_and_control_bytes() {
        let value = serde_json::json!({"text":"\u{0}\n\"\\é😀", "array":["~\u{7f}",7,true,null], "é":"\u{2028}"});
        let bytes = canonical(&value);
        assert_eq!(bytes, br#"{"array":["~\u007f",7,true,null],"text":"\u0000\n\"\\\u00e9\ud83d\ude00","\u00e9":"\u2028"}"#);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
    }
}

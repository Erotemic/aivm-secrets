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
// Capture ordering and number spelling once. Layout and string quoting are
// owned by the extracted encoder used by both canonical bytes and guest frames.
pub(crate) struct Captured(aivm_secrets_garrett_core::json_wire::Value);
impl Drop for Captured {
    fn drop(&mut self) {
        use aivm_secrets_garrett_core::json_wire::Value as Wire;
        use zeroize::Zeroize;
        fn clear(value: &mut Wire) {
            match value {
                Wire::Number(bytes) => bytes.zeroize(),
                Wire::Text(scalars) => scalars.zeroize(),
                Wire::Array(values) => values.iter_mut().for_each(clear),
                Wire::Object(fields) => {
                    for (name, value) in fields {
                        name.zeroize();
                        clear(value);
                    }
                }
                Wire::Null | Wire::Boolean(_) => (),
            }
        }
        clear(&mut self.0);
    }
}
impl Captured {
    /// Wrap an already-extracted public wire value (zeroized on drop).
    pub(crate) fn released(value: aivm_secrets_garrett_core::json_wire::Value) -> Self {
        Self(value)
    }
}
/// A guest reply: either the extracted wire value released by the core read
/// pipeline or control verbs, or a native serde reply (approval/forward).
pub(crate) enum Reply {
    Released(Captured),
    Native(Value),
}
impl Reply {
    /// The wire value a reply is framed from: the released extracted value,
    /// or the captured native reply.
    pub(crate) fn captured(self) -> Captured {
        match self {
            Reply::Released(captured) => captured,
            Reply::Native(value) => capture(&value),
        }
    }
}
pub(crate) fn capture(value: &Value) -> Captured {
    use aivm_secrets_garrett_core::json_wire::Value as Wire;
    fn convert(value: &Value) -> Wire {
        match value {
            Value::Null => Wire::Null,
            Value::Bool(value) => Wire::Boolean(*value),
            Value::Number(value) => Wire::Number(if let Some(integer) = value.as_i64() {
                integer.to_string().into_bytes()
            } else {
                value.to_string().into_bytes()
            }),
            Value::String(value) => Wire::Text(value.chars().map(u32::from).collect()),
            Value::Array(values) => Wire::Array(values.iter().map(convert).collect()),
            Value::Object(fields) => Wire::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.chars().map(u32::from).collect(), convert(value)))
                    .collect(),
            ),
        }
    }
    Captured(convert(value))
}
impl Captured {
    pub(crate) fn wire(&self) -> &aivm_secrets_garrett_core::json_wire::Value {
        &self.0
    }
}
pub fn canonical(value: &Value) -> Vec<u8> {
    aivm_secrets_garrett_core::json_wire::encode(&capture(value).0)
        .ok()
        .expect("Rust JSON scalars")
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
    fn previous(value: &Value) -> Vec<u8> {
        use std::fmt::Write;
        fn string(out: &mut String, value: &str) {
            out.push('"');
            for c in value.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    ' '..='~' => out.push(c),
                    _ => {
                        for unit in c.encode_utf16(&mut [0; 2]) {
                            write!(out, "\\u{unit:04x}").unwrap();
                        }
                    }
                }
            }
            out.push('"');
        }
        fn emit(out: &mut String, value: &Value) {
            match value {
                Value::Null => out.push_str("null"),
                Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
                Value::Number(value) => {
                    if let Some(integer) = value.as_i64() {
                        write!(out, "{integer}").unwrap();
                    } else {
                        write!(out, "{value}").unwrap();
                    }
                }
                Value::String(value) => string(out, value),
                Value::Array(values) => {
                    out.push('[');
                    for (index, value) in values.iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        emit(out, value);
                    }
                    out.push(']');
                }
                Value::Object(fields) => {
                    out.push('{');
                    for (index, (name, value)) in fields.iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        string(out, name);
                        out.push(':');
                        emit(out, value);
                    }
                    out.push('}');
                }
            }
        }
        let mut out = String::new();
        emit(&mut out, value);
        out.into_bytes()
    }
    #[test]
    fn complete_core_encoder_preserves_native_number_and_container_spelling() {
        for text in [
            "null",
            "true",
            "false",
            "[]",
            "{}",
            "-0",
            "-9223372036854775808",
            "18446744073709551616",
            "1.2300",
            "1e+04",
            "-0.0",
            "1e-300",
            "[{},[],[1,true,null]]",
            r#"{"$serde_json::private::Number":"kept","é":"😀"}"#,
        ] {
            let value = parse(text.as_bytes(), 65536).unwrap();
            assert_eq!(canonical(&value), previous(&value), "{text}");
        }
        let huge = Value::Number(serde_json::from_str(&"9".repeat(4300)).unwrap());
        let mut value = serde_json::json!({"number":huge,"text":"\u{0}\n\r\t\u{7f}é😀","flags":[true,false,null]});
        for _ in 0..32 {
            assert_eq!(canonical(&value), previous(&value));
            value = serde_json::json!({"nested":[value,{},[]],"empty":""});
        }
    }
    #[test]
    fn native_canonical_preserves_exact_nested_unicode_and_control_bytes() {
        let value = serde_json::json!({"text":"\u{0}\n\"\\é😀", "array":["~\u{7f}",7,true,null], "é":"\u{2028}"});
        let bytes = canonical(&value);
        assert_eq!(bytes, br#"{"array":["~\u007f",7,true,null],"text":"\u0000\n\"\\\u00e9\ud83d\ude00","\u00e9":"\u2028"}"#);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
    }
}

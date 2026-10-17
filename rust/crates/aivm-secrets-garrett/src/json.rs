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
fn validate(raw: &RawValue, depth: usize) -> Outcome<()> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => {
            if depth >= 64 {
                return Err(Error::InvalidCapability);
            }
            let fields: Distinct =
                serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?;
            for value in fields.0.values() {
                validate(value, depth + 1)?;
            }
        }
        b'[' => {
            if depth >= 64 {
                return Err(Error::InvalidCapability);
            }
            let values: Vec<Box<RawValue>> =
                serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?;
            for value in &values {
                validate(value, depth + 1)?;
            }
        }
        b'"' => {
            let _: String = serde_json::from_str(text).map_err(|_| Error::InvalidCapability)?;
        }
        b'-' | b'0'..=b'9' => {
            if text.contains(['.', 'e', 'E']) {
                let number: f64 = text.parse().map_err(|_| Error::InvalidCapability)?;
                if !number.is_finite() {
                    return Err(Error::InvalidCapability);
                }
            } else if text.trim_start_matches('-').len() > 4300 {
                return Err(Error::InvalidCapability);
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn parse(bytes: &[u8], limit: usize) -> Outcome<Value> {
    if bytes.len() > limit {
        return Err(Error::InvalidCapability);
    }
    let raw: Box<RawValue> = serde_json::from_slice(bytes).map_err(|_| Error::InvalidCapability)?;
    validate(&raw, 0)?;
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidCapability)
}
fn string(out: &mut String, value: &str) {
    use std::fmt::Write;
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
                    write!(out, "\\u{unit:04x}").expect("String write");
                }
            }
        }
    }
    out.push('"');
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

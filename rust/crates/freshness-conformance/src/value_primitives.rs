//! Independently implemented value adapters; no Python execution or fallback.
use super::{has_keys, integer, refusal, Object};
use serde_json::{json, value::RawValue, Value};
use std::fmt::Write;

fn quoted(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
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

// Inspect raw number spellings before conversion: an exponent is a float,
// even when it denotes an integer. Digest numbers must fit a signed word.
fn canonical(raw: &RawValue, out: &mut String) -> Result<(), ()> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => {
            let fields: Object = serde_json::from_str(text).map_err(|_| ())?;
            out.push('{');
            for (index, (key, value)) in fields.0.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                quoted(out, key);
                out.push(':');
                canonical(value, out)?;
            }
            out.push('}');
        }
        b'[' => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                canonical(value, out)?;
            }
            out.push(']');
        }
        b'"' => quoted(out, &serde_json::from_str::<String>(text).map_err(|_| ())?),
        b'-' | b'0'..=b'9' => {
            out.push_str(&integer(raw).map_err(|_| ())?.to_string());
        }
        _ => out.push_str(text),
    }
    Ok(())
}

// Construct objects ourselves: Value's generic deserializer interprets Serde's
// private Number/RawValue keys as tagged values, even in ordinary input JSON.
fn value(raw: &RawValue) -> Result<Value, ()> {
    let text = raw.get();
    Ok(match text.as_bytes()[0] {
        b'{' => {
            let fields: Object = serde_json::from_str(text).map_err(|_| ())?;
            Value::Object(
                fields
                    .0
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), value(v)?)))
                    .collect::<Result<_, ()>>()?,
            )
        }
        b'[' => {
            let children: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            Value::Array(
                children
                    .iter()
                    .map(|v| value(v))
                    .collect::<Result<_, _>>()?,
            )
        }
        b'"' => Value::String(serde_json::from_str(text).map_err(|_| ())?),
        b'-' | b'0'..=b'9' => Value::Number(serde_json::from_str(text).map_err(|_| ())?),
        b't' => Value::Bool(true),
        b'f' => Value::Bool(false),
        b'n' => Value::Null,
        _ => return Err(()),
    })
}

pub(super) fn evaluate(name: &str, args: &Object) -> Result<Value, ()> {
    let value = match name {
        "binding.require_match" => {
            let actual = serde_json::from_str::<String>(args.0["actual"].get());
            let expected = serde_json::from_str::<String>(args.0["expected"].get());
            match (actual, expected) {
                (Ok(a), Ok(b)) if a == b => Value::Null,
                _ => return Ok(refusal("invalid_capability")),
            }
        }
        "codec.digest" => {
            let mut encoded = String::new();
            canonical(&args.0["value"], &mut encoded)?;
            let hash = ring::digest::digest(&ring::digest::SHA256, encoded.as_bytes());
            Value::String(hash.as_ref().iter().map(|b| format!("{b:02x}")).collect())
        }
        "wire.parse_frame" => {
            let frame: Object = serde_json::from_str(args.0["frame"].get()).map_err(|_| ())?;
            let verbs: Vec<_> = ["request", "describe", "delegate", "renounce"]
                .into_iter()
                .filter(|verb| frame.0.contains_key(*verb))
                .collect();
            if verbs.len() != 1 || !has_keys(&frame, &["version", "capability", verbs[0]], &[]) {
                return Err(());
            }
            if integer(&frame.0["version"]).map_err(|_| ())? != 1 {
                return Err(());
            }
            let capability: String =
                serde_json::from_str(frame.0["capability"].get()).map_err(|_| ())?;
            let verb = verbs[0];
            let payload = &frame.0[verb];
            if capability.len() > 32768
                || (matches!(verb, "describe" | "renounce") && payload.get() != "true")
            {
                return Err(());
            }
            json!({"verb":verb,"capability":capability,
                   "payload":value(payload)?})
        }
        _ => return Err(()),
    };
    Ok(json!({"ok":true,"value":value}))
}

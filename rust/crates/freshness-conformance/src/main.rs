//! Scoped JSONL adapter for the verified freshness leaves, never a broker.
use aivm_secrets_primitives::{advance, require_active, require_current, require_fresh, Denial};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, value::RawValue, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, Read, Write};

const MAX_LINE: usize = 65536;
const MAX_DEPTH: usize = 64;
// Match the default Python 3.11+ JSON integer conversion policy before dispatch.
const MAX_INTEGER_DIGITS: usize = 4300;

/// Preserve raw number spellings and reject duplicate keys before typed decoding.
struct Object(BTreeMap<String, Box<RawValue>>);

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Object;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object with distinct keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut fields: M) -> Result<Object, M::Error> {
                let mut result = BTreeMap::new();
                while let Some((key, value)) = fields.next_entry::<String, Box<RawValue>>()? {
                    if result.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Object(result))
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

// Validate the whole document before dispatch, including unused/wrong-type
// values. RawValue avoids converting arbitrary integers to floating point.
fn validate(raw: &RawValue, depth: usize) -> Result<(), ()> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => {
            if depth >= MAX_DEPTH {
                return Err(());
            }
            let object: Object = serde_json::from_str(text).map_err(|_| ())?;
            for child in object.0.values() {
                validate(child, depth + 1)?;
            }
        }
        b'[' => {
            if depth >= MAX_DEPTH {
                return Err(());
            }
            let values: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            for child in &values {
                validate(child, depth + 1)?;
            }
        }
        b'"' => {
            serde_json::from_str::<String>(text).map_err(|_| ())?;
        }
        b'-' | b'0'..=b'9' => {
            if text.contains(['.', 'e', 'E']) {
                let number: f64 = text.parse().map_err(|_| ())?;
                if !number.is_finite() {
                    return Err(());
                }
            } else if text.trim_start_matches('-').len() > MAX_INTEGER_DIGITS {
                return Err(());
            }
        }
        _ => {}
    }
    Ok(())
}

fn has_keys(object: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.0.contains_key(*key))
        && object
            .0
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn integer(raw: &RawValue) -> Result<i64, Denial> {
    let text = raw.get();
    if text.contains(['.', 'e', 'E']) {
        return Err(Denial::InvalidCapability);
    }
    text.parse().map_err(|_| Denial::InvalidCapability)
}

fn refusal(code: &str) -> Value {
    json!({"ok": false, "code": code})
}

fn result(answer: Result<Option<i64>, Denial>) -> Value {
    match answer {
        Ok(value) => json!({"ok": true, "value": value}),
        Err(Denial::InvalidCapability) => refusal("invalid_capability"),
        Err(Denial::Revoked) => refusal("revoked"),
    }
}

fn evaluate(line: &[u8]) -> Result<Value, ()> {
    let raw: Box<RawValue> = serde_json::from_slice(line).map_err(|_| ())?;
    validate(&raw, 0)?;
    let envelope: Object = serde_json::from_str(raw.get()).map_err(|_| ())?;
    if !has_keys(&envelope, &["version", "primitive", "args"], &[]) {
        return Err(());
    }
    if integer(&envelope.0["version"]).map_err(|_| ())? != 1 {
        return Err(());
    }
    let primitive: String = serde_json::from_str(envelope.0["primitive"].get()).map_err(|_| ())?;
    let args: Object = serde_json::from_str(envelope.0["args"].get()).map_err(|_| ())?;
    let (required, optional): (&[&str], &[&str]) = match primitive.as_str() {
        "epochs.advance" => (&["current"], &["maximum"]),
        "epochs.require_current" => (&["actual", "expected"], &[]),
        "validity.require_active" => (&["now", "not_before", "expires_at"], &[]),
        "freshness.require_fresh" => (
            &["actual", "expected", "now", "not_before", "expires_at"],
            &[],
        ),
        _ => return Err(()),
    };
    if !has_keys(&args, required, optional) {
        return Err(());
    }
    let get = |name: &str| integer(&args.0[name]);
    let answer = (|| match primitive.as_str() {
        "epochs.advance" => {
            let maximum = match args.0.get("maximum") {
                Some(raw) => integer(raw)?,
                None => i32::MAX as i64,
            };
            advance(get("current")?, maximum).map(Some)
        }
        "epochs.require_current" => require_current(get("actual")?, get("expected")?).map(|_| None),
        "validity.require_active" => {
            require_active(get("now")?, get("not_before")?, get("expires_at")?).map(|_| None)
        }
        "freshness.require_fresh" => require_fresh(
            get("actual")?,
            get("expected")?,
            get("now")?,
            get("not_before")?,
            get("expires_at")?,
        )
        .map(|_| None),
        _ => unreachable!(),
    })();
    Ok(result(answer))
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        if (&mut input)
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line)?
            == 0
        {
            return Ok(());
        }
        let reply = if line.len() > MAX_LINE {
            // Discard bounded chunks until the oversized line ends, then resume.
            while !line.ends_with(b"\n") {
                line.clear();
                if (&mut input)
                    .take((MAX_LINE + 1) as u64)
                    .read_until(b'\n', &mut line)?
                    == 0
                {
                    break;
                }
            }
            refusal("invalid_request")
        } else {
            evaluate(&line).unwrap_or_else(|_| refusal("invalid_request"))
        };
        serde_json::to_writer(&mut output, &reply)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

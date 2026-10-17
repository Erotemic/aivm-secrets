//! Typed response selection runs in the extracted core. The JSON adapter only
//! converts input nodes and renders the owned selected tree; it has no raw
//! provider-document fallback.
use super::*;
use aivm_secrets_garrett_core::disclosure as filter;

pub struct Disclosure {
    rules: BTreeMap<String, Vec<filter::Field>>,
}
struct Projection;
impl Projection {
    fn parse(v: &Value, depth: usize) -> Outcome<filter::Projection> {
        if depth > 8 {
            return bad();
        }
        let m = keys(v, &["at", "type"], &["fields", "items", "max_items"])?;
        let kind = match m["type"].as_str() {
            Some("integer") => filter::Kind::Integer,
            Some("boolean") => filter::Kind::Boolean,
            Some("text") => filter::Kind::Text,
            Some("null") => filter::Kind::Null,
            Some("object") => {
                if m.len() != 3 {
                    return bad();
                }
                filter::Kind::Object(Self::fields(
                    m.get("fields").ok_or(Error::InvalidPolicy)?,
                    depth + 1,
                )?)
            }
            Some("array") => {
                if m.len() != 4 {
                    return bad();
                }
                filter::Kind::Array(
                    Box::new(Self::parse(
                        m.get("items").ok_or(Error::InvalidPolicy)?,
                        depth + 1,
                    )?),
                    integer(m.get("max_items").ok_or(Error::InvalidPolicy)?, 1, 1000)? as usize,
                )
            }
            _ => return bad(),
        };
        if !matches!(kind, filter::Kind::Object(_) | filter::Kind::Array(..)) && m.len() != 2 {
            return bad();
        }
        Ok(filter::Projection {
            at: pointer(&m["at"])?
                .into_iter()
                .map(String::into_bytes)
                .collect(),
            kind,
        })
    }
    fn fields(v: &Value, depth: usize) -> Outcome<Vec<filter::Field>> {
        let m = v.as_object().ok_or(Error::InvalidPolicy)?;
        if m.is_empty() || m.len() > 32 {
            return bad();
        }
        m.iter()
            .map(|(n, v)| {
                name(n, false)?;
                Ok(filter::Field {
                    name: n.as_bytes().to_vec(),
                    projection: Self::parse(v, depth)?,
                })
            })
            .collect()
    }
}
fn document(v: &Value) -> filter::Json {
    match v {
        Value::Null => filter::Json::Null,
        Value::Bool(b) => filter::Json::Boolean(*b),
        Value::Number(n) => n
            .as_i64()
            .map(filter::Json::Integer)
            .unwrap_or(filter::Json::Opaque),
        Value::String(s) => filter::Json::Text(s.as_bytes().to_vec()),
        Value::Array(values) => filter::Json::Array(values.iter().map(document).collect()),
        Value::Object(values) => filter::Json::Object(
            values
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), document(v)))
                .collect(),
        ),
    }
}
fn render(v: filter::Json) -> Outcome<Value> {
    Ok(match v {
        filter::Json::Null => Value::Null,
        filter::Json::Boolean(b) => json!(b),
        filter::Json::Integer(n) => json!(n),
        filter::Json::Text(s) => json!(String::from_utf8(s).map_err(|_| Error::UpstreamResponse)?),
        filter::Json::Array(values) => {
            Value::Array(values.into_iter().map(render).collect::<Outcome<_>>()?)
        }
        filter::Json::Object(values) => {
            let mut out = Map::new();
            for (name, value) in values {
                let name = String::from_utf8(name).map_err(|_| Error::UpstreamResponse)?;
                if out.insert(name, render(value)?).is_some() {
                    return Err(Error::UpstreamResponse);
                }
            }
            Value::Object(out)
        }
        filter::Json::Opaque => return Err(Error::UpstreamResponse),
    })
}
impl Disclosure {
    pub fn parse(value: &Value, operations: &[String]) -> Outcome<Self> {
        let m = value.as_object().ok_or(Error::InvalidPolicy)?;
        if m.keys().cloned().collect::<BTreeSet<_>>() != operations.iter().cloned().collect() {
            return bad();
        }
        Ok(Self {
            rules: m
                .iter()
                .map(|(op, v)| Ok((op.clone(), Projection::fields(v, 0)?)))
                .collect::<Outcome<_>>()?,
        })
    }
    pub fn project(&self, operation: &str, response: &Value, credential: &[u8]) -> Outcome<Value> {
        let tree = document(response);
        let selected = filter::project_fields(
            &tree,
            self.rules.get(operation).ok_or(Error::Denied)?,
            9,
            2 * 1024 * 1024 - 4096,
        )
        .map_err(|_| Error::UpstreamResponse)?;
        let value = render(selected.value)?;
        ensure_safe(&value, credential)?;
        let released = core::release(core::ProviderReply {
            selected: json::canonical(&value),
            discarded: json::canonical(response),
        });
        json::parse(&released, 2 * 1024 * 1024).map_err(|_| Error::UpstreamResponse)
    }
}
fn contains(value: &[u8], secret: &[u8]) -> bool {
    !secret.is_empty() && value.windows(secret.len()).any(|part| part == secret)
}
fn reject_reflection(v: &Value, secret: &[u8]) -> Outcome<()> {
    let bad = match v {
        Value::String(s) => contains(s.as_bytes(), secret),
        Value::Array(values) => {
            for v in values {
                reject_reflection(v, secret)?;
            }
            false
        }
        Value::Object(values) => {
            for (n, v) in values {
                if contains(n.as_bytes(), secret) {
                    return Err(Error::UpstreamResponse);
                }
                reject_reflection(v, secret)?;
            }
            false
        }
        _ => false,
    };
    if bad {
        Err(Error::UpstreamResponse)
    } else {
        Ok(())
    }
}
pub(crate) fn ensure_safe(v: &Value, secret: &[u8]) -> Outcome<()> {
    reject_reflection(v, secret)?;
    if contains(&json::canonical(v), secret) {
        return Err(Error::UpstreamResponse);
    }
    Ok(())
}

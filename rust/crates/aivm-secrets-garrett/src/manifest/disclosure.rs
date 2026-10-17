//! Host-side typed projection, separate from untrusted client formatting. Object
//! schemas discard unknown fields; arrays project each element through a schema.
use super::*;
pub struct Disclosure {
    rules: BTreeMap<String, BTreeMap<String, Projection>>,
}
struct Projection {
    at: Vec<String>,
    kind: Kind,
}
enum Kind {
    Integer,
    Boolean,
    Text,
    Null,
    Object(BTreeMap<String, Projection>),
    Array(Box<Projection>, usize),
}
impl Projection {
    fn parse(v: &Value, depth: usize) -> Outcome<Self> {
        if depth > 8 {
            return bad();
        }
        let m = keys(v, &["at", "type"], &["fields", "items", "max_items"])?;
        let kind = match m["type"].as_str() {
            Some("integer") => Kind::Integer,
            Some("boolean") => Kind::Boolean,
            Some("text") => Kind::Text,
            Some("null") => Kind::Null,
            Some("object") => {
                if m.len() != 3 {
                    return bad();
                }
                Kind::Object(Self::fields(
                    m.get("fields").ok_or(Error::InvalidPolicy)?,
                    depth + 1,
                )?)
            }
            Some("array") => {
                if m.len() != 4 {
                    return bad();
                }
                Kind::Array(
                    Box::new(Self::parse(
                        m.get("items").ok_or(Error::InvalidPolicy)?,
                        depth + 1,
                    )?),
                    integer(m.get("max_items").ok_or(Error::InvalidPolicy)?, 1, 1000)? as usize,
                )
            }
            _ => return bad(),
        };
        if !matches!(kind, Kind::Object(_) | Kind::Array(..)) && m.len() != 2 {
            return bad();
        }
        Ok(Self {
            at: pointer(&m["at"])?,
            kind,
        })
    }
    fn fields(v: &Value, depth: usize) -> Outcome<BTreeMap<String, Self>> {
        let m = v.as_object().ok_or(Error::InvalidPolicy)?;
        if m.is_empty() || m.len() > 32 {
            return bad();
        }
        m.iter()
            .map(|(n, v)| {
                name(n, false)?;
                Ok((n.clone(), Self::parse(v, depth)?))
            })
            .collect()
    }
    fn apply(&self, response: &Value, budget: &mut usize) -> Outcome<Value> {
        let value = lookup(response, &self.at, Error::UpstreamResponse)?;
        match &self.kind {
            Kind::Integer if value.as_i64().is_some() => leaf(value, budget),
            Kind::Boolean if value.is_boolean() => leaf(value, budget),
            Kind::Text
                if value
                    .as_str()
                    .is_some_and(|s| s.len() <= MAX_TEXT && !s.contains('\0')) =>
            {
                leaf(value, budget)
            }
            Kind::Null if value.is_null() => leaf(value, budget),
            Kind::Object(fields) if value.is_object() => Self::apply_fields(fields, value, budget),
            Kind::Array(item, maximum) => {
                let values = value.as_array().ok_or(Error::UpstreamResponse)?;
                if values.len() > *maximum {
                    return Err(Error::UpstreamResponse);
                }
                charge(budget, 2 + values.len())?;
                Ok(Value::Array(
                    values
                        .iter()
                        .map(|v| item.apply(v, budget))
                        .collect::<Outcome<Vec<_>>>()?,
                ))
            }
            _ => Err(Error::UpstreamResponse),
        }
    }
    fn apply_fields(
        fields: &BTreeMap<String, Self>,
        response: &Value,
        budget: &mut usize,
    ) -> Outcome<Value> {
        // A small provider document can expand through repeated projections.
        // Charge each selected copy before constructing it, reserving space
        // for the final reply envelope and pagination metadata.
        charge(
            budget,
            2 + fields.keys().map(|n| n.len() + 4).sum::<usize>(),
        )?;
        Ok(Value::Object(
            fields
                .iter()
                .map(|(n, p)| Ok((n.clone(), p.apply(response, budget)?)))
                .collect::<Outcome<Map<_, _>>>()?,
        ))
    }
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
        let value = Projection::apply_fields(
            self.rules.get(operation).ok_or(Error::Denied)?,
            response,
            &mut (2 * 1024 * 1024 - 4096),
        )?;
        ensure_safe(&value, credential)?;
        let released = core::release(core::ProviderReply {
            selected: json::canonical(&value),
            discarded: json::canonical(response),
        });
        json::parse(&released, 2 * 1024 * 1024).map_err(|_| Error::UpstreamResponse)
    }
}
fn charge(budget: &mut usize, size: usize) -> Outcome<()> {
    *budget = budget.checked_sub(size).ok_or(Error::UpstreamResponse)?;
    Ok(())
}
fn leaf(value: &Value, budget: &mut usize) -> Outcome<Value> {
    charge(budget, json::canonical(value).len())?;
    Ok(value.clone())
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

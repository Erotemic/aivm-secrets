//! Typed response selection runs in the extracted core. The JSON adapter only
//! converts input nodes and renders the owned selected tree; it has no raw
//! provider-document fallback.
use super::*;
use aivm_secrets_garrett_core::disclosure as filter;

pub struct Disclosure {
    rules: BTreeMap<String, Vec<filter::Field>>,
}

// A disclosure key names a host-selected field in the *public reply*, not
// an input parameter or operation. JSON clients (including `gh --json`)
// require camelCase keys such as `headRefOid`. Keep the identifier alphabet
// bounded without loosening the policy grammar for guest-controlled names.
fn public_field_name(value: &str) -> Outcome<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 32
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return bad();
    }
    Ok(())
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
                public_field_name(n)?;
                Ok(filter::Field {
                    name: n.as_bytes().to_vec(),
                    projection: Self::parse(v, depth)?,
                })
            })
            .collect()
    }
}
pub(crate) fn document(v: &Value) -> filter::Json {
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
    aivm_secrets_garrett_core::reflection::contains(value, secret)
}
pub(crate) fn ensure_safe(v: &Value, secret: &[u8]) -> Outcome<()> {
    // The parser permits at most 64 container levels. One extra step covers
    // the terminal scalar; exhaustion is a refusal, never an unchecked leaf.
    if !aivm_secrets_garrett_core::json_reflection::safe(&document(v), secret, 65) {
        return Err(Error::UpstreamResponse);
    }
    if contains(&json::canonical(v), secret) {
        return Err(Error::UpstreamResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_case_public_projection_preserves_exact_host_selected_names() {
        let operations = vec!["pr.view".to_owned()];
        let selected = json!({"pr.view": {
            "number": {"at": ["number"], "type": "integer"},
            "headRefOid": {"at": ["head", "sha"], "type": "text"}
        }});
        let disclosure = Disclosure::parse(&selected, &operations).unwrap();
        let response = json!({
            "number": 13861,
            "head": {"sha": "aabbcc"},
            "credential": "discarded-private-provider-field"
        });
        assert_eq!(
            disclosure
                .project("pr.view", &response, b"broker-secret")
                .unwrap(),
            json!({"number": 13861, "headRefOid": "aabbcc"})
        );
    }

    #[test]
    fn public_projection_field_names_remain_strictly_bounded() {
        let operations = vec!["pr.view".to_owned()];
        for invalid in [
            "HeadRefOid",
            "head-ref-oid",
            "head.ref.oid",
            "head ref oid",
            "head/ref/oid",
            "_private",
            "",
            "abcdefghijklmnopqrstuvwxyzabcdefg",
        ] {
            let mut fields = Map::new();
            fields.insert(
                invalid.to_owned(),
                json!({
                    "at": ["head", "sha"], "type": "text"
                }),
            );
            let config = json!({"pr.view": fields});
            assert!(
                Disclosure::parse(&config, &operations).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn reflected_credential_in_camel_case_field_is_still_rejected() {
        let operations = vec!["pr.view".to_owned()];
        let selected = json!({"pr.view": {
            "headRefOid": {"at": ["head", "sha"], "type": "text"}
        }});
        let disclosure = Disclosure::parse(&selected, &operations).unwrap();
        let response = json!({"head": {"sha": "broker-secret"}});
        assert!(matches!(
            disclosure.project("pr.view", &response, b"broker-secret"),
            Err(Error::UpstreamResponse)
        ));
    }
}

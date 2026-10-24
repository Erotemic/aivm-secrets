//! Typed response selection runs in the extracted core. The JSON adapter only
//! converts input nodes and renders the owned selected tree; it has no raw
//! provider-document fallback.
use super::*;
use aivm_secrets_garrett_core::{disclosure as filter, selected_conversion};

pub struct Disclosure {
    rules: BTreeMap<String, Vec<filter::Field>>,
}

// A disclosure key is a host-chosen output name, never a provider input path.
// Its exact byte predicate lives in the Aeneas-extracted production core.
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
                let name = n.as_bytes().to_vec();
                if !selected_conversion::public_field_name(&name) {
                    return bad();
                }
                Ok(filter::Field {
                    name,
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
// The entire selected-tree -> Unicode-scalar / number-token traversal now
// lives in production-called Aeneas-extracted Rust. The native serde adapter
// handles provider/schema inputs and parses only the already-released result.
fn render(v: &filter::Json) -> Outcome<Vec<u8>> {
    let wire = selected_conversion::render_wire(v).map_err(|_| Error::UpstreamResponse)?;
    aivm_secrets_garrett_core::json_wire::encode(&wire).map_err(|_| Error::UpstreamResponse)
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
    /// The host output schema for one operation, if configured.
    pub(crate) fn fields(&self, operation: &str) -> Option<&Vec<filter::Field>> {
        self.rules.get(operation)
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
        let selected_bytes = render(&selected.value)?;
        ensure_selected_safe(&selected.value, &selected_bytes, credential)?;
        let released = core::release(core::ProviderReply {
            selected: selected_bytes,
            discarded: json::canonical(response),
        });
        json::parse(&released, 2 * 1024 * 1024).map_err(|_| Error::UpstreamResponse)
    }
}
fn contains(value: &[u8], secret: &[u8]) -> bool {
    aivm_secrets_garrett_core::reflection::contains(value, secret)
}
// Check the *same* source-owned selected tree and its encoded bytes. This
// avoids a serde round trip (or a second encoding) before release. Reflection
// of the assembled guest reply is still checked by `ensure_safe` separately.
fn ensure_selected_safe(v: &filter::Json, wire: &[u8], secret: &[u8]) -> Outcome<()> {
    if !aivm_secrets_garrett_core::json_reflection::safe(v, secret, 65)
        || contains(wire, secret)
    {
        return Err(Error::UpstreamResponse);
    }
    Ok(())
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
    fn extracted_wire_renderer_keeps_selected_value_and_exact_native_bytes() {
        // Ordered host field schema (the native serde map supplies this order).
        let selected = filter::Json::Object(vec![
            (b"empty".to_vec(), filter::Json::Object(vec![])),
            (
                b"letter".to_vec(),
                filter::Json::Text("é😀\n".as_bytes().to_vec()),
            ),
            (
                b"numbers".to_vec(),
                filter::Json::Array(vec![
                    filter::Json::Integer(i64::MIN),
                    filter::Json::Integer(i64::MAX),
                    filter::Json::Null,
                    filter::Json::Boolean(true),
                ]),
            ),
        ]);
        let wire = render(&selected).unwrap();
        let expected = json!({
            "letter":"é😀\n",
            "numbers":[i64::MIN, i64::MAX, null, true],
            "empty":{},
        });
        assert_eq!(wire, json::canonical(&expected));
        assert_eq!(json::parse(&wire, 4096).unwrap(), expected);
    }

    #[test]
    fn selected_wire_capture_preserves_nested_public_bytes() {
        let selected = filter::Json::Object(vec![
            (
                b"a".to_vec(),
                filter::Json::Array(vec![
                    filter::Json::Object(vec![(b"n".to_vec(), filter::Json::Integer(i64::MIN))]),
                    filter::Json::Boolean(false),
                    filter::Json::Null,
                ]),
            ),
            (
                "z\n".as_bytes().to_vec(),
                filter::Json::Text("\u{0001}é😀".as_bytes().to_vec()),
            ),
        ]);
        let wire = render(&selected).unwrap();
        let expected = json!({
            "z\n": "\u{0001}é😀",
            "a": [{"n": i64::MIN}, false, null],
        });
        let expected_wire = concat!(
            r#"{"a":[{"n":-9223372036854775808},false,null],"#,
            r#""z\n":"\u0001\u00e9\ud83d\ude00"}"#
        );
        assert_eq!(wire.as_slice(), expected_wire.as_bytes());
        assert_eq!(wire, json::canonical(&expected));
        assert_eq!(json::parse(&wire, 4096).unwrap(), expected);
    }

    #[test]
    fn selected_renderer_refuses_invalid_utf8_opaque_or_duplicate_fields() {
        for selected in [
            filter::Json::Text(vec![0xc0, 0xaf]),
            filter::Json::Object(vec![(vec![0xff], filter::Json::Null)]),
            filter::Json::Array(vec![filter::Json::Opaque]),
            filter::Json::Object(vec![
                (b"same".to_vec(), filter::Json::Null),
                (b"same".to_vec(), filter::Json::Integer(1)),
            ]),
        ] {
            assert_eq!(render(&selected), Err(Error::UpstreamResponse));
        }
    }

    // The previous native release pipeline (serde pagination, projection,
    // assembly and reflection), kept only as a byte-equality oracle for the
    // extracted `selected_release::Manifest`.
    fn old_release(
        disclosure: &Disclosure,
        page: Option<(usize, Vec<String>, Option<Option<i64>>)>,
        raw: &Value,
        secret: &[u8],
    ) -> Outcome<Vec<u8>> {
        let metadata = match &page {
            None => None,
            Some((size, at, parameter)) => {
                let mut value = raw;
                for key in at {
                    value = value.as_object().and_then(|m| m.get(key)).ok_or(Error::UpstreamResponse)?;
                }
                let rows = value.as_array().ok_or(Error::UpstreamResponse)?;
                if rows.len() > *size {
                    return Err(Error::UpstreamResponse);
                }
                let mut meta = json!({"per_page":size,"possibly_more":rows.len()==*size});
                if let Some(arg) = parameter {
                    meta["page"] = json!(arg.ok_or(Error::InvalidRequest)?);
                }
                Some(json!({"pagination":meta}))
            }
        };
        let selected = disclosure.project("pr.view", raw, secret)?;
        let mut reply = json!({"version":1,"ok":true,"result":selected});
        if let Some(metadata) = metadata {
            reply["meta"] = metadata;
        }
        ensure_safe(&reply, secret)?;
        Ok(json::canonical(&reply))
    }

    struct Always;
    impl aivm_secrets_garrett_core::selected_release::Current for Always {
        type Error = Error;
        fn current(&mut self) -> Outcome<()> {
            Ok(())
        }
        fn refuse(&mut self, denial: aivm_secrets_garrett_core::selected_release::Denial) -> Error {
            aivm_secrets_garrett_core::public_error::of_release(denial)
        }
    }

    #[test]
    fn extracted_release_equals_previous_native_release() {
        use aivm_secrets_garrett_core::selected_release::{self as release, Page, PageArgument};
        let disclosure = Disclosure::parse(
            &json!({"pr.view": {
                "title": {"at": ["title"], "type": "text"},
                "ids": {"at": ["items"], "type": "array", "max_items": 4,
                        "items": {"at": ["id"], "type": "integer"}}
            }}),
            &["pr.view".to_owned()],
        ).unwrap();
        let documents = [
            json!({"title": "é", "items": [{"id": 1}, {"id": 2}], "private": "x"}),
            json!({"title": "full", "items": [{"id": 1}, {"id": 2}, {"id": 3}]}),
            json!({"title": "over", "items": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}]}),
            json!({"title": "no rows"}),
            json!({"title": "has broker-secret inside", "items": []}),
            json!({"title": 7, "items": []}),
        ];
        let pages: [Option<(usize, Vec<String>, Option<Option<i64>>)>; 5] = [
            None,
            Some((3, vec!["items".into()], None)),
            Some((3, vec!["items".into()], Some(Some(2)))),
            Some((3, vec!["items".into()], Some(None))),
            Some((3, vec!["missing".into()], Some(Some(1)))),
        ];
        let secret = b"broker-secret".to_vec();
        for raw in &documents {
            for page in &pages {
                let expected = old_release(&disclosure, page.clone(), raw, &secret);
                let input = page.as_ref().map(|(size, at, parameter)| Page {
                    at: at.iter().map(|k| k.as_bytes().to_vec()).collect(),
                    size: *size as i64,
                    argument: match parameter {
                        None => PageArgument::Unused,
                        Some(None) => PageArgument::Missing,
                        Some(Some(value)) => PageArgument::Value(*value),
                    },
                });
                let tree = document(raw);
                let mut work = release::Manifest {
                    current: Always,
                    document: &tree,
                    fields: disclosure.fields("pr.view"),
                    page: &input,
                    secret: &secret,
                };
                let actual = release::select(&mut work).map(|wire| {
                    aivm_secrets_garrett_core::json_wire::encode(&wire).ok().unwrap()
                });
                assert_eq!(actual, expected, "{raw} {page:?}");
            }
        }
    }

    #[test]
    fn selected_render_matches_native_canonical_for_nested_host_schema() {
        let disclosure = Disclosure::parse(
            &json!({"pr.view": {
                "title": {"at": ["title"], "type": "text"},
                "metadata": {"at": ["details"], "type": "object", "fields": {
                    "available": {"at": ["available"], "type": "boolean"},
                    "tags": {"at": ["tags"], "type": "array", "max_items": 6,
                             "items": {"at": [], "type": "text"}}
                }},
                "count": {"at": ["count"], "type": "integer"}
            }}),
            &["pr.view".to_owned()],
        ).unwrap();
        let raw = json!({
            "title": "\né😀\\\"",
            "details": {"available": true, "tags": ["two", "ñ", "\u{7f}"]},
            "count": i64::MIN,
            "discarded_secret": "not selected",
        });
        let fields = disclosure.rules.get("pr.view").unwrap();
        let selected = filter::project_fields(&document(&raw), fields, 9, 2 * 1024 * 1024 - 4096)
            .ok()
            .expect("test document must project successfully");
        let selected_wire = render(&selected.value).unwrap();
        let expected = json!({
            "count": i64::MIN,
            "metadata": {"available": true, "tags": ["two", "ñ", "\u{7f}"]},
            "title": raw["title"].clone(),
        });
        assert_eq!(selected_wire, json::canonical(&expected));
        assert_eq!(json::parse(&selected_wire, 4096).unwrap(), expected);
    }

    #[test]
    fn selected_reflection_checks_decoded_and_exact_encoded_bytes() {
        let selected = filter::Json::Object(vec![(
            b"name".to_vec(),
            filter::Json::Text("é😀".as_bytes().to_vec()),
        )]);
        let wire = render(&selected).unwrap();
        assert!(ensure_selected_safe(&selected, &wire, b"absent").is_ok());
        assert_eq!(
            ensure_selected_safe(&selected, &wire, "é".as_bytes()),
            Err(Error::UpstreamResponse),
        );
        assert_eq!(
            ensure_selected_safe(&selected, &wire, br"\u00e9"),
            Err(Error::UpstreamResponse),
        );
        assert_eq!(
            ensure_selected_safe(&selected, &wire, b"name"),
            Err(Error::UpstreamResponse),
        );
    }

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

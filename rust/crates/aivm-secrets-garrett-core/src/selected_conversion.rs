//! Production-used traversal from an approved disclosure tree to a native
//! public JSON value. This is the *same* Rust function called by the manifest
//! adapter; the pinned Aeneas pipeline must extract this traversal rather
//! than a proof-only mirror.
//!
//! The native builder owns UTF-8 decoding, serde value construction, map
//! insertion, and their error behavior. Those are explicit, narrow external
//! callbacks, not claims about arbitrary serde or guest-wire bytes.
#![allow(clippy::ptr_arg)]

use crate::disclosure::Json;

/// Each builder operation constructs public data from the already selected
/// tree. In particular, there is no raw provider response argument or fallback.
/// `name` precedes rendering its child, and `insert` follows that rendering,
/// preserving the production adapter's failure/short-circuit order.
pub trait Builder {
    type Value;
    type Name;
    type Object;
    type Error;

    fn null(&mut self) -> Self::Value;
    fn boolean(&mut self, value: bool) -> Self::Value;
    fn integer(&mut self, value: i64) -> Self::Value;
    fn text(&mut self, bytes: &Vec<u8>) -> Result<Self::Value, Self::Error>;
    fn array(&mut self, values: Vec<Self::Value>) -> Self::Value;
    fn name(&mut self, bytes: &Vec<u8>) -> Result<Self::Name, Self::Error>;
    fn empty_object(&mut self) -> Self::Object;
    fn insert(
        &mut self,
        object: &mut Self::Object,
        name: Self::Name,
        value: Self::Value,
    ) -> Result<(), Self::Error>;
    fn finish_object(&mut self, object: Self::Object) -> Self::Value;
    fn invalid(&mut self) -> Self::Error;
}

/// Traverse only the extracted `disclosure.project_fields` output. No opaque
/// leaf may become a public value. Every array element and object field must
/// be converted successfully before the enclosing value can be returned.
///
/// The native `SerdeBuilder` is instantiated in `manifest/disclosure.rs`.
/// Correspondence of builder callbacks and subsequent serde serialization
/// remains to be proved separately, but structural selection is source-owned.
pub fn render<B: Builder>(selected: &Json, builder: &mut B) -> Result<B::Value, B::Error> {
    match selected {
        Json::Null => Ok(builder.null()),
        Json::Boolean(value) => Ok(builder.boolean(*value)),
        Json::Integer(value) => Ok(builder.integer(*value)),
        Json::Text(bytes) => builder.text(bytes),
        Json::Array(values) => {
            let mut out = Vec::new();
            let mut index = 0;
            while index < values.len() {
                let value = render(&values[index], builder)?;
                out.push(value);
                index += 1;
            }
            Ok(builder.array(out))
        }
        Json::Object(fields) => {
            let mut out = builder.empty_object();
            let mut index = 0;
            while index < fields.len() {
                let field = &fields[index];
                let name = builder.name(&field.0)?;
                let value = render(&field.1, builder)?;
                builder.insert(&mut out, name, value)?;
                index += 1;
            }
            Ok(builder.finish_object(out))
        }
        Json::Opaque => Err(builder.invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Failure {
        Invalid,
        BadName,
        Duplicate,
    }
    struct Recording {
        calls: Vec<&'static str>,
    }
    impl Builder for Recording {
        type Value = String;
        type Name = String;
        type Object = Vec<(String, String)>;
        type Error = Failure;

        fn null(&mut self) -> String {
            "null".into()
        }
        fn boolean(&mut self, value: bool) -> String {
            format!("{value}")
        }
        fn integer(&mut self, value: i64) -> String {
            format!("{value}")
        }
        fn text(&mut self, bytes: &Vec<u8>) -> Result<String, Failure> {
            self.calls.push("text");
            String::from_utf8(bytes.clone()).map_err(|_| Failure::Invalid)
        }
        fn array(&mut self, values: Vec<String>) -> String {
            self.calls.push("array");
            format!("[{}]", values.join(","))
        }
        fn name(&mut self, bytes: &Vec<u8>) -> Result<String, Failure> {
            self.calls.push("name");
            String::from_utf8(bytes.clone()).map_err(|_| Failure::BadName)
        }
        fn empty_object(&mut self) -> Self::Object {
            Vec::new()
        }
        fn insert(
            &mut self,
            object: &mut Self::Object,
            name: String,
            value: String,
        ) -> Result<(), Failure> {
            self.calls.push("insert");
            if object.iter().any(|(key, _)| key == &name) {
                return Err(Failure::Duplicate);
            }
            object.push((name, value));
            Ok(())
        }
        fn finish_object(&mut self, values: Self::Object) -> String {
            self.calls.push("object");
            let fields = values
                .iter()
                .map(|(key, value)| format!("{key}:{value}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
        fn invalid(&mut self) -> Failure {
            Failure::Invalid
        }
    }

    #[test]
    fn nested_selection_uses_only_supplied_children_in_order() {
        let selected = Json::Object(vec![
            (b"ok".to_vec(), Json::Boolean(true)),
            (
                b"items".to_vec(),
                Json::Array(vec![Json::Integer(-42), Json::Text(b"yes".to_vec())]),
            ),
        ]);
        let mut builder = Recording { calls: vec![] };
        assert_eq!(
            render(&selected, &mut builder),
            Ok("{ok:true,items:[-42,yes]}".into())
        );
        assert_eq!(
            builder.calls,
            ["name", "insert", "name", "text", "array", "insert", "object"]
        );
    }

    #[test]
    fn rejected_member_short_circuits_before_later_members() {
        let selected = Json::Object(vec![
            (b"field".to_vec(), Json::Text(b"first".to_vec())),
            (b"field".to_vec(), Json::Text(b"second".to_vec())),
            (b"later".to_vec(), Json::Text(b"never".to_vec())),
        ]);
        let mut builder = Recording { calls: vec![] };
        assert_eq!(render(&selected, &mut builder), Err(Failure::Duplicate));
        assert_eq!(
            builder.calls,
            ["name", "text", "insert", "name", "text", "insert"]
        );
    }

    #[test]
    fn malformed_name_is_checked_before_child_and_opaque_cannot_escape() {
        let selected = Json::Object(vec![(vec![255], Json::Text(b"not reached".to_vec()))]);
        let mut builder = Recording { calls: vec![] };
        assert_eq!(render(&selected, &mut builder), Err(Failure::BadName));
        assert_eq!(builder.calls, ["name"]);
        assert_eq!(render(&Json::Opaque, &mut builder), Err(Failure::Invalid));
        assert_eq!(render(&Json::Array(vec![Json::Opaque]), &mut builder), Err(Failure::Invalid));
    }
}

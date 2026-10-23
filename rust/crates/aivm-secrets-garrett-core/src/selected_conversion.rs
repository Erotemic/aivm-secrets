//! Production-used rendering of an approved disclosure tree to exact public
//! JSON bytes. `render_wire` calls this module's generic recursive `render`
//! with a concrete `WireBuilder` and feeds the existing extracted wire encoder.
//! The pinned Aeneas pipeline extracts the same Rust called by the manifest
//! adapter, not a proof-only mirror. The native `serde_json` adapter remains
//! responsible for input parsing, host schema construction and final guest
//! response handling, not for converting this selected tree.
#![allow(clippy::ptr_arg)]

use crate::disclosure::Json;

/// Validate the field names accepted by the native manifest schema parser.
/// They are host-owned output keys, not JSON pointers or provider field names.
/// This exact production-called byte loop is extracted by Aeneas.
pub fn public_field_name(bytes: &Vec<u8>) -> bool {
    if bytes.len() == 0 || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if first < b'a' || first > b'z' {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let lowercase = byte >= b'a' && byte <= b'z';
        let uppercase = byte >= b'A' && byte <= b'Z';
        let digit = byte >= b'0' && byte <= b'9';
        if !(lowercase || uppercase || digit || byte == b'_') {
            return false;
        }
        index += 1;
    }
    true
}

/// Generic interface used by the extracted recursive renderer. Production
/// instantiates it as `WireBuilder`; every operation sees only selected data,
/// never the raw provider response. Name decoding precedes the child and
/// insertion follows it, retaining failure/short-circuit order.
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
/// The production specialization uses a concrete extracted `WireBuilder`;
/// the final guest JSON parse/assembly/capture remains a separate proof edge.
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

/// Construct the exact JSON-wire representation from the selected tree.
/// This is the production renderer: UTF-8 decoding, number spelling, object
/// insertion, and rejection are all implemented in the Aeneas-extracted crate.
/// The native adapter no longer provides a generic serde construction callback.
#[derive(Debug, PartialEq, Eq)]
pub enum WireDenial {
    InvalidText,
    DuplicateName,
    Opaque,
}

/// Strict Unicode scalar decoding of RFC 3629 UTF-8; rejects overlong encodings,
/// surrogate values and scalars above U+10FFFF. Every byte is consumed once.
/// No std::str::from_utf8 implementation is used in this production conversion.
pub fn utf8_scalars(bytes: &Vec<u8>) -> Result<Vec<u32>, WireDenial> {
    let mut scalars = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let first = bytes[i];
        if first < 0x80 {
            scalars.push(first as u32);
            i += 1;
        } else if first >= 0xc2 && first <= 0xdf {
            if bytes.len() - i < 2 {
                return Err(WireDenial::InvalidText);
            }
            let second = bytes[i + 1];
            if second < 0x80 || second > 0xbf {
                return Err(WireDenial::InvalidText);
            }
            scalars.push(((first as u32 - 0xc0) * 64) + (second as u32 - 0x80));
            i += 2;
        } else if first >= 0xe0 && first <= 0xef {
            if bytes.len() - i < 3 {
                return Err(WireDenial::InvalidText);
            }
            let second = bytes[i + 1];
            let third = bytes[i + 2];
            if second < 0x80 || second > 0xbf || third < 0x80 || third > 0xbf
                || (first == 0xe0 && second < 0xa0)
                || (first == 0xed && second >= 0xa0)
            {
                return Err(WireDenial::InvalidText);
            }
            scalars.push(
                (first as u32 - 0xe0) * 4096
                    + (second as u32 - 0x80) * 64
                    + (third as u32 - 0x80),
            );
            i += 3;
        } else if first >= 0xf0 && first <= 0xf4 {
            if bytes.len() - i < 4 {
                return Err(WireDenial::InvalidText);
            }
            let second = bytes[i + 1];
            let third = bytes[i + 2];
            let fourth = bytes[i + 3];
            if second < 0x80 || second > 0xbf || third < 0x80 || third > 0xbf
                || fourth < 0x80 || fourth > 0xbf
                || (first == 0xf0 && second < 0x90)
                || (first == 0xf4 && second >= 0x90)
            {
                return Err(WireDenial::InvalidText);
            }
            scalars.push(
                (first as u32 - 0xf0) * 262144
                    + (second as u32 - 0x80) * 4096
                    + (third as u32 - 0x80) * 64
                    + (fourth as u32 - 0x80),
            );
            i += 4;
        } else {
            return Err(WireDenial::InvalidText);
        }
    }
    Ok(scalars)
}

/// Decimal integer tokens, including i64::MIN, are spelled by extracted Rust.
fn append_u64_decimal(output: &mut Vec<u8>, value: u64) {
    if value >= 10 {
        append_u64_decimal(output, value / 10);
    }
    output.push(b'0' + (value % 10) as u8);
}
pub fn integer_token(value: i64) -> Vec<u8> {
    let mut output = Vec::new();
    if value == i64::MIN {
        output.extend_from_slice(b"-9223372036854775808");
    } else if value < 0 {
        output.push(b'-');
        append_u64_decimal(&mut output, (-value) as u64);
    } else {
        append_u64_decimal(&mut output, value as u64);
    }
    output
}

pub struct WireBuilder;
impl Builder for WireBuilder {
    type Value = crate::json_wire::Value;
    type Name = Vec<u32>;
    type Object = Vec<(Vec<u32>, crate::json_wire::Value)>;
    type Error = WireDenial;

    fn null(&mut self) -> Self::Value {
        crate::json_wire::Value::Null
    }
    fn boolean(&mut self, value: bool) -> Self::Value {
        crate::json_wire::Value::Boolean(value)
    }
    fn integer(&mut self, value: i64) -> Self::Value {
        crate::json_wire::Value::Number(integer_token(value))
    }
    fn text(&mut self, bytes: &Vec<u8>) -> Result<Self::Value, Self::Error> {
        Ok(crate::json_wire::Value::Text(utf8_scalars(bytes)?))
    }
    fn array(&mut self, values: Vec<Self::Value>) -> Self::Value {
        crate::json_wire::Value::Array(values)
    }
    fn name(&mut self, bytes: &Vec<u8>) -> Result<Self::Name, Self::Error> {
        utf8_scalars(bytes)
    }
    fn empty_object(&mut self) -> Self::Object {
        Vec::new()
    }
    fn insert(
        &mut self,
        object: &mut Self::Object,
        name: Self::Name,
        value: Self::Value,
    ) -> Result<(), Self::Error> {
        let mut i = 0;
        while i < object.len() {
            if object[i].0 == name {
                return Err(WireDenial::DuplicateName);
            }
            i += 1;
        }
        // The native host constructs schema fields from its ordered serde map;
        // extracted project_fields preserves that order, so the production
        // input is already in canonical key order. No new sorting pass.
        object.push((name, value));
        Ok(())
    }
    fn finish_object(&mut self, object: Self::Object) -> Self::Value {
        crate::json_wire::Value::Object(object)
    }
    fn invalid(&mut self) -> Self::Error {
        WireDenial::Opaque
    }
}

/// The production read-release path uses this specialization of the generic
/// Aeneas-extracted renderer. The only subsequent format operation is the
/// already-extracted json_wire::encode. Reflection is checked on this same
/// selected tree and its emitted bytes before the native release adapter.
pub fn render_wire(selected: &Json) -> Result<crate::json_wire::Value, WireDenial> {
    render(selected, &mut WireBuilder)
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
    fn utf8_decoder_matches_rust_reference_and_rejects_malformed_encodings() {
        for n in 0..=255_u8 {
            for m in 0..=255_u8 {
                let bytes = vec![n, m];
                let reference = std::str::from_utf8(&bytes)
                    .ok()
                    .map(|s| s.chars().map(u32::from).collect::<Vec<_>>());
                assert_eq!(utf8_scalars(&bytes).ok(), reference, "{bytes:?}");
            }
        }
        for scalar in (0..=0x10ffff_u32).step_by(101) {
            if let Some(c) = char::from_u32(scalar) {
                let value = c.to_string();
                assert_eq!(utf8_scalars(&value.into_bytes()), Ok(vec![scalar]));
            }
        }
        for bytes in [
            vec![0x80], vec![0xc0, 0x80], vec![0xc1, 0xbf],
            vec![0xe0, 0x9f, 0xbf], vec![0xed, 0xa0, 0x80],
            vec![0xf0, 0x8f, 0xbf, 0xbf], vec![0xf4, 0x90, 0x80, 0x80],
            vec![0xf5, 0x80, 0x80, 0x80], vec![0xe2, 0x82],
            vec![0xf0, 0x90, 0x80], vec![0xe2, 0x28, 0xa1],
        ] {
            assert_eq!(utf8_scalars(&bytes), Err(WireDenial::InvalidText));
        }
        for valid in ["", "ascii", "\u{0000}\n", "é", "😀", "\u{10ffff}"] {
            assert_eq!(
                utf8_scalars(&valid.as_bytes().to_vec()),
                Ok(valid.chars().map(u32::from).collect()),
            );
        }
    }

    #[test]
    fn i64_tokens_are_identical_to_standard_decimal_formatting() {
        for n in [
            i64::MIN,
            i64::MIN + 1,
            -100,
            -10,
            -1,
            0,
            1,
            9,
            10,
            42,
            i64::MAX,
        ] {
            assert_eq!(integer_token(n), n.to_string().into_bytes());
        }
        for n in -1000..=1000 {
            assert_eq!(integer_token(n), n.to_string().into_bytes());
        }
    }

    #[test]
    fn concrete_wire_builder_preserves_selected_order_and_short_circuits() {
        use crate::json_wire::encode;
        let selected = Json::Object(vec![
            (b"a".to_vec(), Json::Array(vec![Json::Integer(i64::MIN), Json::Null])),
            (b"z".to_vec(), Json::Text("é😀".as_bytes().to_vec())),
        ]);
        let actual = render_wire(&selected).unwrap();
        assert_eq!(
            encode(&actual).ok().expect("selected wire must encode"),
            br#"{"a":[-9223372036854775808,null],"z":"\u00e9\ud83d\ude00"}"#
        );
        assert!(matches!(
            render_wire(&Json::Object(vec![
                (b"x".to_vec(), Json::Null),
                (b"x".to_vec(), Json::Opaque),
            ])),
            Err(WireDenial::Opaque)
        ));
        assert!(matches!(
            render_wire(&Json::Object(vec![
                (b"x".to_vec(), Json::Null),
                (b"x".to_vec(), Json::Boolean(true)),
            ])),
            Err(WireDenial::DuplicateName)
        ));
        assert!(matches!(
            render_wire(&Json::Text(vec![0xff])),
            Err(WireDenial::InvalidText)
        ));
    }

    #[test]
    fn public_name_matches_previous_native_validator() {
        // Exact parity against the prior native predicate, including UTF-8
        // multibyte sequences and all possible byte values.
        fn original(bytes: &[u8]) -> bool {
            !bytes.is_empty()
                && bytes.len() <= 32
                && bytes[0].is_ascii_lowercase()
                && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        }
        let mut samples = vec![vec![], b"headRefOid".to_vec(), b"a_123".to_vec()];
        for len in [1, 2, 31, 32, 33] {
            for byte in 0..=255_u8 {
                samples.push(vec![byte; len]);
                let mut mixed = vec![b'a'; len];
                mixed[len - 1] = byte;
                samples.push(mixed);
            }
        }
        for sample in samples {
            assert_eq!(public_field_name(&sample), original(&sample), "{sample:?}");
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

    /// The accepted language proved in proofs/GarrettPublicFieldNameContract.lean
    /// (`public_field_name_spec`); dev/verification/anodized_pilot.py reruns
    /// this test with the Anodized contract attribute to compare behaviour.
    #[test]
    fn public_field_name_accepts_exactly_the_documented_language() {
        let accepted: [&[u8]; 6] = [b"a", b"title", b"head_ref_oid", b"aB9_", b"z0", b"abcdefghijklmnopqrstuvwxyz012345"];
        let refused: [&[u8]; 10] = [
            b"",                                  // empty
            b"abcdefghijklmnopqrstuvwxyz0123456", // 33 bytes
            b"Title",                             // uppercase first byte
            b"_name",                             // underscore first byte
            b"9name",                             // digit first byte
            b"na-me",                             // '-' later
            b"na.me",                             // '.' later
            b"na me",                             // space later
            b"nam\xc3\xa9",                       // non-ASCII later
            b"name/",                             // '/' later
        ];
        for name in accepted {
            assert!(public_field_name(&name.to_vec()), "{:?}", name);
        }
        for name in refused {
            assert!(!public_field_name(&name.to_vec()), "{:?}", name);
        }
    }
}

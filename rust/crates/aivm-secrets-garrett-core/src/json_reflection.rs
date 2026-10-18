//! Literal credential exclusion from decoded JSON keys and strings. The
//! serializer still needs its separate byte check; this is not a detector for
//! alternate encodings or arbitrary provider-controlled information flows.
use crate::{disclosure::Json, reflection::contains};

pub fn safe(value: &Json, secret: &[u8], fuel: usize) -> bool {
    if fuel == 0 {
        return false;
    }
    match value {
        Json::Text(text) => !contains(text, secret),
        Json::Array(values) => {
            let mut i = 0;
            while i < values.len() {
                if !safe(&values[i], secret, fuel - 1) {
                    return false;
                }
                i += 1;
            }
            true
        }
        Json::Object(fields) => {
            let mut i = 0;
            while i < fields.len() {
                if contains(&fields[i].0, secret) {
                    return false;
                }
                if !safe(&fields[i].1, secret, fuel - 1) {
                    return false;
                }
                i += 1;
            }
            true
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_parser_depth_has_room_for_terminal_text() {
        let mut value = Json::Text(b"public".to_vec());
        for _ in 0..64 {
            value = Json::Array(vec![value]);
        }
        assert!(safe(&value, b"credential", 65));
        assert!(!safe(&value, b"credential", 64));
        value = Json::Array(vec![value]);
        assert!(!safe(&value, b"credential", 65));
        assert!(safe(&value, b"credential", 66));
    }
    #[test]
    fn final_object_key_and_nested_value_are_checked() {
        let key = Json::Object(vec![
            (b"public".to_vec(), Json::Null),
            (b"prefix-credential".to_vec(), Json::Array(vec![])),
        ]);
        let value = Json::Object(vec![
            (b"public".to_vec(), Json::Null),
            (
                b"last".to_vec(),
                Json::Array(vec![Json::Null, Json::Text(b"credential-suffix".to_vec())]),
            ),
        ]);
        assert!(!safe(&key, b"credential", 65));
        assert!(!safe(&value, b"credential", 65));
        assert!(safe(&value, b"absent", 65));
    }
}

//! Complete canonical JSON layout over a captured native value. Number token
//! spelling, UTF-8/scalar conversion and object order are native contracts.
//! Only successful encoding can enter bounded guest-frame preparation.
#![allow(clippy::ptr_arg)]

pub enum Value {
    Null,
    Boolean(bool),
    Number(Vec<u8>),
    Text(Vec<u32>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u32>, Value)>),
}
pub enum EncodingDenial {
    InvalidText,
}

pub fn append(output: &mut Vec<u8>, value: &Value) -> bool {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Boolean(value) => {
            if *value {
                output.extend_from_slice(b"true");
            } else {
                output.extend_from_slice(b"false");
            }
        }
        Value::Number(token) => output.extend_from_slice(token),
        Value::Text(scalars) => return crate::json_string::append(output, scalars),
        Value::Array(values) => return append_array(output, values),
        Value::Object(fields) => return append_fields(output, fields),
    }
    true
}

fn append_array(output: &mut Vec<u8>, values: &Vec<Value>) -> bool {
    output.push(b'[');
    let mut index = 0;
    while index < values.len() {
        if index > 0 {
            output.push(b',');
        }
        if !append(output, &values[index]) {
            return false;
        }
        index += 1;
    }
    output.push(b']');
    true
}
fn append_field(output: &mut Vec<u8>, field: &(Vec<u32>, Value)) -> bool {
    if !crate::json_string::append(output, &field.0) {
        return false;
    }
    output.push(b':');
    append(output, &field.1)
}
fn append_fields(output: &mut Vec<u8>, fields: &Vec<(Vec<u32>, Value)>) -> bool {
    output.push(b'{');
    let mut index = 0;
    while index < fields.len() {
        if index > 0 {
            output.push(b',');
        }
        if !append_field(output, &fields[index]) {
            return false;
        }
        index += 1;
    }
    output.push(b'}');
    true
}

pub fn encode(value: &Value) -> Result<Vec<u8>, EncodingDenial> {
    let mut output = Vec::new();
    if !append(&mut output, value) {
        return Err(EncodingDenial::InvalidText);
    }
    Ok(output)
}

pub fn prepare(
    value: &Value,
    limit: usize,
) -> Result<crate::guest_frame::Frame, crate::guest_frame::FrameDenial> {
    match encode(value) {
        Ok(payload) => crate::guest_frame::prepare(payload, limit),
        Err(_) => Err(crate::guest_frame::FrameDenial::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(value: &str) -> Vec<u32> {
        value.chars().map(u32::from).collect()
    }
    #[test]
    fn complete_nested_layout_preserves_number_tokens_keys_and_scalar_bytes() {
        let value = Value::Object(vec![
            (
                text("é"),
                Value::Array(vec![
                    Value::Null,
                    Value::Boolean(false),
                    Value::Boolean(true),
                    Value::Number(b"-9223372036854775808".to_vec()),
                    Value::Number(b"1.25e+04".to_vec()),
                    Value::Text(text("\n😀")),
                ]),
            ),
            (text("empty"), Value::Object(vec![])),
        ]);
        let wire = encode(&value).ok().unwrap();
        assert_eq!(wire, br#"{"\u00e9":[null,false,true,-9223372036854775808,1.25e+04,"\n\ud83d\ude00"],"empty":{}}"#);
        assert!(prepare(&value, wire.len()).is_err());
        assert!(prepare(&value, wire.len() + 1).is_ok());
    }
    #[test]
    fn invalid_nested_values_and_names_never_construct_a_frame() {
        for value in [
            Value::Text(vec![0xd800]),
            Value::Array(vec![Value::Null, Value::Text(vec![0x110000])]),
            Value::Object(vec![(vec![0xdfff], Value::Null)]),
            Value::Object(vec![(text("good"), Value::Text(vec![u32::MAX]))]),
        ] {
            assert!(encode(&value).is_err());
            assert!(prepare(&value, 4096).is_err());
        }
        // Raw token grammar is a native conversion contract, but frame safety
        // still rejects newline injection even when that contract is violated.
        assert!(prepare(&Value::Number(b"0\n{}".to_vec()), 4096).is_err());
    }
    #[test]
    fn arrays_and_objects_insert_exactly_the_required_separators() {
        for (value, expected) in [
            (Value::Array(vec![]), b"[]".as_slice()),
            (Value::Object(vec![]), b"{}"),
            (
                Value::Array(vec![Value::Array(vec![]), Value::Object(vec![])]),
                b"[[],{}]",
            ),
        ] {
            assert_eq!(encode(&value).ok().unwrap(), expected);
        }
    }
}

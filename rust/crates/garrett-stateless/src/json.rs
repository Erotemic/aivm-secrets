//! Strict JSON for `garrett-stateless-v1` (spec section 2): duplicate keys,
//! excessive depth and malformed input are errors; the canonical encoding
//! is byte-identical to Python's `json.dumps(sort_keys=True,
//! separators=(",", ":"), ensure_ascii=True)` for the values this profile
//! emits.
use std::collections::BTreeMap;

/// Largest integer this profile treats as an integer (`2^53 - 1`).
pub const MAX_INTEGER: i64 = 9007199254740991;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// An integer of magnitude at most [`MAX_INTEGER`].
    Int(i64),
    /// Any other number, kept as its text; never emitted canonically.
    Number(String),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

#[derive(Debug)]
pub struct JsonError;

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|map| map.get(key))
    }
}

/// Parse `bytes` (at most `limit` bytes, nesting at most `depth`).
pub fn parse(bytes: &[u8], limit: usize, depth: usize) -> Result<Value, JsonError> {
    if bytes.len() > limit {
        return Err(JsonError);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JsonError)?;
    let mut parser = Parser {
        text: text.as_bytes(),
        at: 0,
        depth,
    };
    parser.blank();
    let value = parser.value(0)?;
    parser.blank();
    if parser.at != parser.text.len() {
        return Err(JsonError);
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn blank(&mut self) {
        while self.at < self.text.len()
            && matches!(self.text[self.at], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.at += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }
    fn expect(&mut self, literal: &[u8]) -> Result<(), JsonError> {
        if self.text[self.at..].starts_with(literal) {
            self.at += literal.len();
            Ok(())
        } else {
            Err(JsonError)
        }
    }
    fn value(&mut self, level: usize) -> Result<Value, JsonError> {
        match self.peek().ok_or(JsonError)? {
            b'{' => {
                if level >= self.depth {
                    return Err(JsonError);
                }
                self.at += 1;
                let mut map = BTreeMap::new();
                self.blank();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    return Ok(Value::Object(map));
                }
                loop {
                    self.blank();
                    if self.peek() != Some(b'"') {
                        return Err(JsonError);
                    }
                    let key = self.string()?;
                    self.blank();
                    self.expect(b":")?;
                    self.blank();
                    let value = self.value(level + 1)?;
                    if map.insert(key, value).is_some() {
                        return Err(JsonError);
                    }
                    self.blank();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Value::Object(map));
                        }
                        _ => return Err(JsonError),
                    }
                }
            }
            b'[' => {
                if level >= self.depth {
                    return Err(JsonError);
                }
                self.at += 1;
                let mut items = Vec::new();
                self.blank();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    self.blank();
                    items.push(self.value(level + 1)?);
                    self.blank();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Value::Array(items));
                        }
                        _ => return Err(JsonError),
                    }
                }
            }
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.expect(b"true").map(|_| Value::Bool(true)),
            b'f' => self.expect(b"false").map(|_| Value::Bool(false)),
            b'n' => self.expect(b"null").map(|_| Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError),
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.at;
        while self.at < self.text.len() && self.text[self.at].is_ascii_digit() {
            self.at += 1;
        }
        self.at - start
    }
    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let first = self.at;
        let count = self.digits();
        if count == 0 || (count > 1 && self.text[first] == b'0') {
            return Err(JsonError);
        }
        let mut integer = true;
        if self.peek() == Some(b'.') {
            self.at += 1;
            if self.digits() == 0 {
                return Err(JsonError);
            }
            integer = false;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return Err(JsonError);
            }
            integer = false;
        }
        let text = std::str::from_utf8(&self.text[start..self.at]).map_err(|_| JsonError)?;
        if integer {
            if let Ok(value) = text.parse::<i64>() {
                if (-MAX_INTEGER..=MAX_INTEGER).contains(&value) {
                    return Ok(Value::Int(value));
                }
            }
        }
        Ok(Value::Number(text.to_owned()))
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.at + 4 > self.text.len() {
            return Err(JsonError);
        }
        let text = std::str::from_utf8(&self.text[self.at..self.at + 4]).map_err(|_| JsonError)?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(JsonError);
        }
        self.at += 4;
        u32::from_str_radix(text, 16).map_err(|_| JsonError)
    }
    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b"\"")?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(JsonError)?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek().ok_or(JsonError)?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let high = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&high) {
                                self.expect(b"\\u")?;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(JsonError);
                                }
                                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                            } else if (0xdc00..0xe000).contains(&high) {
                                return Err(JsonError);
                            } else {
                                high
                            };
                            out.push(char::from_u32(code).ok_or(JsonError)?);
                        }
                        _ => return Err(JsonError),
                    }
                }
                0..=0x1f => return Err(JsonError),
                _ => {
                    // Copy one UTF-8 scalar (the input is valid UTF-8).
                    let rest = std::str::from_utf8(&self.text[self.at..]).map_err(|_| JsonError)?;
                    let ch = rest.chars().next().ok_or(JsonError)?;
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }
}

fn escape(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
                }
            }
            c => out.push(c as u8),
        }
    }
    out.push(b'"');
}

fn encode(out: &mut Vec<u8>, value: &Value) -> Result<(), JsonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::Number(_) => return Err(JsonError),
        Value::Str(text) => escape(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                escape(out, key);
                out.push(b':');
                encode(out, item)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// The canonical encoding; an error only for a non-integer number.
pub fn canonical(value: &Value) -> Result<Vec<u8>, JsonError> {
    let mut out = Vec::new();
    encode(&mut out, value)?;
    Ok(out)
}

/// Build an object from `(key, value)` pairs.
pub fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub fn text(value: &str) -> Value {
    Value::Str(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_matches_python() {
        let value = parse(
            br#"{"b":[1,true,null],"a":"x\"\\\u00e9\ud83d\ude00\n"}"#,
            1024,
            16,
        )
        .unwrap();
        assert_eq!(
            canonical(&value).unwrap(),
            br#"{"a":"x\"\\\u00e9\ud83d\ude00\n","b":[1,true,null]}"#.to_vec()
        );
    }

    #[test]
    fn rejects_duplicates_depth_and_garbage() {
        assert!(parse(br#"{"a":1,"a":2}"#, 100, 16).is_err());
        assert!(parse(b"[[[1]]]", 100, 2).is_err());
        assert!(parse(b"[1]", 100, 2).is_ok());
        for bad in [
            &b"01"[..],
            b"{\"a\":}",
            b"\"\x01\"",
            b"[1,]",
            b"1 2",
            b"\"\\ud800\"",
        ] {
            assert!(parse(bad, 100, 16).is_err(), "{bad:?}");
        }
        assert_eq!(parse(b"1.5", 100, 16).unwrap(), Value::Number("1.5".into()));
        assert_eq!(
            parse(b"9007199254740992", 100, 16).unwrap(),
            Value::Number("9007199254740992".into())
        );
        assert_eq!(parse(b"-0", 100, 16).unwrap(), Value::Int(0));
    }
}

//! The extracted canonical-JSON validator (`stateless_token::upstream_object`)
//! against the native strict parser and canonical encoder: on canonical
//! encodings of generated values and on byte-level mutations of them, the
//! validator accepts exactly what `parse` then `canonical` reproduces.
use aivm_secrets_garrett_core::stateless_token::upstream_object;
use garrett_stateless::json::{self, Value};
use std::collections::BTreeMap;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn text(rng: &mut Rng) -> String {
    let len = rng.below(6);
    (0..len)
        .map(|_| match rng.below(6) {
            0 => char::from_u32(rng.below(0x20) as u32).unwrap(),
            1 => ['"', '\\', '/', '\u{7f}'][rng.below(4) as usize],
            2 => char::from_u32(0xa0 + rng.below(0x700) as u32).unwrap(),
            3 => char::from_u32(0x1f600 + rng.below(64) as u32).unwrap(),
            _ => char::from_u32(0x20 + rng.below(0x5f) as u32).unwrap(),
        })
        .collect()
}

fn value(rng: &mut Rng, depth: usize) -> Value {
    match if depth == 0 {
        rng.below(5)
    } else {
        rng.below(7)
    } {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => {
            let magnitude: i64 = [0, 1, 9, 10, 9007199254740991][rng.below(5) as usize];
            Value::Int(if rng.below(2) == 1 {
                -magnitude
            } else {
                magnitude
            })
        }
        3 | 4 => Value::Str(text(rng)),
        5 => Value::Array((0..rng.below(4)).map(|_| value(rng, depth - 1)).collect()),
        _ => Value::Object(object(rng, depth - 1)),
    }
}

fn object(rng: &mut Rng, depth: usize) -> BTreeMap<String, Value> {
    (0..rng.below(4))
        .map(|_| (text(rng), value(rng, depth)))
        .collect()
}

/// What the native strict codec accepts as the `upstream` object.
fn native(bytes: &[u8]) -> bool {
    match json::parse(bytes, 1 << 20, 15) {
        Ok(Value::Object(map)) => {
            json::canonical(&Value::Object(map)).ok().as_deref() == Some(bytes)
        }
        _ => false,
    }
}

#[test]
fn validator_agrees_with_the_native_codec() {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut accepted = 0;
    for _ in 0..4000 {
        let bytes = json::canonical(&Value::Object(object(&mut rng, 3))).unwrap();
        assert!(
            upstream_object(&bytes),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        accepted += 1;
        let mut mutated = bytes.clone();
        match rng.below(3) {
            0 if !mutated.is_empty() => {
                let at = rng.below(mutated.len() as u64) as usize;
                mutated[at] = b" \"\\,:{}[]0-9eE.utnaf\x7f\n"[rng.below(22) as usize];
            }
            1 => {
                let at = rng.below(mutated.len() as u64 + 1) as usize;
                mutated.insert(at, b"\" ,0\\u}"[rng.below(7) as usize]);
            }
            _ if mutated.len() > 1 => {
                let at = rng.below(mutated.len() as u64) as usize;
                mutated.remove(at);
            }
            _ => (),
        }
        assert_eq!(
            upstream_object(&mutated),
            native(&mutated),
            "{}",
            String::from_utf8_lossy(&mutated)
        );
    }
    assert_eq!(accepted, 4000);
}

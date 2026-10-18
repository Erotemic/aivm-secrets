//! Admission and durable reservation must precede a coordinated write.
//! Durability, authenticated peer checks and provider I/O are adapter contracts.
pub trait Dispatch {
    type Output;
    type Error;
    fn check(&self) -> Result<(), Self::Error>;
    fn reserve(&self) -> Result<(), Self::Error>;
    fn emit(&self) -> Result<Self::Output, Self::Error>;
    fn finish(&self) -> Result<(), Self::Error>;
    fn outcome_unknown(&self) -> Self::Error;
}

pub fn dispatch<D: Dispatch>(ops: &D, keyed_write: bool) -> Result<D::Output, D::Error> {
    match ops.check() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if keyed_write {
        match ops.reserve() {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
    }
    let result = match ops.emit() {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if keyed_write {
        match ops.finish() {
            Ok(()) => (),
            Err(_) => return Err(ops.outcome_unknown()),
        }
    }
    Ok(result)
}

/// Guest retry names are opaque transport metadata. Only this closed ASCII
/// alphabet enters the principal-scoped reservation-key derivation.
pub fn retry_byte(byte: u8) -> bool {
    (byte >= b'A' && byte <= b'Z')
        || (byte >= b'a' && byte <= b'z')
        || (byte >= b'0' && byte <= b'9')
        || byte == b'-'
        || byte == b'_'
}
pub fn valid_retry_key(key: &[u8]) -> bool {
    if key.len() < 8 || key.len() > 128 {
        return false;
    }
    let mut i = 0;
    while i < key.len() {
        if !retry_byte(key[i]) {
            return false;
        }
        i += 1;
    }
    true
}

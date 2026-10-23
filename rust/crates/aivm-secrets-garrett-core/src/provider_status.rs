//! Production-called provider status line parser and manifest status
//! classification. The guest learns the class of a refused provider status
//! through the public error code; this module is the whole of that mapping.
#![allow(clippy::ptr_arg)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusDenial {
    /// Not an exact `HTTP/1.x NNN reason` line.
    Malformed,
    /// 4xx: the provider refused the request.
    Rejected,
    /// Any other non-2xx status.
    Failed,
    /// 206: a partial representation is never released.
    Partial,
}

/// Parse an octet-exact `HTTP/1.1 NNN reason` or `HTTP/1.0 NNN reason` line:
/// three ASCII digits, single spaces, a reason without control bytes, and
/// valid UTF-8 overall. Integer parsing never normalizes malformed framing.
pub fn parse(raw: &Vec<u8>) -> Result<u16, StatusDenial> {
    if raw.len() < 13 {
        return Err(StatusDenial::Malformed);
    }
    if raw[0] != b'H' || raw[1] != b'T' || raw[2] != b'T' || raw[3] != b'P'
        || raw[4] != b'/' || raw[5] != b'1' || raw[6] != b'.'
        || (raw[7] != b'1' && raw[7] != b'0')
        || raw[8] != b' ' || raw[12] != b' '
    {
        return Err(StatusDenial::Malformed);
    }
    if !digits(raw) || !reason(raw) {
        return Err(StatusDenial::Malformed);
    }
    if crate::selected_conversion::utf8_scalars(raw).is_err() {
        return Err(StatusDenial::Malformed);
    }
    Ok((raw[9] - b'0') as u16 * 100 + (raw[10] - b'0') as u16 * 10 + (raw[11] - b'0') as u16)
}

/// Bytes 9..12 are ASCII digits.
fn digits(raw: &Vec<u8>) -> bool {
    let mut i = 9;
    while i < 12 {
        if raw[i] < b'0' || raw[i] > b'9' {
            return false;
        }
        i += 1;
    }
    true
}

/// The reason phrase (from byte 13) has no control byte other than tab.
fn reason(raw: &Vec<u8>) -> bool {
    let mut j = 13;
    while j < raw.len() {
        let byte = raw[j];
        if (byte < 32 && byte != 9) || byte == 127 {
            return false;
        }
        j += 1;
    }
    true
}

/// Manifest response admission: only 2xx other than 206 proceeds.
pub fn manifest(status: u16) -> Result<(), StatusDenial> {
    if status >= 400 && status < 500 {
        return Err(StatusDenial::Rejected);
    }
    if status < 200 || status >= 300 {
        return Err(StatusDenial::Failed);
    }
    if status == 206 {
        return Err(StatusDenial::Partial);
    }
    Ok(())
}

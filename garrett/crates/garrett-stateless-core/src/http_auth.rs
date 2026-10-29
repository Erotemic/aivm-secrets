//! The upstream authentication field's exact bytes.
//! Validation completes before the caller's zeroizing buffer is modified.
use crate::credential_use::Authentication;

pub enum HeaderDenial {
    InvalidCredential,
}

// The pinned slice model exposes len; no foreign is_empty contract is needed.
#[allow(clippy::len_zero)]
pub fn valid_credential(secret: &[u8]) -> bool {
    if secret.len() == 0 || secret.len() > 4096 {
        return false;
    }
    for byte in secret {
        if *byte < b'!' || *byte > b'~' {
            return false;
        }
    }
    true
}

pub fn append_header(
    output: &mut Vec<u8>,
    secret: &[u8],
    authentication: &Authentication,
) -> Result<(), HeaderDenial> {
    if !valid_credential(secret) {
        return Err(HeaderDenial::InvalidCredential);
    }
    match authentication {
        Authentication::Bearer => output.extend_from_slice(b"Authorization: Bearer "),
        Authentication::ApiKey => output.extend_from_slice(b"X-API-Key: "),
    }
    output.extend_from_slice(secret);
    output.extend_from_slice(b"\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_credential_preserves_the_entire_existing_buffer() {
        for secret in [
            Vec::new(),
            b"TOKEN\r\nHost: attacker.test".to_vec(),
            b"TOKEN\n\nGET /".to_vec(),
            vec![b'X'; 4097],
            vec![0],
            vec![255],
            b"TOKEN ".to_vec(),
        ] {
            for authentication in [Authentication::Bearer, Authentication::ApiKey] {
                let mut bytes = vec![0, 255, 13, 10, b'X'];
                let original = bytes.clone();
                assert!(append_header(&mut bytes, &secret, &authentication).is_err());
                assert_eq!(bytes, original);
            }
        }
    }

    #[test]
    fn valid_boundaries_append_exactly_one_authentication_line() {
        for length in [1, 4096] {
            let secret = vec![b'~'; length];
            for (authentication, prefix) in [
                (Authentication::Bearer, b"Authorization: Bearer ".as_slice()),
                (Authentication::ApiKey, b"X-API-Key: ".as_slice()),
            ] {
                let mut bytes = b"existing\r\n".to_vec();
                assert!(append_header(&mut bytes, &secret, &authentication).is_ok());
                assert_eq!(bytes, [b"existing\r\n", prefix, &secret, b"\r\n"].concat());
            }
        }
    }
}

//! Concrete request-line framing. Host/headers/body are separate adapter inputs.

pub enum RequestDenial {
    InvalidLine,
}

pub fn valid_method(method: &[u8]) -> bool {
    let get: &[u8] = b"GET";
    let post: &[u8] = b"POST";
    let patch: &[u8] = b"PATCH";
    method == get || method == post || method == patch
}

// Keep the existing native wire grammar; policy compilation is stricter.
#[allow(clippy::len_zero)]
pub fn valid_target(target: &[u8]) -> bool {
    if target.len() == 0 || target.len() > 8192 || target[0] != b'/' {
        return false;
    }
    if target.len() > 1 && target[1] == b'/' {
        return false;
    }
    for byte in target {
        if *byte < b'!' || *byte > b'~' || *byte == b'#' {
            return false;
        }
    }
    true
}

pub fn append_line(
    output: &mut Vec<u8>,
    method: &[u8],
    target: &[u8],
) -> Result<(), RequestDenial> {
    if !valid_method(method) || !valid_target(target) {
        return Err(RequestDenial::InvalidLine);
    }
    output.extend_from_slice(method);
    output.extend_from_slice(b" ");
    output.extend_from_slice(target);
    output.extend_from_slice(b" HTTP/1.1\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_method_and_target_are_copied_without_rewriting() {
        let mut longest = vec![b'a'; 8192];
        longest[0] = b'/';
        for method in [b"GET".as_slice(), b"POST", b"PATCH"] {
            for target in [
                b"/".as_slice(),
                b"/v1/tickets/7?state=open",
                b"/safe%20literal",
                &longest,
            ] {
                let mut output = b"existing".to_vec();
                assert!(append_line(&mut output, method, target).is_ok());
                assert_eq!(
                    output,
                    [b"existing", method, b" ", target, b" HTTP/1.1\r\n"].concat()
                );
            }
        }
    }

    #[test]
    fn refused_lines_do_not_change_the_existing_buffer() {
        let mut long = vec![b'a'; 8193];
        long[0] = b'/';
        for target in [
            b"".as_slice(),
            b"https://attacker.test/",
            b"//attacker.test/",
            b"/ok\r\nHost: attacker.test",
            b"/ok HTTP/1.1\r\nX: injected",
            b"/fragment#x",
            b"/tab\t",
            &[b'/', 255],
            &long,
        ] {
            let mut output = b"existing\r\n".to_vec();
            let original = output.clone();
            assert!(append_line(&mut output, b"GET", target).is_err());
            assert_eq!(output, original);
        }
        for method in [b"".as_slice(), b"CONNECT", b"TRACE", b"get", b"GET\r\nX: y"] {
            let mut output = b"existing\r\n".to_vec();
            let original = output.clone();
            assert!(append_line(&mut output, method, b"/safe").is_err());
            assert_eq!(output, original);
        }
    }
}

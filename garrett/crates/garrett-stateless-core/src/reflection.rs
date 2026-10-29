//! Exact literal credential reflection checks over borrowed bytes. These do not
//! detect semantic leakage; `proxy_http` checks each encoding it withholds.

pub fn matches_at(value: &[u8], secret: &[u8], start: usize) -> bool {
    if start > value.len() || secret.len() > value.len() - start {
        return false;
    }
    value[start..start + secret.len()] == *secret
}

// len is modeled by the pinned extractor; slice::is_empty is not needed.
#[allow(clippy::len_zero)]
pub fn contains(value: &[u8], secret: &[u8]) -> bool {
    if secret.len() == 0 || secret.len() > value.len() {
        return false;
    }
    let last = value.len() - secret.len();
    let mut start = 0;
    while start <= last {
        if matches_at(value, secret, start) {
            return true;
        }
        start += 1;
    }
    false
}

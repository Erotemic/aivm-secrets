//! The upstream request: the field filter, the deny rules and the exact encoder.
use super::*;

#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct DenyRule {
    /// Empty means any method.
    pub method: Vec<u8>,
    pub path: Vec<u8>,
}

/// Guest fields never forwarded: credentials of any scheme, proxy and
/// hop-by-hop fields, framing, negotiation the proxy owns, method overrides
/// (which could route around method-specific deny rules) and ranges (which
/// could fetch an echoed credential in pieces).
pub fn dropped(field: &Field) -> bool {
    name_is(field, b"authorization")
        || name_is(field, b"x-api-key")
        || name_is(field, b"proxy-authorization")
        || name_is(field, b"proxy-connection")
        || name_is(field, b"connection")
        || name_is(field, b"keep-alive")
        || name_is(field, b"transfer-encoding")
        || name_is(field, b"content-length")
        || name_is(field, b"te")
        || name_is(field, b"trailer")
        || name_is(field, b"upgrade")
        || name_is(field, b"host")
        || name_is(field, b"accept-encoding")
        || name_is(field, b"cookie")
        || name_is(field, b"x-http-method-override")
        || name_is(field, b"x-method-override")
        || name_is(field, b"x-http-method")
        || name_is(field, b"range")
        || name_is(field, b"if-range")
}

pub fn forwarded(fields: &[Field]) -> Vec<Field> {
    let mut out = Vec::new();
    for field in fields {
        if !dropped(field) {
            out.push(Field {
                name: field.name.clone(),
                value: field.value.clone(),
            });
        }
    }
    out
}

/// A rule matches its exact path, the same path with a trailing slash, or,
/// for a `/`-ending prefix, the prefix without its slash and everything
/// under it.
#[allow(clippy::len_zero)]
/// An empty rule method matches any method.
#[allow(clippy::len_zero)]
pub fn method_ok(rule_method: &[u8], method: &[u8]) -> bool {
    rule_method.len() == 0 || rule_method == method
}

/// `path` is `prefix` followed by exactly one `/`.
pub fn plus_slash(prefix: &[u8], path: &[u8]) -> bool {
    path.len() > prefix.len()
        && path.len() - prefix.len() == 1
        && path[prefix.len()] == b'/'
        && &path[..prefix.len()] == prefix
}

/// `rule_path` ends with `/`.
pub fn ends_with_slash(rule_path: &[u8]) -> bool {
    rule_path.len() > 0 && rule_path[rule_path.len() - 1] == b'/'
}

/// The rule path matches exactly, with one added trailing `/`, and, for a
/// rule path ending in `/`, without that `/` or as a prefix.
pub fn path_matches(rule_path: &[u8], path: &[u8]) -> bool {
    path == rule_path
        || plus_slash(rule_path, path)
        || (ends_with_slash(rule_path)
            && (plus_slash(path, rule_path)
                || (path.len() >= rule_path.len() && &path[..rule_path.len()] == rule_path)))
}

pub fn rule_matches(rule: &DenyRule, method: &[u8], path: &[u8]) -> bool {
    method_ok(&rule.method, method) && path_matches(&rule.path, path)
}

pub fn denied(rules: &[DenyRule], method: &[u8], path: &[u8]) -> bool {
    for rule in rules {
        if rule_matches(rule, method, path) {
            return true;
        }
    }
    false
}

/// A field that is one header line: a non-empty token name and a value of
/// visible ASCII, SP and HTAB (so no CR, LF or NUL).
#[allow(clippy::len_zero)]
pub fn clean_field(field: &Field) -> bool {
    field.name.len() != 0
        && all_token(&field.name, field.name.len())
        && all_value(&field.value, 0, field.value.len())
}

pub fn clean_fields(fields: &[Field]) -> bool {
    for field in fields {
        if !clean_field(field) {
            return false;
        }
    }
    true
}

pub fn append_fields(output: &mut Vec<u8>, fields: &[Field]) {
    for field in fields {
        output.extend_from_slice(&field.name);
        output.extend_from_slice(b": ");
        output.extend_from_slice(&field.value);
        output.extend_from_slice(b"\r\n");
    }
}

pub fn needs_length(request: &Request) -> bool {
    let post: &[u8] = b"POST";
    let put: &[u8] = b"PUT";
    let patch: &[u8] = b"PATCH";
    let method: &[u8] = &request.method;
    request.body.len() > 0 || method == post || method == put || method == patch
}

/// The canonical upstream request for an accepted guest request.
///
/// Refuses a deny-listed request or an invalid credential before touching
/// `output`. The credential enters `output` only through
/// `http_auth::append_header`, after the filtered guest fields.
pub fn encode_upstream(
    output: &mut Vec<u8>,
    request: &Request,
    host: &[u8],
    rules: &[DenyRule],
    secret: &[u8],
    authentication: &Authentication,
) -> Result<(), Refusal> {
    // Re-validate everything the parser should already have ensured, so the
    // framing of the upstream request does not depend on the parser.
    if !valid_method(&request.method) || !check_target(&request.target) {
        return Err(Refusal::InvalidRequest);
    }
    let fields = forwarded(&request.fields);
    if !clean_fields(&fields) {
        return Err(Refusal::InvalidRequest);
    }
    let end = path_end(&request.target);
    if denied(rules, &request.method, &request.target[..end]) {
        return Err(Refusal::Denied);
    }
    if !http_auth::valid_credential(secret) {
        return Err(Refusal::InvalidCredential);
    }
    output.extend_from_slice(&request.method);
    output.extend_from_slice(b" ");
    output.extend_from_slice(&request.target);
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(host);
    output.extend_from_slice(b"\r\n");
    append_fields(output, &fields);
    match http_auth::append_header(output, secret, authentication) {
        Ok(()) => (),
        Err(_) => return Err(Refusal::InvalidCredential),
    }
    output.extend_from_slice(b"Accept-Encoding: identity\r\nConnection: close\r\n");
    if needs_length(request) {
        output.extend_from_slice(b"Content-Length: ");
        http_wire::append_decimal(output, request.body.len());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    Ok(())
}

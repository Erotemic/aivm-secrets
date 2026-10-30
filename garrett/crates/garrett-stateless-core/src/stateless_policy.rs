//! Operation authorization for the `garrett-stateless-v1` proxy
//! (`docs/garrett-stateless-v1.md` section 11.1).
//!
//! An [`OperationPolicy`] is static configuration, decided by a pure
//! function of the surrogate's authenticated claims and the request's
//! [`Operation`]: its method, path and body length. It never sees the
//! credential, the surrogate or any upstream bytes, and it reads no state, so
//! it keeps the proxy stateless. `stateless_proxy::decide` consults it after
//! the surrogate is authenticated and before the credential is decrypted.
//!
//! There are exactly two policies:
//!
//! * [`Unrestricted`] is Garrett's proxy: any operation (the route's deny
//!   rules still apply in the encoder);
//! * [`ReadOnly`] permits only `GET` and `HEAD` without a body, for an
//!   allowed provider (the destination) and path (the resource).

use crate::proxy_http::{method_ok, path_end, path_matches, Request};
use crate::stateless::SurrogateClaims;

/// What a policy sees of a request: never its credential-bearing fields.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct Operation {
    pub method: Vec<u8>,
    /// The request target up to any `?`.
    pub path: Vec<u8>,
    pub body: usize,
}

/// The operation a request asks for.
pub fn operation_of(request: &Request) -> Operation {
    let end = path_end(&request.target);
    Operation {
        method: request.method.clone(),
        path: request.target[..end].to_vec(),
        body: request.body.len(),
    }
}

/// A static operation policy. `permits` must be a function of its
/// arguments alone.
pub trait OperationPolicy {
    fn permits(&self, claims: &SurrogateClaims, operation: &Operation) -> bool;
}

/// Garrett's proxy: every operation is authorized by the surrogate alone.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct Unrestricted;

impl OperationPolicy for Unrestricted {
    fn permits(&self, _claims: &SurrogateClaims, _operation: &Operation) -> bool {
        true
    }
}

/// One allowed resource: a provider, a method (empty means `GET` or
/// `HEAD`) and a path, matched like a deny rule's path (`path_matches`).
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct Resource {
    pub provider: Vec<u8>,
    pub method: Vec<u8>,
    pub path: Vec<u8>,
}

/// The constrained read-only proxy.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct ReadOnly {
    pub resources: Vec<Resource>,
}

/// `GET` or `HEAD`.
pub fn read_method(method: &[u8]) -> bool {
    let get: &[u8] = b"GET";
    let head: &[u8] = b"HEAD";
    method == get || method == head
}

pub fn resource_allows(resource: &Resource, provider: &[u8], operation: &Operation) -> bool {
    let own: &[u8] = &resource.provider;
    own == provider
        && method_ok(&resource.method, &operation.method)
        && path_matches(&resource.path, &operation.path)
}

/// Some resource allows the operation at `provider`.
pub fn any_allows(resources: &[Resource], provider: &[u8], operation: &Operation) -> bool {
    for resource in resources {
        if resource_allows(resource, provider, operation) {
            return true;
        }
    }
    false
}

impl OperationPolicy for ReadOnly {
    fn permits(&self, claims: &SurrogateClaims, operation: &Operation) -> bool {
        read_method(&operation.method)
            && operation.body == 0
            && any_allows(&self.resources, &claims.provider, operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(provider: &[u8]) -> SurrogateClaims {
        SurrogateClaims {
            issuer: b"iss".to_vec(),
            audience: b"aud".to_vec(),
            subject: b"agent".to_vec(),
            token_id: b"j".to_vec(),
            provider: provider.to_vec(),
            certificate: b"PEER".to_vec(),
            issued_at: 100,
            expires_at: 200,
            renew_until: 300,
        }
    }

    fn op(method: &str, path: &str, body: usize) -> Operation {
        Operation {
            method: method.as_bytes().to_vec(),
            path: path.as_bytes().to_vec(),
            body,
        }
    }

    #[test]
    fn read_only_restricts_method_resource_destination_and_body() {
        let policy = ReadOnly {
            resources: vec![
                Resource {
                    provider: b"api".to_vec(),
                    method: Vec::new(),
                    path: b"/user".to_vec(),
                },
                Resource {
                    provider: b"api".to_vec(),
                    method: b"GET".to_vec(),
                    path: b"/repos/".to_vec(),
                },
            ],
        };
        let api = claims(b"api");
        assert!(policy.permits(&api, &op("GET", "/user", 0)));
        assert!(policy.permits(&api, &op("HEAD", "/user", 0)));
        assert!(policy.permits(&api, &op("GET", "/repos/a/b", 0)));
        assert!(!policy.permits(&api, &op("HEAD", "/repos/a/b", 0)));
        assert!(!policy.permits(&api, &op("POST", "/user", 0)));
        assert!(!policy.permits(&api, &op("GET", "/user", 1)));
        assert!(!policy.permits(&api, &op("GET", "/admin", 0)));
        assert!(!policy.permits(&api, &op("GET", "/users", 0)));
        assert!(!policy.permits(&claims(b"other"), &op("GET", "/user", 0)));
        // A method rule cannot widen read-only.
        let wide = ReadOnly {
            resources: vec![Resource {
                provider: b"api".to_vec(),
                method: b"DELETE".to_vec(),
                path: b"/".to_vec(),
            }],
        };
        assert!(!wide.permits(&api, &op("DELETE", "/user", 0)));
        assert!(Unrestricted.permits(&api, &op("DELETE", "/user", 9)));
    }
}

//! Route-bound request bytes and immutable endpoint returned only on encoding
//! success. Native JSON/String/header conversion, DNS and TLS remain adapters.
#![allow(clippy::ptr_arg)]
use crate::{credential_use::Route, http_wire};

pub struct Fields {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub accept: Vec<u8>,
    pub headers: Vec<http_wire::Header>,
}

/// Only the successful route-bound encoder constructs this destination.
pub struct Endpoint {
    host: Vec<u8>,
    port: u16,
}
impl Endpoint {
    pub fn host(&self) -> &Vec<u8> {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

fn head(route: &Route, fields: Fields) -> Result<http_wire::Head, http_wire::EncodingDenial> {
    if route.port <= 0 || route.port > 65535 {
        return Err(http_wire::EncodingDenial::InvalidRequest);
    }
    Ok(http_wire::Head {
        method: fields.method,
        target: fields.target,
        host: route.host.clone(),
        port: route.port as u16,
        accept: fields.accept,
        headers: fields.headers,
    })
}

/// The caller retains its zeroizing buffer on every failure. Endpoint getters
/// expose exactly the Host/port passed to the complete checked wire encoder.
pub fn append(
    output: &mut Vec<u8>,
    route: &Route,
    fields: Fields,
    secret: &[u8],
    body: Option<&[u8]>,
) -> Result<Endpoint, http_wire::EncodingDenial> {
    let head = match head(route, fields) {
        Ok(head) => head,
        Err(error) => return Err(error),
    };
    match http_wire::append_request(output, &head, secret, &route.authentication, body) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(Endpoint {
        host: head.host,
        port: head.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_use::Authentication;

    fn route(port: i64, authentication: Authentication) -> Route {
        Route {
            host: b"api.example.org".to_vec(),
            port,
            path: b"/not-the-selected-target".to_vec(),
            authentication,
        }
    }
    fn fields() -> Fields {
        Fields {
            method: b"POST".to_vec(),
            target: b"/graphql?source=guest".to_vec(),
            accept: b"application/json".to_vec(),
            headers: vec![http_wire::Header {
                name: b"X-Request-ID".to_vec(),
                value: b"synthetic-7".to_vec(),
            }],
        }
    }
    #[test]
    fn exact_route_authentication_and_endpoint_share_complete_request_bytes() {
        for (authentication, auth) in [
            (
                Authentication::Bearer,
                b"Authorization: Bearer TOKEN\r\n".as_slice(),
            ),
            (Authentication::ApiKey, b"X-API-Key: TOKEN\r\n".as_slice()),
        ] {
            let mut output = b"prefix\0".to_vec();
            let route = route(9443, authentication);
            let body = b"{}\0\xff";
            let endpoint = append(&mut output, &route, fields(), b"TOKEN", Some(body))
                .ok()
                .unwrap();
            assert_eq!(endpoint.host(), &route.host);
            assert_eq!(endpoint.port(), 9443);
            let expected = [b"prefix\0POST /graphql?source=guest HTTP/1.1\r\nHost: api.example.org:9443\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\nX-Request-ID: synthetic-7\r\n".as_slice(),auth,b"Content-Type: application/json\r\nContent-Length: 4\r\n\r\n",body].concat();
            assert_eq!(output, expected);
        }
    }
    #[test]
    fn invalid_route_or_encoder_input_cannot_change_buffer_or_return_endpoint() {
        for port in [i64::MIN, -1, 0, 65536, i64::MAX] {
            let mut output = b"preserved\0".to_vec();
            assert!(matches!(
                append(
                    &mut output,
                    &route(port, Authentication::Bearer),
                    fields(),
                    b"TOKEN",
                    None
                ),
                Err(http_wire::EncodingDenial::InvalidRequest)
            ));
            assert_eq!(output, b"preserved\0");
        }
        for kind in 0..4 {
            let mut route = route(443, Authentication::Bearer);
            let mut fields = fields();
            let mut secret = b"TOKEN".as_slice();
            match kind {
                0 => route.host = b"other\r\nHost: attack".to_vec(),
                1 => fields.target = b"//attacker/".to_vec(),
                2 => fields.headers[0].name = b"Host".to_vec(),
                _ => secret = b"TOKEN\r\nInjected: yes",
            }
            let mut output = b"preserved\0".to_vec();
            assert!(append(&mut output, &route, fields, secret, None).is_err());
            assert_eq!(output, b"preserved\0");
        }
    }
}

//! Production-called public error table and guest denial frame.
//! Every guest-visible failure the bridge emits is built here from one of
//! these fixed variants: a constant code and constant message, never error
//! text, provider data or credential bytes. The native adapter maps its
//! `Error` enum one-to-one onto `PublicError` and calls `denial_frame`.

use crate::json_wire::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicError {
    InvalidCapability,
    InvalidPolicy,
    ResourceMismatch,
    InvalidRequest,
    Denied,
    Unreachable,
    UpstreamResponse,
    UpstreamRejected,
    UpstreamError,
    InternalError,
    UnsafeFile,
    OutcomeUnknown,
    Exhausted,
    Revoked,
    CredentialSource,
    Expired,
    AuthorizationDenied,
}

impl PublicError {
    /// The host-side spelling of the code (the same text as `code`).
    pub fn name(self) -> &'static str {
        match self {
            PublicError::InvalidCapability => "invalid_capability",
            PublicError::InvalidPolicy => "invalid_policy",
            PublicError::ResourceMismatch => "resource_mismatch",
            PublicError::InvalidRequest => "invalid_request",
            PublicError::Denied => "denied",
            PublicError::Unreachable => "unreachable",
            PublicError::UpstreamResponse => "upstream_response",
            PublicError::UpstreamRejected => "upstream_rejected",
            PublicError::UpstreamError => "upstream_error",
            PublicError::InternalError => "internal_error",
            PublicError::UnsafeFile => "unsafe_file",
            PublicError::OutcomeUnknown => "outcome_unknown",
            PublicError::Exhausted => "exhausted",
            PublicError::Revoked => "revoked",
            PublicError::CredentialSource | PublicError::AuthorizationDenied => "credential_source",
            PublicError::Expired => "expired",
        }
    }
}

/// The public error of a selected-release refusal.
pub fn of_release(denial: crate::selected_release::Denial) -> PublicError {
    match denial {
        crate::selected_release::Denial::Denied => PublicError::Denied,
        crate::selected_release::Denial::UpstreamResponse => PublicError::UpstreamResponse,
        crate::selected_release::Denial::InvalidRequest => PublicError::InvalidRequest,
    }
}

/// The public error of a credential-use refusal.
pub fn of_use(denial: crate::credential_use::UseDenial) -> PublicError {
    match denial {
        crate::credential_use::UseDenial::InvalidCapability => PublicError::InvalidCapability,
        crate::credential_use::UseDenial::Denied => PublicError::Denied,
        crate::credential_use::UseDenial::Revoked => PublicError::Revoked,
        crate::credential_use::UseDenial::Upstream => PublicError::UpstreamResponse,
    }
}

/// The public error of a provider status refusal: 4xx is `upstream_rejected`,
/// any other failure `upstream_error`, an unusable status line or a partial
/// response `upstream_response`.
pub fn of_status(denial: crate::provider_status::StatusDenial) -> PublicError {
    match denial {
        crate::provider_status::StatusDenial::Malformed => PublicError::UpstreamResponse,
        crate::provider_status::StatusDenial::Partial => PublicError::UpstreamResponse,
        crate::provider_status::StatusDenial::Rejected => PublicError::UpstreamRejected,
        crate::provider_status::StatusDenial::Failed => PublicError::UpstreamError,
    }
}

/// Stable machine-readable code. `AuthorizationDenied` deliberately shares
/// `credential_source` so the guest cannot distinguish the two causes.
pub fn code(error: PublicError) -> Vec<u8> {
    let mut out = Vec::new();
    match error {
        PublicError::InvalidCapability => out.extend_from_slice(b"invalid_capability"),
        PublicError::InvalidPolicy => out.extend_from_slice(b"invalid_policy"),
        PublicError::ResourceMismatch => out.extend_from_slice(b"resource_mismatch"),
        PublicError::InvalidRequest => out.extend_from_slice(b"invalid_request"),
        PublicError::Denied => out.extend_from_slice(b"denied"),
        PublicError::Unreachable => out.extend_from_slice(b"unreachable"),
        PublicError::UpstreamResponse => out.extend_from_slice(b"upstream_response"),
        PublicError::UpstreamRejected => out.extend_from_slice(b"upstream_rejected"),
        PublicError::UpstreamError => out.extend_from_slice(b"upstream_error"),
        PublicError::InternalError => out.extend_from_slice(b"internal_error"),
        PublicError::UnsafeFile => out.extend_from_slice(b"unsafe_file"),
        PublicError::OutcomeUnknown => out.extend_from_slice(b"outcome_unknown"),
        PublicError::Exhausted => out.extend_from_slice(b"exhausted"),
        PublicError::Revoked => out.extend_from_slice(b"revoked"),
        PublicError::CredentialSource => out.extend_from_slice(b"credential_source"),
        PublicError::AuthorizationDenied => out.extend_from_slice(b"credential_source"),
        PublicError::Expired => out.extend_from_slice(b"expired"),
    }
    out
}

/// Fixed human-readable message; most failures share the generic one.
pub fn message(error: PublicError) -> Vec<u8> {
    let mut out = Vec::new();
    match error {
        PublicError::InvalidCapability => out.extend_from_slice(b"Capability authentication failed."),
        PublicError::InvalidRequest => out.extend_from_slice(b"Malformed or unsupported request."),
        PublicError::Denied => out.extend_from_slice(b"Operation is outside the granted authority."),
        PublicError::UnsafeFile => out.extend_from_slice(b"Host file ownership, permissions, or type is unsafe."),
        PublicError::OutcomeUnknown => {
            out.extend_from_slice(b"A dispatched request may have completed; reconcile before retrying.")
        }
        _ => out.extend_from_slice(b"Broker failed closed."),
    }
    out
}

/// ASCII bytes as JSON text scalars. The table above is ASCII only.
fn text(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        out.push(bytes[i] as u32);
        i += 1;
    }
    out
}

/// The exact guest denial value
/// `{"error":{"code":..,"message":..},"ok":false,"version":1}`, with keys in
/// the same order the native serde map previously produced.
pub fn denial(error: PublicError) -> Value {
    Value::Object(vec![
        (
            text(b"error"),
            Value::Object(vec![
                (text(b"code"), Value::Text(text(&code(error)))),
                (text(b"message"), Value::Text(text(&message(error)))),
            ]),
        ),
        (text(b"ok"), Value::Boolean(false)),
        (text(b"version"), Value::Number(b"1".to_vec())),
    ])
}

/// The bridge's only failure-frame constructor.
pub fn denial_frame(
    error: PublicError,
    limit: usize,
) -> Result<crate::guest_frame::Frame, crate::guest_frame::FrameDenial> {
    crate::json_wire::prepare(&denial(error), limit)
}

/// The bridge's frame for one answer: a reply is framed from its wire value;
/// a failure is the fixed denial line of its public code. This is the whole
/// guest-visible frame choice (`GuestFrame::from_answer` only maps types).
pub fn answer_frame(
    answer: Result<&crate::json_wire::Value, PublicError>,
    limit: usize,
) -> Result<crate::guest_frame::Frame, crate::guest_frame::FrameDenial> {
    match answer {
        Ok(value) => crate::json_wire::prepare(value, limit),
        Err(error) => denial_frame(error, limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ALL: [PublicError; 17] = [
        PublicError::InvalidCapability, PublicError::InvalidPolicy,
        PublicError::ResourceMismatch, PublicError::InvalidRequest, PublicError::Denied,
        PublicError::Unreachable, PublicError::UpstreamResponse,
        PublicError::UpstreamRejected, PublicError::UpstreamError,
        PublicError::InternalError, PublicError::UnsafeFile, PublicError::OutcomeUnknown,
        PublicError::Exhausted, PublicError::Revoked, PublicError::CredentialSource,
        PublicError::Expired, PublicError::AuthorizationDenied,
    ];

    // The table is printable ASCII that JSON never needs to escape, so the
    // guest sees the literal text.
    #[test]
    fn table_is_unescaped_printable_ascii() {
        for error in ALL {
            for byte in code(error).into_iter().chain(message(error)) {
                assert!((0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\');
            }
        }
    }

    #[test]
    fn denial_frame_is_the_fixed_json_line() {
        let mut frame = denial_frame(PublicError::Denied, 4096).ok().unwrap();
        struct Sink(Vec<u8>);
        impl crate::guest_frame::Writer for Sink {
            type Error = ();
            const ALREADY_ATTEMPTED: () = ();
            fn write_frame(&mut self, wire: &[u8]) -> Result<(), ()> {
                self.0.extend_from_slice(wire);
                Ok(())
            }
        }
        let mut sink = Sink(Vec::new());
        frame.send(&mut sink).unwrap();
        assert_eq!(
            sink.0,
            b"{\"error\":{\"code\":\"denied\",\"message\":\"Operation is outside the granted authority.\"},\"ok\":false,\"version\":1}\n"
        );
    }
}

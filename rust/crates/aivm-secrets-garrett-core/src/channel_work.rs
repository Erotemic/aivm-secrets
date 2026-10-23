//! Source-owned provider channel lifecycle around native primitives.
//!
//! `Submitting` is the provider work the production dispatch actually runs.
//! It holds the credential; native request primitives never receive it. It
//! encodes the request with the extracted `provider_wire::append`, checks the
//! target for credential reflection, constructs the channel, sends with the
//! extracted `Channel::submit`, and mints the response-gate token before the
//! native parser sees anything. The native work supplies the request fields,
//! a zeroizing wrapper for the encoded bytes, the connection and the parser,
//! plus the dispatch callbacks it already owned (audit, freshness, reservation).
use crate::credential_use::Route;
use crate::disclosure::Json;
use crate::http_wire::EncodingDenial;
use crate::provider_wire::{Endpoint, Fields};
use crate::manifest::AdmissionStamp;
use crate::provider_io::{Channel, RouteWork, WireBytes, Writer};
use crate::read_transition::Phase;
use crate::response_gate::{self, Released};
use crate::{dispatch, provider_exchange};

pub trait ChannelWork {
    type Body: WireBytes;
    type Writer: Writer<Error = Self::Error>;
    type Meta;
    type Output;
    type Error;
    const INVALID_TRANSITION: Self::Error;
    const INVALID_POLICY: Self::Error;
    const OUTCOME_UNKNOWN: Self::Error;
    /// The provider target would reflect the credential.
    const REFLECTED: Self::Error;

    fn effect_write(&self) -> bool;
    fn prepare(&mut self) -> Result<(), Self::Error>;
    fn configure(&mut self, keyed_write: bool) -> Result<(), Self::Error>;
    fn check(&mut self) -> Result<(), Self::Error>;
    fn reserve(&mut self) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn audit_route(&mut self, route: &Route, phase: Phase) -> Result<(), Self::Error>;
    /// Host-selected request fields and optional JSON body (no credential).
    fn request_fields(&mut self) -> Result<RequestParts, Self::Error>;
    /// The provider target, for the credential-reflection check.
    fn target(&self) -> Vec<u8>;
    /// Take ownership of the encoded request (zeroized when dropped).
    fn wrap_body(&mut self, encoded: Vec<u8>) -> Self::Body;
    fn encoding_error(&mut self, denial: EncodingDenial) -> Self::Error;
    /// The authenticated connection to the encoder's endpoint.
    fn connect(&mut self, endpoint: &Endpoint) -> Result<(Self::Writer, Self::Meta), Self::Error>;
    /// Parse a response; the token exists only after a successful submit.
    fn parse(
        &mut self,
        released: Released<Self::Body, Self::Writer, Self::Meta>,
    ) -> Result<Self::Output, Self::Error>;
}

pub struct RequestParts {
    pub fields: Fields,
    pub body: Option<Vec<u8>>,
}

/// The extracted request encoder over the host fields, route and credential.
pub fn encode(
    output: &mut Vec<u8>,
    route: &Route,
    parts: RequestParts,
    secret: &Vec<u8>,
) -> Result<Endpoint, EncodingDenial> {
    match parts.body {
        Some(bytes) => crate::provider_wire::append(output, route, parts.fields, secret, Some(&bytes)),
        None => crate::provider_wire::append(output, route, parts.fields, secret, None),
    }
}

pub struct Submitting<'a, W: ChannelWork> {
    work: W,
    secret: &'a Vec<u8>,
}
impl<'a, W: ChannelWork> Submitting<'a, W> {
    pub fn new(work: W, secret: &'a Vec<u8>) -> Self {
        Self { work, secret }
    }
}

impl<W: ChannelWork> provider_exchange::Provider for Submitting<'_, W> {
    type Channel = Channel<W::Body, W::Writer, W::Meta>;
    type Output = W::Output;
    type Error = W::Error;
    const INVALID_POLICY: Self::Error = W::INVALID_POLICY;
    const OUTCOME_UNKNOWN: Self::Error = W::OUTCOME_UNKNOWN;

    /// Only the routed setup may open a channel.
    fn setup(&mut self) -> Result<Self::Channel, Self::Error> {
        Err(W::INVALID_TRANSITION)
    }
    /// Only `current_admission::Bound` may supply admission.
    fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
        Err(W::INVALID_TRANSITION)
    }
    fn send(&mut self, channel: &mut Self::Channel) -> Result<(), Self::Error> {
        channel.submit()
    }
    fn receive(&mut self, channel: Self::Channel) -> Result<Self::Output, Self::Error> {
        match response_gate::receive(channel) {
            Ok(released) => self.work.parse(released),
            Err(error) => Err(error),
        }
    }
}

impl<W: ChannelWork> dispatch::Work for Submitting<'_, W> {
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;
    fn effect_write(&self) -> bool {
        self.work.effect_write()
    }
    /// Native preparation, then the extracted target reflection check.
    fn prepare(&mut self) -> Result<(), Self::Error> {
        match self.work.prepare() {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        let target = Json::Object(vec![(b"target".to_vec(), Json::Text(self.work.target()))]);
        match crate::selected_release::checked(target, self.secret) {
            Ok(_) => Ok(()),
            Err(_) => Err(W::REFLECTED),
        }
    }
    /// Unrouted audit is refused; `Routed` audits through `audit_route`.
    fn audit(&mut self, _phase: Phase) -> Result<(), Self::Error> {
        Err(W::INVALID_TRANSITION)
    }
    fn configure(&mut self, keyed_write: bool) -> Result<(), Self::Error> {
        self.work.configure(keyed_write)
    }
    fn check(&mut self) -> Result<(), Self::Error> {
        self.work.check()
    }
    fn reserve(&mut self) -> Result<(), Self::Error> {
        self.work.reserve()
    }
    fn finish(&mut self) -> Result<(), Self::Error> {
        self.work.finish()
    }
}

impl<W: ChannelWork> RouteWork<Channel<W::Body, W::Writer, W::Meta>, W::Error>
    for Submitting<'_, W>
{
    /// Encode the request for the captured route with the credential, then
    /// connect to the encoder's endpoint; the channel owns both.
    fn setup_route(
        &mut self,
        route: &Route,
    ) -> Result<Channel<W::Body, W::Writer, W::Meta>, W::Error> {
        let parts = match self.work.request_fields() {
            Ok(parts) => parts,
            Err(error) => return Err(error),
        };
        let mut encoded = Vec::new();
        let endpoint = match encode(&mut encoded, route, parts, self.secret) {
            Ok(endpoint) => endpoint,
            Err(denial) => return Err(self.work.encoding_error(denial)),
        };
        let body = self.work.wrap_body(encoded);
        let (writer, meta) = match self.work.connect(&endpoint) {
            Ok(parts) => parts,
            Err(error) => return Err(error),
        };
        Ok(Channel::new(body, writer, meta))
    }
    fn audit_route(&mut self, route: &Route, phase: Phase) -> Result<(), W::Error> {
        self.work.audit_route(route, phase)
    }
}

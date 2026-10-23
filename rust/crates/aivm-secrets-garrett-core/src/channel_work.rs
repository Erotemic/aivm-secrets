//! Source-owned provider channel lifecycle around three native primitives.
//!
//! `Submitting` is the provider work the production dispatch actually runs.
//! It constructs the provider channel from the encoded request and the
//! connection, sends with the extracted `Channel::submit`, and mints the
//! response-gate token before the native parser sees anything. The native
//! work supplies only the request body, the connection and the parser, plus
//! the dispatch callbacks it already owned (audit, freshness, reservation).
use crate::credential_use::Route;
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

    fn effect_write(&self) -> bool;
    fn prepare(&mut self) -> Result<(), Self::Error>;
    fn configure(&mut self, keyed_write: bool) -> Result<(), Self::Error>;
    fn check(&mut self) -> Result<(), Self::Error>;
    fn reserve(&mut self) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn audit_route(&mut self, route: &Route, phase: Phase) -> Result<(), Self::Error>;
    /// The credential-bearing request bytes for this route.
    fn request_body(&mut self, route: &Route) -> Result<Self::Body, Self::Error>;
    /// The authenticated connection the request will be written to.
    fn connect(&mut self, route: &Route) -> Result<(Self::Writer, Self::Meta), Self::Error>;
    /// Parse a response; the token exists only after a successful submit.
    fn parse(
        &mut self,
        released: Released<Self::Body, Self::Writer, Self::Meta>,
    ) -> Result<Self::Output, Self::Error>;
}

pub struct Submitting<W: ChannelWork> {
    work: W,
}
impl<W: ChannelWork> Submitting<W> {
    pub fn new(work: W) -> Self {
        Self { work }
    }
}

impl<W: ChannelWork> provider_exchange::Provider for Submitting<W> {
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

impl<W: ChannelWork> dispatch::Work for Submitting<W> {
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;
    fn effect_write(&self) -> bool {
        self.work.effect_write()
    }
    fn prepare(&mut self) -> Result<(), Self::Error> {
        self.work.prepare()
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

impl<W: ChannelWork> RouteWork<Channel<W::Body, W::Writer, W::Meta>, W::Error> for Submitting<W> {
    /// Encode the request before connecting; the channel owns both.
    fn setup_route(
        &mut self,
        route: &Route,
    ) -> Result<Channel<W::Body, W::Writer, W::Meta>, W::Error> {
        let body = match self.work.request_body(route) {
            Ok(body) => body,
            Err(error) => return Err(error),
        };
        let (writer, meta) = match self.work.connect(route) {
            Ok(parts) => parts,
            Err(error) => return Err(error),
        };
        Ok(Channel::new(body, writer, meta))
    }
    fn audit_route(&mut self, route: &Route, phase: Phase) -> Result<(), W::Error> {
        self.work.audit_route(route, phase)
    }
}

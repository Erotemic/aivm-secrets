//! Current manifest admission with a fixed identity/credential-use context.
//! Native primitives cannot replace this borrowed context. Their clock,
//! revocation, lease, coordination and other I/O semantics remain contracts.
use crate::{
    credential_use::{UseClaims, UseDenial, UseGrant},
    manifest::{self, AdmissionStamp},
    Claims, Expectation,
};

pub struct Context<'a> {
    identity: &'a Claims,
    expected: &'a Expectation,
    peer: &'a Vec<u8>,
    claims: &'a UseClaims,
    grant: &'a UseGrant,
    operation: &'a Vec<u8>,
    write: bool,
    allowed: bool,
}
impl<'a> Context<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: &'a Claims,
        expected: &'a Expectation,
        peer: &'a Vec<u8>,
        claims: &'a UseClaims,
        grant: &'a UseGrant,
        operation: &'a Vec<u8>,
        write: bool,
        allowed: bool,
    ) -> Self {
        Self {
            identity,
            expected,
            peer,
            claims,
            grant,
            operation,
            write,
            allowed,
        }
    }
    pub(crate) fn route(&self) -> &crate::credential_use::Route {
        &self.grant.route
    }
    pub fn current<C: Checks>(&self, checks: &mut C) -> Result<AdmissionStamp, C::Error> {
        match checks.coordination() {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        let now = match checks.clock() {
            Ok(now) => now,
            Err(error) => return Err(error),
        };
        match checks.control(now) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        match checks.lease(now) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        match crate::present(self.identity, self.expected, self.peer, now) {
            Ok(()) => (),
            Err(_) => return Err(C::INVALID_CAPABILITY),
        }
        let elapsed = match checks.elapsed() {
            Ok(elapsed) => elapsed,
            Err(error) => return Err(error),
        };
        match manifest::current(
            self.claims,
            self.grant,
            self.operation,
            self.operation,
            self.write,
            self.allowed,
            now,
            elapsed,
        ) {
            Ok(stamp) => Ok(stamp),
            Err(error) => Err(C::use_error(error)),
        }
    }
}

pub trait Checks {
    type Error;
    const INVALID_CAPABILITY: Self::Error;
    fn coordination(&mut self) -> Result<(), Self::Error>;
    fn clock(&mut self) -> Result<i64, Self::Error>;
    fn control(&mut self, now: i64) -> Result<(), Self::Error>;
    fn lease(&mut self, now: i64) -> Result<(), Self::Error>;
    fn elapsed(&mut self) -> Result<i64, Self::Error>;
    fn use_error(error: UseDenial) -> Self::Error;
}

/// The actual provider driver checks this fixed context. The native raw
/// adapter's recheck is never used; other primitive post-states are retained.
pub struct Bound<'a, W: crate::dispatch::Work, C: Checks<Error = W::Error>> {
    context: &'a Context<'a>,
    work: W,
    checks: C,
}
impl<'a, W: crate::dispatch::Work, C: Checks<Error = W::Error>> Bound<'a, W, C> {
    pub fn new(context: &'a Context<'a>, work: W, checks: C) -> Self {
        Self {
            context,
            work,
            checks,
        }
    }
}
impl<W: crate::dispatch::Work, C: Checks<Error = W::Error>> crate::provider_exchange::Provider
    for Bound<'_, W, C>
{
    type Channel = W::Channel;
    type Output = W::Output;
    type Error = W::Error;
    const INVALID_POLICY: Self::Error = W::INVALID_POLICY;
    const OUTCOME_UNKNOWN: Self::Error = W::OUTCOME_UNKNOWN;
    fn setup(&mut self) -> Result<Self::Channel, Self::Error> {
        self.work.setup()
    }
    fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
        self.context.current(&mut self.checks)
    }
    fn send(&mut self, channel: &mut Self::Channel) -> Result<(), Self::Error> {
        self.work.send(channel)
    }
    fn receive(&mut self, channel: Self::Channel) -> Result<Self::Output, Self::Error> {
        self.work.receive(channel)
    }
}
impl<W: crate::dispatch::Work, C: Checks<Error = W::Error>> crate::dispatch::Work
    for Bound<'_, W, C>
{
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;
    fn effect_write(&self) -> bool {
        self.work.effect_write()
    }
    fn prepare(&mut self) -> Result<(), Self::Error> {
        self.work.prepare()
    }
    fn audit(&mut self, phase: crate::read_transition::Phase) -> Result<(), Self::Error> {
        self.work.audit(phase)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_use::{Authentication, Route},
        dispatch,
        provider_exchange::{self, Provider, Stage},
        read_transition::{self, Phase},
        request_effects::RequestEffects,
    };

    struct Fixture {
        identity: Claims,
        expected: Expectation,
        peer: Vec<u8>,
        claims: UseClaims,
        grant: UseGrant,
        operation: Vec<u8>,
    }
    fn claims() -> UseClaims {
        UseClaims {
            binding: b"binding".to_vec(),
            policy: b"policy".to_vec(),
            grant: b"grant".to_vec(),
            issued_at: 1,
            expires_at: 100,
        }
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                identity: Claims {
                    issuer: b"issuer".to_vec(),
                    audience: b"audience".to_vec(),
                    subject: b"subject".to_vec(),
                    token_id: b"token".to_vec(),
                    issued_at: 1,
                    expires_at: 100,
                    epoch: 0,
                    certificate: b"peer".to_vec(),
                },
                expected: Expectation {
                    issuer: b"issuer".to_vec(),
                    audience: b"audience".to_vec(),
                    subject: b"subject".to_vec(),
                    epoch: 0,
                },
                peer: b"peer".to_vec(),
                claims: claims(),
                operation: b"op".to_vec(),
                grant: UseGrant {
                    claims: claims(),
                    operation: b"op".to_vec(),
                    active: true,
                    route: Route {
                        host: b"api.example.org".to_vec(),
                        port: 443,
                        path: b"/".to_vec(),
                        authentication: Authentication::Bearer,
                    },
                },
            }
        }
        fn context(&self, write: bool, allowed: bool) -> Context<'_> {
            Context::new(
                &self.identity,
                &self.expected,
                &self.peer,
                &self.claims,
                &self.grant,
                &self.operation,
                write,
                allowed,
            )
        }
    }
    struct NativeChecks {
        calls: Vec<(&'static str, Option<i64>)>,
        fault: Option<&'static str>,
        now: i64,
        elapsed: i64,
    }
    impl NativeChecks {
        fn new(fault: Option<&'static str>) -> Self {
            Self {
                calls: vec![],
                fault,
                now: 2,
                elapsed: 1,
            }
        }
        fn step(&mut self, name: &'static str, now: Option<i64>) -> Result<(), &'static str> {
            self.calls.push((name, now));
            if self.fault == Some(name) {
                Err("fault")
            } else {
                Ok(())
            }
        }
    }
    impl Checks for NativeChecks {
        type Error = &'static str;
        const INVALID_CAPABILITY: Self::Error = "identity";
        fn coordination(&mut self) -> Result<(), Self::Error> {
            self.step("coordination", None)
        }
        fn clock(&mut self) -> Result<i64, Self::Error> {
            self.step("clock", None)?;
            Ok(self.now)
        }
        fn control(&mut self, now: i64) -> Result<(), Self::Error> {
            self.step("control", Some(now))
        }
        fn lease(&mut self, now: i64) -> Result<(), Self::Error> {
            self.step("lease", Some(now))
        }
        fn elapsed(&mut self) -> Result<i64, Self::Error> {
            self.step("elapsed", None)?;
            Ok(self.elapsed)
        }
        fn use_error(error: UseDenial) -> Self::Error {
            match error {
                UseDenial::InvalidCapability => "grant",
                UseDenial::Denied => "denied",
                UseDenial::Revoked => "revoked",
                UseDenial::Upstream => "upstream",
            }
        }
    }

    #[test]
    fn exact_sampler_order_and_terminal_primitive_failure_prefixes() {
        let fixture = Fixture::new();
        let context = fixture.context(false, true);
        let expected = [
            ("coordination", None),
            ("clock", None),
            ("control", Some(2)),
            ("lease", Some(2)),
            ("elapsed", None),
        ];
        for (index, (fault, _)) in expected.iter().enumerate() {
            let mut checks = NativeChecks::new(Some(fault));
            assert!(matches!(context.current(&mut checks), Err("fault")));
            assert_eq!(checks.calls, expected[..=index]);
        }
        let mut checks = NativeChecks::new(None);
        let stamp = context.current(&mut checks).unwrap();
        assert_eq!(checks.calls, expected);
        assert_eq!((stamp.now(), stamp.elapsed(), stamp.write()), (2, 1, false));
    }

    #[test]
    fn identity_refusal_precedes_elapsed_and_grant_refusal_preserves_mapping() {
        for mutation in 0..5 {
            let mut fixture = Fixture::new();
            match mutation {
                0 => fixture.peer = b"other-peer".to_vec(),
                1 => fixture.expected.subject = b"other-subject".to_vec(),
                2 => fixture.expected.epoch = 1,
                3 => fixture.identity.expires_at = 2,
                _ => fixture.identity.audience = b"other-audience".to_vec(),
            }
            let mut checks = NativeChecks::new(None);
            assert!(matches!(
                fixture.context(false, true).current(&mut checks),
                Err("identity")
            ));
            assert_eq!(
                checks
                    .calls
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
                ["coordination", "clock", "control", "lease"]
            );
        }
        for mutation in 0..4 {
            let mut fixture = Fixture::new();
            let mut checks = NativeChecks::new(None);
            match mutation {
                0 => fixture.grant.active = false,
                1 => fixture.claims.policy = b"other-policy".to_vec(),
                2 => checks.elapsed = 99,
                _ => {}
            }
            let write = mutation == 3;
            assert!(
                matches!(fixture.context(write,!write).current(&mut checks),Err(error) if error==if write { "denied" } else { "grant" })
            );
            assert_eq!(checks.calls.last(), Some(&("elapsed", None)));
        }
    }

    struct RawProvider {
        calls: Vec<&'static str>,
        write: bool,
    }
    impl Provider for RawProvider {
        type Channel = u8;
        type Output = u8;
        type Error = &'static str;
        const INVALID_POLICY: Self::Error = "policy";
        const OUTCOME_UNKNOWN: Self::Error = "unknown";
        fn setup(&mut self) -> Result<u8, Self::Error> {
            self.calls.push("setup");
            Ok(7)
        }
        fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
            self.calls.push("unbound-current");
            Err("unbound")
        }
        fn send(&mut self, channel: &mut u8) -> Result<(), Self::Error> {
            self.calls.push("send");
            *channel = 9;
            Ok(())
        }
        fn receive(&mut self, channel: u8) -> Result<u8, Self::Error> {
            self.calls.push("receive");
            Ok(channel)
        }
    }
    impl dispatch::Work for RawProvider {
        const INVALID_TRANSITION: Self::Error = "invalid";
        fn effect_write(&self) -> bool {
            self.write
        }
        fn prepare(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn audit(&mut self, _: Phase) -> Result<(), Self::Error> {
            self.calls.push("audit");
            Ok(())
        }
        fn configure(&mut self, _: bool) -> Result<(), Self::Error> {
            Ok(())
        }
        fn check(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn reserve(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn finish(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn owned_dispatch_uses_bound_current_and_never_raw_recheck_or_late_send() {
        let fixture = Fixture::new();
        for (phase, write) in [
            (Phase::Preflight, false),
            (Phase::Final, false),
            (Phase::Final, true),
        ] {
            for fault in [None, Some("control"), Some("lease")] {
                let context = fixture.context(write, true);
                let work = Bound::new(
                    &context,
                    RawProvider {
                        calls: vec![],
                        write,
                    },
                    NativeChecks::new(fault),
                );
                let report = dispatch::dispatch(
                    work,
                    read_transition::prepare(phase, write, write).map_err(|_| "policy"),
                    RequestEffects::new(),
                    false,
                );
                let receipt = report.effects.phase(phase);
                assert!(receipt.audit_acknowledged());
                assert!(!report.work.work.calls.contains(&"unbound-current"));
                if fault.is_some() {
                    assert!(matches!(report.outcome, Err("fault")));
                    assert_eq!(report.provider_stage, Some(Stage::Admission));
                    assert_eq!(report.work.work.calls, ["audit", "setup"]);
                    assert!(!receipt.provider_attempted());
                } else {
                    assert_eq!(report.outcome, Ok(9));
                    assert_eq!(
                        report.work.work.calls,
                        ["audit", "setup", "send", "receive"]
                    );
                    let stamp = receipt.current().unwrap();
                    assert_eq!((stamp.now(), stamp.elapsed(), stamp.write()), (2, 1, write));
                    assert!(receipt.dispatch_succeeded());
                }
            }
        }
        // Direct use of a raw provider remains fail closed before HTTP send.
        let prepared =
            read_transition::prepare(Phase::Final, false, false).unwrap_or_else(|_| panic!("read"));
        let audited =
            read_transition::acknowledge(prepared, true).unwrap_or_else(|_| panic!("audit"));
        let mut raw = RawProvider {
            calls: vec![],
            write: false,
        };
        let report = provider_exchange::exchange(&mut raw, &audited);
        assert!(matches!(report.into_result(), Err("unbound")));
        assert_eq!(raw.calls, ["setup", "unbound-current"]);
    }
}

//! Request-scoped immutable admission context around native primitive factories.
//! Raw factories cannot choose the context of the bound provider they produce.
//! Primitive/environment and complete native I/O semantics remain separate.
use crate::{current_admission, provider_io, read_transition, request_adapter};

pub trait CheckFactory {
    type Error;
    type Checks: current_admission::Checks<Error = Self::Error>;
    fn checks(&mut self) -> Self::Checks;
}

pub struct ScopedRequest<'a, W: request_adapter::Work, F: CheckFactory<Error = W::Error>>
where
    W::Dispatch: provider_io::RouteWork<
        <W::Dispatch as crate::provider_exchange::Provider>::Channel,
        W::Error,
    >,
{
    context: &'a current_admission::Context<'a>,
    work: W,
    factory: F,
}
impl<'a, W: request_adapter::Work, F: CheckFactory<Error = W::Error>> ScopedRequest<'a, W, F>
where
    W::Dispatch: provider_io::RouteWork<
        <W::Dispatch as crate::provider_exchange::Provider>::Channel,
        W::Error,
    >,
{
    pub fn new(context: &'a current_admission::Context<'a>, work: W, factory: F) -> Self {
        Self {
            context,
            work,
            factory,
        }
    }
}
impl<'a, W: request_adapter::Work, F: CheckFactory<Error = W::Error>> request_adapter::Work
    for ScopedRequest<'a, W, F>
where
    W::Dispatch: provider_io::RouteWork<
        <W::Dispatch as crate::provider_exchange::Provider>::Channel,
        W::Error,
    >,
{
    type Facts = W::Facts;
    type Effect = W::Effect;
    type Output = W::Output;
    type Error = W::Error;
    type Dispatch = current_admission::Bound<'a, provider_io::Routed<'a, W::Dispatch>, F::Checks>;
    type Completion = W::Completion;
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;
    const INVALID_POLICY: Self::Error = W::INVALID_POLICY;

    fn preflight(&self) -> Result<Option<Self::Effect>, Self::Error> {
        self.work.preflight()
    }
    fn empty_facts(&self) -> Self::Facts {
        self.work.empty_facts()
    }
    fn final_effect(&self, facts: &Self::Facts) -> Result<Option<Self::Effect>, Self::Error> {
        self.work.final_effect(facts)
    }
    fn effect_write(&self, effect: &Self::Effect) -> bool {
        self.work.effect_write(effect)
    }
    fn operation_write(&self) -> bool {
        self.work.operation_write()
    }
    fn dispatch(
        &mut self,
        phase: read_transition::Phase,
        effect: Self::Effect,
    ) -> request_adapter::DispatchPlan<Self::Dispatch> {
        let plan = self.work.dispatch(phase, effect);
        let checks = self.factory.checks();
        let routed = provider_io::Routed::new(self.context.route(), plan.work);
        let work = current_admission::Bound::new(self.context, routed, checks);
        request_adapter::DispatchPlan {
            work,
            keyed_write: plan.keyed_write,
        }
    }
    fn complete(&mut self, raw: Self::Facts) -> Self::Completion {
        self.work.complete(raw)
    }
    fn recheck(&mut self) -> Result<(), Self::Error> {
        self.work.recheck()
    }
    fn outcome_unknown(&self) -> Self::Error {
        self.work.outcome_unknown()
    }
}

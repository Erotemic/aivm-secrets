//! Closed request-callback progression. Only this module can borrow the raw
//! adapter; callers must consume the tracked mutable state for every call.
//! Trace variants encode a bounded accepted invocation prefix without storing
//! credentials, provider values, guest data, or allocating a log buffer.

use super::{Phase, Request};

#[derive(Clone, Copy)]
pub enum Trace {
    Empty,
    PreflightPlan,
    EmptyFacts,
    PreflightDispatch,
    FinalPlan { preflight: bool },
    Current { preflight: bool },
    WriteKind { preflight: bool },
    FinalDispatch { preflight: bool },
    Complete { preflight: bool, final_effect: bool },
    Uncertain { preflight: bool },
}

enum Progress {
    Start,
    Empty,
    Preflight,
    FinalPlan {
        preflight: bool,
    },
    Current {
        preflight: bool,
        final_effect: bool,
    },
    WriteKind {
        preflight: bool,
    },
    FinalDispatch {
        preflight: bool,
        write: bool,
    },
    Complete {
        preflight: bool,
        final_effect: bool,
        write: bool,
    },
    Uncertain {
        preflight: bool,
    },
    Finished,
    Halted,
}

pub struct Invocation<R> {
    adapter: R,
    trace: Trace,
    progress: Progress,
}

impl<R: Request> Invocation<R> {
    pub fn new(adapter: R) -> Self {
        Self {
            adapter,
            trace: Trace::Empty,
            progress: Progress::Start,
        }
    }

    pub fn trace(&self) -> Trace {
        self.trace
    }

    fn reject<T>(&mut self) -> Result<T, R::Error> {
        self.progress = Progress::Halted;
        Err(R::INVALID_TRANSITION)
    }

    pub(super) fn preflight(&mut self) -> Result<Option<R::Effect>, R::Error> {
        if !matches!(self.progress, Progress::Start) {
            return self.reject();
        }
        self.trace = Trace::PreflightPlan;
        self.progress = Progress::Halted;
        match self.adapter.preflight() {
            Ok(None) => {
                self.progress = Progress::Empty;
                Ok(None)
            }
            Ok(Some(effect)) => {
                self.progress = Progress::Preflight;
                Ok(Some(effect))
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn empty_facts(&mut self) -> Result<R::Facts, R::Error> {
        if !matches!(self.progress, Progress::Empty) {
            return self.reject();
        }
        self.trace = Trace::EmptyFacts;
        self.progress = Progress::Halted;
        let facts = self.adapter.empty_facts();
        self.progress = Progress::FinalPlan { preflight: false };
        Ok(facts)
    }

    pub(super) fn dispatch(
        &mut self,
        phase: Phase,
        effect: R::Effect,
    ) -> Result<R::Facts, R::Error> {
        let (preflight, write) = match (phase, &self.progress) {
            (Phase::Preflight, Progress::Preflight) => (true, false),
            (Phase::Final, Progress::FinalDispatch { preflight, write }) => (*preflight, *write),
            _ => return self.reject(),
        };
        self.trace = match phase {
            Phase::Preflight => Trace::PreflightDispatch,
            Phase::Final => Trace::FinalDispatch { preflight },
        };
        self.progress = Progress::Halted;
        match self.adapter.dispatch(phase, effect) {
            Ok(facts) => {
                self.progress = match phase {
                    Phase::Preflight => Progress::FinalPlan { preflight: true },
                    Phase::Final => Progress::Complete {
                        preflight,
                        final_effect: true,
                        write,
                    },
                };
                Ok(facts)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn final_effect(&mut self, facts: &R::Facts) -> Result<Option<R::Effect>, R::Error> {
        let preflight = match self.progress {
            Progress::FinalPlan { preflight } => preflight,
            _ => return self.reject(),
        };
        self.trace = Trace::FinalPlan { preflight };
        self.progress = Progress::Halted;
        match self.adapter.final_effect(facts) {
            Ok(None) => {
                self.progress = Progress::Current {
                    preflight,
                    final_effect: false,
                };
                Ok(None)
            }
            Ok(Some(effect)) => {
                self.progress = Progress::Current {
                    preflight,
                    final_effect: true,
                };
                Ok(Some(effect))
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn recheck(&mut self) -> Result<(), R::Error> {
        let (preflight, final_effect) = match self.progress {
            Progress::Current {
                preflight,
                final_effect,
            } => (preflight, final_effect),
            _ => return self.reject(),
        };
        self.trace = Trace::Current { preflight };
        self.progress = Progress::Halted;
        match self.adapter.recheck() {
            Ok(()) => {
                self.progress = if final_effect {
                    Progress::WriteKind { preflight }
                } else {
                    Progress::Complete {
                        preflight,
                        final_effect: false,
                        write: false,
                    }
                };
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn effect_write(&mut self, effect: &R::Effect) -> Result<bool, R::Error> {
        let preflight = match self.progress {
            Progress::WriteKind { preflight } => preflight,
            _ => return self.reject(),
        };
        self.trace = Trace::WriteKind { preflight };
        self.progress = Progress::Halted;
        let write = self.adapter.effect_write(effect);
        self.progress = Progress::FinalDispatch { preflight, write };
        Ok(write)
    }

    pub(super) fn complete(&mut self, raw: R::Facts) -> Result<R::Output, R::Error> {
        let (preflight, final_effect, write) = match self.progress {
            Progress::Complete {
                preflight,
                final_effect,
                write,
            } => (preflight, final_effect, write),
            _ => return self.reject(),
        };
        self.trace = Trace::Complete {
            preflight,
            final_effect,
        };
        self.progress = Progress::Halted;
        match self.adapter.complete(raw) {
            Ok(reply) => {
                self.progress = Progress::Finished;
                Ok(reply)
            }
            Err(error) => {
                if write {
                    self.progress = Progress::Uncertain { preflight };
                }
                Err(error)
            }
        }
    }

    pub(super) fn outcome_unknown(&mut self) -> R::Error {
        let preflight = match self.progress {
            Progress::Uncertain { preflight } => preflight,
            _ => {
                self.progress = Progress::Halted;
                return R::INVALID_TRANSITION;
            }
        };
        self.trace = Trace::Uncertain { preflight };
        self.progress = Progress::Halted;
        self.adapter.outcome_unknown()
    }

    /// A stale successful value cannot bypass a later rejected invocation.
    pub fn into_result(self, result: Result<R::Output, R::Error>) -> Result<R::Output, R::Error> {
        match result {
            Ok(reply) => {
                if matches!(self.progress, Progress::Finished) {
                    Ok(reply)
                } else {
                    Err(R::INVALID_TRANSITION)
                }
            }
            Err(error) => Err(error),
        }
    }
}

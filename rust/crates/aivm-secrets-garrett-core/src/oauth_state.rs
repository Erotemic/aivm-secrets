//! OAuth custody decisions and durable-before-send refresh composition.
pub enum RefreshState {
    Ready,
    InDoubt,
    Reauthorize,
}
pub enum ExchangeFailure {
    NotSent,
    Rejected,
    Uncertain,
}
pub enum RefreshDenial {
    Revoked,
    Unsettled,
    Expired,
    Exhausted,
    Invalid,
    Storage,
    Uncertain,
    NotSent,
    Rejected,
}
pub enum RefreshEvent {
    Recorded,
    InDoubt,
    NotSent,
    Rejected,
}
pub fn classify(sent: bool, status: i64, invalid_grant: bool) -> ExchangeFailure {
    if !sent {
        ExchangeFailure::NotSent
    } else if status == 400 && invalid_grant {
        ExchangeFailure::Rejected
    } else {
        ExchangeFailure::Uncertain
    }
}
pub fn settled_failure(prior: &RefreshState, failure: &ExchangeFailure) -> RefreshState {
    match failure {
        ExchangeFailure::NotSent => match prior {
            RefreshState::Ready => RefreshState::Ready,
            RefreshState::InDoubt => RefreshState::InDoubt,
            RefreshState::Reauthorize => RefreshState::Reauthorize,
        },
        ExchangeFailure::Rejected => RefreshState::Reauthorize,
        ExchangeFailure::Uncertain => RefreshState::InDoubt,
    }
}
pub fn permit_refresh(
    active: bool,
    state: &RefreshState,
    has_refresh: bool,
    generation: i64,
    retry_in_doubt: bool,
) -> Result<(), RefreshDenial> {
    if !active {
        return Err(RefreshDenial::Revoked);
    }
    match state {
        RefreshState::Ready => (),
        RefreshState::InDoubt => {
            if !retry_in_doubt {
                return Err(RefreshDenial::Unsettled);
            }
        }
        RefreshState::Reauthorize => return Err(RefreshDenial::Unsettled),
    }
    if !has_refresh {
        return Err(RefreshDenial::Expired);
    }
    if generation < 0 {
        return Err(RefreshDenial::Invalid);
    }
    if generation >= 2147483647 {
        return Err(RefreshDenial::Exhausted);
    }
    Ok(())
}
pub struct LeaseMeta {
    pub epoch: i64,
    pub generation: i64,
    pub expires_at: i64,
}
pub fn require_lease(
    active: bool,
    state: &RefreshState,
    current: &LeaseMeta,
    leased: &LeaseMeta,
    now: i64,
) -> Result<(), RefreshDenial> {
    if !active
        || current.epoch != leased.epoch
        || current.generation != leased.generation
        || current.expires_at != leased.expires_at
    {
        return Err(RefreshDenial::Revoked);
    }
    match state {
        RefreshState::Ready => (),
        _ => return Err(RefreshDenial::Unsettled),
    }
    if now < 0 || now >= current.expires_at {
        return Err(RefreshDenial::Expired);
    }
    Ok(())
}
/// A running session pins enrollment epoch, while each request selects the
/// vault's current generation. Renewal never bypasses ready/active/expiry.
pub fn require_current_lease(
    active: bool,
    state: &RefreshState,
    current: &LeaseMeta,
    expected_epoch: i64,
    now: i64,
) -> Result<(), RefreshDenial> {
    require_lease(
        active,
        state,
        current,
        &LeaseMeta {
            epoch: expected_epoch,
            generation: current.generation,
            expires_at: current.expires_at,
        },
        now,
    )
}

pub enum StoreFailure {
    Failed,
}
pub trait RefreshOps {
    type Successor;
    fn intent(&self) -> Result<(), StoreFailure>;
    fn quarantine(&self) -> Result<(), StoreFailure>;
    fn exchange(&self) -> Result<Self::Successor, ExchangeFailure>;
    fn commit(&self, successor: &Self::Successor) -> Result<(), StoreFailure>;
    fn settle(&self, state: &RefreshState) -> Result<(), StoreFailure>;
    fn observe(&self, event: RefreshEvent) -> Result<(), StoreFailure>;
}
#[allow(clippy::too_many_arguments, clippy::redundant_pattern_matching)]
pub fn refresh_once<O: RefreshOps>(
    ops: &O,
    active: bool,
    prior: &RefreshState,
    has_refresh: bool,
    generation: i64,
    retry_in_doubt: bool,
) -> Result<O::Successor, RefreshDenial> {
    if let Err(error) = permit_refresh(active, prior, has_refresh, generation, retry_in_doubt) {
        return Err(error);
    }
    if let Err(_) = ops.intent() {
        return Err(RefreshDenial::Storage);
    }
    if let Err(_) = ops.quarantine() {
        return Err(RefreshDenial::Uncertain);
    }
    match ops.exchange() {
        Ok(successor) => {
            if let Err(_) = ops.commit(&successor) {
                let _ = ops.observe(RefreshEvent::InDoubt);
                return Err(RefreshDenial::Uncertain);
            }
            if let Err(_) = ops.observe(RefreshEvent::Recorded) {
                return Err(RefreshDenial::Uncertain);
            }
            Ok(successor)
        }
        Err(ExchangeFailure::Uncertain) => {
            let _ = ops.observe(RefreshEvent::InDoubt);
            Err(RefreshDenial::Uncertain)
        }
        Err(failure) => {
            let state = settled_failure(prior, &failure);
            if let Err(_) = ops.settle(&state) {
                let _ = ops.observe(RefreshEvent::InDoubt);
                return Err(RefreshDenial::Uncertain);
            }
            let (event, denial) = match failure {
                ExchangeFailure::NotSent => (RefreshEvent::NotSent, RefreshDenial::NotSent),
                ExchangeFailure::Rejected => (RefreshEvent::Rejected, RefreshDenial::Rejected),
                ExchangeFailure::Uncertain => (RefreshEvent::InDoubt, RefreshDenial::Uncertain),
            };
            if let Err(_) = ops.observe(event) {
                return Err(RefreshDenial::Uncertain);
            }
            Err(denial)
        }
    }
}

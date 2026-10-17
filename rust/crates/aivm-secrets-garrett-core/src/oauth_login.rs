//! Callback binding and one-shot authorization-code lifecycle. Byte decoding,
//! clock provenance, PKCE hashing, HTTPS and vault durability are adapters.
pub enum Stage {
    Pending,
    Accepted,
    Denied,
    Exchanging,
    Complete,
    Uncertain,
}
pub enum LoginDenial {
    Invalid,
    Expired,
    Consumed,
}
pub enum IssuerRule {
    Absent,
    Exact(Vec<u8>),
}
pub struct Pending {
    pub state: Vec<u8>,
    pub issuer: IssuerRule,
    pub issued_at: i64,
    pub expires_at: i64,
}
pub struct Callback {
    pub state: Vec<u8>,
    pub issuer: Vec<u8>,
    pub has_issuer: bool,
    pub denied: bool,
}
pub fn current(pending: &Pending, now: i64) -> Result<(), LoginDenial> {
    if pending.issued_at < 0 || pending.issued_at > 9223372036854775207 {
        return Err(LoginDenial::Invalid);
    }
    if pending.expires_at <= pending.issued_at || pending.expires_at > pending.issued_at + 600 {
        return Err(LoginDenial::Invalid);
    }
    if now < pending.issued_at || now >= pending.expires_at {
        return Err(LoginDenial::Expired);
    }
    Ok(())
}
pub fn claim(
    stage: &Stage,
    pending: &Pending,
    callback: &Callback,
    now: i64,
) -> Result<Stage, LoginDenial> {
    match stage {
        Stage::Pending => (),
        _ => return Err(LoginDenial::Consumed),
    }
    match current(pending, now) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if callback.state != pending.state {
        return Err(LoginDenial::Invalid);
    }
    match &pending.issuer {
        IssuerRule::Absent => {
            if callback.has_issuer {
                return Err(LoginDenial::Invalid);
            }
        }
        IssuerRule::Exact(expected) => {
            if !callback.has_issuer || callback.issuer != *expected {
                return Err(LoginDenial::Invalid);
            }
        }
    }
    if callback.denied {
        Ok(Stage::Denied)
    } else {
        Ok(Stage::Accepted)
    }
}
pub fn begin(stage: &Stage, pending: &Pending, now: i64) -> Result<Stage, LoginDenial> {
    match stage {
        Stage::Accepted => (),
        _ => return Err(LoginDenial::Consumed),
    }
    match current(pending, now) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(Stage::Exchanging)
}
pub fn finish(stage: &Stage, installed: bool) -> Result<Stage, LoginDenial> {
    match stage {
        Stage::Exchanging => (),
        _ => return Err(LoginDenial::Consumed),
    }
    if installed {
        Ok(Stage::Complete)
    } else {
        Ok(Stage::Uncertain)
    }
}

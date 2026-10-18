//! Admission and durable reservation must precede a coordinated write.
//! Durability, authenticated peer checks and provider I/O are adapter contracts.
pub trait Dispatch {
    type Output;
    type Error;
    fn check(&self) -> Result<(), Self::Error>;
    fn reserve(&self) -> Result<(), Self::Error>;
    fn emit(&self) -> Result<Self::Output, Self::Error>;
    fn finish(&self) -> Result<(), Self::Error>;
    fn outcome_unknown(&self) -> Self::Error;
}

pub fn dispatch<D: Dispatch>(ops: &D, keyed_write: bool) -> Result<D::Output, D::Error> {
    match ops.check() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if keyed_write {
        match ops.reserve() {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
    }
    let result = match ops.emit() {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if keyed_write {
        match ops.finish() {
            Ok(()) => (),
            Err(_) => return Err(ops.outcome_unknown()),
        }
    }
    Ok(result)
}

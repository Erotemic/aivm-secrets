//! Last admission before an already-prepared credential-bearing emission.
//! Setup and durable intent may block; adapters construct this continuation
//! after those steps and sample their trusted clocks again in `recheck`.

pub trait PendingEmission {
    type Output;
    type Error;
    fn recheck(&self) -> Result<(), Self::Error>;
    fn emit(self) -> Result<Self::Output, Self::Error>;
}

pub fn emit_current<E: PendingEmission>(pending: E) -> Result<E::Output, E::Error> {
    match pending.recheck() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    pending.emit()
}

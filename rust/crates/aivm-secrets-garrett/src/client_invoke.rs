//! Untrusted-side named operation translation. Authorization, write admission
//! and reservation decisions remain entirely in the broker.
use aivm_secrets_garrett::{json, Error, Outcome};
use aivm_secrets_garrett_core::coordination::valid_retry_key;
use rustix::fs::{open, Mode, OFlags};
use serde_json::{json as value, Value};
use std::{collections::BTreeMap, fs::File, io::Read};

const MAX_ARGUMENTS: usize = 16384;
pub(crate) struct Invoke {
    request: Value,
}
fn arguments_file(path: &str) -> Outcome<Vec<u8>> {
    let mut data = Vec::new();
    if path == "-" {
        std::io::stdin()
            .take((MAX_ARGUMENTS + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::InvalidRequest)?;
    } else {
        // Arguments are untrusted data, not authority configuration. Ordinary
        // readable files (including explicit symlinks) work; FIFO/device input
        // is refused without blocking on open. Credentials stay in private files.
        let file = File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| Error::InvalidRequest)?,
        );
        if !file
            .metadata()
            .map_err(|_| Error::InvalidRequest)?
            .is_file()
        {
            return Err(Error::InvalidRequest);
        }
        file.take((MAX_ARGUMENTS + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::InvalidRequest)?;
    }
    if data.len() > MAX_ARGUMENTS {
        return Err(Error::InvalidRequest);
    }
    Ok(data)
}
impl Invoke {
    pub(crate) fn parse(words: &[String]) -> Outcome<Self> {
        let operation = words.first().ok_or(Error::InvalidRequest)?;
        json::word(&value!(operation), 128).map_err(|_| Error::InvalidRequest)?;
        let rest = &words[1..];
        if !rest.len().is_multiple_of(2) {
            return Err(Error::InvalidRequest);
        }
        let mut options = BTreeMap::new();
        for pair in rest.as_chunks::<2>().0 {
            if !matches!(
                pair[0].as_str(),
                "--arguments" | "--arguments-file" | "--idempotency-key"
            ) || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(Error::InvalidRequest);
            }
        }
        if options.contains_key("--arguments") && options.contains_key("--arguments-file") {
            return Err(Error::InvalidRequest);
        }
        if let Some(key) = options.get("--idempotency-key") {
            if !valid_retry_key(key.as_bytes()) {
                return Err(Error::InvalidRequest);
            }
        }
        let bytes = if let Some(inline) = options.get("--arguments") {
            inline.as_bytes().to_vec()
        } else if let Some(path) = options.get("--arguments-file") {
            arguments_file(path)?
        } else {
            b"{}".to_vec()
        };
        let arguments = json::parse(&bytes, MAX_ARGUMENTS).map_err(|_| Error::InvalidRequest)?;
        if !arguments.is_object() {
            return Err(Error::InvalidRequest);
        }
        let mut request = value!({"operation":operation,"arguments":arguments});
        if let Some(key) = options.get("--idempotency-key") {
            request
                .as_object_mut()
                .ok_or(Error::InvalidRequest)?
                .insert("idempotency_key".into(), value!(key));
        }
        Ok(Self { request })
    }
    pub(crate) fn frame(&self) -> Value {
        value!({"version":1,"request":self.request})
    }
}

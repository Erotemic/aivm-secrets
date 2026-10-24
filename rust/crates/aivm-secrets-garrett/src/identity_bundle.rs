//! Explicit local certificate/JWT snapshots. Binding checks are unverified
//! consistency checks; the broker still authenticates every mTLS call.
use crate::{
    certificates, crypto,
    files::{self, PrivateDirectory},
    json, model, Error, Outcome,
};
use aivm_secrets_garrett_core::bundle as core;
use ring::digest;
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_BUNDLE: usize = 262144;
const LOCK: &str = ".bundle.lock";
pub struct GuestBundle {
    pub certificate: Vec<u8>,
    pub capability: Zeroizing<String>,
    pub certificate_sha256: String,
}
impl GuestBundle {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(json::canonical(&json!({"schema":1,
            "certificate":std::str::from_utf8(&self.certificate).expect("canonical PEM"),
            "capability":self.capability.as_str()})))
    }
}
fn hash(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn pair(certificate: &[u8], token: &str) -> Outcome<GuestBundle> {
    let der = certificates::decode_pem(certificate, "CERTIFICATE", 65536)?;
    let (rest, _) =
        x509_parser::parse_x509_certificate(&der).map_err(|_| Error::InvalidCapability)?;
    if !rest.is_empty() {
        return Err(Error::InvalidCapability);
    }
    let thumb = crypto::certificate_thumbprint(&der)?;
    crypto::token_key_id(token)?;
    let parts: Vec<_> = token.split('.').collect();
    let header = crypto::decode(parts[0], 4096)?;
    let header_canonical = json::canonical(&json::parse(&header, 4096)?) == header;
    let signature_length = crypto::decode(parts[2], 65536)?.len();
    let raw = crypto::decode(parts[1], 65536)?;
    let mut payload = json::parse(&raw, 65536)?;
    json::keys(
        &payload,
        &[
            "iss", "aud", "sub", "jti", "iat", "exp", "epoch", "cnf", "enc",
        ],
        &[],
    )?;
    let payload_canonical = json::canonical(&payload) == raw;
    let encrypted = payload
        .as_object_mut()
        .ok_or(Error::InvalidCapability)?
        .remove("enc")
        .ok_or(Error::InvalidCapability)?;
    let encrypted_length =
        crypto::decode(encrypted.as_str().ok_or(Error::InvalidCapability)?, 65536)?.len();
    let claims = model::claims(&payload)?;
    // The consistency decision is the extracted `bundle::consistent`.
    if !aivm_secrets_garrett_core::bundle::consistent(
        header_canonical,
        payload_canonical,
        signature_length,
        encrypted_length,
        &claims.certificate,
        &thumb.as_bytes().to_vec(),
    ) {
        return Err(Error::InvalidCapability);
    }
    Ok(GuestBundle {
        certificate: certificates::pem(&der, "CERTIFICATE").into_bytes(),
        capability: Zeroizing::new(token.to_owned()),
        certificate_sha256: thumb,
    })
}
pub fn parse(data: &[u8]) -> Outcome<GuestBundle> {
    let value = json::parse(data, MAX_BUNDLE)?;
    let m = json::keys(&value, &["schema", "certificate", "capability"], &[])?;
    json::integer(&m["schema"], 1, 1)?;
    pair(
        m["certificate"]
            .as_str()
            .ok_or(Error::InvalidCapability)?
            .as_bytes(),
        m["capability"].as_str().ok_or(Error::InvalidCapability)?,
    )
}
struct Destination {
    directory: PrivateDirectory,
    parent: PathBuf,
    name: String,
}
impl Destination {
    fn at(path: &Path) -> Outcome<Self> {
        let parent = path.parent().ok_or(Error::UnsafeFile)?.to_owned();
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(Error::UnsafeFile)?
            .to_owned();
        if name == LOCK || name.starts_with(".bundle-") {
            return Err(Error::UnsafeFile);
        }
        let directory = PrivateDirectory::open(&parent)?;
        // Validate the leaf even when it does not exist yet.
        directory.exists(&name)?;
        Ok(Self {
            directory,
            parent,
            name,
        })
    }
}
pub fn load(path: &Path) -> Outcome<GuestBundle> {
    let at = Destination::at(path)?;
    let _lock = at
        .directory
        .lock_named(LOCK, false)
        .map_err(|_| Error::UnsafeFile)?;
    let bytes = Zeroizing::new(at.directory.read(&at.name, MAX_BUNDLE)?);
    parse(&bytes)
}
struct Publication<'a> {
    at: &'a Destination,
    data: &'a [u8],
    replace: bool,
    staged: RefCell<Option<String>>,
    error: RefCell<Option<Error>>,
}
impl Publication<'_> {
    fn failed<T>(&self, error: Error) -> Result<T, core::InstallFailure> {
        *self.error.borrow_mut() = Some(error);
        Err(core::InstallFailure::Unpublished)
    }
}
impl core::BundleStore for Publication<'_> {
    fn current(&self) -> Result<Option<Vec<u8>>, core::InstallFailure> {
        let observed = (|| {
            if !self.at.directory.exists(&self.at.name)? {
                return Ok(None);
            }
            let bytes = Zeroizing::new(self.at.directory.read(&self.at.name, MAX_BUNDLE)?);
            parse(&bytes)?; // Never overwrite arbitrary private material.
            Ok(Some(hash(&bytes)))
        })();
        match observed {
            Ok(value) => Ok(value),
            Err(error) => self.failed(error),
        }
    }
    fn stage(&self) -> Result<(), core::InstallFailure> {
        let staged: Outcome<String> = (|| {
            let name = format!(".bundle-{}", files::random_id()?);
            self.at.directory.write_new(&name, self.data)?;
            Ok(name)
        })();
        match staged {
            Ok(name) => {
                *self.staged.borrow_mut() = Some(name);
                Ok(())
            }
            Err(_) => self.failed(Error::UnsafeFile),
        }
    }
    fn publish(&self) -> Result<(), core::InstallFailure> {
        let publish = (|| {
            let staged = self.staged.borrow();
            let name = staged.as_ref().ok_or(Error::OutcomeUnknown)?;
            self.at
                .directory
                .activate_file(name, &self.at.name, self.replace)?;
            let current = PrivateDirectory::open(&self.at.parent)?;
            if !self.at.directory.same_inode(&current)? {
                return Err(Error::OutcomeUnknown);
            }
            Ok(())
        })();
        publish.map_err(|_| core::InstallFailure::OutcomeUnknown)
    }
}
// Inputs use held private directories too, but are not active bundle pointers
// and need not obey the output's reserved staging-name rule.
fn read_source(path: &Path, limit: usize) -> Outcome<Vec<u8>> {
    let directory = PrivateDirectory::open(path.parent().ok_or(Error::UnsafeFile)?)?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Error::UnsafeFile)?;
    directory.read(name, limit)
}
pub fn install(
    certificate: &Path,
    jwt_file: &Path,
    output: &Path,
    expected_current: Option<&str>,
) -> Outcome<Value> {
    let expected = match expected_current {
        None => None,
        Some(value) => {
            if value.len() != 64
                || value
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            {
                return Err(Error::InvalidRequest);
            }
            Some(
                (0..32)
                    .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).expect("checked hex"))
                    .collect(),
            )
        }
    };
    let token = Zeroizing::new(read_source(jwt_file, 65536)?);
    let token = std::str::from_utf8(&token)
        .map_err(|_| Error::InvalidCapability)?
        .trim_end_matches(['\r', '\n']);
    let bundle = pair(&read_source(certificate, 65536)?, token)?;
    let data = bundle.encode();
    let at = Destination::at(output)?;
    // Creation races converge on the one checked lock inode. The held lock is
    // retained through current-digest checking, staging, activation and fsync.
    if !at.directory.exists(LOCK)? {
        match at.directory.create_file(LOCK) {
            Ok(file) => {
                file.sync_all().map_err(|_| Error::UnsafeFile)?;
                at.directory.sync().map_err(|_| Error::UnsafeFile)?;
            }
            Err(_) => {
                at.directory.file(LOCK, true)?;
            }
        }
    }
    let _lock = at
        .directory
        .lock_named(LOCK, true)
        .map_err(|_| Error::UnsafeFile)?;
    let publication = Publication {
        at: &at,
        data: &data,
        replace: expected.is_some(),
        staged: RefCell::new(None),
        error: RefCell::new(None),
    };
    match core::install(&publication, expected) {
        Ok(()) => (),
        Err(core::InstallFailure::Changed) => {
            return Err(if expected_current.is_none() {
                Error::UnsafeFile
            } else {
                Error::Denied
            })
        }
        Err(core::InstallFailure::Unpublished) => {
            return Err(publication.error.borrow().unwrap_or(Error::UnsafeFile))
        }
        Err(core::InstallFailure::OutcomeUnknown) => return Err(Error::OutcomeUnknown),
    }
    Ok(
        json!({"path":output,"digest":hex(&hash(&data)),"certificate_sha256":bundle.certificate_sha256}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivm_secrets_garrett_core::bundle::BundleStore;
    use std::{fs, os::unix::fs::PermissionsExt};
    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("garrett-bundle-{}", files::random_id().unwrap()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn acknowledged_publication_replaces_one_private_inode() {
        let scope = Temporary::new();
        let at = Destination::at(&scope.0.join("bundle.json")).unwrap();
        at.directory.write_new(&at.name, b"old snapshot").unwrap();
        let publication = Publication {
            at: &at,
            data: b"new snapshot",
            replace: true,
            staged: RefCell::new(None),
            error: RefCell::new(None),
        };
        assert!(publication.stage().is_ok());
        assert_eq!(at.directory.read(&at.name, 100).unwrap(), b"old snapshot");
        assert!(publication.publish().is_ok());
        assert_eq!(at.directory.read(&at.name, 100).unwrap(), b"new snapshot");
        assert_eq!(
            fs::metadata(scope.0.join(&at.name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn initial_publication_never_overwrites_an_existing_target() {
        let scope = Temporary::new();
        let at = Destination::at(&scope.0.join("bundle.json")).unwrap();
        at.directory.write_new(&at.name, b"old snapshot").unwrap();
        let publication = Publication {
            at: &at,
            data: b"new snapshot",
            replace: false,
            staged: RefCell::new(None),
            error: RefCell::new(None),
        };
        assert!(publication.stage().is_ok());
        assert!(matches!(
            publication.publish(),
            Err(core::InstallFailure::OutcomeUnknown)
        ));
        assert_eq!(at.directory.read(&at.name, 100).unwrap(), b"old snapshot");
    }
    #[test]
    fn lost_parent_coordinate_after_rename_is_uncertain_without_rollback() {
        let scope = Temporary::new();
        let parent = scope.0.join("current");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let at = Destination::at(&parent.join("bundle.json")).unwrap();
        at.directory.write_new(&at.name, b"old snapshot").unwrap();
        let publication = Publication {
            at: &at,
            data: b"new snapshot",
            replace: true,
            staged: RefCell::new(None),
            error: RefCell::new(None),
        };
        assert!(publication.stage().is_ok());
        fs::rename(&parent, scope.0.join("held")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            publication.publish(),
            Err(core::InstallFailure::OutcomeUnknown)
        ));
        assert_eq!(at.directory.read(&at.name, 100).unwrap(), b"new snapshot");
        assert!(!parent.join("bundle.json").exists());
    }
}

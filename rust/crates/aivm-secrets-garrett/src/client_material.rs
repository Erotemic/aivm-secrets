//! Explicit exportable software identities. No enrollment or TPM assertion is
//! implied by generating a key; host approval still binds the exact CSR key.
use crate::{certificates::ClientRequest, files::PrivateDirectory, Error, Outcome};
use aivm_secrets_garrett_core::client_material as core;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

struct Destination {
    directory: PrivateDirectory,
    parent: PathBuf,
    name: String,
    path: PathBuf,
}
impl Destination {
    fn at(path: &Path, fresh: bool) -> Outcome<Self> {
        if !path.is_absolute() || path.to_str().is_none() {
            return Err(Error::UnsafeFile);
        }
        let parent = path.parent().ok_or(Error::UnsafeFile)?.to_owned();
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(Error::UnsafeFile)?
            .to_owned();
        let directory = PrivateDirectory::open(&parent)?;
        if fresh && directory.exists(&name)? {
            return Err(Error::UnsafeFile);
        }
        Ok(Self {
            directory,
            parent,
            name,
            path: path.to_owned(),
        })
    }
    fn same_target(&self, other: &Self) -> Outcome<bool> {
        Ok(self.name == other.name && self.directory.same_inode(&other.directory)?)
    }
    fn publish(&self, data: &[u8]) -> Outcome<()> {
        self.directory.publish_new(&self.name, data)?;
        // Held descriptors keep writes on the approved inode; also verify that
        // the returned operator coordinate still names that inode.
        let current = PrivateDirectory::open(&self.parent).map_err(|_| Error::OutcomeUnknown)?;
        if !self
            .directory
            .same_inode(&current)
            .map_err(|_| Error::OutcomeUnknown)?
        {
            return Err(Error::OutcomeUnknown);
        }
        Ok(())
    }
}
struct Material {
    key: Zeroizing<String>,
    csr: String,
    fingerprint: String,
}
fn request_for(key: &KeyPair) -> Outcome<(String, String)> {
    let mut parameters =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::InternalError)?;
    parameters.distinguished_name = DistinguishedName::new();
    parameters
        .distinguished_name
        .push(DnType::CommonName, "aivm-untrusted-request");
    let csr = parameters
        .serialize_request(key)
        .and_then(|v| v.pem())
        .map_err(|_| Error::InternalError)?;
    let checked = ClientRequest::from_pem(csr.as_bytes())?;
    if checked.subject_public_key_info() != key.subject_public_key_info() {
        return Err(Error::InternalError);
    }
    Ok((csr, checked.fingerprint()))
}
fn generated() -> Outcome<Material> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| Error::InternalError)?;
    let (csr, fingerprint) = request_for(&key)?;
    Ok(Material {
        key: Zeroizing::new(key.serialize_pem()),
        csr,
        fingerprint,
    })
}
struct Publication<'a> {
    key: &'a Destination,
    csr: &'a Destination,
    material: &'a Material,
}
fn failure(error: Error) -> core::PublishFailure {
    if error == Error::OutcomeUnknown {
        core::PublishFailure::OutcomeUnknown
    } else {
        core::PublishFailure::Unpublished
    }
}
impl core::RequestStore for Publication<'_> {
    fn write_key(&self) -> Result<(), core::PublishFailure> {
        self.key
            .publish(self.material.key.as_bytes())
            .map_err(failure)
    }
    fn write_csr(&self) -> Result<(), core::PublishFailure> {
        self.csr
            .publish(self.material.csr.as_bytes())
            .map_err(failure)
    }
}
fn public_result(key: &Destination, csr: &Destination, fingerprint: &str) -> Value {
    json!({"key_fingerprint":fingerprint,"key":key.path,"csr":csr.path,
        "security":"exportable software key; no VM attestation"})
}
pub fn request(key: &Path, csr: &Path) -> Outcome<Value> {
    let key = Destination::at(key, true)?;
    let csr = Destination::at(csr, true)?;
    if key.same_target(&csr)? {
        return Err(Error::UnsafeFile);
    }
    let material = generated()?;
    core::publish_request(&Publication {
        key: &key,
        csr: &csr,
        material: &material,
    })
    .map_err(|error| match error {
        core::PublishFailure::Unpublished => Error::UnsafeFile,
        core::PublishFailure::OutcomeUnknown => Error::OutcomeUnknown,
    })?;
    Ok(public_result(&key, &csr, &material.fingerprint))
}
/// Recover the public request from a retained key without replacing either file.
pub fn csr_from_key(key: &Path, csr: &Path) -> Outcome<Value> {
    let key = Destination::at(key, false)?;
    let csr = Destination::at(csr, true)?;
    if key.same_target(&csr)? {
        return Err(Error::UnsafeFile);
    }
    let pem = Zeroizing::new(key.directory.read(&key.name, 8192)?);
    let text = std::str::from_utf8(&pem).map_err(|_| Error::InvalidCapability)?;
    let material = KeyPair::from_pem(text).map_err(|_| Error::InvalidCapability)?;
    if material.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(Error::InvalidCapability);
    }
    let (request, fingerprint) = request_for(&material)?;
    csr.publish(request.as_bytes())?;
    Ok(public_result(&key, &csr, &fingerprint))
}
pub fn inspect_csr(path: &Path) -> Outcome<Value> {
    let data = crate::files::read_trusted_public(path, 8192)?;
    Ok(json!({"key_fingerprint":ClientRequest::from_pem(&data)?.fingerprint()}))
}

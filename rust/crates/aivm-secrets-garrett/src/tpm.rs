//! Explicit TPM2-tools signing profile. Never exports a key or falls back.
//!
//! The host must separately establish the provenance of the pinned public area.
//! Reading local TPM attributes is not remote attestation. A software TPM is
//! useful for interoperability tests, but its state is copyable by its host.
use crate::{client, files, Error, Outcome};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use rustls::{
    pki_types::SubjectPublicKeyInfoDer,
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    SignatureAlgorithm, SignatureScheme,
};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// Inputs are trusted local configuration, never fields in a broker request.
pub struct Configuration {
    pub tcti: String,
    pub persistent_handle: u32,
    pub authorization_file: PathBuf,
    pub public_area_file: PathBuf,
    pub work_directory: PathBuf,
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(parent: &Path) -> Outcome<Self> {
        files::private_directory(parent)?;
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::InternalError)?;
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = parent.join(format!("sign-{name}"));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| Error::UnsafeFile)?;
        Ok(Self(path))
    }
    fn write(&self, name: &str, data: &[u8]) -> Outcome<PathBuf> {
        let path = self.0.join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(data))
            .map_err(|_| Error::UnsafeFile)?;
        Ok(path)
    }
    fn read(&self, name: &str, limit: usize) -> Outcome<Vec<u8>> {
        let path = self.0.join(name);
        // tpm2-tools creates files with the process umask. The enclosing random
        // directory is private; restrict the file before applying our reader.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::UnsafeFile)?;
        files::read_private(&path, limit)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Configuration {
    fn validate(&self) -> Outcome<()> {
        if !(0x81000000..=0x81ffffff).contains(&self.persistent_handle) {
            return Err(Error::InvalidCapability);
        }
        files::private_directory(&self.work_directory)?;
        if self.tcti != "device:/dev/tpmrm0" && self.tcti != "device:/dev/tpm0" {
            let path = self
                .tcti
                .strip_prefix("swtpm:path=")
                .ok_or(Error::InvalidCapability)?;
            if path.contains([',', '\n', '\r', '\0']) {
                return Err(Error::InvalidCapability);
            }
            let socket = Path::new(path);
            files::private_directory(socket.parent().ok_or(Error::UnsafeFile)?)?;
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = fs::symlink_metadata(socket).map_err(|_| Error::UnsafeFile)?;
            if !socket.is_absolute()
                || !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(Error::UnsafeFile);
            }
        }
        let auth = zeroize::Zeroizing::new(files::read_private(&self.authorization_file, 64)?);
        if auth.len() < 16 || auth.len() > 32 {
            return Err(Error::InvalidCapability);
        }
        Ok(())
    }
    fn command(&self, name: &str, args: &[&std::ffi::OsStr]) -> Outcome<()> {
        // Fixed executable + explicit TCTI + cleared environment exclude PATH,
        // TPM2TOOLS_TCTI and caller-selected plugins from the custody decision.
        let executable = match name {
            "readpublic" => "/usr/bin/tpm2_readpublic",
            "sign" => "/usr/bin/tpm2_sign",
            _ => return Err(Error::InternalError),
        };
        let mut child = Command::new(executable)
            .env_clear()
            .arg("-Q")
            .arg("-T")
            .arg(&self.tcti)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::InvalidCapability)?;
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(Error::InvalidCapability)
                    }
                }
                Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::InvalidCapability);
                }
            }
        }
    }
}

/// Strict TPMT_PUBLIC profile: SHA256 Name, P256 ECDSA/SHA256, internally
/// generated, fixed TPM/parent, signing only, no policy or exportable origin.
/// Return the SEC1 point and its corresponding DER SubjectPublicKeyInfo.
pub(crate) fn public_key(area: &[u8]) -> Outcome<(Vec<u8>, Vec<u8>)> {
    const PREFIX: &[u8] = &[
        0, 0x23, 0, 0x0b, 0, 4, 0, 0x72, 0, 0, 0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10, 0, 0x20,
    ];
    if area.len() != 88 || !area.starts_with(PREFIX) || area[54..56] != [0, 32] {
        return Err(Error::InvalidCapability);
    }
    let mut point = vec![4];
    point.extend_from_slice(&area[22..54]);
    point.extend_from_slice(&area[56..88]);
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0,
    ];
    spki.extend_from_slice(&point);
    Ok((point, spki))
}
struct TpmKey {
    configuration: Arc<Configuration>,
    point: Vec<u8>,
    spki: Vec<u8>,
}
impl fmt::Debug for TpmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmSigningKey(P256)")
    }
}
struct TpmSigner {
    configuration: Arc<Configuration>,
    point: Vec<u8>,
}
impl fmt::Debug for TpmSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TpmSigner(P256)")
    }
}
impl SigningKey for TpmKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(TpmSigner {
                    configuration: self.configuration.clone(),
                    point: self.point.clone(),
                }) as Box<dyn Signer>
            })
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}
impl Signer for TpmSigner {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.sign_checked(message)
            .map_err(|_| rustls::Error::General("TPM signing failed".into()))
    }
}
impl TpmSigner {
    fn sign_checked(&self, message: &[u8]) -> Outcome<Vec<u8>> {
        self.configuration.validate()?;
        let scratch = Scratch::new(&self.configuration.work_directory)?;
        let digest = scratch.write("digest", digest::digest(&digest::SHA256, message).as_ref())?;
        // Read authorization into a fresh private file: never an argument value.
        let auth = zeroize::Zeroizing::new(files::read_private(
            &self.configuration.authorization_file,
            32,
        )?);
        let authorization = scratch.write("auth", &auth)?;
        let auth_arg = format!("file:{}", authorization.display());
        let handle = format!("0x{:08x}", self.configuration.persistent_handle);
        let output = scratch.0.join("signature");
        self.configuration.command(
            "sign",
            &[
                "-c".as_ref(),
                handle.as_ref(),
                "-p".as_ref(),
                auth_arg.as_ref(),
                "-g".as_ref(),
                "sha256".as_ref(),
                "-s".as_ref(),
                "ecdsa".as_ref(),
                "-d".as_ref(),
                "-f".as_ref(),
                "plain".as_ref(),
                "-o".as_ref(),
                output.as_os_str(),
                digest.as_os_str(),
            ],
        )?;
        let result = scratch.read("signature", 80)?;
        // A persistent handle can be replaced. A returned signature must match
        // the pinned identity, even after the initial ReadPublic check.
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &self.point)
            .verify(message, &result)
            .map_err(|_| Error::InvalidCapability)?;
        Ok(result)
    }
}

fn load_key(configuration: Configuration) -> Outcome<TpmKey> {
    configuration.validate()?;
    let area = files::read_private(&configuration.public_area_file, 1024)?;
    let (point, spki) = public_key(&area)?;
    let scratch = Scratch::new(&configuration.work_directory)?;
    let output = scratch.0.join("public");
    let handle = format!("0x{:08x}", configuration.persistent_handle);
    configuration.command(
        "readpublic",
        &[
            "-c".as_ref(),
            handle.as_ref(),
            "-f".as_ref(),
            "tpmt".as_ref(),
            "-o".as_ref(),
            output.as_os_str(),
        ],
    )?;
    if scratch.read("public", 1024)? != area {
        return Err(Error::InvalidCapability);
    }
    Ok(TpmKey {
        configuration: Arc::new(configuration),
        point,
        spki,
    })
}

impl rcgen::PublicKeyData for TpmKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
    fn subject_public_key_info(&self) -> Vec<u8> {
        self.spki.clone()
    }
}
impl rcgen::SigningKey for TpmKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        TpmSigner {
            configuration: self.configuration.clone(),
            point: self.point.clone(),
        }
        .sign_checked(message)
        .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
/// Sign a possession request using a provisioned key. Local attributes and a
/// signature do not replace the host's independent attestation approval.
pub(crate) fn create_request(configuration: Configuration) -> Outcome<(String, String)> {
    crate::client_material::request_for(&load_key(configuration)?)
}

pub fn identity(
    configuration: Configuration,
    certificate: &[u8],
    server_ca: &[u8],
) -> Outcome<client::AuthenticatedClientConfig> {
    let key = load_key(configuration)?;
    let certificates = rustls_pemfile::certs(&mut &*certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidCapability)?;
    let key = CertifiedKey::new(certificates, Arc::new(key));
    key.keys_match().map_err(|_| Error::InvalidCapability)?;
    client::signing_resolver(server_ca, Arc::new(SingleCertAndKey::from(key)))
}

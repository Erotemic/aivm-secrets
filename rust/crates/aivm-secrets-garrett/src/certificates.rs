//! Host-selected P-256 CA and strict possession-checked client CSR adapters.
//! No request-selected names, extensions, trust roots or private-key output.
use crate::{attestation::VerifiedIdentity, json, Error, Outcome};
use aivm_secrets_garrett_core::enrollment as core;
use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SubjectPublicKeyInfo, PKCS_ECDSA_P256_SHA256,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use x509_parser::{
    certification_request::X509CertificationRequest,
    prelude::{FromDer, ParsedExtension, X509Certificate},
};
use zeroize::Zeroizing;

const MAX_CSR: usize = 8192;
const P256_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
fn p256(spki: &[u8]) -> Outcome<()> {
    if spki.len() != 91 || !spki.starts_with(P256_PREFIX) {
        return Err(Error::InvalidCapability);
    }
    Ok(())
}
fn decode_pem(bytes: &[u8], label: &str, limit: usize) -> Outcome<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > limit || !bytes.is_ascii() {
        return Err(Error::InvalidCapability);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidCapability)?
        .trim();
    let body = text
        .strip_prefix(&format!("-----BEGIN {label}-----"))
        .and_then(|v| v.strip_suffix(&format!("-----END {label}-----")))
        .ok_or(Error::InvalidCapability)?;
    let encoded = Zeroizing::new(
        body.bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    Ok(Zeroizing::new(
        STANDARD
            .decode(&encoded)
            .map_err(|_| Error::InvalidCapability)?,
    ))
}
fn pem(der: &[u8], label: &str) -> String {
    let encoded = STANDARD.encode(der);
    let mut result = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        result.push('\n');
    }
    result.push_str(&format!("-----END {label}-----\n"));
    result
}
fn serial() -> Outcome<rcgen::SerialNumber> {
    let mut bytes = [0u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::InternalError)?;
    bytes[0] = (bytes[0] & 0x7f) | 1;
    Ok(bytes.to_vec().into())
}
fn date(stamp: i64) -> Outcome<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(stamp).map_err(|_| Error::InvalidCapability)
}
fn parameters(name: &str, not_before: i64, not_after: i64) -> Outcome<CertificateParams> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = date(not_before)?;
    params.not_after = date(not_after)?;
    params.serial_number = Some(serial()?);
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}
/// Only parsing and verifying a signature can construct this public candidate.
pub struct ClientRequest {
    spki: Vec<u8>,
    fingerprint: Vec<u8>,
}
impl ClientRequest {
    pub fn from_pem(bytes: &[u8]) -> Outcome<Self> {
        let der = decode_pem(bytes, "CERTIFICATE REQUEST", MAX_CSR)?;
        let (rest, csr) =
            X509CertificationRequest::from_der(&der).map_err(|_| Error::InvalidCapability)?;
        let info = &csr.certification_request_info;
        if !rest.is_empty()
            || info.version.0 != 0
            || csr.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
            || csr.signature_algorithm.parameters.is_some()
            || csr.signature_value.unused_bits != 0
        {
            return Err(Error::InvalidCapability);
        }
        info.attributes_map()
            .map_err(|_| Error::InvalidCapability)?;
        // Empty extension-request attributes are emitted by some CSR tools.
        // No requested certificate extension is accepted or copied.
        if info.attributes().iter().any(|a| matches!(
            a.parsed_attribute(),
            x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(e) if !e.extensions.is_empty()
        )) { return Err(Error::InvalidCapability); }
        let spki = info.subject_pki.raw.to_vec();
        p256(&spki)?;
        csr.verify_signature()
            .map_err(|_| Error::InvalidCapability)?;
        let fingerprint = digest::digest(&digest::SHA256, &spki).as_ref().to_vec();
        Ok(Self { spki, fingerprint })
    }
    pub fn fingerprint(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub fn subject_public_key_info(&self) -> &[u8] {
        &self.spki
    }
}
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate: Vec<u8>,
    not_before: i64,
    not_after: i64,
}
impl CertificateAuthority {
    pub fn from_pem(certificate: &[u8], private_key: &[u8]) -> Outcome<Self> {
        let der = decode_pem(certificate, "CERTIFICATE", 65536)?;
        let key_der = decode_pem(private_key, "PRIVATE KEY", 8192)?;
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(key_der.to_vec()),
            &PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|_| Error::InvalidCapability)?;
        let (rest, cert) = X509Certificate::from_der(&der).map_err(|_| Error::InvalidCapability)?;
        let constraints = cert
            .basic_constraints()
            .map_err(|_| Error::InvalidCapability)?
            .ok_or(Error::InvalidCapability)?;
        let usage = cert
            .key_usage()
            .map_err(|_| Error::InvalidCapability)?
            .ok_or(Error::InvalidCapability)?;
        cert.extensions_map()
            .map_err(|_| Error::InvalidCapability)?;
        if !rest.is_empty()
            || cert.version().0 != 2
            || cert.subject() != cert.issuer()
            || !constraints.critical
            || !constraints.value.ca
            || constraints.value.path_len_constraint != Some(0)
            || !usage.critical
            || !usage.value.key_cert_sign()
            || cert.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
            || cert.signature_algorithm.parameters.is_some()
            || cert.signature_algorithm != cert.tbs_certificate.signature
            || cert.signature_value.unused_bits != 0
            || cert.public_key().raw != key.subject_public_key_info()
            || cert.extensions().iter().any(|e| {
                !matches!(
                    e.parsed_extension(),
                    ParsedExtension::BasicConstraints(_)
                        | ParsedExtension::KeyUsage(_)
                        | ParsedExtension::SubjectKeyIdentifier(_)
                        | ParsedExtension::AuthorityKeyIdentifier(_)
                )
            })
        {
            return Err(Error::InvalidCapability);
        }
        p256(cert.public_key().raw)?;
        cert.verify_signature(None)
            .map_err(|_| Error::InvalidCapability)?;
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        if not_after <= not_before {
            return Err(Error::InvalidCapability);
        }
        let certificate = der.to_vec();
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(certificate.clone()), key)
            .map_err(|_| Error::InvalidCapability)?;
        Ok(Self {
            issuer,
            certificate,
            not_before,
            not_after,
        })
    }
    pub fn generate(now: i64) -> Outcome<Self> {
        if !(0..=253370764799).contains(&now) {
            return Err(Error::InvalidCapability);
        }
        let mut params = parameters("aivm-secrets host CA", now - 60, now + 31536000)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| Error::InternalError)?;
        let cert = params.self_signed(&key).map_err(|_| Error::InternalError)?;
        let key_pem = Zeroizing::new(key.serialize_pem());
        Self::from_pem(cert.pem().as_bytes(), key_pem.as_bytes())
    }
    pub fn certificate_pem(&self) -> String {
        pem(&self.certificate, "CERTIFICATE")
    }
    pub fn enroll_software(
        &self,
        request: ClientRequest,
        subject: &str,
        approve_fingerprint: &str,
        now: i64,
    ) -> Outcome<core::IssuedClient> {
        let fingerprint = json::hex(&serde_json::json!(approve_fingerprint), 64)?;
        let decoded = (0..32)
            .map(|i| {
                u8::from_str_radix(&fingerprint[i * 2..i * 2 + 2], 16)
                    .map_err(|_| Error::InvalidCapability)
            })
            .collect::<Outcome<Vec<_>>>()?;
        self.enroll(
            request,
            subject,
            core::Approval::Software {
                fingerprint: decoded,
            },
            now,
        )
    }
    pub fn enroll_tpm(
        &self,
        request: ClientRequest,
        subject: &str,
        evidence: VerifiedIdentity,
        now: i64,
    ) -> Outcome<core::IssuedClient> {
        // Verification does not grant an indefinitely reusable evidence token.
        // Preserve the original challenge deadline through signing admission.
        evidence.require_fresh()?;
        self.enroll(
            request,
            subject,
            core::Approval::Tpm {
                spki: evidence.subject_public_key_info().to_vec(),
            },
            now,
        )
    }
    fn enroll(
        &self,
        request: ClientRequest,
        subject: &str,
        approval: core::Approval,
        now: i64,
    ) -> Outcome<core::IssuedClient> {
        json::word(&serde_json::json!(subject), 128)?;
        let input = core::EnrollmentInput {
            subject: subject.as_bytes().to_vec(),
            candidate: core::Candidate {
                spki: request.spki,
                fingerprint: request.fingerprint,
            },
            ca_not_before: self.not_before,
            ca_not_after: self.not_after,
            now,
        };
        core::enroll_client(&SigningAdapter(self), input, &approval).map_err(|e| match e {
            core::EnrollmentDenial::Denied => Error::Denied,
            core::EnrollmentDenial::Expired => Error::Expired,
            _ => Error::InvalidCapability,
        })
    }
    #[cfg(feature = "conformance")]
    pub(crate) fn fixture_private_key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.issuer.key().serialize_pem())
    }
}
struct SigningAdapter<'a>(&'a CertificateAuthority);
impl core::ClientSigner for SigningAdapter<'_> {
    fn sign(&self, plan: &core::ClientPlan) -> Result<Vec<u8>, core::EnrollmentDenial> {
        let build = || -> Outcome<Vec<u8>> {
            p256(&plan.spki)?;
            // Fresh parameters discard the CSR's untrusted identity and every
            // requested certificate capability. Only client authentication is issued.
            let mut params = parameters("aivm-guest", plan.not_before, plan.not_after)?;
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let public =
                SubjectPublicKeyInfo::from_der(&plan.spki).map_err(|_| Error::InvalidCapability)?;
            let cert = params
                .signed_by(&public, &self.0.issuer)
                .map_err(|_| Error::InternalError)?;
            Ok(cert.der().to_vec())
        };
        build().map_err(|_| core::EnrollmentDenial::Signing)
    }
}
pub fn client_certificate_pem(issued: &core::IssuedClient) -> String {
    pem(&issued.certificate, "CERTIFICATE")
}

/// Synthetic fixtures only: private-key serialization is excluded from normal builds.
#[cfg(feature = "conformance")]
pub(crate) fn fixture(v: &serde_json::Value) -> Outcome<serde_json::Value> {
    use serde_json::json;
    let action = v["action"].as_str().ok_or(Error::InvalidCapability)?;
    let text = |k: &str| v[k].as_str().ok_or(Error::InvalidCapability);
    if action == "ca-create" {
        json::keys(v, &["action", "now"], &[])?;
        let ca = CertificateAuthority::generate(json::integer(&v["now"], 0, 253370764799)?)?;
        return Ok(
            json!({"ok":true,"ca_pem":ca.certificate_pem(),"key_pem":&*ca.fixture_private_key_pem()}),
        );
    }
    if action == "csr-inspect" {
        json::keys(v, &["action", "csr_pem"], &[])?;
        let request = ClientRequest::from_pem(text("csr_pem")?.as_bytes())?;
        let hex: String = request.spki.iter().map(|b| format!("{b:02x}")).collect();
        return Ok(json!({"ok":true,"fingerprint":request.fingerprint(),"spki_der_hex":hex}));
    }
    if action == "server-generate" {
        json::keys(v, &["action", "ca_pem", "ca_key_pem", "now"], &[])?;
        let ca = CertificateAuthority::from_pem(
            text("ca_pem")?.as_bytes(),
            text("ca_key_pem")?.as_bytes(),
        )?;
        let now = json::integer(&v["now"], 0, 253399708799)?;
        if now - 60 < ca.not_before || now + 2592000 >= ca.not_after {
            return Err(Error::Expired);
        }
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| Error::InternalError)?;
        let mut params = parameters("localhost", now - 60, now + 2592000)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|_| Error::InvalidCapability)?,
        ));
        let cert = params
            .signed_by(&key, &ca.issuer)
            .map_err(|_| Error::InternalError)?;
        let key_pem = Zeroizing::new(key.serialize_pem());
        return Ok(json!({"ok":true,"certificate_pem":cert.pem(),"key_pem":&*key_pem}));
    }
    let additional = match action {
        "client-software" => "approve_fingerprint",
        "client-tpm" => "evidence",
        _ => return Err(Error::InvalidCapability),
    };
    json::keys(
        v,
        &[
            "action",
            "ca_pem",
            "ca_key_pem",
            "csr_pem",
            "subject",
            "now",
            additional,
        ],
        if action == "client-tpm" {
            &["expire_evidence"]
        } else {
            &[]
        },
    )?;
    let ca =
        CertificateAuthority::from_pem(text("ca_pem")?.as_bytes(), text("ca_key_pem")?.as_bytes())?;
    let request = ClientRequest::from_pem(text("csr_pem")?.as_bytes())?;
    let now = json::integer(&v["now"], 0, i64::MAX)?;
    let issued = if action == "client-tpm" {
        let mut verified = crate::conformance::verify_attestation_fixture(&v["evidence"])?;
        if let Some(expire) = v.get("expire_evidence") {
            if expire.as_bool().ok_or(Error::InvalidCapability)? {
                verified = verified.fixture_expired();
            }
        }
        ca.enroll_tpm(request, text("subject")?, verified, now)?
    } else {
        ca.enroll_software(request, text("subject")?, text("approve_fingerprint")?, now)?
    };
    let assurance = match issued.plan.assurance {
        core::Assurance::OperatorApproved => "operator-approved-software",
        core::Assurance::AttestedTpm => "attested-tpm",
    };
    Ok(
        json!({"ok":true,"certificate_pem":client_certificate_pem(&issued),"subject":text("subject")?,"not_before":issued.plan.not_before,"not_after":issued.plan.not_after,"assurance":assurance}),
    )
}

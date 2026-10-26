//! A minimal development PKI: a CA, server certificates and agent client
//! certificates (software keys). Production deployments use their own CA;
//! a TPM-resident agent key is certified from a CSR by that CA.
use crate::error::{Error, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use zeroize::Zeroizing;

fn failed(_: rcgen::Error) -> Error {
    Error::Tls("certificate generation".into())
}

fn window(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(days);
}

/// A PEM certificate and its PEM PKCS#8 private key.
pub struct Issued {
    pub certificate: String,
    pub key: Zeroizing<String>,
}

/// A self-signed CA that may only issue end-entity certificates.
pub fn create_ca(name: &str, days: i64) -> Result<Issued> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(failed)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    window(&mut params, days);
    let certificate = params.self_signed(&key).map_err(failed)?;
    Ok(Issued {
        certificate: certificate.pem(),
        key: Zeroizing::new(key.serialize_pem()),
    })
}

/// What a leaf certificate is for.
pub enum Leaf<'a> {
    /// A TLS server for these DNS names (or IP addresses).
    Server(&'a [String]),
    /// An agent client; `uri` is an optional URI SAN (for example a SPIFFE ID).
    Client { name: &'a str, uri: Option<&'a str> },
}

pub fn issue(ca_certificate: &str, ca_key: &str, leaf: Leaf<'_>, days: i64) -> Result<Issued> {
    let ca_key = KeyPair::from_pem(ca_key).map_err(failed)?;
    let issuer = Issuer::from_ca_cert_pem(ca_certificate, ca_key).map_err(failed)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(failed)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    match leaf {
        Leaf::Server(names) => {
            params.distinguished_name.push(
                DnType::CommonName,
                names.first().cloned().unwrap_or_default(),
            );
            for name in names {
                params
                    .subject_alt_names
                    .push(match name.parse::<std::net::IpAddr>() {
                        Ok(address) => SanType::IpAddress(address),
                        Err(_) => SanType::DnsName(name.clone().try_into().map_err(failed)?),
                    });
            }
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        Leaf::Client { name, uri } => {
            params.distinguished_name.push(DnType::CommonName, name);
            if let Some(uri) = uri {
                params
                    .subject_alt_names
                    .push(SanType::URI(uri.to_owned().try_into().map_err(failed)?));
            }
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
    }
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    window(&mut params, days);
    let certificate = params.signed_by(&key, &issuer).map_err(failed)?;
    Ok(Issued {
        certificate: certificate.pem(),
        key: Zeroizing::new(key.serialize_pem()),
    })
}

//! Bind operator-selected identity and verified CSR key evidence before signing.
//! CSR possession, attestation and CA validation are trusted typed adapters.
#![allow(clippy::ptr_arg)]

pub enum EnrollmentDenial {
    Invalid,
    Denied,
    Expired,
    Signing,
}
pub enum Approval {
    Software { fingerprint: Vec<u8> },
    Tpm { spki: Vec<u8> },
}
pub enum Assurance {
    OperatorApproved,
    AttestedTpm,
}
pub struct Candidate {
    pub spki: Vec<u8>,
    pub fingerprint: Vec<u8>,
}
pub fn approve_key(
    candidate: &Candidate,
    approval: &Approval,
) -> Result<Assurance, EnrollmentDenial> {
    match approval {
        Approval::Software { fingerprint } => {
            if candidate.fingerprint != *fingerprint {
                return Err(EnrollmentDenial::Denied);
            }
            Ok(Assurance::OperatorApproved)
        }
        Approval::Tpm { spki } => {
            if candidate.spki != *spki {
                return Err(EnrollmentDenial::Denied);
            }
            Ok(Assurance::AttestedTpm)
        }
    }
}
pub struct EnrollmentInput {
    pub subject: Vec<u8>,
    pub candidate: Candidate,
    pub ca_not_before: i64,
    pub ca_not_after: i64,
    pub now: i64,
}
pub struct ClientPlan {
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub assurance: Assurance,
}
pub fn authorize_client(
    input: EnrollmentInput,
    approval: &Approval,
) -> Result<ClientPlan, EnrollmentDenial> {
    let assurance = match approve_key(&input.candidate, approval) {
        Ok(assurance) => assurance,
        Err(error) => return Err(error),
    };
    // The supported X.509 date range is 0000..9999. A leaf is valid for seven
    // days, with the reference's 60-second skew, strictly inside its CA
    // window. Near the CA's end the leaf is cut short to end one second
    // before the CA does; a leaf that would then last less than a day is
    // refused, so the CA must be rotated before that.
    if input.now < 0 || input.now > 253401695999 {
        return Err(EnrollmentDenial::Invalid);
    }
    let not_before = input.now - 60;
    // Checked first, so `ca_not_after - 1` below cannot underflow.
    if not_before < input.ca_not_before || input.ca_not_after <= input.now + 86400 {
        return Err(EnrollmentDenial::Expired);
    }
    let full = input.now + 604800;
    let not_after = if full < input.ca_not_after {
        full
    } else {
        input.ca_not_after - 1
    };
    Ok(ClientPlan {
        subject: input.subject,
        spki: input.candidate.spki,
        not_before,
        not_after,
        assurance,
    })
}
pub trait ClientSigner {
    fn sign(&self, plan: &ClientPlan) -> Result<Vec<u8>, EnrollmentDenial>;
}
pub struct IssuedClient {
    pub plan: ClientPlan,
    pub certificate: Vec<u8>,
}
pub fn enroll_client<S: ClientSigner>(
    signer: &S,
    input: EnrollmentInput,
    approval: &Approval,
) -> Result<IssuedClient, EnrollmentDenial> {
    let plan = match authorize_client(input, approval) {
        Ok(plan) => plan,
        Err(error) => return Err(error),
    };
    let certificate = match signer.sign(&plan) {
        Ok(certificate) => certificate,
        Err(error) => return Err(error),
    };
    Ok(IssuedClient { plan, certificate })
}

//! # `garrett-stateless`
//!
//! A standalone implementation of `garrett-stateless-v1`
//! (`docs/garrett-stateless-v1.md`), the architecture Matthew Garrett
//! described in *Securing agentic identity* (July 2, 2026):
//!
//! * a **broker** ([`broker::Broker`]) runs a browser authorization-code
//!   login for an mTLS-authenticated agent and mints a signed surrogate JWT
//!   that carries the provider credential encrypted and is bound to the
//!   agent's certificate;
//! * a **proxy** ([`proxy::Proxy`]) accepts ordinary API requests that carry
//!   the surrogate as a bearer token over mTLS, checks the binding against the
//!   connection's certificate, decrypts the credential and forwards the
//!   request to the provider route the token names;
//! * an **agent** client ([`agent::Agent`]) for both.
//!
//! Neither broker nor proxy keeps persistent state; the proxy keeps no
//! authorization state, and the broker only an in-progress OAuth login.
//! Every security decision is made by the Aeneas-extracted controllers in
//! `garrett-stateless-core` (`stateless`, `stateless_login`,
//! `stateless_proxy`), which the Lean proofs are about (`proofs/Garrett.lean`
//! states them). `tests/library.rs` shows the library in one page. This
//! crate provides the adapters: Ed25519 and AES-256-GCM ([`token`]), key
//! sets ([`keys`]), TLS ([`tls`]), HTTP and the OAuth token request.
//!
//! **Security invariants** (each a property of the extracted controller,
//! under the adapter contracts in the specification):
//!
//! 1. A surrogate is decrypted only after its signature, issuer, audience,
//!    provider, lifetime, clock and certificate binding have been checked.
//! 2. A surrogate issued for certificate C is refused on a connection
//!    authenticated as any certificate D ≠ C.
//! 3. The provider request contains the decrypted credential exactly once,
//!    as the route's authentication line, and goes only to the route of the
//!    token's authenticated provider.
//! 4. A login's surrogate is bound to the certificate that began the login
//!    and delivered only to that certificate.
//!
//! The cryptographic primitives (`ring`), TLS and X.509 (`rustls`,
//! `webpki`) and the operating system are trusted, not proved.
#![forbid(unsafe_code)]

pub mod agent;
pub mod broker;
pub mod config;
pub mod encoding;
pub mod error;
pub mod files;
pub mod http;
pub mod json;
pub mod keys;
pub mod login;
pub mod pki;
pub mod proxy;
pub mod tls;
pub mod token;
#[cfg(feature = "tpm")]
pub mod tpm;

pub use error::{Error, Result};
pub use garrett_stateless_core::stateless::{Acceptance, IssuePolicy, Rejection, SurrogateClaims};

/// The profile name.
pub const PROFILE: &str = "garrett-stateless-v1";

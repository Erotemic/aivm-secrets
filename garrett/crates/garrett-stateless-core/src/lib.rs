//! The pure decisions of `garrett-stateless-v1` (`docs/garrett-stateless-v1.md`),
//! after Matthew Garrett's "Securing agentic identity". Every function here is
//! a pure function of its arguments or calls only the adapter traits it is
//! given (`SurrogateOpener`, `SurrogateSealer`, `KeyMaterial`, `Channel`,
//! `Origin`); Aeneas extracts this crate and `proofs/` proves it.
//!
//! * `stateless`, `stateless_token`: surrogate issuance, the token codec and
//!   opening (verify, admit, decrypt);
//! * `stateless_login`, `stateless_mailbox`: the optional OAuth login;
//! * `stateless_policy`, `stateless_proxy`: operation authorization and the
//!   proxy's request decision and connection loop;
//! * `proxy_http`, `proxy_controller`, `proxy_connect`, `http_wire`,
//!   `http_auth`, `reflection`, `credential_use`,
//!   `oauth_login`: the HTTP/1.1 framing, exact upstream encoding, response
//!   release and OAuth login primitives those decisions use.
//!
//! # The API
//!
//! A caller needs these; everything else is `pub` so that the application
//! shell and the proofs can name it, not as a stable interface.
//!
//! | Use | Items |
//! | --- | --- |
//! | issue a surrogate | [`stateless::issue`], [`stateless::IssuePolicy`], [`stateless::Grant`], [`stateless_token::TokenSealer::new`] |
//! | open one | [`stateless::open`] (= [`stateless::authenticate`] then [`stateless::decrypt`]), [`stateless::Acceptance`], [`stateless_token::KeySet::new`] |
//! | renew one | [`stateless::renew`] |
//! | decide a proxied request | [`stateless_proxy::decide`]; run a connection with [`stateless_proxy::connection`] |
//! | restrict operations | [`stateless_policy::Unrestricted`], [`stateless_policy::ReadOnly`] |
//! | the OAuth login | [`stateless_mailbox`]: `start`, `pending`, `accept`, `exchange`, `finish`, `poll` |
//! | adapters you implement | [`stateless_token::KeyMaterial`], [`stateless_token::StateKey`], [`stateless_mailbox::CodeExchange`], [`stateless_proxy::Channel`], [`stateless_proxy::Origin`] |
//!
//! With the feature `derive`, the non-secret value and error types
//! implement `Debug`, `Clone`, `PartialEq` and `Eq`; types holding a
//! credential, token, key or request never do.
#![forbid(unsafe_code)]
// Scalar guards keep extraction independent of Range/iterator implementations.
#![allow(clippy::manual_range_contains)]
// Explicit Result matches preserve the small control-flow shape of the proofs.
#![allow(clippy::question_mark)]

pub mod credential_use;
pub mod http_auth;
pub mod http_wire;
pub mod oauth_login;
pub mod proxy_connect;
pub mod proxy_controller;
pub mod proxy_http;
pub mod reflection;
pub mod stateless;
pub mod stateless_login;
pub mod stateless_mailbox;
pub mod stateless_policy;
pub mod stateless_proxy;
pub mod stateless_token;

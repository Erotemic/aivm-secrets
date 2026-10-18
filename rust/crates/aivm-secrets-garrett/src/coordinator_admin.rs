//! Explicit host operator client. Possessing member configuration grants no
//! operator authority; the remote service authenticates and authorizes each call.
use crate::{coordination::Coordinator, Outcome};
use aivm_secrets_garrett_core::coordinator_authority::Action;
use serde_json::Value;
use std::path::Path;

pub struct Client(Coordinator);
impl Client {
    pub fn from_file(path: &Path) -> Outcome<Self> {
        Ok(Self(Coordinator::from_file(path)?))
    }
    pub fn activate(&self, members: &[String]) -> Outcome<Value> {
        self.0.operator(Action::Activate, Some(members))
    }
    pub fn revoke(&self) -> Outcome<Value> {
        self.0.operator(Action::Revoke, None)
    }
    pub fn status(&self) -> Outcome<Value> {
        self.0.operator(Action::Status, None)
    }
}

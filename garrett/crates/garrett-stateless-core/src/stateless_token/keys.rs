//! Key material, key entries and validated key sets (spec section 3).
// Explicit indices, matches and loops keep to what Aeneas models.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::len_zero,
    clippy::single_match,
    clippy::match_like_matches_macro,
    clippy::comparison_chain,
    clippy::manual_map
)]

use super::*;

/// One key's primitives, implemented by the native shell with `ring`.
pub trait KeyMaterial {
    /// Ed25519: whether `signature` is valid for `message` under this key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    /// AES-256-GCM: the plaintext, or `None` if authentication fails.
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>>;
    /// Ed25519 signature of `message`, or `None` without a signing key.
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>>;
    /// AES-256-GCM: the ciphertext with its tag appended.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>;
}

/// One configured `kid`: the issuer it signs for and its key material.
pub struct KeyEntry<M> {
    pub kid: Vec<u8>,
    pub issuer: Vec<u8>,
    pub material: M,
}

/// A validated key set: 1 to 8 entries, valid names, no `kid` twice.
pub struct KeySet<M> {
    pub(super) entries: Vec<KeyEntry<M>>,
}

/// The first entry for `kid` (or `entries.len()`).
pub fn select<M>(entries: &[KeyEntry<M>], kid: &[u8]) -> usize {
    let mut index = 0;
    while index < entries.len() && !named(&entries[index], kid) {
        index += 1;
    }
    index
}

pub fn named<M>(entry: &KeyEntry<M>, kid: &[u8]) -> bool {
    let own: &[u8] = &entry.kid;
    own == kid
}

/// 1 to 8 entries, valid `kid` and issuer grammars, and no `kid` twice, so
/// every `kid` selects at most one entry.
pub fn keys_valid<M>(entries: &[KeyEntry<M>]) -> bool {
    if entries.len() < 1 || entries.len() > MAX_KEYS {
        return false;
    }
    let mut valid = true;
    let mut index = 0;
    while index < entries.len() {
        if !entry_valid(entries, index) {
            valid = false;
        }
        index += 1;
    }
    valid
}

/// Entry `index` has valid names and is the first for its `kid`.
pub fn entry_valid<M>(entries: &[KeyEntry<M>], index: usize) -> bool {
    let entry = &entries[index];
    is_kid(&entry.kid) && is_text(&entry.issuer) && select(entries, &entry.kid) == index
}

#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub enum KeyError {
    Invalid,
}

impl<M> KeySet<M> {
    /// The key set, if the entries are a valid one.
    pub fn new(entries: Vec<KeyEntry<M>>) -> Result<KeySet<M>, KeyError> {
        if !keys_valid(&entries) {
            return Err(KeyError::Invalid);
        }
        Ok(KeySet { entries })
    }

    pub fn entries(&self) -> &[KeyEntry<M>] {
        &self.entries
    }
}

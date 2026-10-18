//! Decisions for one durable principal and one principal-scoped write key.
//! SQLite lookup/commit, peer authentication and host parsing are adapters.
#![allow(clippy::ptr_arg)]

/// Keep wire parsing in the adapter, but classify every supported action here.
#[derive(Clone, Copy)]
pub enum Action {
    Activate,
    Revoke,
    Status,
    Check,
    Reserve,
    Finish,
}

pub enum Denial {
    Denied,
    Revoked,
    OutcomeUnknown,
    Storage,
}
pub struct Principal {
    pub active: bool,
    pub members: Vec<Vec<u8>>,
    pub revision: i64,
}
pub struct Reservation {
    pub digest: Vec<u8>,
    pub completed: bool,
}

pub fn contains_peer(members: &[Vec<u8>], peer: &Vec<u8>) -> bool {
    for member in members {
        if *member == *peer {
            return true;
        }
    }
    false
}

pub fn require_operator(operators: &[Vec<u8>], peer: &Vec<u8>) -> Result<(), Denial> {
    if !contains_peer(operators, peer) {
        return Err(Denial::Denied);
    }
    Ok(())
}

/// Early operator rejection preserves the wire protocol's validation order.
/// Member admission needs the principal snapshot and happens in `authorize`.
pub fn require_operator_for(
    action: Action,
    operators: &[Vec<u8>],
    peer: &Vec<u8>,
) -> Result<(), Denial> {
    match action {
        Action::Activate | Action::Revoke | Action::Status => require_operator(operators, peer),
        Action::Check | Action::Reserve | Action::Finish => Ok(()),
    }
}

/// One exhaustive gate before the adapter interprets any action against rows.
/// Operator authority does not imply membership in a principal, or vice versa.
pub fn authorize(
    action: Action,
    operators: &[Vec<u8>],
    peer: &Vec<u8>,
    current: Option<&Principal>,
) -> Result<Option<i64>, Denial> {
    require_operator_for(action, operators, peer)?;
    match action {
        Action::Activate | Action::Revoke | Action::Status => Ok(None),
        Action::Check | Action::Reserve | Action::Finish => Ok(Some(admit(current, peer)?)),
    }
}

pub fn activate(current: Option<&Principal>, members: Vec<Vec<u8>>) -> Result<Principal, Denial> {
    match current {
        Some(_) => Err(Denial::Revoked),
        None => Ok(Principal {
            active: true,
            members,
            revision: 1,
        }),
    }
}

pub fn revoke(current: Option<Principal>) -> Result<Principal, Denial> {
    match current {
        None => Ok(Principal {
            active: false,
            members: Vec::new(),
            revision: 1,
        }),
        Some(mut principal) => {
            if principal.revision < 1 || principal.revision == i64::MAX {
                return Err(Denial::Storage);
            }
            principal.active = false;
            principal.revision += 1;
            Ok(principal)
        }
    }
}

pub fn admit(current: Option<&Principal>, peer: &Vec<u8>) -> Result<i64, Denial> {
    let principal = match current {
        None => return Err(Denial::Revoked),
        Some(principal) => principal,
    };
    if !principal.active {
        return Err(Denial::Revoked);
    }
    if !contains_peer(&principal.members, peer) {
        return Err(Denial::Revoked);
    }
    Ok(principal.revision)
}

pub fn reserve(current: Option<&Reservation>, digest: Vec<u8>) -> Result<Reservation, Denial> {
    match current {
        Some(_) => Err(Denial::OutcomeUnknown),
        None => Ok(Reservation {
            digest,
            completed: false,
        }),
    }
}

pub fn finish(current: Option<Reservation>, digest: &Vec<u8>) -> Result<Reservation, Denial> {
    match current {
        Some(mut row) => {
            if row.digest != *digest {
                return Err(Denial::OutcomeUnknown);
            }
            row.completed = true;
            Ok(row)
        }
        None => Err(Denial::OutcomeUnknown),
    }
}

/// A missing principal is a status observation, never a revocation receipt.
/// JSON shape/type checks and authenticated remote commit remain adapters.
pub fn operator_acknowledged(action: Action, active: bool, revision: Option<i64>) -> bool {
    match action {
        Action::Activate => match revision {
            Some(revision) => active && revision == 1,
            None => false,
        },
        Action::Revoke => match revision {
            Some(revision) => !active && revision >= 1,
            None => false,
        },
        Action::Status => match revision {
            Some(revision) => revision >= 1,
            None => !active,
        },
        Action::Check | Action::Reserve | Action::Finish => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_members_and_preemptive_tombstones() {
        let peer = b"member-a".to_vec();
        let active = activate(None, vec![peer.clone()]).ok().unwrap();
        assert!(admit(Some(&active), &peer).is_ok());
        assert!(admit(Some(&active), &b"outsider".to_vec()).is_err());
        let tombstone = revoke(Some(active)).ok().unwrap();
        assert!(admit(Some(&tombstone), &peer).is_err());
        assert!(activate(Some(&tombstone), vec![peer.clone()]).is_err());
        let preemptive = revoke(None).ok().unwrap();
        assert!(activate(Some(&preemptive), vec![peer]).is_err());
    }
    #[test]
    fn reserved_keys_stay_spent_after_completion() {
        let digest = b"digest".to_vec();
        let reserved = reserve(None, digest.clone()).ok().unwrap();
        assert!(reserve(Some(&reserved), b"different".to_vec()).is_err());
        let completed = finish(Some(reserved), &digest).ok().unwrap();
        assert!(completed.completed);
        assert!(reserve(Some(&completed), digest).is_err());
    }
}

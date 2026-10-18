//! Decisions for one durable principal and one principal-scoped write key.
//! SQLite lookup/commit, peer authentication and host parsing are adapters.
#![allow(clippy::ptr_arg)]

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

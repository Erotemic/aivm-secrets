use super::{AuthorityError, Result};
use crate::{files::PrivateDirectory, json, tls::VerifiedPeer, Error};
use aivm_secrets_garrett_core::coordinator_authority as core;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{path::Path, sync::Mutex, time::Duration};

const DATABASE: &str = "coordination.sqlite3";
const MESSAGE: usize = 4096;

pub struct Ledger {
    root: PrivateDirectory,
    // One native writer connection; rows are read inside each new transaction.
    // Holding it also keeps SQLite sidecar lifetime stable across RPC workers.
    connection: Mutex<Connection>,
}
impl Ledger {
    pub fn initialize(path: &Path) -> Result<Self> {
        let parent = PrivateDirectory::open(path.parent().ok_or(Error::UnsafeFile)?)?;
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(Error::UnsafeFile)?;
        let root = parent.create_directory(name)?;
        root.create_file(DATABASE)?
            .sync_all()
            .map_err(|_| AuthorityError::Storage)?;
        root.sync()?;
        let mut conn = Self::connection(&root)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The released Python schema is intentionally unchanged.
        tx.execute_batch(
            "CREATE TABLE principals (
            name TEXT PRIMARY KEY, active INTEGER NOT NULL, members TEXT NOT NULL,
            revision INTEGER NOT NULL, CHECK(active IN (0,1)));
            CREATE TABLE writes (
            name TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL,
            PRIMARY KEY(name, key), CHECK(state IN ('reserved','completed')));",
        )?;
        tx.commit()?;
        root.sync()?;
        Ok(Self {
            root,
            connection: Mutex::new(conn),
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        let root = PrivateDirectory::open(path)?;
        let conn = Self::connection(&root)?;
        // Opening must never silently create or repair an absent schema.
        conn.prepare("SELECT name,active,members,revision FROM principals LIMIT 0")?;
        conn.prepare("SELECT name,key,digest,state FROM writes LIMIT 0")?;
        Ok(Self {
            root,
            connection: Mutex::new(conn),
        })
    }
    fn checked_files(root: &PrivateDirectory) -> Result<()> {
        root.file(DATABASE, true)?;
        for name in root.names()? {
            if !matches!(
                name.as_str(),
                DATABASE
                    | "coordination.sqlite3-wal"
                    | "coordination.sqlite3-shm"
                    | "coordination.sqlite3-journal"
            ) {
                return Err(Error::UnsafeFile.into());
            }
            root.file(&name, true)?;
        }
        Ok(())
    }
    fn connection(root: &PrivateDirectory) -> Result<Connection> {
        Self::checked_files(root)?;
        let path = root.held_path(DATABASE)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        if conn.is_readonly("main")? {
            return Err(AuthorityError::Storage);
        }
        conn.busy_timeout(Duration::from_secs(4))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(AuthorityError::Storage);
        }
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;")?;
        Self::checked_files(root)?;
        Ok(conn)
    }
    pub(super) fn handle(
        &self,
        peer: &VerifiedPeer,
        operators: &[Vec<u8>],
        value: &Value,
    ) -> Result<Value> {
        let data = json::keys(value, &["action", "name"], &["members", "key", "digest"])
            .map_err(|_| Error::InvalidRequest)?;
        let action = match data["action"].as_str() {
            Some("activate") => core::Action::Activate,
            Some("revoke") => core::Action::Revoke,
            Some("status") => core::Action::Status,
            Some("check") => core::Action::Check,
            Some("reserve") => core::Action::Reserve,
            Some("finish") => core::Action::Finish,
            _ => return Err(Error::InvalidRequest.into()),
        };
        let name = principal_name(&data["name"])?;
        let peer = peer.certificate_sha256_hex().as_bytes().to_vec();
        core::require_operator_for(action, operators, &peer)?;
        let required = match action {
            core::Action::Activate => vec!["action", "name", "members"],
            core::Action::Check | core::Action::Revoke | core::Action::Status => {
                vec!["action", "name"]
            }
            core::Action::Reserve | core::Action::Finish => vec!["action", "name", "key", "digest"],
        };
        json::keys(value, &required, &[]).map_err(|_| Error::InvalidRequest)?;
        let members = if matches!(action, core::Action::Activate) {
            Some(member_bytes(&data["members"])?)
        } else {
            None
        };
        let write = if matches!(action, core::Action::Reserve | core::Action::Finish) {
            Some((
                json::hex(&data["key"], 64).map_err(|_| Error::InvalidRequest)?,
                json::hex(&data["digest"], 64).map_err(|_| Error::InvalidRequest)?,
            ))
        } else {
            None
        };
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        Self::checked_files(&self.root)?;
        let behavior = if matches!(action, core::Action::Check | core::Action::Status) {
            TransactionBehavior::Deferred
        } else {
            TransactionBehavior::Immediate
        };
        let tx = conn.transaction_with_behavior(behavior)?;
        let current = read_principal(&tx, name)?;
        let admission = core::authorize(action, operators, &peer, current.as_ref())?;
        let result = match action {
            core::Action::Activate => {
                let row = core::activate(current.as_ref(), members.ok_or(Error::InvalidRequest)?)?;
                tx.execute(
                    "INSERT INTO principals VALUES (?,?,?,?)",
                    params![
                        name,
                        i64::from(row.active),
                        members_json(&row.members)?,
                        row.revision
                    ],
                )?;
                json!({"active":row.active,"revision":row.revision})
            }
            core::Action::Revoke => {
                let row = core::revoke(current)?;
                tx.execute(
                    "INSERT INTO principals VALUES (?,?,?,?) ON CONFLICT(name)
                    DO UPDATE SET active=excluded.active,revision=excluded.revision",
                    params![
                        name,
                        i64::from(row.active),
                        members_json(&row.members)?,
                        row.revision
                    ],
                )?;
                json!({"active":row.active,"revision":row.revision})
            }
            core::Action::Status => match current {
                None => json!({"active":false,"revision":null}),
                Some(row) => json!({"active":row.active,"revision":row.revision}),
            },
            core::Action::Check => {
                let revision = admission.ok_or(AuthorityError::Storage)?;
                json!({"active":true,"revision":revision})
            }
            core::Action::Reserve | core::Action::Finish => {
                let (key, digest) = write.ok_or(Error::InvalidRequest)?;
                let prior = read_reservation(&tx, name, &key)?;
                if matches!(action, core::Action::Reserve) {
                    let row = core::reserve(prior.as_ref(), digest.into_bytes())?;
                    let state = reservation_state(&row);
                    let digest =
                        String::from_utf8(row.digest).map_err(|_| AuthorityError::Storage)?;
                    tx.execute(
                        "INSERT INTO writes VALUES (?,?,?,?)",
                        params![name, key, digest, state],
                    )?;
                    json!({"reserved":true})
                } else {
                    let row = core::finish(prior, &digest.as_bytes().to_vec())?;
                    let state = reservation_state(&row);
                    let digest =
                        String::from_utf8(row.digest).map_err(|_| AuthorityError::Storage)?;
                    let count = tx.execute(
                        "UPDATE writes SET state=? WHERE name=? AND key=? AND digest=?",
                        params![state, name, key, digest],
                    )?;
                    if count != 1 {
                        return Err(Error::OutcomeUnknown.into());
                    }
                    json!({"recorded":true})
                }
            }
        };
        // No positive response leaves this function before COMMIT acknowledges.
        tx.commit()?;
        Ok(result)
    }
}
fn principal_name(value: &Value) -> Result<&str> {
    let name = value.as_str().ok_or(Error::InvalidPolicy)?;
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(Error::InvalidPolicy.into());
    }
    Ok(name)
}
fn member_bytes(value: &Value) -> Result<Vec<Vec<u8>>> {
    let values = value.as_array().ok_or(Error::InvalidRequest)?;
    if values.is_empty() || values.len() > 32 {
        return Err(Error::InvalidRequest.into());
    }
    let mut result = values
        .iter()
        .map(|v| json::hex(v, 64).map(String::into_bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidRequest)?;
    result.sort();
    if result.windows(2).any(|v| v[0] == v[1]) {
        return Err(Error::InvalidRequest.into());
    }
    Ok(result)
}
fn members_json(members: &[Vec<u8>]) -> Result<String> {
    let values = members
        .iter()
        .map(|v| std::str::from_utf8(v).map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| AuthorityError::Storage)?;
    String::from_utf8(json::canonical(&json!(values))).map_err(|_| AuthorityError::Storage)
}
fn read_principal(conn: &Connection, name: &str) -> Result<Option<core::Principal>> {
    let row: Option<(i64, String, i64)> = conn
        .query_row(
            "SELECT active,members,revision FROM principals WHERE name=?",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(active, members, revision)| {
        if !matches!(active, 0 | 1) || revision < 1 {
            return Err(AuthorityError::Storage);
        }
        let parsed =
            json::parse(members.as_bytes(), MESSAGE).map_err(|_| AuthorityError::Storage)?;
        let values = parsed.as_array().ok_or(AuthorityError::Storage)?;
        let members = if active == 0 && values.is_empty() {
            Vec::new()
        } else {
            member_bytes(&parsed).map_err(|_| AuthorityError::Storage)?
        };
        Ok(core::Principal {
            active: active == 1,
            members,
            revision,
        })
    })
    .transpose()
}
fn read_reservation(conn: &Connection, name: &str, key: &str) -> Result<Option<core::Reservation>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT digest,state FROM writes WHERE name=? AND key=?",
            params![name, key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(digest, state)| {
        json::hex(&json!(digest), 64).map_err(|_| AuthorityError::Storage)?;
        if !matches!(state.as_str(), "reserved" | "completed") {
            return Err(AuthorityError::Storage);
        }
        Ok(core::Reservation {
            digest: digest.into_bytes(),
            completed: state == "completed",
        })
    })
    .transpose()
}

fn reservation_state(row: &core::Reservation) -> &'static str {
    if row.completed {
        "completed"
    } else {
        "reserved"
    }
}

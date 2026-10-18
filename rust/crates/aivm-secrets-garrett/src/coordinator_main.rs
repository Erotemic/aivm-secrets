//! Explicit host-only service. No credential, key or request body is printed.
use aivm_secrets_garrett::{
    coordinator_authority::{AuthorityError, Ledger, Result, Server},
    json, Error,
};
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    path::Path,
};
fn output(value: &Value) -> Result<()> {
    let mut stream = io::stdout().lock();
    stream
        .write_all(&json::canonical(value))
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| AuthorityError::Public(Error::InternalError))
}
fn execute(args: &[String]) -> Result<()> {
    match args {
        [action, flag, path] if action == "init" && flag == "--directory" => {
            Ledger::initialize(Path::new(path))?;
            output(&json!({"version":1,"ok":true}))
        }
        [action, flag, path] if action == "serve" && flag == "--config" => {
            let server = Server::from_file(Path::new(path))?;
            output(&json!({"version":1,"ok":true,"listen":server.local_address()?.to_string()}))?;
            server.serve()
        }
        _ => Err(Error::InvalidRequest.into()),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-coordinator init --directory ABSOLUTE_NEW_PRIVATE_DIRECTORY\ngarrett-coordinator serve --config PRIVATE_JSON\nOptional experimental mTLS/SQLite single-host authority; no database replication or offline admission fallback.");
        return;
    }
    if let Err(error) = execute(&args) {
        let _ = output(&json!({"version":1,"ok":false,"error":{"code":error.code()}}));
        std::process::exit(1);
    }
}

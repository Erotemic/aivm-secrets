// Development JSONL conformance adapter, not a privileged service endpoint.
use aivm_secrets_garrett::{json, model, Error};
use serde_json::json;
use std::io::{self, BufRead, Write};
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let crypto_mode = args.as_slice() == ["--test-crypto"];
    let registry_mode = args.as_slice() == ["--registry"]
        || (args.is_empty() && env!("CARGO_BIN_NAME") == "registry-conformance");
    let identity_mode = args.as_slice() == ["--identity"]
        || (args.is_empty() && env!("CARGO_BIN_NAME") == "identity-conformance");
    let manifest_mode = args.is_empty() && env!("CARGO_BIN_NAME") == "manifest-conformance";
    let oauth_mode = args.is_empty() && env!("CARGO_BIN_NAME") == "oauth-conformance";
    let authority_mode = args.is_empty() && env!("CARGO_BIN_NAME") == "authority-conformance";
    let rotation_mode = args.is_empty() && env!("CARGO_BIN_NAME") == "key-rotation-conformance";
    let vm_mode = args.is_empty() && env!("CARGO_BIN_NAME") == "vm-conformance";
    if !args.is_empty() && !crypto_mode && !registry_mode && !identity_mode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown conformance mode",
        ));
    }
    let limit = if crypto_mode || registry_mode || manifest_mode {
        262144
    } else if identity_mode || authority_mode {
        8192
    } else if rotation_mode || vm_mode {
        4096
    } else {
        32768
    };
    let input = io::stdin();
    let mut input = input.lock();
    let output = io::stdout();
    let mut output = output.lock();
    loop {
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let chunk = input.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            let size = chunk
                .iter()
                .position(|b| *b == b'\n')
                .map_or(chunk.len(), |i| i + 1);
            let finished = chunk[size - 1] == b'\n';
            if line.len() + size > limit {
                oversized = true;
            }
            if !oversized {
                line.extend_from_slice(&chunk[..size]);
            }
            input.consume(size);
            if finished {
                break;
            }
        }
        if line.is_empty() && !oversized {
            break;
        }
        let result = if oversized {
            Err(Error::InvalidCapability)
        } else {
            json::parse(&line, limit).and_then(|v| {
                if crypto_mode {
                    #[cfg(feature = "conformance")]
                    {
                        aivm_secrets_garrett::conformance::evaluate(&v)
                    }
                    #[cfg(not(feature = "conformance"))]
                    {
                        Err(Error::InvalidCapability)
                    }
                } else if manifest_mode {
                    aivm_secrets_garrett::manifest::evaluate(&v)
                } else if oauth_mode {
                    aivm_secrets_garrett::oauth::evaluate(&v)
                } else if authority_mode {
                    aivm_secrets_garrett::lifecycle::evaluate_authority(&v)
                } else if rotation_mode {
                    aivm_secrets_garrett::lifecycle::evaluate_key_rotation(&v)
                } else if vm_mode {
                    aivm_secrets_garrett::lifecycle::evaluate_vm(&v)
                } else if identity_mode {
                    model::evaluate_identity(&v)
                } else if registry_mode {
                    aivm_secrets_garrett::registry::evaluate(&v)
                } else {
                    model::evaluate(&v)
                }
            })
        };
        let answer = result.unwrap_or_else(|e| {
            if e==Error::AuthorizationDenied {json!({"ok":false,"code":e.code(),"reason":"authorization_denied"})}
            else {json!({"ok":false,"code":if oauth_mode && e==Error::InvalidCapability {"credential_source"} else {e.code()}})}
        });
        output.write_all(&json::canonical(&answer))?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

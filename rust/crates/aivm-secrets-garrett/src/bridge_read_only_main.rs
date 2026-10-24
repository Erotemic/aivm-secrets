//! `garrett-bridge-read-only`: the same bridge, refusing at startup every
//! configuration outside the read profile the native proofs cover
//! (`manifest-https-v1`, `writes = "deny"`, no legacy forwarding, no
//! coordinator). A read-only release deploys this binary.
#[path = "bridge_main.rs"]
mod bridge;

fn main() {
    bridge::run(true)
}

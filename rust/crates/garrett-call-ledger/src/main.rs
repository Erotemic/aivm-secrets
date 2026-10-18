//! Read compiler JSON on stdin; emit only a validated host-side projection.
use std::io::{self, BufWriter, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-call-ledger [--max-bytes N] [--profile bridge|coordinator] < CHARON_JSON > PROJECTION_JSON");
        return Ok(());
    }
    let (selection, args) = match args.as_slice() {
        [rest @ .., flag, profile] if flag == "--profile" => (profile.as_str(), rest),
        rest => ("bridge", rest),
    };
    let target = match selection {
        "bridge" => garrett_call_ledger::CompilerProfile::Bridge,
        "coordinator" => garrett_call_ledger::CompilerProfile::Coordinator,
        _ => return Err("unknown compiler target profile".into()),
    };
    let max_bytes = match args {
        [] => 8 * 1024 * 1024 * 1024,
        [flag, limit] if flag == "--max-bytes" => limit.parse()?,
        _ => return Err("expected --max-bytes N or no arguments".into()),
    };
    let data = garrett_call_ledger::project(io::stdin().lock(), max_bytes, target)?;
    let mut output = BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut output, &data)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

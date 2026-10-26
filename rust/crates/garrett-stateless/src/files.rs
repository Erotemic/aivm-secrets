//! Bounded file reads; private files must not be readable by other users.
use crate::error::{Error, Result};
use std::io::{Read, Write};
use std::path::Path;

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::Io(format!("{}: {}", path.display(), e.kind())))?;
    let mut out = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut out)?;
    if out.len() > limit {
        return Err(Error::Io(format!("{}: too large", path.display())));
    }
    Ok(out)
}

/// A public input (configuration, certificates, CA bundles).
pub fn read_public(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_bounded(path, limit)
}

/// A secret input (keys, credentials): refused if group or other can read it.
pub fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::Io(format!("{}: {}", path.display(), e.kind())))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Io(format!(
                "{}: must not be accessible to group or others",
                path.display()
            )));
        }
    }
    read_bounded(path, limit)
}

/// Create a new file readable only by its owner; never overwrite.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| Error::Io(format!("{}: {}", path.display(), e.kind())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Replace a private file atomically (key rotation).
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", crate::encoding::random_id()?));
    write_private(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
        .map_err(|e| Error::Io(format!("{}: {}", path.display(), e.kind())))?;
    Ok(())
}

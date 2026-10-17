//! Host paths are selected by the operator and never by protocol messages.
use crate::{Error, Outcome};
use rustix::fs::{open, Mode, OFlags};
use std::{
    fs,
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

pub fn private_directory(path: &Path) -> Outcome<()> {
    if !path.is_absolute() {
        return Err(Error::UnsafeFile);
    }
    for parent in path.ancestors() {
        let info = fs::symlink_metadata(parent).map_err(|_| Error::UnsafeFile)?;
        let own = info.uid() == rustix::process::geteuid().as_raw();
        let root_sticky = info.uid() == 0 && info.mode() & 0o1000 != 0;
        if !info.is_dir() || (!own && info.uid() != 0) || (info.mode() & 0o022 != 0 && !root_sticky)
        {
            return Err(Error::UnsafeFile);
        }
    }
    let info = fs::symlink_metadata(path).map_err(|_| Error::UnsafeFile)?;
    if info.uid() != rustix::process::geteuid().as_raw() || info.mode() & 0o077 != 0 {
        return Err(Error::UnsafeFile);
    }
    Ok(())
}
pub fn read_private(path: &Path, limit: usize) -> Outcome<Vec<u8>> {
    private_directory(path.parent().ok_or(Error::UnsafeFile)?)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| Error::UnsafeFile)?;
    let file = fs::File::from(fd);
    let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
    if !info.is_file()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.mode() & 0o077 != 0
    {
        return Err(Error::UnsafeFile);
    }
    let mut out = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|_| Error::UnsafeFile)?;
    if out.len() > limit {
        return Err(Error::UnsafeFile);
    }
    Ok(out)
}
pub fn broker_socket(path: &Path) -> Outcome<()> {
    if path.file_name() != Some(std::ffi::OsStr::new("broker.sock")) {
        return Err(Error::UnsafeFile);
    }
    private_directory(path.parent().ok_or(Error::UnsafeFile)?)?;
    let info = fs::symlink_metadata(path).map_err(|_| Error::UnsafeFile)?;
    if !info.file_type().is_socket()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.mode() & 0o077 != 0
    {
        return Err(Error::UnsafeFile);
    }
    Ok(())
}

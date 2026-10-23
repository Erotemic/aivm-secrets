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

/// Principal-owned authority scope. Every component is opened without symlink
/// traversal; later operations stay relative to the held directory inode.
pub(crate) struct PrivateDirectory(fs::File);
impl PrivateDirectory {
    pub(crate) fn open(path: &Path) -> Outcome<Self> {
        let directory = Self::trusted_directory(path)?;
        Self::check_private(&directory)?;
        Ok(Self(directory))
    }
    fn trusted_directory(path: &Path) -> Outcome<fs::File> {
        use std::path::Component;
        if !path.is_absolute() {
            return Err(Error::UnsafeFile);
        }
        let mut directory = fs::File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::UnsafeFile)?,
        );
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    Self::check_ancestor(&directory)?;
                    directory = fs::File::from(
                        rustix::fs::openat(
                            &directory,
                            name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(|_| Error::UnsafeFile)?,
                    );
                }
                _ => return Err(Error::UnsafeFile),
            }
        }
        Self::check_ancestor(&directory)?;
        Ok(directory)
    }
    fn check_ancestor(file: &fs::File) -> Outcome<()> {
        let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
        let own = info.uid() == rustix::process::geteuid().as_raw();
        let sticky = info.uid() == 0 && info.mode() & 0o1000 != 0;
        if !info.is_dir() || (!own && info.uid() != 0) || (info.mode() & 0o022 != 0 && !sticky) {
            return Err(Error::UnsafeFile);
        }
        Ok(())
    }
    fn check_private(file: &fs::File) -> Outcome<()> {
        let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
        if !info.is_dir()
            || info.uid() != rustix::process::geteuid().as_raw()
            || info.mode() & 0o077 != 0
        {
            return Err(Error::UnsafeFile);
        }
        Ok(())
    }
    fn name(name: &str) -> Outcome<()> {
        if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\', '\0']) {
            return Err(Error::UnsafeFile);
        }
        Ok(())
    }
    pub(crate) fn same_inode(&self, other: &Self) -> Outcome<bool> {
        let a = self.0.metadata().map_err(|_| Error::UnsafeFile)?;
        let b = other.0.metadata().map_err(|_| Error::UnsafeFile)?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }
    pub(crate) fn child(&self, name: &str) -> Outcome<Self> {
        Self::name(name)?;
        let file = fs::File::from(
            rustix::fs::openat(
                &self.0,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::UnsafeFile)?,
        );
        Self::check_private(&file)?;
        Ok(Self(file))
    }
    pub(crate) fn create_directory(&self, name: &str) -> Outcome<Self> {
        Self::name(name)?;
        rustix::fs::mkdirat(&self.0, name, Mode::from_raw_mode(0o700))
            .map_err(|_| Error::UnsafeFile)?;
        self.sync()?;
        self.child(name)
    }
    fn checked_file(file: &fs::File) -> Outcome<()> {
        let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
        if !info.is_file()
            || info.uid() != rustix::process::geteuid().as_raw()
            || info.mode() & 0o077 != 0
            || info.nlink() != 1
        {
            return Err(Error::UnsafeFile);
        }
        Ok(())
    }
    pub(crate) fn file(&self, name: &str, write: bool) -> Outcome<fs::File> {
        Self::name(name)?;
        let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
        let file = fs::File::from(
            rustix::fs::openat(
                &self.0,
                name,
                access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| Error::UnsafeFile)?,
        );
        Self::checked_file(&file)?;
        Ok(file)
    }
    pub(crate) fn read(&self, name: &str, limit: usize) -> Outcome<Vec<u8>> {
        let file = self.file(name, false)?;
        let mut out = Vec::new();
        file.take((limit + 1) as u64)
            .read_to_end(&mut out)
            .map_err(|_| Error::UnsafeFile)?;
        if out.len() > limit {
            return Err(Error::UnsafeFile);
        }
        Ok(out)
    }
    pub(crate) fn create_file(&self, name: &str) -> Outcome<fs::File> {
        Self::name(name)?;
        let file = fs::File::from(
            rustix::fs::openat(
                &self.0,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| Error::UnsafeFile)?,
        );
        Self::checked_file(&file)?;
        Ok(file)
    }
    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> Outcome<()> {
        use std::io::Write;
        let mut file = self.create_file(name)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::InternalError)?;
        self.sync()
    }
    pub(crate) fn replace(&self, name: &str, bytes: &[u8]) -> Outcome<()> {
        // Existing state must remain a private regular inode. Renaming replaces
        // its directory entry; no link target is ever followed or written.
        self.file(name, false)?;
        let temp = format!(".state-{}", random_id()?);
        self.write_new(&temp, bytes)?;
        rustix::fs::renameat(&self.0, &temp, &self.0, name).map_err(|_| Error::OutcomeUnknown)?;
        self.sync().map_err(|_| Error::OutcomeUnknown)
    }
    pub(crate) fn publish_new(&self, name: &str, bytes: &[u8]) -> Outcome<()> {
        Self::name(name)?;
        let staged = format!(".issued-{}", random_id()?);
        self.write_new(&staged, bytes)?;
        // A failed rename acknowledgement can follow completed publication.
        // Keep the same conservative outcome as state-pointer replacement.
        rustix::fs::renameat_with(
            &self.0,
            &staged,
            &self.0,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
        self.sync().map_err(|_| Error::OutcomeUnknown)
    }
    /// Activate an already durable private staging inode. After entering this
    /// operation all failed acknowledgements are conservatively uncertain.
    pub(crate) fn activate_file(&self, staged: &str, target: &str, replace: bool) -> Outcome<()> {
        Self::name(staged)?;
        Self::name(target)?;
        self.file(staged, false)?;
        if replace {
            self.file(target, false)?;
            rustix::fs::renameat(&self.0, staged, &self.0, target)
                .map_err(|_| Error::OutcomeUnknown)?;
        } else {
            rustix::fs::renameat_with(
                &self.0,
                staged,
                &self.0,
                target,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| Error::OutcomeUnknown)?;
        }
        self.sync().map_err(|_| Error::OutcomeUnknown)
    }
    pub(crate) fn publish_directory(&self, staged: &str, target: &str) -> Outcome<()> {
        Self::name(staged)?;
        Self::name(target)?;
        rustix::fs::renameat_with(
            &self.0,
            staged,
            &self.0,
            target,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
        self.sync().map_err(|_| Error::OutcomeUnknown)
    }
    pub(crate) fn exists(&self, name: &str) -> Outcome<bool> {
        Self::name(name)?;
        match rustix::fs::statat(&self.0, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(Error::UnsafeFile),
        }
    }
    pub(crate) fn names(&self) -> Outcome<Vec<String>> {
        let directory = rustix::fs::Dir::read_from(&self.0).map_err(|_| Error::UnsafeFile)?;
        let mut names = Vec::new();
        for entry in directory {
            let entry = entry.map_err(|_| Error::UnsafeFile)?;
            let name = entry.file_name().to_str().map_err(|_| Error::UnsafeFile)?;
            if !matches!(name, "." | "..") {
                Self::name(name)?;
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }
    pub(crate) fn lock(&self, exclusive: bool) -> Outcome<fs::File> {
        self.lock_named(".enrollment.lock", exclusive)
    }
    pub(crate) fn lock_named(&self, name: &str, exclusive: bool) -> Outcome<fs::File> {
        let file = self.file(name, exclusive)?;
        let operation = if exclusive {
            rustix::fs::FlockOperation::LockExclusive
        } else {
            rustix::fs::FlockOperation::LockShared
        };
        rustix::fs::flock(&file, operation).map_err(|_| Error::InternalError)?;
        let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
        let current = rustix::fs::statat(&self.0, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::UnsafeFile)?;
        if info.dev() != current.st_dev || info.ino() != current.st_ino || info.nlink() != 1 {
            return Err(Error::UnsafeFile);
        }
        Ok(file)
    }
    /// Anchor SQLite's pathname-based VFS to this held directory. SQLite
    /// still owns opening/locking sidecars; the directory is host-private.
    #[cfg(feature = "coordinator-server")]
    pub(crate) fn held_path(&self, name: &str) -> Outcome<std::path::PathBuf> {
        use std::os::fd::AsRawFd;
        Self::name(name)?;
        // SQLITE_OPEN_NOFOLLOW rejects /proc/self/fd symlinks as well. Resolve
        // the held directory, then re-open its trusted path and compare inodes.
        // SQLite's own VFS still relies on host-controlled directory stability.
        let resolved = fs::read_link(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
            .map_err(|_| Error::UnsafeFile)?;
        let checked = Self::open(&resolved)?;
        if !self.same_inode(&checked)? {
            return Err(Error::UnsafeFile);
        }
        Ok(resolved.join(name))
    }
    pub(crate) fn sync(&self) -> Outcome<()> {
        self.0.sync_all().map_err(|_| Error::InternalError)
    }
}

/// CA bundles may be public, but their held path and inode must be controlled
/// by root or the current principal. Environment-selected trust is never used.
pub fn read_trusted_public(path: &Path, limit: usize) -> Outcome<Vec<u8>> {
    let directory = PrivateDirectory::trusted_directory(path.parent().ok_or(Error::UnsafeFile)?)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::UnsafeFile)?;
    PrivateDirectory::name(name)?;
    let file = fs::File::from(
        rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeFile)?,
    );
    let info = file.metadata().map_err(|_| Error::UnsafeFile)?;
    if !info.is_file()
        || (info.uid() != 0 && info.uid() != rustix::process::geteuid().as_raw())
        || info.mode() & 0o022 != 0
    {
        return Err(Error::UnsafeFile);
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::UnsafeFile)?;
    if bytes.len() > limit {
        return Err(Error::UnsafeFile);
    }
    Ok(bytes)
}

/// Public unpredictable names; entropy never becomes a secret argument/log.
pub(crate) fn random_id() -> Outcome<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::InternalError)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

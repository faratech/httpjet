//! Linux private, single-writer snapshot storage. Payload schemas belong to the
//! account/order manager; one snapshot must contain all mutually dependent state.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Component,
};

use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};

use crate::AcmeConfig;

const MAX_SNAPSHOT: usize = 1024 * 1024;
const SNAPSHOT: &str = "state.snapshot";
const PENDING: &str = ".state.pending";

/// Holds an exclusive advisory lock on a pinned, pre-provisioned 0700 directory.
/// No Debug implementation: callers must not accidentally log account state.
pub struct PrivateStore {
    directory: File,
    write_failed: bool,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe ACME storage metadata",
    )
}

fn check_file(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > MAX_SNAPSHOT as u64
    {
        return Err(invalid());
    }
    Ok(())
}

impl PrivateStore {
    /// The operator must provision the final directory first. Walk every parent
    /// using openat + NOFOLLOW, never resolving a symlink in the configured path.
    pub fn open(config: &AcmeConfig) -> io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = File::from(fs::open("/", flags, Mode::empty())?);
        let uid = rustix::process::geteuid().as_raw();
        for component in config.storage().components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let parent = directory.metadata()?;
            // Root-owned sticky directories (e.g. /tmp) protect child names from
            // other users. Every child is checked after opening its pinned fd.
            if (parent.uid() != 0 && parent.uid() != uid)
                || (parent.mode() & 0o022 != 0
                    && !(parent.uid() == 0 && parent.mode() & 0o1000 != 0))
            {
                return Err(invalid());
            }
            directory = File::from(fs::openat(&directory, name, flags, Mode::empty())?);
        }
        let metadata = directory.metadata()?;
        if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)?;
        let store = Self {
            directory,
            write_failed: false,
        };
        // Validate persisted state before accepting ownership. A pending write
        // is never promoted: only the fsynced, renamed snapshot is authoritative.
        store.read()?;
        if let Some(pending) = store.open_file(PENDING)? {
            check_file(&pending)?;
            fs::unlinkat(&store.directory, PENDING, AtFlags::empty())?;
            store.directory.sync_all()?;
        }
        Ok(store)
    }

    fn open_file(&self, name: &str) -> io::Result<Option<File>> {
        match fs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => Ok(Some(File::from(fd))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns only committed state, bounded even if a same-uid writer races us.
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(file) = self.open_file(SNAPSHOT)? else {
            return Ok(None);
        };
        check_file(&file)?;
        let mut bytes = Vec::new();
        file.take(MAX_SNAPSHOT as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SNAPSHOT {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }

    /// An error after rename means the new snapshot may already be visible;
    /// callers must stop/reconcile, not assume rollback or retry issuance.
    pub fn replace(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.write_failed {
            return Err(io::Error::other(
                "ACME storage requires reopen after write failure",
            ));
        }
        if bytes.len() > MAX_SNAPSHOT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME snapshot exceeds limit",
            ));
        }
        self.write_failed = true;
        self.replace_inner(bytes)?;
        self.write_failed = false;
        Ok(())
    }

    fn replace_inner(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(old) = self.open_file(SNAPSHOT)? {
            check_file(&old)?;
        }
        let mut pending = File::from(fs::openat(
            &self.directory,
            PENDING,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        // A restrictive umask must fail closed rather than leave unreadable state.
        check_file(&pending)?;
        pending.write_all(bytes)?;
        pending.sync_all()?;
        fs::renameat(&self.directory, PENDING, &self.directory, SNAPSHOT)?;
        self.directory.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Directory;
    use std::{
        fs as stdfs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hj-acme-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            stdfs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn config(&self) -> AcmeConfig {
            AcmeConfig::new(
                Directory::parse("https://ca.test/directory", false).unwrap(),
                &["example.test"],
                self.0.clone(),
                true,
            )
            .unwrap()
        }
        fn private_file(&self, name: &str, bytes: &[u8]) {
            stdfs::write(self.0.join(name), bytes).unwrap();
            stdfs::set_permissions(self.0.join(name), stdfs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            stdfs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn snapshot_roundtrip_lock_and_restart() {
        let f = Fixture::new();
        let mut store = PrivateStore::open(&f.config()).unwrap();
        assert!(store.read().unwrap().is_none());
        assert!(PrivateStore::open(&f.config()).is_err());
        store.replace(b"old-account-and-order").unwrap();
        store.replace(b"new-account-and-order").unwrap();
        drop(store);
        f.private_file(PENDING, b"uncommitted partial state");
        let store = PrivateStore::open(&f.config()).unwrap();
        assert_eq!(store.read().unwrap().unwrap(), b"new-account-and-order");
        assert!(!f.0.join(PENDING).exists());
    }
    #[test]
    fn rejects_unsafe_permissions_links_and_oversize() {
        let f = Fixture::new();
        stdfs::set_permissions(&f.0, stdfs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        stdfs::set_permissions(&f.0, stdfs::Permissions::from_mode(0o700)).unwrap();
        f.private_file("other", b"secret");
        symlink("other", f.0.join(SNAPSHOT)).unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        stdfs::remove_file(f.0.join(SNAPSHOT)).unwrap();
        stdfs::hard_link(f.0.join("other"), f.0.join(SNAPSHOT)).unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        stdfs::remove_file(f.0.join(SNAPSHOT)).unwrap();
        let mut store = PrivateStore::open(&f.config()).unwrap();
        assert!(store.replace(&vec![0; MAX_SNAPSHOT + 1]).is_err());
        assert!(store.read().unwrap().is_none());
    }
    #[test]
    fn symlink_parent_and_pending_fail_closed() {
        let f = Fixture::new();
        symlink(&f.0, f.0.join("alias")).unwrap();
        let config = AcmeConfig::new(
            Directory::parse("https://ca.test/dir", false).unwrap(),
            &["example.test"],
            f.0.join("alias"),
            true,
        )
        .unwrap();
        assert!(PrivateStore::open(&config).is_err());
        symlink("missing", f.0.join(PENDING)).unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        assert!(f.0.join(PENDING).is_symlink());
    }

    #[test]
    fn failed_write_preserves_committed_state_and_requires_reopen() {
        let f = Fixture::new();
        let mut store = PrivateStore::open(&f.config()).unwrap();
        store.replace(b"committed").unwrap();
        f.private_file(PENDING, b"interrupted");
        assert!(store.replace(b"replacement").is_err());
        stdfs::remove_file(f.0.join(PENDING)).unwrap();
        assert!(store.replace(b"retry").is_err());
        assert_eq!(store.read().unwrap().unwrap(), b"committed");
        drop(store);
        let mut reopened = PrivateStore::open(&f.config()).unwrap();
        reopened.replace(b"reconciled").unwrap();
        assert_eq!(reopened.read().unwrap().unwrap(), b"reconciled");
    }

    #[test]
    fn unsafe_snapshot_objects_are_rejected_without_blocking() {
        let f = Fixture::new();
        fs::mknodat(
            fs::CWD,
            f.0.join(SNAPSHOT),
            fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        stdfs::remove_file(f.0.join(SNAPSHOT)).unwrap();
        f.private_file(SNAPSHOT, b"secret");
        stdfs::set_permissions(f.0.join(SNAPSHOT), stdfs::Permissions::from_mode(0o644)).unwrap();
        assert!(PrivateStore::open(&f.config()).is_err());
        f.private_file(SNAPSHOT, &vec![0; MAX_SNAPSHOT + 1]);
        assert!(PrivateStore::open(&f.config()).is_err());
    }
}

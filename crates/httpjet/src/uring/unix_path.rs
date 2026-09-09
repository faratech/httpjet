//! Filesystem ownership for self-bound Unix listeners. Inherited listeners never
//! acquire this guard: their pathname belongs to the socket-activation manager.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::{Path, PathBuf},
};

pub(crate) struct OwnedUnixPath {
    // Pin the directory across renames and symlink changes in ancestor paths.
    _directory: File,
    pinned_path: PathBuf,
    requested_path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedUnixPath {
    pub(super) fn bind(path: &Path) -> io::Result<(UnixListener, Self)> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unix listener needs a filename",
            )
        })?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let metadata = directory.metadata()?;
        // Sticky directories (e.g. /tmp) protect our socket from other users.
        // Otherwise directory entries must not be writable by group/other.
        // The operator/root remains trusted; inode checks are not a sandbox
        // against another process running with our own privileges.
        let uid = unsafe { libc::geteuid() };
        if ![0, uid].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unix listener directory must be operator-owned and protected from entry replacement",
            ));
        }
        let pinned_path =
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        // Never probe-and-unlink an existing entry: connect failure does not
        // prove ownership, and may mean permission failure rather than staleness.
        let listener = UnixListener::bind(&pinned_path)?;
        let metadata = std::fs::symlink_metadata(&pinned_path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other(
                "unix listener pathname changed during bind",
            ));
        }
        let owned = Self {
            _directory: directory,
            pinned_path,
            requested_path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(&owned.pinned_path, std::fs::Permissions::from_mode(0o660))?;
        listener.set_nonblocking(true)?;
        Ok((listener, owned))
    }

    pub(crate) fn matches_requested_path(&self, path: &Path) -> bool {
        self.requested_path == path
    }
}

impl Drop for OwnedUnixPath {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.pinned_path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && let Err(error) = std::fs::remove_file(&self.pinned_path)
        {
            tracing::warn!(%error, "could not remove owned unix listener pathname");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hj-owned-uds-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn path(&self) -> PathBuf {
            self.0.join("http.sock")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn owned_socket_is_removed_and_can_be_rebound() {
        let fixture = Fixture::new();
        let (listener, owned) = OwnedUnixPath::bind(&fixture.path()).unwrap();
        assert_eq!(
            std::fs::metadata(fixture.path()).unwrap().mode() & 0o777,
            0o660
        );
        drop(listener);
        drop(owned);
        assert!(!fixture.path().exists());
        let (listener, owned) = OwnedUnixPath::bind(&fixture.path()).unwrap();
        drop(listener);
        drop(owned);
    }

    #[test]
    fn existing_files_symlinks_and_stale_sockets_are_never_removed() {
        let fixture = Fixture::new();
        let path = fixture.path();
        std::fs::write(&path, b"unrelated").unwrap();
        assert!(OwnedUnixPath::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"unrelated");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing-target", &path).unwrap();
        assert!(OwnedUnixPath::bind(&path).is_err());
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        std::fs::remove_file(&path).unwrap();
        drop(UnixListener::bind(&path).unwrap());
        let inode = std::fs::metadata(&path).unwrap().ino();
        assert!(OwnedUnixPath::bind(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    }

    #[test]
    fn retirement_preserves_replacement_entry() {
        let fixture = Fixture::new();
        let (listener, owned) = OwnedUnixPath::bind(&fixture.path()).unwrap();
        std::fs::remove_file(fixture.path()).unwrap();
        let replacement = UnixListener::bind(fixture.path()).unwrap();
        let inode = std::fs::metadata(fixture.path()).unwrap().ino();
        drop(listener);
        drop(owned);
        assert_eq!(std::fs::metadata(fixture.path()).unwrap().ino(), inode);
        drop(replacement);
    }

    #[test]
    fn cleanup_follows_pinned_directory_not_replaced_parent() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let (listener, owned) = OwnedUnixPath::bind(&parent.join("http.sock")).unwrap();
        let moved = fixture.0.join("moved");
        std::fs::rename(&parent, &moved).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("http.sock"), b"replacement").unwrap();
        drop(listener);
        drop(owned);
        assert!(!moved.join("http.sock").exists());
        assert_eq!(
            std::fs::read(parent.join("http.sock")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn unprotected_shared_directory_is_rejected() {
        let fixture = Fixture::new();
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            OwnedUnixPath::bind(&fixture.path()).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!fixture.path().exists());
    }

    #[test]
    fn sticky_shared_directory_is_supported() {
        let fixture = Fixture::new();
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let (listener, owned) = OwnedUnixPath::bind(&fixture.path()).unwrap();
        drop(listener);
        drop(owned);
        assert!(!fixture.path().exists());
    }

    #[test]
    fn final_parent_symlink_is_rejected_without_creating_socket() {
        let fixture = Fixture::new();
        let real = fixture.0.join("real");
        let link = fixture.0.join("link");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(OwnedUnixPath::bind(&link.join("http.sock")).is_err());
        assert!(!real.join("http.sock").exists());
    }
}

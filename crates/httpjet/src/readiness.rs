//! A process-owned readiness marker for foreground service supervisors.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ReadyFile {
    _directory: File,
    // Keep the inode allocated until cleanup, including after pathname removal.
    _file: File,
    destination: PathBuf,
    staged: PathBuf,
    device: u64,
    inode: u64,
}

impl ReadyFile {
    pub(crate) fn prepare(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--ready-file requires an absolute path",
            ));
        }
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--ready-file requires a filename",
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--ready-file requires a parent directory",
            )
        })?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no preconditions and does not change identity.
        let uid = unsafe { libc::geteuid() };
        if ![0, uid].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "readiness directory must be operator-owned and not writable by group or others",
            ));
        }
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let destination = pinned.join(name);
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace an existing readiness marker",
            ));
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let staged = pinned.join(format!(
            ".httpjet-ready-{}-{nonce}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staged)?;
        let metadata = file.metadata()?;
        let mut marker = Self {
            _directory: directory,
            _file: file,
            destination,
            staged,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        marker
            ._file
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        writeln!(marker._file, "{}", std::process::id())?;
        Ok(marker)
    }

    pub(crate) fn publish(&mut self) -> io::Result<()> {
        // link creates the complete marker atomically and never replaces a path.
        std::fs::hard_link(&self.staged, &self.destination)?;
        std::fs::remove_file(&self.staged)
    }

    fn unlink_owned(&self, path: &Path) {
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_file() && metadata.dev() == self.device && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        self.unlink_owned(&self.destination);
        self.unlink_owned(&self.staged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "httpjet-ready-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn marker(&self) -> PathBuf {
            self.0.join("ready")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn marker_is_private_and_visible_only_after_publication() {
        let fixture = Fixture::new();
        let mut marker = ReadyFile::prepare(&fixture.marker()).unwrap();
        assert!(!fixture.marker().exists());
        marker.publish().unwrap();
        assert_eq!(
            std::fs::read_to_string(fixture.marker()).unwrap(),
            format!("{}\n", std::process::id())
        );
        assert_eq!(
            std::fs::metadata(fixture.marker()).unwrap().mode() & 0o777,
            0o600
        );
        drop(marker);
        assert!(!fixture.marker().exists());
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 0);
    }

    #[test]
    fn existing_files_and_symlinks_are_preserved() {
        let fixture = Fixture::new();
        std::fs::write(fixture.marker(), "keep").unwrap();
        assert!(ReadyFile::prepare(&fixture.marker()).is_err());
        assert_eq!(std::fs::read_to_string(fixture.marker()).unwrap(), "keep");
        std::fs::remove_file(fixture.marker()).unwrap();
        let target = fixture.0.join("target");
        std::fs::write(&target, "target").unwrap();
        std::os::unix::fs::symlink(&target, fixture.marker()).unwrap();
        assert!(ReadyFile::prepare(&fixture.marker()).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "target");
    }

    #[test]
    fn raced_destination_and_replacement_are_never_unlinked() {
        let fixture = Fixture::new();
        let mut marker = ReadyFile::prepare(&fixture.marker()).unwrap();
        std::fs::write(fixture.marker(), "raced").unwrap();
        assert!(marker.publish().is_err());
        drop(marker);
        assert_eq!(std::fs::read_to_string(fixture.marker()).unwrap(), "raced");
        std::fs::remove_file(fixture.marker()).unwrap();
        let mut marker = ReadyFile::prepare(&fixture.marker()).unwrap();
        marker.publish().unwrap();
        std::fs::remove_file(fixture.marker()).unwrap();
        std::fs::write(fixture.marker(), "replacement").unwrap();
        drop(marker);
        assert_eq!(
            std::fs::read_to_string(fixture.marker()).unwrap(),
            "replacement"
        );
    }

    #[test]
    fn cleanup_uses_the_pinned_directory_after_rename() {
        let fixture = Fixture::new();
        let directory = fixture.0.join("original");
        std::fs::create_dir(&directory).unwrap();
        let mut marker = ReadyFile::prepare(&directory.join("ready")).unwrap();
        marker.publish().unwrap();
        let moved = fixture.0.join("moved");
        std::fs::rename(&directory, &moved).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("ready"), "keep").unwrap();
        drop(marker);
        assert!(!moved.join("ready").exists());
        assert_eq!(
            std::fs::read_to_string(directory.join("ready")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn unsafe_parents_and_relative_paths_are_rejected() {
        let fixture = Fixture::new();
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ReadyFile::prepare(&fixture.marker()).is_err());
        assert!(ReadyFile::prepare(Path::new("ready")).is_err());
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = fixture.0.join("alias");
        std::os::unix::fs::symlink(&fixture.0, &alias).unwrap();
        assert!(ReadyFile::prepare(&alias.join("ready")).is_err());
    }
}

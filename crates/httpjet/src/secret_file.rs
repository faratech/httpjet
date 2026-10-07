//! Opening operator-provisioned secrets (tokens, keys). The checks run on the opened
//! descriptor, never through a racy path-based preflight, and a final-component
//! symlink is refused.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Open `path` for reading if it is a single-link regular file owned by root or this
/// process's effective user, with no group or other permission bits.
pub(crate) fn open_private_regular_file(path: &Path) -> io::Result<(File, Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not mutate process identity.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || (metadata.uid() != 0 && metadata.uid() != euid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a single-link regular file owned by root or this user, without group/other permissions",
                path.display()
            ),
        ));
    }
    Ok((file, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_file_open_fails_closed_on_mode_links_and_type() {
        let root = std::env::temp_dir().join(format!("hj-secret-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("secret");
        std::fs::write(&path, [7u8; 32]).unwrap();
        for mode in [0o400, 0o600, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(open_private_regular_file(&path).is_ok(), "{mode:o}");
        }
        for mode in [0o640, 0o644, 0o604, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(open_private_regular_file(&path).is_err(), "{mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_private_regular_file(&link).is_err(), "symlink");
        let hard = root.join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(
            open_private_regular_file(&path).is_err(),
            "second hard link"
        );
        std::fs::remove_file(&hard).unwrap();
        assert!(open_private_regular_file(&root).is_err(), "directory");
        assert!(
            open_private_regular_file(&root.join("absent"))
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

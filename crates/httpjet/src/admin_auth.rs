//! Credential loading for the opt-in local configuration writer.
//! Never log file contents or retain a plaintext token in the authentication state.
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use subtle::ConstantTimeEq;

pub(crate) struct AuthToken([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidToken;

impl std::fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("admin token file or credential rejected")
    }
}
impl std::error::Error for InvalidToken {}
impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken([REDACTED])")
    }
}

fn canonical(token: &[u8]) -> bool {
    token.len() == 64
        && token
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

impl AuthToken {
    #[cfg(test)]
    pub(crate) fn fixture(value: &[u8]) -> Self {
        assert!(canonical(value));
        Self(Sha256::digest(value).into())
    }
    /// Token = 32 random bytes rendered as 64 lowercase hex characters, with an
    /// optional final LF. The path must reside in an operator-controlled directory.
    /// O_NOFOLLOW rejects a final-component symlink; metadata is checked on the
    /// opened descriptor, not through a racy path-based preflight check.
    pub(crate) fn load(path: &Path) -> Result<Self, InvalidToken> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| InvalidToken)?;
        let metadata = file.metadata().map_err(|_| InvalidToken)?;
        // SAFETY: geteuid has no preconditions and does not mutate process identity.
        let euid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
            || (metadata.uid() != 0 && metadata.uid() != euid)
            || metadata.nlink() != 1
            || !matches!(metadata.len(), 64 | 65)
        {
            return Err(InvalidToken);
        }
        // Bounded even if an authorized owner changes the file after metadata.
        let mut bytes = Vec::with_capacity(66);
        file.take(66)
            .read_to_end(&mut bytes)
            .map_err(|_| InvalidToken)?;
        let value = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if !canonical(value) {
            return Err(InvalidToken);
        }
        Ok(Self(Sha256::digest(value).into()))
    }

    pub(crate) fn authenticate(&self, headers: &[httparse::Header<'_>]) -> bool {
        let mut values = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("authorization"));
        let Some(value) = values.next() else {
            return false;
        };
        values.next().is_none() && self.accepts(value.value)
    }

    /// Reject malformed input before hashing; fixed-size digest comparison uses
    /// a maintained constant-time primitive, not an early-exit byte comparison.
    fn accepts(&self, header: &[u8]) -> bool {
        if header.len() != 71 || !header[..7].eq_ignore_ascii_case(b"Bearer ") {
            return false;
        }
        let value = &header[7..];
        if !canonical(value) {
            return false;
        }
        let digest: [u8; 32] = Sha256::digest(value).into();
        bool::from(self.0.ct_eq(&digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hj-admin-auth-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join("token");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn permissions_link_types_and_content_fail_closed() {
        let fixture = Fixture::new();
        for mode in [0o644, 0o640, 0o666, 0o700, 0o4600] {
            assert!(AuthToken::load(&fixture.file(TOKEN, mode)).is_err());
        }
        for value in [
            b"".as_slice(),
            b"short",
            &[b'a'; 66],
            &[b'G'; 64],
            &[b'a'; 63],
        ] {
            assert!(AuthToken::load(&fixture.file(value, 0o600)).is_err());
        }
        let path = fixture.file(TOKEN, 0o600);
        let link = fixture.0.join("link");
        symlink(&path, &link).unwrap();
        assert!(AuthToken::load(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(AuthToken::load(&path).is_err());
        assert!(AuthToken::load(&fixture.0).is_err());
    }
    #[test]
    fn exact_bearer_credentials_and_redacted_debug() {
        let fixture = Fixture::new();
        for mode in [0o400, 0o600] {
            let mut value = TOKEN.to_vec();
            value.push(b'\n');
            let token = AuthToken::load(&fixture.file(&value, mode)).unwrap();
            let mut header = b"Bearer ".to_vec();
            header.extend_from_slice(TOKEN);
            assert!(token.accepts(&header));
            let field = httparse::Header {
                name: "Authorization",
                value: &header,
            };
            assert!(token.authenticate(&[field]));
            assert!(!token.authenticate(&[]));
            assert!(!token.authenticate(&[
                field,
                httparse::Header {
                    name: "aUtHoRiZaTiOn",
                    value: &header
                }
            ]));
            assert_eq!(format!("{token:?}"), "AuthToken([REDACTED])");
            for index in [7, 38, 70] {
                let mut wrong = header.clone();
                wrong[index] = if wrong[index] == b'a' { b'b' } else { b'a' };
                assert!(!token.accepts(&wrong));
            }
            for bad in [b"".as_slice(), TOKEN, b"Basic abc", b"Bearer short"] {
                assert!(!token.accepts(bad));
            }
            header.push(b' ');
            assert!(!token.accepts(&header));
        }
    }
}

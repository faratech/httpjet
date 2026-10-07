//! `.htaccess` HTTP Basic authentication (Tier 1.3).
//!
//! [`AuthRealm`] captures `AuthType Basic` + `AuthName` +
//! `AuthUserFile` (+ `Require valid-user` / `Require user …`). Verification
//! reads the htpasswd file at authorization time (admin-controlled path, low
//! traffic trees) and supports the standard hash formats:
//!
//! * `$2y$` / `$2b$` / `$2a$` bcrypt (htpasswd `-B`, the Apache 2.4 default)
//! * `{SHA}base64(sha1)` (htpasswd `-s`)
//! * `apr1` MD5 → **unsupported**: verifies false
//! * plaintext (htpasswd `-p`) → **unsupported**, as in Apache on Unix: accepting it
//!   would let any readable `user:value` line act as a password
//!
//! `AuthUserFile` is written by whoever controls the `.htaccess`, so the file must
//! resolve inside the docroot or an operator-allowed root ([`open_user_file`]);
//! otherwise the plaintext branch would turn any readable file into a per-line
//! equality oracle.

use std::path::{Component, Path, PathBuf};

/// bcrypt costs above this are refused: each verification would otherwise let a
/// `.htaccess` author pin a worker thread for seconds per request.
pub const MAX_BCRYPT_COST: u32 = 14;

#[derive(Debug, thiserror::Error)]
pub enum AuthFileError {
    #[error("AuthUserFile {path} resolves outside the docroot and the allowed roots")]
    OutsideAllowedRoots { path: PathBuf },
    #[error("AuthUserFile {path} is unreadable: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("AuthUserFile {path} uses bcrypt cost {cost}, above {MAX_BCRYPT_COST}")]
    BcryptCostTooHigh { path: PathBuf, cost: u32 },
}

/// Upper bound on an htpasswd file read per verification.
const MAX_USER_FILE_BYTES: u64 = 1 << 20;

/// Open an `AuthUserFile` for verification. A relative path (no `.`/`..`
/// components) is taken from `doc_root`. The file is opened once and its real
/// path is read back from the descriptor, so containment is judged on exactly the
/// file that will be read: it must lie inside `doc_root` or one of `allowed_roots`.
pub fn open_user_file(
    user_file: &Path,
    doc_root: &Path,
    allowed_roots: &[PathBuf],
) -> Result<std::fs::File, AuthFileError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let outside = || AuthFileError::OutsideAllowedRoots {
        path: user_file.to_path_buf(),
    };
    let unreadable = |source| AuthFileError::Unreadable {
        path: user_file.to_path_buf(),
        source,
    };
    let joined = if user_file.is_absolute() {
        user_file.to_path_buf()
    } else {
        if user_file
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(outside());
        }
        doc_root.join(user_file)
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&joined)
        .map_err(unreadable)?;
    if !file.metadata().map_err(unreadable)?.is_file() {
        return Err(outside());
    }
    let real =
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(unreadable)?;
    let inside = std::iter::once(doc_root)
        .chain(allowed_roots.iter().map(PathBuf::as_path))
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| real.starts_with(root));
    if inside { Ok(file) } else { Err(outside()) }
}

fn bcrypt_cost(hash: &str) -> Option<u32> {
    if !(hash.starts_with("$2y$") || hash.starts_with("$2b$") || hash.starts_with("$2a$")) {
        return None;
    }
    hash.get(4..6)?.parse().ok()
}

/// A user record resolved from an htpasswd file.
pub struct HtpasswdEntry {
    pub user: String,
    pub hash: String,
}

/// Read htpasswd text: `user:hash` per line, `#` comments skipped.
pub fn read_htpasswd(reader: impl std::io::Read) -> std::io::Result<Vec<HtpasswdEntry>> {
    use std::io::Read;
    let mut text = String::new();
    reader.take(MAX_USER_FILE_BYTES).read_to_string(&mut text)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(user, hash)| HtpasswdEntry {
            user: user.trim().to_string(),
            hash: hash.trim().to_string(),
        })
        .collect())
}

/// Verify `pass` against an htpasswd hash. `false` for unsupported schemes
/// (the caller warns once per file at parse time).
pub fn verify_hash(pass: &str, hash: &str) -> bool {
    if hash.starts_with("$2y$") || hash.starts_with("$2b$") || hash.starts_with("$2a$") {
        bcrypt::verify(pass, hash).unwrap_or(false)
    } else if let Some(b64) = hash.strip_prefix("{SHA}") {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
            Ok(expected) if expected.len() == 20 => {
                let digest = sha1_sha1(pass.as_bytes());
                ct_eq(&digest, &expected)
            }
            _ => false,
        }
    } else {
        false // apr1, crypt() and plaintext: unsupported
    }
}

fn sha1_sha1(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

/// Constant-time equality for equal-length secret comparisons.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verify `user`/`pass` against an htpasswd file: the matching entry's hash decides
/// (file read per verification — auth'd trees are low-traffic admin surfaces). An
/// unknown user still pays one bcrypt at the file's cost, so response time does not
/// reveal which users exist.
pub fn verify_credentials(
    user_file: &Path,
    file: std::fs::File,
    user: &str,
    pass: &str,
) -> Result<bool, AuthFileError> {
    let entries = read_htpasswd(file).map_err(|source| AuthFileError::Unreadable {
        path: user_file.to_path_buf(),
        source,
    })?;
    let too_costly = entries
        .iter()
        .filter_map(|e| bcrypt_cost(&e.hash))
        .find(|cost| *cost > MAX_BCRYPT_COST);
    if let Some(cost) = too_costly {
        return Err(AuthFileError::BcryptCostTooHigh {
            path: user_file.to_path_buf(),
            cost,
        });
    }
    let mut matched = false;
    let mut valid = false;
    for entry in entries.iter().filter(|e| ct_eq_str(e.user.as_str(), user)) {
        matched = true;
        valid |= verify_hash(pass, &entry.hash);
    }
    if !matched {
        if let Some(cost) = entries.iter().find_map(|e| bcrypt_cost(&e.hash)) {
            let _ = bcrypt::hash_with_salt(pass, cost, [0u8; 16]);
        }
    }
    Ok(valid)
}

/// Decode a `Basic` Authorization header value (`base64(user:pass)`).
pub fn decode_basic_credentials(encoded: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let joined = String::from_utf8(decoded).ok()?;
    let (user, pass) = joined.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Constant-time string comparison (realm/user checks).
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_hashes_verify() {
        // htpasswd -s user:password
        let hash = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        assert!(verify_hash("password", hash));
        assert!(!verify_hash("wrong", hash));
    }

    #[test]
    fn bcrypt_hashes_verify() {
        // htpasswd -bnBC 4 user password — generated at test time so the vector
        // is authoritative for the bcrypt crate in the lockfile.
        let hash = bcrypt::hash("password", 4).expect("bcrypt hash");
        assert!(hash.starts_with("$2"));
        assert!(verify_hash("password", &hash));
        assert!(!verify_hash("definitely-wrong", &hash));
    }

    #[test]
    fn plaintext_entries_never_verify() {
        assert!(!verify_hash("secret", "secret"));
        assert!(!verify_hash("", ""));
    }

    #[test]
    fn apr1_and_crypt_are_unsupported() {
        assert!(!verify_hash("x", "$apr1$salt$hash"));
        assert!(!verify_hash("x", "cryptstylehash"));
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hj-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn open_user_file_confines_relative_and_absolute_paths() {
        let base = scratch("confine");
        let doc_root = base.join("docroot");
        let conf = base.join("conf");
        let outside = base.join("outside");
        for dir in [&doc_root, &conf, &outside] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(doc_root.join("users"), "a:b\n").unwrap();
        std::fs::write(conf.join("users"), "a:b\n").unwrap();
        std::fs::write(outside.join("secret"), "line\n").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), doc_root.join("link")).unwrap();
        let roots = [conf.clone()];

        assert!(open_user_file(Path::new("users"), &doc_root, &roots).is_ok());
        assert!(open_user_file(&conf.join("users"), &doc_root, &roots).is_ok());
        assert!(
            matches!(
                open_user_file(&conf.join("users"), &doc_root, &[]),
                Err(AuthFileError::OutsideAllowedRoots { .. })
            ),
            "only the docroot is allowed by default"
        );
        for rejected in [
            PathBuf::from("../outside/secret"),
            PathBuf::from("./users"),
            outside.join("secret"),
            PathBuf::from("link"),
        ] {
            assert!(
                matches!(
                    open_user_file(&rejected, &doc_root, &roots),
                    Err(AuthFileError::OutsideAllowedRoots { .. })
                ),
                "{rejected:?}"
            );
        }
        assert!(matches!(
            open_user_file(Path::new("missing"), &doc_root, &roots),
            Err(AuthFileError::Unreadable { .. })
        ));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn bcrypt_cost_above_the_cap_is_refused_before_hashing() {
        let base = scratch("cost");
        let file = base.join("users");
        std::fs::write(
            &file,
            "admin:$2y$15$abcdefghijklmnopqrstuuvwxyzabcdefghijklmnopqrstuvwxyz12\n",
        )
        .unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            verify_credentials(&file, std::fs::File::open(&file).unwrap(), "admin", "x"),
            Err(AuthFileError::BcryptCostTooHigh { cost: 15, .. })
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn missing_user_pays_the_same_bcrypt_cost() {
        let base = scratch("timing");
        let file = base.join("users");
        let hash = bcrypt::hash("password", 8).unwrap();
        std::fs::write(&file, format!("admin:{hash}\n")).unwrap();
        let verify = |user: &str, pass: &str| {
            verify_credentials(&file, std::fs::File::open(&file).unwrap(), user, pass).unwrap()
        };
        assert!(verify("admin", "password"));
        assert!(!verify("admin", "wrong"));
        let time = |user: &str| {
            let started = std::time::Instant::now();
            for _ in 0..4 {
                assert!(!verify(user, "wrong"));
            }
            started.elapsed()
        };
        let (known, unknown) = (time("admin"), time("nobody"));
        assert!(
            unknown * 3 > known,
            "an unknown user must pay a comparable bcrypt: known {known:?}, unknown {unknown:?}"
        );
        assert_eq!(bcrypt_cost(&hash), Some(8));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn basic_credentials_decode() {
        // base64("user:pass")
        let (u, p) = decode_basic_credentials("dXNlcjpwYXNz").unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("user", "pass"));
        assert!(decode_basic_credentials("!!!").is_none());
        assert!(decode_basic_credentials("dXNlcg==").is_none(), "no colon");
    }

    #[test]
    fn usernames_require_exact_case_and_length() {
        assert!(!ct_eq_str("Admin", "admin"));
        let long = format!("admin{}", "x".repeat(256));
        assert!(!ct_eq_str(&long, "admin"));
        assert!(!ct_eq_str("admin", &long));
    }
}

/// (Tier 1.3) A resolved Basic-auth realm from one `.htaccess` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRealm {
    pub realm: String,
    pub user_file: std::path::PathBuf,
    pub require_valid_user: bool,
    pub require_users: Vec<String>,
}

impl AuthRealm {
    /// `WWW-Authenticate` challenge value for a 401 response.
    pub fn challenge(&self) -> String {
        let escaped = self.realm.replace('\\', "\\\\").replace('"', "\\\"");
        format!("Basic realm=\"{escaped}\"")
    }

    /// True when `user` satisfies the realm's `Require` directives.
    pub fn user_satisfies(&self, user: &str) -> bool {
        if self.require_valid_user {
            return true;
        }
        self.require_users
            .iter()
            .any(|u| crate::auth::ct_eq_str(u, user))
    }
}

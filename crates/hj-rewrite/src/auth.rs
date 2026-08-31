//! `.htaccess` HTTP Basic authentication (Tier 1.3).
//!
//! [`crate::htaccess::AuthRealm`] captures `AuthType Basic` + `AuthName` +
//! `AuthUserFile` (+ `Require valid-user` / `Require user …`). Verification
//! reads the htpasswd file at authorization time (admin-controlled path, low
//! traffic trees) and supports the standard hash formats:
//!
//! * `$2y$` / `$2b$` / `$2a$` bcrypt (htpasswd `-B`, the Apache 2.4 default)
//! * `{SHA}base64(sha1)` (htpasswd `-s`)
//! * `apr1` MD5 → **unsupported**: verifies false and is warned at parse time
//! * plaintext (htpasswd `-p`) — constant-time compared, warned at parse time

use std::path::Path;

/// A user record resolved from an htpasswd file.
pub struct HtpasswdEntry {
    pub user: String,
    pub hash: String,
}

/// Read the htpasswd file: `user:hash` per line, `#` comments skipped.
pub fn read_htpasswd(path: &Path) -> std::io::Result<Vec<HtpasswdEntry>> {
    let text = std::fs::read_to_string(path)?;
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
    } else if hash.contains('$') {
        false // apr1 ($apr1$) and crypt() variants: unsupported
    } else {
        // Plaintext (htpasswd -p): constant-time compare.
        ct_eq(pass.as_bytes(), hash.as_bytes())
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

/// Verify `user`/`pass` against an htpasswd file: the matching entry's hash
/// decides (file read per verification — auth'd trees are low-traffic admin
/// surfaces; mtime-cached credential files are a future optimization).
pub fn verify_credentials(user_file: &Path, user: &str, pass: &str) -> bool {
    match read_htpasswd(user_file) {
        Ok(entries) => entries
            .iter()
            .filter(|e| ct_eq_str(e.user.as_str(), user))
            .any(|e| verify_hash(pass, &e.hash)),
        Err(_) => false,
    }
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
    let (x, y) = (a.as_bytes(), b.as_bytes());
    let mut acc = (x.len() ^ y.len()) as u8;
    for (i, ch) in y.iter().enumerate() {
        acc |= x.get(i).unwrap_or(&0) ^ ch;
    }
    acc == 0
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
    fn plaintext_is_constant_time_compared() {
        assert!(verify_hash("secret", "secret"));
        assert!(!verify_hash("secre", "secret"));
    }

    #[test]
    fn apr1_and_crypt_are_unsupported() {
        assert!(!verify_hash("x", "$apr1$salt$hash"));
        assert!(!verify_hash("x", "cryptstylehash"));
    }

    #[test]
    fn basic_credentials_decode() {
        // base64("user:pass")
        let (u, p) = decode_basic_credentials("dXNlcjpwYXNz").unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("user", "pass"));
        assert!(decode_basic_credentials("!!!").is_none());
        assert!(decode_basic_credentials("dXNlcg==").is_none(), "no colon");
    }
}

/// (Tier 1.3) A resolved Basic-auth realm from one `.htaccess` file.
#[derive(Debug, Clone)]
pub struct AuthRealm {
    pub realm: String,
    pub user_file: std::path::PathBuf,
    pub require_valid_user: bool,
    pub require_users: Vec<String>,
}

impl AuthRealm {
    /// `WWW-Authenticate` challenge value for a 401 response.
    pub fn challenge(&self) -> String {
        format!("Basic realm=\"{}\"", self.realm)
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

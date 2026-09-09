use std::{
    collections::BTreeSet,
    fmt,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Domain,
    Directory,
    Identifiers,
    Storage,
    TermsNotAccepted,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Domain => "ACME requires an explicit ASCII DNS name (no wildcard or IP)",
            Self::Directory => {
                "ACME directory must be HTTPS, or explicit test-mode HTTP on a loopback IP"
            }
            Self::Identifiers => "ACME requires 1..100 distinct identifiers",
            Self::Storage => {
                "ACME storage must be an absolute non-root path without dot components"
            }
            Self::TermsNotAccepted => "ACME terms acceptance must be explicit",
        })
    }
}
impl std::error::Error for ConfigError {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Domain(String);
impl Domain {
    /// DNS-01 additionally supports a single complete leftmost wildcard label.
    pub fn parse_dns01(value: &str) -> Result<Self, ConfigError> {
        match value.strip_prefix("*.") {
            Some(base) => {
                let base = Self::parse(base)?;
                if base.0.len() > 251 {
                    return Err(ConfigError::Domain);
                }
                Ok(Self(format!("*.{}", base.0)))
            }
            None => Self::parse(value),
        }
    }
    pub fn verification_name(&self) -> String {
        self.0
            .strip_prefix("*.")
            .map_or_else(|| self.0.clone(), |base| format!("a.{base}"))
    }
    pub fn dns_base(&self) -> &str {
        self.0.strip_prefix("*.").unwrap_or(&self.0)
    }
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty()
            || value.len() > 253
            || !value.is_ascii()
            || !value.contains('.')
            || value.parse::<IpAddr>().is_ok()
            || !value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(ConfigError::Domain);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Directory(http::Uri);
impl Directory {
    /// Test mode permits only literal loopback IP HTTP URLs, never a hostname
    /// whose DNS result might change. HTTPS remains the production requirement.
    pub fn parse(value: &str, allow_loopback_http: bool) -> Result<Self, ConfigError> {
        if value.len() > 2048 {
            return Err(ConfigError::Directory);
        }
        let uri: http::Uri = value.parse().map_err(|_| ConfigError::Directory)?;
        let authority = uri.authority().ok_or(ConfigError::Directory)?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if host.is_empty()
            || value.contains('#')
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || uri.path().is_empty()
            || authority.port_u16() == Some(0)
            || (authority.as_str().contains(':')
                && authority.port_u16().is_none()
                && !authority.as_str().ends_with(']'))
        {
            return Err(ConfigError::Directory);
        }
        let allowed = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => {
                allow_loopback_http && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            }
            _ => false,
        };
        if !allowed {
            return Err(ConfigError::Directory);
        }
        Ok(Self(uri))
    }
    pub fn uri(&self) -> &http::Uri {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    directory: Directory,
    domains: BTreeSet<Domain>,
    storage: PathBuf,
    dns01: bool,
}
impl AcmeConfig {
    pub fn new(
        directory: Directory,
        identifiers: &[&str],
        storage: PathBuf,
        accept_terms: bool,
    ) -> Result<Self, ConfigError> {
        Self::build(directory, identifiers, storage, accept_terms, false)
    }
    pub fn new_dns01(
        directory: Directory,
        identifiers: &[&str],
        storage: PathBuf,
        accept_terms: bool,
    ) -> Result<Self, ConfigError> {
        Self::build(directory, identifiers, storage, accept_terms, true)
    }
    fn build(
        directory: Directory,
        identifiers: &[&str],
        storage: PathBuf,
        accept_terms: bool,
        dns01: bool,
    ) -> Result<Self, ConfigError> {
        if !accept_terms {
            return Err(ConfigError::TermsNotAccepted);
        }
        if identifiers.is_empty() || identifiers.len() > 100 {
            return Err(ConfigError::Identifiers);
        }
        let domains: BTreeSet<_> = identifiers
            .iter()
            .map(|s| {
                if dns01 {
                    Domain::parse_dns01(s)
                } else {
                    Domain::parse(s)
                }
            })
            .collect::<Result<_, _>>()?;
        if domains.len() != identifiers.len() {
            return Err(ConfigError::Identifiers);
        }
        if dns01
            && domains
                .iter()
                .any(|d| d.dns_base().len() + "_acme-challenge.".len() > 253)
        {
            return Err(ConfigError::Domain);
        }
        if !storage.is_absolute()
            || storage == Path::new("/")
            || storage.as_os_str().len() > 4096
            || storage.as_os_str().as_encoded_bytes().contains(&0)
            || storage
                .components()
                .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
            || storage
                .as_os_str()
                .as_encoded_bytes()
                .split(|b| *b == b'/')
                .any(|p| p == b".")
        {
            return Err(ConfigError::Storage);
        }
        Ok(Self {
            directory,
            domains,
            storage,
            dns01,
        })
    }
    pub fn directory(&self) -> &Directory {
        &self.directory
    }
    pub fn domains(&self) -> &BTreeSet<Domain> {
        &self.domains
    }
    pub fn storage(&self) -> &Path {
        &self.storage
    }
    pub fn is_dns01(&self) -> bool {
        self.dns01
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_are_explicit_and_canonical() {
        assert_eq!(
            Domain::parse("EXAMPLE.Test.").unwrap().as_str(),
            "example.test"
        );
        for bad in [
            "",
            "*.example.test",
            "127.0.0.1",
            "[::1]",
            "localhost",
            "é.test",
            "x..test",
            "-x.test",
            "x-.test",
            "x.test..",
            "x.test/path",
            "x.test:80",
            " x.test",
            "x_test.test",
        ] {
            assert!(Domain::parse(bad).is_err(), "{bad}");
        }
        assert!(Domain::parse(&format!("{}.test", "x".repeat(64))).is_err());
    }
    #[test]
    fn directory_trust_boundary() {
        assert!(Directory::parse("https://ca.test/directory", false).is_ok());
        for good in ["http://127.0.0.1:14000/dir", "http://[::1]:14000/dir"] {
            assert!(Directory::parse(good, true).is_ok());
            assert!(Directory::parse(good, false).is_err());
        }
        for bad in [
            "http://localhost/dir",
            "http://10.0.0.1/dir",
            "ftp://ca.test/dir",
            "https://u:p@ca.test/dir",
            "https://ca.test/dir?secret=1",
            "https://ca.test/dir#x",
            "https://ca.test:99999/dir",
            "https://ca.test:0/dir",
            "/directory",
        ] {
            assert!(Directory::parse(bad, true).is_err(), "{bad}");
        }
    }
    #[test]
    fn configuration_is_explicit_bounded_and_non_mutating() {
        let dir = Directory::parse("https://ca.test/dir", false).unwrap();
        let make =
            |names: &[&str], path: &str, tos| AcmeConfig::new(dir.clone(), names, path.into(), tos);
        assert!(make(&["a.test"], "/var/lib/httpjet/acme", true).is_ok());
        assert!(make(&["a.test"], "/var/lib/httpjet/acme", false).is_err());
        assert!(make(&[], "/x", true).is_err());
        assert!(make(&["a.test", "A.TEST."], "/x", true).is_err());
        for path in ["/", "relative", "/x/../y", "/x/./y", "/x\0y"] {
            assert!(make(&["a.test"], path, true).is_err(), "{path}");
        }
    }

    #[test]
    fn dns01_requires_room_for_the_challenge_owner() {
        let dir = Directory::parse("https://ca.test/dir", false).unwrap();
        let base = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(45)
        );
        assert_eq!(base.len(), 237);
        let wildcard = format!("*.{base}");
        assert!(AcmeConfig::new_dns01(dir.clone(), &[&base, &wildcard], "/x".into(), true).is_ok());
        let too_long = format!("{base}d");
        assert!(Domain::parse(&too_long).is_ok());
        assert!(AcmeConfig::new_dns01(dir, &[&too_long], "/x".into(), true).is_err());
        for bad in [
            "*.*.example.test",
            "x*.example.test",
            "*.localhost",
            "*.127.0.0.1",
        ] {
            assert!(Domain::parse_dns01(bad).is_err());
        }
    }
}

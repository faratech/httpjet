use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config file {path} is {len} bytes, over the {max}-byte limit")]
    TooLarge { path: PathBuf, len: u64, max: u64 },
    #[error("failed to parse XML in {path}: {msg}")]
    Xml { path: PathBuf, msg: String },
    #[error("invalid <{directive}> value {value:?} in {path}: {reason}")]
    InvalidValue {
        path: PathBuf,
        directive: &'static str,
        value: String,
        reason: String,
    },
    /// A vhost file lacks a directive the vhost cannot be configured without.
    /// Like OLS, the load skips only that vhost.
    #[error("missing <{directive}> in {path}: {reason}")]
    MissingDirective {
        path: PathBuf,
        directive: &'static str,
        reason: String,
    },
}

pub type Result<T> = std::result::Result<T, ConfigError>;

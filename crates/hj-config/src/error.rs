use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse XML in {path}: {msg}")]
    Xml { path: PathBuf, msg: String },
}

pub type Result<T> = std::result::Result<T, ConfigError>;

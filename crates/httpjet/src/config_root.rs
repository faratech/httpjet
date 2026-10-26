use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) fn resolve(
    explicit: Option<PathBuf>,
    environment: Option<OsString>,
    installed: &Path,
) -> anyhow::Result<PathBuf> {
    if let Some(root) = explicit {
        return Ok(root);
    }
    if let Some(root) = environment {
        anyhow::ensure!(!root.is_empty(), "HTTPJET_ROOT must not be empty");
        return Ok(PathBuf::from(root));
    }
    if installed.join("conf/httpd_config.xml").is_file() {
        return Ok(installed.to_path_buf());
    }
    Ok(PathBuf::from("/usr/local/lsws"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_root_takes_precedence_over_environment_and_installation() {
        let root = resolve(
            Some(PathBuf::from("/explicit")),
            Some(OsString::from("/environment")),
            Path::new("/installed"),
        )
        .unwrap();
        assert_eq!(root, Path::new("/explicit"));
    }

    #[test]
    fn explicit_root_takes_precedence_over_empty_environment() {
        assert_eq!(
            resolve(
                Some(PathBuf::from("/explicit")),
                Some(OsString::new()),
                Path::new("/installed"),
            )
            .unwrap(),
            Path::new("/explicit")
        );
    }

    #[test]
    fn environment_root_does_not_require_an_existing_configuration() {
        assert_eq!(
            resolve(
                None,
                Some(OsString::from("/environment")),
                Path::new("/installed"),
            )
            .unwrap(),
            Path::new("/environment")
        );
    }

    #[test]
    fn empty_environment_is_reported_instead_of_selecting_the_working_directory() {
        assert!(resolve(None, Some(OsString::new()), Path::new("/installed")).is_err());
    }

    #[test]
    fn installed_root_is_selected_only_when_its_main_configuration_exists() {
        let directory = std::env::temp_dir().join(format!(
            "httpjet-root-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        assert_eq!(
            resolve(None, None, &directory).unwrap(),
            Path::new("/usr/local/lsws")
        );
        std::fs::create_dir(directory.join("conf")).unwrap();
        std::fs::write(directory.join("conf/httpd_config.xml"), "invalid").unwrap();
        assert_eq!(resolve(None, None, &directory).unwrap(), directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

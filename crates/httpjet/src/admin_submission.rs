use hj_config::parse_bundle;
use hj_core::config::ServerConfig;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    server_xml: String,
    vhosts: Vec<VhostDocument>,
    mime: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VhostDocument {
    name: String,
    xml: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidSubmission;

pub(crate) fn parse(root: &Path, body: &[u8]) -> Result<ServerConfig, InvalidSubmission> {
    if body.len() > crate::admin_protocol::MAX_BODY {
        return Err(InvalidSubmission);
    }
    let submission: Submission = serde_json::from_slice(body).map_err(|_| InvalidSubmission)?;
    if submission.vhosts.len() > 128 {
        return Err(InvalidSubmission);
    }
    let mut documents = BTreeMap::new();
    for vhost in submission.vhosts {
        if vhost.name.is_empty() || documents.insert(vhost.name, vhost.xml).is_some() {
            return Err(InvalidSubmission);
        }
    }
    parse_bundle(root, &submission.server_xml, &documents, &submission.mime)
        .map_err(|_| InvalidSubmission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_rejects_ambiguous_or_incomplete_submissions() {
        let root = Path::new("/synthetic-root");
        let valid = br#"{"server_xml":"<httpServerConfig/>","vhosts":[],"mime":""}"#;
        assert!(parse(root, valid).is_ok());
        for invalid in [
            r#"{"server_xml":"<httpServerConfig/>","vhosts":[]}"#,
            r#"{"server_xml":"<httpServerConfig/>","vhosts":[],"mime":"","secret":"hidden"}"#,
            r#"{"server_xml":"<httpServerConfig/>","server_xml":"<httpServerConfig/>","vhosts":[],"mime":""}"#,
            r#"{"server_xml":"<httpServerConfig/>","vhosts":[{"name":"x","xml":"<virtualHostConfig/>"},{"name":"x","xml":"<virtualHostConfig/>"}],"mime":""}"#,
            r#"{"server_xml":"<httpServerConfig/>","vhosts":[],"mime":""} {}"#,
        ] {
            assert_eq!(
                parse(root, invalid.as_bytes()).err(),
                Some(InvalidSubmission)
            );
        }
        assert!(parse(root, &vec![b' '; crate::admin_protocol::MAX_BODY + 1]).is_err());
    }
}

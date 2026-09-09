use hj_config::parse_bundle;
use std::{collections::BTreeMap, path::Path};

const SERVER: &str = r#"<httpServerConfig>
<serverName>bundle.test</serverName>
<security><fileAccessControl><followSymbolLink>1</followSymbolLink></fileAccessControl></security>
<virtualHostList><virtualHost><name>site</name><vhRoot>$SERVER_ROOT/site</vhRoot>
<configFile>/path/that/must/not/be/read.xml</configFile>
<allowSymbolLink>0</allowSymbolLink></virtualHost></virtualHostList>
</httpServerConfig>"#;

fn documents() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "site".into(),
        "<virtualHostConfig><docRoot>$VH_ROOT/www</docRoot></virtualHostConfig>".into(),
    )])
}

#[test]
fn bundle_normalizes_supplied_documents_without_file_loading() {
    let cfg = parse_bundle(
        Path::new("/synthetic-root"),
        SERVER,
        &documents(),
        "text/custom = xyz",
    )
    .unwrap();
    let site = cfg.vhosts["site"].config.as_ref().unwrap();
    assert_eq!(site.doc_root, Path::new("/synthetic-root/site/www"));
    assert!(!site.allow_symbol_link);
    assert_eq!(cfg.mime.by_suffix["xyz"], "text/custom");
    let mut docs = documents();
    docs.get_mut("site").unwrap().push_str("<broken");
    assert!(parse_bundle(Path::new("/synthetic-root"), SERVER, &docs, "").is_err());
}

#[test]
fn bundle_rejects_missing_extra_duplicate_and_oversized_input() {
    let root = Path::new("/synthetic-root");
    assert!(parse_bundle(root, SERVER, &BTreeMap::new(), "").is_err());
    let mut docs = documents();
    docs.insert("extra".into(), "<virtualHostConfig/>".into());
    assert!(parse_bundle(root, SERVER, &docs, "").is_err());
    let duplicate = SERVER.replace(
        "</virtualHostList>",
        "<virtualHost><name>site</name></virtualHost></virtualHostList>",
    );
    assert!(parse_bundle(root, &duplicate, &documents(), "").is_err());
    assert!(parse_bundle(root, SERVER, &documents(), &"x".repeat(1024 * 1024)).is_err());
    let error = parse_bundle(root, "<secret-value", &documents(), "").unwrap_err();
    assert_eq!(error.to_string(), "invalid configuration submission");
    assert_eq!(format!("{error:?}"), "BundleError");
}

#[test]
fn bundle_requires_single_bounded_documents_without_dtds() {
    let root = Path::new("/synthetic-root");
    for xml in [
        "<wrong/>",
        "<httpServerConfig/><httpServerConfig/>",
        "<httpServerConfig/>trailing",
        "<!DOCTYPE httpServerConfig><httpServerConfig/>",
        "<httpServerConfig><unclosed></httpServerConfig>",
    ] {
        assert!(parse_bundle(root, xml, &BTreeMap::new(), "").is_err());
    }
    let nested = format!(
        "<httpServerConfig>{}{}</httpServerConfig>",
        "<nested>".repeat(64),
        "</nested>".repeat(64)
    );
    assert!(parse_bundle(root, &nested, &BTreeMap::new(), "").is_err());
    assert!(parse_bundle(root, "<httpServerConfig/>", &BTreeMap::new(), "").is_ok());
}

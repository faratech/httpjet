//! Pre-pass that makes LiteSpeed XML read the way OLS's `XmlNode` tree does
//! before the serde layer sees it:
//!
//! - element names match case-insensitively (`util/xmlnode.cpp`
//!   `s_case_insensitive = 1`), so a known element written in another case is
//!   renamed to the schema spelling instead of being silently ignored (#922);
//! - `getChild` returns the FIRST child of a name, so a repeated single-valued
//!   element is dropped after its first occurrence instead of failing the whole
//!   document with serde's `duplicate field` (#923).
//!
//! A document that needs neither change is returned borrowed, byte-for-byte.
//! Malformed XML is also returned unchanged so the serde parse reports it.

use std::borrow::Cow;
use std::path::Path;

use quick_xml::events::Event;

/// Every element name the raw serde structs read (field renames, aliases, and
/// bare field names). `known_names_cover_the_raw_schema` keeps it in sync.
const KNOWN: &[&str] = &[
    "accessControl",
    "accessDenyDir",
    "accessFileName",
    "accessLog",
    "addDefaultCharset",
    "addDefaultCharsetCustomized",
    "addMIMEType",
    "address",
    "addressWeights",
    "allow",
    "allowBrowse",
    "allowList",
    "allowOverride",
    "allowSymbolLink",
    "apacheConf",
    "asnAllow",
    "asnDeny",
    "auth",
    "authorizer",
    "autoIndex",
    "autoLoadHtaccess",
    "autoStart",
    "backlog",
    "bandwidthLimit",
    "base",
    "brCompressLevel",
    "CACertFile",
    "CACertPath",
    "cache",
    "cachePolicy",
    "cacheStatusCode",
    "cacheStorePath",
    "certChain",
    "certFile",
    "CGIRLimit",
    "checkPrivateCache",
    "checkPublicCache",
    "chrootMode",
    "chrootPath",
    "clientCertFile",
    "clientKeyFile",
    "clientVerify",
    "command",
    "compressibleTypes",
    "configFile",
    "connTimeout",
    "context",
    "contextList",
    "CPUHardLimit",
    "CPUSoftLimit",
    "crlFile",
    "customErrorPages",
    "defaultCharsetCustomized",
    "deny",
    "denyList",
    "detachedMode",
    "dir",
    "docRoot",
    "domain",
    "enable",
    "enableBrCompress",
    "enableCache",
    "enabled",
    "enableDynBrCompress",
    "enableDynGzipCompress",
    "enableDynZstdCompress",
    "enableExpires",
    "enableGzipCompress",
    "enableHotlinkCtrl",
    "enablePostCache",
    "enablePrivateCache",
    "enablePublicCache",
    "enableScript",
    "enableStapling",
    "enableZstdCompress",
    "env",
    "errCode",
    "errorPage",
    "expectedStatus",
    "expireInSeconds",
    "expires",
    "expiresByType",
    "extMaxIdleTime",
    "extProcessor",
    "extProcessorList",
    "extraHeaders",
    "fall",
    "fileAccessControl",
    "fileETag",
    "fileName",
    "followSymbolLink",
    "forceStrictOwnership",
    "forceType",
    "geoAllow",
    "geoDeny",
    "geoipDBFile",
    "gidMin",
    "group",
    "gzipCompressLevel",
    "handler",
    "healthCheck",
    "host",
    "hotlinkCtrl",
    "htAccess",
    "id",
    "index",
    "indexFiles",
    "indexFiles_useServer",
    "initTimeout",
    "instances",
    "interval",
    "ipc",
    "keepAliveTimeout",
    "keepDays",
    "keyFile",
    "listener",
    "listenerList",
    "listeners",
    "loadBalancePolicy",
    "location",
    "log",
    "logging",
    "logHeaders",
    "map",
    "maxCachedFileSize",
    "maxConnections",
    "maxConns",
    "maxKeepAliveReq",
    "maxMMapFileSize",
    "maxProcessTime",
    "maxReqBodySize",
    "maxReqHeaderSize",
    "maxReqURLLen",
    "member",
    "memHardLimit",
    "memSoftLimit",
    "mode",
    "mount",
    "name",
    "namespace",
    "net",
    "path",
    "pcKeepAliveTimeout",
    "perIpRate",
    "perIpRateWindowSecs",
    "phpConfig",
    "phpHandler",
    "phpIniOverride",
    "pid",
    "privateExpireInSeconds",
    "procHardLimit",
    "procSoftLimit",
    "proxyProtocol",
    "proxyProtocolPeers",
    "quic",
    "quicEnable",
    "realm",
    "realmList",
    "required",
    "respBuffer",
    "respectCacheable",
    "responseTimeout",
    "restrained",
    "retryTimeout",
    "rewrite",
    "rise",
    "rollingSize",
    "rules",
    "runOnStartUp",
    "scriptHandler",
    "scriptHandlerList",
    "secure",
    "security",
    "serverName",
    "setUIDMode",
    "storage",
    "subFilter",
    "subFilterMaxBody",
    "subFilterOnce",
    "subFilterTypes",
    "suexec",
    "suexecGroup",
    "suexecUser",
    "suffix",
    "suffixes",
    "suspendedVhosts",
    "timeout",
    "totalInMemCacheSize",
    "totalMMapCacheSize",
    "tuning",
    "type",
    "uidMin",
    "uri",
    "url",
    "useIpInProxyHeader",
    "user",
    "useServer",
    "uts",
    "verifyDepth",
    "vhDomain",
    "vhName",
    "vhost",
    "vhostMap",
    "vhostMapList",
    "vhRoot",
    "vhssl",
    "vhTemplate",
    "vhTemplateList",
    "virtualHost",
    "virtualHostList",
    "websocket",
    "websocketList",
    "zstdCompressLevel",
];

/// `(parent, child)` pairs the serde layer reads as a list (`Vec` fields).
/// Every other known child keeps only its first occurrence.
const REPEATABLE: &[(&str, &str)] = &[
    ("accessControl", "allow"),
    ("accessControl", "allowList"),
    ("accessControl", "deny"),
    ("accessControl", "denyList"),
    ("accessDenyDir", "dir"),
    ("context", "subFilter"),
    ("contextList", "context"),
    ("customErrorPages", "errorPage"),
    ("extProcessor", "address"),
    ("extProcessor", "env"),
    ("extProcessorList", "extProcessor"),
    ("listenerList", "listener"),
    ("phpConfig", "env"),
    ("phpConfig", "phpHandler"),
    ("realmList", "realm"),
    ("rewrite", "map"),
    ("scriptHandlerList", "scriptHandler"),
    ("vhTemplate", "member"),
    ("vhTemplateList", "vhTemplate"),
    ("vhostMapList", "vhostMap"),
    ("virtualHostList", "virtualHost"),
    ("websocketList", "websocket"),
];

fn canonical(name: &[u8]) -> Option<&'static str> {
    KNOWN
        .iter()
        .copied()
        .find(|k| k.as_bytes().eq_ignore_ascii_case(name))
}

struct Frame<'a> {
    name: Cow<'a, str>,
    seen: Vec<&'static str>,
}

/// Apply OLS element-name and first-child semantics (see the module docs).
pub(super) fn normalize<'a>(text: &'a str, path: &Path) -> Cow<'a, str> {
    match plan(text, path) {
        Some(edits) if !edits.is_empty() => {
            let mut out = String::with_capacity(text.len());
            let mut at = 0;
            for (start, end, replacement) in edits {
                out.push_str(&text[at..start]);
                out.push_str(replacement);
                at = end;
            }
            out.push_str(&text[at..]);
            Cow::Owned(out)
        }
        _ => Cow::Borrowed(text),
    }
}

/// Ordered, non-overlapping `(start, end, replacement)` byte edits, or `None`
/// when the document does not tokenize.
fn plan<'a>(text: &'a str, path: &Path) -> Option<Vec<(usize, usize, &'static str)>> {
    let mut reader = quick_xml::Reader::from_str(text);
    let mut edits = Vec::new();
    let mut stack: Vec<Frame<'a>> = Vec::new();
    // (depth inside the dropped element, its start offset)
    let mut skipping: Option<(usize, usize)> = None;
    loop {
        let before = usize::try_from(reader.buffer_position()).ok()?;
        let event = reader.read_event().ok()?;
        let after = usize::try_from(reader.buffer_position()).ok()?;
        match event {
            Event::Start(ref tag) | Event::Empty(ref tag) => {
                let opens = matches!(event, Event::Start(_));
                if let Some((depth, _)) = skipping.as_mut() {
                    if opens {
                        *depth += 1;
                    }
                    continue;
                }
                let raw = tag.name().into_inner().as_bytes();
                let known = canonical(raw);
                if let (Some(name), Some(parent)) = (known, stack.last_mut()) {
                    let repeatable = REPEATABLE
                        .iter()
                        .any(|(p, c)| *p == parent.name && *c == name);
                    if !repeatable && parent.seen.contains(&name) {
                        tracing::warn!(
                            path = %path.display(),
                            parent = %parent.name,
                            element = name,
                            "duplicated <{name}> ignored; the first occurrence applies (OLS getChild)"
                        );
                        if opens {
                            skipping = Some((1, before));
                        } else {
                            edits.push((before, after, ""));
                        }
                        continue;
                    }
                    parent.seen.push(name);
                }
                if let Some(name) = known.filter(|n| n.as_bytes() != raw) {
                    tracing::warn!(
                        path = %path.display(),
                        element = %String::from_utf8_lossy(raw),
                        "element name case differs from the schema; reading it as <{name}>"
                    );
                    let at = before + 1;
                    edits.push((at, at + raw.len(), name));
                }
                if opens {
                    let name = match known {
                        Some(name) => Cow::Borrowed(name),
                        None => Cow::Owned(String::from_utf8_lossy(raw).into_owned()),
                    };
                    stack.push(Frame {
                        name,
                        seen: Vec::new(),
                    });
                }
            }
            Event::End(ref tag) => {
                if let Some((depth, start)) = skipping.as_mut() {
                    *depth -= 1;
                    if *depth == 0 {
                        edits.push((*start, after, ""));
                        skipping = None;
                    }
                    continue;
                }
                stack.pop();
                let raw = tag.name().into_inner().as_bytes();
                if let Some(name) = canonical(raw).filter(|n| n.as_bytes() != raw) {
                    let at = before + 2;
                    edits.push((at, at + raw.len(), name));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    // Start/End tags carry no inner whitespace before the name in valid XML;
    // verify the computed name offsets before trusting them.
    let consistent = edits.iter().all(|(start, end, replacement)| {
        replacement.is_empty()
            || text
                .get(*start..*end)
                .is_some_and(|s| s.eq_ignore_ascii_case(replacement))
    });
    consistent.then_some(edits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(text: &str) -> String {
        normalize(text, Path::new("<test>")).into_owned()
    }

    #[test]
    fn canonical_documents_are_borrowed_unchanged() {
        let text = "<?xml version=\"1.0\"?>\n<virtualHostConfig>\n  <docRoot>/a</docRoot>\n  \
                    <contextList><context><uri>/</uri></context><context><uri>/b</uri></context></contextList>\n\
                    <!-- c --><unknownThing>x</unknownThing><unknownThing>y</unknownThing>\n</virtualHostConfig>";
        assert!(matches!(
            normalize(text, Path::new("<test>")),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn mis_cased_known_names_are_renamed() {
        assert_eq!(
            norm("<r><Security><AccessControl><DENY>ALL</DENY></AccessControl></Security></r>"),
            "<r><security><accessControl><deny>ALL</deny></accessControl></security></r>"
        );
        assert_eq!(norm("<r><DOCROOT/></r>"), "<r><docRoot/></r>");
    }

    #[test]
    fn repeated_single_child_keeps_the_first() {
        assert_eq!(
            norm("<r><docRoot>/a</docRoot>\n<docRoot>/b</docRoot><DocRoot/></r>"),
            "<r><docRoot>/a</docRoot>\n</r>"
        );
        assert_eq!(
            norm(
                "<r><rewrite><enable>1</enable></rewrite><rewrite><rules><x/></rules></rewrite></r>"
            ),
            "<r><rewrite><enable>1</enable></rewrite></r>"
        );
    }

    #[test]
    fn list_children_are_kept() {
        let text = "<r><extProcessorList><extProcessor><address>a</address><address>b</address>\
                    <env>A=1</env><env>B=2</env></extProcessor><extProcessor/></extProcessorList></r>";
        assert_eq!(norm(text), text);
    }

    #[test]
    fn malformed_xml_is_left_for_the_parser() {
        let text = "<r><docRoot>/a</docroot></r>";
        assert_eq!(norm(text), text);
    }

    /// Every element the raw serde structs read is in `KNOWN`, and every list
    /// field's element is in `REPEATABLE`, so neither table can drift.
    #[test]
    fn known_names_cover_the_raw_schema() {
        let src = include_str!("raw.rs");
        let mut attrs = String::new();
        for line in src.lines().map(str::trim) {
            if line.starts_with("#[")
                || (!attrs.is_empty()
                    && line.starts_with(|c: char| c == '"' || c == ')' || c.is_ascii_alphabetic())
                    && !line.starts_with("pub(super)"))
            {
                attrs.push_str(line);
                continue;
            }
            let Some(field) = line.strip_prefix("pub(super) ") else {
                continue;
            };
            if field.starts_with("struct ") {
                attrs.clear();
                continue;
            }
            let Some((ident, ty)) = field.split_once(": ") else {
                continue;
            };
            let quoted = |key: &str| -> Vec<String> {
                attrs
                    .match_indices(key)
                    .filter_map(|(i, _)| {
                        let rest = &attrs[i + key.len()..];
                        rest.split('"').nth(1).map(str::to_string)
                    })
                    .collect()
            };
            let mut names = quoted("rename = ");
            if names.is_empty() {
                names.push(ident.to_string());
            }
            names.extend(quoted("alias = "));
            for name in &names {
                assert!(KNOWN.contains(&name.as_str()), "{name} missing from KNOWN");
                if ty.starts_with("Vec<") {
                    assert!(
                        REPEATABLE.iter().any(|(_, c)| c == name),
                        "{name} missing from REPEATABLE"
                    );
                }
            }
            attrs.clear();
        }
        for (i, a) in KNOWN.iter().enumerate() {
            for b in &KNOWN[i + 1..] {
                assert!(!a.eq_ignore_ascii_case(b), "{a}/{b} collide");
            }
        }
    }
}

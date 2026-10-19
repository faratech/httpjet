//! OLS-parity regressions for the LiteSpeed XML loader (#919-#928).

use std::path::{Path, PathBuf};

use hj_config::{ConfigError, ContextKind, ExtAddress, ExtKind, ServerConfig};

fn root(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ols-parity-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("conf/vhosts")).unwrap();
    dir
}

/// Load a server whose `<virtualHostList>` is `decls` (or one `v` vhost reading
/// `conf/vhosts/v.xml` = `vhost_body`), plus `server_extra` server children.
fn load_full(
    name: &str,
    server_extra: &str,
    decls: Option<&str>,
    vhost_body: &str,
) -> hj_config::Result<ServerConfig> {
    let dir = root(name);
    let decls = decls.map(str::to_string).unwrap_or_else(|| {
        "<virtualHost><name>v</name><vhRoot>/srv/v/</vhRoot>\
         <configFile>$SERVER_ROOT/conf/vhosts/v.xml</configFile></virtualHost>"
            .into()
    });
    std::fs::write(
        dir.join("conf/httpd_config.xml"),
        format!("<httpServerConfig>{server_extra}<virtualHostList>{decls}</virtualHostList></httpServerConfig>"),
    )
    .unwrap();
    std::fs::write(
        dir.join("conf/vhosts/v.xml"),
        format!("<virtualHostConfig>{vhost_body}</virtualHostConfig>"),
    )
    .unwrap();
    hj_config::load(&dir)
}

fn load_vhost(name: &str, vhost_body: &str) -> hj_config::Result<ServerConfig> {
    load_full(name, "", None, vhost_body)
}

fn vhost(cfg: &ServerConfig) -> &hj_config::VHostConfig {
    cfg.vhosts["v"].config.as_deref().expect("vhost loaded")
}

fn invalid(result: hj_config::Result<ServerConfig>) -> (&'static str, String) {
    match result {
        Err(ConfigError::InvalidValue {
            directive, value, ..
        }) => (directive, value),
        other => panic!("expected InvalidValue, got {:?}", other.map(|_| ())),
    }
}

fn context(uri: &str, extra: &str) -> String {
    format!(
        "<docRoot>/srv/v/html/</docRoot><contextList><context><type>null</type>\
         <uri>{uri}</uri>{extra}</context></contextList>"
    )
}

#[test]
fn regex_and_relative_context_uris_are_rejected_919() {
    for (i, uri) in ["exp:^/admin", "EXP:\\.php$", "admin/"]
        .into_iter()
        .enumerate()
    {
        let (directive, value) = invalid(load_vhost(
            &format!("919-{i}"),
            &context(uri, "<allowBrowse>0</allowBrowse>"),
        ));
        assert_eq!((directive, value.as_str()), ("context.uri", uri));
    }
    let cfg = load_vhost(
        "919-ok",
        &context("/admin/", "<allowBrowse>0</allowBrowse>"),
    )
    .unwrap();
    assert!(!vhost(&cfg).contexts[0].allow_browse);
}

#[test]
fn context_location_expands_like_ols_920() {
    let cases = [
        ("assets/", "/srv/v/html/assets/"),
        ("$DOC_ROOT/x/", "/srv/v/html//x/"),
        ("$doc_root/x/", "/srv/v/html//x/"),
        ("$vh_root/y/", "/srv/v//y/"),
        ("/abs/$VH_DOMAIN/", "/abs/v.example/"),
        ("$Server_Root/z", "SERVER/z"),
    ];
    for (i, (location, want)) in cases.into_iter().enumerate() {
        let name = format!("920-{i}");
        let body = format!(
            "<vhDomain>v.example</vhDomain>{}",
            context("/a/", &format!("<location>{location}</location>"))
        );
        let cfg = load_vhost(&name, &body).unwrap();
        let want = want.replace("SERVER", &cfg.server_root.to_string_lossy());
        assert_eq!(
            vhost(&cfg).contexts[0].location.as_deref(),
            Some(Path::new(&want)),
            "{location}"
        );
    }
    // $VH_DOMAIN defaults to the vhost name.
    let cfg = load_vhost(
        "920-default-domain",
        &context("/a/", "<location>/d/$VH_DOMAIN</location>"),
    )
    .unwrap();
    assert_eq!(
        vhost(&cfg).contexts[0].location.as_deref(),
        Some(Path::new("/d/v"))
    );
}

#[test]
fn template_members_and_vhost_listeners_are_rejected_921() {
    let template = |member: &str| {
        format!(
            "<vhTemplateList><vhTemplate><name>t</name><templateFile>x.xml</templateFile>\
             <listeners>Default</listeners>{member}</vhTemplate></vhTemplateList>"
        )
    };
    // Prod shape: template-level listeners and no members still load.
    load_full("921-ok", &template(""), None, "<docRoot>/srv</docRoot>").unwrap();
    let (directive, value) = invalid(load_full(
        "921-member",
        &template(
            "<member><vhName>extra.example</vhName><vhDomain>extra.example</vhDomain></member>",
        ),
        None,
        "<docRoot>/srv</docRoot>",
    ));
    assert_eq!(
        (directive, value.as_str()),
        ("vhTemplate.member", "extra.example")
    );
    let (directive, _) = invalid(load_full(
        "921-listeners",
        "",
        Some(
            "<virtualHost><name>v</name><vhRoot>/srv/v/</vhRoot><listeners>Default</listeners>\
             <configFile>$SERVER_ROOT/conf/vhosts/v.xml</configFile></virtualHost>",
        ),
        "<docRoot>/srv</docRoot>",
    ));
    assert_eq!(directive, "virtualHost.listeners");
}

#[test]
fn element_names_are_case_insensitive_922() {
    // A mis-cased vhost ACL is now seen, so the fail-closed check refuses it.
    let (directive, _) = invalid(load_vhost(
        "922-acl",
        "<docRoot>/srv</docRoot><security><accesscontrol><Deny>203.0.113.0/24</Deny></accesscontrol></security>",
    ));
    assert_eq!(directive, "accessControl");
    let cfg = load_vhost(
        "922-browse",
        &context("/p/", "<AllowBrowse>0</AllowBrowse>")
            .replace("<docRoot>", "<DocRoot>")
            .replace("</docRoot>", "</DocRoot>"),
    )
    .unwrap();
    assert!(!vhost(&cfg).contexts[0].allow_browse);
    assert_eq!(vhost(&cfg).doc_root, Path::new("/srv/v/html/"));
    let cfg = load_full(
        "922-server",
        "<TUNING><MaxReqBodySize>8M</MaxReqBodySize></TUNING>",
        None,
        "<docRoot>/srv</docRoot>",
    )
    .unwrap();
    assert_eq!(cfg.tuning.max_req_body_size, 8 << 20);
}

#[test]
fn duplicated_child_takes_the_first_923() {
    let cfg = load_vhost(
        "923",
        "<docRoot>/first/</docRoot><docRoot>/second/</docRoot>\
         <rewrite><enable>1</enable></rewrite><rewrite><enable>0</enable></rewrite>",
    )
    .unwrap();
    assert_eq!(vhost(&cfg).doc_root, Path::new("/first/"));
    assert!(vhost(&cfg).rewrite.enable);
}

#[test]
fn duplicate_vhost_name_keeps_the_first_924() {
    let cfg = load_full(
        "924",
        "",
        Some(
            "<virtualHost><name>v</name><vhRoot>/srv/one/</vhRoot>\
             <configFile>$SERVER_ROOT/conf/vhosts/v.xml</configFile></virtualHost>\
             <virtualHost><name>v</name><vhRoot>/srv/two/</vhRoot>\
             <configFile>$SERVER_ROOT/conf/vhosts/other.xml</configFile></virtualHost>",
        ),
        "<docRoot>$VH_ROOT</docRoot>",
    )
    .unwrap();
    assert_eq!(cfg.vhost_order, vec!["v".to_string()]);
    assert_eq!(cfg.vhosts["v"].vh_root, Path::new("/srv/one/"));
    assert_eq!(vhost(&cfg).doc_root, Path::new("/srv/one/"));
}

#[test]
fn php_ini_override_and_custom_error_pages_fail_closed_925() {
    let (directive, value) = invalid(load_vhost(
        "925-php",
        "<docRoot>/srv</docRoot><phpIniOverride>\n; comment\nphp_admin_value open_basedir \"/srv\"\n</phpIniOverride>",
    ));
    assert_eq!(directive, "phpIniOverride");
    assert!(value.contains("open_basedir"));
    let (directive, _) = invalid(load_vhost(
        "925-ctx-php",
        &context(
            "/a/",
            "<phpIniOverride>php_admin_flag engine off</phpIniOverride>",
        ),
    ));
    assert_eq!(directive, "phpIniOverride");
    let (directive, value) = invalid(load_vhost(
        "925-errors",
        "<docRoot>/srv</docRoot><customErrorPages><errorPage><errCode>404</errCode>\
         <url>/404.html</url></errorPage></customErrorPages>",
    ));
    assert_eq!(
        (directive, value.as_str()),
        ("customErrorPages", "404 /404.html")
    );
    // Empty blocks (the stock LSWS templates) are inert.
    load_vhost(
        "925-empty",
        "<docRoot>/srv</docRoot><phpIniOverride>\n</phpIniOverride><phpIniOverride/>\
         <customErrorPages>\n</customErrorPages>",
    )
    .unwrap();
}

#[test]
fn request_size_limits_out_of_range_use_defaults_926() {
    let tuning = |name: &str, body: &str| {
        load_full(
            name,
            &format!("<tuning>{body}</tuning>"),
            None,
            "<docRoot>/srv</docRoot>",
        )
        .unwrap()
        .tuning
    };
    let d = hj_config::Tuning::default();
    let t = tuning(
        "926-low",
        "<maxReqURLLen>10</maxReqURLLen><maxReqHeaderSize>100</maxReqHeaderSize>\
         <maxReqBodySize>0</maxReqBodySize><maxCachedFileSize>4194304</maxCachedFileSize>",
    );
    assert_eq!(t.max_req_url_len, d.max_req_url_len);
    assert_eq!(t.max_req_header_size, d.max_req_header_size);
    assert_eq!(t.max_req_body_size, d.max_req_body_size);
    assert_eq!(
        t.max_cached_file_size, 4_194_304,
        "maxCachedFileSize is not clamped"
    );
    let t = tuning(
        "926-high",
        "<maxReqURLLen>65537</maxReqURLLen><maxReqHeaderSize>131072</maxReqHeaderSize>",
    );
    assert_eq!(t.max_req_url_len, d.max_req_url_len);
    assert_eq!(t.max_req_header_size, d.max_req_header_size);
    let t = tuning(
        "926-ok",
        "<maxReqURLLen>100</maxReqURLLen><maxReqHeaderSize>131068</maxReqHeaderSize>\
         <maxReqBodySize>4096</maxReqBodySize>",
    );
    assert_eq!(
        (
            t.max_req_url_len,
            t.max_req_header_size,
            t.max_req_body_size
        ),
        (100, 131_068, 4096)
    );
}

#[test]
fn ext_processor_type_and_address_parse_like_ols_927() {
    let ext = |name: &str, body: &str| {
        load_full(
            name,
            &format!(
                "<extProcessorList><extProcessor><name>app</name>{body}</extProcessor></extProcessorList>"
            ),
            None,
            "<docRoot>/srv</docRoot>",
        )
    };
    for (i, (body, kind, path)) in [
        (
            "<type>LSAPI</type><address>UDS://run/a.sock</address>",
            ExtKind::Lsapi,
            "/run/a.sock",
        ),
        (
            "<type>Fcgi</type><address>unix:/run/b.sock</address>",
            ExtKind::FastCgi,
            "/run/b.sock",
        ),
        (
            "<type>Proxy</type><address>Unix:/run/c.sock</address>",
            ExtKind::Proxy,
            "/run/c.sock",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let cfg = ext(&format!("927-{i}"), body).unwrap();
        let processor = &cfg.ext_processors[0];
        assert_eq!(processor.kind, kind, "{body}");
        assert!(
            matches!(&processor.address, ExtAddress::Uds(p) if p == Path::new(path)),
            "{body}: {:?}",
            processor.address
        );
    }
    for (i, body) in [
        "<address>127.0.0.1:9000</address>",
        "<type>servlet</type><address>127.0.0.1:9000</address>",
        "<type>loadbalancer</type><address>127.0.0.1:9000</address>",
        "<type>bogus</type><address>127.0.0.1:9000</address>",
    ]
    .into_iter()
    .enumerate()
    {
        let (directive, _) = invalid(ext(&format!("927-bad-{i}"), body));
        assert_eq!(directive, "extProcessor.type", "{body}");
    }
}

#[test]
fn server_level_script_handlers_merge_under_the_vhost_928() {
    let server = "<scriptHandlerList>\
        <scriptHandler><suffix>php74</suffix><type>lsapi</type><handler>lsphp74</handler></scriptHandler>\
        <scriptHandler><suffix>PHP</suffix><type>lsapi</type><handler>server-php</handler></scriptHandler>\
        </scriptHandlerList>";
    let cfg = load_full(
        "928",
        server,
        None,
        "<docRoot>/srv</docRoot><scriptHandlerList><scriptHandler><suffix>php</suffix>\
         <type>lsapi</type><handler>vhost-php</handler></scriptHandler></scriptHandlerList>",
    )
    .unwrap();
    let handlers = &vhost(&cfg).script_handlers;
    let find = |suffix: &str| {
        let matching: Vec<_> = handlers.iter().filter(|h| h.suffix == suffix).collect();
        assert_eq!(matching.len(), 1, "{suffix}: {handlers:?}");
        matching[0]
    };
    assert_eq!(
        find("php").handler,
        "vhost-php",
        "the vhost entry wins per suffix"
    );
    assert_eq!(find("php74").handler, "lsphp74");
    assert_eq!(find("php74").kind, ContextKind::Lsapi);

    let (directive, _) = invalid(load_full(
        "928-bad",
        "<scriptHandlerList><scriptHandler><suffix>php74</suffix><type>lsapi</type></scriptHandler></scriptHandlerList>",
        None,
        "<docRoot>/srv</docRoot>",
    ));
    assert_eq!(directive, "scriptHandler.handler");
}

/// #936: a comma-separated suffix list yields one handler per suffix.
#[test]
fn script_handler_suffix_list_is_split_936() {
    let cfg = load_full(
        "936",
        "<scriptHandlerList><scriptHandler><suffix>php74, PHP8x,</suffix><type>lsapi</type>\
         <handler>lsphp74</handler></scriptHandler></scriptHandlerList>",
        None,
        "<docRoot>/srv</docRoot>",
    )
    .unwrap();
    let suffixes: Vec<_> = vhost(&cfg)
        .script_handlers
        .iter()
        .map(|h| (h.suffix.as_str(), h.handler.as_str()))
        .collect();
    assert!(suffixes.contains(&("php74", "lsphp74")), "{suffixes:?}");
    assert!(suffixes.contains(&("php8x", "lsphp74")), "{suffixes:?}");
    assert!(
        !suffixes.iter().any(|(s, _)| s.contains(',')),
        "{suffixes:?}"
    );

    let (directive, _) = invalid(load_full(
        "936-dot",
        "",
        None,
        "<docRoot>/srv</docRoot><scriptHandlerList><scriptHandler><suffix>php.bak</suffix>\
         <type>lsapi</type><handler>lsphp</handler></scriptHandler></scriptHandlerList>",
    ));
    assert_eq!(directive, "scriptHandler.suffix");
}

/// #999: context `<rewrite>` rules, `<apacheConf>` (any level) and context
/// `<forceType>`/`<addMIMEType>` are not implemented, so declaring one refuses
/// the load instead of serving without it; empty or disabled blocks stay inert.
#[test]
fn unimplemented_rewrite_apache_conf_and_mime_directives_fail_closed_999() {
    let rules = "<rules>RewriteEngine On\nRewriteRule .* - [F]</rules>";
    for (i, (vhost_rewrite, extra, directive)) in [
        (
            "",
            format!("<rewrite><enable>1</enable>{rules}</rewrite>"),
            "rewrite",
        ),
        // No <enable>: OLS inherits the vhost's rewrite switch.
        (
            "<rewrite><enable>1</enable></rewrite>",
            format!("<rewrite>{rules}</rewrite>"),
            "rewrite",
        ),
        (
            "",
            "<REWRITE><Enable>1</Enable><Rules>RewriteRule ^ - [F]</Rules></REWRITE>".into(),
            "rewrite",
        ),
        (
            "",
            "<apacheConf>Require all denied</apacheConf>".into(),
            "apacheConf",
        ),
        ("", "<forceType>text/plain</forceType>".into(), "forceType"),
        ("", "<ForceType>text/plain</ForceType>".into(), "forceType"),
        (
            "",
            "<addMIMEType>text/plain txt, image/png png</addMIMEType>".into(),
            "addMIMEType",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!("{vhost_rewrite}{}", context("/internal/", &extra));
        let (found, _) = invalid(load_vhost(&format!("999-ctx-{i}"), &body));
        assert_eq!(found, directive, "{body}");
    }
    let (found, value) = invalid(load_vhost(
        "999-vhost-apache",
        "<docRoot>/srv</docRoot><apacheConf>\n# note\nOptions -Indexes\n</apacheConf>",
    ));
    assert_eq!((found, value.as_str()), ("apacheConf", "Options -Indexes"));
    let (found, _) = invalid(load_full(
        "999-server-apache",
        "<apacheConf>Header set X-Frame-Options DENY</apacheConf>",
        None,
        "<docRoot>/srv</docRoot>",
    ));
    assert_eq!(found, "apacheConf");

    for (i, (vhost_extra, extra)) in [
        ("", "<rewrite/>".to_string()),
        ("", "<rewrite></rewrite>".into()),
        ("", format!("<rewrite><enable>0</enable>{rules}</rewrite>")),
        // Inherits the vhost's rewrite switch, absent = off.
        ("", format!("<rewrite>{rules}</rewrite>")),
        (
            "<rewrite><enable>0</enable></rewrite>",
            format!("<rewrite>{rules}</rewrite>"),
        ),
        (
            "",
            "<rewrite><enable>1</enable><rules>\n# only a comment\n</rules></rewrite>".into(),
        ),
        ("", "<apacheConf>\n</apacheConf>".into()),
        ("", "<apacheConf># disabled</apacheConf>".into()),
        (
            "",
            "<forceType>none</forceType><addMIMEType></addMIMEType>".into(),
        ),
        ("", "<forceType>  </forceType>".into()),
    ]
    .into_iter()
    .enumerate()
    {
        let body = format!("{vhost_extra}{}", context("/internal/", &extra));
        load_vhost(&format!("999-inert-{i}"), &body).unwrap_or_else(|e| panic!("{body}: {e}"));
    }
    load_full(
        "999-server-inert",
        "<apacheConf>\n  \n</apacheConf>",
        None,
        "<docRoot>/srv</docRoot><apacheConf/>",
    )
    .unwrap();
}

/// #1000: `<suspendedVhosts>`, the declaration's `<enabled>` and the vhost file's
/// `<enabled>` all disable a vhost (OLS: the declaration gates the file, the
/// suspended list overrides both, absent = enabled).
#[test]
fn disabled_and_suspended_vhosts_are_marked_1000() {
    let disabled = |name: &str, server: &str, decl_enabled: &str, file_enabled: &str| {
        let decl = format!(
            "<virtualHost><name>v</name><vhRoot>/srv/v/</vhRoot>{decl_enabled}\
             <configFile>$SERVER_ROOT/conf/vhosts/v.xml</configFile></virtualHost>"
        );
        let cfg = load_full(
            name,
            server,
            Some(&decl),
            &format!("<docRoot>/srv/v/html/</docRoot>{file_enabled}"),
        )
        .unwrap();
        vhost(&cfg).disabled
    };
    assert!(!disabled("1000-default", "", "", ""));
    assert!(!disabled(
        "1000-on",
        "",
        "<enabled>1</enabled>",
        "<enabled>1</enabled>"
    ));
    assert!(disabled("1000-decl", "", "<enabled>0</enabled>", ""));
    // The declaration gates the file: a file `1` cannot re-enable it.
    assert!(disabled(
        "1000-gate",
        "",
        "<enabled>0</enabled>",
        "<enabled>1</enabled>"
    ));
    assert!(disabled("1000-file", "", "", "<enabled>0</enabled>"));
    assert!(disabled("1000-file-case", "", "", "<Enabled> 0 </Enabled>"));
    // OLS getLongValue: strtoll reads no digits as 0; out of range keeps the default.
    assert!(disabled("1000-strtoll", "", "<enabled>no</enabled>", ""));
    assert!(!disabled(
        "1000-range",
        "",
        "<enabled>2</enabled>",
        "<enabled></enabled>"
    ));
    for (i, list) in ["v", "a, v", "a,v,b", " a v ", "\nv\n"]
        .into_iter()
        .enumerate()
    {
        let server = format!("<suspendedVhosts>{list}</suspendedVhosts>");
        assert!(
            disabled(
                &format!("1000-suspended-{i}"),
                &server,
                "<enabled>1</enabled>",
                ""
            ),
            "{list:?}"
        );
    }
    for (i, list) in ["", "vv", "V", "a,b"].into_iter().enumerate() {
        let server = format!("<suspendedVhosts>{list}</suspendedVhosts>");
        assert!(
            !disabled(&format!("1000-other-{i}"), &server, "", ""),
            "{list:?}"
        );
    }
}

/// #1001: OLS `ConfigCtx::getRootPath` roots a path that starts with neither `/`
/// nor `$` at `$SERVER_ROOT` (never the process cwd), and a vhost needs a docRoot.
#[test]
fn relative_paths_root_at_server_root_and_doc_root_is_required_1001() {
    let cfg = load_full(
        "1001",
        "<listenerList><listener><name>tls</name><address>127.0.0.1:8443</address>\
         <secure>1</secure><keyFile>conf/l.key</keyFile><certFile>conf/l.crt</certFile>\
         <CACertFile>conf/ca.pem</CACertFile><crlFile>conf/l.crl</crlFile></listener></listenerList>",
        Some(
            "<virtualHost><name>v</name><vhRoot>sites/v/</vhRoot>\
             <configFile>conf/vhosts/v.xml</configFile></virtualHost>",
        ),
        "<docRoot>html/</docRoot>\
         <vhssl><keyFile>conf/v.key</keyFile><certFile>$VH_ROOT/v.crt</certFile>\
         <CACertFile>/etc/ca.pem</CACertFile></vhssl>\
         <logging><log><useServer>0</useServer><fileName>logs/v_error.log</fileName></log>\
         <accessLog><useServer>0</useServer><fileName>stdout</fileName></accessLog></logging>\
         <contextList><context><type>null</type><uri>/a/</uri><location>assets/</location></context></contextList>",
    )
    .unwrap();
    let root = cfg.server_root.clone();
    assert_eq!(cfg.vhosts["v"].vh_root, root.join("sites/v/"));
    let v = vhost(&cfg);
    assert_eq!(v.doc_root, root.join("html/"));
    let ssl = v.vhssl.as_ref().expect("vhssl");
    assert_eq!(ssl.key_file, root.join("conf/v.key"));
    assert_eq!(ssl.cert_file, root.join("sites/v/v.crt"));
    assert_eq!(ssl.ca_cert_file.as_deref(), Some(Path::new("/etc/ca.pem")));
    assert_eq!(
        v.error_log_file.as_ref().map(|f| f.path.clone()),
        Some(root.join("logs/v_error.log"))
    );
    assert_eq!(
        v.access_log_file.as_ref().map(|f| f.path.clone()),
        Some(PathBuf::from("stdout")),
        "OLS keeps stdout/stderr verbatim"
    );
    assert_eq!(
        v.contexts[0].location.as_deref(),
        Some(root.join("html/assets/").as_path())
    );
    let tls = cfg.listeners[0].tls.as_ref().expect("listener tls");
    assert_eq!(tls.key_file, root.join("conf/l.key"));
    assert_eq!(tls.cert_file, root.join("conf/l.crt"));
    assert_eq!(
        tls.ca_cert_file.as_deref(),
        Some(root.join("conf/ca.pem").as_path())
    );
    assert_eq!(
        tls.crl_file.as_deref(),
        Some(root.join("conf/l.crl").as_path())
    );

    for (i, body) in ["", "<docRoot></docRoot>", "<docRoot>\n  </docRoot>"]
        .into_iter()
        .enumerate()
    {
        let cfg = load_vhost(&format!("1001-missing-{i}"), body).unwrap();
        assert!(cfg.vhosts["v"].config.is_none(), "{body:?}");
    }
}

/// #1010: OLS `configBasics` fails only the vhost without a document root (a stub
/// file like LSWS's `<virtualHostConfig></virtualHostConfig>` default.xml); the
/// other vhosts load, and the skip is reported with its reason.
#[test]
fn vhost_without_doc_root_skips_only_that_vhost_1010() {
    let dir = root("1010");
    std::fs::write(
        dir.join("conf/httpd_config.xml"),
        "<httpServerConfig><virtualHostList>\
         <virtualHost><name>good</name><vhRoot>/srv/good/</vhRoot>\
         <configFile>$SERVER_ROOT/conf/vhosts/good.xml</configFile></virtualHost>\
         <virtualHost><name>stub</name><vhRoot>/srv/stub/</vhRoot>\
         <configFile>$SERVER_ROOT/conf/vhosts/stub.xml</configFile></virtualHost>\
         </virtualHostList></httpServerConfig>",
    )
    .unwrap();
    std::fs::write(
        dir.join("conf/vhosts/good.xml"),
        "<virtualHostConfig><docRoot>/srv/good/html/</docRoot></virtualHostConfig>",
    )
    .unwrap();
    std::fs::write(
        dir.join("conf/vhosts/stub.xml"),
        "<virtualHostConfig></virtualHostConfig>",
    )
    .unwrap();
    let (cfg, skipped) = hj_config::load_report(&dir).unwrap();
    let good = cfg.vhosts["good"].config.as_deref().expect("good loads");
    assert_eq!(good.doc_root, Path::new("/srv/good/html/"));
    assert!(cfg.vhosts["stub"].config.is_none());
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].name, "stub");
    assert!(
        matches!(
            skipped[0].error,
            ConfigError::MissingDirective {
                directive: "docRoot",
                ..
            }
        ),
        "{:?}",
        skipped[0].error
    );
    assert!(hj_config::load(&dir).is_ok());

    // A security directive httpjet cannot enforce still refuses the whole load.
    std::fs::write(
        dir.join("conf/vhosts/stub.xml"),
        "<virtualHostConfig><docRoot>/srv/stub/</docRoot>\
         <accessControl><deny>ALL</deny></accessControl></virtualHostConfig>",
    )
    .unwrap();
    assert_eq!(invalid(hj_config::load(&dir)).0, "accessControl");
}

fn php_handler(id: &str, command: &str, suffixes: Option<&str>) -> String {
    let suffixes = suffixes
        .map(|s| format!("<suffixes>{s}</suffixes>"))
        .unwrap_or_default();
    format!("<phpHandler><id>{id}</id><command>{command}</command>{suffixes}</phpHandler>")
}

fn load_php(name: &str, handlers: &str) -> hj_config::Result<ServerConfig> {
    load_full(
        name,
        &format!("<phpConfig>{handlers}</phpConfig>"),
        None,
        "<docRoot>/srv</docRoot>",
    )
}

/// #1027: every `<phpHandler>` is read and its `<id>` is a handled suffix
/// (LSWS); handlers sharing one command merge, different commands refuse.
#[test]
fn php_handlers_are_a_list_and_each_id_is_a_suffix_1027() {
    let live = php_handler(
        "php8",
        "/usr/local/lsws/lsphp8/bin/lsphp",
        Some("php, html"),
    );
    let cfg = load_php("1027-live", &live).unwrap();
    let php = cfg.php_config.as_ref().unwrap();
    assert_eq!(php.handler_id, "php8");
    assert_eq!(php.command, Path::new("/usr/local/lsws/lsphp8/bin/lsphp"));
    assert_eq!(php.suffixes, ["php", "html", "php8"]);

    // No <suffixes> keeps the historical `php` default, plus the id.
    let php = load_php("1027-default", &php_handler("php74", "/opt/lsphp", None))
        .unwrap()
        .php_config
        .unwrap();
    assert_eq!(php.suffixes, ["php", "php74"]);

    // Handlers on one command merge; a repeated suffix is listed once.
    let merged = format!(
        "{}{}",
        php_handler("php74", "/opt/lsphp", Some("php74")),
        php_handler("php8", "/opt/lsphp", Some("php, PHP74")),
    );
    let php = load_php("1027-merge", &merged).unwrap().php_config.unwrap();
    assert_eq!(php.handler_id, "php74");
    assert_eq!(php.command, Path::new("/opt/lsphp"));
    assert_eq!(php.suffixes, ["php74", "php", "php8"]);

    // The issue's multi-PHP shape: `.php` belongs to the SECOND handler's binary.
    // One pool cannot run both, so the load is refused instead of serving source.
    for (i, second) in [
        php_handler("php8", "/opt/php8/lsphp", Some("php")),
        php_handler("php8", "", Some("php")),
    ]
    .iter()
    .enumerate()
    {
        let handlers = format!(
            "{}{second}",
            php_handler("php74", "/opt/php74/lsphp", Some("php74"))
        );
        let (directive, value) = invalid(load_php(&format!("1027-conflict-{i}"), &handlers));
        assert_eq!(directive, "phpHandler.command");
        assert!(value.starts_with("php74=/opt/php74/lsphp php8="), "{value}");
    }
}

fn ht_access(mask: &str) -> String {
    format!("<docRoot>/srv</docRoot><htAccess><allowOverride>{mask}</allowOverride></htAccess>")
}

/// #1028: LSWS gates `.htaccess` directives per category at server, vhost and
/// context level; httpjet implements only all-or-nothing per vhost, so any other
/// mask refuses the load. 0 and 31 behave as before.
#[test]
fn partial_allow_override_masks_refuse_the_load_1028() {
    // An empty mask means "inherit" in LSWS, which httpjet does not model.
    for (i, mask) in ["1", "4", "15", "30", "63", "all", "0x1f", "-1", "1,4", ""]
        .into_iter()
        .enumerate()
    {
        let (directive, value) = invalid(load_vhost(&format!("1028-vhost-{i}"), &ht_access(mask)));
        assert_eq!((directive, value.as_str()), ("allowOverride", mask));
    }
    let off = load_vhost("1028-off", &ht_access("0")).unwrap();
    let off = vhost(&off);
    assert_eq!((off.allow_override, off.allow_override_explicit), (0, true));
    assert!(!off.overrides_enabled(true));
    let all = load_vhost("1028-all", &ht_access(" 31 ")).unwrap();
    let all = vhost(&all);
    assert_eq!(
        (all.allow_override, all.allow_override_explicit),
        (31, true)
    );
    assert!(all.overrides_enabled(false));
    let absent = load_vhost(
        "1028-absent",
        "<docRoot>/srv</docRoot><htAccess><accessFileName>.acl</accessFileName></htAccess>",
    )
    .unwrap();
    let absent = vhost(&absent);
    assert_eq!(
        (absent.allow_override, absent.allow_override_explicit),
        (0, false)
    );
    assert_eq!(absent.access_file_name, ".acl");

    // Server level: the ceiling for every vhost; only 31 (or absent) loads.
    for (i, server) in [
        "<htAccess><allowOverride>0</allowOverride></htAccess>",
        "<htAccess><allowOverride>1</allowOverride></htAccess>",
        "<HTACCESS><AllowOverride>30</AllowOverride></HTACCESS>",
    ]
    .into_iter()
    .enumerate()
    {
        let result = load_full(&format!("1028-server-{i}"), server, None, &ht_access("31"));
        assert_eq!(invalid(result).0, "allowOverride", "{server}");
    }
    let (directive, value) = invalid(load_full(
        "1028-server-name",
        "<htAccess><allowOverride>31</allowOverride><accessFileName>.acl</accessFileName></htAccess>",
        None,
        &ht_access("31"),
    ));
    assert_eq!((directive, value.as_str()), ("accessFileName", ".acl"));
    for (i, server) in [
        "",
        "<htAccess/>",
        "<htAccess><allowOverride>31</allowOverride><accessFileName>.htaccess</accessFileName></htAccess>",
    ]
    .into_iter()
    .enumerate()
    {
        let cfg = load_full(&format!("1028-server-ok-{i}"), server, None, &ht_access("31"))
            .unwrap_or_else(|e| panic!("{server}: {e}"));
        assert_eq!(vhost(&cfg).allow_override, 31);
    }
    // A vhost without its own mask inherits the server's; its explicit 0 narrows it.
    let server = "<htAccess><allowOverride>31</allowOverride></htAccess>";
    let cfg = load_full("1028-inherit", server, None, "<docRoot>/srv</docRoot>").unwrap();
    let inherited = vhost(&cfg);
    assert_eq!(
        (inherited.allow_override, inherited.allow_override_explicit),
        (31, false)
    );
    assert!(inherited.overrides_enabled(false));
    let cfg = load_full("1028-narrow", server, None, &ht_access("0")).unwrap();
    assert!(!vhost(&cfg).overrides_enabled(true));
    let cfg = load_full("1028-no-server", "", None, "<docRoot>/srv</docRoot>").unwrap();
    assert!(!vhost(&cfg).overrides_enabled(false));

    // Context level can only narrow, which is not implemented: any mask refuses.
    for (i, mask) in ["0", "1", "31"].into_iter().enumerate() {
        let body = context(
            "/uploads/",
            &format!("<allowOverride>{mask}</allowOverride>"),
        );
        let (directive, value) = invalid(load_vhost(&format!("1028-ctx-{i}"), &body));
        assert_eq!((directive, value.as_str()), ("allowOverride", mask));
    }
    load_vhost(
        "1028-ctx-empty",
        &context("/uploads/", "<allowOverride> </allowOverride>"),
    )
    .unwrap();
}

/// #1029: OLS applies a vhost's own `<vhssl><clientVerify>` on SNI; httpjet
/// verifies client certificates per listener only, so a vhost asking for one
/// refuses the load. Absent, 0 and OLS out-of-range values (= 0) load as before.
#[test]
fn vhost_client_verify_refuses_the_load_1029() {
    let ssl = |extra: &str| {
        format!(
            "<docRoot>/srv</docRoot><vhssl><keyFile>/k.pem</keyFile>\
             <certFile>/c.pem</certFile>{extra}</vhssl>"
        )
    };
    for (i, (vhssl, want)) in [
        (ssl("<clientVerify>2</clientVerify>"), "clientVerify=2"),
        (
            ssl("<clientVerify>1</clientVerify><verifyDepth>3</verifyDepth>"),
            "clientVerify=1 verifyDepth=3",
        ),
        (
            ssl("<ClientVerify> 3 </ClientVerify><crlFile>/x.crl</crlFile>\
                 <CACertPath>/ca/</CACertPath>"),
            "clientVerify=3 crlFile=/x.crl CACertPath=/ca/",
        ),
        // Refused even without the certificate pair that keeps a vhssl block.
        (
            "<docRoot>/srv</docRoot><vhssl><clientVerify>2</clientVerify></vhssl>".into(),
            "clientVerify=2",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (directive, value) = invalid(load_vhost(&format!("1029-{i}"), &vhssl));
        assert_eq!((directive, value.as_str()), ("clientVerify", want));
    }
    for (i, extra) in [
        "",
        "<clientVerify>0</clientVerify>",
        "<clientVerify></clientVerify><verifyDepth>2</verifyDepth><CACertPath>/ca/</CACertPath>",
        "<clientVerify>7</clientVerify>",
    ]
    .into_iter()
    .enumerate()
    {
        let cfg = load_vhost(&format!("1029-ok-{i}"), &ssl(extra))
            .unwrap_or_else(|e| panic!("{extra}: {e}"));
        assert_eq!(
            vhost(&cfg).vhssl.as_ref().map(|s| s.cert_file.clone()),
            Some(PathBuf::from("/c.pem"))
        );
    }
}

/// #1030: `<rewrite><map>` lookups are not implemented, so `${map:key}` would be
/// compared literally; a declared map refuses the load (enabled or not, since
/// `.htaccess` rules can use vhost maps). Empty map elements are inert.
#[test]
fn vhost_rewrite_maps_refuse_the_load_1030() {
    let rewrite = |enable: &str, maps: &str| {
        format!(
            "<docRoot>/srv</docRoot><rewrite><enable>{enable}</enable>{maps}\
             <rules>RewriteEngine On</rules></rewrite>"
        )
    };
    let map = "<map><name>blocked</name><location>txt:/etc/blocked.map</location></map>";
    for (i, enable) in ["1", "0"].into_iter().enumerate() {
        let (directive, value) = invalid(load_vhost(&format!("1030-{i}"), &rewrite(enable, map)));
        assert_eq!(
            (directive, value.as_str()),
            ("rewrite.map", "blocked txt:/etc/blocked.map")
        );
    }
    let (directive, value) = invalid(load_vhost(
        "1030-second",
        &rewrite("1", "<map/><MAP><name>m</name></MAP>"),
    ));
    assert_eq!((directive, value.as_str()), ("rewrite.map", "m"));
    load_vhost(
        "1030-empty",
        &rewrite("1", "<map/><map><name> </name><location></location></map>"),
    )
    .unwrap();
}

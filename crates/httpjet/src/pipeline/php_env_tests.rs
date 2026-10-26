//! CGI environment a script sees through the full pipeline, against a synthetic
//! LSAPI peer that echoes selected `$_SERVER` vars (no PHP process, no production socket).
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ECHOED: &[&str] = &[
    "REQUEST_METHOD",
    "REQUEST_URI",
    "SCRIPT_NAME",
    "SCRIPT_FILENAME",
    "QUERY_STRING",
    "REDIRECT_STATUS",
    "REDIRECT_URL",
    "REDIRECT_QUERY_STRING",
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "HTTP_COOKIE",
    "HTTP_USER_AGENT",
    "HTTP_X_CUSTOM",
    "HTTP_CONTENT_TYPE",
];

fn echo_body(env: &BTreeMap<String, String>) -> String {
    ECHOED
        .iter()
        .filter_map(|k| env.get(*k).map(|v| format!("{k}={v}\n")))
        .collect()
}

/// `$_SERVER` as lsphp builds it (`sapi_lsapi_register_variables`): the header block
/// first, then the env table, whose entries win.
fn server_vars(body: &[u8]) -> BTreeMap<String, String> {
    let (env, env_end) = parse_env(body);
    let i32_at = |at: usize| i32::from_le_bytes(body[at..at + 4].try_into().unwrap()) as usize;
    let pad = (8 - ((8 + env_end) % 8)) % 8;
    let raw_at = env_end + pad + hj_lsapi::HEADER_INDEX_LEN + i32_at(24) * 16;
    let raw = String::from_utf8_lossy(&body[raw_at..raw_at + i32_at(0)]).into_owned();
    let mut vars = BTreeMap::new();
    for line in raw.split("\r\n") {
        let Some((name, value)) = line.split_once(": ") else {
            continue;
        };
        let key = match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => continue,
            "content-type" => "CONTENT_TYPE".to_string(),
            "content-length" => "CONTENT_LENGTH".to_string(),
            name => format!("HTTP_{}", name.to_ascii_uppercase().replace('-', "_")),
        };
        vars.insert(key, value.to_string());
    }
    vars.extend(env);
    vars
}

fn parse_env(body: &[u8]) -> (BTreeMap<String, String>, usize) {
    let field = |at: usize| u16::from_be_bytes(body[at..at + 2].try_into().unwrap()) as usize;
    let mut env = BTreeMap::new();
    let mut at = 36;
    for table in 0..2 {
        loop {
            let (k, v) = (field(at), field(at + 2));
            at += 4;
            if k == 0 && v == 0 {
                break;
            }
            if table == 1 {
                let key = String::from_utf8_lossy(&body[at..at + k - 1]).into_owned();
                let value = String::from_utf8_lossy(&body[at + k..at + k + v - 1]).into_owned();
                env.insert(key, value);
            }
            at += k + v;
        }
    }
    (env, at)
}

fn packet(kind: hj_lsapi::PacketType, body: &[u8]) -> Vec<u8> {
    let mut out = vec![b'L', b'S', kind as u8, hj_lsapi::proto::HOST_LSAPI_ENDIAN];
    out.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn response(body: &[u8]) -> Vec<u8> {
    let line = b"Content-Type: text/plain";
    let mut head = Vec::new();
    head.extend_from_slice(&1i32.to_le_bytes());
    head.extend_from_slice(&200i32.to_le_bytes());
    head.extend_from_slice(&((line.len() + 1) as u16).to_le_bytes());
    head.extend_from_slice(line);
    head.push(0);
    let mut out = packet(hj_lsapi::PacketType::RespHeader, &head);
    out.extend(packet(hj_lsapi::PacketType::RespStream, body));
    out.extend(packet(hj_lsapi::PacketType::RespEnd, b""));
    out
}

async fn echo_peer(listener: tokio::net::UnixListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            loop {
                let mut head = [0u8; 8];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let size = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
                let mut body = vec![0; size - 8];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                if head[2] != hj_lsapi::PacketType::BeginRequest as u8 {
                    continue;
                }
                let env = server_vars(&body);
                if stream
                    .write_all(&response(echo_body(&env).as_bytes()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }
}

struct Peer {
    dir: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn php_state(root: PathBuf) -> (Arc<ServerState>, Peer) {
    let dir = temp_root("lsapi-echo");
    let socket = dir.join("php.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let task = tokio::spawn(echo_peer(listener));
    let mut template = hj_lsapi::SupervisorConfig::from_php_config(
        &hj_core::config::PhpConfig::default(),
        &socket,
        "",
        "",
    );
    template.children = 2;
    template.retry_timeout = Duration::from_millis(200);
    let registry =
        hj_lsapi::LsapiRegistry::new_external(template, Duration::from_secs(5), None, 1 << 20);
    let state = build_state_with_lsapi(
        root,
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| {
            let vhost = server.vhosts.get_mut(VHOST).unwrap();
            Arc::make_mut(vhost.config.as_mut().unwrap()).index_files =
                vec!["index.php".into(), "index.html".into()];
        },
        crate::state::RewriteTuning::default(),
        Some(registry),
    );
    (state, Peer { dir, task })
}

async fn echoed(resp: Response) -> (http::StatusCode, BTreeMap<String, String>) {
    let status = resp.status();
    let body = match resp.into_body() {
        Body::Full(b) => b,
        Body::Stream(s) => {
            use http_body_util::BodyExt;
            s.collect().await.unwrap().to_bytes()
        }
        Body::Empty => bytes::Bytes::new(),
        Body::File(_) => panic!("a script response is never a file"),
    };
    let text = String::from_utf8(body.to_vec()).unwrap();
    let env = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (status, env)
}

/// Regression (#947): a DirectoryIndex script reports itself in SCRIPT_NAME (OLS
/// appendIndexToUri), so PHP_SELF / framework base-path detection see the index
/// file; REQUEST_URI stays the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_index_script_name_names_the_index() {
    let root = temp_root("php-dir-index");
    std::fs::create_dir(root.join("xf")).unwrap();
    std::fs::write(root.join("xf/index.php"), b"<?php\n").unwrap();
    std::fs::write(root.join("index.php"), b"<?php\n").unwrap();
    let (state, _peer) = php_state(root.clone());

    let (status, env) = echoed(run(&state, get(CANON_HOST, "/xf/?a=1", None)).await).await;
    assert_eq!(status, http::StatusCode::OK, "{env:?}");
    assert_eq!(env["SCRIPT_NAME"], "/xf/index.php");
    assert_eq!(env["REQUEST_URI"], "/xf/?a=1");
    assert_eq!(env["QUERY_STRING"], "a=1");
    assert!(env["SCRIPT_FILENAME"].ends_with("/xf/index.php"));

    let (_, env) = echoed(run(&state, get(CANON_HOST, "/", None)).await).await;
    assert_eq!(env["SCRIPT_NAME"], "/index.php");
    assert_eq!(env["REQUEST_URI"], "/");
}

fn with_headers(method: &str, uri: &str, body: &'static [u8]) -> Request {
    use http_body_util::BodyExt;
    http::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, CANON_HOST)
        .header(header::COOKIE, "sid=abc")
        .header(header::USER_AGENT, "probe/1.0")
        .header("x-custom", "kept")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::CONTENT_LENGTH, body.len())
        .body(
            http_body_util::Full::new(bytes::Bytes::from_static(body))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Regression (#948): a PHP ErrorDocument runs as an internal redirect of the
/// SAME request (LSWS httpcgitool): it keeps the inbound headers and the original
/// REQUEST_URI, gets REDIRECT_URL/REDIRECT_STATUS/REDIRECT_QUERY_STRING, and is a
/// bodyless GET (no body framing reaches the backend). A POST to a missing path
/// is a 404 that runs the ErrorDocument, not a static-handler 405.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn php_error_document_sees_original_request() {
    let root = temp_root("php-errordoc-env");
    std::fs::create_dir(root.join("ed")).unwrap();
    std::fs::write(root.join("ed/err.php"), b"<?php\n").unwrap();
    std::fs::write(root.join("present.txt"), b"static file").unwrap();
    std::fs::write(root.join(".htaccess"), "ErrorDocument 404 /ed/err.php\n").unwrap();
    let (state, _peer) = php_state(root.clone());

    for method in ["GET", "POST"] {
        let resp = run(
            &state,
            with_headers(method, "/missing/page?x=1&y=2", b"a=b"),
        )
        .await;
        let (status, env) = echoed(resp).await;
        assert_eq!(status, http::StatusCode::NOT_FOUND, "{method}: {env:?}");
        assert_eq!(env["REQUEST_URI"], "/missing/page?x=1&y=2", "{method}");
        assert_eq!(env["SCRIPT_NAME"], "/ed/err.php", "{method}");
        assert_eq!(env["QUERY_STRING"], "", "{method}");
        assert_eq!(env["REDIRECT_STATUS"], "404", "{method}");
        assert_eq!(env["REDIRECT_URL"], "/missing/page", "{method}");
        assert_eq!(env["REDIRECT_QUERY_STRING"], "x=1&y=2", "{method}");
        assert_eq!(env["REQUEST_METHOD"], "GET", "{method}");
        assert_eq!(env["HTTP_COOKIE"], "sid=abc", "{method}");
        assert_eq!(env["HTTP_USER_AGENT"], "probe/1.0", "{method}");
        assert_eq!(env["HTTP_X_CUSTOM"], "kept", "{method}");
        assert!(!env.contains_key("CONTENT_TYPE"), "{method}: {env:?}");
        assert!(!env.contains_key("HTTP_CONTENT_TYPE"), "{method}: {env:?}");
        assert!(
            env.get("CONTENT_LENGTH").is_none_or(|v| v == "0"),
            "{method}: {env:?}"
        );
    }

    // No query on the original: no REDIRECT_QUERY_STRING.
    let (_, env) = echoed(run(&state, get(CANON_HOST, "/gone", None)).await).await;
    assert_eq!(env["REQUEST_URI"], "/gone");
    assert!(!env.contains_key("REDIRECT_QUERY_STRING"), "{env:?}");

    // An existing static file still refuses a non-GET method.
    let resp = run(&state, with_headers("POST", "/present.txt", b"a=b")).await;
    assert_eq!(resp.status(), http::StatusCode::METHOD_NOT_ALLOWED);
}

fn ua_req(method: &str, uri: &str, ua: &str) -> Request {
    use http_body_util::BodyExt;
    http::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, CANON_HOST)
        .header(header::USER_AGENT, ua)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::CONTENT_LENGTH, 3)
        .body(
            http_body_util::Full::new(bytes::Bytes::from_static(b"a=b"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

const BAD_BOT_DENY: &str =
    "SetEnvIf User-Agent BadBot bad_bot\nOrder Allow,Deny\nAllow from all\nDeny from env=bad_bot\n";

/// A symlinked resource's target-directory chain is judged with
/// the request's real method and with that chain's own SetEnvIf, on the dispatch
/// path and on the on-core static path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlinked_target_chain_sees_real_method_and_its_own_setenvif() {
    let root = temp_root("mapped-target-env");
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(root.join("private/real.php"), b"<?php\n").unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "<LimitExcept GET>\nRequire all denied\n</LimitExcept>\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("private/real.php"), root.join("alias.php")).unwrap();
    std::fs::create_dir(root.join("private2")).unwrap();
    std::fs::write(root.join("private2/real.php"), b"<?php\n").unwrap();
    std::fs::write(root.join("private2/real.txt"), b"static").unwrap();
    std::fs::write(root.join("private2/.htaccess"), BAD_BOT_DENY).unwrap();
    std::os::unix::fs::symlink(root.join("private2/real.php"), root.join("alias2.php")).unwrap();
    std::os::unix::fs::symlink(root.join("private2/real.txt"), root.join("alias2.txt")).unwrap();
    let (state, _peer) = php_state(root.clone());

    for (method, uri, ua, expected) in [
        ("POST", "/private/real.php", "x", 403),
        ("GET", "/private/real.php", "x", 200),
        ("GET", "/alias.php", "x", 200),
        ("POST", "/alias.php", "x", 403),
        ("PUT", "/alias.php", "x", 403),
        ("GET", "/private2/real.php", "BadBot", 403),
        ("GET", "/alias2.php", "BadBot", 403),
        ("POST", "/alias2.php", "BadBot", 403),
        ("GET", "/alias2.php", "good", 200),
        ("GET", "/alias2.txt", "BadBot", 403),
        ("GET", "/alias2.txt", "good", 200),
    ] {
        let (status, env) = echoed_any(run(&state, ua_req(method, uri, ua)).await).await;
        assert_eq!(status.as_u16(), expected, "{method} {uri} UA={ua}: {env:?}");
    }
    // The on-core path must not serve what dispatch() denies.
    let probe = |ua: &str| {
        http::Request::builder()
            .uri("/alias2.txt")
            .header(header::HOST, CANON_HOST)
            .header(header::USER_AGENT, ua)
            .body(hj_core::empty_incoming())
            .unwrap()
    };
    assert!(
        fast_serve_req(&state, &probe("BadBot")).await.is_none(),
        "on-core served a target its own SetEnvIf denies"
    );
    let served = fast_serve_req(&state, &probe("good")).await;
    assert_eq!(served.map(|r| r.status().as_u16()), Some(200));
}

/// A per-directory rewrite into another directory runs that
/// destination chain's SetEnvIf before its env-based deny (Apache's internal
/// redirect reruns mod_setenvif before access).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_directory_rewrite_runs_destination_setenvif_before_access() {
    let root = temp_root("rewrite-dest-env");
    std::fs::create_dir(root.join("protected")).unwrap();
    std::fs::write(root.join("protected/x.php"), b"<?php\n").unwrap();
    std::fs::write(root.join("protected/.htaccess"), BAD_BOT_DENY).unwrap();
    // An intermediate hop: /relay's own rules move the request on to /pub, whose
    // chain has no deny, so only the hop's access phase can refuse it.
    std::fs::create_dir(root.join("relay")).unwrap();
    std::fs::create_dir(root.join("pub")).unwrap();
    std::fs::write(root.join("pub/y.php"), b"<?php\n").unwrap();
    std::fs::write(
        root.join("relay/.htaccess"),
        format!("{BAD_BOT_DENY}RewriteEngine On\nRewriteRule ^x\\.php$ /pub/y.php [L]\n"),
    )
    .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^go$ /protected/x.php [L]\nRewriteRule ^hop$ /relay/x.php [L]\n",
    )
    .unwrap();
    let (state, _peer) = php_state(root.clone());
    for (method, uri, ua, expected, script) in [
        ("GET", "/protected/x.php", "BadBot", 403, ""),
        ("GET", "/protected/x.php", "good", 200, "/protected/x.php"),
        ("GET", "/go", "BadBot", 403, ""),
        ("POST", "/go", "BadBot", 403, ""),
        ("GET", "/go", "good", 200, "/protected/x.php"),
        ("GET", "/hop", "BadBot", 403, ""),
        ("POST", "/hop", "BadBot", 403, ""),
        ("GET", "/hop", "good", 200, "/pub/y.php"),
    ] {
        let (status, env) = echoed_any(run(&state, ua_req(method, uri, ua)).await).await;
        assert_eq!(status.as_u16(), expected, "{method} {uri} UA={ua}: {env:?}");
        if expected == 200 {
            assert!(env["SCRIPT_FILENAME"].ends_with(script), "{uri}: {env:?}");
        }
    }
}

/// [`echoed`] for a response that may be a static file or an error page.
async fn echoed_any(resp: Response) -> (http::StatusCode, BTreeMap<String, String>) {
    if matches!(resp.body(), Body::File(_)) {
        return (resp.status(), BTreeMap::new());
    }
    echoed(resp).await
}
